#!/usr/bin/env bats
#
# Tests for migrate-to-nftables.sh
#
# Strategy: create a temp sandbox with mock binaries for nft, ipset,
# iptables, ip6tables, systemctl, and a fake update_blacklist.py.
# Override STATE_DIR, BACKUP_DIR, CONF_FILE via --conf and env.

SCRIPT="$BATS_TEST_DIRNAME/migrate-to-nftables.sh"

setup() {
    SANDBOX="$(mktemp -d)"
    STATE_DIR="$SANDBOX/state"
    BACKUP_DIR="$SANDBOX/backups"
    CONF_DIR="$SANDBOX/conf"
    BIN_DIR="$SANDBOX/bin"
    SBIN_DIR="$SANDBOX/sbin"
    NFT_DROP_DIR="$SANDBOX/nftables.d"
    SYSTEMD_DIR="$SANDBOX/systemd"

    mkdir -p "$STATE_DIR" "$BACKUP_DIR" "$CONF_DIR" "$BIN_DIR" "$SBIN_DIR" \
             "$NFT_DROP_DIR" "$SYSTEMD_DIR"

    # Fake config
    cat > "$CONF_DIR/ipset-blacklist.conf" <<'EOF'
IPSET_BLACKLIST_NAME=blacklist
IP_BLACKLIST_RESTORE=/tmp/test-restore
BLACKLISTS=("https://example.com/list.txt")
EOF

    # Fake update_blacklist.py with detect_backend
    cat > "$SBIN_DIR/update_blacklist.py" <<'PYEOF'
#!/usr/bin/env python3
def detect_backend(): pass
PYEOF
    chmod +x "$SBIN_DIR/update_blacklist.py"

    # Mock nft — tracks calls, succeeds by default
    cat > "$BIN_DIR/nft" <<'NFTEOF'
#!/bin/bash
echo "$@" >> "$SANDBOX/nft.log"
# "list table" succeeds only if table was "created"
if [[ "$*" == *"list table"* ]]; then
    [ -f "$SANDBOX/nft-table-exists" ] && exit 0 || exit 1
fi
# "delete table" removes marker
if [[ "$*" == *"delete table"* ]]; then
    rm -f "$SANDBOX/nft-table-exists"
    exit 0
fi
# "-f -" (batch apply) creates the table marker
if [[ "$*" == "-f -" ]]; then
    touch "$SANDBOX/nft-table-exists"
    exit 0
fi
# "-j list set" returns JSON with elements
if [[ "$*" == *"-j list set"* ]]; then
    echo '{"nftables":[{"set":{"elem":["1.2.3.4","5.6.7.8"]}}]}'
    exit 0
fi
# "list table inet blacklist" for finalize save
if [[ "$*" == "list table inet blacklist" ]]; then
    echo 'table inet blacklist { set v4 { } }'
    exit 0
fi
exit 0
NFTEOF
    chmod +x "$BIN_DIR/nft"

    # Mock ipset
    cat > "$BIN_DIR/ipset" <<'IPEOF'
#!/bin/bash
echo "$@" >> "$SANDBOX/ipset.log"
case "$1" in
    list)
        if [ "$2" = "-n" ]; then
            [ -f "$SANDBOX/ipset-exists" ] && exit 0 || exit 1
        fi
        echo "1.1.1.1"
        echo "2.2.2.2"
        ;;
    save)
        echo "create blacklist hash:net"
        echo "add blacklist 1.1.1.1"
        echo "add blacklist 2.2.2.2"
        ;;
    destroy)
        rm -f "$SANDBOX/ipset-exists"
        ;;
esac
exit 0
IPEOF
    chmod +x "$BIN_DIR/ipset"

    # Mock iptables / ip6tables / iptables-save / ip6tables-save
    for cmd in iptables ip6tables; do
        cat > "$BIN_DIR/$cmd" <<'EOF'
#!/bin/bash
exit 0
EOF
        chmod +x "$BIN_DIR/$cmd"
        cat > "$BIN_DIR/${cmd}-save" <<'EOF'
#!/bin/bash
echo "# Generated"
exit 0
EOF
        chmod +x "$BIN_DIR/${cmd}-save"
    done

    # Mock systemctl
    cat > "$BIN_DIR/systemctl" <<'EOF'
#!/bin/bash
echo "$@" >> "$SANDBOX/systemctl.log"
exit 0
EOF
    chmod +x "$BIN_DIR/systemctl"

    # Mock python3 for count_nft_elements
    cat > "$BIN_DIR/python3" <<'EOF'
#!/bin/bash
# Just consume stdin and print a count
python3.real -c "$(cat)" 2>/dev/null || echo "2"
EOF
    # Actually, let the real python3 handle it
    rm "$BIN_DIR/python3"

    # Mark ipset as existing
    touch "$SANDBOX/ipset-exists"

    export SANDBOX
}

teardown() {
    rm -rf "$SANDBOX"
}

# Helper: run the script with our sandbox paths
run_migrate() {
    # Override paths by patching the script via env + sed
    # Simpler: create a wrapper that overrides variables then sources
    local wrapper="$SANDBOX/run.sh"
    cat > "$wrapper" <<WEOF
#!/bin/bash
export PATH="$BIN_DIR:\$PATH"
export EUID=0

# Source the script but override paths
# We use sed to create a patched copy
sed \\
    -e 's|STATE_DIR="/var/lib/ipset-blacklist"|STATE_DIR="$STATE_DIR"|' \\
    -e 's|STATE_FILE="\$STATE_DIR/migration-state"|STATE_FILE="$STATE_DIR/migration-state"|' \\
    -e 's|BACKUP_DIR="/var/backups"|BACKUP_DIR="$BACKUP_DIR"|' \\
    -e 's|CONF_FILE="/etc/ipset-blacklist/ipset-blacklist.conf"|CONF_FILE="$CONF_DIR/ipset-blacklist.conf"|' \\
    -e 's|NFT_DROP_DIR="/etc/nftables.d"|NFT_DROP_DIR="$NFT_DROP_DIR"|' \\
    -e 's|NFT_DROP_FILE="\$NFT_DROP_DIR/blacklist.nft"|NFT_DROP_FILE="$NFT_DROP_DIR/blacklist.nft"|' \\
    -e 's|SYSTEMD_UNIT_FILE="/etc/systemd/system/\$SYSTEMD_UNIT"|SYSTEMD_UNIT_FILE="$SYSTEMD_DIR/nft-blacklist.service"|' \\
    -e 's|local script="/usr/local/sbin/update_blacklist.py"|local script="$SBIN_DIR/update_blacklist.py"|' \\
    -e 's|if \[ "\$EUID" -ne 0 \]|if [ "\$EUID" -ne 0 ] \&\& false|' \\
    "$SCRIPT" > "$SANDBOX/patched.sh"
chmod +x "$SANDBOX/patched.sh"
exec bash "$SANDBOX/patched.sh" "\$@"
WEOF
    chmod +x "$wrapper"
    "$wrapper" "$@"
}

# ---------------------------------------------------------------
# Arg parsing
# ---------------------------------------------------------------
@test "help flag exits 0" {
    run run_migrate --help
    [ "$status" -eq 0 ]
    [[ "$output" == *"Usage:"* ]]
}

# ---------------------------------------------------------------
# State machine
# ---------------------------------------------------------------
@test "read_state returns empty when no state file" {
    rm -f "$STATE_DIR/migration-state"
    run run_migrate --rollback
    [ "$status" -ne 0 ]
    [[ "$output" == *"No migration in progress"* ]]
}

@test "migrate creates state=migrated" {
    run run_migrate
    [ "$status" -eq 0 ]
    grep -q "STATE=migrated" "$STATE_DIR/migration-state"
}

@test "migrate twice fails" {
    run_migrate
    run run_migrate
    [ "$status" -ne 0 ]
    [[ "$output" == *"Already migrated"* ]]
}

@test "rollback after migrate sets state=rolled-back" {
    run_migrate
    run run_migrate --rollback
    [ "$status" -eq 0 ]
    grep -q "STATE=rolled-back" "$STATE_DIR/migration-state"
}

@test "rollback twice fails" {
    run_migrate
    run_migrate --rollback
    run run_migrate --rollback
    [ "$status" -ne 0 ]
    [[ "$output" == *"Already rolled back"* ]]
}

@test "finalize without migrate fails" {
    run run_migrate --finalize --enable-service
    [ "$status" -ne 0 ]
    [[ "$output" == *"Run migrate first"* ]]
}

@test "finalize after rollback fails" {
    run_migrate
    run_migrate --rollback
    run run_migrate --finalize --enable-service
    [ "$status" -ne 0 ]
    [[ "$output" == *"Run migrate again"* ]]
}

@test "finalize after migrate sets state=finalized" {
    run_migrate
    run run_migrate --finalize --enable-service
    [ "$status" -eq 0 ]
    grep -q "STATE=finalized" "$STATE_DIR/migration-state"
}

@test "finalize twice fails" {
    run_migrate
    run_migrate --finalize --enable-service
    run run_migrate --finalize --enable-service
    [ "$status" -ne 0 ]
    [[ "$output" == *"Already finalized"* ]]
}

@test "rollback after finalize fails" {
    run_migrate
    run_migrate --finalize --enable-service
    run run_migrate --rollback
    [ "$status" -ne 0 ]
    [[ "$output" == *"Cannot rollback after finalize"* ]]
}

# ---------------------------------------------------------------
# Preflight: check_script_nft_capable
# ---------------------------------------------------------------
@test "migrate fails if update_blacklist.py missing" {
    rm "$SBIN_DIR/update_blacklist.py"
    run run_migrate
    [ "$status" -ne 0 ]
    [[ "$output" == *"not found"* ]]
}

@test "migrate fails if script lacks detect_backend" {
    echo '#!/usr/bin/env python3' > "$SBIN_DIR/update_blacklist.py"
    run run_migrate
    [ "$status" -ne 0 ]
    [[ "$output" == *"lacks nft support"* ]]
}

@test "finalize fails if script lacks detect_backend" {
    run_migrate
    echo '#!/usr/bin/env python3' > "$SBIN_DIR/update_blacklist.py"
    run run_migrate --finalize --enable-service
    [ "$status" -ne 0 ]
    [[ "$output" == *"lacks nft support"* ]]
}

# ---------------------------------------------------------------
# Backups
# ---------------------------------------------------------------
@test "migrate creates backup files" {
    run_migrate
    local count
    count=$(ls "$BACKUP_DIR"/ipset-blacklist-*.dump 2>/dev/null | wc -l)
    [ "$count" -ge 1 ]
    count=$(ls "$BACKUP_DIR"/iptables-*.rules 2>/dev/null | wc -l)
    [ "$count" -ge 1 ]
}

# ---------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------
@test "load_conf reads custom set names" {
    cat > "$CONF_DIR/ipset-blacklist.conf" <<'EOF'
IPSET_BLACKLIST_NAME=mylist
NFT_TABLE=mytable
EOF
    run_migrate
    # The state file should exist (migration ran successfully with custom names)
    grep -q "STATE=migrated" "$STATE_DIR/migration-state"
}

# ---------------------------------------------------------------
# Finalize: --dry-run and --enable-service
# ---------------------------------------------------------------
@test "finalize without --enable-service shows plan and exits" {
    run_migrate
    run run_migrate --finalize
    [ "$status" -eq 0 ]
    [[ "$output" == *"--enable-service required"* ]]
    # State should still be migrated, not finalized
    grep -q "STATE=migrated" "$STATE_DIR/migration-state"
}

@test "finalize --dry-run shows plan and exits" {
    run_migrate
    run run_migrate --finalize --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"Dry run"* ]]
    grep -q "STATE=migrated" "$STATE_DIR/migration-state"
}

@test "finalize --enable-service installs systemd unit" {
    run_migrate
    run_migrate --finalize --enable-service
    [ -f "$SYSTEMD_DIR/nft-blacklist.service" ]
    grep -q "daemon-reload" "$SANDBOX/systemctl.log"
    grep -q "enable" "$SANDBOX/systemctl.log"
}

@test "finalize --enable-service saves nft drop file" {
    run_migrate
    run_migrate --finalize --enable-service
    [ -f "$NFT_DROP_DIR/blacklist.nft" ]
}

# ---------------------------------------------------------------
# nft table lifecycle
# ---------------------------------------------------------------
@test "migrate calls nft to create table" {
    run_migrate
    grep -q "\-f \-" "$SANDBOX/nft.log"
}

@test "rollback calls nft delete table" {
    run_migrate
    run_migrate --rollback
    grep -q "delete table" "$SANDBOX/nft.log"
}
