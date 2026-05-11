#!/bin/bash
#
# migrate-to-nftables.sh — three-phase migration from ipset+iptables to nftables
#
# Usage:
#   sudo ./migrate-to-nftables.sh [--conf PATH]                          # migrate
#   sudo ./migrate-to-nftables.sh --rollback [--conf PATH]               # rollback
#   sudo ./migrate-to-nftables.sh --finalize --enable-service [--conf P] # finalize
#   sudo ./migrate-to-nftables.sh --finalize --dry-run [--conf PATH]     # preview
#
# State is tracked in /var/lib/ipset-blacklist/migration-state.
# Backups are written to /var/backups/ipset-blacklist-*.

set -euo pipefail

# ---------------- Defaults ----------------
STATE_DIR="/var/lib/ipset-blacklist"
STATE_FILE="$STATE_DIR/migration-state"
BACKUP_DIR="/var/backups"
CONF_FILE="/etc/ipset-blacklist/ipset-blacklist.conf"
DRY_RUN=false
ENABLE_SERVICE=false

NFT_TABLE="blacklist"
NFT_SET_V4="v4"
NFT_SET_V6="v6"
IPSET_V4="blacklist"
IPSET_V6="blacklist6"

NFT_DROP_DIR="/etc/nftables.d"
NFT_DROP_FILE="$NFT_DROP_DIR/blacklist.nft"
SYSTEMD_UNIT="nft-blacklist.service"
SYSTEMD_UNIT_FILE="/etc/systemd/system/$SYSTEMD_UNIT"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# ---------------- Helpers ----------------
die()  { echo -e "${RED}Error: $1${NC}" >&2; exit 1; }
info() { echo -e "${GREEN}$1${NC}"; }
warn() { echo -e "${YELLOW}$1${NC}"; }

read_state() {
    if [ -f "$STATE_FILE" ]; then
        grep "^STATE=" "$STATE_FILE" 2>/dev/null | cut -d= -f2
    fi
}

check_script_nft_capable() {
    local script="/usr/local/sbin/update_blacklist.py"
    if [ ! -f "$script" ]; then
        die "update_blacklist.py not found at $script. Deploy it first."
    fi
    if ! grep -q 'detect_backend' "$script"; then
        die "Deployed $script lacks nft support (detect_backend not found).\nDeploy the nft-capable version before migrating."
    fi
}

write_state() {
    mkdir -p "$STATE_DIR"
    cat > "$STATE_FILE" <<EOF
STATE=$1
DATE=$(date -Iseconds)
BACKUP_IPSET=${BACKUP_IPSET:-}
BACKUP_IPTABLES=${BACKUP_IPTABLES:-}
BACKUP_IP6TABLES=${BACKUP_IP6TABLES:-}
IPSET_V4_COUNT=${IPSET_V4_COUNT:-0}
IPSET_V6_COUNT=${IPSET_V6_COUNT:-0}
EOF
}

_conf_val() {
    sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*\([^#]*\).*/\1/p" "$CONF_FILE" 2>/dev/null | tr -d '[:space:]'
}

load_conf() {
    if [ ! -f "$CONF_FILE" ]; then return; fi
    local val
    val=$(_conf_val IPSET_BLACKLIST_NAME)
    if [ -n "$val" ]; then
        IPSET_V4="$val"
        IPSET_V6="${val}6"
    fi
    val=$(_conf_val SET_NAME4)
    if [ -n "$val" ]; then IPSET_V4="$val"; fi
    val=$(_conf_val SET_NAME6)
    if [ -n "$val" ]; then IPSET_V6="$val"; fi
    val=$(_conf_val NFT_TABLE)
    if [ -n "$val" ]; then NFT_TABLE="$val"; fi
    val=$(_conf_val NFT_SET_V4)
    if [ -n "$val" ]; then NFT_SET_V4="$val"; fi
    val=$(_conf_val NFT_SET_V6)
    if [ -n "$val" ]; then NFT_SET_V6="$val"; fi
}

cleanup_on_error() {
    warn "Migration failed — cleaning up partial nft state..."
    nft delete table inet "$NFT_TABLE" 2>/dev/null || true
    die "Migration aborted. Host remains on ipset+iptables, unchanged."
}

ipset_set_exists() {
    ipset list -n "$1" >/dev/null 2>&1
}

count_ipset_entries() {
    ipset list "$1" 2>/dev/null | grep -cE '^[0-9]' || true
}

count_nft_elements() {
    nft -j list set inet "$NFT_TABLE" "$1" 2>/dev/null \
        | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    for item in data.get('nftables', []):
        s = item.get('set')
        if s and 'elem' in s:
            print(len(s['elem']))
            sys.exit(0)
    print(0)
except Exception:
    print(0)
" 2>/dev/null || echo 0
}

# Build an nft batch script from ipset entries
build_nft_populate_script() {
    local set_name="$1" nft_set="$2"
    ipset save "$set_name" 2>/dev/null | python3 -c "
import sys
entries = []
for line in sys.stdin:
    parts = line.strip().split()
    if len(parts) >= 3 and parts[0] == 'add':
        entries.append(parts[2])
table = '${NFT_TABLE}'
nft_set = '${nft_set}'
CHUNK = 10000
for i in range(0, len(entries), CHUNK):
    chunk = entries[i:i+CHUNK]
    elems = ', '.join(chunk)
    print(f'add element inet {table} {nft_set} {{ {elems} }}')
"
}

# ---------------- Parse args ----------------
MODE="migrate"
while [ $# -gt 0 ]; do
    case "$1" in
        --rollback)       MODE="rollback"; shift ;;
        --finalize)       MODE="finalize"; shift ;;
        --dry-run)        DRY_RUN=true; shift ;;
        --enable-service) ENABLE_SERVICE=true; shift ;;
        --conf)           CONF_FILE="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 [--rollback|--finalize] [--dry-run] [--enable-service] [--conf PATH]"
            echo ""
            echo "Modes:"
            echo "  (default)        Create nft table alongside ipset (coexistence)"
            echo "  --rollback       Remove nft table, revert to ipset only"
            echo "  --finalize       Remove ipset+iptables, keep nft only"
            echo ""
            echo "Options:"
            echo "  --dry-run        Show what finalize would do without making changes"
            echo "  --enable-service Install and enable nft-blacklist.service (required for finalize)"
            echo "  --conf PATH      Path to ipset-blacklist.conf"
            exit 0
            ;;
        *) die "Unknown option: $1" ;;
    esac
done

# ---------------- Pre-flight ----------------
if [ "$EUID" -ne 0 ]; then die "Must run as root"; fi
load_conf

# ================================================================
#  MIGRATE
# ================================================================
do_migrate() {
    command -v nft  >/dev/null 2>&1 || die "nft binary not found. Install nftables first."
    command -v ipset >/dev/null 2>&1 || die "ipset binary not found."
    check_script_nft_capable
    ipset_set_exists "$IPSET_V4" || die "ipset set '$IPSET_V4' not found. Nothing to migrate."

    local state
    state=$(read_state)
    if [ "$state" = "migrated" ]; then die "Already migrated. Run --finalize or --rollback."; fi
    if [ "$state" = "finalized" ]; then die "Already finalized. nft is the active backend."; fi

    if nft list table inet "$NFT_TABLE" >/dev/null 2>&1; then
        die "nft table 'inet $NFT_TABLE' already exists. Remove it first or run --rollback."
    fi

    trap cleanup_on_error ERR

    # 1. Backup
    local datestamp
    datestamp=$(date +%Y%m%d-%H%M%S)
    BACKUP_IPSET="$BACKUP_DIR/ipset-blacklist-$datestamp.dump"
    BACKUP_IPTABLES="$BACKUP_DIR/iptables-$datestamp.rules"
    BACKUP_IP6TABLES="$BACKUP_DIR/ip6tables-$datestamp.rules"

    info "Backing up current state..."
    ipset save > "$BACKUP_IPSET"
    iptables-save > "$BACKUP_IPTABLES"
    ip6tables-save > "$BACKUP_IP6TABLES" 2>/dev/null || true
    info "  ipset   → $BACKUP_IPSET"
    info "  iptables → $BACKUP_IPTABLES"
    info "  ip6tables → $BACKUP_IP6TABLES"

    # 2. Count existing entries
    IPSET_V4_COUNT=$(count_ipset_entries "$IPSET_V4")
    IPSET_V6_COUNT=0
    if ipset_set_exists "$IPSET_V6"; then
        IPSET_V6_COUNT=$(count_ipset_entries "$IPSET_V6")
    fi
    info "Existing ipset entries: v4=$IPSET_V4_COUNT v6=$IPSET_V6_COUNT"

    # 3. Create nft table + sets + chain
    info "Creating nft table inet $NFT_TABLE..."
    local setup_script
    setup_script="table inet $NFT_TABLE {
  set $NFT_SET_V4 {
    type ipv4_addr
    flags interval
  }
  set $NFT_SET_V6 {
    type ipv6_addr
    flags interval
  }
  chain input {
    type filter hook input priority filter; policy accept;
    ip saddr @$NFT_SET_V4 drop
    ip6 saddr @$NFT_SET_V6 drop
  }
}"
    echo "$setup_script" | nft -f -

    # 4. Populate sets from ipset
    info "Populating nft sets from ipset..."
    local populate_script=""
    populate_script=$(build_nft_populate_script "$IPSET_V4" "$NFT_SET_V4")
    if ipset_set_exists "$IPSET_V6"; then
        local v6_script
        v6_script=$(build_nft_populate_script "$IPSET_V6" "$NFT_SET_V6")
        if [ -n "$v6_script" ]; then
            populate_script="${populate_script}
${v6_script}"
        fi
    fi
    if [ -n "$populate_script" ]; then
        echo "$populate_script" | nft -f -
    fi

    # 5. Verify counts match
    local nft_v4_count nft_v6_count
    nft_v4_count=$(count_nft_elements "$NFT_SET_V4")
    nft_v6_count=$(count_nft_elements "$NFT_SET_V6")
    info "nft element counts: v4=$nft_v4_count v6=$nft_v6_count"

    if [ "$nft_v4_count" -lt "$((IPSET_V4_COUNT / 2))" ] && [ "$IPSET_V4_COUNT" -gt 0 ]; then
        warn "Warning: nft v4 count ($nft_v4_count) is much less than ipset ($IPSET_V4_COUNT)"
        warn "Some entries may have been merged by nft interval optimization"
    fi

    # 6. Record state
    trap - ERR
    write_state "migrated"

    echo ""
    info "=== Migration complete ==="
    info "  ipset+iptables left in place (rollback available)"
    info "  nft table 'inet $NFT_TABLE' created with $nft_v4_count v4 + $nft_v6_count v6 entries"

    echo ""
    info "Next steps:"
    info "  - Next cron run of update_blacklist.py will auto-detect nft and dual-write both backends"
    info "  - Monitor for a few runs, then finalize:"
    info "    sudo $0 --finalize --enable-service"
    info "  - Preview finalize without making changes:"
    info "    sudo $0 --finalize --dry-run"
    info "  - To undo: sudo $0 --rollback"
}

# ================================================================
#  ROLLBACK
# ================================================================
do_rollback() {
    local state
    state=$(read_state)
    if [ -z "$state" ]; then die "No migration in progress. Nothing to rollback."; fi
    if [ "$state" = "finalized" ]; then die "Cannot rollback after finalize. Restore from backup manually."; fi
    if [ "$state" = "rolled-back" ]; then die "Already rolled back."; fi
    if [ "$state" != "migrated" ]; then die "Unexpected state: $state"; fi

    info "Rolling back: removing nft table inet $NFT_TABLE..."
    nft delete table inet "$NFT_TABLE" 2>/dev/null || warn "nft table already gone"

    write_state "rolled-back"

    echo ""
    info "=== Rollback complete ==="
    info "  Reverted to ipset+iptables"
    info "  ipset sets and iptables rules were never removed — traffic still blocked"
    info "  ipset data is current (dual-write kept it fresh during coexistence)"
}

# ================================================================
#  FINALIZE
# ================================================================
do_finalize() {
    local state
    state=$(read_state)
    if [ -z "$state" ]; then die "No migration in progress. Run migrate first."; fi
    if [ "$state" = "finalized" ]; then die "Already finalized."; fi
    if [ "$state" = "rolled-back" ]; then die "Migration was rolled back. Run migrate again first."; fi
    if [ "$state" != "migrated" ]; then die "Unexpected state: $state"; fi

    check_script_nft_capable

    # Verify nft is active and populated
    nft list table inet "$NFT_TABLE" >/dev/null 2>&1 || die "nft table 'inet $NFT_TABLE' not found"
    local nft_v4_count
    nft_v4_count=$(count_nft_elements "$NFT_SET_V4")
    if [ "$nft_v4_count" -eq 0 ]; then die "nft set $NFT_SET_V4 is empty. Populate it before finalizing."; fi

    # --dry-run or missing --enable-service: show what would happen and exit
    if $DRY_RUN || ! $ENABLE_SERVICE; then
        if $DRY_RUN; then
            info "=== Dry run: finalize would perform these actions ==="
        else
            warn "=== --enable-service required to finalize ==="
            warn "Finalize would perform these actions:"
        fi
        echo ""
        local step=1
        info "  $step. Remove iptables DROP rules for $IPSET_V4 / $IPSET_V6"; step=$((step + 1))
        info "  $step. Destroy ipset sets $IPSET_V4 / $IPSET_V6"; step=$((step + 1))
        info "  $step. Save nft table to $NFT_DROP_FILE"; step=$((step + 1))
        info "  $step. Install systemd unit $SYSTEMD_UNIT_FILE"; step=$((step + 1))
        info "  $step. Enable $SYSTEMD_UNIT (loads blacklist table on boot)"; step=$((step + 1))
        info "  $step. Write migration state: finalized"
        echo ""
        local legacy
        legacy=$(grep -rlw 'ipset' /etc/network/if-up.d/ /etc/network/if-pre-up.d/ 2>/dev/null || true)
        if [ -n "$legacy" ]; then
            warn "Found if-up.d scripts that reference ipset — review and disable before finalizing:"
            echo "$legacy" | while read -r f; do warn "  $f"; done
        fi
        warn "Check for other legacy boot scripts (cron @reboot, rc.local, custom"
        warn "scripts) that load ipset — they will fail after ipset is removed."
        echo ""
        if ! $DRY_RUN; then
            info "To proceed:  sudo $0 --finalize --enable-service"
            info "To preview:  sudo $0 --finalize --dry-run"
        fi
        exit 0
    fi

    info "Finalizing..."

    # Step 1: Persist nft BEFORE removing legacy (fail-safe ordering)
    mkdir -p "$NFT_DROP_DIR"
    echo '#!/usr/sbin/nft -f' > "$NFT_DROP_FILE"
    nft list table inet "$NFT_TABLE" >> "$NFT_DROP_FILE"
    info "  Saved blacklist table to $NFT_DROP_FILE"

    cat > "$SYSTEMD_UNIT_FILE" <<'UNIT'
[Unit]
Description=nftables blacklist table
After=ufw.service firewalld.service network-pre.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/nft -f /etc/nftables.d/blacklist.nft
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload
    systemctl enable "$SYSTEMD_UNIT"
    info "  Installed and enabled $SYSTEMD_UNIT"

    # Step 2: Now safe to remove legacy ipset+iptables
    iptables -D INPUT -m set --match-set "$IPSET_V4" src -j DROP 2>/dev/null || true
    ip6tables -D INPUT -m set --match-set "$IPSET_V6" src -j DROP 2>/dev/null || true
    info "  Removed iptables DROP rules"

    if ipset_set_exists "$IPSET_V4"; then
        ipset destroy "$IPSET_V4"
        info "  Destroyed ipset $IPSET_V4"
    fi
    if ipset_set_exists "$IPSET_V6"; then
        ipset destroy "$IPSET_V6"
        info "  Destroyed ipset $IPSET_V6"
    fi

    write_state "finalized"

    echo ""
    info "=== Finalize complete ==="
    info "  ipset sets and iptables rules removed"
    info "  nft table 'inet $NFT_TABLE' is now the sole backend"
    info "  $SYSTEMD_UNIT enabled — blacklist loads on boot"

    # Scan for legacy scripts that reference ipset
    local legacy
    legacy=$(grep -rlw 'ipset' /etc/network/if-up.d/ /etc/network/if-pre-up.d/ 2>/dev/null || true)
    if [ -n "$legacy" ]; then
        echo ""
        warn "Found if-up.d scripts that reference ipset — review and disable:"
        echo "$legacy" | while read -r f; do warn "  $f"; done
    fi
    echo ""
    warn "Check for other legacy boot scripts (cron @reboot, rc.local, custom"
    warn "scripts) that load ipset — they will fail now that ipset sets are gone."
    echo ""
    local backup_ipset
    backup_ipset=$(grep "^BACKUP_IPSET=" "$STATE_FILE" 2>/dev/null | cut -d= -f2)
    if [ -n "$backup_ipset" ] && [ -f "$backup_ipset" ]; then
        info "  Backups preserved at $BACKUP_DIR/ipset-blacklist-*"
        info "  To restore from backup: ipset restore < $backup_ipset"
    fi
}

# ---------------- Dispatch ----------------
case "$MODE" in
    migrate)  do_migrate  ;;
    rollback) do_rollback ;;
    finalize) do_finalize ;;
esac
