#!/bin/bash
#
# migrate-to-nftables.sh — three-phase migration from ipset+iptables to nftables
#
# Usage:
#   sudo ./migrate-to-nftables.sh [--conf PATH]            # migrate (create nft alongside ipset)
#   sudo ./migrate-to-nftables.sh --rollback [--conf PATH]  # remove nft, revert to ipset
#   sudo ./migrate-to-nftables.sh --finalize [--conf PATH]  # remove ipset+iptables, nft only
#
# State is tracked in /var/lib/ipset-blacklist/migration-state.
# Backups are written to /var/backups/ipset-blacklist-*.

set -euo pipefail

# ---------------- Defaults ----------------
STATE_DIR="/var/lib/ipset-blacklist"
STATE_FILE="$STATE_DIR/migration-state"
BACKUP_DIR="/var/backups"
CONF_FILE="/etc/ipset-blacklist/ipset-blacklist.conf"

NFT_TABLE="blacklist"
NFT_SET_V4="v4"
NFT_SET_V6="v6"
IPSET_V4="blacklist"
IPSET_V6="blacklist6"

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

load_conf() {
    [ ! -f "$CONF_FILE" ] && return
    local val
    val=$(grep -E '^\s*IPSET_BLACKLIST_NAME\s*=' "$CONF_FILE" 2>/dev/null | sed 's/.*=\s*//' | tr -d '[:space:]')
    if [ -n "$val" ]; then
        IPSET_V4="$val"
        IPSET_V6="${val}6"
    fi
    val=$(grep -E '^\s*SET_NAME4\s*=' "$CONF_FILE" 2>/dev/null | sed 's/.*=\s*//' | tr -d '[:space:]')
    [ -n "$val" ] && IPSET_V4="$val"
    val=$(grep -E '^\s*SET_NAME6\s*=' "$CONF_FILE" 2>/dev/null | sed 's/.*=\s*//' | tr -d '[:space:]')
    [ -n "$val" ] && IPSET_V6="$val"
    val=$(grep -E '^\s*NFT_TABLE\s*=' "$CONF_FILE" 2>/dev/null | sed 's/.*=\s*//' | tr -d '[:space:]')
    [ -n "$val" ] && NFT_TABLE="$val"
    val=$(grep -E '^\s*NFT_SET_V4\s*=' "$CONF_FILE" 2>/dev/null | sed 's/.*=\s*//' | tr -d '[:space:]')
    [ -n "$val" ] && NFT_SET_V4="$val"
    val=$(grep -E '^\s*NFT_SET_V6\s*=' "$CONF_FILE" 2>/dev/null | sed 's/.*=\s*//' | tr -d '[:space:]')
    [ -n "$val" ] && NFT_SET_V6="$val"
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
    ipset list "$1" 2>/dev/null | grep -cE '^\d' || echo 0
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
        --rollback) MODE="rollback"; shift ;;
        --finalize) MODE="finalize"; shift ;;
        --conf)     CONF_FILE="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 [--rollback|--finalize] [--conf PATH]"
            echo ""
            echo "Modes:"
            echo "  (default)   Create nft table alongside ipset (coexistence)"
            echo "  --rollback  Remove nft table, revert to ipset only"
            echo "  --finalize  Remove ipset+iptables, keep nft only"
            exit 0
            ;;
        *) die "Unknown option: $1" ;;
    esac
done

# ---------------- Pre-flight ----------------
[ "$EUID" -ne 0 ] && die "Must run as root"
load_conf

# ================================================================
#  MIGRATE
# ================================================================
do_migrate() {
    command -v nft  >/dev/null 2>&1 || die "nft binary not found. Install nftables first."
    command -v ipset >/dev/null 2>&1 || die "ipset binary not found."
    ipset_set_exists "$IPSET_V4" || die "ipset set '$IPSET_V4' not found. Nothing to migrate."

    local state
    state=$(read_state)
    [ "$state" = "migrated" ] && die "Already migrated. Run --finalize or --rollback."
    [ "$state" = "finalized" ] && die "Already finalized. nft is the active backend."

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
    info "    sudo $0 --finalize"
    info "  - To undo: sudo $0 --rollback"
}

# ================================================================
#  ROLLBACK
# ================================================================
do_rollback() {
    local state
    state=$(read_state)
    [ -z "$state" ] && die "No migration in progress. Nothing to rollback."
    [ "$state" = "finalized" ] && die "Cannot rollback after finalize. Restore from backup manually."
    [ "$state" = "rolled-back" ] && die "Already rolled back."
    [ "$state" != "migrated" ] && die "Unexpected state: $state"

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
    [ -z "$state" ] && die "No migration in progress. Run migrate first."
    [ "$state" = "finalized" ] && die "Already finalized."
    [ "$state" = "rolled-back" ] && die "Migration was rolled back. Run migrate again first."
    [ "$state" != "migrated" ] && die "Unexpected state: $state"

    # Verify nft is active and populated
    nft list table inet "$NFT_TABLE" >/dev/null 2>&1 || die "nft table 'inet $NFT_TABLE' not found"
    local nft_v4_count
    nft_v4_count=$(count_nft_elements "$NFT_SET_V4")
    [ "$nft_v4_count" -eq 0 ] && die "nft set $NFT_SET_V4 is empty. Populate it before finalizing."

    info "Finalizing: removing ipset+iptables..."

    # Remove iptables rules (ignore errors — rules may already be gone)
    iptables -D INPUT -m set --match-set "$IPSET_V4" src -j DROP 2>/dev/null || true
    ip6tables -D INPUT -m set --match-set "$IPSET_V6" src -j DROP 2>/dev/null || true
    info "  Removed iptables DROP rules"

    # Destroy ipset sets
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
