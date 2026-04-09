# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Lint
pylint update_blacklist.py

# Test dry run (requires root + installed ipset/iptables)
sudo python3 update_blacklist.py --conf /etc/ipset-blacklist/ipset-blacklist.conf --dry-run --verbose

# Run specific feature without network access
sudo python3 update_blacklist.py --analyze blacklist.dump --set blacklist --show-removed

# Deploy (installs to /usr/local/sbin)
sudo ./deploy.sh
```

## Architecture

Single-file Python script (`update_blacklist.py`) with no third-party dependencies. Two operating modes:

**Update mode** (default): Fetches IP blocklists → parses/normalizes → deduplicates → writes ipset restore file → optionally applies atomically via `ipset swap`.

**Analyze mode** (`--analyze FILE`): Reads an existing `ipset save` dump, reports exact duplicates and covered subnets, optionally emits a clean CIDR list.

### Key pipeline stages (update mode)

1. **Config parsing** — reads bash-style `BLACKLISTS=(...)` conf via regex (not `bash -c`)
2. **Fetch** (`fetch_source`) — HTTP/HTTPS with 3-attempt exponential backoff; local `file://` paths
3. **Parse** (`parse_entry`) — handles raw IPs, CIDRs, `add <set> <addr>` lines; normalizes hosts to /32 or /128
4. **Dedup** (`remove_covered`) — O(N·P) algorithm: for each prefix length P (sorted shortest to longest), removes any network covered by a broader range already in the set; P ≤ 32 for v4, ≤ 128 for v6
5. **Write** — emits `ipset restore`-compatible format with `create` + `add` lines
6. **Apply** (`--apply`) — uses a `-tmp` set name, `ipset restore`, `ipset swap`, then `ipset destroy` on the old set; ensures `iptables`/`ip6tables` `INPUT -m set --match-set` rules exist

### IPv4/IPv6 split

The script maintains separate v4 and v6 network lists throughout. Sets are named `blacklist` (v4, `hash:net`) and `blacklist6` (v6). `--ipv4-only` skips all v6 processing.

### Configuration format

`ipset-blacklist.conf` uses bash variable syntax. The parser extracts values with regex; it does **not** source the file. Supported keys: `IPSET_BLACKLIST_NAME`, `IP_BLACKLIST_RESTORE`, `IP_BLACKLIST`, `BLACKLISTS`, `MAXELEM`, `HASHSIZE`, `VERBOSE`, `FORCE`, `IPTABLES_IPSET_RULE_NUMBER`.

### Private IP filtering

`PRIVATE_NETWORKS` constant lists RFC1918, loopback, link-local, multicast, and IPv6 equivalents. Applied after parsing, before dedup. Disable with `--no-filter-private`.
