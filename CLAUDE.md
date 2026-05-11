# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Run tests
python3 -m unittest test_update_blacklist -v

# Lint
pylint update_blacklist.py

# Run all tests
python3 -m unittest test_update_blacklist -v

# Run a single test class
python3 -m unittest test_update_blacklist.TestOptimizeFast -v

# Run a single test method
python3 -m unittest test_update_blacklist.TestOptimizeFast.test_covered_subnet_removed -v

# Test dry run (requires root + installed ipset/iptables)
sudo python3 update_blacklist.py --conf /etc/ipset-blacklist/ipset-blacklist.conf --dry-run --verbose

# Run specific feature without network access
sudo python3 update_blacklist.py --analyze blacklist.dump --set blacklist --show-removed

# Deploy (installs to /usr/local/sbin, stamps version from VERSION file)
sudo ./deploy.sh
```

## Dev Setup

```bash
# Activate pre-commit hook (runs tests before each commit)
git config core.hooksPath .githooks
```

## Architecture

Single-file Python script (`update_blacklist.py`) with no third-party dependencies. Python 3.7+, stdlib only. Tests in `test_update_blacklist.py` using `unittest`.

Two operating modes:

**Update mode** (default): Fetches IP blocklists → parses/normalizes → deduplicates → writes ipset restore file → optionally applies atomically via `ipset swap`.

**Analyze mode** (`--analyze FILE`): Reads an existing `ipset save` dump, reports exact duplicates and covered subnets, optionally emits a clean CIDR list.

### Key pipeline stages (update mode)

1. **Config parsing** (`load_conf`) — reads bash-style `BLACKLISTS=(...)` conf via regex (not `bash -c`)
2. **Fetch** (`fetch_source`) — HTTP/HTTPS with 3-attempt exponential backoff; local `file://` paths
3. **Parse** (`parse_entry` / `parse_addr_token`) — handles raw IPs, CIDRs, `add <set> <addr>` lines; normalizes hosts to /32 or /128
4. **Dedup** (`optimize_fast`) — O(N·P) algorithm: for each prefix length P (sorted shortest to longest), removes any network covered by a broader range already in the set; P ≤ 32 for v4, ≤ 128 for v6. Also filters private IPs via `is_private_ip`.
5. **Write** (`write_restore`) — emits `ipset restore`-compatible format with `create` + `add` lines
6. **Apply** (`--apply`) — uses a `-tmp` set name, `ipset restore`, `ipset swap`, then `ipset destroy` on the old set; ensures `iptables`/`ip6tables` `INPUT -m set --match-set` rules exist

### Public API (imported by tests)

`Config`, `analyze_dumpfile`, `apply_nft_batch`, `check_nft_table_valid`, `detect_backend`, `detect_dump_format`, `format_net_str`, `is_private_ip`, `load_conf`, `optimize_fast`, `parse_addr_token`, `parse_entry`, `parse_nft_dump`, `setup_nft_table_script`, `tuple_to_net`, `write_nft_batch`, `write_restore`

### IPv4/IPv6 split

The script maintains separate v4 and v6 network lists throughout. Sets are named `blacklist` (v4, `hash:net`) and `blacklist6` (v6). `--ipv4-only` skips all v6 processing.

### Configuration format

`ipset-blacklist.conf` uses bash variable syntax. The parser extracts values with regex; it does **not** source the file. Supported keys: `IPSET_BLACKLIST_NAME`, `IP_BLACKLIST_RESTORE`, `IP_BLACKLIST`, `BLACKLISTS`, `MAXELEM`, `HASHSIZE`, `VERBOSE`, `FORCE`, `IPTABLES_IPSET_RULE_NUMBER`, `BACKEND`, `NFT_TABLE`, `NFT_SET_V4`, `NFT_SET_V6`.

### Deployment hosts

Config lives at `/etc/ipset-blacklist/ipset-blacklist.conf` on each host. Changes to the config must be applied per-host (not centrally managed).

| Host | ipset-blacklist | GeoIP |
|------|:-:|:--|
| cs | yes | geoipupdate + cron + timer |
| mx | yes | geoipupdate + cron + timer |
| notifications | yes | geoipupdate + cron + timer |
| nx | yes | geoipupdate + cron + timer |
| ux | yes | geoipupdate + cron + timer |
| talon | yes | geoipupdate + cron + timer |
| worf | yes | geoipupdate + cron + timer |
| ws | yes | geoipupdate + cron + timer |
| dev | no | no |
| duo | no | no |
| lamp | no | no |
| mdb | no | no |
| ndao | no | no |
| xt | no | no |

### Private IP filtering

`PRIVATE_NETWORKS` constant lists RFC1918, loopback, link-local, multicast, and IPv6 equivalents. Applied after parsing, before dedup. Disable with `--no-filter-private`.

### nftables backend

Auto-detection prefers nft over ipset during coexistence (after migrate, before finalize). Detection validates table structure via `nft -j` JSON, not just existence. Write-only mode always emits ipset format unless `--backend nft` explicit.

New CLI args: `--backend {ipset,nft,auto}`, `--nft-table`, `--nft-set-v4`, `--nft-set-v6`, `--import-ipset`, `--export-ipset`, `--analyze-format {ipset,nft,auto}`.

New config keys: `BACKEND`, `NFT_TABLE`, `NFT_SET_V4`, `NFT_SET_V6`.

Key functions: `detect_backend`, `check_nft_table_valid`, `write_nft_batch`, `setup_nft_table_script`, `apply_nft_batch`, `parse_nft_dump`, `detect_dump_format`, `format_net_str`.

During coexistence (`migrate-to-nftables.sh` state=migrated), cron dual-writes both nft AND ipset so rollback always has fresh data.

### Config dataclass

`Config` dataclass (15 fields) replaces the old `Dict[str, Any]`. Immutable after construction — `load_conf()` parses the file, `_resolve_config()` merges CLI overrides via `dataclasses.replace()`. All public functions accept `Config` instead of positional args.

### Migration script

`migrate-to-nftables.sh` — standalone bash, three modes: migrate (default), `--rollback`, `--finalize`. State tracked in `/var/lib/ipset-blacklist/migration-state`. Reads set names from `ipset-blacklist.conf` via `--conf`.
