# nftables Migration Plan

Migrate `update_blacklist.py` from ipset+iptables to nftables, with automatic backend detection and conversion routines.

## Goal

Use nftables if the `nft` binary is present, fall back to ipset+iptables if not. No config changes required for existing deployments.

## Backend Auto-Detection

Prefer continuity over novelty: if an existing ipset `blacklist` set is found, keep using the ipset backend even if `nft` is installed. This prevents a silent backend switch on the first run after `nft` is installed.

```
auto detection order:
  1. ipset backend  — if ipset set "blacklist" already exists
  2. nft backend    — if nft binary is present
  3. error          — no supported backend found
```

Force a specific backend with `--backend {ipset,nft,auto}` or `BACKEND=nft` in the conf file.

## New CLI Flags

```
--backend {ipset,nft,auto}   default: auto
--nft-table NAME             default: "inet blacklist"
--nft-set-v4 NAME            default: "v4"
--nft-set-v6 NAME            default: "v6"
--export-ipset FILE          dump current nft sets → ipset restore format (rollback)
--import-ipset FILE          import existing ipset save dump → nft sets
```

All existing flags (`--apply`, `--force`, `--dry-run`, `--analyze`, `--conf`, `--ipv4-only`, etc.) continue to work with both backends.

## New Functions

| Function | Purpose |
|---|---|
| `detect_backend()` | Auto-detect: check ipset set existence, then nft binary |
| `write_nft_batch(path, table, set4, set6, v4_nets, v6_nets)` | nft equivalent of `write_restore()`. Emits `flush set` + chunked `add element` lines. |
| `setup_nft_table(table, set4, set6, dry_run)` | First-time `--force` setup. Emits full table+sets+chain via `nft -f`. |
| `apply_nft_batch(path, dry_run)` | Runs `nft -f <path>`. Surfaces stderr on failure. |
| `ensure_nft_chain(table, set4, set6, dry_run)` | Idempotent: creates chain rules if missing. Replaces `ensure_rule()`. |
| `nft_dump_to_networks(path)` | Parses `nft list set` output. State machine over `elements = { ... }` block. |
| `import_ipset_to_nft(dump, table, set4, set6, dry_run)` | Conversion: ipset save → nft sets. Reuses `analyze_dumpfile()` + `write_nft_batch()`. |
| `export_nft_to_ipset(table, set4, set6, out_path, dry_run)` | Rollback: nft sets → ipset restore file. Calls `nft list set`, parses, calls existing `write_restore()`. |

## nftables Design

**Single `inet` table, dual sets** — one `inet` family table handles both v4 and v6. Separate sets are required because `flags interval` sets cannot mix address families.

```
table inet blacklist {
    set v4 {
        type ipv4_addr
        flags interval
        elements = { ... }
    }
    set v6 {
        type ipv6_addr
        flags interval
        elements = { ... }
    }
    chain input {
        type filter hook input priority 0; policy accept;
        ip  saddr @v4 drop
        ip6 saddr @v6 drop
    }
}
```

**Atomicity** — Normal updates (`flush set` + `add element`) never touch chain rules, so there is no traffic gap. This mirrors the current `ipset swap` pattern. Only `--force` (first-time setup) rebuilds the full table.

**Element chunking** — Chunk `add element` at ~10,000 entries per statement to avoid kernel netlink buffer limits at high IP counts.

## `--analyze` Changes

Auto-detect dump format by scanning the first few lines for `elements =` / `type ipv4_addr` / `table `. Dispatch to a new `_parse_nft_dump()` or the existing `_parse_ipset_dump()`. Add `--analyze-format {ipset,nft,auto}` escape hatch.

## `deploy.sh` Changes

Condition pre-flight checks on detected backend:
- nft mode: check for `nft` binary
- ipset mode: check for `ipset` + `iptables` binaries (existing behavior)

## Migration Path for Existing Users

1. Optionally add `BACKEND=nft` to conf (or pass `--backend nft` to force)
2. `--backend nft --force --dry-run` to preview the table definition
3. `--export-ipset /tmp/rollback.restore` before first nft run
4. Run with `--force` to create the table and populate sets
5. Verify, then remove old iptables rules and ipsets manually
6. Update cron entry (identical flags; `BACKEND=nft` in conf is sufficient)

## Risks

- **No true transaction** — `flush set` + `add element` has the same mid-file crash risk as `ipset restore`. Building a `v4_tmp` set + `nft replace rule` would be safer but is significantly more complex; acceptable risk for a cron tool.
- **`delete table` wipes custom rules** — only the `--force` path does this; document clearly.
- **`iptables` may be a nft shim** — on Debian 12+, `iptables` is often `iptables-nft`. Detection must check for the real `ipset` set, not just the binaries.
- **`auto` could switch backends unexpectedly** — mitigated by checking set existence before preferring nft.
