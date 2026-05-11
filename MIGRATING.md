# Migrating from ipset+iptables to nftables

This guide covers migrating hosts that currently use ipset+iptables to the nftables backend.

## Prerequisites

- Python 3.7+, nftables installed
- Existing ipset-blacklist deployment with `ipset-blacklist.conf`
- Root access

## Overview

The migration is three phases: **migrate** (both backends coexist), **monitor**, **finalize** (ipset removed). You can roll back at any point before finalize.

During coexistence, `update_blacklist.py` auto-detects nft and dual-writes both backends on every cron run, keeping ipset data fresh for rollback.

## Step 1: Migrate

Creates an nft table alongside the existing ipset sets. Existing iptables rules stay in place.

```bash
sudo ./migrate-to-nftables.sh --conf /etc/ipset-blacklist/ipset-blacklist.conf
```

This will:
- Back up current ipset sets and iptables rules to `/var/backups/`
- Create `inet blacklist` nft table with interval sets
- Populate nft sets from current ipset data
- Record state in `/var/lib/ipset-blacklist/migration-state`

Cron jobs keep running unchanged — `update_blacklist.py` auto-detects the nft table and writes to both backends.

## Step 2: Monitor

Let it run for a few cron cycles. Verify nft is being used:

```bash
# Check nft table
sudo nft list table inet blacklist

# Check cron logs
grep update_blacklist /var/log/syslog
```

## Step 3: Finalize (or rollback)

```bash
# When confident — removes ipset sets and iptables rules:
sudo ./migrate-to-nftables.sh --finalize --enable-service

# Preview what finalize will do:
sudo ./migrate-to-nftables.sh --finalize --dry-run

# Or revert — removes nft table, ipset resumes:
sudo ./migrate-to-nftables.sh --rollback
```

After finalize, ipset is gone. Backups are preserved in `/var/backups/`.

## Converting data

```bash
# Convert an ipset dump to nft batch format
sudo update_blacklist.py --import-ipset blacklist.dump --out blacklist.nft

# Convert nft JSON dump to ipset restore format
sudo update_blacklist.py --export-ipset nft-dump.json --out blacklist.restore
```

## Forcing a backend

Auto-detection (`--backend auto`, the default) checks for an nft table first, then falls back to ipset. Override with:

```bash
# Force nft
sudo update_blacklist.py --conf /etc/ipset-blacklist/ipset-blacklist.conf --backend nft --apply

# Force ipset
sudo update_blacklist.py --conf /etc/ipset-blacklist/ipset-blacklist.conf --backend ipset --apply
```

Or set `BACKEND=nft` in `ipset-blacklist.conf`.

## Config keys

| Key | Default | Description |
|-----|---------|-------------|
| `BACKEND` | `auto` | `auto`, `nft`, or `ipset` |
| `NFT_TABLE` | `blacklist` | nft table name |
| `NFT_SET_V4` | `v4` | nft IPv4 set name |
| `NFT_SET_V6` | `v6` | nft IPv6 set name |

## State file

Migration state is tracked in `/var/lib/ipset-blacklist/migration-state`:

```
STATE=migrated|finalized|rolled-back
DATE=2026-05-10T14:30:00
BACKUP_IPSET=/var/backups/ipset-blacklist-20260510.dump
BACKUP_IPTABLES=/var/backups/iptables-20260510.rules
```
