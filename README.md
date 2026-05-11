# ipset-blacklist Python Implementation

A fast, enhanced Python implementation inspired by [trick77/ipset-blacklist](https://github.com/trick77/ipset-blacklist).

This is a complete rewrite in Python with no code from the original shell script. It maintains compatibility with the same configuration file format while providing significant enhancements.

## Features

### Core Functionality
- Fetches IP blocklists from URLs or local files
- Normalizes to CIDRs (/32, /128 for hosts)
- **Advanced deduplication**: Removes exact duplicates AND covered subnets (O(N·P) algorithm)
- Generates `nft` batch files for atomic apply via `nft -f`
- **Import/export** between ipset and nft formats

### Major Enhancements Over Original
- **Smart subnet optimization**: Removes IPs/subnets covered by broader ranges (original only removes exact duplicates)
- **Full IPv6 support** with dual-stack handling (original is IPv4-only)
- **Analysis mode**: Audit existing ipset files for duplicates and covered subnets
- **Dry-run mode**: Test changes without modifying the system
- **Private IP filtering**: Configurable filtering of RFC1918, loopback, multicast ranges
- **Retry logic**: Automatic retry with exponential backoff for network failures
- **Proper logging**: Configurable verbosity levels instead of just echo
- **Progress indicators**: Won't flood SSH connections
- **Configuration validation**: Warns about potential issues
- **Security**: No shell injection vulnerabilities, fail-closed fetch, input validation
- **nftables native**: Uses `nft` interval sets with auto-detection and atomic batch updates

## Drop-in Replacement

The Python script is designed as a **drop-in replacement** for the original shell script:

```bash
# Original cron job:
/usr/local/sbin/update-blacklist.sh /etc/ipset-blacklist/ipset-blacklist.conf

# New cron job (just change the script name):
/usr/local/sbin/update_blacklist.py --conf /etc/ipset-blacklist/ipset-blacklist.conf

# Or use the drop-in wrapper (same name as original):
/usr/local/sbin/update-blacklist.sh /etc/ipset-blacklist/ipset-blacklist.conf
```

- Reads the **same configuration file** format
- Produces **nft batch files** (or ipset restore with `--backend ipset`)
- Supports all original config variables (BLACKLISTS, MAXELEM, HASHSIZE, etc.)
- Adds `--force` flag equivalent to `FORCE=yes` in original
- Includes `update-blacklist.sh` wrapper for cron jobs that call the original script name

## Requirements

- Python 3.7+
- `nftables`
- **No Python packages required** - uses only standard library

## Development

```bash
# Run tests
python3 -m unittest test_update_blacklist -v

# Activate the pre-commit hook (run once after cloning)
git config core.hooksPath .githooks
```

## Installation

```bash
# Automated install (stamps version, installs man page, runs preflight checks)
sudo ./deploy.sh

# Or install manually
sudo install -m 0755 update_blacklist.py /usr/local/sbin/update_blacklist.py
sudo install -d /usr/local/share/man/man8
sudo install -m 0644 update_blacklist.8 /usr/local/share/man/man8/
sudo mandb

# Use existing config from original ipset-blacklist
# Config at: /etc/ipset-blacklist/ipset-blacklist.conf
```

## Basic Usage

### Generate optimized restore file (no changes to firewall)
```bash
sudo update_blacklist.py --conf /etc/ipset-blacklist/ipset-blacklist.conf
```

### Apply to firewall (atomic swap)
```bash
sudo update_blacklist.py --conf /etc/ipset-blacklist/ipset-blacklist.conf --apply
```

### Test mode (dry run)
```bash
sudo update_blacklist.py --conf /etc/ipset-blacklist/ipset-blacklist.conf --dry-run --verbose
```

### IPv4-only mode (like original)
```bash
sudo update_blacklist.py --conf /etc/ipset-blacklist/ipset-blacklist.conf --apply --ipv4-only
```

## New Features

### Analysis Mode

Analyze existing ipset for duplicates and covered subnets:

```bash
# Save current set
sudo ipset save blacklist > blacklist.dump

# Analyze
sudo update_blacklist.py --analyze blacklist.dump --set blacklist --show-removed

# Output:
# Total adds: 77283
# Unique adds: 64715
# Exact duplicates removed: 0
# Covered subnets removed: 12568
```

Extract clean CIDR list:
```bash
sudo update_blacklist.py --analyze blacklist.dump --set blacklist --format cidr > clean.txt
```

### Private IP Filtering

By default, filters RFC1918 and reserved ranges. Disable with:
```bash
sudo update_blacklist.py --conf /etc/ipset-blacklist/ipset-blacklist.conf --no-filter-private
```

### Enhanced Options

- `--version` - Show version number and exit
- `--dry-run` - Simulate without making changes
- `--force` - Create nft table/sets if missing
- `--verbose` / `--quiet` - Control output verbosity
- `--progress` - Show progress bars
- `--collapse` - Additional CIDR aggregation
- `--show-removed` - Report what was deduplicated
- `--allow-partial` - Continue even if >50% of sources fail to fetch
- `--backend {ipset,nft,auto}` - Force a specific firewall backend
- `--nft-table` / `--nft-set-v4` / `--nft-set-v6` - Override nft table/set names
- `--analyze-format {ipset,nft,auto}` - Force parser for `--analyze` input
- `--import-ipset FILE` - Convert ipset dump to nft batch format
- `--export-ipset FILE` - Convert nft JSON dump to ipset restore format

## Cron Setup

Update your cron to use the Python script:

```bash
# /etc/cron.d/update-blacklist
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
MAILTO=root

33 23 * * * root /usr/local/sbin/update_blacklist.py --conf /etc/ipset-blacklist/ipset-blacklist.conf --apply --ipv4-only >/dev/null
```

## Memory Usage

- **100k IPs**: ~35 MB
- **400k IPs**: ~140 MB
- **800k IPs**: ~280 MB
- **1.6M IPs**: ~560 MB

Suitable for any system with 1GB+ RAM.

## Performance

- O(N·P) optimization algorithm (P ≤ 32 for IPv4, ≤ 128 for IPv6)
- Processes 800k entries in seconds
- 3x retry with exponential backoff for reliability
- Progress updates at 5% intervals (SSH-friendly)

## Credits

**Inspiration**: The original [trick77/ipset-blacklist](https://github.com/trick77/ipset-blacklist) shell script provided the concept and configuration format.

**Python implementation by**:
- Kenneth Shane Hartman ([kshartman](https://github.com/kshartman) @ GitHub, shane@ai.mit.edu)
- ChatGPT (OpenAI) - Optimization algorithms and initial implementation
- Claude (Anthropic) - Code improvements and documentation

## Documentation

- `man update_blacklist` — full man page with all options, config keys, and examples (installed by `deploy.sh`)

## License

MIT License - See [LICENSE](LICENSE) file for details.

This is a complete reimplementation in Python with no code from the original shell script.

## Migrating from ipset

See [MIGRATING.md](MIGRATING.md) for the full migration guide, import/export commands, and config keys.