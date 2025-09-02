# ipset-blacklist Python Implementation

A fast, enhanced Python implementation inspired by [trick77/ipset-blacklist](https://github.com/trick77/ipset-blacklist).

This is a complete rewrite in Python with no code from the original shell script. It maintains compatibility with the same configuration file format while providing significant enhancements.

## Features

### Core Functionality
- Fetches IP blocklists from URLs or local files
- Normalizes to CIDRs (/32, /128 for hosts)
- **Advanced deduplication**: Removes exact duplicates AND covered subnets (O(N·P) algorithm)
- Generates `ipset restore` files compatible with the original
- Atomic apply with `--apply` flag using temporary sets and swap

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
- **Security**: No shell injection vulnerabilities

## Drop-in Replacement

The Python script is designed as a **drop-in replacement** for the original shell script:

```bash
# Original cron job:
/usr/local/sbin/update-blacklist.sh /etc/ipset-blacklist/ipset-blacklist.conf

# New cron job (just change the script name):
/usr/local/sbin/update_blacklist.py --conf /etc/ipset-blacklist/ipset-blacklist.conf
```

- Reads the **same configuration file** format
- Produces **compatible ipset restore files**
- Supports all original config variables (BLACKLISTS, MAXELEM, HASHSIZE, etc.)
- Adds `--force` flag equivalent to `FORCE=yes` in original

## Requirements

- Python 3.7+
- `ipset` (v6+ recommended)
- `iptables` (and `ip6tables` if using IPv6)
- **No Python packages required** - uses only standard library

## Installation

```bash
# Install the script
sudo install -m 0755 update_blacklist.py /usr/local/sbin/update_blacklist.py

# Install man page
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

- `--dry-run` - Simulate without making changes
- `--force` - Create ipsets/rules if missing (like FORCE=yes)
- `--verbose` / `--quiet` - Control output verbosity
- `--progress` - Show progress bars
- `--collapse` - Additional CIDR aggregation
- `--show-removed` - Report what was deduplicated

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

## License

MIT License - See [LICENSE](LICENSE) file for details.

This is a complete reimplementation in Python with no code from the original shell script.

## Migration from Shell Script

1. **Test first**: Run with `--dry-run` to verify
2. **Compare output**: Check restore file matches expected format
3. **Update cron**: Change `update-blacklist.sh` to `update_blacklist.py`
4. **Keep config**: Same config file works unchanged
5. **Monitor initially**: Check logs after first few runs

The Python version will produce slightly different (better) results due to covered subnet removal, but the format and structure remain fully compatible.