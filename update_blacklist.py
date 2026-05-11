#!/usr/bin/env python3
# pylint: disable=line-too-long,too-many-lines
# pylint: disable=too-many-locals,too-many-branches,too-many-statements
# pylint: disable=too-many-arguments
# The above are disabled because:
# - line-too-long: Some argument descriptions and log messages are clearer when not wrapped
# - too-many-*: This is a CLI tool with complex main() function handling many options
# - too-many-arguments: Required for comprehensive configuration options
"""
Python ipset-blacklist with fast final-list optimization + --apply + --analyze.

- Reads original-style conf (BLACKLISTS, MAXELEM, IPSET_BLACKLIST_NAME, IP_BLACKLIST_RESTORE, etc.)
- Fetches sources (http/https/file), parses IPs/CIDRs, normalizes /32 & /128
- Removes exact duplicates and covered subnets in O(N·P) (P ≤ 32/128)
- Optional collapse aggregation
- Writes ipset-restore file (unless --no-write)
- With --apply: atomically swaps tmp sets into place and ensures iptables/ip6tables rules exist
- With --analyze FILE: analyze an ipset save/restore file for exact dupes & covered subnets; optionally emit clean CIDR list
- IPv4-only environments are handled gracefully: v6 blocks/rules are omitted when there are no v6 entries (or use --ipv4-only)

TODO: Migrate to nftables backend with auto-detection (see NFTABLES_MIGRATION.md).
      Use nft if present and no existing ipset blacklist, otherwise fall back to ipset+iptables.
      Add --backend {ipset,nft,auto}, --export-ipset, --import-ipset flags.
"""

import argparse
import ipaddress
import json
import logging
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, List, Tuple, Dict, Set, Optional, Union
from urllib.parse import urlparse

__version__ = "dev"

# ---------------- Defaults ----------------
DEFAULT_SET_V4   = "blacklist"
DEFAULT_SET_V6   = "blacklist6"
DEFAULT_HASH_V4  = "hash:net"
DEFAULT_HASH_V6  = "hash:net"
DEFAULT_HASHSIZE = 16384
DEFAULT_MAXELEM  = 800000
DEFAULT_TIMEOUT  = 30
DEFAULT_PROGRESS_INTERVAL = 0.5  # percent
DEFAULT_OUT_PATH = "/etc/ipset-blacklist/ip-blacklist.restore"
DEFAULT_MAX_RETRIES = 2  # Total of 3 attempts
DEFAULT_RETRY_DELAYS = [1, 4]  # Exponential backoff in seconds
DEFAULT_NFT_TABLE   = "blacklist"
DEFAULT_NFT_SET_V4  = "v4"
DEFAULT_NFT_SET_V6  = "v6"

# Private IP ranges to filter by default (RFC 1918, loopback, etc.)
PRIVATE_NETWORKS_V4: List[ipaddress.IPv4Network] = [
    ipaddress.IPv4Network("0.0.0.0/8"),      # Current network
    ipaddress.IPv4Network("10.0.0.0/8"),     # Private
    ipaddress.IPv4Network("127.0.0.0/8"),    # Loopback
    ipaddress.IPv4Network("169.254.0.0/16"), # Link-local
    ipaddress.IPv4Network("172.16.0.0/12"),  # Private
    ipaddress.IPv4Network("192.168.0.0/16"), # Private
    ipaddress.IPv4Network("224.0.0.0/4"),    # Multicast
    ipaddress.IPv4Network("240.0.0.0/4"),    # Reserved
]
PRIVATE_NETWORKS_V6: List[ipaddress.IPv6Network] = [
    ipaddress.IPv6Network("::1/128"),        # IPv6 loopback
    ipaddress.IPv6Network("fc00::/7"),       # IPv6 unique local
    ipaddress.IPv6Network("fe80::/10"),      # IPv6 link-local
    ipaddress.IPv6Network("ff00::/8"),       # IPv6 multicast
]

# Configure logging
logger = logging.getLogger('ipset-blacklist')

# ---------------- Regexes ----------------
ADD_LINE_ANY_SET = re.compile(r'^\s*add\s+(\S+)\s+(\S+)\s*$')  # add <set> <addr/cidr>
ADD_LINE         = re.compile(r'^\s*add\s+\S+\s+(\S+)\s*$')    # add <set> <addr/cidr> (addr only)
CIDR_OR_IP       = re.compile(r'^\s*([0-9a-fA-F:.]+(?:/\d{1,3})?)\s*$')
COMMENT          = re.compile(r'^\s*[#;]')

# ---------------- Helpers ----------------
def is_local_path(s: str) -> bool:
    """Return True if s is a local filesystem path (not an http/https URL)."""
    if not s:
        return False
    if "://" not in s:
        return True
    return urlparse(s).scheme in ('', 'file')

def fetch_source(src: str, timeout: int, max_retries: int = DEFAULT_MAX_RETRIES) -> str:
    """Return text from URL or local file. Empty string on fetch errors.

    Args:
        src: URL or file path to fetch
        timeout: Timeout in seconds for network operations
        max_retries: Maximum number of retries for network failures

    Returns:
        Content as string, or empty string on error
    """
    if is_local_path(src):
        path = urlparse(src).path if src.startswith("file://") else src
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                return f.read()
        except OSError as e:
            logger.debug("Failed to read file %s: %s", src, e)
            return ""

    # For HTTPS, ensure certificate verification (urllib default is to verify)
    req = urllib.request.Request(src, headers={"User-Agent":"ipset-blacklist-py"})

    last_error = None
    for attempt in range(max_retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read().decode("utf-8", "ignore")

        except urllib.error.HTTPError as e:
            # Don't retry on 4xx errors (client errors)
            if 400 <= e.code < 500:
                logger.debug("HTTP %d error for %s (not retrying)", e.code, src)
                return ""
            # 5xx errors are retryable
            last_error = e

        except urllib.error.URLError as e:
            # Certificate errors should not be retried (security risk)
            if hasattr(e, 'reason') and 'certificate' in str(e.reason).lower():
                logger.warning("SSL certificate verification failed for %s: %s", src, e.reason)
                return ""
            # Other URLErrors (network issues) are retryable
            last_error = e

        except OSError as e:
            last_error = e

        # Retry logic for retryable errors
        if attempt < max_retries:
            delay = DEFAULT_RETRY_DELAYS[min(attempt, len(DEFAULT_RETRY_DELAYS)-1)]
            logger.debug("Failed to fetch %s (attempt %d/%d): %s. Retrying in %ds",
                        src, attempt+1, max_retries+1, last_error, delay)
            time.sleep(delay)
        else:
            # Final failure after all retries
            logger.debug("Failed to fetch %s after %d attempts: %s", src, attempt+1, last_error)

    return ""

def parse_addr_token(tok: str) -> Optional[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]:
    """Return IPv4/IPv6 network for '1.2.3.0/24' or '1.2.3.4' (host->/32,/128)."""
    try:
        if '/' in tok:
            return ipaddress.ip_network(tok, strict=False)
        ip = ipaddress.ip_address(tok)
        return ipaddress.ip_network(f"{ip}/32" if ip.version == 4 else f"{ip}/128", strict=False)
    except ValueError:
        return None

def parse_entry(line: str) -> Optional[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]:
    """Parse a single line from a source list into a network or None."""
    line = line.strip()
    if not line or COMMENT.match(line):
        return None
    m = ADD_LINE.match(line)
    cidr_m = CIDR_OR_IP.match(line)
    tok = m.group(1) if m else (cidr_m.group(1) if cidr_m else None)
    if not tok:
        return None
    return parse_addr_token(tok)

def mask_for(prefixlen: int, vbits: int) -> int:
    """Return an integer bitmask for the given prefix length."""
    if prefixlen == 0:
        return 0
    return ((1 << vbits) - 1) ^ ((1 << (vbits - prefixlen)) - 1)

def net_to_tuple(n: Union[ipaddress.IPv4Network, ipaddress.IPv6Network]) -> Tuple[int, int, int]:
    """Convert a network object to a (version, addr_int, prefixlen) tuple."""
    if isinstance(n, ipaddress.IPv4Network):
        return (4, int(n.network_address), n.prefixlen)
    return (6, int(n.network_address), n.prefixlen)

def tuple_to_net(t: Tuple[int, int, int]) -> Union[ipaddress.IPv4Network, ipaddress.IPv6Network]:
    """Convert a (version, addr_int, prefixlen) tuple back to a network object."""
    vbits, addr, plen = t
    if vbits == 4:
        ip = ipaddress.IPv4Address(addr)
        return ipaddress.ip_network(f"{ip}/{plen}", strict=False)
    ip = ipaddress.IPv6Address(addr)
    return ipaddress.ip_network(f"{ip}/{plen}", strict=False)

def sort_key_net(n: Union[ipaddress.IPv4Network, ipaddress.IPv6Network]) -> Tuple[int, int, int]:
    """Sort key for network objects: v4 before v6, then by address and prefix."""
    return (0 if n.version == 4 else 1, int(n.network_address), n.prefixlen)

def sort_key_tuple(t: Tuple[int, int, int]) -> Tuple[int, int, int]:
    """Sort key for network tuples: v4 before v6, then by prefix and address."""
    vbits, addr, plen = t
    return (0 if vbits == 4 else 1, plen, addr)

def format_net_str(n: Union[ipaddress.IPv4Network, ipaddress.IPv6Network]) -> str:
    """Format a network: bare address for hosts, CIDR for subnets."""
    if n.prefixlen == (32 if n.version == 4 else 128):
        return str(n.network_address)
    return str(n)

def format_network_tuple(tt: Tuple[int, int, int]) -> str:
    """Format a network tuple for display."""
    return format_net_str(tuple_to_net(tt))

def progress_tick(i: int, total: int, label: str, next_tick: int, interval_pct: float) -> int:
    """Update progress bar, return next threshold tick."""
    if total <= 0:
        return next_tick
    pct = int(i * 100 / total)
    # Only update at reasonable intervals (minimum 5%)
    step = max(5, int(interval_pct))
    if pct >= next_tick:
        sys.stderr.write(f"\r{label}... {pct}%")
        sys.stderr.flush()
        return pct + step
    return next_tick

# ---------------- Optimizer ----------------
def is_private_ip(network: Union[ipaddress.IPv4Network, ipaddress.IPv6Network]) -> bool:
    """Check if a network is in private/reserved IP ranges."""
    if isinstance(network, ipaddress.IPv4Network):
        return any(network.subnet_of(p) or network.supernet_of(p) for p in PRIVATE_NETWORKS_V4)
    return any(network.subnet_of(p) or network.supernet_of(p) for p in PRIVATE_NETWORKS_V6)

def optimize_fast(nets: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]],
                  show_progress: bool = False,
                  interval_pct: float = DEFAULT_PROGRESS_INTERVAL,
                  filter_private: bool = True) -> Tuple[List[Tuple[int, int, int]], List[Tuple]]:
    """Remove exact duplicates and covered subnets; return (kept_tuples, removed_records).

    Args:
        nets: List of IP networks to optimize
        show_progress: Show progress indicators
        interval_pct: Progress update interval in percent
        filter_private: Filter out private/reserved IP ranges

    Returns:
        Tuple of (kept network tuples, removed records with reasons)
    """
    # Filter private IPs if requested
    if filter_private:
        filtered_nets = []
        private_removed = []
        for n in nets:
            if is_private_ip(n):
                t = net_to_tuple(n)
                private_removed.append((t, "private-ip", None))
                logger.debug("Filtering private IP: %s", n)
            else:
                filtered_nets.append(n)
        nets = filtered_nets
    else:
        private_removed = []

    nets = sorted(nets, key=sort_key_net)

    # Exact dedup
    seen, uniques, removed = set(), [], private_removed.copy()
    total = len(nets)
    next_tick = 0
    for i, n in enumerate(nets, 1):
        t = net_to_tuple(n)
        if t in seen:
            removed.append((t, "exact-duplicate", t))
        else:
            seen.add(t)
            uniques.append(t)
        if show_progress:
            next_tick = progress_tick(i, total, "Deduplicating", next_tick, interval_pct)
    if show_progress and total:
        sys.stderr.write("\n")

    # Remove covered subnets using prefix index
    kept = []
    kept_v4 = [set() for _ in range(33)]
    kept_v6 = [set() for _ in range(129)]
    uniques.sort(key=sort_key_tuple)  # broader first
    total = len(uniques)
    next_tick = 0

    for i, t in enumerate(uniques, 1):
        vbits, addr, plen = t
        covered_by = None
        if plen > 0:
            if vbits == 4:
                for p in range(plen - 1, -1, -1):
                    m = mask_for(p, 32)
                    super_addr = addr & m
                    if super_addr in kept_v4[p]:
                        covered_by = (4, super_addr, p)
                        break
            else:
                for p in range(plen - 1, -1, -1):
                    m = mask_for(p, 128)
                    super_addr = addr & m
                    if super_addr in kept_v6[p]:
                        covered_by = (6, super_addr, p)
                        break
        if covered_by:
            removed.append((t, "covered-by-broader", covered_by))
        else:
            kept.append(t)
            if vbits == 4:
                kept_v4[plen].add(addr)
            else:
                kept_v6[plen].add(addr)

        if show_progress:
            next_tick = progress_tick(i, total, "Removing covered subnets", next_tick, interval_pct)
    if show_progress and total:
        sys.stderr.write("\n")
    return kept, removed

# ---------------- Conf parsing ----------------
def validate_config(cfg: Dict[str, Any]) -> List[str]:
    """Validate configuration and return list of warnings."""
    warnings = []

    # Check for valid paths
    out_path = Path(cfg["OUT_PATH"])
    if not out_path.parent.exists():
        warnings.append(f"Output directory does not exist: {out_path.parent}")

    # Check numeric values
    if cfg["MAXELEM"] < 1000:
        warnings.append(f"MAXELEM seems too low: {cfg['MAXELEM']}")
    if cfg["HASHSIZE"] < 1024:
        warnings.append(f"HASHSIZE seems too low: {cfg['HASHSIZE']}")
    if cfg["TIMEOUT"] < 5:
        warnings.append(f"TIMEOUT may be too short: {cfg['TIMEOUT']}s")

    # Check blacklist sources
    if not cfg["BLACKLISTS"]:
        warnings.append("No blacklist sources configured")

    # Check set names
    if not re.match(r'^[A-Za-z0-9:_-]+$', cfg["SET_NAME4"]):
        warnings.append(f"Invalid SET_NAME4: {cfg['SET_NAME4']}")
    if not re.match(r'^[A-Za-z0-9:_-]+$', cfg["SET_NAME6"]):
        warnings.append(f"Invalid SET_NAME6: {cfg['SET_NAME6']}")

    return warnings

# ---------------- nft backend detection ----------------
def check_nft_table_valid(table: str = DEFAULT_NFT_TABLE,
                          set_v4: str = DEFAULT_NFT_SET_V4,
                          set_v6: str = DEFAULT_NFT_SET_V6) -> bool:
    """Check if nft table exists AND contains expected sets via JSON API."""
    try:
        result = subprocess.run(
            ["nft", "-j", "list", "table", "inet", table],
            capture_output=True, timeout=10, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return False
    try:
        data = json.loads(result.stdout)
    except (json.JSONDecodeError, ValueError):
        return False
    expected = {set_v4, set_v6}
    found: Set[str] = set()
    for item in data.get("nftables", []):
        s = item.get("set")
        if s and s.get("name") in expected:
            found.add(s["name"])
    return expected.issubset(found)


def detect_backend(force_backend: str = "auto",
                   set_name: str = DEFAULT_SET_V4,
                   nft_table: str = DEFAULT_NFT_TABLE,
                   nft_set_v4: str = DEFAULT_NFT_SET_V4,
                   nft_set_v6: str = DEFAULT_NFT_SET_V6,
                   force: bool = False) -> str:
    """Detect which firewall backend to use.

    Priority:
      0. force_backend != "auto" → return it
      1. nft table exists with expected sets → "nft"
      2. ipset set exists → "ipset"
      3. --force + nft binary → "nft"
      4. --force + ipset binary → "ipset"
      5. error
    """
    if force_backend != "auto":
        return force_backend

    if check_nft_table_valid(nft_table, nft_set_v4, nft_set_v6):
        return "nft"

    try:
        subprocess.run(["ipset", "list", "-n", set_name],
                       capture_output=True, timeout=10, check=True)
        return "ipset"
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        pass

    if force:
        if shutil.which("nft"):
            return "nft"
        if shutil.which("ipset"):
            return "ipset"

    raise RuntimeError("No supported firewall backend found. "
                       "Install nft or ipset, or use --force to create a new backend.")


def load_conf(path: str) -> Dict[str, Any]:
    """
    Recognized:
      BLACKLISTS=( ... )
      MAXELEM=, HASHSIZE=, TIMEOUT=
      IPSET_BLACKLIST_NAME= (v4 name; v6 defaults to <name>6 unless SET_NAME6 present)
      IPSET_TMP_BLACKLIST_NAME= (temp set name for atomic swap)
      IP_BLACKLIST_RESTORE=
      SET_NAME4=, SET_NAME6=
      IPTABLES_IPSET_RULE_NUMBER=
      FORCE= (yes/no)
      BACKEND= (auto/ipset/nft)
      NFT_TABLE=, NFT_SET_V4=, NFT_SET_V6=
    """
    cfg = {
        "BLACKLISTS": [],
        "HASHSIZE": DEFAULT_HASHSIZE,
        "MAXELEM": DEFAULT_MAXELEM,
        "TIMEOUT": DEFAULT_TIMEOUT,
        "SET_NAME4": DEFAULT_SET_V4,
        "SET_NAME6": DEFAULT_SET_V6,
        "SET_TMP_NAME4": None,
        "SET_TMP_NAME6": None,
        "OUT_PATH": DEFAULT_OUT_PATH,
        "IPTABLES_POS": 1,
        "FORCE": False,
        "BACKEND": "auto",
        "NFT_TABLE": DEFAULT_NFT_TABLE,
        "NFT_SET_V4": DEFAULT_NFT_SET_V4,
        "NFT_SET_V6": DEFAULT_NFT_SET_V6,
    }
    if not path:
        return cfg
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        text = f.read()

    # Find BLACKLISTS array - match until the closing paren on its own line or with trailing content
    m = re.search(r'^\s*BLACKLISTS\s*=\s*\((.*?)\n\)', text, re.S | re.M)
    if m:
        body = m.group(1)
        # Process each line to handle comments properly
        for line in body.split('\n'):
            # Remove comment if present
            line = line.split('#')[0].strip()
            if not line:
                continue
            # Extract quoted strings
            items = re.findall(r'"([^"]+)"|\'([^\']+)\'', line)
            for a, b in items:
                v = a or b
                if v:
                    cfg["BLACKLISTS"].append(v.strip())

    for k in ("HASHSIZE","MAXELEM","TIMEOUT"):
        m = re.search(rf'^\s*{k}\s*=\s*([0-9]+)\s*$', text, re.M)
        if m:
            cfg[k] = int(m.group(1))

    m = re.search(r'^\s*IP_BLACKLIST_RESTORE\s*=\s*([^\s#]+)\s*$', text, re.M)
    if m:
        cfg["OUT_PATH"] = m.group(1)

    m4 = re.search(r'^\s*SET_NAME4\s*=\s*([A-Za-z0-9:_-]+)\s*$', text, re.M)
    m6 = re.search(r'^\s*SET_NAME6\s*=\s*([A-Za-z0-9:_-]+)\s*$', text, re.M)
    if m4:
        cfg["SET_NAME4"] = m4.group(1)
    if m6:
        cfg["SET_NAME6"] = m6.group(1)

    if not m4 or not m6:
        m = re.search(r'^\s*IPSET_BLACKLIST_NAME\s*=\s*([A-Za-z0-9:_-]+)\s*$', text, re.M)
        if m:
            base = m.group(1)
            if not m4:
                cfg["SET_NAME4"] = base
            if not m6:
                cfg["SET_NAME6"] = base + "6"

    m = re.search(r'^\s*IPTABLES_IPSET_RULE_NUMBER\s*=\s*([0-9]+)\s*$', text, re.M)
    if m:
        cfg["IPTABLES_POS"] = max(1, int(m.group(1)))

    # Check for IPSET_TMP_BLACKLIST_NAME
    m = re.search(r'^\s*IPSET_TMP_BLACKLIST_NAME\s*=\s*([A-Za-z0-9:_-]+)\s*$', text, re.M)
    if m:
        cfg["SET_TMP_NAME4"] = m.group(1)
        cfg["SET_TMP_NAME6"] = m.group(1) + "6"  # Assume same pattern

    # Check for FORCE mode
    m = re.search(r'^\s*FORCE\s*=\s*(yes|no)\s*$', text, re.M)
    if m:
        cfg["FORCE"] = m.group(1).lower() == "yes"

    # nft backend config
    m = re.search(r'^\s*BACKEND\s*=\s*(auto|ipset|nft)\s*$', text, re.M)
    if m:
        cfg["BACKEND"] = m.group(1)
    m = re.search(r'^\s*NFT_TABLE\s*=\s*([A-Za-z0-9_-]+)\s*$', text, re.M)
    if m:
        cfg["NFT_TABLE"] = m.group(1)
    m = re.search(r'^\s*NFT_SET_V4\s*=\s*([A-Za-z0-9_-]+)\s*$', text, re.M)
    if m:
        cfg["NFT_SET_V4"] = m.group(1)
    m = re.search(r'^\s*NFT_SET_V6\s*=\s*([A-Za-z0-9_-]+)\s*$', text, re.M)
    if m:
        cfg["NFT_SET_V6"] = m.group(1)

    return cfg

# ---------------- Restore writer (IPv6-safe) ----------------
def write_restore(path: str, set4: str, set6: str, hashsize: int, maxelem: int,
                  v4: List[str], v6: List[str], tmp: bool = False, dry_run: bool = False,
                  set4_tmp: Optional[str] = None, set6_tmp: Optional[str] = None) -> str:
    """
    Emit ipset-restore commands. Only writes family blocks that have entries.
    If tmp=True, do atomic swap via <set>-tmp for the families that have entries.
    """
    lines = []

    if tmp:
        if v4:
            if not set4_tmp:
                set4_tmp = f"{set4}-tmp"
            lines += [
                f"create {set4_tmp} {DEFAULT_HASH_V4} family inet hashsize {hashsize} maxelem {maxelem} -exist",
                f"flush {set4_tmp}",
            ]
            for n in v4:
                lines.append(f"add {set4_tmp} {n}")
            lines += [
                f"create {set4} {DEFAULT_HASH_V4} family inet hashsize {hashsize} maxelem {maxelem} -exist",
                f"swap {set4_tmp} {set4}",
                f"destroy {set4_tmp}",
            ]
        if v6:
            if not set6_tmp:
                set6_tmp = f"{set6}-tmp"
            lines += [
                f"create {set6_tmp} {DEFAULT_HASH_V6} family inet6 hashsize {hashsize} maxelem {maxelem} -exist",
                f"flush {set6_tmp}",
            ]
            for n in v6:
                lines.append(f"add {set6_tmp} {n}")
            lines += [
                f"create {set6} {DEFAULT_HASH_V6} family inet6 hashsize {hashsize} maxelem {maxelem} -exist",
                f"swap {set6_tmp} {set6}",
                f"destroy {set6_tmp}",
            ]
    else:
        if v4:
            lines.append(f"create {set4} {DEFAULT_HASH_V4} family inet hashsize {hashsize} maxelem {maxelem}")
            for n in v4:
                lines.append(f"add {set4} {n}")
        if v6:
            lines.append(f"create {set6} {DEFAULT_HASH_V6} family inet6 hashsize {hashsize} maxelem {maxelem}")
            for n in v6:
                lines.append(f"add {set6} {n}")

    text = "\n".join(lines) + ("\n" if lines else "")
    if not dry_run:
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        logger.info("Wrote restore file: %s (v4=%d, v6=%d)", path, len(v4), len(v6))
    else:
        logger.info("[DRY RUN] Would write restore file: %s (v4=%d, v6=%d)", path, len(v4), len(v6))
    return text

# ---------------- nft batch writer ----------------
NFT_CHUNK_SIZE = 10000

def write_nft_batch(path: str, table: str, set_v4: str, set_v6: str,
                    v4: List[str], v6: List[str], dry_run: bool = False) -> str:
    """Write an nft batch script that flushes and repopulates sets.

    Elements are chunked into groups of NFT_CHUNK_SIZE to stay within
    netlink buffer limits.
    """
    lines: List[str] = []

    def _add_elements(set_name: str, entries: List[str]) -> None:
        lines.append(f"flush set inet {table} {set_name}")
        for i in range(0, len(entries), NFT_CHUNK_SIZE):
            chunk = entries[i:i + NFT_CHUNK_SIZE]
            elems = ", ".join(chunk)
            lines.append(f"add element inet {table} {set_name} {{ {elems} }}")

    if v4:
        _add_elements(set_v4, v4)
    if v6:
        _add_elements(set_v6, v6)

    text = "\n".join(lines) + ("\n" if lines else "")
    if not dry_run:
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        logger.info("Wrote nft batch: %s (v4=%d, v6=%d)", path, len(v4), len(v6))
    else:
        logger.info("[DRY RUN] Would write nft batch: %s (v4=%d, v6=%d)", path, len(v4), len(v6))
    return text


def setup_nft_table_script(table: str = DEFAULT_NFT_TABLE,
                           set_v4: str = DEFAULT_NFT_SET_V4,
                           set_v6: str = DEFAULT_NFT_SET_V6,
                           ipv4_only: bool = False,
                           ipv6_only: bool = False) -> str:
    """Generate an nft -f script that creates the table, sets, and drop rules."""
    lines = [
        f"table inet {table} {{",
    ]
    if not ipv6_only:
        lines.append(f"  set {set_v4} {{")
        lines.append("    type ipv4_addr")
        lines.append("    flags interval")
        lines.append("  }")
    if not ipv4_only:
        lines.append(f"  set {set_v6} {{")
        lines.append("    type ipv6_addr")
        lines.append("    flags interval")
        lines.append("  }")
    lines.append("  chain input {")
    lines.append("    type filter hook input priority filter; policy accept;")
    if not ipv6_only:
        lines.append(f"    ip saddr @{set_v4} drop")
    if not ipv4_only:
        lines.append(f"    ip6 saddr @{set_v6} drop")
    lines.append("  }")
    lines.append("}")
    return "\n".join(lines) + "\n"


def apply_nft_batch(script: str, dry_run: bool = False) -> None:
    """Run an nft batch script via nft -f stdin."""
    if dry_run:
        logger.info("[DRY RUN] Would apply nft batch (%d bytes)", len(script))
        return
    result = subprocess.run(["nft", "-f", "-"], input=script.encode("utf-8"),
                            capture_output=True, timeout=30, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"nft -f failed (rc={result.returncode}): "
                           f"{result.stderr.decode('utf-8', 'ignore').strip()}")
    logger.info("Applied nft batch (%d bytes)", len(script))


# ---------------- Rules ----------------
def ensure_rule(cmd_check: List[str], cmd_insert: List[str], dry_run: bool = False) -> bool:
    """Idempotently ensure an iptables/ip6tables rule exists.

    Args:
        cmd_check: Command list to check if rule exists
        cmd_insert: Command list to insert rule
        dry_run: If True, only simulate

    Returns:
        True if rule already exists, False if it was inserted
    """
    if dry_run:
        logger.info("[DRY RUN] Would check/insert rule: %s", " ".join(cmd_insert))
        return True
    try:
        subprocess.run(cmd_check, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=10)
        return True  # already exists
    except subprocess.CalledProcessError:
        try:
            subprocess.run(cmd_insert, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=10)
            return False  # inserted now
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to insert rule: {' '.join(cmd_insert)}") from e

# ---------------- Analyze dump ----------------
def detect_dump_format(path: str) -> str:
    """Sniff the first ~20 lines to determine if a dump is ipset or nft format."""
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for i, ln in enumerate(f):
            if i >= 20:
                break
            stripped = ln.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped.startswith("{") or stripped.startswith('"nftables"'):
                return "nft"
            if stripped.startswith("add ") or stripped.startswith("create "):
                return "ipset"
            if '"set"' in stripped or '"table"' in stripped:
                return "nft"
    return "unknown"


def parse_nft_dump(path_or_json: str) -> Tuple[List, Dict[str, int]]:
    """Parse nft JSON output (from nft -j list set or file) into networks + totals."""
    totals = {"adds_total": 0}
    nets: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = []
    with open(path_or_json, "r", encoding="utf-8", errors="ignore") as f:
        text = f.read()
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        logger.warning("Failed to parse nft JSON from %s", path_or_json)
        return nets, totals

    for item in data.get("nftables", []):
        s = item.get("set")
        if not s:
            continue
        for elem in s.get("elem", []):
            tok = None
            if isinstance(elem, str):
                tok = elem
            elif isinstance(elem, dict) and "prefix" in elem:
                p = elem["prefix"]
                tok = f"{p.get('addr', '')}/{p.get('len', '')}"
            if tok:
                n = parse_addr_token(tok)
                if n:
                    nets.append(n)
                    totals["adds_total"] += 1
    return nets, totals


def analyze_dumpfile(path: str, sets_filter: Optional[Set[str]] = None) -> Tuple[List, Dict[str, int]]:
    """Parse an ipset save/restore file and return list of networks, plus totals."""
    totals = {"adds_total": 0}
    nets = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for ln in f:
            m = ADD_LINE_ANY_SET.match(ln)
            if not m:
                continue
            set_name, tok = m.group(1), m.group(2)
            if sets_filter and set_name not in sets_filter:
                continue
            n = parse_addr_token(tok)
            if n:
                nets.append(n)
                totals["adds_total"] += 1
    return nets, totals

# ---------------- Main ----------------
def main():
    """Main entry point for the ipset-blacklist manager."""
    ap = argparse.ArgumentParser(description="Python ipset-blacklist with fast optimization, --apply and --analyze.")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    ap.add_argument("--conf", default="/etc/ipset-blacklist/ipset-blacklist.conf", help="Config file.")
    ap.add_argument("--out",  default=None, help="Output ipset-restore file; default = IP_BLACKLIST_RESTORE or built-in.")
    ap.add_argument("--progress", action="store_true", help="Show progress to stderr.")
    ap.add_argument("--progress-interval", type=float, default=DEFAULT_PROGRESS_INTERVAL,
                    help="Progress update interval in percent (default 0.5).")
    ap.add_argument("--collapse", action="store_true", help="Collapse adjacent/overlapping networks after optimize.")
    ap.add_argument("--show-removed", action="store_true", help="List removed entries (stderr).")
    ap.add_argument("--extra-source", action="append", default=[], help="Additional source URL/file (repeatable).")
    ap.add_argument("--apply", action="store_true", help="Apply to kernel via ipset restore (atomic swap) and ensure iptables/ip6tables rules.")
    ap.add_argument("--force", action="store_true", help="Create ipsets and iptables rules if they don't exist (like FORCE=yes in shell script).")
    ap.add_argument("--iptables-pos", type=int, default=None, help="iptables rule insert position (overrides conf).")
    ap.add_argument("--no-write", action="store_true", help="Do not write the restore file (still applies if --apply).")
    ap.add_argument("--dry-run", action="store_true", help="Simulate actions without making changes (implies --no-write unless --apply).")
    ap.add_argument("--no-filter-private", action="store_true", help="Do not filter private/reserved IP ranges.")
    ap.add_argument("--ipv4-only", action="store_true", help="Ignore IPv6 entirely.")
    ap.add_argument("--ipv6-only", action="store_true", help="Ignore IPv4 entirely.")
    ap.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging.")
    ap.add_argument("--quiet", "-q", action="store_true", help="Suppress non-error output.")
    # Analyze mode
    ap.add_argument("--analyze", metavar="FILE", help="Analyze an ipset/nft dump file for duplicates and covered subnets.")
    ap.add_argument("--analyze-format", choices=["ipset","nft","auto"], default="auto", help="Force analyze parser (default: auto-detect).")
    ap.add_argument("--set", dest="sets", action="append", default=[], help="When using --analyze, limit to this set name (repeatable).")
    ap.add_argument("--format", choices=["add","cidr"], default="add", help="When emitting lists (analyze/normal), choose output format.")
    # nft backend options
    ap.add_argument("--backend", choices=["ipset","nft","auto"], default=None, help="Force backend (default: auto-detect, or config BACKEND).")
    ap.add_argument("--nft-table", default=None, help="nft table name (default: config or 'blacklist').")
    ap.add_argument("--nft-set-v4", default=None, help="nft v4 set name (default: config or 'v4').")
    ap.add_argument("--nft-set-v6", default=None, help="nft v6 set name (default: config or 'v6').")
    args = ap.parse_args()

    # Configure logging based on verbosity
    if args.quiet:
        logging.basicConfig(level=logging.ERROR, format='%(message)s')
    elif args.verbose:
        logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
    else:
        logging.basicConfig(level=logging.INFO, format='%(message)s')

    # Dry run implies no-write unless --apply is also specified
    if args.dry_run:
        logger.info("[DRY RUN MODE] No changes will be made to the system")
        if not args.apply:
            args.no_write = True

    # ANALYZE MODE
    if args.analyze:
        dump_fmt = args.analyze_format
        if dump_fmt == "auto":
            dump_fmt = detect_dump_format(args.analyze)
            logger.debug("Auto-detected dump format: %s", dump_fmt)

        if dump_fmt == "nft":
            nets, totals = parse_nft_dump(args.analyze)
        else:
            sets_filter = set(args.sets) if args.sets else None
            nets, totals = analyze_dumpfile(args.analyze, sets_filter=sets_filter)
        if args.ipv4_only:
            nets = [n for n in nets if n.version == 4]
        if args.ipv6_only:
            nets = [n for n in nets if n.version == 6]

        if args.progress:
            logger.info("Parsed adds: %d", totals.get('adds_total', 0))

        kept_t, removed = optimize_fast(nets, show_progress=args.progress, interval_pct=args.progress_interval,
                                        filter_private=not args.no_filter_private)

        exact = sum(1 for _, r, _ in removed if r == "exact-duplicate")
        covered = sum(1 for _, r, _ in removed if r == "covered-by-broader")
        private = sum(1 for _, r, _ in removed if r == "private-ip")
        unique = len(kept_t)
        total_adds = totals.get("adds_total", 0)
        logger.info("Total adds: %d", total_adds)
        logger.info("Unique adds: %d", unique)
        logger.info("Exact duplicates removed: %d", exact)
        logger.info("Covered subnets removed: %d", covered)
        if private > 0:
            logger.info("Private IPs filtered: %d", private)

        if args.show_removed:
            logger.info("\n# Removed entries:")
            for t, reason, cov in removed:
                if reason == "exact-duplicate":
                    logger.info("# %s  -> removed as exact duplicate", format_network_tuple(t))
                elif reason == "private-ip":
                    logger.info("# %s  -> removed as private IP", format_network_tuple(t))
                else:
                    logger.info("# %s  -> removed (covered by %s)", format_network_tuple(t), format_network_tuple(cov))

        kept_t.sort(key=sort_key_tuple)
        if args.format == "cidr":
            for t in kept_t:
                print(format_net_str(tuple_to_net(t)))
        else:
            for t in kept_t:
                print(f"add {format_net_str(tuple_to_net(t))}")
        return

    # NORMAL FLOW (conf-driven)
    cfg = load_conf(args.conf)

    # Validate configuration
    warnings = validate_config(cfg)
    for warning in warnings:
        logger.warning("Config warning: %s", warning)

    # Apply FORCE from config if not overridden by command line
    if not args.force and cfg.get("FORCE"):
        args.force = True
        logger.debug("Enabled FORCE mode from config")

    out_path = args.out or cfg["OUT_PATH"]
    set4, set6 = cfg["SET_NAME4"], cfg["SET_NAME6"]
    hashsize, maxelem = cfg["HASHSIZE"], cfg["MAXELEM"]
    ipt_pos = args.iptables_pos if args.iptables_pos is not None else cfg.get("IPTABLES_POS", 1)
    sources = cfg["BLACKLISTS"] + list(args.extra_source)

    # Resolve nft config (CLI overrides > config > defaults)
    nft_table = args.nft_table or cfg["NFT_TABLE"]
    nft_set_v4 = args.nft_set_v4 or cfg["NFT_SET_V4"]
    nft_set_v6 = args.nft_set_v6 or cfg["NFT_SET_V6"]
    force_backend = args.backend or cfg["BACKEND"]

    # Detect backend only when applying; write-only always uses ipset (D2)
    # unless --backend nft was explicitly set
    backend = "ipset"
    if args.apply or args.force:
        try:
            backend = detect_backend(force_backend=force_backend, set_name=set4,
                                     nft_table=nft_table, nft_set_v4=nft_set_v4,
                                     nft_set_v6=nft_set_v6, force=args.force)
        except RuntimeError as e:
            logger.error(str(e))
            sys.exit(2)
        logger.info("Backend: %s", backend)
    elif force_backend == "nft":
        backend = "nft"
        logger.info("Backend: nft (explicit)")

    logger.info("Sources: %d", len(sources))

    # Fetch & parse
    raw_networks = []
    total = len(sources) or 1
    next_tick = 0
    for i, src in enumerate(sources, 1):
        text = fetch_source(src, timeout=cfg["TIMEOUT"])
        for ln in text.splitlines():
            n = parse_entry(ln)
            if n:
                raw_networks.append(n)
        if args.progress:
            next_tick = progress_tick(i, total, "Fetching sources", next_tick, args.progress_interval)
    if args.progress and sources:
        sys.stderr.write("\n")

    logger.info("Parsed entries: %d", len(raw_networks))

    # Optimize
    kept_t, removed = optimize_fast(raw_networks, show_progress=args.progress, interval_pct=args.progress_interval,
                                    filter_private=not args.no_filter_private)

    # Format final lists
    v4, v6 = [], []
    kept_t.sort(key=sort_key_tuple)

    if args.collapse:
        _pre = [tuple_to_net(t) for t in kept_t]
        _v4 = [n for n in _pre if isinstance(n, ipaddress.IPv4Network)]
        _v6 = [n for n in _pre if isinstance(n, ipaddress.IPv6Network)]
        nets2: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = [
            *ipaddress.collapse_addresses(_v4),
            *ipaddress.collapse_addresses(_v6),
        ]
        nets2.sort(key=sort_key_net)
        for n in nets2:
            if n.version == 4:
                v4.append(format_net_str(n))
            else:
                v6.append(format_net_str(n))
    else:
        for t in kept_t:
            n = tuple_to_net(t)
            if n.version == 4:
                v4.append(format_net_str(n))
            else:
                v6.append(format_net_str(n))

    # Family forcing
    if args.ipv4_only:
        v6 = []
    if args.ipv6_only:
        v4 = []

    # Write output
    restore_text = ""
    nft_batch_text = ""
    set4_tmp = cfg.get("SET_TMP_NAME4")
    set6_tmp = cfg.get("SET_TMP_NAME6")

    if backend == "nft":
        if args.apply:
            nft_batch_text = write_nft_batch(out_path, nft_table, nft_set_v4, nft_set_v6,
                                             v4, v6, dry_run=args.dry_run)
        elif not args.no_write:
            nft_batch_text = write_nft_batch(out_path, nft_table, nft_set_v4, nft_set_v6,
                                             v4, v6, dry_run=args.dry_run)
    else:
        if args.apply:
            restore_text = write_restore(out_path, set4, set6, hashsize, maxelem, v4, v6,
                                        tmp=True, dry_run=args.dry_run, set4_tmp=set4_tmp, set6_tmp=set6_tmp)
        elif not args.no_write:
            restore_text = write_restore(out_path, set4, set6, hashsize, maxelem, v4, v6,
                                        tmp=False, dry_run=args.dry_run)

    # Dual-write during coexistence (D7): if nft is primary, also write ipset
    # so rollback always has fresh data
    if backend == "nft" and args.apply:
        try:
            subprocess.run(["ipset", "list", "-n", set4],
                           capture_output=True, timeout=10, check=True)
            ipset_coexist = True
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            ipset_coexist = False
        if ipset_coexist:
            logger.info("Dual-write: updating ipset (coexistence mode)")
            restore_text = write_restore(out_path + ".ipset", set4, set6, hashsize, maxelem,
                                         v4, v6, tmp=True, dry_run=args.dry_run,
                                         set4_tmp=set4_tmp, set6_tmp=set6_tmp)

    # Removed report (if requested)
    if args.show_removed:
        by_reason = {"exact-duplicate":0, "covered-by-broader":0, "private-ip":0}
        logger.info("\n# Removed entries:")
        for t, reason, cov in removed:
            by_reason[reason] = by_reason.get(reason,0)+1
            if reason == "exact-duplicate":
                logger.info("# %s  -> removed as exact duplicate", format_network_tuple(t))
            elif reason == "private-ip":
                logger.info("# %s  -> removed as private IP", format_network_tuple(t))
            else:
                logger.info("# %s  -> removed (covered by %s)", format_network_tuple(t), format_network_tuple(cov))
        logger.info("# Totals: exact-duplicate=%d, covered-by-broader=%d, private-ip=%d",
                   by_reason.get('exact-duplicate',0),
                   by_reason.get('covered-by-broader',0),
                   by_reason.get('private-ip',0))

    # Progress already logged in write_restore function

    # Apply to kernel
    if args.apply:
        if backend == "nft":
            if not nft_batch_text.strip():
                logger.warning("Nothing to apply (no entries). Skipping nft apply.")
                return

            # Create table/sets if --force and table doesn't exist yet
            if args.force and not check_nft_table_valid(nft_table, nft_set_v4, nft_set_v6):
                setup_script = setup_nft_table_script(nft_table, nft_set_v4, nft_set_v6,
                                                      ipv4_only=args.ipv4_only, ipv6_only=args.ipv6_only)
                logger.info("Creating nft table %s (--force mode)", nft_table)
                apply_nft_batch(setup_script, dry_run=args.dry_run)

            apply_nft_batch(nft_batch_text, dry_run=args.dry_run)

            # Dual-write: also apply ipset restore if coexisting
            if restore_text.strip():
                if args.dry_run:
                    logger.info("[DRY RUN] Would apply ipset restore (dual-write, %d lines)",
                                len(restore_text.splitlines()))
                else:
                    try:
                        subprocess.run(["ipset", "restore"], input=restore_text.encode("utf-8"),
                                       capture_output=True, check=True, timeout=30)
                        logger.info("Dual-write: applied ipset restore")
                    except subprocess.CalledProcessError as e:
                        logger.warning("Dual-write ipset restore failed (non-fatal): %s",
                                       e.stderr.decode("utf-8", "ignore").strip())

        else:
            # ipset backend
            if not restore_text.strip():
                logger.warning("Nothing to apply (no entries). Skipping ipset restore.")
                return

            # Check if sets exist, create if --force
            if not args.dry_run and args.force:
                for setname, family in [(set4, "inet"), (set6, "inet6")]:
                    if (setname == set4 and not v4) or (setname == set6 and not v6):
                        continue
                    try:
                        subprocess.run(["ipset", "list", "-n", setname],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
                    except subprocess.CalledProcessError:
                        logger.info("Creating ipset %s (--force mode)", setname)
                        subprocess.run(["ipset", "create", setname,
                                       DEFAULT_HASH_V4 if family == "inet" else DEFAULT_HASH_V6,
                                       "family", family, "hashsize", str(hashsize),
                                       "maxelem", str(maxelem)], check=False)

            if args.dry_run:
                logger.info("[DRY RUN] Would apply ipset restore with %d lines",
                            len(restore_text.splitlines()))
            else:
                try:
                    subprocess.run(["ipset", "restore"], input=restore_text.encode("utf-8"),
                                   capture_output=True, check=True, timeout=30)
                    logger.info("Successfully applied ipset restore")
                except subprocess.CalledProcessError as e:
                    logger.error("ipset restore failed:\n%s", e.stderr.decode("utf-8", "ignore"))
                    if not args.force:
                        logger.error("Hint: Use --force to create missing ipsets")
                    sys.exit(2)

            # Only ensure iptables rules for non-empty families
            if v4:
                v4_check = ["iptables", "-C", "INPUT", "-m", "set", "--match-set", set4, "src", "-j", "DROP"]
                v4_insert = ["iptables", "-I", "INPUT", str(ipt_pos), "-m", "set", "--match-set", set4, "src", "-j", "DROP"]
                try:
                    existed = ensure_rule(v4_check, v4_insert, dry_run=args.dry_run)
                    if not args.dry_run:
                        logger.info("IPv4 rule %s", "already exists" if existed else "inserted")
                except RuntimeError as e:
                    logger.error(str(e))

            if v6:
                v6_check = ["ip6tables", "-C", "INPUT", "-m", "set", "--match-set", set6, "src", "-j", "DROP"]
                v6_insert = ["ip6tables", "-I", "INPUT", str(ipt_pos), "-m", "set", "--match-set", set6, "src", "-j", "DROP"]
                try:
                    existed = ensure_rule(v6_check, v6_insert, dry_run=args.dry_run)
                    if not args.dry_run:
                        logger.info("IPv6 rule %s", "already exists" if existed else "inserted")
                except RuntimeError as e:
                    logger.error(str(e))

    logger.info("Done.")

if __name__ == "__main__":
    main()
