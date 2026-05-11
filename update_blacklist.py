#!/usr/bin/env python3
# pylint: disable=line-too-long,too-many-lines
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
- Supports nftables backend with auto-detection (nft preferred over ipset during coexistence)
- Import/export between ipset and nft formats via --import-ipset / --export-ipset
"""

import argparse
import dataclasses
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
from typing import List, Tuple, Dict, Set, Optional, Union
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


@dataclasses.dataclass
class Config:  # pylint: disable=too-many-instance-attributes
    """Typed configuration for the ipset-blacklist pipeline."""
    blacklists: List[str] = dataclasses.field(default_factory=list)
    hashsize: int = DEFAULT_HASHSIZE
    maxelem: int = DEFAULT_MAXELEM
    timeout: int = DEFAULT_TIMEOUT
    set_v4: str = DEFAULT_SET_V4
    set_v6: str = DEFAULT_SET_V6
    set_tmp_v4: Optional[str] = None
    set_tmp_v6: Optional[str] = None
    out_path: str = DEFAULT_OUT_PATH
    iptables_pos: int = 1
    force: bool = False
    backend: str = "auto"
    nft_table: str = DEFAULT_NFT_TABLE
    nft_set_v4: str = DEFAULT_NFT_SET_V4
    nft_set_v6: str = DEFAULT_NFT_SET_V6


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

def _filter_private(nets: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]
                    ) -> Tuple[List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]], List]:
    """Partition nets into (non-private, removed_records)."""
    filtered, removed = [], []
    for n in nets:
        if is_private_ip(n):
            removed.append((net_to_tuple(n), "private-ip", None))
            logger.debug("Filtering private IP: %s", n)
        else:
            filtered.append(n)
    return filtered, removed


def _dedup_exact(nets: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]],
                 show_progress: bool, interval_pct: float
                 ) -> Tuple[List[Tuple[int, int, int]], List]:
    """Remove exact duplicate networks. Returns (unique_tuples, removed_records)."""
    seen: Set[Tuple[int, int, int]] = set()
    uniques, removed = [], []
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
            next_tick = progress_tick(i, total, "Deduplicating",
                                     next_tick, interval_pct)
    if show_progress and total:
        sys.stderr.write("\n")
    return uniques, removed


def _find_covering_net(vbits: int, addr: int, plen: int,
                       prefix_index: Dict[int, List[Set[int]]]
                       ) -> Optional[Tuple[int, int, int]]:
    """Return the broader tuple that covers (vbits, addr, plen), or None."""
    if plen == 0:
        return None
    max_bits = 32 if vbits == 4 else 128
    idx = prefix_index[vbits]
    for p in range(plen - 1, -1, -1):
        super_addr = addr & mask_for(p, max_bits)
        if super_addr in idx[p]:
            return (vbits, super_addr, p)
    return None


def _remove_covered(uniques: List[Tuple[int, int, int]],
                    show_progress: bool, interval_pct: float
                    ) -> Tuple[List[Tuple[int, int, int]], List]:
    """Remove subnets covered by broader ranges using a prefix index."""
    prefix_index: Dict[int, List[Set[int]]] = {
        4: [set() for _ in range(33)],
        6: [set() for _ in range(129)],
    }
    uniques.sort(key=sort_key_tuple)
    kept, removed = [], []
    total = len(uniques)
    next_tick = 0
    for i, t in enumerate(uniques, 1):
        vbits, addr, plen = t
        covered_by = _find_covering_net(vbits, addr, plen, prefix_index)
        if covered_by:
            removed.append((t, "covered-by-broader", covered_by))
        else:
            kept.append(t)
            prefix_index[vbits][plen].add(addr)
        if show_progress:
            next_tick = progress_tick(i, total, "Removing covered subnets",
                                     next_tick, interval_pct)
    if show_progress and total:
        sys.stderr.write("\n")
    return kept, removed


def optimize_fast(nets: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]],
                  show_progress: bool = False,
                  interval_pct: float = DEFAULT_PROGRESS_INTERVAL,
                  filter_private: bool = True) -> Tuple[List[Tuple[int, int, int]], List[Tuple]]:
    """Remove exact duplicates and covered subnets; return (kept_tuples, removed_records)."""
    removed: List = []
    if filter_private:
        nets, private_removed = _filter_private(nets)
        removed.extend(private_removed)

    nets = sorted(nets, key=sort_key_net)
    uniques, dedup_removed = _dedup_exact(nets, show_progress, interval_pct)
    removed.extend(dedup_removed)

    kept, covered_removed = _remove_covered(uniques, show_progress, interval_pct)
    removed.extend(covered_removed)
    return kept, removed

# ---------------- Conf parsing ----------------
def validate_config(cfg: Config) -> List[str]:
    """Validate configuration and return list of warnings."""
    warnings = []
    out_path = Path(cfg.out_path)
    if not out_path.parent.exists():
        warnings.append(f"Output directory does not exist: {out_path.parent}")
    if cfg.maxelem < 1000:
        warnings.append(f"MAXELEM seems too low: {cfg.maxelem}")
    if cfg.hashsize < 1024:
        warnings.append(f"HASHSIZE seems too low: {cfg.hashsize}")
    if cfg.timeout < 5:
        warnings.append(f"TIMEOUT may be too short: {cfg.timeout}s")
    if not cfg.blacklists:
        warnings.append("No blacklist sources configured")
    if not re.match(r'^[A-Za-z0-9:_-]+$', cfg.set_v4):
        warnings.append(f"Invalid set_v4: {cfg.set_v4}")
    if not re.match(r'^[A-Za-z0-9:_-]+$', cfg.set_v6):
        warnings.append(f"Invalid set_v6: {cfg.set_v6}")
    return warnings

# ---------------- nft backend detection ----------------
def check_nft_table_valid(cfg: Optional[Config] = None) -> bool:
    """Check if nft table exists AND contains expected sets via JSON API."""
    if cfg is None:
        cfg = Config()
    try:
        result = subprocess.run(
            ["nft", "-j", "list", "table", "inet", cfg.nft_table],
            capture_output=True, timeout=10, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return False
    try:
        data = json.loads(result.stdout)
    except (json.JSONDecodeError, ValueError):
        return False
    expected = {cfg.nft_set_v4, cfg.nft_set_v6}
    found: Set[str] = set()
    for item in data.get("nftables", []):
        s = item.get("set")
        if s and s.get("name") in expected:
            found.add(s["name"])
    return expected.issubset(found)


def detect_backend(cfg: Config) -> str:
    """Detect which firewall backend to use.

    Priority:
      0. cfg.backend != "auto" → return it
      1. nft table exists with expected sets → "nft"
      2. ipset set exists → "ipset"
      3. cfg.force + nft binary → "nft"
      4. cfg.force + ipset binary → "ipset"
      5. error
    """
    if cfg.backend != "auto":
        return cfg.backend

    if check_nft_table_valid(cfg):
        return "nft"

    try:
        subprocess.run(["ipset", "list", "-n", cfg.set_v4],
                       capture_output=True, timeout=10, check=True)
        return "ipset"
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        pass

    if cfg.force:
        if shutil.which("nft"):
            return "nft"
        if shutil.which("ipset"):
            return "ipset"

    raise RuntimeError("No supported firewall backend found. "
                       "Install nft or ipset, or use --force to create a new backend.")


_ID_PAT = r'[A-Za-z0-9:_-]+'


def _conf_str(text: str, key: str, pattern: str = r'[^\s#]+') -> Optional[str]:
    """Extract a string config value matching key=pattern from bash-style config."""
    m = re.search(rf'^\s*{key}\s*=\s*({pattern})\s*$', text, re.M)
    return m.group(1) if m else None


def _conf_int(text: str, key: str) -> Optional[int]:
    """Extract an integer config value from bash-style config."""
    m = re.search(rf'^\s*{key}\s*=\s*([0-9]+)\s*$', text, re.M)
    return int(m.group(1)) if m else None


def _parse_blacklists(text: str, cfg: Config) -> None:
    """Parse the BLACKLISTS=( ... ) array into cfg.blacklists."""
    m = re.search(r'^\s*BLACKLISTS\s*=\s*\((.*?)\n\)', text, re.S | re.M)
    if not m:
        return
    for line in m.group(1).split('\n'):
        line = line.split('#')[0].strip()
        if not line:
            continue
        for a, b in re.findall(r'"([^"]+)"|\'([^\']+)\'', line):
            val = (a or b).strip()
            if val:
                cfg.blacklists.append(val)


def _parse_set_names(text: str, cfg: Config) -> None:
    """Parse SET_NAME4/SET_NAME6/IPSET_BLACKLIST_NAME with fallback logic."""
    s4 = _conf_str(text, "SET_NAME4", _ID_PAT)
    s6 = _conf_str(text, "SET_NAME6", _ID_PAT)
    if s4:
        cfg.set_v4 = s4
    if s6:
        cfg.set_v6 = s6
    if not s4 or not s6:
        base = _conf_str(text, "IPSET_BLACKLIST_NAME", _ID_PAT)
        if base:
            if not s4:
                cfg.set_v4 = base
            if not s6:
                cfg.set_v6 = base + "6"


def load_conf(path: str) -> Config:
    """Parse bash-style ipset-blacklist config file into a Config object."""
    cfg = Config()
    if not path:
        return cfg
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        text = f.read()

    _parse_blacklists(text, cfg)

    for attr, key in [("hashsize", "HASHSIZE"), ("maxelem", "MAXELEM"), ("timeout", "TIMEOUT")]:
        val = _conf_int(text, key)
        if val is not None:
            setattr(cfg, attr, val)

    val = _conf_str(text, "IP_BLACKLIST_RESTORE")
    if val:
        cfg.out_path = val

    _parse_set_names(text, cfg)

    ipt_pos = _conf_int(text, "IPTABLES_IPSET_RULE_NUMBER")
    if ipt_pos is not None:
        cfg.iptables_pos = max(1, ipt_pos)

    tmp_name = _conf_str(text, "IPSET_TMP_BLACKLIST_NAME", _ID_PAT)
    if tmp_name:
        cfg.set_tmp_v4 = tmp_name
        cfg.set_tmp_v6 = tmp_name + "6"

    force_val = _conf_str(text, "FORCE", r'yes|no')
    if force_val:
        cfg.force = force_val.lower() == "yes"

    val = _conf_str(text, "BACKEND", r'auto|ipset|nft')
    if val:
        cfg.backend = val
    for attr, key in [("nft_table", "NFT_TABLE"), ("nft_set_v4", "NFT_SET_V4"), ("nft_set_v6", "NFT_SET_V6")]:
        val = _conf_str(text, key, r'[A-Za-z0-9_-]+')
        if val:
            setattr(cfg, attr, val)

    return cfg

# ---------------- Restore writer (IPv6-safe) ----------------
def _restore_lines(families: List[Tuple], hashsize: int, maxelem: int,
                   tmp: bool) -> List[str]:
    """Generate ipset restore command lines for each address family."""
    lines: List[str] = []
    for setname, tmpname, hashtype, family, entries in families:
        if not entries:
            continue
        if tmp:
            lines.append(f"create {tmpname} {hashtype} family {family}"
                         f" hashsize {hashsize} maxelem {maxelem} -exist")
            lines.append(f"flush {tmpname}")
            lines.extend(f"add {tmpname} {n}" for n in entries)
            lines.append(f"create {setname} {hashtype} family {family}"
                         f" hashsize {hashsize} maxelem {maxelem} -exist")
            lines.append(f"swap {tmpname} {setname}")
            lines.append(f"destroy {tmpname}")
        else:
            lines.append(f"create {setname} {hashtype} family {family}"
                         f" hashsize {hashsize} maxelem {maxelem}")
            lines.extend(f"add {setname} {n}" for n in entries)
    return lines


def write_restore(cfg: Config, v4: List[str], v6: List[str],
                  tmp: bool = False, dry_run: bool = False) -> str:
    """Emit ipset-restore commands. Only writes family blocks that have entries."""
    families = [
        (cfg.set_v4, cfg.set_tmp_v4 or f"{cfg.set_v4}-tmp", DEFAULT_HASH_V4, "inet", v4),
        (cfg.set_v6, cfg.set_tmp_v6 or f"{cfg.set_v6}-tmp", DEFAULT_HASH_V6, "inet6", v6),
    ]
    lines = _restore_lines(families, cfg.hashsize, cfg.maxelem, tmp)
    text = "\n".join(lines) + ("\n" if lines else "")
    if dry_run:
        logger.info("[DRY RUN] Would write restore file: %s (v4=%d, v6=%d)",
                    cfg.out_path, len(v4), len(v6))
    else:
        with open(cfg.out_path, "w", encoding="utf-8") as f:
            f.write(text)
        logger.info("Wrote restore file: %s (v4=%d, v6=%d)", cfg.out_path, len(v4), len(v6))
    return text

# ---------------- nft batch writer ----------------
NFT_CHUNK_SIZE = 10000

def write_nft_batch(cfg: Config, v4: List[str], v6: List[str],
                    dry_run: bool = False) -> str:
    """Write an nft batch script that flushes and repopulates sets.

    Elements are chunked into groups of NFT_CHUNK_SIZE to stay within
    netlink buffer limits.
    """
    table = cfg.nft_table
    lines: List[str] = []

    def _add_elements(set_name: str, entries: List[str]) -> None:
        lines.append(f"flush set inet {table} {set_name}")
        for i in range(0, len(entries), NFT_CHUNK_SIZE):
            chunk = entries[i:i + NFT_CHUNK_SIZE]
            elems = ", ".join(chunk)
            lines.append(f"add element inet {table} {set_name} {{ {elems} }}")

    if v4:
        _add_elements(cfg.nft_set_v4, v4)
    if v6:
        _add_elements(cfg.nft_set_v6, v6)

    text = "\n".join(lines) + ("\n" if lines else "")
    if dry_run:
        logger.info("[DRY RUN] Would write nft batch: %s (v4=%d, v6=%d)",
                    cfg.out_path, len(v4), len(v6))
    else:
        with open(cfg.out_path, "w", encoding="utf-8") as f:
            f.write(text)
        logger.info("Wrote nft batch: %s (v4=%d, v6=%d)", cfg.out_path, len(v4), len(v6))
    return text


def setup_nft_table_script(cfg: Optional[Config] = None,
                           ipv4_only: bool = False,
                           ipv6_only: bool = False) -> str:
    """Generate an nft -f script that creates the table, sets, and drop rules."""
    if cfg is None:
        cfg = Config()
    lines = [f"table inet {cfg.nft_table} {{"]
    if not ipv6_only:
        lines.append(f"  set {cfg.nft_set_v4} {{")
        lines.append("    type ipv4_addr")
        lines.append("    flags interval")
        lines.append("  }")
    if not ipv4_only:
        lines.append(f"  set {cfg.nft_set_v6} {{")
        lines.append("    type ipv6_addr")
        lines.append("    flags interval")
        lines.append("  }")
    lines.append("  chain input {")
    lines.append("    type filter hook input priority filter; policy accept;")
    if not ipv6_only:
        lines.append(f"    ip saddr @{cfg.nft_set_v4} drop")
    if not ipv4_only:
        lines.append(f"    ip6 saddr @{cfg.nft_set_v6} drop")
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

# ---------------- Main (sub-functions) ----------------
def _build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    ap = argparse.ArgumentParser(
        description="Python ipset-blacklist with fast optimization, --apply and --analyze.")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    ap.add_argument("--conf", default="/etc/ipset-blacklist/ipset-blacklist.conf",
                    help="Config file.")
    ap.add_argument("--out", default=None,
                    help="Output file; default = IP_BLACKLIST_RESTORE or built-in.")
    ap.add_argument("--progress", action="store_true", help="Show progress to stderr.")
    ap.add_argument("--progress-interval", type=float, default=DEFAULT_PROGRESS_INTERVAL,
                    help="Progress update interval in percent (default 0.5).")
    ap.add_argument("--collapse", action="store_true",
                    help="Collapse adjacent/overlapping networks after optimize.")
    ap.add_argument("--show-removed", action="store_true",
                    help="List removed entries (stderr).")
    ap.add_argument("--extra-source", action="append", default=[],
                    help="Additional source URL/file (repeatable).")
    ap.add_argument("--apply", action="store_true",
                    help="Apply to kernel via ipset restore (atomic swap).")
    ap.add_argument("--force", action="store_true",
                    help="Create ipsets/rules if missing (like FORCE=yes).")
    ap.add_argument("--iptables-pos", type=int, default=None,
                    help="iptables rule insert position (overrides conf).")
    ap.add_argument("--no-write", action="store_true",
                    help="Do not write the restore file.")
    ap.add_argument("--dry-run", action="store_true",
                    help="Simulate actions without making changes.")
    ap.add_argument("--no-filter-private", action="store_true",
                    help="Do not filter private/reserved IP ranges.")
    ap.add_argument("--ipv4-only", action="store_true", help="Ignore IPv6 entirely.")
    ap.add_argument("--ipv6-only", action="store_true", help="Ignore IPv4 entirely.")
    ap.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging.")
    ap.add_argument("--quiet", "-q", action="store_true", help="Suppress non-error output.")
    ap.add_argument("--analyze", metavar="FILE",
                    help="Analyze an ipset/nft dump file for duplicates.")
    ap.add_argument("--analyze-format", choices=["ipset", "nft", "auto"], default="auto",
                    help="Force analyze parser (default: auto-detect).")
    ap.add_argument("--set", dest="sets", action="append", default=[],
                    help="Limit --analyze to this set name (repeatable).")
    ap.add_argument("--format", choices=["add", "cidr"], default="add",
                    help="Output format for emitted lists.")
    ap.add_argument("--backend", choices=["ipset", "nft", "auto"], default=None,
                    help="Force backend (default: auto-detect, or config).")
    ap.add_argument("--nft-table", default=None, help="nft table name.")
    ap.add_argument("--nft-set-v4", default=None, help="nft v4 set name.")
    ap.add_argument("--nft-set-v6", default=None, help="nft v6 set name.")
    ap.add_argument("--import-ipset", metavar="FILE",
                    help="Convert ipset dump to nft batch format.")
    ap.add_argument("--export-ipset", metavar="FILE",
                    help="Convert nft JSON dump to ipset restore format.")
    return ap


def _configure_logging(args: argparse.Namespace) -> None:
    """Set up logging level and handle dry-run flag side effects."""
    if args.quiet:
        logging.basicConfig(level=logging.ERROR, format='%(message)s')
    elif args.verbose:
        logging.basicConfig(level=logging.DEBUG,
                            format='%(asctime)s - %(levelname)s - %(message)s')
    else:
        logging.basicConfig(level=logging.INFO, format='%(message)s')

    if args.dry_run:
        logger.info("[DRY RUN MODE] No changes will be made to the system")
        if not args.apply:
            args.no_write = True


def _run_import(args: argparse.Namespace) -> None:
    """Handle --import-ipset: convert ipset dump to nft batch."""
    nets, totals = analyze_dumpfile(args.import_ipset)
    v4 = [format_net_str(n) for n in nets if n.version == 4]
    v6 = [format_net_str(n) for n in nets if n.version == 6]
    cfg = Config(
        out_path=args.out or "/dev/stdout",
        nft_table=args.nft_table or DEFAULT_NFT_TABLE,
        nft_set_v4=args.nft_set_v4 or DEFAULT_NFT_SET_V4,
        nft_set_v6=args.nft_set_v6 or DEFAULT_NFT_SET_V6,
    )
    write_nft_batch(cfg, v4, v6)
    logger.info("Converted %d entries (v4=%d, v6=%d)",
                totals["adds_total"], len(v4), len(v6))


def _run_export(args: argparse.Namespace) -> None:
    """Handle --export-ipset: convert nft JSON dump to ipset restore."""
    nets, totals = parse_nft_dump(args.export_ipset)
    v4 = [format_net_str(n) for n in nets if n.version == 4]
    v6 = [format_net_str(n) for n in nets if n.version == 6]
    cfg = Config(out_path=args.out or "/dev/stdout")
    write_restore(cfg, v4, v6)
    logger.info("Exported %d entries (v4=%d, v6=%d)",
                totals["adds_total"], len(v4), len(v6))


def _run_analyze(args: argparse.Namespace) -> None:
    """Handle --analyze: audit a dump file for duplicates and covered subnets."""
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

    kept_t, removed = optimize_fast(
        nets, show_progress=args.progress, interval_pct=args.progress_interval,
        filter_private=not args.no_filter_private)

    exact = sum(1 for _, r, _ in removed if r == "exact-duplicate")
    covered = sum(1 for _, r, _ in removed if r == "covered-by-broader")
    private = sum(1 for _, r, _ in removed if r == "private-ip")
    logger.info("Total adds: %d", totals.get("adds_total", 0))
    logger.info("Unique adds: %d", len(kept_t))
    logger.info("Exact duplicates removed: %d", exact)
    logger.info("Covered subnets removed: %d", covered)
    if private > 0:
        logger.info("Private IPs filtered: %d", private)

    if args.show_removed:
        _report_removed(removed)

    kept_t.sort(key=sort_key_tuple)
    if args.format == "cidr":
        for t in kept_t:
            print(format_net_str(tuple_to_net(t)))
    else:
        for t in kept_t:
            print(f"add {format_net_str(tuple_to_net(t))}")


def _report_removed(removed: List) -> None:
    """Print a detailed report of removed entries to the log."""
    by_reason: Dict[str, int] = {}
    logger.info("\n# Removed entries:")
    for t, reason, cov in removed:
        by_reason[reason] = by_reason.get(reason, 0) + 1
        if reason == "exact-duplicate":
            logger.info("# %s  -> removed as exact duplicate", format_network_tuple(t))
        elif reason == "private-ip":
            logger.info("# %s  -> removed as private IP", format_network_tuple(t))
        else:
            logger.info("# %s  -> removed (covered by %s)",
                        format_network_tuple(t), format_network_tuple(cov))
    logger.info("# Totals: exact-duplicate=%d, covered-by-broader=%d, private-ip=%d",
                by_reason.get('exact-duplicate', 0),
                by_reason.get('covered-by-broader', 0),
                by_reason.get('private-ip', 0))


def _cli_overrides(args: argparse.Namespace, cfg: Config) -> Dict[str, object]:
    """Build a dict of CLI overrides to apply on top of the parsed Config."""
    ov: Dict[str, object] = {"force": args.force or cfg.force}
    if args.out:
        ov["out_path"] = args.out
    if args.iptables_pos is not None:
        ov["iptables_pos"] = args.iptables_pos
    if args.extra_source:
        ov["blacklists"] = cfg.blacklists + list(args.extra_source)
    if args.nft_table:
        ov["nft_table"] = args.nft_table
    if args.nft_set_v4:
        ov["nft_set_v4"] = args.nft_set_v4
    if args.nft_set_v6:
        ov["nft_set_v6"] = args.nft_set_v6
    if args.backend:
        ov["backend"] = args.backend
    return ov


def _detect_effective_backend(args: argparse.Namespace, cfg: Config) -> str:
    """Determine the effective backend, running detection when needed."""
    if args.apply or cfg.force:
        try:
            backend = detect_backend(cfg)
        except RuntimeError as e:
            logger.error(str(e))
            sys.exit(2)
        logger.info("Backend: %s", backend)
        return backend
    if cfg.backend == "nft":
        logger.info("Backend: nft (explicit)")
        return "nft"
    if cfg.backend != "auto":
        return cfg.backend
    return "ipset"


def _resolve_config(args: argparse.Namespace) -> Config:
    """Load conf file, merge CLI overrides, detect backend."""
    file_cfg = load_conf(args.conf)
    for w in validate_config(file_cfg):
        logger.warning("Config warning: %s", w)
    if not args.force and file_cfg.force:
        logger.debug("Enabled FORCE mode from config")

    cfg = dataclasses.replace(file_cfg, **_cli_overrides(args, file_cfg))
    backend = _detect_effective_backend(args, cfg)
    cfg = dataclasses.replace(cfg, backend=backend)

    logger.info("Sources: %d", len(cfg.blacklists))
    return cfg


def _fetch_and_optimize(args: argparse.Namespace,
                        cfg: Config) -> Tuple[List[str], List[str], List]:
    """Fetch sources, parse, optimize, format. Returns (v4_strs, v6_strs, removed)."""
    raw_networks: List = []
    sources = cfg.blacklists
    total = len(sources) or 1
    next_tick = 0
    for i, src in enumerate(sources, 1):
        text = fetch_source(src, timeout=cfg.timeout)
        for ln in text.splitlines():
            n = parse_entry(ln)
            if n:
                raw_networks.append(n)
        if args.progress:
            next_tick = progress_tick(i, total, "Fetching sources",
                                     next_tick, args.progress_interval)
    if args.progress and sources:
        sys.stderr.write("\n")

    logger.info("Parsed entries: %d", len(raw_networks))

    kept_t, removed = optimize_fast(
        raw_networks, show_progress=args.progress,
        interval_pct=args.progress_interval,
        filter_private=not args.no_filter_private)

    kept_t.sort(key=sort_key_tuple)
    v4, v6 = _split_families(kept_t, args.collapse)
    if args.ipv4_only:
        v6 = []
    if args.ipv6_only:
        v4 = []
    return v4, v6, removed


def _split_families(kept_t: List[Tuple[int, int, int]],
                    collapse: bool) -> Tuple[List[str], List[str]]:
    """Convert kept tuples to formatted v4/v6 string lists, with optional collapse."""
    if collapse:
        nets = [tuple_to_net(t) for t in kept_t]
        v4_nets = [n for n in nets if isinstance(n, ipaddress.IPv4Network)]
        v6_nets = [n for n in nets if isinstance(n, ipaddress.IPv6Network)]
        merged: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = [
            *ipaddress.collapse_addresses(v4_nets),
            *ipaddress.collapse_addresses(v6_nets),
        ]
        merged.sort(key=sort_key_net)
        v4 = [format_net_str(n) for n in merged if n.version == 4]
        v6 = [format_net_str(n) for n in merged if n.version == 6]
    else:
        v4, v6 = [], []
        for t in kept_t:
            n = tuple_to_net(t)
            if n.version == 4:
                v4.append(format_net_str(n))
            else:
                v6.append(format_net_str(n))
    return v4, v6


def _write_output(args: argparse.Namespace, cfg: Config,
                  v4: List[str], v6: List[str]) -> Tuple[str, str]:
    """Write restore/nft batch files. Returns (restore_text, nft_batch_text)."""
    restore_text = ""
    nft_batch_text = ""

    if cfg.backend == "nft":
        if args.apply or not args.no_write:
            nft_batch_text = write_nft_batch(cfg, v4, v6, dry_run=args.dry_run)
    else:
        if not args.no_write or args.apply:
            restore_text = write_restore(cfg, v4, v6,
                                         tmp=args.apply, dry_run=args.dry_run)

    if cfg.backend == "nft" and args.apply:
        restore_text = _dual_write_ipset(args, cfg, v4, v6)

    return restore_text, nft_batch_text


def _dual_write_ipset(args: argparse.Namespace, cfg: Config,
                      v4: List[str], v6: List[str]) -> str:
    """During nft coexistence, also write ipset restore so rollback has fresh data."""
    try:
        subprocess.run(["ipset", "list", "-n", cfg.set_v4],
                       capture_output=True, timeout=10, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return ""
    logger.info("Dual-write: updating ipset (coexistence mode)")
    ipset_cfg = dataclasses.replace(cfg, out_path=cfg.out_path + ".ipset")
    return write_restore(ipset_cfg, v4, v6, tmp=True, dry_run=args.dry_run)


def _apply_nft(args: argparse.Namespace, cfg: Config,
               nft_batch_text: str, restore_text: str) -> None:
    """Apply nft batch + optional dual-write ipset restore."""
    if not nft_batch_text.strip():
        logger.warning("Nothing to apply (no entries). Skipping nft apply.")
        return

    if cfg.force and not check_nft_table_valid(cfg):
        setup_script = setup_nft_table_script(
            cfg, ipv4_only=args.ipv4_only, ipv6_only=args.ipv6_only)
        logger.info("Creating nft table %s (--force mode)", cfg.nft_table)
        apply_nft_batch(setup_script, dry_run=args.dry_run)

    apply_nft_batch(nft_batch_text, dry_run=args.dry_run)

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
        print("NOTE: nft migration pending on this host. "
              "Run migrate-to-nftables.sh --finalize when ready.",
              file=sys.stderr)


def _apply_ipset(args: argparse.Namespace, cfg: Config,
                 restore_text: str, v4: List[str], v6: List[str]) -> None:
    """Apply ipset restore + ensure iptables rules."""
    if not restore_text.strip():
        logger.warning("Nothing to apply (no entries). Skipping ipset restore.")
        return

    if not args.dry_run and cfg.force:
        _force_create_ipsets(cfg, v4, v6)

    if args.dry_run:
        logger.info("[DRY RUN] Would apply ipset restore with %d lines",
                    len(restore_text.splitlines()))
    else:
        try:
            subprocess.run(["ipset", "restore"], input=restore_text.encode("utf-8"),
                           capture_output=True, check=True, timeout=30)
            logger.info("Successfully applied ipset restore")
        except subprocess.CalledProcessError as e:
            logger.error("ipset restore failed:\n%s",
                         e.stderr.decode("utf-8", "ignore"))
            if not cfg.force:
                logger.error("Hint: Use --force to create missing ipsets")
            sys.exit(2)

    _ensure_iptables_rules(args, cfg, v4, v6)


def _force_create_ipsets(cfg: Config,
                         v4: List[str], v6: List[str]) -> None:
    """Create ipset sets if they don't exist (--force mode)."""
    for setname, family, entries in [(cfg.set_v4, "inet", v4), (cfg.set_v6, "inet6", v6)]:
        if not entries:
            continue
        try:
            subprocess.run(["ipset", "list", "-n", setname],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           check=True)
        except subprocess.CalledProcessError:
            hash_type = DEFAULT_HASH_V4 if family == "inet" else DEFAULT_HASH_V6
            logger.info("Creating ipset %s (--force mode)", setname)
            subprocess.run(["ipset", "create", setname, hash_type,
                           "family", family, "hashsize", str(cfg.hashsize),
                           "maxelem", str(cfg.maxelem)], check=False, timeout=10)


def _ensure_iptables_rules(args: argparse.Namespace, cfg: Config,
                           v4: List[str], v6: List[str]) -> None:
    """Ensure iptables/ip6tables DROP rules exist for non-empty families."""
    ipt_pos = str(cfg.iptables_pos)
    for entries, cmd, setname in [(v4, "iptables", cfg.set_v4), (v6, "ip6tables", cfg.set_v6)]:
        if not entries:
            continue
        check = [cmd, "-C", "INPUT", "-m", "set", "--match-set", setname, "src", "-j", "DROP"]
        insert = [cmd, "-I", "INPUT", ipt_pos, "-m", "set", "--match-set", setname, "src", "-j", "DROP"]
        try:
            existed = ensure_rule(check, insert, dry_run=args.dry_run)
            if not args.dry_run:
                family = "IPv4" if cmd == "iptables" else "IPv6"
                logger.info("%s rule %s", family, "already exists" if existed else "inserted")
        except RuntimeError as e:
            logger.error(str(e))


# ---------------- Main (dispatcher) ----------------
def main():
    """Main entry point for the ipset-blacklist manager."""
    args = _build_parser().parse_args()
    _configure_logging(args)

    if args.import_ipset:
        _run_import(args)
        return
    if args.export_ipset:
        _run_export(args)
        return
    if args.analyze:
        _run_analyze(args)
        return

    cfg = _resolve_config(args)
    v4, v6, removed = _fetch_and_optimize(args, cfg)
    restore_text, nft_batch_text = _write_output(args, cfg, v4, v6)

    if args.show_removed:
        _report_removed(removed)

    if args.apply:
        if cfg.backend == "nft":
            _apply_nft(args, cfg, nft_batch_text, restore_text)
        else:
            _apply_ipset(args, cfg, restore_text, v4, v6)

    logger.info("Done.")


if __name__ == "__main__":
    main()
