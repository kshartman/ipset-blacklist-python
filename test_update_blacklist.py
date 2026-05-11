#!/usr/bin/env python3
"""Unit tests for update_blacklist.py — parsing, dedup, config, restore output."""

import ipaddress
import json
import subprocess
import tempfile
import textwrap
import unittest

from unittest import mock

from update_blacklist import (
    Config,
    DEFAULT_NFT_SET_V4,
    DEFAULT_NFT_SET_V6,
    DEFAULT_NFT_TABLE,
    NFT_CHUNK_SIZE,
    __version__,
    analyze_dumpfile,
    apply_nft_batch,
    check_nft_table_valid,
    detect_backend,
    detect_dump_format,
    ensure_rule,
    fetch_source,
    format_net_str,
    is_local_path,
    is_private_ip,
    load_conf,
    optimize_fast,
    parse_addr_token,
    parse_entry,
    parse_nft_dump,
    setup_nft_table_script,
    write_nft_batch,
    write_restore,
)

# ---------------------------------------------------------------------------
# is_local_path
# ---------------------------------------------------------------------------
class TestIsLocalPath(unittest.TestCase):

    def test_plain_path(self):
        self.assertTrue(is_local_path("/etc/ipset-blacklist/custom.list"))

    def test_relative_path(self):
        self.assertTrue(is_local_path("blocklist.txt"))

    def test_file_url(self):
        self.assertTrue(is_local_path("file:///etc/ipset-blacklist/custom.list"))

    def test_http_url(self):
        self.assertFalse(is_local_path("http://example.com/list.txt"))

    def test_https_url(self):
        self.assertFalse(is_local_path("https://example.com/list.txt"))

    def test_empty_string(self):
        self.assertFalse(is_local_path(""))


# ---------------------------------------------------------------------------
# parse_addr_token
# ---------------------------------------------------------------------------
class TestParseAddrToken(unittest.TestCase):

    def test_ipv4_host(self):
        n = parse_addr_token("1.2.3.4")
        self.assertEqual(str(n), "1.2.3.4/32")

    def test_ipv4_cidr(self):
        n = parse_addr_token("10.0.0.0/8")
        self.assertEqual(str(n), "10.0.0.0/8")

    def test_ipv4_host_with_bits_set(self):
        # strict=False — host bits are masked
        n = parse_addr_token("10.1.2.3/8")
        self.assertEqual(str(n), "10.0.0.0/8")

    def test_ipv6_host(self):
        n = parse_addr_token("2001:db8::1")
        self.assertEqual(str(n), "2001:db8::1/128")

    def test_ipv6_cidr(self):
        n = parse_addr_token("2001:db8::/32")
        self.assertEqual(str(n), "2001:db8::/32")

    def test_garbage_returns_none(self):
        self.assertIsNone(parse_addr_token("not-an-ip"))

    def test_empty_returns_none(self):
        self.assertIsNone(parse_addr_token(""))


# ---------------------------------------------------------------------------
# parse_entry
# ---------------------------------------------------------------------------
class TestParseEntry(unittest.TestCase):

    def test_bare_ip(self):
        self.assertEqual(str(parse_entry("1.2.3.4")), "1.2.3.4/32")

    def test_cidr_line(self):
        self.assertEqual(str(parse_entry("192.168.1.0/24")), "192.168.1.0/24")

    def test_ipset_add_line(self):
        self.assertEqual(str(parse_entry("add blacklist 5.6.7.8")), "5.6.7.8/32")

    def test_ipset_add_cidr(self):
        self.assertEqual(str(parse_entry("add myset 203.0.113.0/24")), "203.0.113.0/24")

    def test_comment_hash(self):
        self.assertIsNone(parse_entry("# this is a comment"))

    def test_comment_semicolon(self):
        self.assertIsNone(parse_entry("; another comment"))

    def test_blank_line(self):
        self.assertIsNone(parse_entry(""))
        self.assertIsNone(parse_entry("   "))

    def test_garbage(self):
        self.assertIsNone(parse_entry("not valid at all"))

    def test_leading_whitespace(self):
        self.assertEqual(str(parse_entry("  1.2.3.4  ")), "1.2.3.4/32")

    def test_ipv6_host(self):
        self.assertEqual(str(parse_entry("2001:db8::1")), "2001:db8::1/128")

    def test_ipv6_add_line(self):
        self.assertEqual(str(parse_entry("add bl6 2001:db8::/32")), "2001:db8::/32")


# ---------------------------------------------------------------------------
# is_private_ip
# ---------------------------------------------------------------------------
class TestIsPrivateIp(unittest.TestCase):

    def _net(self, s):
        return ipaddress.ip_network(s, strict=False)

    # IPv4 private
    def test_rfc1918_10(self):
        self.assertTrue(is_private_ip(self._net("10.0.0.1")))

    def test_rfc1918_172(self):
        self.assertTrue(is_private_ip(self._net("172.16.0.0/12")))

    def test_rfc1918_192(self):
        self.assertTrue(is_private_ip(self._net("192.168.1.1")))

    def test_loopback(self):
        self.assertTrue(is_private_ip(self._net("127.0.0.1")))

    def test_link_local(self):
        self.assertTrue(is_private_ip(self._net("169.254.0.1")))

    def test_multicast(self):
        self.assertTrue(is_private_ip(self._net("224.0.0.1")))

    def test_reserved(self):
        self.assertTrue(is_private_ip(self._net("240.0.0.1")))

    def test_subnet_of_private(self):
        # 192.168.5.0/24 is a subnet of 192.168.0.0/16
        self.assertTrue(is_private_ip(self._net("192.168.5.0/24")))

    def test_public_ipv4(self):
        self.assertFalse(is_private_ip(self._net("8.8.8.8")))

    def test_public_cidr(self):
        self.assertFalse(is_private_ip(self._net("203.0.113.0/24")))

    # IPv6 private
    def test_ipv6_loopback(self):
        self.assertTrue(is_private_ip(self._net("::1")))

    def test_ipv6_unique_local(self):
        self.assertTrue(is_private_ip(self._net("fc00::1")))

    def test_ipv6_link_local(self):
        self.assertTrue(is_private_ip(self._net("fe80::1")))

    def test_ipv6_multicast(self):
        self.assertTrue(is_private_ip(self._net("ff02::1")))

    def test_public_ipv6(self):
        self.assertFalse(is_private_ip(self._net("2001:db8::1")))


# ---------------------------------------------------------------------------
# optimize_fast
# ---------------------------------------------------------------------------
class TestOptimizeFast(unittest.TestCase):

    def _nets(self, *cidrs):
        return [ipaddress.ip_network(c, strict=False) for c in cidrs]

    def _kept_strs(self, nets, **kwargs):
        from update_blacklist import tuple_to_net
        kept, _ = optimize_fast(nets, **kwargs)
        return {str(tuple_to_net(t)) for t in kept}

    def test_exact_duplicate_removed(self):
        nets = self._nets("1.2.3.4/32", "1.2.3.4/32")
        kept, removed = optimize_fast(nets, filter_private=False)
        self.assertEqual(len(kept), 1)
        reasons = [r[1] for r in removed]
        self.assertIn("exact-duplicate", reasons)

    def test_covered_subnet_removed(self):
        # 1.0.0.0/8 covers 1.2.3.0/24
        nets = self._nets("1.0.0.0/8", "1.2.3.0/24")
        kept_s = self._kept_strs(nets, filter_private=False)
        self.assertIn("1.0.0.0/8", kept_s)
        self.assertNotIn("1.2.3.0/24", kept_s)

    def test_broader_covered_by_narrower_not_removed(self):
        # The /8 is broader; the /24 should be removed, not the /8
        nets = self._nets("1.0.0.0/8", "1.2.3.0/24")
        kept_s = self._kept_strs(nets, filter_private=False)
        self.assertIn("1.0.0.0/8", kept_s)

    def test_disjoint_nets_both_kept(self):
        nets = self._nets("1.2.3.0/24", "5.6.7.0/24")
        kept_s = self._kept_strs(nets, filter_private=False)
        self.assertEqual(kept_s, {"1.2.3.0/24", "5.6.7.0/24"})

    def test_private_filtered_by_default(self):
        nets = self._nets("10.0.0.1", "8.8.8.8")
        kept_s = self._kept_strs(nets)
        self.assertNotIn("10.0.0.1/32", kept_s)
        self.assertIn("8.8.8.8/32", kept_s)

    def test_private_filter_disabled(self):
        nets = self._nets("10.0.0.1", "8.8.8.8")
        kept_s = self._kept_strs(nets, filter_private=False)
        self.assertIn("10.0.0.1/32", kept_s)

    def test_removed_reason_covered(self):
        nets = self._nets("1.0.0.0/8", "1.2.3.4/32")
        _, removed = optimize_fast(nets, filter_private=False)
        reasons = [r[1] for r in removed]
        self.assertIn("covered-by-broader", reasons)

    def test_ipv6_exact_duplicate(self):
        nets = self._nets("2001:db8::/32", "2001:db8::/32")
        kept, _ = optimize_fast(nets, filter_private=False)
        self.assertEqual(len(kept), 1)

    def test_ipv6_covered_subnet(self):
        nets = self._nets("2001:db8::/32", "2001:db8:1::/48")
        kept_s = self._kept_strs(nets, filter_private=False)
        self.assertIn("2001:db8::/32", kept_s)
        self.assertNotIn("2001:db8:1::/48", kept_s)

    def test_mixed_v4_v6(self):
        nets = self._nets("1.2.3.0/24", "2001:db8::/32")
        kept_s = self._kept_strs(nets, filter_private=False)
        self.assertEqual(kept_s, {"1.2.3.0/24", "2001:db8::/32"})

    def test_empty_input(self):
        kept, removed = optimize_fast([], filter_private=False)
        self.assertEqual(kept, [])
        self.assertEqual(removed, [])

    def test_multiple_covered(self):
        # /8 should absorb all the more-specific nets
        nets = self._nets("1.0.0.0/8", "1.1.0.0/16", "1.1.1.0/24", "1.1.1.1/32")
        kept_s = self._kept_strs(nets, filter_private=False)
        self.assertEqual(kept_s, {"1.0.0.0/8"})


# ---------------------------------------------------------------------------
# load_conf
# ---------------------------------------------------------------------------
class TestLoadConf(unittest.TestCase):

    def _write_conf(self, content):
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False)
        f.write(textwrap.dedent(content))
        f.flush()
        return f.name

    def test_empty_path_returns_defaults(self):
        cfg = load_conf("")
        self.assertEqual(cfg.blacklists, [])
        self.assertEqual(cfg.set_v4, "blacklist")

    def test_blacklists_parsed(self):
        path = self._write_conf("""\
            BLACKLISTS=(
                "https://example.com/list1.txt"
                "https://example.com/list2.txt"
            )
        """)
        cfg = load_conf(path)
        self.assertEqual(cfg.blacklists, [
            "https://example.com/list1.txt",
            "https://example.com/list2.txt",
        ])

    def test_blacklists_inline_comment_stripped(self):
        path = self._write_conf("""\
            BLACKLISTS=(
                "https://example.com/list.txt" # this source
                # "https://example.com/disabled.txt"
            )
        """)
        cfg = load_conf(path)
        self.assertEqual(cfg.blacklists, ["https://example.com/list.txt"])

    def test_numeric_keys(self):
        path = self._write_conf("""\
            MAXELEM=200000
            HASHSIZE=32768
            TIMEOUT=60
            BLACKLISTS=()
        """)
        cfg = load_conf(path)
        self.assertEqual(cfg.maxelem, 200000)
        self.assertEqual(cfg.hashsize, 32768)
        self.assertEqual(cfg.timeout, 60)

    def test_ipset_blacklist_name_sets_both(self):
        path = self._write_conf("IPSET_BLACKLIST_NAME=mylist\nBLACKLISTS=()\n")
        cfg = load_conf(path)
        self.assertEqual(cfg.set_v4, "mylist")
        self.assertEqual(cfg.set_v6, "mylist6")

    def test_explicit_set_names_override(self):
        path = self._write_conf(
            "SET_NAME4=bl4\nSET_NAME6=bl6\nBLACKLISTS=()\n"
        )
        cfg = load_conf(path)
        self.assertEqual(cfg.set_v4, "bl4")
        self.assertEqual(cfg.set_v6, "bl6")

    def test_out_path(self):
        path = self._write_conf(
            "IP_BLACKLIST_RESTORE=/tmp/mylist.restore\nBLACKLISTS=()\n"
        )
        cfg = load_conf(path)
        self.assertEqual(cfg.out_path, "/tmp/mylist.restore")

    def test_force_yes(self):
        path = self._write_conf("FORCE=yes\nBLACKLISTS=()\n")
        self.assertTrue(load_conf(path).force)

    def test_force_no(self):
        path = self._write_conf("FORCE=no\nBLACKLISTS=()\n")
        self.assertFalse(load_conf(path).force)

    def test_iptables_rule_number(self):
        path = self._write_conf("IPTABLES_IPSET_RULE_NUMBER=3\nBLACKLISTS=()\n")
        self.assertEqual(load_conf(path).iptables_pos, 3)

    def test_tmp_set_name(self):
        path = self._write_conf(
            "IPSET_TMP_BLACKLIST_NAME=bl-tmp\nBLACKLISTS=()\n"
        )
        cfg = load_conf(path)
        self.assertEqual(cfg.set_tmp_v4, "bl-tmp")
        self.assertEqual(cfg.set_tmp_v6, "bl-tmp6")


# ---------------------------------------------------------------------------
# write_restore
# ---------------------------------------------------------------------------
class TestWriteRestore(unittest.TestCase):

    def _cfg(self, **overrides):
        defaults = dict(out_path="/dev/null", set_v4="bl", set_v6="bl6",
                        hashsize=16384, maxelem=65536)
        defaults.update(overrides)
        return Config(**defaults)

    def test_v4_only(self):
        text = write_restore(self._cfg(), ["1.2.3.4", "5.6.7.0/24"], [],
                             dry_run=True)
        self.assertIn("create bl hash:net family inet", text)
        self.assertIn("add bl 1.2.3.4", text)
        self.assertIn("add bl 5.6.7.0/24", text)
        self.assertNotIn("bl6", text)

    def test_v6_only(self):
        text = write_restore(self._cfg(), [], ["2001:db8::/32"], dry_run=True)
        self.assertIn("create bl6 hash:net family inet6", text)
        self.assertIn("add bl6 2001:db8::/32", text)
        self.assertNotIn("create bl ", text)

    def test_both_families(self):
        text = write_restore(self._cfg(), ["1.2.3.4"], ["2001:db8::1"],
                             dry_run=True)
        self.assertIn("add bl 1.2.3.4", text)
        self.assertIn("add bl6 2001:db8::1", text)

    def test_empty_produces_empty_output(self):
        text = write_restore(self._cfg(), [], [], dry_run=True)
        self.assertEqual(text, "")

    def test_atomic_swap_tmp_set(self):
        text = write_restore(self._cfg(), ["1.2.3.4"], [], tmp=True,
                             dry_run=True)
        self.assertIn("create bl-tmp", text)
        self.assertIn("swap bl-tmp bl", text)
        self.assertIn("destroy bl-tmp", text)

    def test_atomic_swap_custom_tmp_name(self):
        text = write_restore(self._cfg(set_tmp_v4="my-tmp"), ["1.2.3.4"], [],
                             tmp=True, dry_run=True)
        self.assertIn("create my-tmp", text)
        self.assertIn("swap my-tmp bl", text)


# ---------------------------------------------------------------------------
# analyze_dumpfile
# ---------------------------------------------------------------------------
class TestAnalyzeDumpfile(unittest.TestCase):

    def _write_dump(self, lines):
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".dump", delete=False)
        f.write("\n".join(lines) + "\n")
        f.flush()
        return f.name

    def test_basic_parse(self):
        path = self._write_dump([
            "create blacklist hash:net family inet",
            "add blacklist 1.2.3.4",
            "add blacklist 5.6.7.0/24",
        ])
        nets, totals = analyze_dumpfile(path)
        strs = [str(n) for n in nets]
        self.assertIn("1.2.3.4/32", strs)
        self.assertIn("5.6.7.0/24", strs)
        self.assertEqual(totals["adds_total"], 2)

    def test_set_filter(self):
        path = self._write_dump([
            "add bl4 1.2.3.4",
            "add bl6 2001:db8::1",
        ])
        nets, _ = analyze_dumpfile(path, sets_filter={"bl4"})
        strs = [str(n) for n in nets]
        self.assertIn("1.2.3.4/32", strs)
        self.assertNotIn("2001:db8::1/128", strs)

    def test_skips_create_lines(self):
        path = self._write_dump([
            "create blacklist hash:net family inet",
            "add blacklist 9.9.9.9",
        ])
        nets, totals = analyze_dumpfile(path)
        self.assertEqual(len(nets), 1)
        self.assertEqual(totals["adds_total"], 1)

    def test_empty_file(self):
        path = self._write_dump([])
        nets, totals = analyze_dumpfile(path)
        self.assertEqual(nets, [])
        self.assertEqual(totals["adds_total"], 0)


# ---------------------------------------------------------------------------
# detect_dump_format
# ---------------------------------------------------------------------------
class TestDetectDumpFormat(unittest.TestCase):

    def _write(self, lines):
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".dump", delete=False)
        f.write("\n".join(lines) + "\n")
        f.close()
        return f.name

    def test_ipset_format(self):
        path = self._write(["create blacklist hash:net", "add blacklist 1.2.3.4"])
        self.assertEqual(detect_dump_format(path), "ipset")

    def test_nft_json_format(self):
        path = self._write(['{"nftables": [{"set": {"name": "v4"}}]}'])
        self.assertEqual(detect_dump_format(path), "nft")

    def test_unknown_format(self):
        path = self._write(["some random text", "more random text"])
        self.assertEqual(detect_dump_format(path), "unknown")


# ---------------------------------------------------------------------------
# parse_nft_dump
# ---------------------------------------------------------------------------
class TestParseNftDump(unittest.TestCase):

    def _write_json(self, data):
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        f.write(json.dumps(data))
        f.close()
        return f.name

    def test_basic_elements(self):
        data = {"nftables": [
            {"set": {"name": "v4", "elem": ["1.2.3.4", "5.6.7.8"]}}
        ]}
        nets, totals = parse_nft_dump(self._write_json(data))
        self.assertEqual(totals["adds_total"], 2)
        self.assertEqual(len(nets), 2)

    def test_prefix_elements(self):
        data = {"nftables": [
            {"set": {"name": "v4", "elem": [
                {"prefix": {"addr": "10.0.0.0", "len": 8}}
            ]}}
        ]}
        nets, totals = parse_nft_dump(self._write_json(data))
        self.assertEqual(totals["adds_total"], 1)
        self.assertEqual(str(nets[0]), "10.0.0.0/8")

    def test_mixed_families(self):
        data = {"nftables": [
            {"set": {"name": "v4", "elem": ["1.2.3.4"]}},
            {"set": {"name": "v6", "elem": ["::1"]}}
        ]}
        nets, totals = parse_nft_dump(self._write_json(data))
        self.assertEqual(totals["adds_total"], 2)
        versions = {n.version for n in nets}
        self.assertEqual(versions, {4, 6})

    def test_empty_set(self):
        data = {"nftables": [{"set": {"name": "v4", "elem": []}}]}
        nets, totals = parse_nft_dump(self._write_json(data))
        self.assertEqual(totals["adds_total"], 0)

    def test_malformed_json(self):
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        f.write("not json at all")
        f.close()
        nets, totals = parse_nft_dump(f.name)
        self.assertEqual(nets, [])
        self.assertEqual(totals["adds_total"], 0)


# ---------------------------------------------------------------------------
# format_net_str
# ---------------------------------------------------------------------------
class TestFormatNetStr(unittest.TestCase):

    def test_ipv4_host(self):
        self.assertEqual(format_net_str(ipaddress.ip_network("1.2.3.4/32")), "1.2.3.4")

    def test_ipv6_host(self):
        self.assertEqual(format_net_str(ipaddress.ip_network("::1/128")), "::1")

    def test_ipv4_cidr(self):
        self.assertEqual(format_net_str(ipaddress.ip_network("10.0.0.0/8")), "10.0.0.0/8")


# ---------------------------------------------------------------------------
# write_nft_batch
# ---------------------------------------------------------------------------
class TestWriteNftBatch(unittest.TestCase):

    def _cfg(self, **overrides):
        defaults = dict(out_path="/dev/null")
        defaults.update(overrides)
        return Config(**defaults)

    def test_v4_only(self):
        with tempfile.NamedTemporaryFile(suffix=".nft", delete=False) as f:
            path = f.name
        text = write_nft_batch(self._cfg(out_path=path),
                               ["1.2.3.4", "10.0.0.0/8"], [], dry_run=True)
        self.assertIn("flush set inet blacklist v4", text)
        self.assertIn("add element inet blacklist v4 { 1.2.3.4, 10.0.0.0/8 }", text)
        self.assertNotIn("v6", text)

    def test_v6_only(self):
        text = write_nft_batch(self._cfg(), [], ["::1"], dry_run=True)
        self.assertIn("flush set inet blacklist v6", text)
        self.assertIn("add element inet blacklist v6 { ::1 }", text)
        self.assertNotIn("v4", text)

    def test_both_families(self):
        text = write_nft_batch(self._cfg(), ["1.2.3.4"], ["::1"], dry_run=True)
        self.assertIn("flush set inet blacklist v4", text)
        self.assertIn("flush set inet blacklist v6", text)

    def test_empty(self):
        text = write_nft_batch(self._cfg(), [], [], dry_run=True)
        self.assertEqual(text, "")

    def test_chunking(self):
        entries = [f"10.0.{i // 256}.{i % 256}" for i in range(NFT_CHUNK_SIZE + 5)]
        text = write_nft_batch(self._cfg(), entries, [], dry_run=True)
        add_lines = [l for l in text.splitlines() if l.startswith("add element")]
        self.assertEqual(len(add_lines), 2)

    def test_exact_chunk_boundary(self):
        entries = [f"10.0.{i // 256}.{i % 256}" for i in range(NFT_CHUNK_SIZE)]
        text = write_nft_batch(self._cfg(), entries, [], dry_run=True)
        add_lines = [l for l in text.splitlines() if l.startswith("add element")]
        self.assertEqual(len(add_lines), 1)

    def test_custom_table_and_sets(self):
        text = write_nft_batch(self._cfg(nft_table="mytable", nft_set_v4="myset4",
                                         nft_set_v6="myset6"),
                               ["1.1.1.1"], [], dry_run=True)
        self.assertIn("flush set inet mytable myset4", text)
        self.assertIn("add element inet mytable myset4 { 1.1.1.1 }", text)


# ---------------------------------------------------------------------------
# setup_nft_table_script
# ---------------------------------------------------------------------------
class TestSetupNftTableScript(unittest.TestCase):

    def test_full_table(self):
        s = setup_nft_table_script()
        self.assertIn("table inet blacklist {", s)
        self.assertIn("set v4 {", s)
        self.assertIn("type ipv4_addr", s)
        self.assertIn("set v6 {", s)
        self.assertIn("type ipv6_addr", s)
        self.assertIn("ip saddr @v4 drop", s)
        self.assertIn("ip6 saddr @v6 drop", s)

    def test_ipv4_only(self):
        s = setup_nft_table_script(ipv4_only=True)
        self.assertIn("set v4 {", s)
        self.assertNotIn("set v6 {", s)
        self.assertIn("ip saddr @v4 drop", s)
        self.assertNotIn("ip6 saddr", s)

    def test_ipv6_only(self):
        s = setup_nft_table_script(ipv6_only=True)
        self.assertNotIn("set v4 {", s)
        self.assertIn("set v6 {", s)
        self.assertNotIn("ip saddr @v4", s)
        self.assertIn("ip6 saddr @v6 drop", s)

    def test_custom_names(self):
        s = setup_nft_table_script(Config(nft_table="mytable",
                                          nft_set_v4="myset4",
                                          nft_set_v6="myset6"))
        self.assertIn("table inet mytable {", s)
        self.assertIn("set myset4 {", s)
        self.assertIn("set myset6 {", s)


# ---------------------------------------------------------------------------
# apply_nft_batch
# ---------------------------------------------------------------------------
class TestApplyNftBatch(unittest.TestCase):

    def test_success(self):
        cp = subprocess.CompletedProcess(args=[], returncode=0, stdout=b"", stderr=b"")
        with mock.patch("update_blacklist.subprocess.run", return_value=cp) as m:
            apply_nft_batch("flush set inet blacklist v4\n")
            m.assert_called_once()
            args = m.call_args
            self.assertEqual(args[0][0], ["nft", "-f", "-"])

    def test_failure_raises(self):
        cp = subprocess.CompletedProcess(args=[], returncode=1, stdout=b"", stderr=b"Error: bad input")
        with mock.patch("update_blacklist.subprocess.run", return_value=cp):
            with self.assertRaises(RuntimeError) as ctx:
                apply_nft_batch("bad script\n")
            self.assertIn("bad input", str(ctx.exception))

    def test_dry_run(self):
        with mock.patch("update_blacklist.subprocess.run") as m:
            apply_nft_batch("flush set inet blacklist v4\n", dry_run=True)
            m.assert_not_called()


# ---------------------------------------------------------------------------
# check_nft_table_valid
# ---------------------------------------------------------------------------
class TestCheckNftTableValid(unittest.TestCase):

    def _nft_json(self, sets):
        """Build nft -j output with given set names."""
        items = [{"metainfo": {"json_schema_version": 1}}]
        items.append({"table": {"family": "inet", "name": "blacklist"}})
        for s in sets:
            items.append({"set": {"family": "inet", "name": s, "table": "blacklist",
                                  "type": "ipv4_addr", "flags": ["interval"]}})
        return json.dumps({"nftables": items}).encode()

    def test_valid_table(self):
        cp = subprocess.CompletedProcess(args=[], returncode=0, stdout=self._nft_json(["v4", "v6"]))
        with mock.patch("update_blacklist.subprocess.run", return_value=cp):
            self.assertTrue(check_nft_table_valid())

    def test_missing_set(self):
        cp = subprocess.CompletedProcess(args=[], returncode=0, stdout=self._nft_json(["v4"]))
        with mock.patch("update_blacklist.subprocess.run", return_value=cp):
            self.assertFalse(check_nft_table_valid())

    def test_table_not_found(self):
        with mock.patch("update_blacklist.subprocess.run",
                        side_effect=subprocess.CalledProcessError(1, "nft")):
            self.assertFalse(check_nft_table_valid())


# ---------------------------------------------------------------------------
# detect_backend
# ---------------------------------------------------------------------------
class TestDetectBackend(unittest.TestCase):

    def test_force_backend_ipset(self):
        self.assertEqual(detect_backend(Config(backend="ipset")), "ipset")

    def test_force_backend_nft(self):
        self.assertEqual(detect_backend(Config(backend="nft")), "nft")

    def test_nft_table_valid_wins(self):
        with mock.patch("update_blacklist.check_nft_table_valid", return_value=True):
            self.assertEqual(detect_backend(Config()), "nft")

    def test_ipset_exists_fallback(self):
        cp = subprocess.CompletedProcess(args=[], returncode=0, stdout=b"")
        with mock.patch("update_blacklist.check_nft_table_valid", return_value=False), \
             mock.patch("update_blacklist.subprocess.run", return_value=cp):
            self.assertEqual(detect_backend(Config()), "ipset")

    def test_force_prefers_nft(self):
        with mock.patch("update_blacklist.check_nft_table_valid", return_value=False), \
             mock.patch("update_blacklist.subprocess.run",
                        side_effect=subprocess.CalledProcessError(1, "ipset")), \
             mock.patch("update_blacklist.shutil.which", side_effect=lambda x: "/usr/sbin/nft" if x == "nft" else None):
            self.assertEqual(detect_backend(Config(force=True)), "nft")

    def test_force_falls_back_to_ipset(self):
        with mock.patch("update_blacklist.check_nft_table_valid", return_value=False), \
             mock.patch("update_blacklist.subprocess.run",
                        side_effect=subprocess.CalledProcessError(1, "ipset")), \
             mock.patch("update_blacklist.shutil.which", side_effect=lambda x: "/usr/sbin/ipset" if x == "ipset" else None):
            self.assertEqual(detect_backend(Config(force=True)), "ipset")

    def test_no_backend_raises(self):
        with mock.patch("update_blacklist.check_nft_table_valid", return_value=False), \
             mock.patch("update_blacklist.subprocess.run",
                        side_effect=subprocess.CalledProcessError(1, "ipset")), \
             mock.patch("update_blacklist.shutil.which", return_value=None):
            with self.assertRaises(RuntimeError):
                detect_backend(Config())

    def test_nft_preferred_during_coexistence(self):
        """nft wins even when ipset also exists (coexistence window)."""
        with mock.patch("update_blacklist.check_nft_table_valid", return_value=True):
            self.assertEqual(detect_backend(Config()), "nft")


# ---------------------------------------------------------------------------
# load_conf nft keys
# ---------------------------------------------------------------------------
class TestLoadConfNft(unittest.TestCase):

    def _write_conf(self, lines):
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False)
        f.write("\n".join(lines) + "\n")
        f.close()
        return f.name

    def test_defaults(self):
        cfg = load_conf("")
        self.assertEqual(cfg.backend, "auto")
        self.assertEqual(cfg.nft_table, DEFAULT_NFT_TABLE)
        self.assertEqual(cfg.nft_set_v4, DEFAULT_NFT_SET_V4)
        self.assertEqual(cfg.nft_set_v6, DEFAULT_NFT_SET_V6)

    def test_backend_nft(self):
        cfg = load_conf(self._write_conf(["BACKEND=nft"]))
        self.assertEqual(cfg.backend, "nft")

    def test_custom_nft_table(self):
        cfg = load_conf(self._write_conf(["NFT_TABLE=my_blocklist"]))
        self.assertEqual(cfg.nft_table, "my_blocklist")

    def test_custom_nft_sets(self):
        cfg = load_conf(self._write_conf(["NFT_SET_V4=ipv4set", "NFT_SET_V6=ipv6set"]))
        self.assertEqual(cfg.nft_set_v4, "ipv4set")
        self.assertEqual(cfg.nft_set_v6, "ipv6set")


# ---------------------------------------------------------------------------
# main() nft integration
# ---------------------------------------------------------------------------
class TestMainNftIntegration(unittest.TestCase):
    """Test that main() routes correctly between ipset and nft backends."""

    def _make_conf(self, extra=""):
        """Write a minimal conf with one local source."""
        src = tempfile.NamedTemporaryFile(mode="w", suffix=".list", delete=False)
        src.write("1.2.3.4\n10.0.0.0/8\n")
        src.close()
        conf = tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False)
        conf.write(f'BLACKLISTS=(\n"{src.name}"\n)\n{extra}\n')
        conf.close()
        return conf.name

    @mock.patch("update_blacklist.detect_backend", return_value="nft")
    @mock.patch("update_blacklist.apply_nft_batch")
    @mock.patch("update_blacklist.check_nft_table_valid", return_value=True)
    def test_apply_nft_calls_apply_nft_batch(self, _chk, mock_apply, _det):
        conf = self._make_conf()
        out = tempfile.NamedTemporaryFile(suffix=".nft", delete=False)
        out.close()
        import sys
        with mock.patch.object(sys, "argv", ["prog", "--conf", conf, "--out", out.name,
                                              "--apply", "--quiet", "--ipv4-only"]):
            from update_blacklist import main
            main()
        self.assertTrue(mock_apply.called)

    @mock.patch("update_blacklist.detect_backend", return_value="ipset")
    @mock.patch("update_blacklist.subprocess.run")
    def test_apply_ipset_calls_ipset_restore(self, mock_run, _det):
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout=b"", stderr=b"")
        conf = self._make_conf()
        out = tempfile.NamedTemporaryFile(suffix=".restore", delete=False)
        out.close()
        import sys
        with mock.patch.object(sys, "argv", ["prog", "--conf", conf, "--out", out.name,
                                              "--apply", "--quiet", "--ipv4-only"]):
            from update_blacklist import main
            main()
        restore_calls = [c for c in mock_run.call_args_list
                         if c[0][0][:2] == ["ipset", "restore"]]
        self.assertTrue(len(restore_calls) > 0)

    def test_write_only_emits_ipset_even_when_nft_detected(self):
        """D5: write-only mode always emits ipset format unless --backend nft explicit."""
        conf = self._make_conf()
        out = tempfile.NamedTemporaryFile(suffix=".restore", delete=False)
        out.close()
        import sys
        with mock.patch.object(sys, "argv", ["prog", "--conf", conf, "--out", out.name,
                                              "--quiet", "--ipv4-only"]):
            from update_blacklist import main
            main()
        with open(out.name, "r") as f:
            content = f.read()
        self.assertIn("create blacklist", content)
        self.assertIn("add blacklist", content)
        self.assertNotIn("flush set inet", content)

    def test_write_only_explicit_nft_emits_nft(self):
        """--backend nft in write-only mode should emit nft format."""
        conf = self._make_conf()
        out = tempfile.NamedTemporaryFile(suffix=".nft", delete=False)
        out.close()
        import sys
        with mock.patch.object(sys, "argv", ["prog", "--conf", conf, "--out", out.name,
                                              "--backend", "nft", "--quiet", "--ipv4-only"]):
            from update_blacklist import main
            main()
        with open(out.name, "r") as f:
            content = f.read()
        self.assertIn("flush set inet", content)
        self.assertIn("add element inet", content)


# ---------------------------------------------------------------------------
# import / export
# ---------------------------------------------------------------------------
class TestImportExport(unittest.TestCase):

    def test_import_ipset_to_nft(self):
        """--import-ipset converts ipset dump to nft batch."""
        src = tempfile.NamedTemporaryFile(mode="w", suffix=".dump", delete=False)
        src.write("add blacklist 1.2.3.4\nadd blacklist 10.0.0.0/8\n")
        src.close()
        out = tempfile.NamedTemporaryFile(suffix=".nft", delete=False)
        out.close()
        import sys
        with mock.patch.object(sys, "argv", ["prog", "--import-ipset", src.name,
                                              "--out", out.name, "--quiet"]):
            from update_blacklist import main
            main()
        with open(out.name, "r") as f:
            content = f.read()
        self.assertIn("flush set inet blacklist v4", content)
        self.assertIn("1.2.3.4", content)
        self.assertIn("10.0.0.0/8", content)

    def test_export_nft_to_ipset(self):
        """--export-ipset converts nft JSON to ipset restore."""
        data = {"nftables": [
            {"set": {"name": "v4", "elem": ["1.2.3.4", "5.6.7.8"]}}
        ]}
        src = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        src.write(json.dumps(data))
        src.close()
        out = tempfile.NamedTemporaryFile(suffix=".restore", delete=False)
        out.close()
        import sys
        with mock.patch.object(sys, "argv", ["prog", "--export-ipset", src.name,
                                              "--out", out.name, "--quiet"]):
            from update_blacklist import main
            main()
        with open(out.name, "r") as f:
            content = f.read()
        self.assertIn("create blacklist", content)
        self.assertIn("add blacklist 1.2.3.4", content)
        self.assertIn("add blacklist 5.6.7.8", content)

    def test_roundtrip(self):
        """ipset → nft → ipset roundtrip preserves entries."""
        src = tempfile.NamedTemporaryFile(mode="w", suffix=".dump", delete=False)
        src.write("add blacklist 1.2.3.4\nadd blacklist 10.0.0.0/8\n")
        src.close()

        from update_blacklist import analyze_dumpfile, parse_nft_dump
        nets_orig, _ = analyze_dumpfile(src.name)
        orig_strs = sorted(str(n) for n in nets_orig)

        nft_out = tempfile.NamedTemporaryFile(suffix=".nft", delete=False)
        nft_out.close()
        import sys
        with mock.patch.object(sys, "argv", ["prog", "--import-ipset", src.name,
                                              "--out", nft_out.name, "--quiet"]):
            from update_blacklist import main
            main()

        # parse_nft_dump needs JSON, but write_nft_batch writes nft batch text.
        # Roundtrip verifies the entries survive the conversion by re-parsing the batch.
        with open(nft_out.name, "r") as f:
            batch = f.read()
        # Extract IPs from "add element inet blacklist v4 { ... }" lines
        import re
        found = []
        for m in re.finditer(r'add element inet \S+ \S+ \{ (.+?) \}', batch):
            for tok in m.group(1).split(", "):
                from update_blacklist import parse_addr_token
                n = parse_addr_token(tok.strip())
                if n:
                    found.append(str(n))
        self.assertEqual(sorted(found), orig_strs)


# ---------------------------------------------------------------------------
# fetch_source
# ---------------------------------------------------------------------------
class TestFetchSource(unittest.TestCase):

    def test_local_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("1.2.3.4\n5.6.7.8\n")
            f.flush()
            result = fetch_source(f.name, timeout=5)
        self.assertIn("1.2.3.4", result)
        self.assertIn("5.6.7.8", result)

    def test_local_file_url(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("10.0.0.1\n")
            f.flush()
            result = fetch_source(f"file://{f.name}", timeout=5)
        self.assertIn("10.0.0.1", result)

    def test_local_file_missing(self):
        result = fetch_source("/nonexistent/path/file.txt", timeout=5)
        self.assertEqual(result, "")

    @mock.patch("update_blacklist.urllib.request.urlopen")
    def test_http_success(self, mock_urlopen):
        mock_resp = mock.MagicMock()
        mock_resp.read.return_value = b"1.1.1.1\n2.2.2.2\n"
        mock_resp.__enter__ = mock.MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = mock.MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp
        result = fetch_source("https://example.com/list.txt", timeout=10)
        self.assertIn("1.1.1.1", result)
        mock_urlopen.assert_called_once()

    @mock.patch("update_blacklist.time.sleep")
    @mock.patch("update_blacklist.urllib.request.urlopen")
    def test_http_4xx_no_retry(self, mock_urlopen, mock_sleep):
        import urllib.error
        mock_urlopen.side_effect = urllib.error.HTTPError(
            "https://example.com/list.txt", 404, "Not Found", {}, None)
        result = fetch_source("https://example.com/list.txt", timeout=10, max_retries=2)
        self.assertEqual(result, "")
        mock_urlopen.assert_called_once()
        mock_sleep.assert_not_called()

    @mock.patch("update_blacklist.time.sleep")
    @mock.patch("update_blacklist.urllib.request.urlopen")
    def test_http_5xx_retries(self, mock_urlopen, mock_sleep):
        import urllib.error
        mock_urlopen.side_effect = urllib.error.HTTPError(
            "https://example.com/list.txt", 503, "Service Unavailable", {}, None)
        result = fetch_source("https://example.com/list.txt", timeout=10, max_retries=2)
        self.assertEqual(result, "")
        self.assertEqual(mock_urlopen.call_count, 3)
        self.assertEqual(mock_sleep.call_count, 2)

    @mock.patch("update_blacklist.time.sleep")
    @mock.patch("update_blacklist.urllib.request.urlopen")
    def test_http_5xx_then_success(self, mock_urlopen, mock_sleep):
        import urllib.error
        mock_resp = mock.MagicMock()
        mock_resp.read.return_value = b"9.9.9.9\n"
        mock_resp.__enter__ = mock.MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = mock.MagicMock(return_value=False)
        mock_urlopen.side_effect = [
            urllib.error.HTTPError("u", 500, "ISE", {}, None),
            mock_resp,
        ]
        result = fetch_source("https://example.com/list.txt", timeout=10, max_retries=2)
        self.assertIn("9.9.9.9", result)
        self.assertEqual(mock_urlopen.call_count, 2)

    @mock.patch("update_blacklist.time.sleep")
    @mock.patch("update_blacklist.urllib.request.urlopen")
    def test_cert_error_no_retry(self, mock_urlopen, mock_sleep):
        import urllib.error
        mock_urlopen.side_effect = urllib.error.URLError(
            "SSL: certificate verify failed")
        result = fetch_source("https://example.com/list.txt", timeout=10, max_retries=2)
        self.assertEqual(result, "")
        mock_urlopen.assert_called_once()
        mock_sleep.assert_not_called()

    @mock.patch("update_blacklist.time.sleep")
    @mock.patch("update_blacklist.urllib.request.urlopen")
    def test_network_error_retries(self, mock_urlopen, mock_sleep):
        import urllib.error
        mock_urlopen.side_effect = urllib.error.URLError("Connection refused")
        result = fetch_source("https://example.com/list.txt", timeout=10, max_retries=2)
        self.assertEqual(result, "")
        self.assertEqual(mock_urlopen.call_count, 3)

    @mock.patch("update_blacklist.urllib.request.urlopen")
    def test_user_agent_header(self, mock_urlopen):
        mock_resp = mock.MagicMock()
        mock_resp.read.return_value = b""
        mock_resp.__enter__ = mock.MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = mock.MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp
        fetch_source("https://example.com/list.txt", timeout=10)
        req = mock_urlopen.call_args[0][0]
        self.assertEqual(req.get_header("User-agent"), "ipset-blacklist-py")


# ---------------------------------------------------------------------------
# ensure_rule
# ---------------------------------------------------------------------------
class TestEnsureRule(unittest.TestCase):

    def test_dry_run_returns_true(self):
        result = ensure_rule(
            ["iptables", "-C", "INPUT", "-j", "DROP"],
            ["iptables", "-I", "INPUT", "-j", "DROP"],
            dry_run=True)
        self.assertTrue(result)

    @mock.patch("update_blacklist.subprocess.run")
    def test_rule_already_exists(self, mock_run):
        mock_run.return_value = mock.MagicMock(returncode=0)
        result = ensure_rule(
            ["iptables", "-C", "INPUT", "-j", "DROP"],
            ["iptables", "-I", "INPUT", "-j", "DROP"])
        self.assertTrue(result)
        mock_run.assert_called_once()

    @mock.patch("update_blacklist.subprocess.run")
    def test_rule_inserted(self, mock_run):
        mock_run.side_effect = [
            subprocess.CalledProcessError(1, "iptables"),
            mock.MagicMock(returncode=0),
        ]
        result = ensure_rule(
            ["iptables", "-C", "INPUT", "-j", "DROP"],
            ["iptables", "-I", "INPUT", "-j", "DROP"])
        self.assertFalse(result)
        self.assertEqual(mock_run.call_count, 2)

    @mock.patch("update_blacklist.subprocess.run")
    def test_insert_failure_raises(self, mock_run):
        mock_run.side_effect = [
            subprocess.CalledProcessError(1, "iptables -C"),
            subprocess.CalledProcessError(1, "iptables -I"),
        ]
        with self.assertRaises(RuntimeError) as ctx:
            ensure_rule(
                ["iptables", "-C", "INPUT", "-j", "DROP"],
                ["iptables", "-I", "INPUT", "-j", "DROP"])
        self.assertIn("Failed to insert rule", str(ctx.exception))


# ---------------------------------------------------------------------------
# Version
# ---------------------------------------------------------------------------
class TestVersion(unittest.TestCase):
    def test_version_is_string(self):
        self.assertIsInstance(__version__, str)
        self.assertTrue(len(__version__) > 0)


if __name__ == "__main__":
    unittest.main()
