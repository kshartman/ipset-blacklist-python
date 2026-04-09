#!/usr/bin/env python3
"""Unit tests for update_blacklist.py — parsing, dedup, config, restore output."""

import ipaddress
import tempfile
import textwrap
import unittest

from update_blacklist import (
    analyze_dumpfile,
    is_private_ip,
    load_conf,
    optimize_fast,
    parse_addr_token,
    parse_entry,
    write_restore,
)

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
        self.assertEqual(cfg["BLACKLISTS"], [])
        self.assertEqual(cfg["SET_NAME4"], "blacklist")

    def test_blacklists_parsed(self):
        path = self._write_conf("""\
            BLACKLISTS=(
                "https://example.com/list1.txt"
                "https://example.com/list2.txt"
            )
        """)
        cfg = load_conf(path)
        self.assertEqual(cfg["BLACKLISTS"], [
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
        self.assertEqual(cfg["BLACKLISTS"], ["https://example.com/list.txt"])

    def test_numeric_keys(self):
        path = self._write_conf("""\
            MAXELEM=200000
            HASHSIZE=32768
            TIMEOUT=60
            BLACKLISTS=()
        """)
        cfg = load_conf(path)
        self.assertEqual(cfg["MAXELEM"], 200000)
        self.assertEqual(cfg["HASHSIZE"], 32768)
        self.assertEqual(cfg["TIMEOUT"], 60)

    def test_ipset_blacklist_name_sets_both(self):
        path = self._write_conf("IPSET_BLACKLIST_NAME=mylist\nBLACKLISTS=()\n")
        cfg = load_conf(path)
        self.assertEqual(cfg["SET_NAME4"], "mylist")
        self.assertEqual(cfg["SET_NAME6"], "mylist6")

    def test_explicit_set_names_override(self):
        path = self._write_conf(
            "SET_NAME4=bl4\nSET_NAME6=bl6\nBLACKLISTS=()\n"
        )
        cfg = load_conf(path)
        self.assertEqual(cfg["SET_NAME4"], "bl4")
        self.assertEqual(cfg["SET_NAME6"], "bl6")

    def test_out_path(self):
        path = self._write_conf(
            "IP_BLACKLIST_RESTORE=/tmp/mylist.restore\nBLACKLISTS=()\n"
        )
        cfg = load_conf(path)
        self.assertEqual(cfg["OUT_PATH"], "/tmp/mylist.restore")

    def test_force_yes(self):
        path = self._write_conf("FORCE=yes\nBLACKLISTS=()\n")
        self.assertTrue(load_conf(path)["FORCE"])

    def test_force_no(self):
        path = self._write_conf("FORCE=no\nBLACKLISTS=()\n")
        self.assertFalse(load_conf(path)["FORCE"])

    def test_iptables_rule_number(self):
        path = self._write_conf("IPTABLES_IPSET_RULE_NUMBER=3\nBLACKLISTS=()\n")
        self.assertEqual(load_conf(path)["IPTABLES_POS"], 3)

    def test_tmp_set_name(self):
        path = self._write_conf(
            "IPSET_TMP_BLACKLIST_NAME=bl-tmp\nBLACKLISTS=()\n"
        )
        cfg = load_conf(path)
        self.assertEqual(cfg["SET_TMP_NAME4"], "bl-tmp")
        self.assertEqual(cfg["SET_TMP_NAME6"], "bl-tmp6")


# ---------------------------------------------------------------------------
# write_restore
# ---------------------------------------------------------------------------
class TestWriteRestore(unittest.TestCase):

    def test_v4_only(self):
        text = write_restore("/dev/null", "bl", "bl6", 16384, 65536,
                             ["1.2.3.4", "5.6.7.0/24"], [], dry_run=True)
        self.assertIn("create bl hash:net family inet", text)
        self.assertIn("add bl 1.2.3.4", text)
        self.assertIn("add bl 5.6.7.0/24", text)
        self.assertNotIn("bl6", text)

    def test_v6_only(self):
        text = write_restore("/dev/null", "bl", "bl6", 16384, 65536,
                             [], ["2001:db8::/32"], dry_run=True)
        self.assertIn("create bl6 hash:net family inet6", text)
        self.assertIn("add bl6 2001:db8::/32", text)
        self.assertNotIn("create bl ", text)

    def test_both_families(self):
        text = write_restore("/dev/null", "bl", "bl6", 16384, 65536,
                             ["1.2.3.4"], ["2001:db8::1"], dry_run=True)
        self.assertIn("add bl 1.2.3.4", text)
        self.assertIn("add bl6 2001:db8::1", text)

    def test_empty_produces_empty_output(self):
        text = write_restore("/dev/null", "bl", "bl6", 16384, 65536,
                             [], [], dry_run=True)
        self.assertEqual(text, "")

    def test_atomic_swap_tmp_set(self):
        text = write_restore("/dev/null", "bl", "bl6", 16384, 65536,
                             ["1.2.3.4"], [], tmp=True, dry_run=True)
        self.assertIn("create bl-tmp", text)
        self.assertIn("swap bl-tmp bl", text)
        self.assertIn("destroy bl-tmp", text)

    def test_atomic_swap_custom_tmp_name(self):
        text = write_restore("/dev/null", "bl", "bl6", 16384, 65536,
                             ["1.2.3.4"], [], tmp=True, dry_run=True,
                             set4_tmp="my-tmp")
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


if __name__ == "__main__":
    unittest.main()
