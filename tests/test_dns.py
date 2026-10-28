"""DNS TXT parsing and the optional lookup path. No live network."""

import io
import struct
import unittest
from unittest.mock import patch

from phishcheck.dns_check import (
    DnsError,
    build_query,
    check_published,
    dig_txt,
    lookup_txt,
    parse_dig_output,
    parse_txt_response,
    query_txt_stdlib,
    system_nameserver,
    validate_name,
)


def _txt_answer(query: bytes, text: str) -> bytes:
    tid = struct.unpack("!H", query[:2])[0]
    question = query[12:]
    raw = text.encode("ascii")
    rdata = bytes([len(raw)]) + raw
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 16, 1, 60, len(rdata)) + rdata
    header = struct.pack("!HHHHHH", tid, 0x8180, 1, 1, 0, 0)
    return header + question + answer


class DnsTests(unittest.TestCase):
    def test_query_is_a_txt_question(self) -> None:
        packet = build_query("example.com", tid=0x1234)
        self.assertEqual(struct.unpack("!H", packet[:2])[0], 0x1234)
        self.assertEqual(struct.unpack("!HH", packet[-4:]) , (16, 1))

    def test_rejects_option_like_names(self) -> None:
        for name in ("-o", "example.com;rm", "", "ex ample.com"):
            with self.subTest(name=name):
                with self.assertRaises(DnsError):
                    validate_name(name)
        validate_name("_dmarc.example.com")

    def test_parse_compressed_txt_and_errors(self) -> None:
        query = build_query("example.com", tid=0xAB)
        response = _txt_answer(query, "v=spf1 -all")
        self.assertEqual(parse_txt_response(response, expected_tid=0xAB), ["v=spf1 -all"])
        truncated = struct.pack("!HHHHHH", 0xAB, 0x8380, 1, 0, 0, 0) + query[12:]
        with self.assertRaises(DnsError):
            parse_txt_response(truncated, expected_tid=0xAB)
        nxdomain = struct.pack("!HHHHHH", 0xAB, 0x8183, 1, 0, 0, 0) + query[12:]
        self.assertEqual(parse_txt_response(nxdomain, expected_tid=0xAB), [])

    def test_stdlib_query_uses_a_socket_mock(self) -> None:
        sent = {}

        class FakeSocket:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def settimeout(self, _timeout):
                return None

            def sendto(self, data, addr):
                sent["data"] = data
                sent["addr"] = addr

            def recvfrom(self, _size):
                return _txt_answer(sent["data"], "v=spf1 -all"), ("1.1.1.1", 53)

        with patch("phishcheck.dns_check.socket.socket", return_value=FakeSocket()):
            records = query_txt_stdlib("example.com", "1.1.1.1", tid=0x1234)
        self.assertEqual(records, ["v=spf1 -all"])
        self.assertEqual(sent["addr"], ("1.1.1.1", 53))

    def test_dig_parser_and_mocked_dig(self) -> None:
        self.assertEqual(parse_dig_output('"v=spf1 -all"\n'), ["v=spf1 -all"])
        completed = type("Proc", (), {"returncode": 0, "stdout": '"v=DMARC1; p=reject"\n', "stderr": ""})()
        with patch("phishcheck.dns_check.subprocess.run", return_value=completed) as run:
            records = dig_txt("example.com", "1.1.1.1")
        self.assertEqual(records, ["v=DMARC1; p=reject"])
        argv = run.call_args.args[0]
        self.assertEqual(argv[0], "dig")
        self.assertIn("@1.1.1.1", argv)
        self.assertNotIn("shell", run.call_args.kwargs)

    def test_lookup_prefers_dig_when_present(self) -> None:
        with patch("phishcheck.dns_check.shutil.which", return_value="/usr/bin/dig"), patch(
            "phishcheck.dns_check.dig_txt", return_value=["v=spf1 -all"]
        ) as dig, patch("phishcheck.dns_check.query_txt_stdlib") as stdlib:
            records, transport = lookup_txt("example.com", "1.1.1.1")
        self.assertEqual(transport, "dig")
        self.assertEqual(records, ["v=spf1 -all"])
        dig.assert_called_once()
        stdlib.assert_not_called()

    def test_lookup_uses_stdlib_without_dig(self) -> None:
        with patch("phishcheck.dns_check.shutil.which", return_value=None), patch(
            "phishcheck.dns_check.query_txt_stdlib", return_value=["v=spf1 -all"]
        ) as stdlib:
            records, transport = lookup_txt("example.com", "9.9.9.9")
        self.assertEqual((records, transport), (["v=spf1 -all"], "stdlib"))
        stdlib.assert_called_once()

    def test_system_nameserver_file(self) -> None:
        handle = io.StringIO("nameserver 192.0.2.1\nnameserver 2001:db8::1\n")
        with patch("phishcheck.dns_check.Path.read_text", return_value=handle.getvalue()):
            self.assertEqual(system_nameserver("/tmp/does-not-matter"), "192.0.2.1")

    def test_published_records_are_notes_not_scores(self) -> None:
        def fake(name, server):
            if name.startswith("_dmarc"):
                return ["v=DMARC1; p=quarantine"], "stdlib"
            return ["v=spf1 -all"], "stdlib"

        notes = check_published("news.example", "news.example", server="1.1.1.1", lookup=fake)
        self.assertTrue(all(note.points == 0 for note in notes))
        text = " ".join(note.detail for note in notes)
        self.assertIn("not evaluated", text)
        self.assertIn("p=quarantine", text)
        self.assertIn("include:", text)

    def test_lookup_failure_is_a_note(self) -> None:
        def fake(name, server):
            raise DnsError("timeout")

        notes = check_published("news.example", server="1.1.1.1", lookup=fake)
        self.assertTrue(notes)
        self.assertTrue(all(note.points == 0 for note in notes))
        self.assertIn("failed", notes[0].detail)


if __name__ == "__main__":
    unittest.main()
