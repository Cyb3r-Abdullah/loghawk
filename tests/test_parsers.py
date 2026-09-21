"""Parser tests: correct extraction, correct skipping, and no crashes on junk."""

from __future__ import annotations

import os
import unittest

from helpers import SAMPLES  # noqa: F401  (also fixes sys.path)

from loghawk.models import EventType
from loghawk.parsers import (
    LinuxAuthParser,
    NginxAccessParser,
    WindowsSecurityParser,
    detect_parser,
    parse_paths,
)


class TestLinuxAuthParser(unittest.TestCase):
    def setUp(self) -> None:
        self.parser = LinuxAuthParser(year=2026)

    def parse_one(self, line: str):
        return self.parser.parse_line(line, 1)

    def test_failed_password_for_valid_user(self):
        e = self.parse_one(
            "Sep 21 04:12:35 web-01 sshd[20483]: Failed password for root "
            "from 45.83.91.22 port 51430 ssh2"
        )
        self.assertEqual(e.event_type, EventType.AUTH_FAILURE)
        self.assertEqual(e.user, "root")
        self.assertEqual(e.src_ip, "45.83.91.22")
        self.assertEqual(e.host, "web-01")
        self.assertEqual(e.timestamp.year, 2026)
        self.assertEqual(e.timestamp.hour, 4)

    def test_invalid_user_is_distinct_from_auth_failure(self):
        e = self.parse_one(
            "Sep 21 04:12:33 web-01 sshd[20481]: Failed password for invalid user "
            "admin from 45.83.91.22 port 51422 ssh2"
        )
        self.assertEqual(e.event_type, EventType.INVALID_USER)
        self.assertEqual(e.user, "admin")

    def test_accepted_password_and_publickey(self):
        for method in ("password", "publickey"):
            e = self.parse_one(
                f"Sep 21 04:13:01 web-01 sshd[20501]: Accepted {method} for deploy "
                "from 39.41.2.9 port 51500 ssh2"
            )
            self.assertEqual(e.event_type, EventType.AUTH_SUCCESS, method)
            self.assertEqual(e.user, "deploy")

    def test_sudo_success_captures_command(self):
        e = self.parse_one(
            "Sep 21 04:44:00 web-01 sudo:   deploy : TTY=pts/0 ; PWD=/home/deploy ; "
            "USER=root ; COMMAND=/usr/bin/cat /etc/shadow"
        )
        self.assertEqual(e.event_type, EventType.PRIV_ESCALATION)
        self.assertEqual(e.user, "deploy")
        self.assertEqual(e.extra["target_user"], "root")
        self.assertIn("/etc/shadow", e.extra["command"])

    def test_sudo_failure_captures_attempt_count(self):
        e = self.parse_one(
            "Sep 21 04:42:00 web-01 sudo:   deploy : 3 incorrect password attempts ; "
            "TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/id"
        )
        self.assertEqual(e.event_type, EventType.PRIV_ESCALATION_FAILED)
        self.assertEqual(e.extra["attempts"], 3)

    def test_not_in_sudoers(self):
        e = self.parse_one(
            "Sep 21 04:46:00 web-01 sudo:   guest : user NOT in sudoers ; TTY=pts/1 ; "
            "PWD=/tmp ; USER=root ; COMMAND=/bin/sh"
        )
        self.assertEqual(e.event_type, EventType.PRIV_ESCALATION_FAILED)
        self.assertEqual(e.extra["reason"], "not_in_sudoers")

    def test_uninteresting_lines_are_skipped(self):
        for line in (
            "Sep 21 04:17:00 web-01 CRON[999]: pam_unix(cron:session): session opened for user root",
            "Sep 21 04:18:00 web-01 systemd[1]: Started Daily apt upgrade.",
        ):
            self.assertIsNone(self.parse_one(line), line)

    def test_malformed_input_never_raises(self):
        junk = ["", "   ", "not a log line", "Sep 99 99:99:99", "\x00\xff binary",
                "Sep 21 04:00:00 host proc:"]
        for line in junk:
            self.assertIsNone(self.parse_one(line), repr(line))
        # A whole file of garbage yields zero events rather than an exception.
        self.assertEqual(list(self.parser.parse(junk)), [])


class TestNginxParser(unittest.TestCase):
    def setUp(self) -> None:
        self.parser = NginxAccessParser()

    def test_combined_format_fields(self):
        e = self.parser.parse_line(
            '45.83.91.22 - - [21/Sep/2026:04:20:11 +0000] "GET /a?b=1 HTTP/1.1" '
            '404 153 "-" "sqlmap/1.7"', 1
        )
        self.assertEqual(e.src_ip, "45.83.91.22")
        self.assertEqual(e.extra["status"], 404)
        self.assertEqual(e.extra["method"], "GET")
        self.assertEqual(e.extra["user_agent"], "sqlmap/1.7")

    def test_timezone_offset_is_normalized_to_utc(self):
        e = self.parser.parse_line(
            '1.2.3.4 - - [21/Sep/2026:09:20:11 +0500] "GET / HTTP/1.1" 200 10 "-" "x"', 1
        )
        self.assertEqual(e.timestamp.hour, 4)
        self.assertEqual(e.timestamp.minute, 20)

    def test_url_decoding_exposes_payload(self):
        e = self.parser.parse_line(
            '1.2.3.4 - - [21/Sep/2026:04:00:00 +0000] '
            '"GET /x?f=..%2F..%2Fetc%2Fpasswd HTTP/1.1" 200 10 "-" "curl/8"', 1
        )
        self.assertIn("../../etc/passwd", e.extra["path_decoded"])

    def test_dash_size_becomes_zero(self):
        e = self.parser.parse_line(
            '1.2.3.4 - - [21/Sep/2026:04:00:00 +0000] "GET / HTTP/1.1" 304 - "-" "x"', 1
        )
        self.assertEqual(e.extra["size"], 0)


class TestWindowsParser(unittest.TestCase):
    def setUp(self) -> None:
        self.parser = WindowsSecurityParser()

    def test_failed_logon_maps_status_reason(self):
        e = self.parser.parse_line(
            '{"TimeCreated":"2026-09-21T04:30:12Z","EventID":4625,"Computer":"DC-01",'
            '"TargetUserName":"administrator","IpAddress":"45.83.91.22",'
            '"LogonType":3,"Status":"0xc000006a"}', 1
        )
        self.assertEqual(e.event_type, EventType.AUTH_FAILURE)
        self.assertEqual(e.extra["status_reason"], "wrong password")
        self.assertEqual(e.extra["logon_type_name"], "Network")

    def test_group_membership_change(self):
        e = self.parser.parse_line(
            '{"TimeCreated":"2026-09-21T05:03:00Z","EventID":4728,"Computer":"DC-01",'
            '"TargetUserName":"svc_backup","TargetGroupName":"Domain Admins"}', 1
        )
        self.assertEqual(e.event_type, EventType.GROUP_MEMBER_ADDED)
        self.assertEqual(e.extra["target_group"], "Domain Admins")

    def test_loopback_ip_is_dropped(self):
        e = self.parser.parse_line(
            '{"TimeCreated":"2026-09-21T05:03:00Z","EventID":4624,'
            '"TargetUserName":"svc","IpAddress":"-"}', 1
        )
        self.assertIsNone(e.src_ip)

    def test_unmapped_event_id_is_skipped(self):
        self.assertIsNone(self.parser.parse_line(
            '{"TimeCreated":"2026-09-21T05:03:00Z","EventID":9999}', 1))

    def test_json_array_file_is_supported(self):
        blob = (
            '[{"TimeCreated":"2026-09-21T04:30:12Z","EventID":4625,'
            '"TargetUserName":"a","IpAddress":"1.2.3.4"},'
            '{"TimeCreated":"2026-09-21T04:31:12Z","EventID":4624,'
            '"TargetUserName":"b","IpAddress":"1.2.3.4"}]'
        )
        events = list(self.parser.parse([blob]))
        self.assertEqual(len(events), 2)


class TestAutoDetection(unittest.TestCase):
    def test_each_sample_picks_the_right_parser(self):
        expected = {
            "auth.log": "linux_auth",
            "nginx_access.log": "nginx_access",
            "windows_security.json": "windows_security",
        }
        for filename, parser_name in expected.items():
            path = os.path.join(SAMPLES, filename)
            self.assertTrue(os.path.exists(path), f"missing sample {filename}")
            parser = detect_parser(path, year=2026)
            self.assertIsNotNone(parser, filename)
            self.assertEqual(parser.name, parser_name, filename)

    def test_parse_paths_walks_a_directory_and_sorts_by_time(self):
        events, sources = parse_paths([SAMPLES], year=2026)
        self.assertGreater(len(events), 100)
        self.assertEqual(len(sources), 3)
        timestamps = [e.timestamp for e in events]
        self.assertEqual(timestamps, sorted(timestamps))


if __name__ == "__main__":
    unittest.main(verbosity=2)
