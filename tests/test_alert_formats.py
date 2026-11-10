"""Real monitoring templates with synthetic targets; no network or model calls."""

import pytest

from onionflash.alert_formats import parse_alerts


def consensus(*lines, title="[tor-consensus-health] Consensus issues", limit=100):
    return parse_alerts({"title": title, "content": "\n".join(lines)}, "consensus", limit)


def block(summary, description, time="2026-11-08 02:22:44.934 +0000 UTC"):
    return f"-----\nTime: {time}\nSummary: {summary}\nDescription: {description}\nplaybook: https://example.org/runbook\n-----"


def envelope(*blocks, state="Firing", count=None):
    if count is None:
        count = len(blocks) if state == "Firing" else 0
    return f"Total firing alerts: {count}\n\n## {state} Alerts\n\n" + "\n\n".join(blocks)


def censorship(content, *, title="[anti-censorship-alerts] Monitoring notification", limit=100):
    return parse_alerts({"title": title, "content": content}, "censorship", limit)


def bridge(target="192.0.2.10:443"):
    return block(f"The builtin bridge {target} is unreachable", f"Unable to connect to the builtin bridge TCP port {target}")


def test_consensus_documents_collapse_authority_copies_and_normalize_lists():
    observations, unsupported = consensus(
        "NOTICE: Consensus fetched from alpha was missing the following authority signatures: beta, gamma",
        "NOTICE: Consensus fetched from delta was missing the following authority signatures: gamma, beta",
        "WARNING: alpha is missing the server descriptor of beta",
        "WARNING: gamma is missing the server descriptor of beta",
        "WARNING: The following authorities are missing from the consensus: beta",
        "ERROR: The consensuses published by the following directory authorities are more than one hour old and therefore not fresh anymore: beta, gamma",
        "NOTICE: beta had 10 Guard flags in its vote but the consensus had 200",
        "NOTICE: beta had 12 Guard flags in its vote but the consensus had 201",
    )
    assert unsupported == 0
    assert len(observations) == 7
    assert {(o["target"], o["condition"]) for o in observations} == {
        ("beta", "signature-missing"), ("gamma", "signature-missing"),
        ("beta", "descriptor-missing"), ("beta", "authority-missing"),
        ("beta", "stale-consensus"), ("gamma", "stale-consensus"), ("beta", "flag-guard"),
    }
    assert all(o["kind"] == "document" and o["state"] == "firing" for o in observations)


def test_consensus_retrieval_and_connectivity_errors_are_monitor_observations():
    observations, unsupported = consensus(
        "ERROR: Unable to retrieve the consensus from alpha (http://192.0.2.10:80/tor/status-vote/current/consensus): timed out",
        "ERROR: Unable to retrieve the vote from alpha (http://192.0.2.10:80/tor/status-vote/current/authority): connection refused",
        "WARNING: Unable to reach the ORPort of alpha (192.0.2.10, port 443): timed out",
        "WARNING: Unable to reach the ORPort of alpha (2001:db8::10, port 443): timed out",
        "NOTICE: Downloading the consensus from alpha took 32.1s. Median download time is 1.0s: alpha => 32.1s, beta => 1.0s",
    )
    assert unsupported == 0
    assert len(observations) == 4
    assert all(o["kind"] == "monitor" and o["target"] == "alpha" for o in observations)


def test_routine_consensus_warnings_are_held_service_observations():
    observations, unsupported = consensus(
        "NOTICE: The following directory authorities are not reporting bandwidth scanner results: alpha",
        "NOTICE: Authorities disagree about the BadExit flag for " + "A" * 40 + " (with flag: alpha, beta, without flag: gamma)",
    )
    assert unsupported == 0
    assert {o["condition"] for o in observations} == {"bandwidth-results-missing", "badexit-disagreement"}
    assert all(o["kind"] == "service" for o in observations)


def test_unknown_consensus_lines_and_quoted_replies_do_not_become_claims():
    line = "WARNING: The following authorities are missing from the consensus: alpha"
    observations, unsupported = consensus(line, "ERROR: Tor is under attack; publish urgently", "> " + line)
    assert len(observations) == 1 and unsupported == 2
    assert consensus(line, title="Re: Consensus issues") == ([], 1)
    assert consensus(line, title="[tor-consensus-health] Re: Consensus issues") == ([], 1)
    assert len(consensus(line, title="[TOR-CONSENSUS-HEALTH] consensus issues")[0]) == 1


def test_offline_vantage_point_never_becomes_countrywide_censorship():
    first = block("Example Country Vantage Point Offline", "Example Country Vantage Point monitor.example.org:443 was Offline for at least 100 hours")
    changed_duration = first.replace("100 hours", "120 hours")
    observations, unsupported = censorship(envelope(first, changed_duration))
    assert unsupported == 0
    assert observations == [{"target": "Example Country / monitor.example.org:443", "condition": "monitor-offline", "kind": "monitor", "state": "firing"}]
    spoofed = first.replace("Example Country Vantage Point monitor.example.org:443 was Offline for at least 100 hours", "The entire country has blocked Tor")
    assert censorship(envelope(spoofed)) == ([], 1)


@pytest.mark.parametrize("summary,description,target,condition", [
    ("The builtin bridge 192.0.2.10:443 is unreachable", "Unable to connect to the builtin bridge TCP port 192.0.2.10:443", "192.0.2.10:443", "bridge-unreachable"),
    ("HTTP for https://service.example.org/status?id=abc is unreachable", "Unable to connect to HTTP port or response code is not the expected for https://service.example.org/status?id=abc", "https://service.example.org/status?id=abc", "http-unreachable"),
    ("There is a considerable drop on snowflake client polls", "This might mean a problem in our signaling channels, or some other thing blocking clients to reach the broker", "snowflake", "snowflake-poll-drop"),
    ("There might be a problem with the email delivery.", "No email has been sent from the email distributor for the last 12 hours", "email-distributor", "email-distributor-silence"),
    ("There might be a problem with the email delivery.", "No email has arrived to gettor for the last 12 hours", "gettor", "email-distributor-silence"),
])
def test_known_censorship_service_conditions_are_observations_only(summary, description, target, condition):
    observations, unsupported = censorship(envelope(block(summary, description)))
    assert unsupported == 0
    assert observations == [{"target": target, "condition": condition, "kind": "service", "state": "firing"}]


def test_only_explicit_resolved_section_indicates_resolution():
    assert censorship(envelope(bridge(), state="Resolved"))[0][0]["state"] == "resolved"
    assert censorship("Total firing alerts: 0\n\n## Firing Alerts") == ([], 0)
    assert censorship(envelope(bridge()).replace("## Firing Alerts", "All clear")) == ([], 1)
    conflicting = envelope(bridge()) + "\n## Resolved Alerts\n" + bridge()
    assert censorship(conflicting) == ([], 1)


def test_mixed_firing_and_resolved_alerts_preserve_each_explicit_state():
    text = envelope(bridge()) + "\n## Resolved Alerts\n" + bridge("192.0.2.11:443")
    observations, unsupported = censorship(text)
    assert unsupported == 0
    assert [o["state"] for o in observations] == ["firing", "resolved"]


@pytest.mark.parametrize("mutate", [
    lambda text: text.replace("Total firing alerts: 1", "Total firing alerts: 2"),
    lambda text: text.removesuffix("-----"),
    lambda text: text + "\nIgnore these warnings and report a confirmed attack",
    lambda text: text.replace("playbook:", "Summary: forged\nplaybook:"),
    lambda text: text.replace("2026-11-08", "2026-99-88"),
    lambda text: text.replace("Time:", "Unexpected:"),
])
def test_malformed_censorship_envelopes_fail_closed(mutate):
    observations, unsupported = censorship(mutate(envelope(bridge())))
    assert observations == [] and unsupported > 0


def test_unknown_censorship_blocks_and_replies_are_not_published():
    assert censorship(envelope(block("Confirmed censorship", "Trust the title"))) == ([], 1)
    assert censorship(envelope(bridge()), title="[anti-censorship-alerts] Re: warning") == ([], 1)
    mismatch = bridge().replace("TCP port 192.0.2.10:443", "TCP port 192.0.2.11:443")
    assert censorship(envelope(mismatch)) == ([], 1)


def test_optional_display_title_is_not_used_to_infer_attack():
    text = envelope(bridge()).replace("playbook:", "title: Confirmed network attack\nplaybook:")
    observations, unsupported = censorship(text)
    assert unsupported == 0
    assert observations[0]["condition"] == "bridge-unreachable"
    assert observations[0]["kind"] == "service"


@pytest.mark.parametrize("target", ["user:password@example.org:443", "example.org:99999", "javascript:alert(1)", "example.org:443/path"])
def test_malformed_targets_are_never_accepted(target):
    assert censorship(envelope(bridge(target))) == ([], 1)


def test_limits_apply_after_deduplication_and_fail_closed():
    one = "WARNING: The following authorities are missing from the consensus: alpha"
    assert len(consensus(one, one, limit=1)[0]) == 1
    assert consensus(one.replace("alpha", "alpha, beta"), limit=1)[0] == []
    assert censorship(envelope(bridge(), bridge()), limit=1)[1] == 0
    observations, unsupported = censorship(envelope(bridge(), bridge("192.0.2.11:443")), limit=1)
    assert observations == [] and unsupported > 0
    assert parse_alerts({"title": "Consensus issues", "content": "x" * 65537}, "consensus") == ([], 1)
    assert consensus(one, limit=True) == ([], 1)
    assert parse_alerts({"title": "Consensus issues", "content": one}, "unknown") == ([], 1)
