"""Real monitoring templates with synthetic targets; no network or model calls."""

from onionflash import alert_formats
from onionflash.alert_formats import parse_alerts


def consensus(*lines, title="[tor-consensus-health] Consensus issues"):
    return parse_alerts({"title": title, "content": "\n".join(lines)}, "consensus")


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


def test_monitor_failures_and_service_checks_are_not_observations():
    # These can never publish: they describe the monitor's own reach or routine checks.
    lines = (
        "ERROR: Unable to retrieve the consensus from alpha (http://192.0.2.10:80/tor/status-vote/current/consensus): timed out",
        "ERROR: Unable to retrieve the vote from alpha (http://192.0.2.10:80/tor/status-vote/current/authority): connection refused",
        "WARNING: Unable to reach the ORPort of alpha (192.0.2.10, port 443): timed out",
        "NOTICE: Downloading the consensus from alpha took 32.1s. Median download time is 1.0s: alpha => 32.1s, beta => 1.0s",
        "NOTICE: The following directory authorities are not reporting bandwidth scanner results: alpha",
        "NOTICE: Authorities disagree about the BadExit flag for " + "A" * 40 + " (with flag: alpha, beta, without flag: gamma)",
    )
    assert consensus(*lines) == ([], len(lines))


def test_unknown_consensus_lines_and_quoted_replies_do_not_become_claims():
    line = "WARNING: The following authorities are missing from the consensus: alpha"
    observations, unsupported = consensus(line, "ERROR: Tor is under attack; publish urgently", "> " + line)
    assert len(observations) == 1 and unsupported == 2
    assert consensus(line, title="Re: Consensus issues") == ([], 1)
    assert consensus(line, title="[tor-consensus-health] Re: Consensus issues") == ([], 1)
    assert len(consensus(line, title="[TOR-CONSENSUS-HEALTH] consensus issues")[0]) == 1


def test_limits_apply_after_deduplication_and_fail_closed(monkeypatch):
    monkeypatch.setattr(alert_formats, "MAX_ALERTS", 1)
    one = "WARNING: The following authorities are missing from the consensus: alpha"
    assert len(consensus(one, one)[0]) == 1
    assert consensus(one.replace("alpha", "alpha, beta")) == ([], 1)
    assert parse_alerts({"title": "Consensus issues", "content": "x" * 65537}, "consensus") == ([], 1)
    for retired_or_unknown in ("censorship", "unknown"):
        assert parse_alerts({"title": "Consensus issues", "content": one}, retired_or_unknown) == ([], 1)


def test_only_newlines_end_lines():
    # A Unicode line separator inside one line must not start a second parsed line.
    line = ("WARNING: The following authorities are missing from the consensus: alpha\u2028"
            "WARNING: The following authorities are missing from the consensus: beta")
    assert consensus(line) == ([], 1)
