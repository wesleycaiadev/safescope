"""ResourceLedger tests — create, owns, snapshot, pending, cleanup."""

from __future__ import annotations

from safescope_core.policy.ledger import ResourceLedger


class TestLedgerCreate:
    def test_record_and_owns(self) -> None:
        ledger = ResourceLedger("SCAN-001")
        url = "https://acme.com.br/api/test"
        ledger.record_create(url, "POST", "__SPROOF_001_probe")
        assert ledger.owns(url)
        assert not ledger.owns("https://acme.com.br/other")

    def test_duplicate_url_reuses_entry(self) -> None:
        """Case 10: same URL already ledgered → reuse, not duplicate."""
        ledger = ResourceLedger("SCAN-001")
        url = "https://acme.com.br/api/test"
        ledger.record_create(url, "POST", "__SPROOF_001")
        ledger.record_create(url, "POST", "__SPROOF_002")
        assert ledger.created_count == 1

    def test_different_urls_are_separate(self) -> None:
        ledger = ResourceLedger("SCAN-001")
        ledger.record_create("https://acme.com.br/a", "POST", "__SPROOF_001")
        ledger.record_create("https://acme.com.br/b", "POST", "__SPROOF_002")
        assert ledger.created_count == 2


class TestLedgerSnapshot:
    def test_snapshot_existing_resource(self) -> None:
        """Case 9: capture state before mutating resource we didn't create."""
        ledger = ResourceLedger("SCAN-001")
        url = "https://acme.com.br/api/users/me"
        state = {"role": "user", "name": "test"}
        ledger.snapshot(url, state)
        assert ledger.has_snapshot(url)
        assert not ledger.has_snapshot("https://other.com")

    def test_snapshot_not_overwritten(self) -> None:
        """First snapshot wins — state_before is the original state."""
        ledger = ResourceLedger("SCAN-001")
        url = "https://acme.com.br/api/users/me"
        ledger.snapshot(url, {"role": "user"})
        ledger.snapshot(url, {"role": "admin"})  # should not overwrite
        plan = ledger.restore_plan()
        assert plan[url]["role"] == "user"

    def test_restore_plan(self) -> None:
        ledger = ResourceLedger("SCAN-001")
        ledger.snapshot("https://acme.com.br/a", {"x": 1})
        ledger.snapshot("https://acme.com.br/b", {"y": 2})
        plan = ledger.restore_plan()
        assert len(plan) == 2


class TestLedgerCleanup:
    def test_pending_before_cleanup(self) -> None:
        ledger = ResourceLedger("SCAN-001")
        ledger.record_create("https://acme.com.br/a", "POST", "__SPROOF_001")
        ledger.record_create("https://acme.com.br/b", "POST", "__SPROOF_002")
        assert len(ledger.pending()) == 2

    def test_mark_cleaned(self) -> None:
        ledger = ResourceLedger("SCAN-001")
        url = "https://acme.com.br/a"
        ledger.record_create(url, "POST", "__SPROOF_001")
        ledger.mark_cleaned(url)
        assert len(ledger.pending()) == 0
        assert ledger.cleaned_count == 1

    def test_mark_cleanup_failed(self) -> None:
        ledger = ResourceLedger("SCAN-001")
        url = "https://acme.com.br/a"
        ledger.record_create(url, "POST", "__SPROOF_001")
        ledger.mark_cleanup_failed(url, "404 Not Found")
        entries = ledger.all_entries()
        assert entries[0].cleanup_error == "404 Not Found"
        assert len(ledger.pending()) == 1  # still pending
