"""KillSwitch tests — engage, disengage, state."""

from __future__ import annotations

from safescope_core.policy.gate import KillSwitch


class TestKillSwitch:
    def test_default_disengaged(self) -> None:
        ks = KillSwitch()
        assert ks.engaged is False
        assert ks.reason == ""

    def test_engage(self) -> None:
        ks = KillSwitch()
        ks.engage(reason="incident detected", actor="wesley")
        assert ks.engaged is True
        assert ks.reason == "incident detected"
        assert ks.actor == "wesley"

    def test_disengage(self) -> None:
        ks = KillSwitch()
        ks.engage(reason="test", actor="ci")
        ks.disengage(actor="admin")
        assert ks.engaged is False
        assert ks.actor == "admin"

    def test_state_dict(self) -> None:
        ks = KillSwitch()
        ks.engage(reason="emergency", actor="ops")
        state = ks.state()
        assert state["engaged"] is True
        assert state["reason"] == "emergency"
        assert state["actor"] == "ops"
        assert "at" in state
