"""
NYX Autonomous Agent State Machine
Enforces sequential agent lifecycle state transitions:
IDLE -> ANALYZING -> PLANNING -> WAITING_APPROVAL -> EXECUTING -> VALIDATING -> REPORTING -> COMPLETED
"""
from __future__ import annotations

from typing import List

AGENT_VALID_STATES: List[str] = [
    "IDLE",
    "ANALYZING",
    "PLANNING",
    "WAITING_APPROVAL",
    "EXECUTING",
    "VALIDATING",
    "REPORTING",
    "COMPLETED",
]


class AgentStateMachine:
    """Manages state transitions for the autonomous research agent."""

    def __init__(self, initial_state: str = "IDLE"):
        self._current_state: str = initial_state if initial_state in AGENT_VALID_STATES else "IDLE"

    @property
    def current_state(self) -> str:
        return self._current_state

    def can_transition_to(self, new_state: str, force: bool = False) -> bool:
        """Verify whether transition from current state to new state is allowed."""
        if force:
            return new_state in AGENT_VALID_STATES

        if new_state not in AGENT_VALID_STATES:
            return False

        curr_idx = AGENT_VALID_STATES.index(self._current_state)
        new_idx = AGENT_VALID_STATES.index(new_state)

        # Allow resetting back to IDLE at any time
        if new_state == "IDLE":
            return True

        # Allow forward transition by 1 step or staying in same state
        if new_idx == curr_idx + 1 or new_idx == curr_idx:
            return True

        # Allow returning to PLANNING from WAITING_APPROVAL or EXECUTING if denied
        if self._current_state in ("WAITING_APPROVAL", "EXECUTING") and new_state == "PLANNING":
            return True

        return False

    def transition_to(self, new_state: str, force: bool = False) -> tuple[bool, str]:
        """Transition agent to a new state."""
        ns = new_state.upper()
        if not self.can_transition_to(ns, force=force):
            return False, f"Invalid transition from {self._current_state} to {ns}."

        prev = self._current_state
        self._current_state = ns
        return True, f"Transitioned agent state from {prev} to {ns}."

    set_state = transition_to
