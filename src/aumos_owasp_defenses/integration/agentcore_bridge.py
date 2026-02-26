"""Optional agentcore-sdk event bus integration.

Provides ``OWASPEventBridge``, which subscribes to an agentcore event bus
and routes each event through ``OWASPGuard``.  Security violations are
emitted back onto the bus as structured security events.

Dependency
----------
This module requires the optional ``agentcore-sdk`` package.  If it is
not installed, importing this module raises ``ImportError`` with a
descriptive message rather than a bare ``ModuleNotFoundError``.

Usage
-----
Install the optional dependency::

    pip install aumos-owasp-defenses[agentcore]

Then construct the bridge::

    from aumos_owasp_defenses.integration.agentcore_bridge import OWASPEventBridge
    bridge = OWASPEventBridge(guard=OWASPGuard())
    bridge.attach(event_bus)

Design notes
------------
* The bridge is intentionally thin: it translates agentcore ``Event``
  objects into ``OWASPGuard.protect()`` calls and converts violations
  into ``SecurityEvent`` objects emitted on the bus.
* No agentcore internals are hard-coded; the bridge depends only on the
  published ``agentcore.events`` public API.
* If agentcore-sdk is not available the rest of the library continues to
  work normally; only this module is affected.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from aumos_owasp_defenses.middleware.guard import OWASPGuard, SecurityViolation

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional agentcore import
# ---------------------------------------------------------------------------

try:
    import agentcore.events as _agentcore_events  # type: ignore[import-untyped]

    _AGENTCORE_AVAILABLE = True
except ModuleNotFoundError:
    _AGENTCORE_AVAILABLE = False
    _agentcore_events = None  # type: ignore[assignment]

if TYPE_CHECKING:
    # Allow type-checkers to resolve agentcore types without a runtime import.
    try:
        import agentcore.events as agentcore_events_type
    except ModuleNotFoundError:
        pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _require_agentcore() -> None:
    """Raise a descriptive ImportError if agentcore-sdk is not installed."""
    if not _AGENTCORE_AVAILABLE:
        raise ImportError(
            "The 'agentcore-sdk' package is required to use OWASPEventBridge. "
            "Install it with: pip install aumos-owasp-defenses[agentcore]"
        )


# ---------------------------------------------------------------------------
# OWASPEventBridge
# ---------------------------------------------------------------------------


class OWASPEventBridge:
    """Subscribes to an agentcore event bus and runs events through OWASPGuard.

    Parameters
    ----------
    guard:
        The ``OWASPGuard`` instance to use for all security checks.  If
        ``None``, a default ``OWASPGuard()`` is constructed.
    security_event_type:
        The event type string used when emitting security violations back
        onto the bus.  Defaults to ``"owasp.security_violation"``.
    block_on_violation:
        When ``True``, the bridge emits a ``"owasp.block"`` event in
        addition to the violation event, signalling the bus to halt
        processing.  Defaults to ``True``.

    Raises
    ------
    ImportError
        If ``agentcore-sdk`` is not installed, raised on first call to
        ``attach()``.

    Example
    -------
    ::

        from agentcore.events import EventBus
        from aumos_owasp_defenses.integration.agentcore_bridge import OWASPEventBridge
        from aumos_owasp_defenses.middleware.guard import OWASPGuard

        bus = EventBus()
        bridge = OWASPEventBridge(guard=OWASPGuard())
        bridge.attach(bus)
        # The bridge now intercepts all "agent.input" events on the bus.
    """

    _SUBSCRIBED_EVENT_TYPES: tuple[str, ...] = (
        "agent.input",
        "agent.tool_call",
        "agent.message",
    )

    def __init__(
        self,
        guard: OWASPGuard | None = None,
        security_event_type: str = "owasp.security_violation",
        block_on_violation: bool = True,
    ) -> None:
        self._guard = guard or OWASPGuard()
        self._security_event_type = security_event_type
        self._block_on_violation = block_on_violation
        self._event_bus: object | None = None

    def attach(self, event_bus: object) -> None:
        """Subscribe to the agentcore *event_bus*.

        Parameters
        ----------
        event_bus:
            An agentcore ``EventBus`` instance.  This must be a live bus
            object; the bridge will register listeners for the event types
            listed in ``_SUBSCRIBED_EVENT_TYPES``.

        Raises
        ------
        ImportError
            If agentcore-sdk is not installed.
        """
        _require_agentcore()
        self._event_bus = event_bus

        for event_type in self._SUBSCRIBED_EVENT_TYPES:
            _agentcore_events.subscribe(event_bus, event_type, self.on_event)
            logger.debug("OWASPEventBridge subscribed to event_type=%r", event_type)

        logger.info(
            "OWASPEventBridge attached to event bus; subscribed to %d event types.",
            len(self._SUBSCRIBED_EVENT_TYPES),
        )

    def detach(self) -> None:
        """Unsubscribe from the event bus.

        Safe to call even if the bridge was never attached.
        """
        if self._event_bus is None:
            return
        _require_agentcore()
        for event_type in self._SUBSCRIBED_EVENT_TYPES:
            try:
                _agentcore_events.unsubscribe(
                    self._event_bus, event_type, self.on_event
                )
            except Exception as unsubscribe_error:
                logger.warning(
                    "OWASPEventBridge failed to unsubscribe event_type=%r: %s",
                    event_type,
                    unsubscribe_error,
                )
        self._event_bus = None
        logger.info("OWASPEventBridge detached from event bus.")

    def on_event(self, event: object) -> None:
        """Handle an event from the agentcore bus.

        Extracts the text payload and agent identity from the event,
        passes them through ``OWASPGuard.protect()``, and emits violation
        events for any violations found.

        Parameters
        ----------
        event:
            An agentcore ``Event`` object.  Expected to have at minimum:
            - ``.type`` (str): event type string.
            - ``.payload`` (dict): event payload.
            - ``.agent_id`` (str | None): originating agent identifier.
        """
        _require_agentcore()

        event_type = getattr(event, "type", "unknown")
        payload = getattr(event, "payload", {})
        agent_id = str(getattr(event, "agent_id", "unknown") or "unknown")

        # Extract the text content to inspect.
        input_text: str = ""
        context: dict[str, object] = {}

        if isinstance(payload, dict):
            # Common agentcore payload conventions.
            input_text = str(payload.get("text") or payload.get("content") or "")
            if "tool_name" in payload:
                context["tool_call"] = payload
            if "message_type" in payload:
                context["agent_message"] = payload
            drift_obs = payload.get("drift_observations")
            if isinstance(drift_obs, dict):
                context["drift_observations"] = drift_obs

        if not input_text and not context:
            # Nothing to inspect.
            return

        guard_result = self._guard.protect(
            input_text=input_text,
            agent_id=agent_id,
            context=context,
        )

        if guard_result.violations:
            self._emit_violations(event_bus=self._event_bus, agent_id=agent_id, source_event_type=event_type, violations=guard_result.violations)

        if not guard_result.passed and self._block_on_violation:
            self._emit_block(event_bus=self._event_bus, agent_id=agent_id, source_event_type=event_type)

        for warning_message in guard_result.warnings:
            logger.warning(
                "OWASPGuard warning agent=%r event_type=%r: %s",
                agent_id,
                event_type,
                warning_message,
            )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _emit_violations(
        self,
        event_bus: object,
        agent_id: str,
        source_event_type: str,
        violations: list[SecurityViolation],
    ) -> None:
        """Emit a security violation event onto the bus."""
        for violation in violations:
            logger.warning(
                "OWASP_VIOLATION agent=%r category=%r severity=%r: %s",
                agent_id,
                violation.category,
                violation.severity,
                violation.description,
            )
            try:
                _agentcore_events.emit(
                    event_bus,
                    self._security_event_type,
                    {
                        "agent_id": agent_id,
                        "source_event_type": source_event_type,
                        "category": violation.category,
                        "severity": violation.severity,
                        "description": violation.description,
                    },
                )
            except Exception as emit_error:
                logger.error(
                    "OWASPEventBridge failed to emit violation event: %s",
                    emit_error,
                )

    def _emit_block(
        self,
        event_bus: object,
        agent_id: str,
        source_event_type: str,
    ) -> None:
        """Emit a block event signalling the bus to halt processing."""
        try:
            _agentcore_events.emit(
                event_bus,
                "owasp.block",
                {
                    "agent_id": agent_id,
                    "source_event_type": source_event_type,
                    "reason": "OWASPGuard detected one or more high/critical violations.",
                },
            )
        except Exception as emit_error:
            logger.error(
                "OWASPEventBridge failed to emit block event: %s", emit_error
            )
