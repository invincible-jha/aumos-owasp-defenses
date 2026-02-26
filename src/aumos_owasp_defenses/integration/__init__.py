"""Optional integrations with external agent platforms.

Public surface
--------------
``OWASPEventBridge``
    Subscribes to an AgentCore event bus and runs OWASP ASI defense checks
    against every agent lifecycle event.
``AgentCoreBridge``
    Alias for ``OWASPEventBridge`` (backward-compatible short name).

The agentcore-sdk is an optional dependency.  This package can be imported
without it; only calling ``OWASPEventBridge.attach()`` will raise if the
dependency is not installed.
"""
from __future__ import annotations

from aumos_owasp_defenses.integration.agentcore_bridge import OWASPEventBridge

# Friendly alias for the spec's ``AgentCoreBridge`` name.
AgentCoreBridge = OWASPEventBridge

__all__ = ["AgentCoreBridge", "OWASPEventBridge"]
