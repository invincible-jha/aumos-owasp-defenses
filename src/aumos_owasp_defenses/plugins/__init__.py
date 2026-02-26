"""Plugin subsystem for aumos-owasp-defenses.

The registry module provides the decorator-based registration surface.
Third-party implementations register via this system using
``importlib.metadata`` entry-points under the "aumos_owasp_defenses.plugins"
group.

Example
-------
Declare a plugin in pyproject.toml:

.. code-block:: toml

    [aumos_owasp_defenses.plugins]
    my_plugin = "my_package.plugins.my_plugin:MyPlugin"
"""
from __future__ import annotations

from aumos_owasp_defenses.plugins.registry import PluginRegistry

__all__ = ["PluginRegistry"]
