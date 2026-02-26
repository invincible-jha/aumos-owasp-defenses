"""ASI-04: Supply Chain and Dependency Risks defenses.

Public surface
--------------
``VendorVerifier``
    Verifies tool/plugin integrity via hash comparison against an allowlist.
``AllowlistEntry``
    A single entry in the vendor allowlist.
``VerificationResult``
    Result object returned by ``VendorVerifier.verify()``.
"""
from __future__ import annotations

from aumos_owasp_defenses.defenses.asi04_supply_chain.vendor_verifier import (
    AllowlistEntry,
    VendorVerifier,
    VerificationResult,
)

__all__ = [
    "AllowlistEntry",
    "VendorVerifier",
    "VerificationResult",
]
