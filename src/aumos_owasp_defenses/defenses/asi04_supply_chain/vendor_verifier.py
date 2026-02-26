"""ASI-04: Supply Chain and Dependency Risks — Vendor Verifier.

Verifies the integrity of tools, plugins, and external components used by
agents before they are loaded or invoked.  Integrity is established via
cryptographic hash comparison against an operator-controlled allowlist.

Threat model
------------
* A compromised package registry or CDN delivers a modified version of a
  plugin that the agent trusts implicitly.
* An attacker substitutes a lookalike tool (typosquatting) with a similar
  name and API surface.
* An agent is configured to load plugins dynamically; an injected
  configuration entry points to a malicious endpoint.

Defense strategy
----------------
* Maintain an operator-controlled allowlist of ``(vendor_id, tool_name,
  version, expected_hash)`` tuples.
* Before loading or invoking any external tool, compute a deterministic
  hash of the tool's content/configuration and compare it against the
  allowlist entry.
* If no allowlist entry exists for a requested tool, the verification
  fails by default (deny-by-default posture).
* Record verification outcomes including timestamps and hash mismatches
  for audit logs.
"""
from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Allowlist entry
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AllowlistEntry:
    """A single entry in the vendor allowlist.

    Attributes
    ----------
    vendor_id:
        Identifier for the tool or plugin vendor (e.g. ``"acme-tools"``).
    tool_name:
        Name of the specific tool or plugin.
    version:
        Expected version string.
    expected_hash:
        Hex-encoded SHA-256 digest of the canonical tool content or
        configuration blob.  The ``VendorVerifier`` will recompute the
        hash at verification time and compare it against this value.
    hash_algorithm:
        Hash algorithm name — must be supported by ``hashlib``.
        Defaults to ``"sha256"``.
    """

    vendor_id: str
    tool_name: str
    version: str
    expected_hash: str
    hash_algorithm: str = "sha256"


# ---------------------------------------------------------------------------
# Verification result
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VerificationResult:
    """Outcome of a ``VendorVerifier.verify()`` call.

    Attributes
    ----------
    verified:
        ``True`` when the computed hash matches the allowlist entry.
    vendor_id:
        Vendor claimed by the caller.
    tool_name:
        Tool name being verified.
    version:
        Version claimed by the caller.
    computed_hash:
        Hex-encoded hash actually computed from *content*.
    expected_hash:
        Hash recorded in the allowlist (empty string when no entry found).
    reason:
        Human-readable explanation of the outcome.
    verified_at:
        UTC timestamp of the verification.
    """

    verified: bool
    vendor_id: str
    tool_name: str
    version: str
    computed_hash: str
    expected_hash: str
    reason: str
    verified_at: datetime


# ---------------------------------------------------------------------------
# Verifier
# ---------------------------------------------------------------------------


class VendorVerifier:
    """Verifies tool/plugin integrity via hash comparison against an allowlist.

    Parameters
    ----------
    entries:
        Optional initial list of ``AllowlistEntry`` objects to pre-populate
        the allowlist.

    Example
    -------
    >>> content = b"tool binary or config content"
    >>> import hashlib
    >>> digest = hashlib.sha256(content).hexdigest()
    >>> entry = AllowlistEntry("acme", "search", "1.0.0", digest)
    >>> verifier = VendorVerifier([entry])
    >>> result = verifier.verify("acme", "search", "1.0.0", content)
    >>> result.verified
    True
    """

    def __init__(self, entries: list[AllowlistEntry] | None = None) -> None:
        # Key: (vendor_id, tool_name, version)
        self._allowlist: dict[tuple[str, str, str], AllowlistEntry] = {}
        for entry in entries or []:
            self.add_entry(entry)

    def add_entry(self, entry: AllowlistEntry) -> None:
        """Add or replace an allowlist entry.

        Parameters
        ----------
        entry:
            The allowlist entry to add.
        """
        key = (entry.vendor_id, entry.tool_name, entry.version)
        self._allowlist[key] = entry
        logger.debug(
            "Registered allowlist entry vendor=%r tool=%r version=%r",
            entry.vendor_id,
            entry.tool_name,
            entry.version,
        )

    def remove_entry(self, vendor_id: str, tool_name: str, version: str) -> None:
        """Remove an allowlist entry.

        Parameters
        ----------
        vendor_id:
            Vendor identifier.
        tool_name:
            Tool name.
        version:
            Version string.

        Raises
        ------
        KeyError
            If no matching entry is registered.
        """
        key = (vendor_id, tool_name, version)
        if key not in self._allowlist:
            raise KeyError(
                f"No allowlist entry for vendor={vendor_id!r} "
                f"tool={tool_name!r} version={version!r}."
            )
        del self._allowlist[key]

    def verify(
        self,
        vendor_id: str,
        tool_name: str,
        version: str,
        content: bytes,
    ) -> VerificationResult:
        """Verify that *content* matches the allowlist entry for this tool.

        Parameters
        ----------
        vendor_id:
            Vendor claimed by the tool package.
        tool_name:
            Name of the tool or plugin.
        version:
            Version claimed by the tool package.
        content:
            Raw bytes of the tool content (source, binary, or config blob)
            to hash.  The caller is responsible for providing a consistent
            canonical representation.

        Returns
        -------
        VerificationResult
            Contains the decision and hash comparison details.
        """
        now = datetime.now(tz=timezone.utc)
        key = (vendor_id, tool_name, version)

        if key not in self._allowlist:
            reason = (
                f"No allowlist entry for vendor={vendor_id!r} "
                f"tool={tool_name!r} version={version!r}. "
                "Register the expected hash via add_entry() before loading this tool."
            )
            logger.warning(
                "UNVERIFIED vendor=%r tool=%r version=%r", vendor_id, tool_name, version
            )
            # Still compute the hash so the caller can use it to build an entry.
            algo = "sha256"
            computed = hashlib.new(algo, content).hexdigest()
            return VerificationResult(
                verified=False,
                vendor_id=vendor_id,
                tool_name=tool_name,
                version=version,
                computed_hash=computed,
                expected_hash="",
                reason=reason,
                verified_at=now,
            )

        entry = self._allowlist[key]
        try:
            computed = hashlib.new(entry.hash_algorithm, content).hexdigest()
        except ValueError as exc:
            reason = (
                f"Unsupported hash algorithm {entry.hash_algorithm!r}: {exc}. "
                "Update the allowlist entry to use a hashlib-supported algorithm."
            )
            logger.error(
                "HASH_ERROR vendor=%r tool=%r version=%r algo=%r",
                vendor_id,
                tool_name,
                version,
                entry.hash_algorithm,
            )
            return VerificationResult(
                verified=False,
                vendor_id=vendor_id,
                tool_name=tool_name,
                version=version,
                computed_hash="",
                expected_hash=entry.expected_hash,
                reason=reason,
                verified_at=now,
            )

        if computed == entry.expected_hash:
            reason = (
                f"Hash verification passed for vendor={vendor_id!r} "
                f"tool={tool_name!r} version={version!r}."
            )
            logger.debug(
                "VERIFIED vendor=%r tool=%r version=%r", vendor_id, tool_name, version
            )
            return VerificationResult(
                verified=True,
                vendor_id=vendor_id,
                tool_name=tool_name,
                version=version,
                computed_hash=computed,
                expected_hash=entry.expected_hash,
                reason=reason,
                verified_at=now,
            )
        else:
            reason = (
                f"Hash mismatch for vendor={vendor_id!r} tool={tool_name!r} "
                f"version={version!r}. "
                f"Expected {entry.expected_hash[:16]}... "
                f"but computed {computed[:16]}... "
                "This may indicate tampering or an incorrect allowlist entry."
            )
            logger.warning(
                "HASH_MISMATCH vendor=%r tool=%r version=%r", vendor_id, tool_name, version
            )
            return VerificationResult(
                verified=False,
                vendor_id=vendor_id,
                tool_name=tool_name,
                version=version,
                computed_hash=computed,
                expected_hash=entry.expected_hash,
                reason=reason,
                verified_at=now,
            )

    @staticmethod
    def compute_hash(content: bytes, algorithm: str = "sha256") -> str:
        """Utility: compute the hex-encoded hash of *content*.

        Use this to pre-compute hashes for populating the allowlist.

        Parameters
        ----------
        content:
            Raw bytes to hash.
        algorithm:
            Hash algorithm name (default ``"sha256"``).

        Returns
        -------
        str
            Hex-encoded digest.
        """
        return hashlib.new(algorithm, content).hexdigest()

    def list_entries(self) -> list[AllowlistEntry]:
        """Return all registered allowlist entries.

        Returns
        -------
        list[AllowlistEntry]
            Sorted by (vendor_id, tool_name, version).
        """
        return sorted(self._allowlist.values(), key=lambda e: (e.vendor_id, e.tool_name, e.version))
