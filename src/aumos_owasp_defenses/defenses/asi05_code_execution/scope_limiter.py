"""ASI-05: Insecure Code Execution — Scope Limiter.

Restricts the files, directories, and shell commands an agent's code
execution environment is permitted to access.  Acts as a policy gate
before any path-access or command-execution is dispatched.

Threat model
------------
* An agent executing generated code may attempt to read or write files
  outside its designated working directory (path traversal).
* Generated code may embed shell commands that invoke system utilities
  capable of data exfiltration, privilege escalation, or persistence.
* Recursive or looping code may consume excessive system resources.

Defense strategy
----------------
* ``check_path()``: Resolve the requested path to an absolute form and
  verify it resides within one of the configured allowed root directories.
  Reject paths that traverse upward via ``..`` components.
* ``check_command()``: Tokenise the command string and check the executable
  (first token) against an operator-configured allowlist.  Reject any
  command whose executable is absent from the allowlist.
* Both methods return structured result objects so middleware layers can
  log, warn, or block uniformly.
"""
from __future__ import annotations

import logging
import shlex
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PathCheckResult:
    """Outcome of a ``ScopeLimiter.check_path()`` call.

    Attributes
    ----------
    allowed:
        ``True`` when the path is within the permitted scope.
    requested_path:
        The path string as provided by the caller.
    resolved_path:
        The absolute, normalised path that was evaluated.
    reason:
        Human-readable explanation of the decision.
    """

    allowed: bool
    requested_path: str
    resolved_path: str
    reason: str


@dataclass(frozen=True)
class CommandCheckResult:
    """Outcome of a ``ScopeLimiter.check_command()`` call.

    Attributes
    ----------
    allowed:
        ``True`` when the command's executable is on the allowlist.
    command:
        The raw command string that was evaluated.
    executable:
        The executable token extracted from the command string.
    reason:
        Human-readable explanation of the decision.
    """

    allowed: bool
    command: str
    executable: str
    reason: str


# ---------------------------------------------------------------------------
# Scope limiter
# ---------------------------------------------------------------------------


class ScopeLimiter:
    """Enforces file-path and command-execution scope restrictions.

    Parameters
    ----------
    allowed_roots:
        List of directory paths the agent is permitted to access.  Paths
        may be relative (resolved against the process cwd) or absolute.
        If empty, **all** path checks fail (deny-everything posture).
    allowed_commands:
        Set of executable names (not full paths) the agent is permitted to
        run.  If empty, **all** command checks fail.
    allow_read_only_paths:
        Additional paths the agent may read but not write.  Currently
        enforced at the check level via the ``mode`` parameter.

    Example
    -------
    >>> limiter = ScopeLimiter(
    ...     allowed_roots=["/tmp/agent_workspace"],
    ...     allowed_commands={"python3", "pip"},
    ... )
    >>> limiter.check_path("/tmp/agent_workspace/output.txt").allowed
    True
    >>> limiter.check_path("/etc/passwd").allowed
    False
    >>> limiter.check_command("python3 script.py").allowed
    True
    >>> limiter.check_command("curl https://example.com").allowed
    False
    """

    def __init__(
        self,
        allowed_roots: list[str] | None = None,
        allowed_commands: set[str] | None = None,
        allow_read_only_paths: list[str] | None = None,
    ) -> None:
        self._allowed_roots: list[Path] = [
            Path(root).resolve() for root in (allowed_roots or [])
        ]
        self._allowed_commands: set[str] = set(allowed_commands or [])
        self._read_only_roots: list[Path] = [
            Path(root).resolve() for root in (allow_read_only_paths or [])
        ]

    # ------------------------------------------------------------------
    # Configuration helpers
    # ------------------------------------------------------------------

    def add_allowed_root(self, root: str) -> None:
        """Add a directory to the allowed path roots.

        Parameters
        ----------
        root:
            Directory path string (absolute or relative).
        """
        resolved = Path(root).resolve()
        if resolved not in self._allowed_roots:
            self._allowed_roots.append(resolved)

    def add_allowed_command(self, executable: str) -> None:
        """Add an executable name to the command allowlist.

        Parameters
        ----------
        executable:
            Bare executable name (e.g. ``"python3"``), not a full path.
        """
        self._allowed_commands.add(executable)

    def remove_allowed_command(self, executable: str) -> None:
        """Remove an executable from the allowlist.

        Parameters
        ----------
        executable:
            Bare executable name to remove.
        """
        self._allowed_commands.discard(executable)

    # ------------------------------------------------------------------
    # Path check
    # ------------------------------------------------------------------

    def check_path(self, path: str, mode: str = "read") -> PathCheckResult:
        """Verify that *path* is within an allowed root directory.

        Parameters
        ----------
        path:
            The file or directory path to evaluate.
        mode:
            Access mode: ``"read"`` or ``"write"``.  Write access to
            read-only roots is denied even if the path resolves correctly.

        Returns
        -------
        PathCheckResult
            Contains the decision and resolved path.
        """
        try:
            resolved = Path(path).resolve()
        except (OSError, ValueError) as exc:
            return PathCheckResult(
                allowed=False,
                requested_path=path,
                resolved_path="",
                reason=f"Path resolution failed: {exc}",
            )

        # Check against read/write allowed roots.
        for root in self._allowed_roots:
            try:
                resolved.relative_to(root)
                logger.debug("ALLOW path=%r root=%r mode=%r", path, str(root), mode)
                return PathCheckResult(
                    allowed=True,
                    requested_path=path,
                    resolved_path=str(resolved),
                    reason=f"Path is within allowed root {str(root)!r} (mode={mode}).",
                )
            except ValueError:
                continue

        # Check read-only roots (only for read mode).
        if mode == "read":
            for root in self._read_only_roots:
                try:
                    resolved.relative_to(root)
                    logger.debug(
                        "ALLOW_READ_ONLY path=%r root=%r", path, str(root)
                    )
                    return PathCheckResult(
                        allowed=True,
                        requested_path=path,
                        resolved_path=str(resolved),
                        reason=(
                            f"Path is within read-only root {str(root)!r}. "
                            "Read access permitted; write access is denied."
                        ),
                    )
                except ValueError:
                    continue

        roots_display = [str(r) for r in self._allowed_roots]
        reason = (
            f"Path {str(resolved)!r} is outside all allowed roots: {roots_display!r}. "
            "Adjust the ScopeLimiter configuration to permit this path, or "
            "ensure the agent's workspace is correctly configured."
        )
        logger.warning("DENY path=%r resolved=%r mode=%r", path, str(resolved), mode)
        return PathCheckResult(
            allowed=False,
            requested_path=path,
            resolved_path=str(resolved),
            reason=reason,
        )

    # ------------------------------------------------------------------
    # Command check
    # ------------------------------------------------------------------

    def check_command(self, command: str) -> CommandCheckResult:
        """Verify that the executable in *command* is on the allowlist.

        The command string is tokenised using POSIX shell lexer rules.
        The first token is taken as the executable name.  If the token
        contains a path separator, only the final component (``basename``)
        is matched against the allowlist.

        Parameters
        ----------
        command:
            The shell command string to evaluate.

        Returns
        -------
        CommandCheckResult
            Contains the decision and the extracted executable token.
        """
        if not command.strip():
            return CommandCheckResult(
                allowed=False,
                command=command,
                executable="",
                reason="Empty command string is not permitted.",
            )

        try:
            tokens = shlex.split(command)
        except ValueError as exc:
            return CommandCheckResult(
                allowed=False,
                command=command,
                executable="",
                reason=f"Command string could not be parsed: {exc}",
            )

        if not tokens:
            return CommandCheckResult(
                allowed=False,
                command=command,
                executable="",
                reason="Command tokenised to an empty list.",
            )

        raw_exe = tokens[0]
        # Strip path prefix so "/usr/bin/python3" → "python3".
        executable = PurePosixPath(raw_exe).name or raw_exe

        if not self._allowed_commands:
            reason = (
                "Command allowlist is empty — all commands are denied by default. "
                "Add permitted executables via add_allowed_command()."
            )
            logger.warning("DENY command=%r (empty allowlist)", command)
            return CommandCheckResult(
                allowed=False,
                command=command,
                executable=executable,
                reason=reason,
            )

        if executable in self._allowed_commands:
            logger.debug("ALLOW command=%r executable=%r", command, executable)
            return CommandCheckResult(
                allowed=True,
                command=command,
                executable=executable,
                reason=f"Executable {executable!r} is on the command allowlist.",
            )

        reason = (
            f"Executable {executable!r} is not on the command allowlist "
            f"{sorted(self._allowed_commands)!r}. "
            "Add it via add_allowed_command() if this command is intentional."
        )
        logger.warning("DENY command=%r executable=%r", command, executable)
        return CommandCheckResult(
            allowed=False,
            command=command,
            executable=executable,
            reason=reason,
        )

    def list_allowed_commands(self) -> list[str]:
        """Return a sorted list of permitted executables.

        Returns
        -------
        list[str]
        """
        return sorted(self._allowed_commands)

    def list_allowed_roots(self) -> list[str]:
        """Return string representations of all allowed root directories.

        Returns
        -------
        list[str]
        """
        return [str(r) for r in self._allowed_roots]
