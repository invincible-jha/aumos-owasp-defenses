"""Tests for ASI-05 ScopeLimiter."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

from aumos_owasp_defenses.defenses.asi05_code_execution.scope_limiter import (
    CommandCheckResult,
    PathCheckResult,
    ScopeLimiter,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def workspace(tmp_path: Path) -> Path:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    return workspace


@pytest.fixture()
def limiter(workspace: Path) -> ScopeLimiter:
    return ScopeLimiter(
        allowed_roots=[str(workspace)],
        allowed_commands={"python3", "pip"},
    )


# ---------------------------------------------------------------------------
# PathCheckResult
# ---------------------------------------------------------------------------


class TestPathCheckResult:
    def test_frozen(self) -> None:
        result = PathCheckResult(True, "/path", "/resolved", "ok")
        with pytest.raises((AttributeError, TypeError)):
            result.allowed = False  # type: ignore[misc]


# ---------------------------------------------------------------------------
# CommandCheckResult
# ---------------------------------------------------------------------------


class TestCommandCheckResult:
    def test_frozen(self) -> None:
        result = CommandCheckResult(True, "cmd", "exe", "ok")
        with pytest.raises((AttributeError, TypeError)):
            result.allowed = False  # type: ignore[misc]


# ---------------------------------------------------------------------------
# ScopeLimiter — construction
# ---------------------------------------------------------------------------


class TestScopeLimiterConstruction:
    def test_empty_construction(self) -> None:
        limiter = ScopeLimiter()
        assert limiter.list_allowed_commands() == []
        assert limiter.list_allowed_roots() == []

    def test_initial_roots(self, workspace: Path) -> None:
        limiter = ScopeLimiter(allowed_roots=[str(workspace)])
        assert str(workspace) in limiter.list_allowed_roots()

    def test_initial_commands(self) -> None:
        limiter = ScopeLimiter(allowed_commands={"python3", "node"})
        assert limiter.list_allowed_commands() == ["node", "python3"]

    def test_add_allowed_root(self, workspace: Path) -> None:
        limiter = ScopeLimiter()
        limiter.add_allowed_root(str(workspace))
        assert str(workspace) in limiter.list_allowed_roots()

    def test_add_allowed_root_no_duplicates(self, workspace: Path) -> None:
        limiter = ScopeLimiter(allowed_roots=[str(workspace)])
        limiter.add_allowed_root(str(workspace))
        assert len(limiter.list_allowed_roots()) == 1

    def test_add_allowed_command(self) -> None:
        limiter = ScopeLimiter()
        limiter.add_allowed_command("myapp")
        assert "myapp" in limiter.list_allowed_commands()

    def test_remove_allowed_command(self) -> None:
        limiter = ScopeLimiter(allowed_commands={"python3"})
        limiter.remove_allowed_command("python3")
        assert "python3" not in limiter.list_allowed_commands()

    def test_remove_nonexistent_command_is_safe(self) -> None:
        limiter = ScopeLimiter()
        limiter.remove_allowed_command("nonexistent")  # Should not raise


# ---------------------------------------------------------------------------
# ScopeLimiter — check_path
# ---------------------------------------------------------------------------


class TestCheckPath:
    def test_allowed_path_inside_workspace(
        self, limiter: ScopeLimiter, workspace: Path
    ) -> None:
        target = workspace / "output.txt"
        result = limiter.check_path(str(target))
        assert result.allowed is True
        assert result.requested_path == str(target)
        assert result.resolved_path != ""

    def test_denied_path_outside_workspace(self, limiter: ScopeLimiter) -> None:
        result = limiter.check_path("/etc/passwd")
        assert result.allowed is False
        assert "outside" in result.reason.lower() or "allowed" in result.reason.lower()

    def test_path_traversal_denied(
        self, limiter: ScopeLimiter, workspace: Path
    ) -> None:
        # Attempt to escape workspace via ..
        traversal = str(workspace / ".." / ".." / "etc" / "passwd")
        result = limiter.check_path(traversal)
        assert result.allowed is False

    def test_empty_allowed_roots_deny_all(self) -> None:
        limiter = ScopeLimiter()
        result = limiter.check_path("/tmp/anything")
        assert result.allowed is False

    def test_read_only_root_allows_read(self, tmp_path: Path) -> None:
        readonly = tmp_path / "readonly"
        readonly.mkdir()
        limiter = ScopeLimiter(
            allowed_roots=[],
            allow_read_only_paths=[str(readonly)],
        )
        result = limiter.check_path(str(readonly / "file.txt"), mode="read")
        assert result.allowed is True

    def test_read_only_root_denies_write(self, tmp_path: Path) -> None:
        readonly = tmp_path / "readonly"
        readonly.mkdir()
        limiter = ScopeLimiter(
            allowed_roots=[],
            allow_read_only_paths=[str(readonly)],
        )
        result = limiter.check_path(str(readonly / "file.txt"), mode="write")
        assert result.allowed is False

    def test_mode_default_is_read(
        self, limiter: ScopeLimiter, workspace: Path
    ) -> None:
        target = workspace / "file.txt"
        result = limiter.check_path(str(target))
        assert result.allowed is True

    def test_subdirectory_inside_workspace_allowed(
        self, limiter: ScopeLimiter, workspace: Path
    ) -> None:
        subdir = workspace / "nested" / "deep"
        result = limiter.check_path(str(subdir / "data.json"))
        assert result.allowed is True


# ---------------------------------------------------------------------------
# ScopeLimiter — check_command
# ---------------------------------------------------------------------------


class TestCheckCommand:
    def test_allowed_command(self, limiter: ScopeLimiter) -> None:
        result = limiter.check_command("python3 script.py")
        assert result.allowed is True
        assert result.executable == "python3"

    def test_denied_command_not_on_list(self, limiter: ScopeLimiter) -> None:
        result = limiter.check_command("curl https://evil.com")
        assert result.allowed is False
        assert "allowlist" in result.reason.lower()

    def test_empty_command_denied(self, limiter: ScopeLimiter) -> None:
        result = limiter.check_command("   ")
        assert result.allowed is False
        assert result.executable == ""

    def test_empty_allowlist_denies_all(self) -> None:
        limiter = ScopeLimiter()  # no allowed_commands → empty
        result = limiter.check_command("python3 main.py")
        assert result.allowed is False
        assert "allowlist" in result.reason.lower()

    def test_path_prefix_stripped(self, limiter: ScopeLimiter) -> None:
        # /usr/bin/python3 → "python3" should match
        result = limiter.check_command("/usr/bin/python3 script.py")
        assert result.allowed is True
        assert result.executable == "python3"

    def test_pip_allowed(self, limiter: ScopeLimiter) -> None:
        result = limiter.check_command("pip install requests")
        assert result.allowed is True

    def test_command_returns_raw_command(self, limiter: ScopeLimiter) -> None:
        cmd = "python3 -m pytest tests/"
        result = limiter.check_command(cmd)
        assert result.command == cmd

    def test_list_allowed_commands_sorted(self) -> None:
        limiter = ScopeLimiter(allowed_commands={"z-cmd", "a-cmd", "m-cmd"})
        assert limiter.list_allowed_commands() == ["a-cmd", "m-cmd", "z-cmd"]
