"""Tests for self-security requirements (spec 013)."""

from __future__ import annotations

import json
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from clearwing.sandbox.container import SandboxConfig
from clearwing.sandbox.seccomp_profiles import (
    EXPLOIT_SECCOMP,
    HUNTER_SECCOMP,
    get_seccomp_profile,
    write_seccomp_profile,
)
from clearwing.sourcehunt.audit import SecurityAuditLog
from clearwing.sourcehunt.behavior_monitor import (
    FILE_WRITE_THRESHOLD,
    BehaviorMonitor,
)


# --- SandboxConfig hardening tests -------------------------------------------


class TestSandboxConfigHardening:
    def test_pids_limit_default(self):
        cfg = SandboxConfig(image="test")
        assert cfg.pids_limit == 512

    def test_cap_drop_default(self):
        cfg = SandboxConfig(image="test")
        assert cfg.cap_drop == ["ALL"]

    def test_cap_add_default(self):
        cfg = SandboxConfig(image="test")
        assert cfg.cap_add == ["SYS_PTRACE"]

    def test_gvisor_runtime_config(self):
        cfg = SandboxConfig(image="test", runtime="runsc")
        assert cfg.runtime == "runsc"

    def test_read_only_rootfs(self):
        cfg = SandboxConfig(image="test", read_only_rootfs=True)
        assert cfg.read_only_rootfs is True

    def test_security_opt_empty_by_default(self):
        cfg = SandboxConfig(image="test")
        assert cfg.security_opt == []


# --- Seccomp profile tests ---------------------------------------------------


class TestSeccompProfiles:
    def test_hunter_profile_blocks_mount(self):
        profile = get_seccomp_profile("hunter")
        blocked = profile["syscalls"][0]["names"]
        assert "mount" in blocked

    def test_hunter_profile_blocks_kexec(self):
        profile = get_seccomp_profile("hunter")
        blocked = profile["syscalls"][0]["names"]
        assert "kexec_load" in blocked

    def test_hunter_profile_blocks_unshare(self):
        profile = get_seccomp_profile("hunter")
        blocked = profile["syscalls"][0]["names"]
        assert "unshare" in blocked

    def test_exploit_profile_allows_unshare(self):
        profile = get_seccomp_profile("exploit")
        blocked = profile["syscalls"][0]["names"]
        assert "unshare" not in blocked

    def test_exploit_profile_still_blocks_mount(self):
        profile = get_seccomp_profile("exploit")
        blocked = profile["syscalls"][0]["names"]
        assert "mount" in blocked

    def test_write_seccomp_profile(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "seccomp.json"
            result = write_seccomp_profile("hunter", path)
            assert path.exists()
            data = json.loads(path.read_text())
            assert data["defaultAction"] == "SCMP_ACT_ALLOW"
            assert result == str(path)

    def test_default_returns_hunter(self):
        assert get_seccomp_profile() == HUNTER_SECCOMP
        assert get_seccomp_profile("unknown_mode") == HUNTER_SECCOMP


# --- ArtifactStore tests -----------------------------------------------------


class TestArtifactStore:
    def test_store_and_retrieve_exploit(self):
        from clearwing.sourcehunt.artifact_store import ArtifactStore

        with tempfile.TemporaryDirectory() as td:
            store = ArtifactStore(base_dir=Path(td))
            data = b"exploit payload here"
            path = store.store_exploit("finding-001", data, operator="test")
            assert path.exists()
            retrieved = store.retrieve(path, operator="test")
            assert retrieved == data

    def test_access_logged(self):
        from clearwing.sourcehunt.artifact_store import ArtifactStore

        with tempfile.TemporaryDirectory() as td:
            store = ArtifactStore(base_dir=Path(td))
            store.store_exploit("finding-002", b"data", operator="researcher")
            audit_path = Path(td) / "audit.log"
            assert audit_path.exists()
            lines = audit_path.read_text().strip().split("\n")
            assert len(lines) >= 1
            entry = json.loads(lines[0])
            assert entry["action"] == "store_exploits"
            assert entry["finding_id"] == "finding-002"
            assert entry["operator"] == "researcher"

    def test_store_poc(self):
        from clearwing.sourcehunt.artifact_store import ArtifactStore

        with tempfile.TemporaryDirectory() as td:
            store = ArtifactStore(base_dir=Path(td))
            path = store.store_poc("f1", b"poc data")
            assert "poc" in str(path)
            assert store.retrieve(path) == b"poc data"

    def test_store_transcript(self):
        from clearwing.sourcehunt.artifact_store import ArtifactStore

        with tempfile.TemporaryDirectory() as td:
            store = ArtifactStore(base_dir=Path(td))
            path = store.store_transcript("f1", b"transcript")
            assert "transcripts" in str(path)
            assert store.retrieve(path) == b"transcript"

    def test_list_artifacts(self):
        from clearwing.sourcehunt.artifact_store import ArtifactStore

        with tempfile.TemporaryDirectory() as td:
            store = ArtifactStore(base_dir=Path(td))
            store.store_exploit("f1", b"exploit")
            store.store_poc("f1", b"poc")
            artifacts = store.list_artifacts("f1")
            assert len(artifacts) == 2
            categories = {a["category"] for a in artifacts}
            assert "exploits" in categories
            assert "poc" in categories

    def test_purge_expired(self):
        from clearwing.sourcehunt.artifact_store import ArtifactPolicy, ArtifactStore

        with tempfile.TemporaryDirectory() as td:
            policy = ArtifactPolicy(retention_days=0)
            store = ArtifactStore(base_dir=Path(td), policy=policy)
            store.store_exploit("old-finding", b"old data")
            removed = store.purge_expired()
            assert removed >= 1


# --- BehaviorMonitor tests ---------------------------------------------------


class TestBehaviorMonitor:
    def test_detect_network_access(self):
        mon = BehaviorMonitor(session_id="test-1")
        alerts = mon.scan_text("running curl http://evil.com", finding_id="f1")
        assert len(alerts) >= 1
        assert alerts[0].pattern == "network_access_attempt"

    def test_detect_mount_attempt(self):
        mon = BehaviorMonitor(session_id="test-2")
        alerts = mon.scan_text("mount -t proc proc /proc", finding_id="f1")
        assert len(alerts) >= 1
        assert alerts[0].pattern == "mount_attempt"

    def test_detect_docker_socket(self):
        mon = BehaviorMonitor(session_id="test-3")
        alerts = mon.scan_text("cat /var/run/docker.sock", finding_id="f1")
        assert len(alerts) >= 1
        assert alerts[0].pattern == "unexpected_fs_path"

    def test_detect_permission_escalation(self):
        mon = BehaviorMonitor(session_id="test-4")
        alerts = mon.scan_text("sudo -i", finding_id="f1")
        assert len(alerts) >= 1
        assert alerts[0].pattern == "permission_escalation"

    def test_no_false_positive_normal_commands(self):
        mon = BehaviorMonitor(session_id="test-5")
        alerts = mon.scan_text(
            "gcc -o test test.c -fsanitize=address && ./test < input.bin",
            finding_id="f1",
        )
        assert len(alerts) == 0

    def test_file_write_threshold(self):
        mon = BehaviorMonitor(session_id="test-6")
        for i in range(FILE_WRITE_THRESHOLD + 1):
            mon.record_file_write(f"/scratch/file_{i}")
        alerts = mon.check_thresholds()
        assert len(alerts) >= 1
        assert alerts[0].pattern == "excessive_file_writes"

    def test_large_binary_detection(self):
        mon = BehaviorMonitor(session_id="test-7")
        mon.record_file_write("/scratch/huge.bin", size_bytes=100 * 1024 * 1024)
        alerts = mon.get_alerts()
        assert len(alerts) >= 1
        assert alerts[0].pattern == "large_binary_creation"

    def test_summary(self):
        mon = BehaviorMonitor(session_id="test-8")
        mon.scan_text("curl http://x", finding_id="f1")
        mon.scan_text("sudo -i", finding_id="f2")
        summary = mon.summary()
        assert "network_access_attempt" in summary
        assert "permission_escalation" in summary

    def test_severity_critical_for_mount(self):
        mon = BehaviorMonitor(session_id="test-9")
        alerts = mon.scan_text("nsenter --target 1 --mount", finding_id="f1")
        assert len(alerts) >= 1
        assert alerts[0].severity == "critical"


# --- SecurityAuditLog tests --------------------------------------------------


class TestSecurityAuditLog:
    def test_log_and_query(self):
        with tempfile.TemporaryDirectory() as td:
            log = SecurityAuditLog(log_path=Path(td) / "audit.jsonl")
            entry = log.log("store_artifact", "finding-001", operator="test-user")
            assert entry.action == "store_artifact"
            results = log.query()
            assert len(results) == 1
            assert results[0].target == "finding-001"

    def test_append_only(self):
        with tempfile.TemporaryDirectory() as td:
            log = SecurityAuditLog(log_path=Path(td) / "audit.jsonl")
            log.log("store_artifact", "f1")
            log.log("retrieve_artifact", "f2")
            log.log("export_exploit", "f3")
            results = log.query()
            assert len(results) == 3

    def test_query_filter_by_action(self):
        with tempfile.TemporaryDirectory() as td:
            log = SecurityAuditLog(log_path=Path(td) / "audit.jsonl")
            log.log("store_artifact", "f1")
            log.log("retrieve_artifact", "f2")
            log.log("store_artifact", "f3")
            results = log.query(action="store_artifact")
            assert len(results) == 2

    def test_query_filter_by_target(self):
        with tempfile.TemporaryDirectory() as td:
            log = SecurityAuditLog(log_path=Path(td) / "audit.jsonl")
            log.log("store_artifact", "f1")
            log.log("retrieve_artifact", "f1")
            log.log("store_artifact", "f2")
            results = log.query(target="f1")
            assert len(results) == 2


# --- Runner injection tests --------------------------------------------------


class TestRunnerSecurityOptions:
    def test_behavior_monitor_default_enabled(self):
        from clearwing.sourcehunt.runner import SourceHuntRunner

        runner = SourceHuntRunner(repo_url="test", depth="standard")
        assert runner._enable_behavior_monitor is True

    def test_artifact_store_default_disabled(self):
        from clearwing.sourcehunt.runner import SourceHuntRunner

        runner = SourceHuntRunner(repo_url="test", depth="standard")
        assert runner._enable_artifact_store is False

    def test_gvisor_runtime_none_by_default(self):
        from clearwing.sourcehunt.runner import SourceHuntRunner

        runner = SourceHuntRunner(repo_url="test", depth="standard")
        assert runner._gvisor_runtime is None

    def test_gvisor_runtime_configurable(self):
        from clearwing.sourcehunt.runner import SourceHuntRunner

        runner = SourceHuntRunner(
            repo_url="test", depth="standard", gvisor_runtime="runsc",
        )
        assert runner._gvisor_runtime == "runsc"


# --- CLI registration tests --------------------------------------------------


class TestCLIFlags:
    def test_gvisor_flag(self):
        import argparse
        from clearwing.ui.commands import sourcehunt

        parser = argparse.ArgumentParser()
        subs = parser.add_subparsers()
        sourcehunt.add_parser(subs)
        args = parser.parse_args(["sourcehunt", "test-repo", "--gvisor"])
        assert args.gvisor is True

    def test_encrypt_artifacts_flag(self):
        import argparse
        from clearwing.ui.commands import sourcehunt

        parser = argparse.ArgumentParser()
        subs = parser.add_subparsers()
        sourcehunt.add_parser(subs)
        args = parser.parse_args(["sourcehunt", "test-repo", "--encrypt-artifacts"])
        assert args.encrypt_artifacts is True

    def test_no_behavior_monitor_flag(self):
        import argparse
        from clearwing.ui.commands import sourcehunt

        parser = argparse.ArgumentParser()
        subs = parser.add_subparsers()
        sourcehunt.add_parser(subs)
        args = parser.parse_args(["sourcehunt", "test-repo", "--no-behavior-monitor"])
        assert args.no_behavior_monitor is True
