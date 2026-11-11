"""Exercise real JSON, filesystem, process and distributable-package boundaries."""

import copy
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import zipfile

import pytest

from integrity_guard import io
from integrity_guard.policy import REQUIRED_CHECK_IDS, policy_digest
from integrity_guard.reporting import annotation_batches, check_output


ROOT = Path(__file__).resolve().parents[1]
MARKER = "SYNTHETIC_PRIVATE_TEST_MARKER_4a71"


def report(*, code=0, count=0):
    data = {
        "schema_version": "1.0",
        "status": "PASS" if code == 0 else "FAIL",
        "exit_code": code,
        "complete": code in {0, 10},
        "summary": MARKER,
        "context": {
            "repository": "example/project",
            "base_sha": "1" * 40,
            "head_sha": "2" * 40,
            "policy_digest": policy_digest(),
        },
        "checks": [
            {"check_id": check_id, "status": "PASS", "complete": True}
            for check_id in REQUIRED_CHECK_IDS
        ],
        "findings": [
            {
                "rule_id": "INT-001" if code else "INT-060",
                "severity": "critical" if code else "info",
                "confidence": "high",
                "blocking": code != 0,
                "message": MARKER,
                "action": MARKER,
                "path": "src/example.py",
                "line": index + 1,
            }
            for index in range(count)
        ],
    }
    if code == 10:
        data["checks"][2]["status"] = "FAIL"
    elif code:
        data["checks"][2].update(status="ERROR", complete=False)
    return data


def run_cli(*args, cwd=None):
    env = dict(os.environ, PYTHONPATH=str(ROOT / "src"), PYTHONNOUSERSITE="1")
    return subprocess.run(
        [sys.executable, "-m", "integrity_guard.cli", *map(str, args)],
        cwd=cwd or ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )


def validate_args(path, *, code=0, base="1" * 40, head="2" * 40, repository="example/project"):
    return [
        "validate", path, "--base", base, "--head", head,
        "--repository", repository, "--process-exit-code", str(code),
    ]


@pytest.mark.parametrize(
    "raw",
    [b'{"status":"FAIL","status":"PASS"}', b'{"a":{"b":1,"b":2}}',
     b'{"a":1,"\\u0061":2}'],
)
def test_duplicate_json_keys_are_rejected_before_a_value_can_win(raw):
    with pytest.raises(io.InvalidResult):
        io.decode_json(raw)


@pytest.mark.parametrize(
    "raw",
    [b"NaN", b"Infinity", b"-Infinity", b"1e10000", b"-1e10000",
     b'{"nested":[1e10000]}'],
)
def test_nonfinite_numbers_are_rejected_including_exponent_overflow(raw):
    with pytest.raises(io.InvalidResult):
        io.decode_json(raw)


@pytest.mark.parametrize("raw", [b"", b"\xff", b"{} trailing", b'{"a":1,}', b"\xef\xbb\xbf{}"])
def test_malformed_or_non_utf8_json_is_rejected(raw):
    with pytest.raises(io.InvalidResult):
        io.decode_json(raw)


def test_size_limit_applies_before_decoding():
    with pytest.raises(io.InvalidResult):
        io.decode_json(b" " * (io.MAX_RESULT_BYTES + 1))


def test_depth_limit_is_explicit_and_predictable():
    raw = b"[" * (io.MAX_JSON_DEPTH + 1) + b"0" + b"]" * (io.MAX_JSON_DEPTH + 1)
    with pytest.raises(io.InvalidResult):
        io.decode_json(raw)


def test_depth_limit_allows_boundary_and_ignores_brackets_inside_strings():
    at_limit = b"[" * io.MAX_JSON_DEPTH + b"0" + b"]" * io.MAX_JSON_DEPTH
    assert isinstance(io.decode_json(at_limit), list)
    value = {"text": "[" * 100 + '{escaped quote: " and slash: \\}' + "]" * 100}
    assert io.decode_json(json.dumps(value).encode()) == value


def test_regular_report_round_trip_has_private_permissions(tmp_path):
    path = tmp_path / "result.json"
    data = report()
    io.write_result(path, data)
    assert io.read_result(path) == data
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert not list(tmp_path.glob(".guard-*"))


@pytest.mark.parametrize("kind", ["missing", "directory", "fifo", "symlink", "broken_symlink"])
def test_reports_require_a_real_regular_file(tmp_path, kind):
    path = tmp_path / "result.json"
    if kind == "directory":
        path.mkdir()
    elif kind == "fifo":
        os.mkfifo(path)
    elif kind in {"symlink", "broken_symlink"}:
        target = tmp_path / "target.json"
        if kind == "symlink":
            io.write_result(target, report())
        path.symlink_to(target)
    with pytest.raises(io.InvalidResult):
        io.read_result(path)


def test_report_file_size_is_bounded(tmp_path):
    path = tmp_path / "large.json"
    path.write_bytes(b" " * (io.MAX_RESULT_BYTES + 1))
    with pytest.raises(io.InvalidResult):
        io.read_result(path)


@pytest.mark.parametrize("value", [[], None, "PASS", 0, True])
def test_report_transport_requires_object_top_level(tmp_path, value):
    path = tmp_path / "result.json"
    path.write_text(json.dumps(value))
    with pytest.raises(io.InvalidResult):
        io.read_result(path)


@pytest.mark.parametrize("code,count", [(0, 0), (0, 1), (10, 1), (21, 0), (30, 0)])
def test_cli_returns_actual_report_exit_as_os_process_status(tmp_path, code, count):
    path = tmp_path / "result.json"
    io.write_result(path, report(code=code, count=count))
    completed = run_cli(*validate_args(path, code=code), cwd=tmp_path)
    assert completed.returncode == code, completed.stderr
    assert MARKER not in completed.stdout + completed.stderr
    assert "Traceback" not in completed.stderr


@pytest.mark.parametrize("case", ["missing", "malformed", "contradictory", "duplicate"])
def test_cli_invalid_result_never_exits_zero(tmp_path, case):
    path = tmp_path / "result.json"
    if case == "malformed":
        path.write_text(MARKER)
    elif case == "contradictory":
        data = report()
        data["complete"] = False
        io.write_result(path, data)
    elif case == "duplicate":
        path.write_text('{"status":"FAIL","status":"PASS"}')
    completed = run_cli(*validate_args(path), cwd=tmp_path)
    assert completed.returncode == 30
    assert MARKER not in completed.stdout + completed.stderr
    assert "Traceback" not in completed.stderr


@pytest.mark.parametrize("field", ["base_sha", "head_sha", "policy_digest", "repository"])
def test_cli_rejects_replayed_report_for_different_context(tmp_path, field):
    data = report()
    data["context"][field] = "other/project" if field == "repository" else "3" * (64 if field == "policy_digest" else 40)
    path = tmp_path / "result.json"
    io.write_result(path, data)
    completed = run_cli(*validate_args(path), cwd=tmp_path)
    assert completed.returncode == 30


def test_cli_rejects_clean_report_from_a_failed_scanner_process(tmp_path):
    path = tmp_path / "result.json"
    io.write_result(path, report())
    completed = run_cli(*validate_args(path, code=21))
    assert completed.returncode == 30


def test_argument_parser_does_not_echo_untrusted_arguments(tmp_path):
    completed = run_cli(*validate_args(tmp_path / "result.json", code=MARKER))
    assert completed.returncode != 0
    assert MARKER not in completed.stdout + completed.stderr
    assert "Traceback" not in completed.stderr


@pytest.mark.parametrize("kind", ["existing", "broken_symlink"])
def test_scan_cli_refuses_stale_output_without_overwriting_it(tmp_path, kind):
    path = tmp_path / "result.json"
    if kind == "existing":
        path.write_text(MARKER)
    else:
        path.symlink_to(tmp_path / "absent.json")
    completed = run_cli(
        "scan", "--repo", tmp_path, "--base", "1" * 40, "--head", "2" * 40,
        "--repository", "example/project", "--output", path,
    )
    assert completed.returncode == 30
    assert "output path already exists" in completed.stdout
    if kind == "existing":
        assert path.read_text() == MARKER
    else:
        assert path.is_symlink()


@pytest.mark.parametrize("count,expected_sizes", [(0, []), (1, [1]), (50, [50]), (51, [50, 1]), (101, [50, 50, 1])])
def test_annotation_pagination_preserves_every_finding(count, expected_sizes):
    data = report(code=10 if count else 0, count=count)
    batches = list(annotation_batches(data))
    assert [len(batch) for batch in batches] == expected_sizes
    annotations = [annotation for batch in batches for annotation in batch]
    assert [annotation["start_line"] for annotation in annotations] == list(range(1, count + 1))
    assert MARKER not in json.dumps(annotations)


@pytest.mark.parametrize("size", [0, 51, -1, True, 1.0, "50"])
def test_invalid_annotation_batch_size_is_not_coerced(size):
    with pytest.raises(ValueError):
        list(annotation_batches(report(), size=size))


def test_public_reporting_drops_all_scanner_free_text():
    data = report(code=10, count=1)
    serialized = json.dumps({"output": check_output(data), "batches": list(annotation_batches(data))})
    assert MARKER not in serialized
    assert "INT-001" in serialized
    assert "src/example.py" in serialized
    assert data["context"]["head_sha"] in serialized


def test_unlocatable_findings_remain_in_summary_without_fake_annotations():
    data = report(code=10, count=2)
    data["findings"][1].pop("path")
    data["findings"][1].pop("line")
    assert "findings=2" in check_output(data)["summary"]
    assert sum(map(len, annotation_batches(data))) == 1


def test_reporting_does_not_mutate_evidence():
    data = report(code=10, count=51)
    before = copy.deepcopy(data)
    check_output(data)
    list(annotation_batches(data))
    assert data == before


def test_built_wheel_contains_usable_schema_outside_source_checkout(tmp_path):
    """A source-tree test cannot detect an omitted JSON package resource."""
    build_root = tmp_path / "project"
    build_root.mkdir()
    shutil.copy2(ROOT / "pyproject.toml", build_root / "pyproject.toml")
    shutil.copy2(ROOT / "README.md", build_root / "README.md")
    shutil.copytree(ROOT / "src", build_root / "src", ignore=shutil.ignore_patterns("__pycache__"))
    wheel_dir = tmp_path / "wheels"
    completed = subprocess.run(
        [sys.executable, "-m", "pip", "wheel", "--no-deps", "--no-build-isolation",
         "--wheel-dir", str(wheel_dir), str(build_root)],
        capture_output=True, text=True, timeout=60, check=False,
        env=dict(os.environ, PIP_NO_INDEX="1", PIP_DISABLE_PIP_VERSION_CHECK="1"),
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    wheels = list(wheel_dir.glob("*.whl"))
    assert len(wheels) == 1
    installed = tmp_path / "installed"
    with zipfile.ZipFile(wheels[0]) as wheel:
        assert "integrity_guard/result.schema.json" in wheel.namelist()
        wheel.extractall(installed)
    smoke = subprocess.run(
        [sys.executable, "-c", "from integrity_guard import policy_digest; print(policy_digest())"],
        cwd=tmp_path,
        env=dict(os.environ, PYTHONPATH=str(installed), PYTHONNOUSERSITE="1"),
        capture_output=True, text=True, timeout=20, check=False,
    )
    assert smoke.returncode == 0, smoke.stderr
    assert smoke.stdout.strip() == policy_digest()
