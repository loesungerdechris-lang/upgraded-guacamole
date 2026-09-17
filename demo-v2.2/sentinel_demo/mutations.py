"""Declarative fixture mutations on independent, owned copies of sealed evidence."""
from __future__ import annotations

import base64
import fcntl
import json
import os
import shutil
import tempfile
from pathlib import Path

from .store import DirectoryStore, descriptor, digest, validate_digest, MAX_BLOB

CATALOG = Path(__file__).resolve().parents[1] / "tests/mutations"
INDEX = "golden-index.json"
MARKER = "mutation-work.json"
OWNER = "sentinel-mutation-work/v1"
INPUTS = ("verification-request.json", "governance-policy.yml", "demo.pub")
OPERATIONS = {"remove-manifest", "remove-payload", "remove-attestation", "corrupt-payload",
              "corrupt-signature", "signed-variant"}


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def read_json(path):
    def reject(_):
        raise ValueError("Non-finite number")
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_BLOB + 1)
    if len(raw) > MAX_BLOB:
        raise ValueError("Input too large")
    return json.loads(raw, object_pairs_hook=unique, parse_constant=reject)


def inventory(root):
    """Reject links and special files; hash a bounded, exact file set."""
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("Expected an ordinary directory")
    entries, total = {}, 0
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("Links are not allowed in evidence fixtures")
        if path.is_dir():
            continue
        if not path.is_file():
            raise ValueError("Special files are not allowed")
        relative = path.relative_to(root).as_posix()
        if relative == INDEX:
            continue
        size = path.stat().st_size
        total += size
        if size > MAX_BLOB or total > 256 * 1024 * 1024 or len(entries) >= 4096:
            raise ValueError("Golden bundle size limit exceeded")
        entries[relative] = {"size": size, "sha256": digest(path.read_bytes())}
    return entries


def seal(root):
    path = Path(root) / INDEX
    raw = encoded({"schema": "sentinel-golden/v1", "files": inventory(root)})
    with path.open("xb") as stream:
        stream.write(raw)
    return digest(raw)


def check_golden(root, pin):
    validate_digest(pin)
    path = Path(root) / INDEX
    if path.is_symlink() or path.stat().st_size > MAX_BLOB or digest(path.read_bytes()) != pin:
        raise ValueError("Golden index does not match the independently supplied pin")
    index = read_json(path)
    if set(index) != {"schema", "files"} or index["schema"] != "sentinel-golden/v1":
        raise ValueError("Unsupported golden index")
    if index["files"] != inventory(root):
        raise ValueError("Golden bundle was changed")


def catalog():
    cases = {}
    for path in sorted(CATALOG.glob("*.yaml")):
        # JSON is a YAML subset: no general YAML parser, tags or executable actions.
        case = read_json(path)
        if (set(case) != {"scenario", "operation", "role", "expectedExit"}
                or case["scenario"] != path.stem or case["scenario"] in cases
                or case["operation"] not in OPERATIONS
                or case["role"] not in {None, "sbom", "governance", "provenance"}
                or type(case["expectedExit"]) is not int or not 1 <= case["expectedExit"] <= 90):
            raise ValueError("Invalid mutation catalog")
        cases[case["scenario"]] = case
    if not cases:
        raise ValueError("Empty mutation catalog")
    return cases


def _apply(work, golden, case):
    store = DirectoryStore(work / "bundle")
    request = read_json(work / INPUTS[0])
    root = request["manifest"]
    bundle = json.loads(store.read_blob(root["payload"]["digest"]))
    statement = json.loads(base64.b64decode(bundle["dsseEnvelope"]["payload"], validate=True))
    entries = {e["role"]: e for e in statement["predicate"]["entries"]}

    def blob(ref):
        return store.root / "blobs/sha256" / validate_digest(ref["digest"])[7:]

    op = case["operation"]
    if op == "remove-manifest":
        blob(root["artifact"]).unlink()
    elif op == "remove-payload":
        blob(entries[case["role"]]["payload"]).unlink()
    elif op == "remove-attestation":
        blob(entries[case["role"]]["artifact"]).unlink()
    elif op == "corrupt-payload":
        with blob(entries[case["role"]]["payload"]).open("ab") as stream:
            stream.write(b"tamper\n")
    elif op == "corrupt-signature":
        signature = bytearray(base64.b64decode(bundle["dsseEnvelope"]["signatures"][0]["sig"]))
        signature[-1] ^= 1
        bundle["dsseEnvelope"]["signatures"][0]["sig"] = base64.b64encode(signature).decode()
        raw = encoded(bundle)
        artifact = json.loads(store.read_manifest(root["artifact"]["digest"]))
        root["payload"] = descriptor(raw, root["payload"]["mediaType"])
        artifact["layers"] = [root["payload"]]
        artifact_raw = encoded(artifact)
        root["artifact"] = descriptor(artifact_raw, root["artifact"]["mediaType"])
        store.write(raw)
        store.write(artifact_raw)
    elif op == "signed-variant":
        variants = read_json(golden / "test-variants/index.json")
        request["manifest"] = variants[case["scenario"]]
        for path in (golden / "test-variants/blobs/sha256").iterdir():
            raw = path.read_bytes()
            if digest(raw)[7:] != path.name:
                raise ValueError("Invalid variant content address")
            store.write(raw)
    (work / INPUTS[0]).write_bytes(encoded(request))


def _ordinary_path(path):
    absolute = Path(os.path.abspath(path))
    if any(p.is_symlink() for p in (absolute, *absolute.parents)):
        raise ValueError("Symlink paths are not allowed")
    return absolute


def mutate(golden, pin, scenario, output):
    cases = catalog()
    if scenario not in cases:
        raise ValueError("Unknown scenario: " + scenario)
    golden, output = _ordinary_path(golden), _ordinary_path(output)
    if golden.is_relative_to(output) or output.is_relative_to(golden):
        raise ValueError("Work directory and golden bundle must not overlap")
    check_golden(golden, pin)
    output.parent.mkdir(parents=True, exist_ok=True)
    lock = output.with_name(output.name + ".mutation.lock")
    # O_NOFOLLOW avoids following a foreign lock-file symlink.
    fd = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "a") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        if output.exists():
            marker = output / MARKER
            if (not output.is_dir() or marker.is_symlink() or not marker.is_file()
                    or read_json(marker).get("owner") != OWNER):
                raise ValueError("Refusing to replace a directory not owned by the mutation runner")
            inventory(output)  # Reject links before removing a prior owned copy.
        with tempfile.TemporaryDirectory(prefix=".sentinel-mutation-", dir=output.parent) as temp:
            work = Path(temp) / "case"
            work.mkdir()
            shutil.copytree(golden / "bundle", work / "bundle", copy_function=shutil.copyfile)
            for name in INPUTS:
                shutil.copyfile(golden / name, work / name)
            _apply(work, golden, cases[scenario])
            (work / MARKER).write_bytes(encoded({"owner": OWNER, "goldenPin": pin, "scenario": scenario}))
            check_golden(golden, pin)
            if output.exists():
                shutil.rmtree(output)
            work.replace(output)
    return cases[scenario]["expectedExit"]
