"""Run the six acceptance scenarios on copies of real exported evidence."""
from __future__ import annotations

import base64
import copy
import json
import shutil
import tempfile
from pathlib import Path

from sentinel_demo.store import DirectoryStore, descriptor
from sentinel_demo.verify import verify_bundle


def _statement(store, reference):
    bundle = json.loads(store.read_blob(reference["payload"]["digest"]))
    return json.loads(base64.b64decode(bundle["dsseEnvelope"]["payload"]))


def run_scenarios(export: Path, request: dict, policy: bytes, key: Path,
                  cosign: str, expected: dict, selected: str = "all") -> list[dict]:
    outcomes = []
    names = list(expected) if selected == "all" else [selected]
    reasons = {"happy-path": "VERIFIED", "missing-sbom": "MISSING_SBOM",
               "missing-governance": "MISSING_GOVERNANCE", "digest-mismatch": "DIGEST_MISMATCH",
               "bad-signature": "INVALID_SIGNATURE", "missing-manifest": "MISSING_MANIFEST"}
    for name in names:
        with tempfile.TemporaryDirectory(prefix="sentinel-case-") as temporary:
            directory = Path(temporary)
            shutil.copytree(export, directory / "bundle")
            store = DirectoryStore(directory / "bundle")
            case = copy.deepcopy(request)
            inventory = _statement(store, request["manifest"])["predicate"]
            if name in {"missing-sbom", "missing-governance"}:
                role = name.removeprefix("missing-")
                entry = next(e for e in inventory["entries"] if e["role"] == role)
                (store.root / "blobs/sha256" / entry["payload"]["digest"][7:]).unlink()
            elif name == "missing-manifest":
                (store.root / "blobs/sha256" / case["manifest"]["artifact"]["digest"][7:]).unlink()
            elif name == "digest-mismatch":
                # Corrupt actual target bytes, leaving the externally expected digest fixed.
                image_digest = case["image"].split("@", 1)[1]
                (store.root / "blobs/sha256" / image_digest[7:]).write_bytes(b'{"tampered":true}')
            elif name == "bad-signature":
                # Rehash the outer container to force the check through to Cosign.
                root = case["manifest"]
                bundle = json.loads(store.read_blob(root["payload"]["digest"]))
                signature = bytearray(base64.b64decode(bundle["dsseEnvelope"]["signatures"][0]["sig"]))
                signature[-1] ^= 1
                bundle["dsseEnvelope"]["signatures"][0]["sig"] = base64.b64encode(signature).decode()
                payload = json.dumps(bundle, separators=(",", ":")).encode()
                artifact = json.loads(store.read_manifest(root["artifact"]["digest"]))
                root["payload"] = descriptor(payload, root["payload"]["mediaType"])
                artifact["layers"] = [root["payload"]]
                artifact_bytes = json.dumps(artifact, separators=(",", ":")).encode()
                root["artifact"] = descriptor(artifact_bytes, root["artifact"]["mediaType"])
                store.write(payload)
                store.write(artifact_bytes)
            result = verify_bundle(case, policy, key, store, cosign)
            want = expected[name]
            matched = (result["status"] == want["status"] and result["exitCode"] == want["exitCode"]
                       and reasons[name] in result["reasonCodes"])
            outcomes.append({"scenario": name, "expected": want, "expectedReason": reasons[name],
                             "accepted": matched, "result": result})
            print(f"{name:20} {result['status']:8} exit={result['exitCode']} test={'PASS' if matched else 'FAIL'}", flush=True)
    return outcomes
