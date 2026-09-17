"""Produce public signed test deltas while the ephemeral fixture key exists."""
from __future__ import annotations

import copy
import json
from pathlib import Path

from sentinel_demo.store import DirectoryStore, descriptor, OCI_MANIFEST

BUNDLE = "application/vnd.dev.sigstore.bundle.v0.3+json"
GOV = "https://sentinel.example/demo/governance/v1"
ROOT = "https://sentinel.example/demo/evidence-manifest/v1"


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def prepare_variants(pipeline, work: Path, export, request, manifest, governance, image_bytes):
    """Only signed deltas leave this function; no private key is exported."""
    deltas = DirectoryStore(pipeline.output / "test-variants")
    gov_entry = next(e for e in manifest["entries"] if e["role"] == "governance")

    def sign(predicate, predicate_type, target_bytes, label, template):
        predicate_path = work / (label + ".predicate.json")
        target = work / (label + ".image.json")
        bundle_path = work / (label + ".sigstore.json")
        predicate_path.write_bytes(encoded(predicate))
        target.write_bytes(target_bytes)
        pipeline.run([pipeline.tool("cosign"), "attest-blob", "--key", str(work / "demo.key"),
                      "--use-signing-config=false", "--tlog-upload=false", "--yes",
                      "--predicate", str(predicate_path), "--type", predicate_type,
                      "--bundle", str(bundle_path), str(target)])
        bundle = bundle_path.read_bytes()
        payload = descriptor(bundle, BUNDLE)
        artifact = json.loads(export.read_manifest(template["artifact"]["digest"]))
        artifact["layers"] = [payload]
        # Remove discovery annotations from the synthetic delta; they are not trust inputs.
        artifact.pop("annotations", None)
        raw = encoded(artifact)
        deltas.write(bundle)
        deltas.write(raw)
        return {"artifact": descriptor(raw, OCI_MANIFEST), "payload": payload}

    variants = {}
    for scenario in ("subject-mismatch", "governance-fail", "unknown-predicate"):
        predicate = copy.deepcopy(governance)
        predicate_type = GOV
        target_bytes = image_bytes
        if scenario == "subject-mismatch":
            target_bytes += b"\n"
        elif scenario == "governance-fail":
            predicate["checks"]["buildPassed"] = False
        else:
            predicate_type = "https://sentinel.example/demo/unknown/v1"
        changed = sign(predicate, predicate_type, target_bytes, scenario, gov_entry)
        inventory = copy.deepcopy(manifest)
        for entry in inventory["entries"]:
            if entry["role"] == "governance":
                entry.update(changed)
        variants[scenario] = sign(inventory, ROOT, image_bytes, scenario + "-root", request["manifest"])
    (pipeline.output / "test-variants/index.json").write_bytes(encoded(variants))
