#!/usr/bin/env python3
"""One pipeline: build, test, scan, attest, retrieve, verify, acceptance cases."""
from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from sentinel_demo.cli import atomic_json
from sentinel_demo.store import DirectoryStore, RegistryStore, descriptor, digest, OCI_MANIFEST
from sentinel_demo.verify import verify_bundle
from scenarios import run_scenarios
from golden_variants import prepare_variants

PROFILE = "sentinel-demo-mvp/v0.1"
M2_PROFILE = "sentinel-demo-m2/v0.1"
TYPES = {"provenance": "https://sentinel.example/demo/provenance/v1", "sbom": "https://cyclonedx.org/bom", "governance": "https://sentinel.example/demo/governance/v1",
         "manifest": "https://sentinel.example/demo/evidence-manifest/v1"}
BUNDLE_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json"


def json_bytes(obj) -> bytes:
    return (json.dumps(obj, sort_keys=True, separators=(",", ":")) + "\n").encode()


class Pipeline:
    def __init__(self, tools: Path, output: Path):
        self.tools, self.output = tools, output
        self.env = os.environ.copy()
        self.env.update({"COSIGN_PASSWORD": "", "SYFT_CHECK_FOR_APP_UPDATE": "false",
                         "SYFT_REGISTRY_INSECURE_USE_HTTP": "true",
                         "LD_LIBRARY_PATH": str(tools / "rust/usr/lib/x86_64-linux-gnu")})
        self.log = (output / "pipeline.log").open("w", encoding="utf-8")
        self.commands = []

    def run(self, command: list[str], timeout: int = 60) -> str:
        proc = subprocess.run(command, cwd=ROOT, env=self.env, text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        # Command paths/versions, never key contents/password values.
        self.commands.append({"command": command, "returnCode": proc.returncode})
        self.log.write("$ " + " ".join(command) + "\n" + proc.stdout + proc.stderr + "\n")
        self.log.flush()
        if proc.returncode:
            raise RuntimeError(f"{Path(command[0]).name} failed ({proc.returncode}): {proc.stderr[-1600:]}")
        return proc.stdout.strip()

    def tool(self, name: str) -> str:
        return str(self.tools / name)


def validate_tools(tools: Path, lock: dict) -> None:
    for item in lock["tools"]:
        path = tools / item["name"]
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != item["binarySha256"]:
            raise RuntimeError("Pinned binary missing or modified: " + item["name"])
    for item in lock["rustFiles"]:
        path = tools / "rust" / item["path"]
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != item["sha256"]:
            raise RuntimeError("Pinned compiler/library missing or modified: " + item["path"])
    for item in lock["rustSymlinks"]:
        path = tools / "rust" / item["path"]
        if not path.is_symlink() or str(path.readlink()) != item["target"]:
            raise RuntimeError("Pinned compiler symlink missing or modified: " + item["path"])


def find_artifact(store: RegistryStore, image_digest: str, bundle: bytes) -> dict:
    target = descriptor(bundle, BUNDLE_TYPE)
    for candidate in store.discover(image_digest):
        raw = store.read_manifest(candidate["digest"])
        if digest(raw) != candidate["digest"]:
            raise RuntimeError("Registry artifact manifest hash mismatch")
        manifest = json.loads(raw)
        layers = manifest.get("layers", [])
        if len(layers) == 1 and layers[0]["digest"] == target["digest"]:
            if layers[0]["size"] != len(bundle) or manifest.get("subject", {}).get("digest") != image_digest:
                raise RuntimeError("Registry attestation binding mismatch")
            downloaded = store.read_blob(target["digest"])
            if downloaded != bundle:
                raise RuntimeError("Registry did not return the signed bundle bytes")
            return {"artifact": descriptor(raw, OCI_MANIFEST), "payload": target}
    raise RuntimeError("Signed bundle not discoverable in registry")


def attest(pipeline: Pipeline, store: RegistryStore, work: Path, image: str,
           role: str, predicate: dict) -> dict:
    image_digest = image.split("@", 1)[1]
    statement = {"_type": "https://in-toto.io/Statement/v0.1",
                 "subject": [{"name": image.split("@", 1)[0], "digest": {"sha256": image_digest[7:]}}],
                 "predicateType": TYPES[role], "predicate": predicate}
    predicate_path = work / (role + ".predicate.json")
    predicate_path.write_bytes(json_bytes(predicate))
    bundle_path = pipeline.output / (role + ".sigstore.json")
    pipeline.run([pipeline.tool("cosign"), "attest", "--key", str(work / "demo.key"),
                  "--use-signing-config=false", "--tlog-upload=false", "--allow-http-registry", "--yes",
                  "--predicate", str(predicate_path), "--type", TYPES[role],
                  "--bundle", str(bundle_path), image])
    bundle = bundle_path.read_bytes()
    if json.loads(bundle).get("verificationMaterial", {}).get("tlogEntries"):
        raise RuntimeError("Unexpected transparency-log submission in local demo profile")
    signed_statement = json.loads(base64.b64decode(json.loads(bundle)["dsseEnvelope"]["payload"]))
    if signed_statement != statement:
        raise RuntimeError("Cosign output statement differs from the expected pinned profile")
    return find_artifact(store, image_digest, bundle)


def run(tools: Path, output: Path, scenario: str, profile: str = PROFILE) -> dict:
    if profile not in {PROFILE, M2_PROFILE}:
        raise ValueError("Unsupported producer profile")
    if output.exists() and any(output.iterdir()):
        raise RuntimeError("Output directory is not empty; choose a new --output path")
    output.mkdir(parents=True, exist_ok=True)
    lock = json.loads((ROOT / "toolchain.lock.json").read_bytes())
    validate_tools(tools, lock)
    pipeline = Pipeline(tools, output)
    server = None
    server_log = None
    try:
        with tempfile.TemporaryDirectory(prefix="sentinel-run-") as temporary:
            work = Path(temporary)
            compiler = str(tools / "rust/usr/bin/rustc")
            source = ROOT / "source/hello-sentinel.rs"
            common = [compiler, "--edition=2021", "--sysroot", str(tools / "rust/usr"),
                      "--remap-path-prefix", str(ROOT) + "=/sentinel", str(source)]
            print("Build and test the Rust fixture", flush=True)
            pipeline.run(common + ["--test", "-o", str(work / "rust-tests")])
            test_output = pipeline.run([str(work / "rust-tests")])
            binary = work / "sentinel-demo"
            pipeline.run(common + ["-C", "opt-level=2", "-C", "strip=symbols", "-C", "target-feature=+crt-static", "-o", str(binary)])
            if pipeline.run([str(binary)]) != "Hello, SENTINEL.":
                raise RuntimeError("Unexpected binary output")
            binary_bytes = binary.read_bytes()
            # Keep optional Dockerfile input outside the distributable evidence.
            (ROOT / ".run").mkdir(exist_ok=True)
            shutil.copy2(binary, ROOT / ".run/sentinel-demo")
            layer = work / "image-layer.tar"
            with tarfile.open(layer, "w", format=tarfile.USTAR_FORMAT) as archive:
                member = tarfile.TarInfo("sentinel-demo")
                member.size, member.mode, member.mtime = len(binary_bytes), 0o755, 0
                member.uid = member.gid = 0
                archive.addfile(member, io.BytesIO(binary_bytes))
            config = work / "registry.yml"
            # Port zero lets the OS choose an unused loopback port. The registry
            # reports it through its JSON startup log, so no racy preallocation.
            config.write_text("version: 0.1\nlog:\n  level: info\n  formatter: json\nstorage:\n  filesystem:\n    rootdirectory: " + str(work / "registry-data") + "\nhttp:\n  addr: 127.0.0.1:0\n")
            server_log = (output / "registry.log").open("w")
            server = subprocess.Popen([pipeline.tool("registry"), "serve", str(config)],
                                      stdout=server_log, stderr=server_log, env=pipeline.env)
            import re
            port = None
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if server.poll() is not None:
                    raise RuntimeError("Registry failed to start")
                content = (output / "registry.log").read_text()
                match = re.search(r"listening on 127\.0\.0\.1:(\d+)", content)
                if match:
                    port = int(match.group(1))
                    break
                time.sleep(0.05)
            if not port:
                raise RuntimeError("Registry startup did not report its listening port")
            repository = f"127.0.0.1:{port}/sentinel-demo"
            tag = repository + ":demo"
            print("Package and push one OCI image to the local registry", flush=True)
            pipeline.run([pipeline.tool("crane"), "append", "--insecure", "--oci-empty-base",
                          "--new_layer", str(layer), "--new_tag", tag])
            pipeline.run([pipeline.tool("crane"), "mutate", "--insecure", "--entrypoint", "/sentinel-demo",
                          "--set-platform", "linux/amd64", "--tag", tag, tag])
            image_digest = pipeline.run([pipeline.tool("crane"), "digest", "--insecure", tag])
            image = repository + "@" + image_digest
            export = DirectoryStore(output / "bundle")
            store = RegistryStore(repository, export)
            image_bytes = store.read_manifest(image_digest)
            if digest(image_bytes) != image_digest:
                raise RuntimeError("Pushed image digest mismatch")
            print("Generate real CycloneDX 1.6 SBOM by image digest", flush=True)
            pipeline.run([pipeline.tool("syft"), "registry:" + image,
                          "-o", "cyclonedx-json@1.6=" + str(output / "sbom.json")], timeout=120)
            sbom = json.loads((output / "sbom.json").read_bytes())
            policy = (ROOT / "policy" / ("governance-m2.yml" if profile == M2_PROFILE else "governance.yml")).read_bytes()
            policy_hash = digest(policy)
            run_id = "demo-" + digest(binary_bytes)[7:23] + "-" + image_digest[7:23]
            governance = {"profile": profile, "fixture": True, "productionApproval": False,
                          "runId": run_id, "imageDigest": image_digest, "policySha256": policy_hash,
                          "checks": {"buildPassed": True, "testsPassed": True, "sbomGenerated": True}}
            (output / "governance.json").write_bytes(json_bytes(governance))
            pipeline.run([pipeline.tool("cosign"), "generate-key-pair", "--output-key-prefix", str(work / "demo")])
            key = output / "demo.pub"
            shutil.copyfile(work / "demo.pub", key)
            print("Sign and upload SBOM, mock governance and inventory", flush=True)
            entries = []
            predicates = [("sbom", sbom), ("governance", governance)]
            if profile == M2_PROFILE:
                provenance = {"profile": profile, "fixture": True, "runId": run_id,
                              "imageDigest": image_digest, "policySha256": policy_hash,
                              "sourceSha256": digest(source.read_bytes()),
                              "binarySha256": digest(binary_bytes), "builder": "sentinel-demo"}
                (output / "provenance.json").write_bytes(json_bytes(provenance))
                predicates.append(("provenance", provenance))
            for role, predicate in predicates:
                reference = attest(pipeline, store, work, image, role, predicate)
                entries.append({"role": role, "predicateType": TYPES[role], **reference})
            manifest = {"profile": profile, "runId": run_id, "imageDigest": image_digest,
                        "policySha256": policy_hash, "entries": entries}
            (output / "evidence-manifest.json").write_bytes(json_bytes(manifest))
            reference = attest(pipeline, store, work, image, "manifest", manifest)
            request = {"profile": profile, "image": image, "manifest": reference,
                       "runId": run_id, "policySha256": policy_hash, "publicKeySha256": digest(key.read_bytes())}
            atomic_json(output / "verification-request.json", request)
            (output / "governance-policy.yml").write_bytes(policy)
            print("Retrieve and verify from the registry", flush=True)
            live = verify_bundle(request, policy, key, store, pipeline.tool("cosign"))
            atomic_json(output / "verification-online.json", live)
            if live["exitCode"] != 0:
                raise RuntimeError("Registry verification failed: " + json.dumps(live))
            offline = verify_bundle(request, policy, key, export, pipeline.tool("cosign"))
            repeat = verify_bundle(request, policy, key, export, pipeline.tool("cosign"))
            atomic_json(output / "verification-offline.json", offline)
            if offline != repeat or live != offline:
                raise RuntimeError("Same bytes produced different online/offline verification results")
            if profile == M2_PROFILE:
                prepare_variants(pipeline, work, export, request, manifest, governance, image_bytes)
                outcomes = [{"scenario": "golden", "accepted": True, "result": live}]
            else:
                expected = json.loads((ROOT / "expected/acceptance.json").read_bytes())["scenarios"]
                outcomes = run_scenarios(output / "bundle", request, policy, key, pipeline.tool("cosign"), expected, scenario)
            atomic_json(output / "acceptance-results.json", {"scenarios": outcomes})
            summary = {"profile": profile, "pipelineStatus": "PASS" if all(x["accepted"] for x in outcomes) else "FAIL",
                       "productionAcceptance": False, "image": image, "manifest": reference,
                       "sourceSha256": digest(source.read_bytes()), "binarySha256": digest(binary_bytes),
                       "policySha256": policy_hash, "toolchainLockSha256": digest((ROOT / "toolchain.lock.json").read_bytes()),
                       "compiler": pipeline.run([compiler, "--version"]), "linker": pipeline.run(["cc", "--version"]).splitlines()[0],
                       "rustTests": test_output, "onlineOfflineEqual": live == offline, "repeatEqual": offline == repeat,
                       "passedScenarios": sum(x["accepted"] for x in outcomes), "totalScenarios": len(outcomes),
                       "tools": [{"name": t["name"], "version": t["version"], "binarySha256": t["binarySha256"]} for t in lock["tools"]],
                       "limitations": ["Mock governance; no human approval", "Local test key; no transparency/time validation",
                                       "No canonical v2.2 conformance", "No SLSA provenance or vulnerability scan",
                                       "Local registry only; no release published", "Host linker/libc not hermetically pinned"]}
            atomic_json(output / "run-summary.json", summary)
            atomic_json(output / "commands.json", {"commands": pipeline.commands})
            if summary["pipelineStatus"] != "PASS":
                raise RuntimeError("An acceptance scenario failed its expected result")
            return summary
    finally:
        if server:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=5)
        if server_log:
            server_log.close()
        pipeline.log.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tools", type=Path, default=ROOT / ".tools")
    parser.add_argument("--output", type=Path, default=ROOT / "release")
    parser.add_argument("--scenario", choices=["all", "happy-path", "missing-sbom", "missing-governance",
                                              "digest-mismatch", "bad-signature", "missing-manifest"], default="all")
    args = parser.parse_args()
    try:
        summary = run(args.tools.resolve(), args.output.resolve(), args.scenario)
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as exc:
        print("DEMO PIPELINE ERROR:", str(exc), file=sys.stderr)
        return 1
    print("SENTINEL DEMO PIPELINE PASS —", summary["passedScenarios"], "/", summary["totalScenarios"], "acceptance cases", flush=True)
    print("No production release or compliance approval.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
