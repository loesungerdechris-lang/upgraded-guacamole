#!/usr/bin/env python3
"""Download the pinned Linux/amd64 demo tools into a user-owned directory."""
from __future__ import annotations

import argparse
import concurrent.futures
import fcntl
import hashlib
import io
import json
import os
import platform
import subprocess
import tarfile
from pathlib import Path
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]


def fetch(item: dict) -> bytes:
    with urlopen(item["url"], timeout=60) as response:
        data = response.read()
    if hashlib.sha256(data).hexdigest() != item["sha256"]:
        raise RuntimeError("Download checksum mismatch for " + item["name"])
    return data


def install_tool(item: dict, destination: Path) -> None:
    target = destination / item["name"]
    if target.is_file() and hashlib.sha256(target.read_bytes()).hexdigest() == item["binarySha256"]:
        target.chmod(0o755)
        return
    data = fetch(item)
    if item["kind"] == "tar":
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            matches = [m for m in archive.getmembers()
                       if m.isfile() and m.name.split("/")[-1] == item["name"]]
            if len(matches) != 1:
                raise RuntimeError("Ambiguous binary in tool archive")
            data = archive.extractfile(matches[0]).read()
    if hashlib.sha256(data).hexdigest() != item["binarySha256"]:
        raise RuntimeError("Extracted binary checksum mismatch")
    target.write_bytes(data)
    target.chmod(0o755)


def install_rust(lock: dict, destination: Path) -> None:
    """Extract only pinned files; validate full bytes before replacing any file."""
    cache = destination / "downloads"
    cache.mkdir(exist_ok=True)
    wanted = {item["path"]: item["sha256"] for item in lock["rustFiles"]}
    installed = set()
    root = (destination / "rust").resolve()
    for item in lock["rustDebianPackages"]:
        package = cache / (item["name"] + ".deb")
        if not package.is_file() or hashlib.sha256(package.read_bytes()).hexdigest() != item["sha256"]:
            package.write_bytes(fetch(item))
        archive_bytes = subprocess.check_output(["dpkg-deb", "--fsys-tarfile", str(package)])
        with tarfile.open(fileobj=io.BytesIO(archive_bytes)) as archive:
            for member in archive:
                name = member.name.removeprefix("./")
                if name not in wanted:
                    continue
                if not member.isfile() or name in installed:
                    raise RuntimeError("Unexpected compiler archive member: " + name)
                data = archive.extractfile(member).read()
                if hashlib.sha256(data).hexdigest() != wanted[name]:
                    raise RuntimeError("Compiler archive member checksum mismatch: " + name)
                target = root / name
                if not target.resolve().is_relative_to(root):
                    raise RuntimeError("Compiler path escapes destination")
                target.parent.mkdir(parents=True, exist_ok=True)
                temporary = target.with_name(target.name + ".installing")
                temporary.write_bytes(data)
                temporary.chmod(member.mode & 0o777)
                temporary.replace(target)
                installed.add(name)
    if installed != set(wanted):
        raise RuntimeError("Compiler archive did not contain every pinned file")
    for item in lock["rustSymlinks"]:
        target = root / item["path"]
        if not (target.parent / item["target"]).resolve().is_relative_to(root):
            raise RuntimeError("Compiler symlink escapes destination")
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.is_symlink():
            target.unlink()
        target.symlink_to(item["target"])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=ROOT / ".tools")
    parser.add_argument("--only", choices=["cosign"])
    args = parser.parse_args()
    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "AMD64"}:
        parser.error("This fixed demo toolchain requires Linux/amd64 (WSL2 is supported)")
    destination = args.directory.resolve()
    destination.mkdir(parents=True, exist_ok=True)
    # Serialize two invocations sharing this user-owned tool directory.
    install_lock = (destination / "install.lock").open("a")
    fcntl.flock(install_lock, fcntl.LOCK_EX)
    lock = json.loads((ROOT / "toolchain.lock.json").read_bytes())
    if args.only:
        install_tool(next(item for item in lock["tools"] if item["name"] == args.only), destination)
        print("Pinned tool ready:", args.only)
        return
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        for _ in pool.map(lambda item: install_tool(item, destination), lock["tools"]):
            pass
    install_rust(lock, destination)
    for item in lock["rustFiles"]:
        path = destination / "rust" / item["path"]
        if hashlib.sha256(path.read_bytes()).hexdigest() != item["sha256"]:
            raise RuntimeError("Extracted compiler/library checksum mismatch: " + item["path"])
    env = os.environ.copy()
    env["LD_LIBRARY_PATH"] = str(destination / "rust/usr/lib/x86_64-linux-gnu")
    subprocess.run([str(destination / "rust/usr/bin/rustc"), "--version"], env=env, check=True)
    print("Pinned demo toolchain ready:", destination)


if __name__ == "__main__":
    main()
