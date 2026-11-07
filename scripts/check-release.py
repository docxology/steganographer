#!/usr/bin/env python3
"""Exercise actual release archives, not source-text wiring. Requires Python 3.12+."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import tarfile
import tempfile


def digest(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def check(directory):
    sums = {}
    for line in (directory / "SHA256SUMS").read_text().splitlines():
        checksum, name = line.split("  ", 1)
        require(Path(name).name == name and name not in sums, "unsafe checksum inventory")
        require(digest((directory / name).read_bytes()) == checksum, f"checksum mismatch: {name}")
        sums[name] = checksum
    require(set(sums) == {p.name for p in directory.iterdir()} - {"SHA256SUMS"}, "incomplete checksum inventory")
    provenance = json.loads((directory / "PROVENANCE.json").read_text())
    inventory = json.loads((directory / "SOURCE.json").read_text())
    require(digest((directory / "SOURCE.json").read_bytes()) == provenance["source_inventory_sha256"], "source inventory checksum mismatch")
    version = provenance["version"]
    root = Path(__file__).resolve().parents[1]
    seen = set()
    for archive in sorted(directory.glob("*.tar.gz")):
        with tarfile.open(archive) as tar, tempfile.TemporaryDirectory() as temporary:
            members = tar.getmembers()
            for member in members:
                path = PurePosixPath(member.name)
                require(not path.is_absolute() and ".." not in path.parts, f"unsafe archive path: {member.name}")
                require(member.isfile() or member.isdir(), f"unsupported archive entry: {member.name}")
                require(not {".git", ".hg", ".svn", "keys", "target", "dist"}.intersection(path.parts), f"excluded archive path: {member.name}")
            roots = {PurePosixPath(member.name).parts[0] for member in members}
            require(len(roots) == 1, f"archive must have one root: {archive}")
            package_root = next(iter(roots))
            if archive.name.endswith("-source.tar.gz"):
                files = {str(PurePosixPath(m.name).relative_to(package_root)): m for m in members if m.isfile()}
                require(set(files) == set(inventory), "source inventory differs from archive")
                for name, member in files.items():
                    data = tar.extractfile(member).read()
                    expected = inventory[name]
                    require(digest(data) == expected["sha256"] and len(data) == expected["bytes"], f"source bytes differ: {name}")
                    require(member.mode == expected["mode"] & 0o7777, f"source mode differs: {name}")
                seen.add("source")
                continue
            tar.extractall(temporary, filter="data")
            package = Path(temporary) / package_root
            details = json.loads((package / "BUILD.json").read_text())
            kind = details["kind"]
            require(kind not in seen, "duplicate variant")
            seen.add(kind)
            if kind in ("native", "portable"):
                require(details["host"] == provenance["host"], "native target differs from provenance")
                reported = subprocess.check_output([str(package / "steganographer"), "--version"], text=True).strip()
                require(reported == f"steganographer {version}", f"CLI version mismatch: {reported}")
                require(len(list((package / "completions").iterdir())) == 5, "incomplete completions")
                require(len(list((package / "man").glob("*.1"))) == (18 if kind == "native" else 16), "incomplete manuals")
                if kind == "native":
                    libraries = [*package.glob("*.dylib"), *package.glob("*.so")]
                    require(len(libraries) == 1, "native archive must contain one plugin library")
                    expected_library = libraries[0].resolve(strict=True)
                    registry = str(Path(temporary) / "registry.bin")
                    env = dict(
                        os.environ,
                        GST_PLUGIN_PATH=str(package),
                        GST_PLUGIN_PATH_1_0=str(package),
                        GST_PLUGIN_SYSTEM_PATH="",
                        GST_PLUGIN_SYSTEM_PATH_1_0="",
                        GST_REGISTRY=registry,
                        GST_REGISTRY_1_0=registry,
                        LC_ALL="C",
                    )
                    for element in ("stegovideo", "stegoaudio"):
                        inspection = subprocess.check_output(
                            ["gst-inspect-1.0", element], env=env, text=True
                        )
                        filenames = [
                            line.strip().split(maxsplit=1)[1]
                            for line in inspection.splitlines()
                            if line.strip().startswith("Filename ")
                        ]
                        require(
                            len(filenames) == 1
                            and Path(filenames[0]).resolve(strict=True) == expected_library,
                            f"{element} was not loaded from the packaged plugin",
                        )
            elif kind == "wasm":
                subprocess.run(["node", str(root / "steganographer-wasm/tests/bindings.cjs"), str(package / "node/steganographer_wasm.js")], check=True)
                subprocess.run(["node", "--input-type=module", "-e", """
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {pathToFileURL} from 'node:url';
const directory = process.argv[1];
const wasm = await import(pathToFileURL(directory + '/steganographer_wasm.js'));
wasm.initSync({module: readFileSync(directory + '/steganographer_wasm_bg.wasm')});
const packet = wasm.packet_encode(Uint8Array.of(1, 2, 3), 1, new Uint8Array(16), new Uint8Array(8), 1, null);
assert.deepEqual(JSON.parse(wasm.packet_decode(packet, null)).body, [1, 2, 3]);
""", str(package / "web")], check=True)
            else:
                raise AssertionError(f"unknown variant: {kind}")
    require(seen == {"source"} | {variant["kind"] for variant in provenance["variants"]}, "missing or unexpected artifact variant")
    print(f"Verified checksums, exact source inventory and consumers: {', '.join(sorted(seen))}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    check(parser.parse_args().directory.resolve(strict=True))
