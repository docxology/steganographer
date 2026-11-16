"""Real release archive/checksum fixtures; no packaged consumers are executed."""
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("release_checker", ROOT / "scripts/check-release.py")
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


class ReleaseCheckerSafetyTests(unittest.TestCase):
    def make_release(self, directory, entries, inventory=None):
        archive = directory / "steganographer-test-source.tar.gz"
        with tarfile.open(archive, "w:gz", format=tarfile.PAX_FORMAT) as tar:
            for name, data in entries:
                member = tarfile.TarInfo(name)
                member.mode = 0o755 if data is None else 0o644
                if data is None:
                    member.type = tarfile.DIRTYPE
                    tar.addfile(member)
                else:
                    member.size = len(data)
                    tar.addfile(member, io.BytesIO(data))
        if inventory is None:
            inventory = {"file": {"sha256": CHECKER.digest(b"good"), "bytes": 4, "mode": 0o100644}}
        source = json.dumps(inventory).encode()
        (directory / "SOURCE.json").write_bytes(source)
        (directory / "PROVENANCE.json").write_text(json.dumps({
            "version": "test", "source_inventory_sha256": CHECKER.digest(source), "variants": [],
        }))
        self.refresh_checksums(directory)
        return archive

    def refresh_checksums(self, directory):
        (directory / "SHA256SUMS").write_text("".join(
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
            for path in sorted(directory.iterdir()) if path.name != "SHA256SUMS"
        ))

    def test_accepts_exact_source_inventory(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            self.make_release(directory, [("package/", None), ("package/file", b"good")])
            CHECKER.check(directory)

    def test_refuses_mixed_wasm_package_versions(self):
        for stale in ("node", "web"):
            with self.subTest(stale=stale), tempfile.TemporaryDirectory() as temporary:
                package = Path(temporary)
                for target in ("node", "web"):
                    (package / target).mkdir()
                    (package / target / "package.json").write_text(json.dumps({"version": "0.9.1"}))
                CHECKER.check_wasm_versions(package, "0.9.1")
                (package / stale / "package.json").write_text(json.dumps({"version": "0.8.0"}))
                with self.assertRaisesRegex(ValueError, f"{stale} WASM package version differs"):
                    CHECKER.check_wasm_versions(package, "0.9.1")

    def test_refuses_stale_missing_or_ambiguous_plugin_version(self):
        for element in ("stegovideo", "stegoaudio"):
            with self.subTest(element=element):
                inspection = "Plugin Details:\n  Name                     steganographer\n  Version                  0.9.1\n"
                CHECKER.check_plugin_version(inspection, "0.9.1", element)
                for versions in ("", "  Version                  0.8.0\n",
                                 "  Version                  0.9.1\n  Version                  0.8.0\n"):
                    with self.subTest(versions=versions):
                        with self.assertRaisesRegex(ValueError, f"{element} plugin version differs"):
                            CHECKER.check_plugin_version("Plugin Details:\n" + versions, "0.9.1", element)

    def test_refuses_duplicate_files_before_inventory_collapse(self):
        for duplicate in ("package/file", "package/./file", "package//file", "./package/file"):
            with self.subTest(duplicate=duplicate), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                self.make_release(directory, [("package/file", b"bad!"), (duplicate, b"good")])
                with self.assertRaisesRegex(ValueError, "duplicate normalized archive path"):
                    CHECKER.check(directory)

    def test_refuses_duplicate_directories(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            self.make_release(directory, [("package/", None), ("./package/", None), ("package/file", b"good")])
            with self.assertRaisesRegex(ValueError, "duplicate normalized archive path"):
                CHECKER.check(directory)

    def test_refuses_explicit_file_directory_collision_in_both_orders(self):
        for reverse in (False, True):
            with self.subTest(reverse=reverse), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                entries = [("package/file", b"good"), ("package/./file/", None)]
                self.make_release(directory, list(reversed(entries)) if reverse else entries)
                with self.assertRaisesRegex(ValueError, "duplicate normalized archive path"):
                    CHECKER.check(directory)

    def test_refuses_implicit_parent_file_collision_in_both_orders(self):
        for reverse in (False, True):
            with self.subTest(reverse=reverse), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                entries = [("package/file", b"good"), ("package/file/child", b"child")]
                inventory = {
                    name: {"sha256": CHECKER.digest(data), "bytes": len(data), "mode": 0o100644}
                    for name, data in (("file", b"good"), ("file/child", b"child"))
                }
                self.make_release(directory, list(reversed(entries)) if reverse else entries, inventory)
                with self.assertRaisesRegex(ValueError, "file/directory collision"):
                    CHECKER.check(directory)

    def test_preserves_strict_gzip_truncation_padding_and_multimember_refusal(self):
        for corruption in ("truncated", "padding", "second-member"):
            with self.subTest(corruption=corruption), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                archive = self.make_release(directory, [("package/file", b"good")])
                original = archive.read_bytes()
                if corruption == "truncated":
                    changed = original[:-1]
                elif corruption == "padding":
                    changed = original + b"\0" * 512
                else:
                    changed = original + gzip.compress(b"another member")
                archive.write_bytes(changed)
                self.refresh_checksums(directory)
                with self.assertRaisesRegex(ValueError, "gzip member"):
                    CHECKER.check(directory)

    def test_preserves_source_byte_and_mode_verification(self):
        for data, mode in ((b"bad!", 0o100644), (b"good", 0o100755)):
            with self.subTest(data=data, mode=mode), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                inventory = {"file": {"sha256": CHECKER.digest(b"good"), "bytes": 4, "mode": mode}}
                self.make_release(directory, [("package/file", data)], inventory)
                with self.assertRaisesRegex(ValueError, "source (bytes|mode) differ"):
                    CHECKER.check(directory)


if __name__ == "__main__":
    unittest.main()
