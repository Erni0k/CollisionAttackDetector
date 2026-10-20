import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from detect_collisions import CHUNK_SIZE, hash_file, identical, scan

# Published MD5 collision example: https://www.mscs.dal.ca/~selinger/md5collision/
FIRST = bytes.fromhex("""
d131dd02c5e6eec4693d9a0698aff95c 2fcab58712467eab4004583eb8fb7f89
55ad340609f4b30283e488832571415a 085125e8f7cdc99fd91dbdf280373c5b
d8823e3156348f5bae6dacd436c919c6 dd53e2b487da03fd02396306d248cda0
e99f33420f577ee8ce54b67080a80d1e c69821bcb6a8839396f9652b6ff72a70
""")
SECOND = bytes.fromhex("""
d131dd02c5e6eec4693d9a0698aff95c 2fcab50712467eab4004583eb8fb7f89
55ad340609f4b30283e4888325f1415a 085125e8f7cdc99fd91dbd7280373c5b
d8823e3156348f5bae6dacd436c919c6 dd53e23487da03fd02396306d248cda0
e99f33420f577ee8ce54b67080280d1e c69821bcb6a8839396f965ab6ff72a70
""")


class DetectorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def write(self, name, content):
        path = self.root / name
        path.write_bytes(content)
        return path

    def cli(self, *args):
        return subprocess.run(
            [sys.executable, str(Path(__file__).with_name("detect_collisions.py")), *map(str, args)],
            capture_output=True, text=True, check=False,
        )

    def test_real_md5_collision_and_cli(self):
        self.assertNotEqual(FIRST, SECOND)
        self.assertEqual(hashlib.md5(FIRST).hexdigest(), "79054025255fb1a26e4bc422aef54eb4")
        self.assertEqual(hashlib.md5(FIRST).digest(), hashlib.md5(SECOND).digest())
        a, b = self.write("a.bin", FIRST), self.write("b.bin", SECOND)
        result = self.cli("--algorithm", "md5", "--json", a, b)
        self.assertEqual(result.returncode, 1, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["files_scanned"], 2)
        self.assertEqual(len(report["collisions"]), 1)
        self.assertEqual(report["duplicates"], [])
        self.assertEqual(report["errors"], [])

    def test_sha256_distinguishes_md5_collision_pair(self):
        a, b = self.write("a", FIRST), self.write("b", SECOND)
        result = self.cli("--json", a, b)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["files_scanned"], 2)
        self.assertEqual(report["collisions"], [])
        self.assertEqual(report["duplicates"], [])

    def test_duplicate_of_second_collision_variant(self):
        paths = [self.write(str(i), data) for i, data in enumerate([FIRST, SECOND, SECOND])]
        report = scan(paths, "md5")
        self.assertEqual(len(report["collisions"]), 1)
        self.assertEqual(len(report["duplicates"]), 1)
        self.assertEqual(report["duplicates"][0]["files"], list(map(str, paths[1:])))

    def test_large_duplicate_and_distinct_file(self):
        content = b"x" * (CHUNK_SIZE * 2 + 17)
        paths = [self.write("a", content), self.write("b", content), self.write("c", content + b"y")]
        report = scan(paths)
        self.assertEqual(report["files_scanned"], 3)
        self.assertEqual(len(report["duplicates"]), 1)
        self.assertEqual(report["collisions"], [])
        self.assertEqual(report["errors"], [])

    def test_empty_files_are_duplicates(self):
        report = scan([self.write("a", b""), self.write("b", b"")])
        self.assertEqual(len(report["duplicates"]), 1)
        self.assertEqual(report["collisions"], [])

    def test_missing_file_continues_but_returns_incomplete_status(self):
        good = self.write("good", b"content")
        result = self.cli("--json", self.root / "missing", good)
        self.assertEqual(result.returncode, 2)
        report = json.loads(result.stdout)
        self.assertEqual(report["files_scanned"], 1)
        self.assertEqual(len(report["errors"]), 1)

    def test_directory_is_reported_as_error(self):
        report = scan([self.root])
        self.assertEqual(report["files_scanned"], 0)
        self.assertEqual(len(report["errors"]), 1)

    def test_changed_file_is_not_reported_as_duplicate(self):
        a, b = self.write("a", b"same"), self.write("b", b"same")
        _, first = hash_file(a, "sha256")
        _, second = hash_file(b, "sha256")
        a.write_bytes(b"changed content")
        with self.assertRaisesRegex(OSError, "File changed"):
            identical(first, second)

    def test_errors_take_precedence_over_collisions(self):
        a, b = self.write("a", FIRST), self.write("b", SECOND)
        result = self.cli("--algorithm", "md5", "--json", a, b, self.root / "missing")
        self.assertEqual(result.returncode, 2)
        report = json.loads(result.stdout)
        self.assertEqual(len(report["collisions"]), 1)
        self.assertEqual(len(report["errors"]), 1)


if __name__ == "__main__":
    unittest.main()
