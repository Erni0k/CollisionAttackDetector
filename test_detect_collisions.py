import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from detect_collisions import (
    CHUNK_SIZE, MAX_DIFFERENCE_RANGES, SUPPORTED_ALGORITHMS,
    compare_files, hash_file, hash_file_many, identical, scan,
)

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
        differences = report["collisions"][0]["differences"]
        self.assertEqual(differences["different_bytes"], 6)
        self.assertEqual(differences["range_count"], 6)
        self.assertEqual(differences["ranges"], [
            {"start": position, "end": position + 1}
            for position in [19, 45, 59, 83, 109, 123]
        ])
        self.assertFalse(differences["ranges_truncated"])

    def differences(self, left, right):
        _, a = hash_file(self.write("left", left), "sha256")
        _, b = hash_file(self.write("right", right), "sha256")
        return compare_files(a, b)

    def test_difference_range_crosses_chunk_boundary(self):
        left = b"a" * (CHUNK_SIZE * 2 + 3)
        right = bytearray(left)
        right[CHUNK_SIZE - 2:CHUNK_SIZE + 2] = b"bbbb"
        result = self.differences(left, right)
        self.assertEqual(result["different_bytes"], 4)
        self.assertEqual(result["ranges"], [{"start": CHUNK_SIZE - 2, "end": CHUNK_SIZE + 2}])

    def test_range_ends_at_start_of_identical_chunk(self):
        result = self.differences(b"a" * (CHUNK_SIZE + 1), b"b" * CHUNK_SIZE + b"a")
        self.assertEqual(result["different_bytes"], CHUNK_SIZE)
        self.assertEqual(result["ranges"], [{"start": 0, "end": CHUNK_SIZE}])

    def test_unequal_lengths_and_empty_file(self):
        for left, right in [(b"abc", b"abcdef"), (b"abcdef", b"abc")]:
            with self.subTest(left=left, right=right):
                result = self.differences(left, right)
                self.assertEqual(result["different_bytes"], 3)
                self.assertEqual(result["ranges"], [{"start": 3, "end": 6}])
        result = self.differences(b"", b"abc")
        self.assertEqual(result["ranges"], [{"start": 0, "end": 3}])
        result = self.differences(b"", b"")
        self.assertEqual(result["different_bytes"], 0)
        self.assertEqual(result["ranges"], [])

    def test_difference_ranges_are_bounded_but_totals_are_exact(self):
        count = MAX_DIFFERENCE_RANGES + 3
        result = self.differences(b"aa" * count, b"ba" * count)
        self.assertEqual(result["different_bytes"], count)
        self.assertEqual(result["range_count"], count)
        self.assertEqual(len(result["ranges"]), MAX_DIFFERENCE_RANGES)
        self.assertTrue(result["ranges_truncated"])

    def test_text_output_locates_known_collision_differences(self):
        a, b = self.write("a", FIRST), self.write("b", SECOND)
        result = self.cli("--algorithm", "md5", a, b)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("6 differing bytes in 6 ranges", result.stdout)
        self.assertIn("bytes 19-19 (0x13-0x13)", result.stdout)
        self.assertIn("bytes 123-123 (0x7b-0x7b)", result.stdout)

    def test_sha256_distinguishes_md5_collision_pair(self):
        a, b = self.write("a", FIRST), self.write("b", SECOND)
        result = self.cli("--json", a, b)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["files_scanned"], 2)
        self.assertEqual(report["collisions"], [])
        self.assertEqual(report["duplicates"], [])

    def test_multiple_hashes_report_collision_only_for_md5(self):
        a, b = self.write("a", FIRST), self.write("b", SECOND)
        result = self.cli("--algorithms", "md5,sha1,sha256", "--json", a, b)
        self.assertEqual(result.returncode, 1, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["algorithms"], ["md5", "sha1", "sha256"])
        self.assertIsNone(report["algorithm"])
        self.assertEqual(report["files_scanned"], 2)
        self.assertEqual(len(report["collisions"]), 1)
        self.assertEqual(report["collisions"][0]["algorithm"], "md5")
        self.assertEqual(report["collisions"][0]["differences"]["different_bytes"], 6)
        self.assertEqual(report["duplicates"], [])
        self.assertEqual(report["errors"], [])

    def test_all_supported_hashes_use_one_streaming_read(self):
        content = b"hash multiple chunks" * (CHUNK_SIZE // 10)
        path = self.write("large", content)
        with patch.object(Path, "open", autospec=True, side_effect=Path.open) as opened:
            digests, _ = hash_file_many(path, SUPPORTED_ALGORITHMS)
        self.assertEqual(opened.call_count, 1)
        self.assertEqual(set(digests), set(SUPPORTED_ALGORITHMS))
        for name, digest in digests.items():
            self.assertEqual(digest, hashlib.new(name, content, usedforsecurity=False).hexdigest())

    def test_duplicates_are_per_algorithm_and_comparison_is_reused(self):
        a, b = self.write("a", b"same content"), self.write("b", b"same content")
        with patch("detect_collisions.compare_files", wraps=compare_files) as compared:
            report = scan([a, b], ["md5", "sha1", "sha256"])
        self.assertEqual(compared.call_count, 1)
        self.assertEqual(report["files_scanned"], 2)
        self.assertEqual([event["algorithm"] for event in report["duplicates"]],
                         ["md5", "sha1", "sha256"])
        self.assertEqual(report["collisions"], [])
        self.assertEqual(report["errors"], [])

    def test_repeated_flags_normalize_and_deduplicate_names(self):
        a, b = self.write("a", FIRST), self.write("b", SECOND)
        result = self.cli("--algorithm", "MD5, sha1", "--algorithm", "md5",
                          "--json", a, b)
        self.assertEqual(result.returncode, 1, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["algorithms"], ["md5", "sha1"])
        self.assertEqual(len(report["collisions"]), 1)

    def test_multi_hash_missing_input_is_reported_once_and_scan_continues(self):
        a, b = self.write("a", FIRST), self.write("b", SECOND)
        result = self.cli("--algorithms", "md5,sha1", "--json",
                          a, self.root / "missing", b)
        self.assertEqual(result.returncode, 2, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["files_scanned"], 2)
        self.assertEqual(len(report["errors"]), 1)
        self.assertEqual(len(report["collisions"]), 1)
        self.assertEqual(report["collisions"][0]["algorithm"], "md5")

    def test_invalid_algorithm_lists_fail_before_scanning(self):
        for value in ["md5,unknown", "md5,", "", "shake_128"]:
            with self.subTest(value=value):
                result = self.cli("--algorithms", value, self.root / "missing")
                self.assertEqual(result.returncode, 2)
                self.assertIn("Choose one or more algorithms", result.stderr)
                self.assertEqual(result.stdout, "")

    def test_multi_hash_text_output_has_separate_summaries(self):
        a, b = self.write("a", FIRST), self.write("b", SECOND)
        result = self.cli("--algorithms", "md5,sha1,sha256", a, b)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("COLLISION [md5]", result.stdout)
        self.assertIn("md5: 1 collisions; 0 duplicates.", result.stdout)
        self.assertIn("sha1: 0 collisions; 0 duplicates.", result.stdout)
        self.assertIn("sha256: 0 collisions; 0 duplicates.", result.stdout)

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
