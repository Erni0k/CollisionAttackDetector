#!/usr/bin/env python3
"""Find observed file hash collisions using bounded-memory, exact comparison."""

import argparse
import hashlib
import json
import os
import stat
from contextlib import ExitStack
from dataclasses import dataclass
from itertools import zip_longest
from pathlib import Path

CHUNK_SIZE = 1024 * 1024
MAX_DIFFERENCE_RANGES = 20


def signature(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


@dataclass(frozen=True)
class FileRecord:
    path: Path
    signature: tuple


def check_unchanged(stream, record):
    if signature(os.fstat(stream.fileno())) != record.signature:
        raise OSError(f"File changed during scan: {record.path}")


def hash_file(path, algorithm):
    # Reject directories, devices, and named pipes before opening them.
    info = path.stat()
    if not stat.S_ISREG(info.st_mode):
        raise OSError("Expected a regular file")
    record = FileRecord(path, signature(info))
    digest = hashlib.new(algorithm, usedforsecurity=False)
    with path.open("rb") as stream:
        check_unchanged(stream, record)
        for chunk in iter(lambda: stream.read(CHUNK_SIZE), b""):
            digest.update(chunk)
        check_unchanged(stream, record)
    return digest.hexdigest(), record


def compare_files(left, right):
    """Summarize differing offsets, retaining a bounded number of byte ranges."""
    ranges = []
    range_count = 0
    different_bytes = 0
    run_start = None
    offset = 0

    def finish_range(start, end):
        nonlocal range_count
        range_count += 1
        if len(ranges) < MAX_DIFFERENCE_RANGES:
            ranges.append({"start": start, "end": end})

    with ExitStack() as stack:
        a = stack.enter_context(left.path.open("rb"))
        b = stack.enter_context(right.path.open("rb"))
        check_unchanged(a, left)
        check_unchanged(b, right)
        while True:
            chunk_a, chunk_b = a.read(CHUNK_SIZE), b.read(CHUNK_SIZE)
            if not chunk_a and not chunk_b:
                break
            if chunk_a == chunk_b:
                if run_start is not None:
                    finish_range(run_start, offset)
                    run_start = None
            else:
                for index, (byte_a, byte_b) in enumerate(zip_longest(chunk_a, chunk_b)):
                    position = offset + index
                    if byte_a != byte_b:
                        different_bytes += 1
                        if run_start is None:
                            run_start = position
                    elif run_start is not None:
                        finish_range(run_start, position)
                        run_start = None
            offset += max(len(chunk_a), len(chunk_b))
        if run_start is not None:
            finish_range(run_start, offset)
        check_unchanged(a, left)
        check_unchanged(b, right)
    return {
        "different_bytes": different_bytes,
        "range_count": range_count,
        "ranges": ranges,
        "ranges_truncated": range_count > len(ranges),
    }


def identical(left, right):
    """Compare bytes directly; another matching hash would not prove equality."""
    return compare_files(left, right)["different_bytes"] == 0


def scan(paths, algorithm="sha256"):
    report = {
        "algorithm": algorithm,
        "files_scanned": 0,
        "collisions": [],
        "duplicates": [],
        "errors": [],
    }
    seen = {}
    for value in paths:
        path = Path(value)
        try:
            digest, record = hash_file(path, algorithm)
            group = seen.setdefault(digest, [])
            first_differences = None
            for index, previous in enumerate(group):
                differences = compare_files(previous, record)
                if index == 0:
                    first_differences = differences
                if differences["different_bytes"] == 0:
                    report["duplicates"].append({
                        "files": [str(previous.path), str(path)], "digest": digest,
                    })
                    break
            else:
                if group:
                    report["collisions"].append({
                        "files": [str(group[0].path), str(path)], "digest": digest,
                        "differences": first_differences,
                    })
                group.append(record)
            report["files_scanned"] += 1
        except (OSError, ValueError) as error:
            report["errors"].append({"file": str(path), "message": str(error)})
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("files", nargs="+", type=Path)
    parser.add_argument("--algorithm", choices=["md5", "sha1", "sha256"], default="sha256")
    parser.add_argument("--json", action="store_true", help="Print a machine-readable report")
    args = parser.parse_args(argv)
    report = scan(args.files, args.algorithm)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for key, label in (("collisions", "COLLISION"), ("duplicates", "DUPLICATE")):
            for event in report[key]:
                print(f"{label}: {event['files'][0]} and {event['files'][1]}")
                print(f"  {args.algorithm}: {event['digest']}")
                if key == "collisions":
                    differences = event["differences"]
                    print(f"  {differences['different_bytes']} differing bytes in "
                          f"{differences['range_count']} ranges (zero-based offsets):")
                    for span in differences["ranges"]:
                        start, last = span["start"], span["end"] - 1
                        print(f"    bytes {start}-{last} (0x{start:x}-0x{last:x})")
                    if differences["ranges_truncated"]:
                        print(f"    Showing the first {MAX_DIFFERENCE_RANGES} ranges.")
        for error in report["errors"]:
            print(f"ERROR: {error['file']}: {error['message']}")
        print(f"Scanned {report['files_scanned']} files; "
              f"{len(report['collisions'])} collisions; "
              f"{len(report['duplicates'])} duplicates; "
              f"{len(report['errors'])} errors.")
    # An incomplete scan takes precedence over detected collisions.
    return 2 if report["errors"] else 1 if report["collisions"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
