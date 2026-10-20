#!/usr/bin/env python3
"""Find observed file hash collisions using bounded-memory, exact comparison."""

import argparse
import hashlib
import json
import os
import stat
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path

CHUNK_SIZE = 1024 * 1024


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


def identical(left, right):
    """Compare bytes directly; another matching hash would not prove equality."""
    with ExitStack() as stack:
        a = stack.enter_context(left.path.open("rb"))
        b = stack.enter_context(right.path.open("rb"))
        check_unchanged(a, left)
        check_unchanged(b, right)
        while True:
            chunk_a, chunk_b = a.read(CHUNK_SIZE), b.read(CHUNK_SIZE)
            if chunk_a != chunk_b:
                equal = False
                break
            if not chunk_a:
                equal = True
                break
        check_unchanged(a, left)
        check_unchanged(b, right)
        return equal


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
            for previous in group:
                if identical(previous, record):
                    report["duplicates"].append({
                        "files": [str(previous.path), str(path)], "digest": digest,
                    })
                    break
            else:
                if group:
                    report["collisions"].append({
                        "files": [str(group[0].path), str(path)], "digest": digest,
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
