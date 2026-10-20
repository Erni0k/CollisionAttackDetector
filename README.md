# CollisionAttackDetector

Detect observed hash collisions among supplied files using Python 3.10 or later.
No external packages are required.

```bash
python3 detect_collisions.py --algorithm sha1 shattered-1.pdf shattered-2.pdf
python3 detect_collisions.py --algorithm sha256 --json file1.pdf file2.pdf
python3 detect_collisions.py --algorithms md5,sha1 shattered-1.pdf shattered-2.pdf
python3 detect_collisions.py --algorithms md5,sha1,sha256 --json file1.pdf file2.pdf
python3 -m unittest -v
```

SHA-256 is the default. Select multiple algorithms with a comma-separated list
using `--algorithm` or `--algorithms`, or repeat `--algorithm md5 --algorithm sha1`.
Repeated names are checked only once. Existing single-algorithm commands still
work. The hashing pass updates all selected digests from the same chunks, reading
each file once; exact comparisons may require additional reads. Byte comparisons
for the same representative are reused across algorithms for each input file.

MD5 and SHA-1 have known practical collision attacks. Their modes are provided
for investigating older hashes and known examples; do not use them for new
security designs. Fixed-length SHA-2, SHA-3, and BLAKE2 variants guaranteed by
Python's `hashlib` are also supported for comparison. This does not imply they
have known practical collision attacks. Use `--help` to list available names.
Variable-output SHAKE functions are excluded because choosing their output
length requires a separate policy.

The scanner hashes files in 1 MiB chunks and compares matching files byte for
byte. Identical content is reported as a duplicate, not a collision. It retains
metadata for each distinct content variant rather than loading entire files into
memory. Missing, unreadable, nonregular, or detectably changed files are reported
as errors; scanning continues with the remaining inputs. Scan stable files:
metadata checks help detect ordinary changes but do not provide an atomic
snapshot or defend against deliberate filesystem races.

Exit codes: `0` means a completed scan with no collisions, `1` means collisions
were found, and `2` means invalid arguments or an incomplete scan due to errors.
Duplicates alone return `0`. JSON output separates collisions, duplicates, and
errors. Each collision or duplicate event includes its `algorithm`. Results are
independent: a pair can collide under MD5 while having different SHA-1 and
SHA-256 digests. Events are counted per algorithm, so an identical pair produces
one duplicate event for each selected hash. `files_scanned` counts each input
file once, and a read error is reported once per input. Text output includes a
summary for every algorithm when more than one is selected.

JSON lists selected names in `algorithms`. The original `algorithm` field remains
the selected name for single-algorithm runs and is `null` for multi-algorithm
runs. A file contributes results only after all selected checks complete; an
error cannot leave partial results for that file. The scanner records one
representative pair per new distinct content variant per algorithm, rather than
every possible pair of matching files.

Collision reports also identify the byte offsets where that pair differs. Text
output uses zero-based offsets with inclusive ends, in decimal and hexadecimal.
JSON adds a `differences` object containing `different_bytes`, `range_count`,
`ranges` (zero-based `start` inclusive, `end` exclusive), and `ranges_truncated`.
Extra bytes beyond the end of a shorter file count as differences. The scanner
compares the complete files and reports exact totals, while keeping only the
first 20 contiguous ranges to bound report size.

For example, the test MD5 collision pair differs at offsets 19, 45, 59, 83, 109,
and 123. These ranges locate file differences; a hash applies to the entire file,
and the ranges do not establish which blocks were used to construct an attack.

This detects collisions present in the supplied files. It does not establish
malicious intent, monitor live traffic, or detect unsuccessful collision attempts.

Public SHA-1 collision PDFs are available from [SHAttered](https://shattered.io/):
[first PDF](https://shattered.io/static/shattered-1.pdf) and
[second PDF](https://shattered.io/static/shattered-2.pdf).
The offline tests include a published MD5 collision pair and exercise the real
hash functions without requiring downloads.
