# CollisionAttackDetector

Detect observed hash collisions among supplied files using Python 3.10 or later.
No external packages are required.

```bash
python3 detect_collisions.py --algorithm sha1 shattered-1.pdf shattered-2.pdf
python3 detect_collisions.py --algorithm sha256 --json file1.pdf file2.pdf
python3 -m unittest -v
```

SHA-256 is the default. MD5 and SHA-1 modes are provided for investigating older
hashes and known collision examples; do not use them for new security designs.

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
errors. It records one representative pair per new distinct content variant,
rather than every possible pair of matching files.

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
