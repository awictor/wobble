# wobble

`wobble` runs any shell command N times and tells you whether it is
deterministic. Before comparing the output of each run it masks volatile
tokens (timestamps, uuids, temp paths, pids, pointers, hashes, ip:port pairs,
and so on), so genuine nondeterminism stands out instead of being buried under
expected timestamp and path noise. It is a single zero-dependency Python 3
file that runs the same on Windows (git-bash) and POSIX.

## Install

`wobble` is one file with no dependencies beyond the Python 3.9+ standard
library. Any of these work:

```sh
# Copy the single file anywhere on your PATH
cp wobble.py /usr/local/bin/wobble && chmod +x /usr/local/bin/wobble

# Or run it in place
python wobble.py -n 10 'your command'
```

The `#!/usr/bin/env python3` shebang makes it directly executable on POSIX
(`./wobble.py ...`) and it is pipx-ready if you prefer to package it.

## What the verdicts mean

- `STABLE` - after masking, every run produced identical output and exit code.
- `VOLATILE-BUT-EQUIVALENT` - runs differ only in masked-away tokens
  (timestamps, uuids, ...); the meaningful output is identical.
- `FLAKY` - runs differ in a way masking cannot explain, or exit codes vary.

## Usage

```
wobble [options] COMMAND

  -n, --runs INT            number of runs (default 10)
  --parallel INT            max concurrent runs (default 1)
  --timing-tolerance FLOAT  percent spread over median before timing is
                            "wobbly" (default 50.0)
  --no-mask                 compare raw output, no token normalization
  --json                    emit a structured JSON report
  --fail-on {none,flaky,volatile}  CI gate (default none)
  --diff-lines INT          max lines of the minimal diff to print (default 40)
  --timeout FLOAT           per-run timeout in seconds (default none)
  --no-color                disable ANSI colorization
  -q, --quiet               print only the verdict line
```

### Stable

```sh
$ python wobble.py -n 5 'echo hi'
STABLE  n=5  classes=1  flake_rate=0.00  varied=[]  timing=0.0s±0.0s
```

### Volatile but equivalent

A command that prints a fresh timestamp and uuid every run is not actually
flaky. wobble masks those tokens and tells you so, while still showing the
raw diff that would otherwise have alarmed you:

```sh
$ python wobble.py -n 8 "python tests/helpers/volatile.py"
VOLATILE-BUT-EQUIVALENT  n=8  classes=1  flake_rate=0.00  varied=[]  timing=0.2s±0.0s
--- run #0
+++ run #1
@@ -1,4 +1,4 @@
 request completed
-timestamp: 2026-09-08T13:51:16.276077
-request-id: c06d58fd-6ee6-41a8-9fc4-4a03e450ce16
+timestamp: 2026-09-08T13:51:16.443561
+request-id: e8f26fd1-cd1e-4c92-bb37-249505a79c7c
 done
```

### Flaky

```sh
$ python wobble.py -n 12 "python tests/helpers/flaky.py"
FLAKY  n=12  classes=2  flake_rate=0.33  varied=[stdout]  timing=0.1s±0.0s
--- run #2
+++ run #0
@@ -1 +1 @@
-result: A
+result: B
```

### JSON report

```sh
$ python wobble.py --json -n 5 'echo hi'
```

emits `{verdict, n, parallel, flake_rate, classes[], dimensions, timing, command}`.

## Masking heuristics

Substitutions are applied in this order (most specific first, so a later
broad pattern cannot clobber an earlier match). Use `--no-mask` to skip the
whole table and compare raw output.

| # | Class | Matches | Placeholder |
|---|-------|---------|-------------|
| 1 | ansi | ANSI escape sequences (`\x1b[...m`) | (stripped) |
| 2 | iso_ts | ISO-8601 dates/datetimes, optional `T`, ms, `Z` or `+HH:MM` | `<TS>` |
| 3 | epoch_ms | 13-digit epoch milliseconds | `<EPOCHMS>` |
| 4 | epoch_s | 10-digit epoch seconds | `<EPOCH>` |
| 5 | uuid | canonical 8-4-4-4-12 UUID | `<UUID>` |
| 6 | hexptr | `0x`-prefixed hex pointers | `<PTR>` |
| 7 | sha_hex | bare 7-40 char hex hashes | `<HASH>` |
| 8 | win_path | Windows absolute paths (`C:\...`) | `<PATH>` |
| 9 | tmp_path | `/tmp`, `/var/folders`, `%TEMP%`, `/private/var` paths | `<PATH>` |
| 10 | ip_port | IPv4 with a port | `<IP:PORT>` |
| 11 | ipv4 | bare IPv4 address | `<IP>` |
| 12 | pid | `pid=`, `pid:`, `PID ` followed by digits | `pid=<PID>` |
| 13 | localhost_port | `localhost:PORT` / `127.0.0.1:PORT` | `<HOST:PORT>` |

## Exit codes

| `--fail-on` | Exit 1 when | Otherwise |
|-------------|-------------|-----------|
| `none` (default) | never (pure reporting) | 0 |
| `flaky` | verdict is `FLAKY` | 0 |
| `volatile` | verdict is `FLAKY` or `VOLATILE-BUT-EQUIVALENT` | 0 |

Usage or internal errors exit with code `2`.

## CI recipe

Gate a build on a test suite being deterministic:

```sh
wobble --fail-on flaky -n 30 'pytest tests/'
```

This runs the suite 30 times, masks volatile noise, and fails the job only if
the masked output or exit code actually varies.

## Tests

```sh
python -m unittest discover -s tests -v
```

Covers the masking rules and their ordering, the clustering and verdict logic
against fabricated runs, end-to-end runs of the stable/volatile/flaky helper
scripts, and the exit-code contract.
