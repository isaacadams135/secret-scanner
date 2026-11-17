# secret-scanner

A small CLI that scans files and directories for hardcoded credentials — AWS
keys, GitHub tokens, private key blocks, that kind of thing. I built it because
I almost committed an AWS access key in a school project once, and now I run
something like this before every push. It is a mini gitleaks: one regex rule
catalog, masked output, CI-friendly exit codes, no dependencies beyond the JDK.

## Features

- 9 built-in rules: AWS keys, GitHub tokens, Slack tokens, private key blocks,
  JWTs, Stripe keys, Google API keys, URL credentials, generic secrets
- Skips `.git`, `node_modules`, `target`, `build`, and other junk directories
- Skips binaries (extension list plus a NUL-byte sniff) and files over 5 MB
- Masks every secret in the output — first and last 4 chars at most
- Exit code 1 when findings exist, so CI fails the build on a leaked key
- Single jar, plain JDK 21, no runtime dependencies

## Build

Requires JDK 21+.

```bash
./gradlew build
./gradlew jar
```

On Windows use `gradlew.bat`.

## Usage

```bash
java -jar build/libs/secret-scanner-1.0.0.jar samples/demo
```

Real output against the planted secrets in `samples/demo`:

```text
samples\demo\config\application.properties:3 [MEDIUM] generic-secret pass...t123
samples\demo\config\application.properties:4 [HIGH] url-credentials http...er2@
samples\demo\notes\server-notes.txt:2 [HIGH] private-key ----...----
samples\demo\src\AppConfig.java:6 [HIGH] aws-access-key AKIA...MPLE
samples\demo\src\AppConfig.java:7 [HIGH] github-token ghp_...cdef

5 findings in 3 files (4 high, 1 medium)
```

Exit code was 1. On a clean tree it prints `no secrets found` and exits 0, so
in CI you can just run it as a step and a leak fails the pipeline.

## How it works

It walks each path you give it, skipping dependency, build, and VCS
directories. Text files are read line by line (Latin-1, so weird bytes never
crash it) and every line is matched against the compiled rule catalog. A match
becomes a finding with the secret masked — the full value is never printed, so
the scan output itself cannot leak the key it just found.

## Only use it on stuff you're allowed to

Scan only code and data you own or have permission to scan.

## License

MIT
