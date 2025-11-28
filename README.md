# SUS Scanner CLI

This repository now exposes a simple CLI built into `sus-params.py` that scans URLs for suspicious query
parameters grouped into the same categories defined by the existing `SUS_*` sets.

## Installation

It's easiest to install the single dependency via `requirements.txt`. Inside a virtual environment (recommended),
run:

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

The file currently pins `dnspython>=2.5.0`, which is required for the scanner's DNS lookups.

## Usage

1. Prepare a newline-separated list of URLs in a plaintext file (comments beginning with `#` are ignored).
2. Run the scanner, pointing it at your input file and an output directory:

```powershell
python sus-params-scanner.py -i urls.txt -o scan-output
```

Only resolved hosts are scanned and matches are emitted as host-aware Markdown tables named
`<host>-sus-<category>-urls.md` (colon characters are rewritten to `-`). Each Markdown file begins with
a title such as `# Openredirect Suspicious Parameters - for example.com` so you can read the category
and host at a glance. The table lists `Path`, `Parameter`, and up to two example URLs per parameter
per unique path, which keeps the files concise while showing representative samples.

The tool pre-resolves every unique host (lowercased) via dnspython (falling back to `socket.getaddrinfo`
when dnspython is unavailable) and streams DNS progress in-place, refreshing the same terminal line
before logging the `X out of Y Hosts resolved successfully` summary. URL scanning likewise updates an
inline `Progress: x/y URLs scanned (%)` line before ending with a newline, keeping the console output tidy.
The scanner uses a thread pool for concurrent processing and reads input files as UTF-8 with replacement
for invalid bytes so noisy feeds don’t break the workflow.

## Example markdown output

```markdown
# Openredirect Suspicious Parameters - for example.com

| Path | Parameter | Examples |
| --- | --- | --- |
| /login | redirect_url | https://example.com/login?redirect_url=https://evil.com |
| /login | redirect_url | https://example.com/login?redirect_url=https://malware.example/landing |
```

Each generated file is located under the directory you pass with `-o` (e.g., `scan-output/example.com-sus-openredirect-urls.md`).
