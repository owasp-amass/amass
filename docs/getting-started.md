# Getting started with Amass

A short newcomer-friendly guide: install, quick examples, troubleshooting, and how to contribute.

## Install

- macOS (Homebrew)
  ```bash
  brew install amass
  ```
- Linux / Windows (prebuilt)
  1. Download latest release: https://github.com/owasp-amass/amass/releases  
  2. Extract and move the binary into a folder on your PATH.
- From source (Go)
  ```bash
  go install github.com/owasp-amass/amass/v3/...@latest
  ```
  Ensure `$GOPATH/bin` (or your Go bin) is in your PATH.

Verify:
```bash
amass -version
```

## Basic usage examples

- Passive subdomain enumeration:
```bash
amass enum -d example.com -o domains.txt
```

- Active enumeration (includes active probes):
```bash
amass enum -active -d example.com -o active-domains.txt
```

- Simple intel (certificate, whois, etc.):
```bash
amass intel -d example.com
```

- Run using a specific resolver:
```bash
amass enum -d example.com -r 8.8.8.8 -o out.txt
```

- Use a config file (optional) for API keys and tuning:
  - Create a config file (JSON/YAML/TOML depending on your workflow) and reference it:
  ```bash
  amass enum -config ./amass-config.yml -d example.com -o out.txt
  ```
  See official docs/releases for config format and available source integrations.

## Helpful flags
- `-d` domain  
- `-o` output file  
- `-active` enable active techniques  
- `-config` use config file for API keys and source settings  
- `-r` resolver

## Common pitfalls & troubleshooting
- "command not found": ensure the binary is on your PATH (Homebrew or `$GOPATH/bin`).
- Permission errors on Windows: run terminal as Administrator or adjust file permissions.
- Network timeouts or empty results: check firewall, proxy, or DNS resolver settings. Try using `-r` with a public resolver (e.g., 8.8.8.8).
- Very large output: narrow sources or use `-config` to limit data sources; run with `-passive` only if active scanning is not required.
- CI or automated runs: ensure API keys (if used) are stored securely in the environment and referenced by `-config`.

## Minimal example config (illustrative)
Put API keys or provider settings in a config file and pass it with `-config`. Refer to the project docs for exact format and supported providers.
```yaml
# amass-config.yml (example; check official docs for exact keys)
sources:
  - crtsh: true
  - censys: true
censys:
  api_id: YOUR_ID
  api_secret: YOUR_SECRET
```

## How to verify your change (for reviewers)
1. View the rendered file on GitHub to confirm formatting.
2. Locally (optional):
   - `amass -version` should print version information.
   - `amass enum -d example.com -o out.txt` should complete without error; `out.txt` may contain zero or more domains depending on the target.
