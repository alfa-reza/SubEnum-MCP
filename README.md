# SubEnum-MCP v0.1.0-dev.1

An stdio-based MCP (Model Context Protocol) server for enumerating subdomain names under a single operator-configured root. Examples in this document use `*.example.com` / `example.com` only as placeholders.

## What it does and its limits

This prerelease collects subdomain names through passive discovery, local candidate generation, bounded DNS wordlist brute-force, and DNS A/AAAA/CNAME resolution. The process binds to exactly one registrable-domain root: the first `start_run` call pins it (`scope_root`, for example `"bmkg.go.id"`), and the pin cannot be changed afterwards except by restarting the server. For CI or fixed deployments, `SUBENUM_SCOPE_ROOT` may optionally pre-pin the same root at process start. Only names within the `.<root>` label boundary are in scope; the apex/root itself is excluded.

HTTP/HTTPS/TLS, port scanning, crawling, takeover, vulnerability checks, AXFR, reverse DNS, DNSSEC walking, and monitoring are not included. Candidate estimation and selection of additional DNS record types are not yet available. An empty DNS response is stored as `no_answer`; when the resolver reports NXDOMAIN explicitly it is recorded as `no_answer` with an NXDOMAIN note, and resolver errors are reported as `dns_error`/`timeout`. Real DNS results retain A, AAAA and CNAME values separately. A CNAME target is response data, not authorization to scan that target. If a backend times out mid-batch, any partial output is salvaged and unobserved hosts are recorded as `timeout` with an actionable warning.

Hostnames are lowercased, whitespace is trimmed, and exactly one trailing dot is removed. DNS label boundaries are checked explicitly. Unicode and `xn--` names are rejected because full IDNA/Punycode validation is not provided.

## Backends

**Real mode (default).** Enumeration tools use the hash-verified backends: Subfinder (passive discovery), AlterX (local candidate generation), and dnsx (DNS wordlist checks and resolution). Before execution, each required binary must be present and its SHA-256 must match the compiled release pin; missing or mismatched binaries produce a clear error (no silent fallback). Reserved placeholder roots (such as `example.com`) are refused for real enumeration.

**Fixture/test mode (explicit only).** Pass `fixture: true` to `start_run` (or set `Fixture` in an in-process test config) to run in-process, deterministic mock backends with no subprocesses and no network. Output is clearly labeled as fixture data. This mode exists for tests and local development.

### Pinned binaries

External backend binaries are supported only on Linux amd64; builds for other platforms support fixture mode, not real enumeration. The server verifies the SHA-256 of each binary against its compiled pin before execution. It does not download or update binaries.

Binaries are auto-discovered in the managed directory `~/.local/share/subenum-mcp/bin/` (or `$XDG_DATA_HOME/subenum-mcp/bin/`): `subfinder`, `dnsx`, `alterx`. `SUBENUM_SUBFINDER_BIN`, `SUBENUM_DNSX_BIN` and `SUBENUM_ALTERX_BIN` override with explicit absolute paths.

| Backend | Version | License | SHA-256 of linux/amd64 archive |
|---|---|---|---|
| Subfinder | v2.17.0 | MIT | `a39c3e5c7a26ef3c430915c4d6cbf7716a00f26769a75e9405aba796142eba37` |
| dnsx | v1.3.1 | MIT | `438b964653056dd51dcfe614b1a16f8bced3cc48a1d27bc07cc6fdf2ef2a9533` |
| AlterX | v0.1.0 | MIT | `ffae5b25138cb27b58900b9b5849e02d0390385fce404252d32e469f2a0e97ac` |

References: [Subfinder release](https://github.com/projectdiscovery/subfinder/releases/tag/v2.17.0), [dnsx release](https://github.com/projectdiscovery/dnsx/releases/tag/v1.3.1), and [AlterX release](https://github.com/projectdiscovery/alterx/releases/tag/v0.1.0). Each release includes its license file.

## Build and run

Install the Go toolchain version specified in `go.mod`, then build the server:

```bash
go build -o subenum ./cmd/subenum
```

Run the stdio server:

```bash
./subenum
```

The agent pins the scope through tool input: `start_run` with `scope_root` (for example `"bmkg.go.id"`). A minimal MCP client configuration is:

```json
{
  "mcp": {
    "servers": {
      "subenum-mcp": {
        "type": "local",
        "command": ["/path/to/subenum"]
      }
    }
  }
}
```

stdout contains only MCP framing; application logs are written to stderr. Only enumerate scopes you are authorized to assess.

## Environment variables

Everything is optional; defaults are chosen so the MCP client needs no `environment` block.

| Env | Default | Purpose |
|---|---|---|
| `SUBENUM_SCOPE_ROOT` | unset | Optional pre-pin of the scope at process start. Normally not set: the agent pins via `start_run` `scope_root`. Only subdomains that pass the suffix boundary are included, and the apex is excluded. |
| `SUBENUM_DATA_DIR` | `~/.local/share/subenum-mcp/data/<scope>` (XDG: `$XDG_DATA_HOME/subenum-mcp/data/<scope>`) | Storage for runs, exports, and managed work files. An explicit override is used directly and must not be reused with a different root. |
| `SUBENUM_SUBFINDER_BIN` | auto-discover `<managed_dir>/bin/subfinder` | Absolute path override for the pinned Subfinder binary. |
| `SUBENUM_DNSX_BIN` | auto-discover `<managed_dir>/bin/dnsx` | Absolute path override for the pinned dnsx binary. |
| `SUBENUM_ALTERX_BIN` | auto-discover `<managed_dir>/bin/alterx` | Absolute path override for the pinned AlterX binary. |
| `SUBENUM_DNSX_RESOLVERS` | nameservers from `/etc/resolv.conf` | Optional comma-separated dnsx resolver list (IPv4[:port], optional `tcp:`/`udp:` scheme). Falls back to dnsx's built-in resolvers if none are readable. Useful when public UDP DNS is blocked and only a local stub resolver (e.g. `127.0.0.53`) is reachable. |

Tool input is structured: there are no parameters for commands, shells, binary paths, custom wordlists, resolvers, or arbitrary CLI flags. `timeout_seconds` defaults to 120 seconds and is capped at 300 seconds. Backend rate, threads, retries, DNS timeout, and options are set by the server.

## MCP tools and hard caps

| Tool | Purpose | Server limits |
|---|---|---|
| `start_run` | Creates a new empty run; the first call pins the process to `scope_root`. Later calls must use the same root. | Requires `scope_root` on the first call; `fixture:true` selects explicit labeled test mode. |
| `discover_subdomains` | Passive subdomain discovery (Subfinder) | `max_records` 1–5,000 (default 100); optional `all_sources` requests all available sources, potentially increasing requests and duration; timeout `0`/empty uses the 120-second default, otherwise 1–300 seconds. |
| `generate_candidates` | Local permutations of in-scope hostnames (AlterX) | Seeds from stored in-scope hosts, bounded by `seed_offset`/`seed_limit` (1–2,000 per call); use the returned `seed_snapshot` with `seed_next_offset`; `max_candidates` 1–5,000; optional `enrich` derives extra words from seeds. |
| `bruteforce_subdomains` | Checks the registered `preset-small` preset (dnsx) | `max_words` 1–1,000; only registered presets accepted; external wordlist is created under `<data_dir>/work/` and removed after the call. |
| `resolve_hosts` | Resolves in-scope hostnames (dnsx) | Explicit `hosts` input: at most 2,000 elements and 2,000 accepted hosts. Omit `hosts` to resolve stored run hosts in batches with `host_offset`/`host_limit`; `max_hosts` 1–2,000 caps each call. Set `timeout_seconds` (up to 300) for large batches; partial results are kept on timeout. |
| `get_results` | Paginates results by run and filters by status | `page` minimum 1; `page_size` 1–1,000 (default 100); status limited to the supported enum. |
| `list_backends` | Backend state and binary verification | Read-only diagnostics; verifies hashes read-only without executing binaries. |
| `doctor` | Local scope/data/binary diagnostics | Does not execute enumeration binaries or send traffic. |
| `export_results` | JSONL/CSV in a managed folder | `jsonl` or `csv`; maximum 100,000 rows and 64 MiB; CSV hardened against formula injection. |

Discovery, generation, brute-force and resolution responses include at most 20 records as a sample. Use `get_results` for paginated stored results. Discovery reports `cap_reached` when the number of returned unique names equals the requested cap; it does not establish whether any results were actually truncated. The discovery cap limits returned names, not the number of passive-source network requests. Passive sources may be incomplete even below the cap. For candidate generation, pass both `seed_snapshot` and `seed_next_offset` on subsequent calls; the snapshot freezes the original seeds across run changes. Up to eight snapshots are kept per server process; older snapshots are evicted and all are lost on restart. An unavailable snapshot requires starting again at offset 0. `host_*`/`seed_*` fields report batch position, not asynchronous progress notifications. `status_counts` and `warning` describe the latest call; sampled stored records retain cumulative historical status.

`resolve_hosts` processes requests in internal batches of at most 500 hosts per dnsx invocation, persisting results after every batch and emitting an MCP progress notification between batches; `timeout_seconds` applies per batch. A backend call that hits its time limit marks unobserved hosts `timeout` and, when every requested host already returned an observation, annotates records with a call-limit note surfaced in the response `warning`.

`list_backends` reports the effective server-owned operational parameters (rate limits, threads, retry, per-query timeout, resolvers, record types) under `settings`, so results can be interpreted and reproduced by hand.

`bruteforce_subdomains` probes three random-label wildcard canaries whenever the preset produced any DNS answer. `wildcard_check` is `suspected` if any canary answers, `no_canary_answer` if the probe returned no positive answer, `unknown` if the probe failed, and `not_checked` if no probe ran (including fixture mode). `no_canary_answer` does not prove absence of wildcard DNS or exclude an unreported resolver failure. A suspected wildcard adds a note and warning to resolved results.

Runs persist their fixture/real mode at creation. Accessing a run from the other mode is rejected. Legacy runs created before mode persistence adopt this process's mode only while empty; any non-empty legacy run is validated against the recorded provenance on every access. Use a separate data directory for fixture tests and real work. Backend license names are reviewed release metadata, not runtime license-file checks; `license_verified` is false because the server does not perform those checks.

`resolve_hosts` optionally accepts `check_wildcard: true`, adding three random-label DNS probes directly below the scope root. The response reports the same `wildcard_check` statuses; fixture mode reports `not_checked`. This root-only check does not detect every nested wildcard and does not classify individual answers. A `resolved` result can still be a wildcard answer and does not by itself prove that the specific name exists independently; validate important findings separately. Explicitly authorize the additional DNS queries before enabling the check.

All external output is reclassified against the root; the apex, invalid formats, and non-matching suffixes are discarded. Rejected resolve inputs are recorded as rejected-at-intake and are never sent to a backend, included in pagination, or exported. Each run's data is bound to the root used when it was created.

## Storage and exports

Runs are stored in `<data_dir>/runs/<run_id>/`, temporary wordlists in `<data_dir>/work/`, and exports are created only in `<data_dir>/exports/<folder>/`. Arbitrary paths and symlinks are rejected, and file operations use `os.Root` to stay confined to the data root. Exports include a manifest with relative paths and SHA-256 checksums. Only in-scope records are included in exports.

## Project license

See `LICENSE`.
Third-party license notices are in [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
