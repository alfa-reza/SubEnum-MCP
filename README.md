# SubEnum-MCP v1.0.0

An stdio-based MCP (Model Context Protocol) server for enumerating subdomain names under a single operator-configured root. Documentation examples use only the `*.example.com` placeholder under the `example.com` root.

## What it does and its limits

v1.0.0 collects subdomain names through passive discovery, local candidate generation, bounded DNS wordlist brute-force, and DNS A/AAAA/CNAME resolution. The root is read from `SUBENUM_SCOPE_ROOT` when the server starts and cannot be changed through tool input. It must be a registrable domain, not a public suffix. Only names within the `.<root>` label boundary are in scope; the apex/root itself is excluded. For example, `api.example.com` is under `example.com`, while `example.com` is not.

HTTP/HTTPS/TLS are not part of v1.0.0 and remain on the v2.0.0 roadmap. v1.0.0 also does not include port scanning, crawling, takeover, vulnerability checks, AXFR, reverse DNS, DNSSEC walking, monitoring, or features outside subdomain-name enumeration. An empty DNS response is stored as `no_answer`, not treated as an NXDOMAIN conclusion. Real DNS results retain A, AAAA and CNAME values separately from fixture data. A CNAME target is response data, not authorization to scan that target.

Hostnames are lowercased, whitespace is trimmed, and exactly one trailing dot is removed. DNS label boundaries are checked explicitly. Unicode and `xn--` names are rejected because full IDNA/Punycode validation is not provided.

## Backend modes

**Fixture** mode is the default. All tools run in-process, deterministically, without subprocesses or network traffic. Results are marked `fixture=true` in provenance and notes.

**External** mode requires `SUBENUM_EXTERNAL_ENABLE=1`, a valid authorization file with an exact scope match, all three configured binaries matching the pinned release hashes, and a non-placeholder root. Invalid authorization or binary path configuration is refused; binaries that do not match their pins are unverified. If external mode is requested without meeting its requirements, the tool returns an error rather than silently falling back to fixture mode. AlterX generates candidates locally and uses a temporary HOME/config that is deleted after the process finishes.

Subfinder and dnsx require a second opt-in, `SUBENUM_LIVE_ENABLE=1`, before sending requests to third-party passive sources or making DNS queries. Enable live operations only for scopes you are authorized to assess and where the relevant service policies permit those methods. AlterX generates candidates locally and does not send DNS queries.

### Pinned binaries

External backend mode is supported on Linux amd64. The server checks the SHA-256 of each extracted binary against its pinned value before opening the external gate and again before each subprocess call. It does not download or update binaries. The `-duc` flag disables the backends' automatic update check.

| Backend | Version | License | SHA-256 of linux/amd64 archive |
|---|---|---|---|
| Subfinder | v2.17.0 | MIT | `a39c3e5c7a26ef3c430915c4d6cbf7716a00f26769a75e9405aba796142eba37` |
| dnsx | v1.3.1 | MIT | `438b964653056dd51dcfe614b1a16f8bced3cc48a1d27bc07cc6fdf2ef2a9533` |
| AlterX | v0.1.0 | MIT | `ffae5b25138cb27b58900b9b5849e02d0390385fce404252d32e469f2a0e97ac` |

References: [Subfinder release](https://github.com/projectdiscovery/subfinder/releases/tag/v2.17.0), [dnsx release](https://github.com/projectdiscovery/dnsx/releases/tag/v1.3.1), and [AlterX release](https://github.com/projectdiscovery/alterx/releases/tag/v0.1.0). Each release includes its license file.

### Operator authorization

Set `SUBENUM_EXTERNAL_AUTH` to the absolute path of a JSON file containing `authorized`, `operator`, `scope_root`, and `acknowledgement`. The file must be a regular, non-symlink file with mode `0600`, no larger than 1 MiB, and its `scope_root` must match `SUBENUM_SCOPE_ROOT` exactly. The authorization file and its parent directory are part of the operator's trust boundary; a local process running under the same OS account may be able to modify them.

```json
{
  "authorized": true,
  "operator": "operator-team-name",
  "scope_root": "example.com",
  "acknowledgement": "I confirm operator authorization for the configured scope."
}
```

## Build and run

Install the Go toolchain version specified in `go.mod`, then build the server:

```bash
go build -o subenum-mcp ./cmd/subenum-mcp
```

Run the stdio server in the default fixture mode:

```bash
SUBENUM_SCOPE_ROOT=example.com SUBENUM_DATA_DIR=./data ./subenum-mcp
```

Fixture mode sends no network traffic. stdout contains only MCP framing; application logs are written to stderr.

## Environment variables

| Env | Default | Purpose |
|---|---|---|
| `SUBENUM_SCOPE_ROOT` | `example.com` | Literal root; only subdomains that pass the suffix boundary are included, and the apex is excluded. |
| `SUBENUM_DATA_DIR` | `data` (resolved to an absolute path from the working directory) | Storage for runs, exports, and managed work files; must not be reused with a different root. |
| `SUBENUM_EXTERNAL_ENABLE` | `0` | Requests external mode; requires matching-scope authorization and all three pinned binaries. |
| `SUBENUM_LIVE_ENABLE` | `0` | Additional opt-in required before Subfinder or dnsx sends network traffic. Use only when authorized and permitted by applicable service policies. |
| `SUBENUM_EXTERNAL_AUTH` | `<absolute_data_dir>/external-authorization.json` | Operator authorization file whose scope must match exactly; overrides must be absolute paths. |
| `SUBENUM_SUBFINDER_BIN` | empty | Absolute path to the pinned Subfinder binary. |
| `SUBENUM_DNSX_BIN` | empty | Absolute path to the pinned dnsx binary. |
| `SUBENUM_ALTERX_BIN` | empty | Absolute path to the pinned AlterX binary. |

Tool input is structured: there are no parameters for commands, shells, binary paths, custom wordlists, resolvers, or arbitrary CLI flags. `timeout_seconds` defaults to 120 seconds and is capped at 300 seconds. Rate, threads, retries, DNS timeout, and backend options are set by the server.

## MCP tools and hard caps

| Tool | Purpose | Server limits |
|---|---|---|
| `start_run` | Creates a new empty run | Use before switching between fixture and external modes |
| `discover_subdomains` | Candidates from fixtures or passive Subfinder | `max_records` 1–5,000; timeout `0`/empty uses the 120-second default, otherwise 1–300 seconds; Subfinder rate 5 HTTP requests/second, source timeout 10 seconds, max runtime 5 minutes |
| `generate_candidates` | Local permutations of in-scope hostnames in a run | Seeds come from stored in-scope hosts and are processed in bounded batches with `seed_offset`/`seed_limit` (1–2,000 per call); `max_candidates` 1–5,000; AlterX output cap 16 MB. |
| `bruteforce_subdomains` | Checks the registered `preset-small` preset (an empty `wordlist` selects this preset) | `max_words` 1–1,000; external wordlist is created under `<data_dir>/work/` and removed after the call; dnsx uses 10 threads, dnsx `-rl 10` per process (not a global DNS-query cap), one attempt, 3-second query timeout |
| `resolve_hosts` | Resolves in-scope hostnames | Explicit `hosts` input: at most 2,000 elements and 2,000 accepted hosts. Omit `hosts` to resolve stored run hosts in bounded batches with `host_offset`/`host_limit`; `max_hosts` 1–2,000 caps each call. dnsx uses 10 threads, dnsx `-rl 10` per process (not a global DNS-query cap across processes), one attempt, 3-second query timeout. |
| `get_results` | Paginates results by run and filters by status | `page` minimum 1; `page_size` 1–1,000 (default 100); status is limited to the supported enum |
| `list_backends` | Fixture, binary pin, license, and gate status | Read-only diagnostics |
| `doctor` | Local scope/data-directory/gate diagnostics | Does not run a backend or send traffic; creates and removes a unique probe through the already-open data root |
| `export_results` | JSONL/CSV in a managed folder | `jsonl` or `csv` format; maximum 100,000 rows and 64 MiB; CSV is hardened against formula injection |

Discovery, generation, brute-force and resolution responses include at most 20 records as a sample. Use `get_results` for paginated stored results. When `hosts` is omitted, `resolve_hosts` and `generate_candidates` report batch progress (`host_*`/`seed_*` fields) so large runs can be processed without sending all names through model context. Runs reject mixing fixture and external observations; use `start_run` when changing modes. Existing mixed runs cannot accept new observations.

Wildcard DNS detection is not implemented in v1.0.0. A `resolved` result can be a wildcard answer and does not by itself prove that the specific name exists independently; validate important findings separately.

All external output is reclassified against the root; the apex, invalid formats, and non-matching suffixes are discarded. Rejected resolve inputs are recorded as rejected-at-intake and are never sent to a backend, included in pagination, or exported. If all resolve inputs are rejected and there is no existing run, the call fails without creating one; if a selected or latest run exists, the rejection is recorded there. Each run's data is bound to the root used when it was created.

## Storage and exports

Runs are stored in `<data_dir>/runs/<run_id>/`, temporary wordlists in `<data_dir>/work/`, and exports are created only in `<data_dir>/exports/<folder>/`. Arbitrary paths and symlinks are rejected, and file operations use `os.Root` to stay confined to the data root on all platforms; Unix also uses `O_NOFOLLOW` for the final file component and locks data-directory/subdirectory modes to `0700`. On non-Unix platforms, access permissions depend on the platform's ACLs. Do not share the data directory with untrusted local processes running under the same user privileges. Exports include a manifest with relative paths and SHA-256 checksums; results and the manifest are removed if export completion fails. Only in-scope records are included in exports.

## Project license

See `LICENSE`.
Third-party license notices are in [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
