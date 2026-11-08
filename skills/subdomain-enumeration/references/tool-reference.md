# SubEnum-MCP tool reference

Applies to v1.0.0. Discover live schemas and client-specific tool aliases before calling; pass the retained `run_id` explicitly. The executable is `subenum`; the server alias is client-configured and need not match the executable.

| Tool | Input and limits |
| --- | --- |
| `start_run` | `scope_root`, optional `fixture`. Pins one root/mode and creates an empty run. |
| `doctor`, `list_backends` | No arguments; local diagnostics, no enumeration traffic. |
| `discover_subdomains` | `max_records` 1–5,000 (default 100); optional `all_sources` requests all available sources and may increase requests and time; `timeout_seconds`. The cap limits returned names, not passive-source network requests. |
| `generate_candidates` | `max_candidates` 1–5,000; optional `enrich` uses seed words; `seed_offset` >= 0; `seed_limit` 1–2,000. Use returned `seed_snapshot` with `seed_next_offset`; snapshots are process-local and bounded. Requires stored seeds; no DNS queries. |
| `bruteforce_subdomains` | `wordlist: "preset-small"`; `max_words` 1–1,000. The preset currently contains 20 words; canaries add queries when answers appear. |
| `resolve_hosts` | Up to 2,000 explicit `hosts`, or stored `host_offset`/`host_limit`; `max_hosts` 1–2,000 must cover the selected batch. Empty `hosts` selects stored names. Optional `check_wildcard` adds three root-level canary queries and does not rule out nested wildcards. |
| `get_results` | `page` >= 1; `page_size` 1–1,000; optional `status`: `candidate`, `resolved`, `no_answer`, `timeout`, or `dns_error`. |
| `export_results` | `format`: `jsonl` or `csv`; optional safe `folder` name, not a path. Maximum 100,000 rows and 64 MiB. |

Discovery, generation, bruteforce, and resolution accept `timeout_seconds`: 0/omitted defaults to 120; otherwise 1–300. Resolve processes up to 500 hosts per internal batch and persists each batch; timeout applies per batch. For explicit hosts, rejected names are reported in `dropped` and excluded from results/export. The server rejects Unicode and `xn--` names.

## Example: offline fixture

Use a fresh process and separate fixture data directory. `example.com` is a reserved placeholder and cannot be used for real enumeration. Replace `RUN_ID` with the actual returned ID; these are input objects, not executable commands.

1. `start_run`: `{"scope_root":"example.com","fixture":true}`
2. `doctor` and `list_backends`: `{}`
3. `discover_subdomains`: `{"run_id":"RUN_ID","max_records":40,"timeout_seconds":120}`
4. `resolve_hosts`: `{"run_id":"RUN_ID","host_offset":0,"host_limit":20,"max_hosts":20,"timeout_seconds":120}`
5. `get_results`: `{"run_id":"RUN_ID","page":1,"page_size":100}`
6. Optional `export_results`: `{"run_id":"RUN_ID","format":"jsonl","folder":"fixture-review"}`

Follow `host_next_offset` and `total_pages` within the agreed budget. Fetch each results page once and reuse its data; avoid writes while paginating stored hosts because their offsets can shift. Candidate generation uses a separate seed snapshot: reuse its token with the next offset, or restart at 0 if unavailable.

## Recovery

- A wrong root/mode requires an operator restart; keep fixture and real data separate. Do not change stored metadata to bypass mode checks.
- Missing or unverified backends require operator action. Real enumeration requires all pinned backends; currently their supported platform is Linux amd64. The server does not download them.
- Inspect warnings and stored records after interruption or partial timeout; earlier resolve batches may already be saved. Retry only within the agreed budget.
- Exports contain all in-scope stored records, not just filtered results. Use a new managed folder if an export already exists. The returned `result.sha256` is server-reported, not an independent verification.
