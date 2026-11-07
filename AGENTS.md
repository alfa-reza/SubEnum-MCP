# Working in this repository

- Keep changes simple and focused on the requested behavior (KISS).
- Do not add features or abstractions for hypothetical future needs (YAGNI).
- Reuse existing logic when it removes meaningful duplication; avoid abstractions that obscure the code (DRY).
- Preserve the configured scope boundary and distinguish fixture data, candidates, and observed DNS results.
- Treat backend output as untrusted input. Do not accept raw commands, flags, or arbitrary paths from MCP clients.
- Add regression tests for behavioral fixes and run the relevant checks before reporting completion.
- Keep documentation and third-party notices accurate; preserve required license text and attribution.
- Respect existing user changes and never scan a domain without authorization.
