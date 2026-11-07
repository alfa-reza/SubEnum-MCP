package server

import (
	"fmt"
	"reflect"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Register installs all v1.0.0 tools on the MCP server.
func (a *App) Register(srv *mcp.Server) {
	addPortableTool(srv, &mcp.Tool{Name: "start_run", Description: "Create a new empty run for a scope. The first call pins this server process to the requested registrable domain; later calls must use the same root or are rejected. Apex is never in scope."}, a.handleStartRun)
	addPortableTool(srv, &mcp.Tool{
		Name: "discover_subdomains",
		Description: "Passive subdomain discovery for the scope pinned by start_run (optionally pre-pinned with SUBENUM_SCOPE_ROOT). " +
			"Call start_run first. Fixture mode is the default and runs in-process with no network. An explicitly enabled external mode uses the pinned passive-only Subfinder binary; it requires SUBENUM_EXTERNAL_ENABLE=1, matching operator authorization, verified binary hashes (auto-discovered from the managed dir or SUBENUM_SUBFINDER_BIN), and SUBENUM_LIVE_ENABLE=1. " +
			"Structured max_records/timeout_seconds are hard-capped; model-provided flags and roots are not accepted. Apex is never in scope.",
	}, a.handleDiscover)

	addPortableTool(srv, &mcp.Tool{
		Name: "generate_candidates",
		Description: "Generate in-scope candidate subdomains from hosts already stored in the run, using a deterministic " +
			"offline fixture simulation by default, or the pinned AlterX local candidate generator when the external gate is enabled. " +
			"No DNS request is made by this tool; candidate names are scope-filtered and hard-capped.",
	}, a.handleGenerateCandidates)

	addPortableTool(srv, &mcp.Tool{
		Name: "bruteforce_subdomains",
		Description: "Check only a registered preset wordlist against the pinned scope using the fixture backend by default. " +
			"External mode uses the pinned dnsx binary (auto-discovered or SUBENUM_DNSX_BIN) and requires the external gate plus SUBENUM_LIVE_ENABLE=1; the wordlist is server-owned and bounded. " +
			"Absent answers are no_answer, never a conclusion of NXDOMAIN.",
	}, a.handleBruteforce)

	addPortableTool(srv, &mcp.Tool{
		Name: "resolve_hosts",
		Description: "Resolve in-scope subdomains using the fixture backend by default. External mode uses pinned dnsx with a fixed rate, thread count, retry count and query timeout; it requires SUBENUM_LIVE_ENABLE=1. " +
			"For large batches set timeout_seconds explicitly (up to 300) and paginate with host_offset/host_limit. " +
			"Out-of-scope/malformed inputs are rejected before a backend call; empty answers become no_answer, never NXDOMAIN.",
	}, a.handleResolve)

	addPortableTool(srv, &mcp.Tool{
		Name:        "get_results",
		Description: "Paginate in-scope records of a run, optionally filtered by status. Rejected intake entries are excluded from pages; their count is reported separately.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, a.handleGetResults)

	addPortableTool(srv, &mcp.Tool{
		Name:        "list_backends",
		Description: "List offline fixture backends and pinned external backend state. External version/hash/license data comes from the compiled release pins; hashes are verified read-only without executing the binaries.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, a.handleListBackends)

	addPortableTool(srv, &mcp.Tool{
		Name:        "doctor",
		Description: "Local diagnostics: scope configuration, data dir writability, runs, fixture backends and external gates. It uses and removes a unique write probe through the opened managed data root; it hashes configured binaries but never executes them or sends network traffic.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, a.handleDoctor)

	addPortableTool(srv, &mcp.Tool{
		Name: "export_results",
		Description: "Export in-scope records of a run as JSONL or CSV into a managed folder under the data dir. " +
			"Arbitrary destination paths are not accepted. The response includes row count and the sha256 checksum; " +
			"CSV cells are hardened against spreadsheet formula injection.",
	}, a.handleExport)
}

// addPortableTool preserves the SDK's typed validation while expressing
// nullable unions with anyOf, which is accepted by a wider range of MCP clients.
func addPortableTool[In, Out any](srv *mcp.Server, tool *mcp.Tool, handler mcp.ToolHandlerFor[In, Out]) {
	if tool.InputSchema == nil {
		schema, err := jsonschema.ForType(reflect.TypeFor[In](), &jsonschema.ForOptions{})
		if err != nil {
			panic(fmt.Sprintf("infer input schema for %s: %v", tool.Name, err))
		}
		portableSchema(schema, map[*jsonschema.Schema]bool{})
		applyToolInputConstraints(tool.Name, schema)
		tool.InputSchema = schema
	}
	if tool.OutputSchema == nil && reflect.TypeFor[Out]() != reflect.TypeFor[any]() {
		schema, err := jsonschema.ForType(reflect.TypeFor[Out](), &jsonschema.ForOptions{})
		if err != nil {
			panic(fmt.Sprintf("infer output schema for %s: %v", tool.Name, err))
		}
		portableSchema(schema, map[*jsonschema.Schema]bool{})
		tool.OutputSchema = schema
	}
	mcp.AddTool(srv, tool, handler)
}

func applyToolInputConstraints(toolName string, schema *jsonschema.Schema) {
	setBounds := func(name string, min, max float64) {
		property := schema.Properties[name]
		if property == nil {
			panic(fmt.Sprintf("input schema for %s has no %q property", toolName, name))
		}
		property.Minimum = &min
		property.Maximum = &max
	}
	setMinimum := func(name string, min float64) {
		property := schema.Properties[name]
		if property == nil {
			panic(fmt.Sprintf("input schema for %s has no %q property", toolName, name))
		}
		property.Minimum = &min
	}
	setEnum := func(name string, values ...any) {
		property := schema.Properties[name]
		if property == nil {
			panic(fmt.Sprintf("input schema for %s has no %q property", toolName, name))
		}
		property.Enum = values
	}

	if property := schema.Properties["run_id"]; property != nil {
		property.Pattern = `^($|r[0-9]{14}-[a-z0-9]{8})$`
	}
	if property := schema.Properties["timeout_seconds"]; property != nil {
		setBounds("timeout_seconds", 0, CapMaxTimeoutSeconds)
	}
	switch toolName {
	case "discover_subdomains":
		setBounds("max_records", 1, CapMaxRecordsPerCall)
	case "generate_candidates":
		setBounds("max_candidates", 1, CapMaxCandidates)
		setMinimum("seed_offset", 0)
		setBounds("seed_limit", 1, CapMaxSeedHosts)
	case "bruteforce_subdomains":
		setBounds("max_words", 1, CapMaxBruteforceWords)
		setEnum("wordlist", "", "preset-small")
	case "resolve_hosts":
		setBounds("max_hosts", 1, CapMaxResolveHosts)
		setMinimum("host_offset", 0)
		setBounds("host_limit", 1, CapMaxResolveHosts)
		hosts := schema.Properties["hosts"]
		if hosts == nil {
			panic("resolve_hosts input schema has no hosts property")
		}
		maxItems := CapMaxResolveHosts
		hosts.MaxItems = &maxItems
	case "get_results":
		setMinimum("page", 1)
		setBounds("page_size", 1, CapMaxPageSize)
		setEnum("status", "", "candidate", "resolved", "no_answer", "timeout", "dns_error")
	case "export_results":
		setEnum("format", "jsonl", "csv")
		if folder := schema.Properties["folder"]; folder != nil {
			folder.Pattern = `^($|[a-z0-9][a-z0-9_-]{0,63})$`
		}
	}
}

func portableSchema(schema *jsonschema.Schema, seen map[*jsonschema.Schema]bool) {
	if schema == nil || seen[schema] {
		return
	}
	seen[schema] = true
	if len(schema.Types) > 1 {
		types := append([]string(nil), schema.Types...)
		schema.Types = nil
		branches := make([]*jsonschema.Schema, 0, len(types))
		for _, typ := range types {
			branches = append(branches, &jsonschema.Schema{Type: typ})
		}
		if len(schema.AnyOf) == 0 {
			schema.AnyOf = branches
		} else {
			schema.AllOf = append(schema.AllOf, &jsonschema.Schema{AnyOf: schema.AnyOf}, &jsonschema.Schema{AnyOf: branches})
			schema.AnyOf = nil
		}
	}
	for _, child := range schema.Defs {
		portableSchema(child, seen)
	}
	for _, child := range schema.Definitions {
		portableSchema(child, seen)
	}
	for _, child := range schema.Properties {
		portableSchema(child, seen)
	}
	for _, child := range schema.PatternProperties {
		portableSchema(child, seen)
	}
	for _, child := range schema.DependentSchemas {
		portableSchema(child, seen)
	}
	for _, child := range schema.DependencySchemas {
		portableSchema(child, seen)
	}
	for _, child := range []*jsonschema.Schema{schema.Items, schema.AdditionalItems, schema.Contains, schema.UnevaluatedItems, schema.AdditionalProperties, schema.PropertyNames, schema.UnevaluatedProperties, schema.Not, schema.If, schema.Then, schema.Else} {
		portableSchema(child, seen)
	}
	for _, children := range [][]*jsonschema.Schema{schema.ItemsArray, schema.PrefixItems, schema.AllOf, schema.AnyOf, schema.OneOf} {
		for _, child := range children {
			portableSchema(child, seen)
		}
	}
}
