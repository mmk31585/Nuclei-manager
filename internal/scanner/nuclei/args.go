package nuclei

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Options is the fully validated, already-resolved input for one nuclei run.
//
// Every optional field is only translated into a nuclei flag when it is set.
// A zero value means "not configured" and leaves the nuclei default in place,
// so a scan without any configuration behaves like `nuclei -list file -jsonl`.
type Options struct {
	TargetsFile   string   // absolute path
	ExcludeHosts  []string // hosts, IPs or CIDRs
	TemplatePaths []string // absolute directories
	TemplateIDs   []string
	ExcludeIDs    []string // template IDs to exclude (-exclude-id)
	Tags          []string
	ExcludeTags   []string
	Severities    []string
	ExcludeSeverity []string // severities to exclude
	Protocols     []string
	ExcludeProtocols []string // protocol types to exclude
	Authors       []string // template authors to run
	RateLimit     int
	Concurrency   int
	BulkSize      int
	TimeoutSec    int
	Retries       int
	MaxHostError  int
	// NoInteractsh disables interactsh callbacks.
	NoInteractsh bool
	// Custom headers passed with every request (e.g. "Authorization: Bearer xxx").
	CustomHeaders []string
	// Cookies sent with every request (e.g. "session=abc123").
	Cookies []string
	// BasicAuth username:password for authenticated scans.
	BasicAuth string
	// Output formats: "jsonl" (default), "json", "sarif".
	OutputFormat string
	// FollowRedirects enables following redirects for HTTP templates.
	FollowRedirects bool
	// MaxRedirects max number of redirects to follow (default 10).
	MaxRedirects int
	// SystemResolvers uses system DNS resolving as error fallback.
	SystemResolvers bool
	// StopAtFirstMatch stops after the first match per template.
	StopAtFirstMatch bool
	// NoHttpx disables httpx probing for non-URL input.
	NoHttpx bool
	// TemplateCondition complex expression to filter templates (e.g. "contains(id,'xss')").
	TemplateCondition string

	// --- Input Formats ---
	// InputMode: "list" (default), "burp", "jsonl", "yaml", "openapi", "swagger"
	InputMode string
	// RequiredOnly uses only required fields in input format when generating requests.
	RequiredOnly bool
	// SkipFormatValidation skips format validation (like missing vars) when parsing input file.
	SkipFormatValidation bool
	// ScanAllIPs scans all IPs associated with DNS record.
	ScanAllIPs bool
	// IPVersion to scan (4, 6).
	IPVersion []string

	// --- Authentication ---
	// SecretFile path to config file containing secrets for authenticated scans.
	SecretFile []string
	// PrefetchSecrets prefetches secrets from the secrets file.
	PrefetchSecrets bool

	// --- Workflows ---
	// Workflows list of workflow or workflow directory to run.
	Workflows []string
	// WorkflowURLs list of workflow URLs to run.
	WorkflowURLs []string

	// --- Template filters ---
	// IncludeTemplates path to template file or directory to be executed even if excluded.
	IncludeTemplates []string
	// ExcludeTemplates path to template file or directory to exclude.
	ExcludeTemplates []string
	// ExcludeTemplateIDs template IDs to exclude (-exclude-id).
	ExcludeTemplateIDs []string
	// IncludeTags tags to be executed even if excluded by default or config.
	IncludeTags []string

	// --- Output enhancements ---
	// StoreResponse stores all request/response passed through nuclei to output directory.
	StoreResponse bool
	// StoreResponseDir custom directory to store responses (default "output").
	StoreResponseDir string
	// OmitRaw omits request/response pairs in JSON/JSONL/Markdown outputs.
	OmitRaw bool
	// OmitTemplate omits encoded template in JSON/JSONL output.
	OmitTemplate bool
	// NoMeta disables printing result metadata in CLI output.
	NoMeta bool
	// Timestamp enables printing timestamp in CLI output.
	Timestamp bool
	// MatcherStatus displays match failure status.
	MatcherStatus bool
	// SarifExport file to export results in SARIF format.
	SarifExport string
	// MarkdownExport directory to export results in markdown format.
	MarkdownExport string
	// JSONExport file to export results in JSON format.
	JSONExport string
	// JSONLExport file to export results in JSONL format.
	JSONLExport string
	// ReportDB nuclei reporting database.
	ReportDB string
	// ReportConfig nuclei reporting module configuration file.
	ReportConfig string
	// Redact redact given list of keys from query parameter, request header and body.
	Redact []string

	// --- Scan Strategy ---
	// ScanStrategy: "auto", "template-spray", "host-spray"
	ScanStrategy string

	// --- Rate Limiting / Performance ---
	RateLimitMinute int
	RateLimitDuration string
	HeadlessBulkSize int
	HeadlessConcurrency int
	JSConcurrency int
	PayloadConcurrency int
	ProbeConcurrency int
	ResponseSizeRead int
	ResponseSizeSave int
	LeaveDefaultPorts bool
	NoMHE bool
	TrackError []string
	Project bool
	ProjectPath string
	Stream bool

	// --- Headless ---
	Headless bool
	PageTimeout int
	ShowBrowser bool
	HeadlessOptions []string
	SystemChrome bool
	ListHeadlessActions bool

	// --- Interactsh/OAST ---
	InteractshServer string
	InteractshToken string
	InteractionsCacheSize int
	InteractionsEviction int
	InteractionsPollDuration int
	InteractionsCooldownPeriod int
}

var (
	reTag        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
	reID         = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.*-]{0,127}$`)
	reAuthor     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
	reHost       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,254}$`)
)

var allowedSeverity = map[string]bool{"info": true, "low": true, "medium": true, "high": true, "critical": true}

// code and headless can run commands or drive a browser; file reads local files. Never allowed.
var allowedProtocol = map[string]bool{
	"dns": true, "http": true, "tcp": true, "ssl": true,
	"websocket": true, "whois": true, "javascript": true, "workflow": true,
}

// forbiddenFlags are nuclei flags the service must never pass, even indirectly.
var forbiddenFlags = []string{
	"-code", "-headless", "-dast", "-fuzz", "-lfa", "-allow-local-file-access",
	"-env-vars", "-update-templates", "-update", "-reset", "-sandbox",
}

func addList(args []string, flag string, vals []string, ok func(string) bool) ([]string, error) {
	if len(vals) == 0 {
		return args, nil
	}
	for _, v := range vals {
		if !ok(v) {
			return nil, fmt.Errorf("invalid value %q for %s", v, flag)
		}
	}
	return append(args, flag, strings.Join(vals, ",")), nil
}

func BuildArgs(o Options) ([]string, error) {
	if !filepath.IsAbs(o.TargetsFile) {
		return nil, errors.New("targets file must be an absolute path")
	}
	args := []string{
		"-list", o.TargetsFile,
		"-jsonl", "-no-color", "-disable-update-check",
		"-stats", "-stats-interval", "15",
	}
	numbers := []struct {
		name     string
		v        int
		min, max int
	}{
		{"rate-limit", o.RateLimit, 1, 10000},
		{"concurrency", o.Concurrency, 1, 500},
		{"bulk-size", o.BulkSize, 1, 500},
		{"timeout", o.TimeoutSec, 1, 300},
		{"retries", o.Retries, 0, 10},
		{"max-host-error", o.MaxHostError, 1, 1000},
	}
	for _, n := range numbers {
		if n.v == 0 {
			continue // not configured: keep the nuclei default
		}
		if n.v < n.min || n.v > n.max {
			return nil, fmt.Errorf("%s must be between %d and %d", n.name, n.min, n.max)
		}
		args = append(args, "-"+n.name, strconv.Itoa(n.v))
	}
	if o.NoInteractsh {
		args = append(args, "-no-interactsh")
	}

	// Authenticated scan flags
	for _, h := range o.CustomHeaders {
		args = append(args, "-header", h)
	}
	for _, c := range o.Cookies {
		args = append(args, "-cookies", c)
	}
	if o.BasicAuth != "" {
		args = append(args, "-basic-auth", o.BasicAuth)
	}

	// Output format (default jsonl is already in the base args)
	switch o.OutputFormat {
	case "json":
		args = append(args, "-json")
	case "sarif":
		args = append(args, "-sarif")
	case "", "jsonl":
		// jsonl already in base args
	default:
		return nil, fmt.Errorf("invalid output format %q", o.OutputFormat)
	}

	// Scan behavior flags
	if o.FollowRedirects {
		args = append(args, "-follow-redirects")
	}
	if o.MaxRedirects > 0 {
		if o.MaxRedirects > 50 {
			return nil, fmt.Errorf("max-redirects must be between 1 and 50")
		}
		args = append(args, "-max-redirects", strconv.Itoa(o.MaxRedirects))
	}
	if o.SystemResolvers {
		args = append(args, "-system-resolvers")
	}
	if o.StopAtFirstMatch {
		args = append(args, "-stop-at-first-match")
	}
	if o.NoHttpx {
		args = append(args, "-no-httpx")
	}
	if o.TemplateCondition != "" {
		args = append(args, "-template-condition", o.TemplateCondition)
	}

	// Input format
	if o.InputMode != "" {
		args = append(args, "-input-mode", o.InputMode)
	}
	if o.RequiredOnly {
		args = append(args, "-required-only")
	}
	if o.SkipFormatValidation {
		args = append(args, "-skip-format-validation")
	}
	if o.ScanAllIPs {
		args = append(args, "-scan-all-ips")
	}
	if len(o.IPVersion) > 0 {
		args = append(args, "-ip-version", strings.Join(o.IPVersion, ","))
	}

	// Authentication
	for _, sf := range o.SecretFile {
		args = append(args, "-secret-file", sf)
	}
	if o.PrefetchSecrets {
		args = append(args, "-prefetch-secrets")
	}

	// Workflows
	if len(o.Workflows) > 0 {
		args = append(args, "-workflows", strings.Join(o.Workflows, ","))
	}
	if len(o.WorkflowURLs) > 0 {
		args = append(args, "-workflow-url", strings.Join(o.WorkflowURLs, ","))
	}

	// Template filters
	if len(o.IncludeTemplates) > 0 {
		args = append(args, "-include-templates", strings.Join(o.IncludeTemplates, ","))
	}
	if len(o.ExcludeTemplateIDs) > 0 {
		args = append(args, "-exclude-id", strings.Join(o.ExcludeTemplateIDs, ","))
	}

	// Output enhancements
	if o.StoreResponse {
		args = append(args, "-store-resp")
	}
	if o.StoreResponseDir != "" {
		args = append(args, "-store-resp-dir", o.StoreResponseDir)
	}
	if o.OmitRaw {
		args = append(args, "-omit-raw")
	}
	if o.OmitTemplate {
		args = append(args, "-omit-template")
	}
	if o.NoMeta {
		args = append(args, "-no-meta")
	}
	if o.Timestamp {
		args = append(args, "-timestamp")
	}
	if o.MatcherStatus {
		args = append(args, "-matcher-status")
	}
	if o.SarifExport != "" {
		args = append(args, "-sarif-export", o.SarifExport)
	}
	if o.MarkdownExport != "" {
		args = append(args, "-markdown-export", o.MarkdownExport)
	}
	if o.JSONExport != "" {
		args = append(args, "-json-export", o.JSONExport)
	}
	if o.JSONLExport != "" {
		args = append(args, "-jsonl-export", o.JSONLExport)
	}
	if o.ReportDB != "" {
		args = append(args, "-report-db", o.ReportDB)
	}
	if o.ReportConfig != "" {
		args = append(args, "-report-config", o.ReportConfig)
	}
	if len(o.Redact) > 0 {
		args = append(args, "-redact", strings.Join(o.Redact, ","))
	}

	// Scan Strategy
	if o.ScanStrategy != "" {
		args = append(args, "-scan-strategy", o.ScanStrategy)
	}

	// Rate Limiting / Performance
	if o.RateLimitMinute > 0 {
		args = append(args, "-rate-limit-minute", strconv.Itoa(o.RateLimitMinute))
	}
	if o.RateLimitDuration != "" {
		args = append(args, "-rate-limit-duration", o.RateLimitDuration)
	}
	if o.HeadlessBulkSize > 0 {
		args = append(args, "-headless-bulk-size", strconv.Itoa(o.HeadlessBulkSize))
	}
	if o.HeadlessConcurrency > 0 {
		args = append(args, "-headless-concurrency", strconv.Itoa(o.HeadlessConcurrency))
	}
	if o.JSConcurrency > 0 {
		args = append(args, "-js-concurrency", strconv.Itoa(o.JSConcurrency))
	}
	if o.PayloadConcurrency > 0 {
		args = append(args, "-payload-concurrency", strconv.Itoa(o.PayloadConcurrency))
	}
	if o.ProbeConcurrency > 0 {
		args = append(args, "-probe-concurrency", strconv.Itoa(o.ProbeConcurrency))
	}
	if o.ResponseSizeRead > 0 {
		args = append(args, "-response-size-read", strconv.Itoa(o.ResponseSizeRead))
	}
	if o.ResponseSizeSave > 0 {
		args = append(args, "-response-size-save", strconv.Itoa(o.ResponseSizeSave))
	}
	if o.LeaveDefaultPorts {
		args = append(args, "-leave-default-ports")
	}
	if o.NoMHE {
		args = append(args, "-no-mhe")
	}
	if len(o.TrackError) > 0 {
		args = append(args, "-track-error", strings.Join(o.TrackError, ","))
	}
	if o.Project {
		args = append(args, "-project")
	}
	if o.ProjectPath != "" {
		args = append(args, "-project-path", o.ProjectPath)
	}
	if o.Stream {
		args = append(args, "-stream")
	}

	// Headless
	if o.Headless {
		args = append(args, "-headless")
	}
	if o.PageTimeout > 0 {
		args = append(args, "-page-timeout", strconv.Itoa(o.PageTimeout))
	}
	if o.ShowBrowser {
		args = append(args, "-show-browser")
	}
	if len(o.HeadlessOptions) > 0 {
		args = append(args, "-headless-options", strings.Join(o.HeadlessOptions, ","))
	}
	if o.SystemChrome {
		args = append(args, "-system-chrome")
	}
	if o.ListHeadlessActions {
		args = append(args, "-list-headless-action")
	}

	// Interactsh/OAST
	if o.InteractshServer != "" {
		args = append(args, "-interactsh-server", o.InteractshServer)
	}
	if o.InteractshToken != "" {
		args = append(args, "-interactsh-token", o.InteractshToken)
	}
	if o.InteractionsCacheSize > 0 {
		args = append(args, "-interactions-cache-size", strconv.Itoa(o.InteractionsCacheSize))
	}
	if o.InteractionsEviction > 0 {
		args = append(args, "-interactions-eviction", strconv.Itoa(o.InteractionsEviction))
	}
	if o.InteractionsPollDuration > 0 {
		args = append(args, "-interactions-poll-duration", strconv.Itoa(o.InteractionsPollDuration))
	}
	if o.InteractionsCooldownPeriod > 0 {
		args = append(args, "-interactions-cooldown-period", strconv.Itoa(o.InteractionsCooldownPeriod))
	}

	var err error
	lists := []struct {
		flag string
		vals []string
		ok   func(string) bool
	}{
		{"-exclude-hosts", o.ExcludeHosts, reHost.MatchString},
		{"-templates", o.TemplatePaths, func(p string) bool {
			return filepath.IsAbs(p) && !strings.ContainsAny(p, ",\r\n")
		}},
		{"-template-id", o.TemplateIDs, reID.MatchString},
		{"-exclude-id", o.ExcludeTemplateIDs, reID.MatchString},
		{"-tags", o.Tags, reTag.MatchString},
		{"-include-tags", o.IncludeTags, reTag.MatchString},
		{"-exclude-tags", o.ExcludeTags, reTag.MatchString},
		{"-severity", o.Severities, func(s string) bool { return allowedSeverity[s] }},
		{"-exclude-severity", o.ExcludeSeverity, func(s string) bool { return allowedSeverity[s] }},
		{"-pt", o.Protocols, func(s string) bool { return allowedProtocol[s] }},
		{"-exclude-type", o.ExcludeProtocols, func(s string) bool { return allowedProtocol[s] }},
		{"-author", o.Authors, reAuthor.MatchString},
	}
	for _, l := range lists {
		if args, err = addList(args, l.flag, l.vals, l.ok); err != nil {
			return nil, err
		}
	}

	// Defense in depth: none of the forbidden flags may ever appear.
	joined := strings.Join(args, " ")
	for _, f := range forbiddenFlags {
		if strings.Contains(joined, f+" ") || strings.HasSuffix(joined, f) {
			return nil, fmt.Errorf("forbidden nuclei flag %s", f)
		}
	}
	return args, nil
}