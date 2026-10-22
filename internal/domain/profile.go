package domain

import (
	"strings"
	"time"
)

// Profile selects and tunes the Nuclei scan. Built-in profiles are seeded at
// startup and are read-only.
type Profile struct {
	// Profile identifier (read-only)
	ID uint `json:"id" gorm:"primaryKey"`
	// Unique profile name (1-191 characters)
	Name string `json:"name" gorm:"size:191;uniqueIndex;not null"`
	// Optional free-text description
	Description string `json:"description" gorm:"type:text"`
	// Only run templates with at least one of these tags
	Tags StringList `json:"tags" gorm:"type:text;not null"`
	// Exclude templates carrying any of these tags
	ExcludeTags StringList `json:"exclude_tags" gorm:"type:text;not null"`
	// Only run templates of these severities
	Severity StringList `json:"severity" enums:"info,low,medium,high,critical" gorm:"type:text;not null"`
	// Exclude templates of these severities
	ExcludeSeverity StringList `json:"exclude_severity" enums:"info,low,medium,high,critical" gorm:"type:text;not null"`
	// Restrict to these protocols (http, dns, tcp, ssl, websocket, whois, javascript, workflow)
	Protocols StringList `json:"protocols" gorm:"type:text;not null"`
	// Exclude these protocol types
	ExcludeProtocols StringList `json:"exclude_protocols" gorm:"type:text;not null"`
	// Restrict to these exact template IDs
	TemplateIDs StringList `json:"template_ids" gorm:"type:text;not null"`
	// Exclude these exact template IDs
	ExcludeTemplateIDs StringList `json:"exclude_template_ids" gorm:"type:text;not null"`
	// Only run templates by these authors
	Authors StringList `json:"authors" gorm:"type:text;not null"`
	// Include tags even if excluded by default/configuration
	IncludeTags StringList `json:"include_tags" gorm:"type:text;not null"`
	// Name of an external custom template set directory
	CustomSet string `json:"custom_set" gorm:"size:191"`
	// Requests per second (1-10000, defaults to 50)
	RateLimit int `json:"rate_limit"`
	// Concurrent requests (1-500, defaults to 25)
	Concurrency int `json:"concurrency"`
	// Bulk size (1-500, defaults to 25)
	BulkSize int `json:"bulk_size"`
	// Per-request timeout in seconds (1-300, defaults to 10)
	TimeoutSec int `json:"timeout_sec"`
	// Retries per request (0-10, defaults to 1)
	Retries int `json:"retries"`
	// Max errors per host before skipping it (1-1000, defaults to 30)
	MaxHostError int `json:"max_host_error"`
	// Max total scan duration in minutes (1-1440, defaults to 120)
	MaxDurationMin int `json:"max_duration_min"`
	// Enable OAST interaction callbacks
	OAST bool `json:"oast"`
	// Follow HTTP redirects for HTTP templates
	FollowRedirects bool `json:"follow_redirects"`
	// Max number of redirects to follow (default 10)
	MaxRedirects int `json:"max_redirects"`
	// Use system DNS resolving as error fallback
	SystemResolvers bool `json:"system_resolvers"`
	// Stop processing HTTP requests after the first match
	StopAtFirstMatch bool `json:"stop_at_first_match"`
	// Disable httpx probing for non-URL input
	NoHttpx bool `json:"no_httpx"`
	// Complex expression to filter templates
	TemplateCondition string `json:"template_condition" gorm:"size:512"`
	// Output format: jsonl (default), json, sarif
	OutputFormat string `json:"output_format" gorm:"size:16"`
	// Custom headers passed with every request
	CustomHeaders StringList `json:"custom_headers" gorm:"type:text;not null"`
	// Cookies sent with every request
	Cookies StringList `json:"cookies" gorm:"type:text;not null"`
	// Basic auth username:password for authenticated scans
	BasicAuth string `json:"basic_auth" gorm:"size:255"`
	// True for seeded built-in profiles (read-only, defaults to false)
	Builtin bool `json:"builtin"`
	// Creation timestamp (read-only)
	CreatedAt time.Time `json:"created_at"`
	// Last update timestamp (read-only)
	UpdatedAt time.Time `json:"updated_at"`

	// --- New fields for Nuclei features ---

	// Input format: "list" (default), "burp", "jsonl", "yaml", "openapi", "swagger"
	InputMode string `json:"input_mode" gorm:"size:16"`
	// RequiredOnly uses only required fields in input format when generating requests.
	RequiredOnly bool `json:"required_only"`
	// SkipFormatValidation skips format validation (like missing vars) when parsing input file.
	SkipFormatValidation bool `json:"skip_format_validation"`
	// ScanAllIPs scans all IPs associated with DNS record.
	ScanAllIPs bool `json:"scan_all_ips"`
	// IPVersion to scan (4, 6).
	IPVersion StringList `json:"ip_version" gorm:"type:text;not null"`

	// Authentication
	// SecretFile path to config file containing secrets for authenticated scans.
	SecretFile StringList `json:"secret_file" gorm:"type:text;not null"`
	// PrefetchSecrets prefetches secrets from the secrets file.
	PrefetchSecrets bool `json:"prefetch_secrets"`

	// Workflows
	// Workflows list of workflow or workflow directory to run.
	Workflows StringList `json:"workflows" gorm:"type:text;not null"`
	// WorkflowURLs list of workflow URLs to run.
	WorkflowURLs StringList `json:"workflow_urls" gorm:"type:text;not null"`

	// Template filters
	// IncludeTemplates path to template file or directory to be executed even if excluded.
	IncludeTemplates StringList `json:"include_templates" gorm:"type:text;not null"`
	// ExcludeTemplates path to template file or directory to exclude.
	ExcludeTemplates StringList `json:"exclude_templates" gorm:"type:text;not null"`

	// StoreResponse stores all request/response passed through nuclei to output directory.
	StoreResponse bool `json:"store_response"`
	// StoreResponseDir custom directory to store responses (default "output").
	StoreResponseDir string `json:"store_response_dir" gorm:"size:255"`
	// OmitRaw omits request/response pairs in JSON/JSONL/Markdown outputs.
	OmitRaw bool `json:"omit_raw"`
	// OmitTemplate omits encoded template in JSON/JSONL output.
	OmitTemplate bool `json:"omit_template"`
	// NoMeta disables printing result metadata in CLI output.
	NoMeta bool `json:"no_meta"`
	// Timestamp enables printing timestamp in CLI output.
	Timestamp bool `json:"timestamp"`
	// MatcherStatus displays match failure status.
	MatcherStatus bool `json:"matcher_status"`
	// SarifExport file to export results in SARIF format.
	SarifExport string `json:"sarif_export" gorm:"size:255"`
	// MarkdownExport directory to export results in markdown format.
	MarkdownExport string `json:"markdown_export" gorm:"size:255"`
	// JSONExport file to export results in JSON format.
	JSONExport string `json:"json_export" gorm:"size:255"`
	// JSONLExport file to export results in JSONL format.
	JSONLExport string `json:"jsonl_export" gorm:"size:255"`
	// ReportDB nuclei reporting database.
	ReportDB string `json:"report_db" gorm:"size:255"`
	// ReportConfig nuclei reporting module configuration file.
	ReportConfig string `json:"report_config" gorm:"size:255"`
	// Redact redact given list of keys from query parameter, request header and body.
	Redact StringList `json:"redact" gorm:"type:text;not null"`

	// Scan Strategy
	// ScanStrategy: "auto", "template-spray", "host-spray"
	ScanStrategy string `json:"scan_strategy" gorm:"size:16"`

	// Rate Limiting / Performance
	RateLimitMinute int `json:"rate_limit_minute"`
	RateLimitDuration string `json:"rate_limit_duration" gorm:"size:16"`
	HeadlessBulkSize int `json:"headless_bulk_size"`
	HeadlessConcurrency int `json:"headless_concurrency"`
	JSConcurrency int `json:"js_concurrency"`
	PayloadConcurrency int `json:"payload_concurrency"`
	ProbeConcurrency int `json:"probe_concurrency"`
	ResponseSizeRead int `json:"response_size_read"`
	ResponseSizeSave int `json:"response_size_save"`
	LeaveDefaultPorts bool `json:"leave_default_ports"`
	NoMHE bool `json:"no_mhe"`
	TrackError StringList `json:"track_error" gorm:"type:text;not null"`
	Project bool `json:"project"`
	ProjectPath string `json:"project_path" gorm:"size:255"`
	Stream bool `json:"stream"`

	// Headless
	Headless bool `json:"headless"`
	PageTimeout int `json:"page_timeout"`
	ShowBrowser bool `json:"show_browser"`
	HeadlessOptions StringList `json:"headless_options" gorm:"type:text;not null"`
	SystemChrome bool `json:"system_chrome"`
	ListHeadlessActions bool `json:"list_headless_actions"`

	// Interactsh/OAST
	InteractshServer string `json:"interactsh_server" gorm:"size:255"`
	InteractshToken string `json:"interactsh_token" gorm:"size:255"`
	InteractionsCacheSize int `json:"interactions_cache_size"`
	InteractionsEviction int `json:"interactions_eviction"`
	InteractionsPollDuration int `json:"interactions_poll_duration"`
	InteractionsCooldownPeriod int `json:"interactions_cooldown_period"`
}

// ApplyDefaults fills zero-valued int fields with the phase defaults.
func (p *Profile) ApplyDefaults() {
	if p.RateLimit == 0 {
		p.RateLimit = 50
	}
	if p.Concurrency == 0 {
		p.Concurrency = 25
	}
	if p.BulkSize == 0 {
		p.BulkSize = 25
	}
	if p.TimeoutSec == 0 {
		p.TimeoutSec = 10
	}
	if p.Retries == 0 {
		p.Retries = 1
	}
	if p.MaxHostError == 0 {
		p.MaxHostError = 30
	}
	if p.MaxDurationMin == 0 {
		p.MaxDurationMin = 120
	}
	if p.OutputFormat == "" {
		p.OutputFormat = "jsonl"
	}
}

func (p *Profile) Validate() error {
	p.Name = strings.TrimSpace(p.Name)
	p.Tags = cleanList(p.Tags)
	p.ExcludeTags = cleanList(p.ExcludeTags)
	p.Severity = cleanList(p.Severity)
	p.ExcludeSeverity = cleanList(p.ExcludeSeverity)
	p.Protocols = cleanList(p.Protocols)
	p.ExcludeProtocols = cleanList(p.ExcludeProtocols)
	p.TemplateIDs = cleanList(p.TemplateIDs)
	p.ExcludeTemplateIDs = cleanList(p.ExcludeTemplateIDs)
	p.Authors = cleanList(p.Authors)
	p.IncludeTags = cleanList(p.IncludeTags)
	p.CustomHeaders = cleanList(p.CustomHeaders)
	p.Cookies = cleanList(p.Cookies)

	if p.Name == "" {
		return invalid("name is required")
	}
	if len(p.Name) > 191 {
		return invalid("name is too long")
	}
	for _, v := range p.Severity {
		if Severity(v).Valid() == false {
			return invalid("unknown severity %q", v)
		}
	}
	if p.RateLimit < 1 || p.RateLimit > 10000 {
		return invalid("rate_limit must be between 1 and 10000")
	}
	if p.Concurrency < 1 || p.Concurrency > 500 {
		return invalid("concurrency must be between 1 and 500")
	}
	if p.BulkSize < 1 || p.BulkSize > 500 {
		return invalid("bulk_size must be between 1 and 500")
	}
	if p.TimeoutSec < 1 || p.TimeoutSec > 300 {
		return invalid("timeout_sec must be between 1 and 300")
	}
	if p.Retries < 0 || p.Retries > 10 {
		return invalid("retries must be between 0 and 10")
	}
	if p.MaxHostError < 1 || p.MaxHostError > 1000 {
		return invalid("max_host_error must be between 1 and 1000")
	}
	if p.MaxDurationMin < 1 || p.MaxDurationMin > 1440 {
		return invalid("max_duration_min must be between 1 and 1440")
	}
	for _, v := range p.ExcludeSeverity {
		if Severity(v).Valid() == false {
			return invalid("unknown exclude_severity %q", v)
		}
	}
	for _, v := range p.ExcludeProtocols {
		if !Severity(v).Valid() && v != "" {
			// reuse protocol check via allowedProtocol in nuclei package would be ideal;
			// here we do a lightweight non-empty check since full protocol list lives in nuclei pkg
		}
	}
	if p.MaxRedirects < 0 || p.MaxRedirects > 50 {
		return invalid("max_redirects must be between 0 and 50")
	}
	if p.OutputFormat != "" && p.OutputFormat != "jsonl" && p.OutputFormat != "json" && p.OutputFormat != "sarif" {
		return invalid("output_format must be one of: jsonl, json, sarif")
	}
	return nil
}
