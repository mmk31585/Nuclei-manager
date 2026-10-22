package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/mmk31585/Nuclei-manager/internal/domain"
)

type ProfileHandler struct {
	repo domain.ProfileRepo
}

func NewProfileHandler(repo domain.ProfileRepo) *ProfileHandler {
	return &ProfileHandler{repo: repo}
}

func (h *ProfileHandler) Register(rg *gin.RouterGroup) {
	g := rg.Group("/profiles")
	g.GET("", h.List)
	g.POST("", h.Create)
	g.GET("/:id", h.Get)
	g.PUT("/:id", h.Update)
	g.DELETE("/:id", h.Delete)
}

// profileRequest is the request body for creating or replacing a profile.
type profileRequest struct {
	// Unique profile name
	Name string `json:"name" example:"external-only"`
	// Optional description
	Description string `json:"description" example:"External-facing web checks"`
	// Only run templates with at least one of these tags
	Tags []string `json:"tags" example:"cve,exposure"`
	// Exclude templates carrying any of these tags
	ExcludeTags []string `json:"exclude_tags" example:"dos,intrusive"`
	// Only run templates of these severities
	Severity []string `json:"severity" example:"medium,high,critical"`
	// Exclude templates of these severities
	ExcludeSeverity []string `json:"exclude_severity" example:"info"`
	// Restrict to these protocols (http, dns, tcp, ssl, websocket, whois, javascript, workflow)
	Protocols []string `json:"protocols" example:"http,ssl"`
	// Exclude these protocol types
	ExcludeProtocols []string `json:"exclude_protocols" example:"dns"`
	// Restrict to these exact template IDs
	TemplateIDs []string `json:"template_ids" example:"cve-2021-0001"`
	// Exclude these exact template IDs
	ExcludeTemplateIDs []string `json:"exclude_template_ids" example:"cve-2020-9999"`
	// Only run templates by these authors
	Authors []string `json:"authors" example:"geeknik"`
	// Include tags even if excluded by default or configuration
	IncludeTags []string `json:"include_tags" example:"dos"`
	// Name of an external custom template set directory
	CustomSet string `json:"custom_set" example:"custom-a"`
	// Requests per second (1-10000)
	RateLimit int `json:"rate_limit" example:"50"`
	// Concurrent requests (1-500)
	Concurrency int `json:"concurrency" example:"25"`
	// Bulk size (1-500)
	BulkSize int `json:"bulk_size" example:"25"`
	// Per-request timeout in seconds (1-300)
	TimeoutSec int `json:"timeout_sec" example:"10"`
	// Retries per request (0-10)
	Retries int `json:"retries" example:"1"`
	// Max errors per host before skipping it (1-1000)
	MaxHostError int `json:"max_host_error" example:"30"`
	// Max total scan duration in minutes (1-1440)
	MaxDurationMin int `json:"max_duration_min" example:"120"`
	// Enable OAST interaction callbacks
	OAST *bool `json:"oast"`
	// Follow HTTP redirects for HTTP templates
	FollowRedirects *bool `json:"follow_redirects"`
	// Max number of redirects to follow (default 10)
	MaxRedirects int `json:"max_redirects" example:"10"`
	// Use system DNS resolving as error fallback
	SystemResolvers *bool `json:"system_resolvers"`
	// Stop processing HTTP requests after the first match
	StopAtFirstMatch *bool `json:"stop_at_first_match"`
	// Disable httpx probing for non-URL input
	NoHttpx *bool `json:"no_httpx"`
	// Complex expression to filter templates
	TemplateCondition string `json:"template_condition" example:"contains(id,'xss')"`
	// Output format: jsonl (default), json, sarif
	OutputFormat string `json:"output_format" example:"jsonl"`
	// Custom headers passed with every request (header:value)
	CustomHeaders []string `json:"custom_headers" example:"Authorization: Bearer xxx"`
	// Cookies sent with every request
	Cookies []string `json:"cookies" example:"session=abc123"`
	// Basic auth username:password for authenticated scans
	BasicAuth string `json:"basic_auth" example:"user:pass"`

	// --- Input Formats ---
	// Input mode: list (default), burp, jsonl, yaml, openapi, swagger
	InputMode string `json:"input_mode" example:"list"`
	// RequiredOnly uses only required fields in input format
	RequiredOnly *bool `json:"required_only"`
	// SkipFormatValidation skips format validation
	SkipFormatValidation *bool `json:"skip_format_validation"`
	// ScanAllIPs scans all IPs associated with DNS record
	ScanAllIPs *bool `json:"scan_all_ips"`
	// IPVersion to scan (4, 6)
	IPVersion []string `json:"ip_version" example:"4,6"`

	// Authentication
	// SecretFile path to config file containing secrets
	SecretFile []string `json:"secret_file" example:"/path/to/secrets.yaml"`
	// PrefetchSecrets prefetches secrets from the secrets file
	PrefetchSecrets *bool `json:"prefetch_secrets"`

	// Workflows
	// Workflows list of workflow or workflow directory to run
	Workflows []string `json:"workflows" example:"workflows/"`
	// WorkflowURLs list of workflow URLs to run
	WorkflowURLs []string `json:"workflow_urls" example:"https://example.com/workflow.yaml"`

	// Template filters
	// IncludeTemplates path to template file or directory to be executed even if excluded
	IncludeTemplates []string `json:"include_templates" example:"custom/"`
	// ExcludeTemplates path to template file or directory to exclude
	ExcludeTemplates []string `json:"exclude_templates" example:"excluded/"`

	// Output enhancements
	// StoreResponse stores all request/response passed through nuclei to output directory
	StoreResponse *bool `json:"store_response"`
	// StoreResponseDir custom directory to store responses (default "output")
	StoreResponseDir string `json:"store_response_dir" example:"output"`
	// OmitRaw omits request/response pairs in JSON/JSONL/Markdown outputs
	OmitRaw *bool `json:"omit_raw"`
	// OmitTemplate omits encoded template in JSON/JSONL output
	OmitTemplate *bool `json:"omit_template"`
	// NoMeta disables printing result metadata in CLI output
	NoMeta *bool `json:"no_meta"`
	// Timestamp enables printing timestamp in CLI output
	Timestamp *bool `json:"timestamp"`
	// MatcherStatus displays match failure status
	MatcherStatus *bool `json:"matcher_status"`
	// SarifExport file to export results in SARIF format
	SarifExport string `json:"sarif_export" example:"results.sarif"`
	// MarkdownExport directory to export results in markdown format
	MarkdownExport string `json:"markdown_export" example:"report/"`
	// JSONExport file to export results in JSON format
	JSONExport string `json:"json_export" example:"results.json"`
	// JSONLExport file to export results in JSONL format
	JSONLExport string `json:"jsonl_export" example:"results.jsonl"`
	// ReportDB nuclei reporting database
	ReportDB string `json:"report_db" example:"report.db"`
	// ReportConfig nuclei reporting module configuration file
	ReportConfig string `json:"report_config" example:"report.yaml"`
	// Redact redact given list of keys from query parameter, request header and body
	Redact []string `json:"redact" example:"password,token"`

	// Scan Strategy
	// ScanStrategy: auto, template-spray, host-spray
	ScanStrategy string `json:"scan_strategy" example:"auto"`

	// Rate Limiting / Performance
	RateLimitMinute int `json:"rate_limit_minute" example:"3000"`
	RateLimitDuration string `json:"rate_limit_duration" example:"1m"`
	HeadlessBulkSize int `json:"headless_bulk_size" example:"10"`
	HeadlessConcurrency int `json:"headless_concurrency" example:"10"`
	JSConcurrency int `json:"js_concurrency" example:"120"`
	PayloadConcurrency int `json:"payload_concurrency" example:"25"`
	ProbeConcurrency int `json:"probe_concurrency" example:"50"`
	ResponseSizeRead int `json:"response_size_read" example:"4194304"`
	ResponseSizeSave int `json:"response_size_save" example:"1048576"`
	LeaveDefaultPorts *bool `json:"leave_default_ports"`
	NoMHE *bool `json:"no_mhe"`
	TrackError []string `json:"track_error" example:"standard"`
	Project *bool `json:"project"`
	ProjectPath string `json:"project_path" example:"/tmp/nuclei-project"`
	Stream *bool `json:"stream"`

	// Headless
	Headless *bool `json:"headless"`
	PageTimeout int `json:"page_timeout" example:"20"`
	ShowBrowser *bool `json:"show_browser"`
	HeadlessOptions []string `json:"headless_options" example:"--no-sandbox"`
	SystemChrome *bool `json:"system_chrome"`
	ListHeadlessActions *bool `json:"list_headless_actions"`

	// Interactsh/OAST
	InteractshServer string `json:"interactsh_server" example:"oast.pro"`
	InteractshToken string `json:"interactsh_token" example:"xxx"`
	InteractionsCacheSize int `json:"interactions_cache_size" example:"5000"`
	InteractionsEviction int `json:"interactions_eviction" example:"60"`
	InteractionsPollDuration int `json:"interactions_poll_duration" example:"5"`
	InteractionsCooldownPeriod int `json:"interactions_cooldown_period" example:"5"`
}

func (r profileRequest) apply(p *domain.Profile) {
	p.Name = r.Name
	p.Description = r.Description
	p.Tags = r.Tags
	p.ExcludeTags = r.ExcludeTags
	p.Severity = r.Severity
	p.ExcludeSeverity = r.ExcludeSeverity
	p.Protocols = r.Protocols
	p.ExcludeProtocols = r.ExcludeProtocols
	p.TemplateIDs = r.TemplateIDs
	p.ExcludeTemplateIDs = r.ExcludeTemplateIDs
	p.Authors = r.Authors
	p.IncludeTags = r.IncludeTags
	p.CustomSet = r.CustomSet
	p.RateLimit = r.RateLimit
	p.Concurrency = r.Concurrency
	p.BulkSize = r.BulkSize
	p.TimeoutSec = r.TimeoutSec
	p.Retries = r.Retries
	p.MaxHostError = r.MaxHostError
	p.MaxDurationMin = r.MaxDurationMin
	if r.OAST != nil {
		p.OAST = *r.OAST
	}
	if r.FollowRedirects != nil {
		p.FollowRedirects = *r.FollowRedirects
	}
	if r.MaxRedirects > 0 {
		p.MaxRedirects = r.MaxRedirects
	}
	if r.SystemResolvers != nil {
		p.SystemResolvers = *r.SystemResolvers
	}
	if r.StopAtFirstMatch != nil {
		p.StopAtFirstMatch = *r.StopAtFirstMatch
	}
	if r.NoHttpx != nil {
		p.NoHttpx = *r.NoHttpx
	}
	p.TemplateCondition = r.TemplateCondition
	if r.OutputFormat != "" {
		p.OutputFormat = r.OutputFormat
	}
	p.CustomHeaders = r.CustomHeaders
	p.Cookies = r.Cookies
	p.BasicAuth = r.BasicAuth

	// --- Input Formats ---
	if r.InputMode != "" {
		p.InputMode = r.InputMode
	}
	if r.RequiredOnly != nil {
		p.RequiredOnly = *r.RequiredOnly
	}
	if r.SkipFormatValidation != nil {
		p.SkipFormatValidation = *r.SkipFormatValidation
	}
	if r.ScanAllIPs != nil {
		p.ScanAllIPs = *r.ScanAllIPs
	}
	if len(r.IPVersion) > 0 {
		p.IPVersion = r.IPVersion
	}

	// Authentication
	if len(r.SecretFile) > 0 {
		p.SecretFile = r.SecretFile
	}
	if r.PrefetchSecrets != nil {
		p.PrefetchSecrets = *r.PrefetchSecrets
	}

	// Workflows
	if len(r.Workflows) > 0 {
		p.Workflows = r.Workflows
	}
	if len(r.WorkflowURLs) > 0 {
		p.WorkflowURLs = r.WorkflowURLs
	}

	// Template filters
	if len(r.IncludeTemplates) > 0 {
		p.IncludeTemplates = r.IncludeTemplates
	}
	if len(r.ExcludeTemplates) > 0 {
		p.ExcludeTemplates = r.ExcludeTemplates
	}

	// Output enhancements
	if r.StoreResponse != nil {
		p.StoreResponse = *r.StoreResponse
	}
	if r.StoreResponseDir != "" {
		p.StoreResponseDir = r.StoreResponseDir
	}
	if r.OmitRaw != nil {
		p.OmitRaw = *r.OmitRaw
	}
	if r.OmitTemplate != nil {
		p.OmitTemplate = *r.OmitTemplate
	}
	if r.NoMeta != nil {
		p.NoMeta = *r.NoMeta
	}
	if r.Timestamp != nil {
		p.Timestamp = *r.Timestamp
	}
	if r.MatcherStatus != nil {
		p.MatcherStatus = *r.MatcherStatus
	}
	if r.SarifExport != "" {
		p.SarifExport = r.SarifExport
	}
	if r.MarkdownExport != "" {
		p.MarkdownExport = r.MarkdownExport
	}
	if r.JSONExport != "" {
		p.JSONExport = r.JSONExport
	}
	if r.JSONLExport != "" {
		p.JSONLExport = r.JSONLExport
	}
	if r.ReportDB != "" {
		p.ReportDB = r.ReportDB
	}
	if r.ReportConfig != "" {
		p.ReportConfig = r.ReportConfig
	}
	if len(r.Redact) > 0 {
		p.Redact = r.Redact
	}

	// Scan Strategy
	if r.ScanStrategy != "" {
		p.ScanStrategy = r.ScanStrategy
	}

	// Rate Limiting / Performance
	if r.RateLimitMinute > 0 {
		p.RateLimitMinute = r.RateLimitMinute
	}
	if r.RateLimitDuration != "" {
		p.RateLimitDuration = r.RateLimitDuration
	}
	if r.HeadlessBulkSize > 0 {
		p.HeadlessBulkSize = r.HeadlessBulkSize
	}
	if r.HeadlessConcurrency > 0 {
		p.HeadlessConcurrency = r.HeadlessConcurrency
	}
	if r.JSConcurrency > 0 {
		p.JSConcurrency = r.JSConcurrency
	}
	if r.PayloadConcurrency > 0 {
		p.PayloadConcurrency = r.PayloadConcurrency
	}
	if r.ProbeConcurrency > 0 {
		p.ProbeConcurrency = r.ProbeConcurrency
	}
	if r.ResponseSizeRead > 0 {
		p.ResponseSizeRead = r.ResponseSizeRead
	}
	if r.ResponseSizeSave > 0 {
		p.ResponseSizeSave = r.ResponseSizeSave
	}
	if r.LeaveDefaultPorts != nil {
		p.LeaveDefaultPorts = *r.LeaveDefaultPorts
	}
	if r.NoMHE != nil {
		p.NoMHE = *r.NoMHE
	}
	if len(r.TrackError) > 0 {
		p.TrackError = r.TrackError
	}
	if r.Project != nil {
		p.Project = *r.Project
	}
	if r.ProjectPath != "" {
		p.ProjectPath = r.ProjectPath
	}
	if r.Stream != nil {
		p.Stream = *r.Stream
	}

	// Headless
	if r.Headless != nil {
		p.Headless = *r.Headless
	}
	if r.PageTimeout > 0 {
		p.PageTimeout = r.PageTimeout
	}
	if r.ShowBrowser != nil {
		p.ShowBrowser = *r.ShowBrowser
	}
	if len(r.HeadlessOptions) > 0 {
		p.HeadlessOptions = r.HeadlessOptions
	}
	if r.SystemChrome != nil {
		p.SystemChrome = *r.SystemChrome
	}
	if r.ListHeadlessActions != nil {
		p.ListHeadlessActions = *r.ListHeadlessActions
	}

	// Interactsh/OAST
	if r.InteractshServer != "" {
		p.InteractshServer = r.InteractshServer
	}
	if r.InteractshToken != "" {
		p.InteractshToken = r.InteractshToken
	}
	if r.InteractionsCacheSize > 0 {
		p.InteractionsCacheSize = r.InteractionsCacheSize
	}
	if r.InteractionsEviction > 0 {
		p.InteractionsEviction = r.InteractionsEviction
	}
	if r.InteractionsPollDuration > 0 {
		p.InteractionsPollDuration = r.InteractionsPollDuration
	}
	if r.InteractionsCooldownPeriod > 0 {
		p.InteractionsCooldownPeriod = r.InteractionsCooldownPeriod
	}
}

// List godoc
// @Summary      List profiles
// @Description  Returns all scan profiles ordered by id, including the seeded built-in profiles.
// @Tags         profiles
// @Produce      json
// @Success      200  {array}   domain.Profile
// @Failure      500  {object}  ErrorResponse
// @Router       /profiles [get]
func (h *ProfileHandler) List(c *gin.Context) {
	out, err := h.repo.List(c.Request.Context())
	if err != nil {
		writeError(c, err)
		return
	}
	c.JSON(http.StatusOK, out)
}

// Get godoc
// @Summary      Get a profile
// @Description  Returns a single profile by id.
// @Tags         profiles
// @Produce      json
// @Param        id   path      int  true  "Profile ID"
// @Success      200  {object}  domain.Profile
// @Failure      400  {object}  ErrorResponse
// @Failure      404  {object}  ErrorResponse
// @Router       /profiles/{id} [get]
func (h *ProfileHandler) Get(c *gin.Context) {
	id, ok := pathID(c)
	if !ok {
		return
	}
	p, err := h.repo.Get(c.Request.Context(), id)
	if err != nil {
		writeError(c, err)
		return
	}
	c.JSON(http.StatusOK, p)
}

// Create godoc
// @Summary      Create a profile
// @Description  Creates a custom profile. Zero-valued numeric fields are filled with defaults before validation.
// @Tags         profiles
// @Accept       json
// @Produce      json
// @Param        profile  body      profileRequest  true  "Profile to create"
// @Success      201      {object}  domain.Profile
// @Failure      400      {object}  ErrorResponse
// @Failure      409      {object}  ErrorResponse
// @Router       /profiles [post]
func (h *ProfileHandler) Create(c *gin.Context) {
	var req profileRequest
	if !bindJSON(c, &req) {
		return
	}
	var p domain.Profile
	req.apply(&p)
	p.Builtin = false
	p.ApplyDefaults()
	if err := p.Validate(); err != nil {
		writeError(c, err)
		return
	}
	if err := h.repo.Create(c.Request.Context(), &p); err != nil {
		writeError(c, err)
		return
	}
	c.JSON(http.StatusCreated, p)
}

// Update godoc
// @Summary      Replace a profile
// @Description  Full replacement of a custom profile by id. Built-in profiles are read-only and return 409.
// @Tags         profiles
// @Accept       json
// @Produce      json
// @Param        id       path      int             true  "Profile ID"
// @Param        profile  body      profileRequest  true  "Replacement profile"
// @Success      200      {object}  domain.Profile
// @Failure      400      {object}  ErrorResponse
// @Failure      404      {object}  ErrorResponse
// @Failure      409      {object}  ErrorResponse  "Built-in profiles are read-only"
// @Router       /profiles/{id} [put]
func (h *ProfileHandler) Update(c *gin.Context) {
	id, ok := pathID(c)
	if !ok {
		return
	}
	var req profileRequest
	if !bindJSON(c, &req) {
		return
	}
	ctx := c.Request.Context()
	p, err := h.repo.Get(ctx, id)
	if err != nil {
		writeError(c, err)
		return
	}
	req.apply(p)
	p.ApplyDefaults()
	if err := p.Validate(); err != nil {
		writeError(c, err)
		return
	}
	if err := h.repo.Update(ctx, p); err != nil {
		writeError(c, err)
		return
	}
	c.JSON(http.StatusOK, p)
}

// Delete godoc
// @Summary      Delete a profile
// @Description  Deletes a custom profile by id. Built-in profiles and profiles referenced by tasks return 409.
// @Tags         profiles
// @Param        id   path      int  true  "Profile ID"
// @Success      204
// @Failure      400  {object}  ErrorResponse
// @Failure      404  {object}  ErrorResponse
// @Failure      409  {object}  ErrorResponse  "Built-in profile or profile in use"
// @Router       /profiles/{id} [delete]
func (h *ProfileHandler) Delete(c *gin.Context) {
	id, ok := pathID(c)
	if !ok {
		return
	}
	if err := h.repo.Delete(c.Request.Context(), id); err != nil {
		writeError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}
