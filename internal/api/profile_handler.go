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
	// Restrict to these protocols (http, dns, tcp, ssl, websocket, whois, javascript, workflow)
	Protocols []string `json:"protocols" example:"http,ssl"`
	// Restrict to these exact template IDs
	TemplateIDs []string `json:"template_ids" example:"cve-2021-0001"`
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
}

func (r profileRequest) apply(p *domain.Profile) {
	p.Name = r.Name
	p.Description = r.Description
	p.Tags = r.Tags
	p.ExcludeTags = r.ExcludeTags
	p.Severity = r.Severity
	p.Protocols = r.Protocols
	p.TemplateIDs = r.TemplateIDs
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
