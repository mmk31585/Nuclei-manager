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

type profileRequest struct {
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	Tags           []string `json:"tags"`
	ExcludeTags    []string `json:"exclude_tags"`
	Severity       []string `json:"severity"`
	Protocols      []string `json:"protocols"`
	TemplateIDs    []string `json:"template_ids"`
	CustomSet      string   `json:"custom_set"`
	RateLimit      int      `json:"rate_limit"`
	Concurrency    int      `json:"concurrency"`
	BulkSize       int      `json:"bulk_size"`
	TimeoutSec     int      `json:"timeout_sec"`
	Retries        int      `json:"retries"`
	MaxHostError   int      `json:"max_host_error"`
	MaxDurationMin int      `json:"max_duration_min"`
	OAST           *bool    `json:"oast"`
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

func (h *ProfileHandler) List(c *gin.Context) {
	out, err := h.repo.List(c.Request.Context())
	if err != nil {
		writeError(c, err)
		return
	}
	c.JSON(http.StatusOK, out)
}

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
