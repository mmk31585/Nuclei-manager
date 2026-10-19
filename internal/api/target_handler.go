package api

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/mmk31585/Nuclei-manager/internal/domain"
	"github.com/mmk31585/Nuclei-manager/internal/scope"
)

type TargetHandler struct {
	repo  domain.TargetRepo
	scope *scope.Service
}

func NewTargetHandler(repo domain.TargetRepo, sc *scope.Service) *TargetHandler {
	return &TargetHandler{repo: repo, scope: sc}
}

func (h *TargetHandler) Register(rg *gin.RouterGroup) {
	g := rg.Group("/targets")
	g.GET("", h.List)
	g.POST("", h.Create)
	g.GET("/:id", h.Get)
	g.PUT("/:id", h.Update)
	g.DELETE("/:id", h.Delete)
}

type targetRequest struct {
	Name       string   `json:"name"`
	Comment    string   `json:"comment"`
	Hosts      []string `json:"hosts"`
	Exclude    []string `json:"exclude"`
	Tags       []string `json:"tags"`
	ProbeFirst *bool    `json:"probe_first"`
}

func (r targetRequest) apply(t *domain.Target) {
	t.Name = r.Name
	t.Comment = r.Comment
	t.Hosts = r.Hosts
	t.Exclude = r.Exclude
	t.Tags = r.Tags
	t.ProbeFirst = r.ProbeFirst == nil || *r.ProbeFirst
}

// prepare validates the target and enforces the scope allowlist on its hosts.
func (h *TargetHandler) prepare(ctx context.Context, t *domain.Target) error {
	if err := t.Validate(); err != nil {
		return err
	}
	return h.scope.CheckAll(ctx, t.Hosts)
}

func (h *TargetHandler) List(c *gin.Context) {
	out, err := h.repo.List(c.Request.Context())
	if err != nil {
		writeError(c, err)
		return
	}
	c.JSON(http.StatusOK, out)
}

func (h *TargetHandler) Get(c *gin.Context) {
	id, ok := pathID(c)
	if !ok {
		return
	}
	t, err := h.repo.Get(c.Request.Context(), id)
	if err != nil {
		writeError(c, err)
		return
	}
	c.JSON(http.StatusOK, t)
}

func (h *TargetHandler) Create(c *gin.Context) {
	var req targetRequest
	if !bindJSON(c, &req) {
		return
	}
	var t domain.Target
	req.apply(&t)
	if err := h.prepare(c.Request.Context(), &t); err != nil {
		writeError(c, err)
		return
	}
	if err := h.repo.Create(c.Request.Context(), &t); err != nil {
		writeError(c, err)
		return
	}
	c.JSON(http.StatusCreated, t)
}

func (h *TargetHandler) Update(c *gin.Context) {
	id, ok := pathID(c)
	if !ok {
		return
	}
	var req targetRequest
	if !bindJSON(c, &req) {
		return
	}
	ctx := c.Request.Context()
	t, err := h.repo.Get(ctx, id)
	if err != nil {
		writeError(c, err)
		return
	}
	req.apply(t)
	if err := h.prepare(ctx, t); err != nil {
		writeError(c, err)
		return
	}
	if err := h.repo.Update(ctx, t); err != nil {
		writeError(c, err)
		return
	}
	c.JSON(http.StatusOK, t)
}

func (h *TargetHandler) Delete(c *gin.Context) {
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
