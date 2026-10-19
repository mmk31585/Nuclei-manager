package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/mmk31585/Nuclei-manager/internal/domain"
)

type ScopeHandler struct {
	repo domain.ScopeRepo
}

func NewScopeHandler(repo domain.ScopeRepo) *ScopeHandler {
	return &ScopeHandler{repo: repo}
}

func (h *ScopeHandler) Register(rg *gin.RouterGroup) {
	g := rg.Group("/scope")
	g.GET("", h.List)
	g.POST("", h.Create)
	g.DELETE("/:id", h.Delete)
}

type scopeRequest struct {
	Kind    domain.ScopeKind `json:"kind"`
	Value   string           `json:"value"`
	Comment string           `json:"comment"`
}

func (r scopeRequest) apply(e *domain.ScopeEntry) {
	e.Kind = r.Kind
	e.Value = r.Value
	e.Comment = r.Comment
}

func (h *ScopeHandler) List(c *gin.Context) {
	out, err := h.repo.List(c.Request.Context())
	if err != nil {
		writeError(c, err)
		return
	}
	c.JSON(http.StatusOK, out)
}

func (h *ScopeHandler) Create(c *gin.Context) {
	var req scopeRequest
	if !bindJSON(c, &req) {
		return
	}
	var e domain.ScopeEntry
	req.apply(&e)
	if err := e.Validate(); err != nil {
		writeError(c, err)
		return
	}
	if err := h.repo.Create(c.Request.Context(), &e); err != nil {
		writeError(c, err)
		return
	}
	c.JSON(http.StatusCreated, e)
}

func (h *ScopeHandler) Delete(c *gin.Context) {
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
