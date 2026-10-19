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

// scopeRequest is the request body for creating a scope entry.
type scopeRequest struct {
	// Entry type: domain, cidr or ip
	Kind domain.ScopeKind `json:"kind" example:"domain"`
	// Entry value; normalized on write (domain lowercased, CIDR/IP canonicalized)
	Value string `json:"value" example:"example.com"`
	// Optional comment
	Comment string `json:"comment" example:"Corporate domain"`
}

func (r scopeRequest) apply(e *domain.ScopeEntry) {
	e.Kind = r.Kind
	e.Value = r.Value
	e.Comment = r.Comment
}

// List godoc
// @Summary      List scope entries
// @Description  Returns all scope allowlist entries ordered by id. An empty allowlist makes the target check fail-closed.
// @Tags         scope
// @Produce      json
// @Success      200  {array}   domain.ScopeEntry
// @Failure      500  {object}  ErrorResponse
// @Router       /scope [get]
func (h *ScopeHandler) List(c *gin.Context) {
	out, err := h.repo.List(c.Request.Context())
	if err != nil {
		writeError(c, err)
		return
	}
	c.JSON(http.StatusOK, out)
}

// Create godoc
// @Summary      Create a scope entry
// @Description  Adds a domain, CIDR or IP to the allowlist. Values are normalized and validated.
// @Tags         scope
// @Accept       json
// @Produce      json
// @Param        entry  body      scopeRequest  true  "Scope entry to create"
// @Success      201    {object}  domain.ScopeEntry
// @Failure      400    {object}  ErrorResponse
// @Failure      409    {object}  ErrorResponse
// @Router       /scope [post]
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

// Delete godoc
// @Summary      Delete a scope entry
// @Description  Removes a scope entry by id.
// @Tags         scope
// @Param        id   path      int  true  "Scope entry ID"
// @Success      204
// @Failure      400  {object}  ErrorResponse
// @Failure      404  {object}  ErrorResponse
// @Router       /scope/{id} [delete]
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
