package api

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/mmk31585/Nuclei-manager/internal/discovery"
	"github.com/mmk31585/Nuclei-manager/internal/domain"
	"github.com/mmk31585/Nuclei-manager/internal/scope"
)

type TargetHandler struct {
	repo      domain.TargetRepo
	scope     *scope.Service
	discovery *discovery.Worker
	endpoints domain.TargetEndpointRepo
}

func NewTargetHandler(repo domain.TargetRepo, sc *scope.Service, dw *discovery.Worker, epRepo domain.TargetEndpointRepo) *TargetHandler {
	return &TargetHandler{repo: repo, scope: sc, discovery: dw, endpoints: epRepo}
}

func (h *TargetHandler) Register(rg *gin.RouterGroup) {
	g := rg.Group("/targets")
	g.GET("", h.List)
	g.POST("", h.Create)
	g.GET("/:id", h.Get)
	g.PUT("/:id", h.Update)
	g.DELETE("/:id", h.Delete)
	g.GET("/:id/endpoints", h.ListEndpoints)
	g.POST("/:id/discover", h.Discover)
}

// targetRequest is the request body for creating or replacing a target.
type targetRequest struct {
	// Unique target name
	Name string `json:"name" example:"staging-web"`
	// Optional comment
	Comment string `json:"comment" example:"Public staging estate"`
	// Hosts to scan (URLs, host:port, bare hosts or IPs); at least one required
	Hosts []string `json:"hosts" example:"https://app.example.com"`
	// Hosts, IPs or CIDRs excluded from the scan
	Exclude []string `json:"exclude" example:"10.0.0.0/8"`
	// Arbitrary labels
	Tags []string `json:"tags" example:"prod"`
	// Probe hosts before scanning; defaults to true when omitted
	ProbeFirst *bool `json:"probe_first"`
	// Port scope for discovery: default, top100, top1000, all, custom (default all)
	PortScope string `json:"port_scope" example:"all"`
	// Custom ports (e.g. "80,443,8000-9000"), used only when port_scope is custom
	CustomPorts string `json:"custom_ports" example:"80,443,8000-9000"`
}

func (r targetRequest) apply(t *domain.Target) {
	t.Name = r.Name
	t.Comment = r.Comment
	t.Hosts = r.Hosts
	t.Exclude = r.Exclude
	t.Tags = r.Tags
	t.ProbeFirst = r.ProbeFirst == nil || *r.ProbeFirst
	if r.PortScope != "" {
		t.PortScope = r.PortScope
	}
	if r.CustomPorts != "" {
		t.CustomPorts = r.CustomPorts
	}
	t.ApplyDefaults()
}

// prepare validates the target and enforces the scope allowlist on its hosts.
func (h *TargetHandler) prepare(ctx context.Context, t *domain.Target) error {
	if err := t.Validate(); err != nil {
		return err
	}
	return h.scope.CheckAll(ctx, t.Hosts)
}

// List godoc
// @Summary      List targets
// @Description  Returns all targets ordered by id.
// @Tags         targets
// @Produce      json
// @Success      200  {array}   domain.Target
// @Failure      500  {object}  ErrorResponse
// @Router       /targets [get]
func (h *TargetHandler) List(c *gin.Context) {
	out, err := h.repo.List(c.Request.Context())
	if err != nil {
		writeError(c, err)
		return
	}
	c.JSON(http.StatusOK, out)
}

// Get godoc
// @Summary      Get a target
// @Description  Returns a single target by id.
// @Tags         targets
// @Produce      json
// @Param        id   path      int  true  "Target ID"
// @Success      200  {object}  domain.Target
// @Failure      400  {object}  ErrorResponse
// @Failure      404  {object}  ErrorResponse
// @Router       /targets/{id} [get]
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

// Create godoc
// @Summary      Create a target
// @Description  Creates a target after validating it and enforcing the scope allowlist on every host. Rejects out-of-scope hosts with 422.
// @Tags         targets
// @Accept       json
// @Produce      json
// @Param        target  body      targetRequest  true  "Target to create"
// @Success      201     {object}  domain.Target
// @Failure      400     {object}  ErrorResponse
// @Failure      409     {object}  ErrorResponse
// @Failure      422     {object}  ErrorResponse  "One or more hosts are outside the allowed scope"
// @Router       /targets [post]
func (h *TargetHandler) Create(c *gin.Context) {
	var req targetRequest
	if !bindJSON(c, &req) {
		return
	}
	var t domain.Target
	req.apply(&t)
	t.DiscoveryStatus = "pending"
	if err := h.prepare(c.Request.Context(), &t); err != nil {
		writeError(c, err)
		return
	}
	if err := h.repo.Create(c.Request.Context(), &t); err != nil {
		writeError(c, err)
		return
	}
	// Start background discovery
	if h.discovery != nil {
		go h.discovery.DiscoverTarget(context.Background(), t.ID)
	}
	c.JSON(http.StatusCreated, t)
}

// Update godoc
// @Summary      Replace a target
// @Description  Full replacement of a target by id. The new host list is re-validated against the scope allowlist.
// @Tags         targets
// @Accept       json
// @Produce      json
// @Param        id      path      int            true  "Target ID"
// @Param        target  body      targetRequest  true  "Replacement target"
// @Success      200     {object}  domain.Target
// @Failure      400     {object}  ErrorResponse
// @Failure      404     {object}  ErrorResponse
// @Failure     422     {object}  ErrorResponse  "One or more hosts are outside the allowed scope"
// @Router       /targets/{id} [put]
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

// ListEndpoints godoc
// @Summary      List discovered endpoints for a target
// @Description  Returns all discovered ports/services for a target.
// @Tags         targets
// @Produce      json
// @Param        id   path      int  true  "Target ID"
// @Success      200  {array}   domain.TargetEndpoint
// @Failure      400  {object}  ErrorResponse
// @Failure      404  {object}  ErrorResponse
// @Router       /targets/{id}/endpoints [get]
func (h *TargetHandler) ListEndpoints(c *gin.Context) {
	id, ok := pathID(c)
	if !ok {
		return
	}
	eps, err := h.endpoints.ListByTarget(c.Request.Context(), id)
	if err != nil {
		writeError(c, err)
		return
	}
	c.JSON(http.StatusOK, eps)
}

// Discover godoc
// @Summary      Re-run discovery for a target
// @Description  Triggers a new port/service discovery run in the background. Returns 202.
// @Tags         targets
// @Param        id   path      int  true  "Target ID"
// @Success      202
// @Failure      400  {object}  ErrorResponse
// @Failure      404  {object}  ErrorResponse
// @Router       /targets/{id}/discover [post]
func (h *TargetHandler) Discover(c *gin.Context) {
	id, ok := pathID(c)
	if !ok {
		return
	}
	if _, err := h.repo.Get(c.Request.Context(), id); err != nil {
		writeError(c, err)
		return
	}
	if h.discovery != nil {
		go h.discovery.DiscoverTarget(context.Background(), id)
	}
	c.Status(http.StatusAccepted)
}

// @Description  Deletes a target by id. Returns 409 when one or more tasks reference it.
// @Tags         targets
// @Param        id   path      int  true  "Target ID"
// @Success      204
// @Failure      400  {object}  ErrorResponse
// @Failure      404  {object}  ErrorResponse
// @Failure      409  {object}  ErrorResponse  "Target is used by one or more tasks"
// @Router       /targets/{id} [delete]
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
