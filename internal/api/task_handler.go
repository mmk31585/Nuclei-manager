package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/mmk31585/Nuclei-manager/internal/domain"
)

type TaskHandler struct {
	repo     domain.TaskRepo
	targets  domain.TargetRepo
	profiles domain.ProfileRepo
}

func NewTaskHandler(repo domain.TaskRepo, targets domain.TargetRepo, profiles domain.ProfileRepo) *TaskHandler {
	return &TaskHandler{repo: repo, targets: targets, profiles: profiles}
}

func (h *TaskHandler) Register(rg *gin.RouterGroup) {
	g := rg.Group("/tasks")
	g.GET("", h.List)
	g.POST("", h.Create)
	g.GET("/:id", h.Get)
	g.PUT("/:id", h.Update)
	g.DELETE("/:id", h.Delete)
}

type taskRequest struct {
	Name              string              `json:"name"`
	Comment           string              `json:"comment"`
	TargetID          uint                `json:"target_id"`
	ProfileID         uint                `json:"profile_id"`
	ScheduleType      domain.ScheduleType `json:"schedule_type"`
	CronExpr          string              `json:"cron_expr"`
	Timezone          string              `json:"timezone"`
	MinSeverity       domain.Severity     `json:"min_severity"`
	AddToAssets       *bool               `json:"add_to_assets"`
	ApplySuppressions *bool               `json:"apply_suppressions"`
	Enabled           *bool               `json:"enabled"`
	RetentionKeepLast int                 `json:"retention_keep_last"`
	NotifyOn          []string            `json:"notify_on"`
}

func (r taskRequest) apply(t *domain.Task) {
	t.Name = r.Name
	t.Comment = r.Comment
	t.TargetID = r.TargetID
	t.ProfileID = r.ProfileID
	t.ScheduleType = r.ScheduleType
	t.CronExpr = r.CronExpr
	t.Timezone = r.Timezone
	t.MinSeverity = r.MinSeverity
	if r.AddToAssets != nil {
		t.AddToAssets = *r.AddToAssets
	}
	if r.ApplySuppressions != nil {
		t.ApplySuppressions = *r.ApplySuppressions
	}
	if r.Enabled != nil {
		t.Enabled = *r.Enabled
	}
	t.RetentionKeepLast = r.RetentionKeepLast
	t.NotifyOn = r.NotifyOn
}

func (h *TaskHandler) List(c *gin.Context) {
	out, err := h.repo.List(c.Request.Context())
	if err != nil {
		writeError(c, err)
		return
	}
	c.JSON(http.StatusOK, out)
}

func (h *TaskHandler) Get(c *gin.Context) {
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

func (h *TaskHandler) save(ctx context.Context, t *domain.Task, c *gin.Context) {
	if _, err := h.targets.Get(ctx, t.TargetID); err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			writeError(c, fmt.Errorf("%w: target_id does not exist", domain.ErrValidation))
		} else {
			writeError(c, err)
		}
		return
	}
	if _, err := h.profiles.Get(ctx, t.ProfileID); err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			writeError(c, fmt.Errorf("%w: profile_id does not exist", domain.ErrValidation))
		} else {
			writeError(c, err)
		}
		return
	}
	if err := h.repo.Create(ctx, t); err != nil {
		writeError(c, err)
		return
	}
	c.JSON(http.StatusCreated, t)
}

func (h *TaskHandler) Create(c *gin.Context) {
	var req taskRequest
	if !bindJSON(c, &req) {
		return
	}
	var t domain.Task
	req.apply(&t)
	t.ApplyDefaults()
	if err := t.Validate(); err != nil {
		writeError(c, err)
		return
	}
	h.save(c.Request.Context(), &t, c)
}

func (h *TaskHandler) Update(c *gin.Context) {
	id, ok := pathID(c)
	if !ok {
		return
	}
	var req taskRequest
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
	t.ApplyDefaults()
	if err := t.Validate(); err != nil {
		writeError(c, err)
		return
	}
	if _, err := h.targets.Get(ctx, t.TargetID); err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			writeError(c, fmt.Errorf("%w: target_id does not exist", domain.ErrValidation))
		} else {
			writeError(c, err)
		}
		return
	}
	if _, err := h.profiles.Get(ctx, t.ProfileID); err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			writeError(c, fmt.Errorf("%w: profile_id does not exist", domain.ErrValidation))
		} else {
			writeError(c, err)
		}
		return
	}
	if err := h.repo.Update(ctx, t); err != nil {
		writeError(c, err)
		return
	}
	c.JSON(http.StatusOK, t)
}

func (h *TaskHandler) Delete(c *gin.Context) {
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
