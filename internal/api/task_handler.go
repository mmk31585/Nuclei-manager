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

// taskRequest is the request body for creating or replacing a task.
type taskRequest struct {
	// Unique task name
	Name string `json:"name" example:"nightly-staging"`
	// Optional comment
	Comment string `json:"comment" example:"Nightly staging scan"`
	// Target to scan (must exist)
	TargetID uint `json:"target_id" example:"1"`
	// Profile to use (must exist)
	ProfileID uint `json:"profile_id" example:"1"`
	// Schedule type: once or cron
	ScheduleType domain.ScheduleType `json:"schedule_type" example:"cron"`
	// Cron expression, required when schedule_type is cron
	CronExpr string `json:"cron_expr" example:"0 2 * * *"`
	// IANA timezone for the schedule
	Timezone string `json:"timezone" example:"UTC"`
	// Minimum severity reported
	MinSeverity domain.Severity `json:"min_severity" example:"medium"`
	// Add discovered hosts to the asset inventory
	AddToAssets *bool `json:"add_to_assets"`
	// Apply configured suppressions to findings
	ApplySuppressions *bool `json:"apply_suppressions"`
	// Whether the schedule is enabled
	Enabled *bool `json:"enabled"`
	// Number of most recent runs to retain (1-1000)
	RetentionKeepLast int `json:"retention_keep_last" example:"20"`
	// Severities that trigger a notification
	NotifyOn []string `json:"notify_on" example:"high,critical"`
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

// List godoc
// @Summary      List tasks
// @Description  Returns all tasks ordered by id.
// @Tags         tasks
// @Produce      json
// @Success      200  {array}   domain.Task
// @Failure      500  {object}  ErrorResponse
// @Router       /tasks [get]
func (h *TaskHandler) List(c *gin.Context) {
	out, err := h.repo.List(c.Request.Context())
	if err != nil {
		writeError(c, err)
		return
	}
	c.JSON(http.StatusOK, out)
}

// Get godoc
// @Summary      Get a task
// @Description  Returns a single task by id.
// @Tags         tasks
// @Produce      json
// @Param        id   path      int  true  "Task ID"
// @Success      200  {object}  domain.Task
// @Failure      400  {object}  ErrorResponse
// @Failure      404  {object}  ErrorResponse
// @Router       /tasks/{id} [get]
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

// save verifies that the referenced target and profile exist, then persists the
// task. It is shared by Create and Update.
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

// Create godoc
// @Summary      Create a task
// @Description  Creates a task binding a target to a profile. Both must already exist.
// @Tags         tasks
// @Accept       json
// @Produce      json
// @Param        task  body      taskRequest  true  "Task to create"
// @Success      201   {object}  domain.Task
// @Failure      400   {object}  ErrorResponse  "Invalid payload or unknown target_id/profile_id"
// @Failure      409   {object}  ErrorResponse
// @Router       /tasks [post]
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

// Update godoc
// @Summary      Replace a task
// @Description  Full replacement of a task by id. The referenced target and profile must exist.
// @Tags         tasks
// @Accept       json
// @Produce      json
// @Param        id    path      int          true  "Task ID"
// @Param        task  body      taskRequest  true  "Replacement task"
// @Success      200   {object}  domain.Task
// @Failure      400   {object}  ErrorResponse  "Invalid payload or unknown target_id/profile_id"
// @Failure      404   {object}  ErrorResponse
// @Failure      409   {object}  ErrorResponse
// @Router       /tasks/{id} [put]
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

// Delete godoc
// @Summary      Delete a task
// @Description  Deletes a task by id. Returns 409 when the task has an active (queued or running) run.
// @Tags         tasks
// @Param        id   path      int  true  "Task ID"
// @Success      204
// @Failure      400  {object}  ErrorResponse
// @Failure      404  {object}  ErrorResponse
// @Failure      409  {object}  ErrorResponse  "Task has an active run"
// @Router       /tasks/{id} [delete]
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
