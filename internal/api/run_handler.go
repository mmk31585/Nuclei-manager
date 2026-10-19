package api

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/mmk31585/Nuclei-manager/internal/domain"
	"github.com/mmk31585/Nuclei-manager/internal/runs"
	"github.com/mmk31585/Nuclei-manager/internal/worker"
)

type RunHandler struct {
	svc     *runs.Service
	repo    domain.RunRepo
	stopper interface{ Stop(id uint) error }
	dataDir string
}

func NewRunHandler(svc *runs.Service, repo domain.RunRepo, st interface{ Stop(id uint) error }, dataDir string) *RunHandler {
	return &RunHandler{svc: svc, repo: repo, stopper: st, dataDir: dataDir}
}

func (h *RunHandler) Register(rg *gin.RouterGroup) {
	rg.POST("/tasks/:id/run", h.CreateForTask)
	g := rg.Group("/runs")
	g.GET("", h.List)
	g.GET("/:id", h.Get)
	g.POST("/:id/stop", h.Stop)
	g.GET("/:id/log", h.Log)
	g.GET("/:id/output", h.Output)
}

// runFile builds the path from the numeric id only, never from a stored path.
func (h *RunHandler) runFile(id uint, name string) string {
	return filepath.Join(h.dataDir, "runs", strconv.FormatUint(uint64(id), 10), name)
}

// CreateForTask godoc
// @Summary      Queue a run for a task
// @Description  Validates the task's target/profile against the scope, freezes a config snapshot and queues a run. The worker picks it up and executes Nuclei.
// @Tags         runs
// @Produce      json
// @Param        id   path      int  true  "Task ID"
// @Success      202  {object}  domain.Run
// @Failure      400  {object}  ErrorResponse  "Task not found, or its target is out of scope"
// @Failure      409  {object}  ErrorResponse  "Task already has an active run"
// @Router       /tasks/{id}/run [post]
func (h *RunHandler) CreateForTask(c *gin.Context) {
	id, ok := pathID(c)
	if !ok {
		return
	}
	run, err := h.svc.Create(c.Request.Context(), id, domain.TriggerManual)
	if err != nil {
		writeError(c, err)
		return
	}
	c.JSON(http.StatusAccepted, run)
}

// List godoc
// @Summary      List runs
// @Description  Returns runs ordered by id (newest first). Optionally filter by task_id and/or status.
// @Tags         runs
// @Produce      json
// @Param        task_id  query     int     false  "Filter by task ID"
// @Param        status   query     string  false  "Filter by status (queued, running, completed, failed, timed_out, stopped, cancelled)"
// @Param        limit    query     int     false  "Maximum results (1-200, default 50)"
// @Success      200      {array}   domain.Run
// @Failure      400      {object}  ErrorResponse
// @Failure      500      {object}  ErrorResponse
// @Router       /runs [get]
func (h *RunHandler) List(c *gin.Context) {
	ctx := c.Request.Context()
	f := domain.RunFilter{
		TaskID: parseUintQuery(c, "task_id"),
		Status: parseRunStatusQuery(c, "status"),
		Limit:  parseIntQuery(c, "limit", 50, 200),
	}
	if f.Status == "" && c.Query("status") != "" {
		writeError(c, fmt.Errorf("%w: invalid status", domain.ErrValidation))
		return
	}
	out, err := h.repo.List(ctx, f)
	if err != nil {
		writeError(c, err)
		return
	}
	c.JSON(http.StatusOK, out)
}

// Get godoc
// @Summary      Get a run
// @Description  Returns a single run by id, including timing and finding counters.
// @Tags         runs
// @Produce      json
// @Param        id   path      int  true  "Run ID"
// @Success      200  {object}  domain.Run
// @Failure      400  {object}  ErrorResponse
// @Failure      404  {object}  ErrorResponse
// @Router       /runs/{id} [get]
func (h *RunHandler) Get(c *gin.Context) {
	id, ok := pathID(c)
	if !ok {
		return
	}
	run, err := h.repo.Get(c.Request.Context(), id)
	if err != nil {
		writeError(c, err)
		return
	}
	c.JSON(http.StatusOK, run)
}

// Stop godoc
// @Summary      Stop a run
// @Description  Cancels a queued run, or asks the worker to stop a running run. Stopping a running run is asynchronous.
// @Tags         runs
// @Produce      json
// @Param        id   path      int  true  "Run ID"
// @Success      200  {object}  domain.Run             "Run cancelled while still queued"
// @Success      202  {object}  object{status=string}  "Stop requested for a running run"
// @Failure      400  {object}  ErrorResponse
// @Failure      404  {object}  ErrorResponse
// @Failure      409  {object}  ErrorResponse  "Run already finished or is not active on this instance"
// @Router       /runs/{id}/stop [post]
func (h *RunHandler) Stop(c *gin.Context) {
	id, ok := pathID(c)
	if !ok {
		return
	}
	ctx := c.Request.Context()
	run, err := h.repo.Get(ctx, id)
	if err != nil {
		writeError(c, err)
		return
	}
	if run.Status.Terminal() {
		writeError(c, fmt.Errorf("%w: run already finished (%s)", domain.ErrConflict, run.Status))
		return
	}
	if run.Status == domain.RunQueued {
		cancelled, err := h.repo.CancelQueued(ctx, id)
		if err != nil {
			writeError(c, err)
			return
		}
		if cancelled {
			updated, err := h.repo.Get(ctx, id)
			if err != nil {
				writeError(c, err)
				return
			}
			c.JSON(http.StatusOK, updated)
			return
		}
		// it was claimed in the meantime: stop the active run below
	}
	// The worker registers a claimed run a few milliseconds after the claim: retry briefly.
	for i := 0; i < 10; i++ {
		err = h.stopper.Stop(id)
		if !errors.Is(err, worker.ErrNotActive) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if errors.Is(err, worker.ErrNotActive) {
		writeError(c, fmt.Errorf("%w: run is not active on this instance", domain.ErrConflict))
		return
	}
	if err != nil {
		writeError(c, err)
		return
	}
	c.JSON(http.StatusAccepted, gin.H{"status": "stopping"})
}

// Log godoc
// @Summary      Read run log
// @Description  Returns a UTF-8 page of the run's supervisor log starting at a byte offset. Pass next_offset back to tail.
// @Tags         runs
// @Produce      json
// @Param        id      path      int   true  "Run ID"
// @Param        offset  query     int   false  "Byte offset to start from (default 0)"
// @Param        limit   query     int   false  "Maximum bytes to return (default 65536, max 1048576)"
// @Success      200     {object}  LogChunk
// @Failure      400     {object}  ErrorResponse
// @Failure      404     {object}  ErrorResponse
// @Router       /runs/{id}/log [get]
func (h *RunHandler) Log(c *gin.Context) {
	id, ok := pathID(c)
	if !ok {
		return
	}
	if _, err := h.repo.Get(c.Request.Context(), id); err != nil {
		writeError(c, err)
		return
	}
	offset, _ := strconv.ParseInt(c.DefaultQuery("offset", "0"), 10, 64)
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "65536"))
	if offset < 0 {
		offset = 0
	}
	if limit <= 0 || limit > 1<<20 {
		limit = 65536
	}
	data, next, eof, err := readChunk(h.runFile(id, "run.log"), offset, limit)
	if errors.Is(err, os.ErrNotExist) {
		c.JSON(http.StatusOK, gin.H{"offset": offset, "next_offset": offset, "eof": true, "data": ""})
		return
	}
	if err != nil {
		writeError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"offset": offset, "next_offset": next, "eof": eof, "data": data})
}

// Output godoc
// @Summary      Download raw run output
// @Description  Downloads the raw Nuclei JSONL results for a run as application/x-ndjson.
// @Tags         runs
// @Produce      application/x-ndjson
// @Param        id   path      int  true  "Run ID"
// @Success      200  {string}  binary  "Newline-delimited JSON results"
// @Failure      400  {object}  ErrorResponse
// @Failure      404  {object}  ErrorResponse  "No output yet"
// @Router       /runs/{id}/output [get]
func (h *RunHandler) Output(c *gin.Context) {
	id, ok := pathID(c)
	if !ok {
		return
	}
	if _, err := h.repo.Get(c.Request.Context(), id); err != nil {
		writeError(c, err)
		return
	}
	p := h.runFile(id, "output.jsonl")
	if _, err := os.Stat(p); err != nil {
		writeError(c, fmt.Errorf("%w: no output yet", domain.ErrNotFound))
		return
	}
	c.Header("Content-Type", "application/x-ndjson")
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="run-%d.jsonl"`, id))
	c.File(p)
}

// readChunk reads up to limit bytes from offset, cutting at the last newline unless at EOF.
func readChunk(path string, offset int64, limit int) (string, int64, bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", offset, true, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return "", offset, true, err
	}
	if offset >= st.Size() {
		return "", st.Size(), true, nil
	}
	buf := make([]byte, limit)
	n, err := f.ReadAt(buf, offset)
	if err != nil && !errors.Is(err, io.EOF) {
		return "", offset, false, err
	}
	buf = buf[:n]
	end := offset + int64(n)
	eof := end >= st.Size()
	if !eof {
		if i := bytes.LastIndexByte(buf, '\n'); i >= 0 {
			buf = buf[:i+1]
			end = offset + int64(len(buf))
		}
	}
	return strings.ToValidUTF8(string(buf), "\uFFFD"), end, eof, nil
}

func parseUintQuery(c *gin.Context, key string) uint {
	v := c.Query(key)
	if v == "" {
		return 0
	}
	n, _ := strconv.ParseUint(v, 10, 64)
	return uint(n)
}

func parseRunStatusQuery(c *gin.Context, key string) domain.RunStatus {
	v := c.Query(key)
	if v == "" {
		return ""
	}
	s := domain.RunStatus(v)
	if !s.Valid() {
		return ""
	}
	return s
}

func parseIntQuery(c *gin.Context, key string, def, max int) int {
	v := c.Query(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 || n > max {
		return def
	}
	return n
}
