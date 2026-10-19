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
