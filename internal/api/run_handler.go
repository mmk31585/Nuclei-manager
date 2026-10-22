package api

import (
	"bufio"
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
	"github.com/jung-kurt/gofpdf"

	"github.com/mmk31585/Nuclei-manager/internal/domain"
	"github.com/mmk31585/Nuclei-manager/internal/runs"
	"github.com/mmk31585/Nuclei-manager/internal/scanner/nuclei"
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
	g.GET("/:id/output.pdf", h.OutputPDF)
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
// @Param        status   query     string  false  "Filter by status"  Enums(queued, running, processing, completed, failed, timed_out, stopped, cancelled)
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
	lines := []string{}
	if data != "" {
		lines = strings.Split(strings.TrimRight(data, "\n"), "\n")
	}
	c.JSON(http.StatusOK, gin.H{"offset": offset, "next_offset": next, "eof": eof, "data": data, "lines": lines})
}

// Output godoc
// @Summary      Download raw run output
// @Description  Downloads the raw Nuclei JSONL results for a run as application/x-ndjson. Use ?format=pdf to get a PDF report instead. The results of the web pass and of the optional network pass are merged; pass "pass=web" or "pass=network" to download only one of them. Returns 204 if the run produced no findings.
// @Tags         runs
// @Produce      application/x-ndjson
// @Produce      application/pdf
// @Param        id     path      string  true  "Run ID"
// @Param        pass   query     string  false "Only return the given pass"  Enums(web, network)
// @Param        format query     string  false "Output format"                 Enums(json, pdf)
// @Success      200  {string}  binary  "Newline-delimited JSON results or PDF report"
// @Success      204  "No findings produced"
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
	format := c.DefaultQuery("format", "json")
	switch format {
	case "json", "pdf":
	default:
		writeError(c, fmt.Errorf("%w: invalid format", domain.ErrValidation))
		return
	}

	if format == "pdf" {
		h.OutputPDF(c)
		return
	}

	pass := c.DefaultQuery("pass", "")
	switch pass {
	case "", "web", "network":
	default:
		writeError(c, fmt.Errorf("%w: invalid pass", domain.ErrValidation))
		return
	}

	webPath := h.runFile(id, "output.jsonl")
	networkPath := h.runFile(id, "network.jsonl")
	paths := []string{webPath}
	if pass != "web" {
		paths = append(paths, networkPath)
	}

	// The passes keep their own file on disk, the download merges them.
	var files []string
	var size int64
	var found bool
	for _, p := range paths {
		fi, err := os.Stat(p)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			writeError(c, err)
			return
		}
		found = true
		if fi.Size() == 0 {
			continue
		}
		files = append(files, p)
		size += fi.Size()
	}
	if !found {
		writeError(c, fmt.Errorf("%w: no output yet", domain.ErrNotFound))
		return
	}
	if size == 0 {
		c.Status(http.StatusNoContent)
		return
	}
	c.Header("Content-Type", "application/x-ndjson")
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="run-%d.jsonl"`, id))
	c.Status(http.StatusOK)
	for _, p := range files {
		f, err := os.Open(p)
		if err != nil {
			return
		}
		_, err = io.Copy(c.Writer, f)
		f.Close()
		if err != nil {
			return
		}
	}
}

// OutputPDF godoc
// @Summary      Download run output as PDF
// @Description  Generates and downloads a PDF report of the run's Nuclei findings (web + network passes merged). Returns 204 if the run produced no findings.
// @Tags         runs
// @Produce      application/pdf
// @Param        id   path      int    true   "Run ID"
// @Success      200  {string}  binary  "PDF report"
// @Success      204  "No findings produced"
// @Failure      400  {object}  ErrorResponse
// @Failure      404  {object}  ErrorResponse  "No output yet"
// @Router       /runs/{id}/output.pdf [get]
func (h *RunHandler) OutputPDF(c *gin.Context) {
	id, ok := pathID(c)
	if !ok {
		return
	}
	if _, err := h.repo.Get(c.Request.Context(), id); err != nil {
		writeError(c, err)
		return
	}

	webPath := h.runFile(id, "output.jsonl")
	networkPath := h.runFile(id, "network.jsonl")

	var events []*nuclei.Event
	for _, p := range []string{webPath, networkPath} {
		f, err := os.Open(p)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			writeError(c, err)
			return
		}
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 1024*1024), 16*1024*1024)
		for scanner.Scan() {
			line := bytes.TrimSpace(scanner.Bytes())
			if len(line) == 0 {
				continue
			}
			ev, err := nuclei.ParseLine(line)
			if err != nil {
				continue
			}
			events = append(events, ev)
		}
		f.Close()
	}

	if len(events) == 0 {
		c.Status(http.StatusNoContent)
		return
	}

	pdf := buildRunPDF(id, events)
	c.Header("Content-Type", "application/pdf")
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="run-%d.pdf"`, id))
	c.Status(http.StatusOK)
	if err := pdf.Output(c.Writer); err != nil {
		return
	}
}

var severityColors = map[string]struct{ r, g, b int }{
	"critical": {r: 220, g: 20, b: 20},
	"high":     {r: 200, g: 80, b: 0},
	"medium":   {r: 220, g: 150, b: 0},
	"low":      {r: 30, g: 140, b: 200},
	"info":     {r: 100, g: 100, b: 100},
}

func buildRunPDF(id uint, events []*nuclei.Event) *gofpdf.Fpdf {
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.AddPage()
	pdf.SetMargins(15, 15, 15)

	// Header
	pdf.SetFont("Arial", "B", 16)
	pdf.SetTextColor(30, 30, 30)
	pdf.Cell(0, 10, fmt.Sprintf("Nuclei Scan Report - Run #%d", id))
	pdf.Ln(6)
	pdf.SetFont("Arial", "", 9)
	pdf.SetTextColor(80, 80, 80)
	pdf.Cell(0, 5, fmt.Sprintf("Generated from raw Nuclei JSONL results for run ID %d", id))
	pdf.Ln(12)

	// Summary counts
	counts := map[string]int{}
	for _, ev := range events {
		counts[ev.Info.Severity]++
	}
	pdf.SetFont("Arial", "B", 12)
	pdf.Cell(0, 8, "Summary")
	pdf.Ln(7)
	pdf.SetFont("Arial", "", 10)
	severityOrder := []string{"critical", "high", "medium", "low", "info"}
	for _, sev := range severityOrder {
		if n := counts[sev]; n > 0 {
			col := severityColors[sev]
			pdf.SetTextColor(col.r, col.g, col.b)
			pdf.Cell(0, 6, fmt.Sprintf("  %s: %d", strings.ToUpper(sev), n))
			pdf.Ln(6)
			pdf.SetTextColor(0, 0, 0)
		}
	}
	pdf.Cell(0, 6, fmt.Sprintf("  Total findings: %d", len(events)))
	pdf.Ln(14)

	// Findings table header
	pdf.SetFont("Arial", "B", 8)
	pdf.SetFillColor(220, 220, 220)
	pdf.CellFormat(15, 7, "Severity", "1", 0, "C", true, 0, "")
	pdf.CellFormat(30, 7, "Template ID", "1", 0, "C", true, 0, "")
	pdf.CellFormat(48, 7, "Template Name", "1", 0, "C", true, 0, "")
	pdf.CellFormat(38, 7, "Host", "1", 0, "C", true, 0, "")
	pdf.CellFormat(32, 7, "Matched At", "1", 0, "C", true, 0, "")
	pdf.CellFormat(30, 7, "Type", "1", 0, "C", true, 0, "")
	pdf.Ln(7)

	// Findings rows
	pdf.SetFont("Arial", "", 7)
	pageRows := 0
	maxRowsPerPage := 45
	for _, ev := range events {
		if pageRows >= maxRowsPerPage {
			pdf.AddPage()
			// repeat table header
			pdf.SetFont("Arial", "B", 8)
			pdf.SetFillColor(220, 220, 220)
			pdf.CellFormat(15, 7, "Severity", "1", 0, "C", true, 0, "")
			pdf.CellFormat(30, 7, "Template ID", "1", 0, "C", true, 0, "")
			pdf.CellFormat(48, 7, "Template Name", "1", 0, "C", true, 0, "")
			pdf.CellFormat(38, 7, "Host", "1", 0, "C", true, 0, "")
			pdf.CellFormat(32, 7, "Matched At", "1", 0, "C", true, 0, "")
			pdf.CellFormat(30, 7, "Type", "1", 0, "C", true, 0, "")
			pdf.Ln(7)
			pdf.SetFont("Arial", "", 7)
			pageRows = 0
		}
		col := severityColors[ev.Info.Severity]
		pdf.SetTextColor(col.r, col.g, col.b)
		pdf.CellFormat(15, 5, strings.ToUpper(ev.Info.Severity), "1", 0, "C", false, 0, "")
		pdf.SetTextColor(0, 0, 0)
		pdf.CellFormat(30, 5, truncate(ev.TemplateID, 28), "1", 0, "L", false, 0, "")
		pdf.CellFormat(48, 5, truncate(ev.Info.Name, 42), "1", 0, "L", false, 0, "")
		pdf.CellFormat(38, 5, truncate(ev.Host, 34), "1", 0, "L", false, 0, "")
		pdf.CellFormat(32, 5, truncate(ev.MatchedAt, 30), "1", 0, "L", false, 0, "")
		pdf.CellFormat(30, 5, truncate(ev.Type, 28), "1", 0, "L", false, 0, "")
		pdf.Ln(5)
		pageRows++
	}

	return pdf
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
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
