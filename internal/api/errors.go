package api

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/mmk31585/Nuclei-manager/internal/domain"
	"github.com/mmk31585/Nuclei-manager/internal/scope"
)

// ErrorResponse is the standard error envelope returned by every endpoint.
type ErrorResponse struct {
	// Human-readable error message
	Error string `json:"error" example:"validation failed: name is required"`
}

// LogChunk is a UTF-8 page of a run's supervisor log.
type LogChunk struct {
	// Byte offset this chunk starts at
	Offset int64 `json:"offset"`
	// Offset to pass as the next page's offset when tailing
	NextOffset int64 `json:"next_offset"`
	// True when there is no more data after this chunk
	Eof bool `json:"eof"`
	// Decoded text chunk (invalid bytes replaced)
	Data string `json:"data"`
	// Decoded text chunk split into individual lines for easier reading
	Lines []string `json:"lines"`
}

func writeError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, domain.ErrValidation):
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	case errors.Is(err, scope.ErrOutOfScope):
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
	case errors.Is(err, domain.ErrNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
	case errors.Is(err, domain.ErrConflict):
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
	default:
		slog.Error("internal error", "err", err, "path", c.FullPath())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
	}
}
