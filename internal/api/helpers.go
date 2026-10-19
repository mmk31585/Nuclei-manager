package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/mmk31585/Nuclei-manager/internal/domain"
)

func pathID(c *gin.Context) (uint, bool) {
	n, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil || n == 0 {
		writeError(c, fmt.Errorf("%w: invalid id", domain.ErrValidation))
		return 0, false
	}
	return uint(n), true
}

func bindJSON(c *gin.Context, dst any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(c.Writer, c.Request.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeError(c, fmt.Errorf("%w: invalid JSON body", domain.ErrValidation))
		return false
	}
	return true
}
