package api

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/mmk31585/Nuclei-manager/internal/domain"
	"github.com/mmk31585/Nuclei-manager/internal/runs"
	"github.com/mmk31585/Nuclei-manager/internal/scope"
)

type Deps struct {
	Ping      func(ctx context.Context) error
	Scope     *scope.Service
	ScopeRepo domain.ScopeRepo
	Targets   domain.TargetRepo
	Profiles  domain.ProfileRepo
	Tasks     domain.TaskRepo
	Runs      *runs.Service
	RunRepo   domain.RunRepo
	Stopper   interface{ Stop(id uint) error }
	DataDir   string
}

func NewRouter(d Deps) *gin.Engine {
	r := gin.New()
	_ = r.SetTrustedProxies(nil)
	r.Use(gin.Recovery(), requestLogger())

	r.GET("/healthz", func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
		defer cancel()
		if err := d.Ping(ctx); err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"status": "unhealthy"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	v1 := r.Group("/api/v1")
	NewScopeHandler(d.ScopeRepo).Register(v1)
	NewTargetHandler(d.Targets, d.Scope).Register(v1)
	NewProfileHandler(d.Profiles).Register(v1)
	NewTaskHandler(d.Tasks, d.Targets, d.Profiles).Register(v1)
	NewRunHandler(d.Runs, d.RunRepo, d.Stopper, d.DataDir).Register(v1)
	return r
}
