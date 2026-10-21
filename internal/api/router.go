package api

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	swaggerfiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"

	docs "github.com/mmk31585/Nuclei-manager/docs"
	"github.com/mmk31585/Nuclei-manager/internal/discovery"
	"github.com/mmk31585/Nuclei-manager/internal/domain"
	"github.com/mmk31585/Nuclei-manager/internal/runs"
	"github.com/mmk31585/Nuclei-manager/internal/scope"
)

type Deps struct {
	Ping            func(ctx context.Context) error
	Scope           *scope.Service
	ScopeRepo       domain.ScopeRepo
	Targets         domain.TargetRepo
	TargetEndpoints domain.TargetEndpointRepo
	Profiles        domain.ProfileRepo
	Tasks           domain.TaskRepo
	Runs            *runs.Service
	RunRepo         domain.RunRepo
	Stopper         interface{ Stop(id uint) error }
	DataDir         string
	SwaggerHost     string
	SwaggerBasePath string
	Discovery       *discovery.Worker
}

var swaggerMu sync.Mutex

// dynamicSwaggerHandler returns a gin handler that dynamically sets the Swagger
// Host and BasePath based on the incoming request (or env var overrides), then
// delegates to the standard ginSwagger handler.
func dynamicSwaggerHandler(swaggerHost, basePath string) gin.HandlerFunc {
	handler := ginSwagger.WrapHandler(swaggerfiles.Handler)
	return func(c *gin.Context) {
		swaggerMu.Lock()
		origHost := docs.SwaggerInfo.Host
		origBasePath := docs.SwaggerInfo.BasePath

		// Use the configured host if set, otherwise derive from request.
		if swaggerHost != "" {
			docs.SwaggerInfo.Host = swaggerHost
		} else {
			docs.SwaggerInfo.Host = c.Request.Host
		}
		if basePath != "" {
			docs.SwaggerInfo.BasePath = basePath
		}
		swaggerMu.Unlock()

		defer func() {
			swaggerMu.Lock()
			docs.SwaggerInfo.Host = origHost
			docs.SwaggerInfo.BasePath = origBasePath
			swaggerMu.Unlock()
		}()

		handler(c)
	}
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

	// Interactive OpenAPI documentation (Swagger UI). The host/basePath are
	// derived dynamically from the incoming request so the Swagger UI works
	// behind any reverse proxy or host name.
	if d.SwaggerHost != "" {
		docs.SwaggerInfo.Host = d.SwaggerHost
	}
	if d.SwaggerBasePath != "" {
		docs.SwaggerInfo.BasePath = d.SwaggerBasePath
	}
	r.GET("/swagger/*any", dynamicSwaggerHandler(d.SwaggerHost, d.SwaggerBasePath))

	v1 := r.Group("/api/v1")
	NewScopeHandler(d.ScopeRepo).Register(v1)
	NewTargetHandler(d.Targets, d.Scope, d.Discovery, d.TargetEndpoints).Register(v1)
	NewProfileHandler(d.Profiles).Register(v1)
	NewRunHandler(d.Runs, d.RunRepo, d.Stopper, d.DataDir).Register(v1)
	NewTaskHandler(d.Tasks, d.Targets, d.Profiles).Register(v1)
	return r
}
