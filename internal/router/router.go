package router

import (
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/fxfuren/ddvpn-gate/internal/handler"
)

// NewRouter создает и настраивает роутер
func NewRouter(healthHandler *handler.HealthHandler, authHandler *handler.AuthHandler) *chi.Mux {
	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.Recoverer)
	r.Use(middleware.RealIP)

	// Routes
	r.Get("/health", healthHandler.ServeHTTP)
	r.Get("/auth", authHandler.VerifyAccess)
	r.Get("/auth-default", authHandler.VerifyDefaultAccess)

	return r
}
