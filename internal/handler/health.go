package handler

import (
	"encoding/json"
	"net/http"
)

// HealthResponse представляет ответ health check
type HealthResponse struct {
	Status string `json:"status"`
}

// HealthHandler обрабатывает запросы health check
type HealthHandler struct{}

// NewHealthHandler создает новый обработчик health check
func NewHealthHandler() *HealthHandler {
	return &HealthHandler{}
}

// ServeHTTP обрабатывает HTTP запрос
func (h *HealthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(HealthResponse{Status: "ok"})
}
