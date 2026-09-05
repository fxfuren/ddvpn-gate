package handler

import (
	"net/http"

	"github.com/fxfuren/ddvpn-gate/internal/service"
	"github.com/sirupsen/logrus"
)

// AuthHandler обрабатывает запросы авторизации
type AuthHandler struct {
	authService *service.AuthService
	logger      *logrus.Logger
}

// NewAuthHandler создает новый обработчик авторизации
func NewAuthHandler(authService *service.AuthService, logger *logrus.Logger) *AuthHandler {
	return &AuthHandler{
		authService: authService,
		logger:      logger,
	}
}

// VerifyAccess обрабатывает запрос проверки доступа по external squad (/auth)
func (h *AuthHandler) VerifyAccess(w http.ResponseWriter, r *http.Request) {
	// Получаем заголовок X-Original-URI
	originalURI := r.Header.Get("X-Original-URI")
	if originalURI == "" {
		h.logger.Warn("⛔ No X-Original-URI header provided")
		w.WriteHeader(http.StatusForbidden)
		return
	}

	h.logger.Infof("🔍 Incoming request: %s", originalURI)

	if !h.authService.IsPanelAvailable() {
		h.logger.Infof("⚠️ Panel is unavailable, bypassing auth and client checks for %s", originalURI)
		w.WriteHeader(http.StatusOK)
		return
	}

	clientResult := h.authService.VerifyClientAccess(service.ClientRequest{
		Accept:    r.Header.Get("Accept"),
		UserAgent: r.UserAgent(),
		DeviceOS:  r.Header.Get("X-Device-OS"),
	})
	if !clientResult.Allowed {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	// Парсим shortUUID из URI
	shortUUID, err := h.authService.ParseShortUUID(originalURI)
	if err != nil {
		h.logger.Errorf("❌ Failed to parse URI: %s", originalURI)
		w.WriteHeader(http.StatusForbidden)
		return
	}

	// Проверяем доступ
	result := h.authService.VerifyAccessWithPCRequirement(
		r.Context(),
		shortUUID,
		clientResult.Reason == "desktop_client_needs_pc_tag",
	)
	if result.Allowed {
		w.WriteHeader(http.StatusOK)
	} else if result.Reason == "user_not_found" {
		w.WriteHeader(http.StatusUnauthorized)
	} else {
		w.WriteHeader(http.StatusForbidden)
	}
}

// VerifyDefaultAccess обрабатывает запрос проверки доступа по default internal squad (/auth-default)
func (h *AuthHandler) VerifyDefaultAccess(w http.ResponseWriter, r *http.Request) {
	// Получаем заголовок X-Original-URI
	originalURI := r.Header.Get("X-Original-URI")
	if originalURI == "" {
		h.logger.Warn("⛔ No X-Original-URI header provided (default)")
		w.WriteHeader(http.StatusForbidden)
		return
	}

	h.logger.Infof("🔍 Incoming request (default): %s", originalURI)

	if !h.authService.IsPanelAvailable() {
		h.logger.Infof("⚠️ Panel is unavailable, bypassing auth checks for %s", originalURI)
		w.WriteHeader(http.StatusOK)
		return
	}

	// Парсим shortUUID из URI
	shortUUID, err := h.authService.ParseShortUUID(originalURI)
	if err != nil {
		h.logger.Errorf("❌ Failed to parse URI: %s", originalURI)
		w.WriteHeader(http.StatusForbidden)
		return
	}

	// Проверяем доступ
	result := h.authService.VerifyDefaultAccess(r.Context(), shortUUID)
	if result.Allowed {
		w.WriteHeader(http.StatusOK)
	} else if result.Reason == "user_not_found" {
		w.WriteHeader(http.StatusUnauthorized)
	} else {
		w.WriteHeader(http.StatusForbidden)
	}
}
