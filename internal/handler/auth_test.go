package handler

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fxfuren/ddvpn-gate/internal/client"
	"github.com/fxfuren/ddvpn-gate/internal/config"
	"github.com/fxfuren/ddvpn-gate/internal/service"
	"github.com/sirupsen/logrus"
)

func TestVerifyDefaultAccessSkipsClientFilter(t *testing.T) {
	t.Parallel()

	handler := newTestAuthHandler(t, `{
		"response": {
			"username": "default-user",
			"tag": "BASIC",
			"externalSquadUuid": "",
			"activeInternalSquads": [
				{"uuid": "default-squad-uuid", "name": "Default Squad"}
			]
		}
	}`)

	req := httptest.NewRequest(http.MethodGet, "/auth-default", nil)
	req.Header.Set("X-Original-URI", "/GfWoC3deZHz45E3s")
	req.Header.Set("User-Agent", "clash-verge/v2.4.4+autobuild.1129.45d4f0e")
	rec := httptest.NewRecorder()

	handler.VerifyDefaultAccess(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected /auth-default to ignore client filter and return 200, got %d", rec.Code)
	}
}

func TestVerifyAccessStillAppliesClientFilter(t *testing.T) {
	t.Parallel()

	handler := newTestAuthHandler(t, `{
		"response": {
			"username": "bypass-user",
			"tag": "BASIC",
			"externalSquadUuid": "allowed-squad-uuid",
			"activeInternalSquads": []
		}
	}`)

	req := httptest.NewRequest(http.MethodGet, "/auth", nil)
	req.Header.Set("X-Original-URI", "/GfWoC3deZHz45E3s")
	req.Header.Set("User-Agent", "clash-verge/v2.4.4+autobuild.1129.45d4f0e")
	rec := httptest.NewRecorder()

	handler.VerifyAccess(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected /auth to keep client filter and return 403, got %d", rec.Code)
	}
}

func TestVerifyAccessAllowsMobileUserInAllowedSquadWithoutPCTag(t *testing.T) {
	t.Parallel()

	handler := newTestAuthHandler(t, `{
		"response": {
			"username": "mobile-user",
			"tag": "BASIC",
			"externalSquadUuid": "allowed-squad-uuid",
			"activeInternalSquads": []
		}
	}`)

	req := httptest.NewRequest(http.MethodGet, "/auth", nil)
	req.Header.Set("X-Original-URI", "/GfWoC3deZHz45E3s")
	req.Header.Set("User-Agent", "Happ/4.7.3/ios/2604120049648")
	rec := httptest.NewRecorder()

	handler.VerifyAccess(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected mobile user in allowed squad to return 200, got %d", rec.Code)
	}
}

func TestVerifyAccessBlocksDesktopUserInAllowedSquadWithoutPCTag(t *testing.T) {
	t.Parallel()

	handler := newTestAuthHandler(t, `{
		"response": {
			"username": "desktop-user",
			"tag": "BASIC",
			"externalSquadUuid": "allowed-squad-uuid",
			"activeInternalSquads": []
		}
	}`)

	req := httptest.NewRequest(http.MethodGet, "/auth", nil)
	req.Header.Set("X-Original-URI", "/GfWoC3deZHz45E3s")
	req.Header.Set("User-Agent", "Happ/2.8.0/Windows/2604081205607")
	rec := httptest.NewRecorder()

	handler.VerifyAccess(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected desktop user without PC tag to return 403, got %d", rec.Code)
	}
}

func TestVerifyAccessAllowsDesktopUserInAllowedSquadWithPCTag(t *testing.T) {
	t.Parallel()

	handler := newTestAuthHandler(t, `{
		"response": {
			"username": "desktop-user",
			"tag": "BYPASS-PC",
			"externalSquadUuid": "allowed-squad-uuid",
			"activeInternalSquads": []
		}
	}`)

	req := httptest.NewRequest(http.MethodGet, "/auth", nil)
	req.Header.Set("X-Original-URI", "/GfWoC3deZHz45E3s")
	req.Header.Set("User-Agent", "Happ/2.8.0/Windows/2604081205607")
	rec := httptest.NewRecorder()

	handler.VerifyAccess(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected desktop user with PC tag to return 200, got %d", rec.Code)
	}
}

func newTestAuthHandler(t *testing.T, responseBody string) *AuthHandler {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(responseBody))
	}))
	t.Cleanup(server.Close)

	remnawaveClient, err := client.NewRemnawaveClient(server.URL, "secret-token", "")
	if err != nil {
		t.Fatalf("NewRemnawaveClient() error = %v", err)
	}

	logger := logrus.New()
	logger.SetOutput(io.Discard) // Disable logs during tests

	panelState := service.NewPanelState()

	cfg := &config.Config{
		AllowedSquadID:    "allowed-squad-uuid",
		DefaultSquadID:    "default-squad-uuid",
		BypassTag:         "ADMIN",
		BypassPCTag:       "BYPASS-PC",
		AllowedClientApps: []string{"happ", "v2raytun", "incy"},
	}

	authService := service.NewAuthService(remnawaveClient, cfg, logger, panelState)
	return NewAuthHandler(authService, logger)
}
