package service

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fxfuren/ddvpn-gate/internal/client"
	"github.com/fxfuren/ddvpn-gate/internal/config"
	"github.com/sirupsen/logrus"
)

func TestVerifyClientAccessAllowsBrowserRequests(t *testing.T) {
	t.Parallel()

	service := newTestAuthService()

	result := service.VerifyClientAccess(ClientRequest{
		Accept:    "text/html,application/xhtml+xml",
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
	})

	if !result.Allowed {
		t.Fatalf("expected browser request to be allowed, got %+v", result)
	}
}

func TestVerifyClientAccessAllowsConfiguredMobileClient(t *testing.T) {
	t.Parallel()

	service := newTestAuthService()

	result := service.VerifyClientAccess(ClientRequest{
		UserAgent: "Happ/4.7.3/ios/2604120049648",
	})

	if !result.Allowed {
		t.Fatalf("expected mobile Happ request to be allowed, got %+v", result)
	}
}

func TestVerifyClientAccessAllowsDesktopClientForUserCheck(t *testing.T) {
	t.Parallel()

	service := newTestAuthService()

	result := service.VerifyClientAccess(ClientRequest{
		UserAgent: "Happ/2.8.0/Windows/2604081205607",
	})

	if !result.Allowed || result.Reason != "desktop_client_needs_pc_tag" {
		t.Fatalf("expected desktop Happ request to require PC tag, got %+v", result)
	}
}

func TestVerifyClientAccessUsesXDeviceOSWhenPresent(t *testing.T) {
	t.Parallel()

	service := newTestAuthService()

	result := service.VerifyClientAccess(ClientRequest{
		UserAgent: "v2raytun/unknown",
		DeviceOS:  "Android",
	})

	if !result.Allowed {
		t.Fatalf("expected X-Device-OS to allow mobile request, got %+v", result)
	}
}

func TestVerifyClientAccessBlocksUnknownClient(t *testing.T) {
	t.Parallel()

	service := newTestAuthService()

	result := service.VerifyClientAccess(ClientRequest{
		UserAgent: "SomeOtherClient/ios",
	})

	if result.Allowed {
		t.Fatalf("expected unknown client to be denied, got %+v", result)
	}
}

func newTestAuthService() *AuthService {
	log := logrus.New()
	log.SetOutput(io.Discard)

	return NewAuthService(nil, &config.Config{
		AllowedClientApps: []string{"happ", "v2raytun", "incy"},
		BypassTag:         "ADMIN",
		BypassPCTag:       "BYPASS-PC",
	}, log, NewPanelState())
}

func TestVerifyAccessPassesThroughWhenUserNotFound(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"message":"user not found"}`, http.StatusNotFound)
	}))
	defer server.Close()

	remnawaveClient, err := client.NewRemnawaveClient(server.URL, "secret-token", "")
	if err != nil {
		t.Fatalf("NewRemnawaveClient() error = %v", err)
	}

	log := logrus.New()
	log.SetOutput(io.Discard)

	cfg := &config.Config{
		AllowedSquadID: "allowed-squad",
		BypassTag:      "ADMIN",
		BypassPCTag:    "BYPASS-PC",
	}

	svc := NewAuthService(remnawaveClient, cfg, log, NewPanelState())
	result := svc.VerifyAccess(context.Background(), "nonexistent-user")

	if !result.Allowed {
		t.Fatalf("expected 404 to be allowed (passthrough), got %+v", result)
	}
	if result.Reason != "user_not_found_passthrough" {
		t.Fatalf("expected reason 'user_not_found_passthrough', got %q", result.Reason)
	}
}

func TestVerifyDefaultAccessPassesThroughWhenUserNotFound(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"message":"user not found"}`, http.StatusNotFound)
	}))
	defer server.Close()

	remnawaveClient, err := client.NewRemnawaveClient(server.URL, "secret-token", "")
	if err != nil {
		t.Fatalf("NewRemnawaveClient() error = %v", err)
	}

	log := logrus.New()
	log.SetOutput(io.Discard)

	cfg := &config.Config{
		DefaultSquadID: "default-squad",
		BypassTag:      "ADMIN",
	}

	svc := NewAuthService(remnawaveClient, cfg, log, NewPanelState())
	result := svc.VerifyDefaultAccess(context.Background(), "nonexistent-user")

	if !result.Allowed {
		t.Fatalf("expected 404 to be allowed (passthrough), got %+v", result)
	}
	if result.Reason != "user_not_found_passthrough" {
		t.Fatalf("expected reason 'user_not_found_passthrough', got %q", result.Reason)
	}
}
