package service

import (
	"io"
	"testing"

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

func TestVerifyClientAccessBlocksDesktopClient(t *testing.T) {
	t.Parallel()

	service := newTestAuthService()

	result := service.VerifyClientAccess(ClientRequest{
		UserAgent: "Happ/2.8.0/Windows/2604081205607",
	})

	if result.Allowed {
		t.Fatalf("expected desktop Happ request to be denied, got %+v", result)
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
		AllowedClientApps: []string{"happ", "v2raytun"},
		BypassTag:         "ADMIN",
	}, log)
}
