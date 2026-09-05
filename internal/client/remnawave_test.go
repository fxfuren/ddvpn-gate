package client

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGetUserByShortUUIDSupportsCurrentAPIResponse(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer secret-token" {
			t.Fatalf("unexpected authorization header: %q", got)
		}
		if got := r.URL.Path; got != "/api/users/by-short-uuid/6_mX7yVYAHAej2qM" {
			t.Fatalf("unexpected request path: %q", got)
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"response": {
				"username": "alice",
				"tag": "ADMIN",
				"externalSquadUuid": "external-uuid",
				"activeInternalSquads": [
					{"uuid": "default-squad-uuid", "name": "Default Squad"}
				]
			}
		}`))
	}))
	defer server.Close()

	client, err := NewRemnawaveClient(server.URL, "secret-token", "")
	if err != nil {
		t.Fatalf("NewRemnawaveClient() error = %v", err)
	}

	user, err := client.GetUserByShortUUID(context.Background(), "6_mX7yVYAHAej2qM")
	if err != nil {
		t.Fatalf("GetUserByShortUUID() error = %v", err)
	}

	if user.Username != "alice" {
		t.Fatalf("unexpected username: %q", user.Username)
	}
	if user.Tag != "ADMIN" {
		t.Fatalf("unexpected tag: %q", user.Tag)
	}
	if user.ExternalSquadUUID != "external-uuid" {
		t.Fatalf("unexpected external squad uuid: %q", user.ExternalSquadUUID)
	}
	if len(user.ActiveInternalSquads) != 1 {
		t.Fatalf("unexpected active internal squads count: %d", len(user.ActiveInternalSquads))
	}
	if user.ActiveInternalSquads[0].UUID != "default-squad-uuid" {
		t.Fatalf("unexpected internal squad uuid: %q", user.ActiveInternalSquads[0].UUID)
	}
}

func TestGetUserByShortUUIDKeepsBackwardCompatibility(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"response": {
				"username": "bob",
				"tag": "VIP",
				"externalSquadUuid": null,
				"subLastUserAgent": "Mozilla/5.0",
				"subLastOpenedAt": "2026-03-28T09:12:17.000Z",
				"activeInternalSquads": []
			}
		}`))
	}))
	defer server.Close()

	client, err := NewRemnawaveClient(server.URL, "secret-token", "")
	if err != nil {
		t.Fatalf("NewRemnawaveClient() error = %v", err)
	}

	user, err := client.GetUserByShortUUID(context.Background(), "legacy-user")
	if err != nil {
		t.Fatalf("GetUserByShortUUID() error = %v", err)
	}

	if user.Username != "bob" {
		t.Fatalf("unexpected username: %q", user.Username)
	}
	if user.Tag != "VIP" {
		t.Fatalf("unexpected tag: %q", user.Tag)
	}
	if user.ExternalSquadUUID != "" {
		t.Fatalf("unexpected external squad uuid: %q", user.ExternalSquadUUID)
	}
}

func TestGetUserByShortUUIDIncludesHTTPStatusInError(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"message":"user not found"}`, http.StatusNotFound)
	}))
	defer server.Close()

	client, err := NewRemnawaveClient(server.URL, "secret-token", "")
	if err != nil {
		t.Fatalf("NewRemnawaveClient() error = %v", err)
	}

	_, err = client.GetUserByShortUUID(context.Background(), "missing-user")
	if err == nil {
		t.Fatal("GetUserByShortUUID() error = nil, want non-nil")
	}

	if !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("expected ErrUserNotFound, got %v", err)
	}

	if !strings.Contains(err.Error(), "status 404") {
		t.Fatalf("expected error to include status code, got %q", err)
	}
	if !strings.Contains(err.Error(), "user not found") {
		t.Fatalf("expected error to include API message, got %q", err)
	}
}

func TestGetUserByShortUUIDAddsCookieHeaderWhenConfigured(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Cookie"); got != "SjbGIfiP=jCMFSbdy" {
			t.Fatalf("unexpected cookie header: %q", got)
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"response":{"username":"alice","activeInternalSquads":[]}}`))
	}))
	defer server.Close()

	client, err := NewRemnawaveClient(server.URL, "secret-token", "SjbGIfiP=jCMFSbdy")
	if err != nil {
		t.Fatalf("NewRemnawaveClient() error = %v", err)
	}

	if _, err := client.GetUserByShortUUID(context.Background(), "cookie-user"); err != nil {
		t.Fatalf("GetUserByShortUUID() error = %v", err)
	}
}

func TestNewRemnawaveClientRejectsInvalidCookieFormat(t *testing.T) {
	t.Parallel()

	_, err := NewRemnawaveClient("https://example.com", "secret-token", "invalid-cookie-format")
	if err == nil {
		t.Fatal("NewRemnawaveClient() error = nil, want non-nil")
	}

	if !strings.Contains(err.Error(), "invalid EGAMES_COOKIE format") {
		t.Fatalf("expected cookie validation error, got %q", err)
	}
}
