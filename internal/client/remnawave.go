package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrPanelUnavailable indicates that the Remnawave panel is unreachable or returning 5xx errors.
var ErrPanelUnavailable = errors.New("panel is unreachable")

// ErrUserNotFound indicates that the user was not found in Remnawave (404 Not Found).
var ErrUserNotFound = errors.New("user not found")

const remnawaveResponseLimit = 1 << 20

// RemnawaveClient wraps HTTP access to the Remnawave API.
type RemnawaveClient struct {
	baseURL    string
	token      string
	egamesCookie string
	httpClient *http.Client
}

// UserData contains the user fields required for authorization checks.
type UserData struct {
	Username             string
	Tag                  string
	ExternalSquadUUID    string
	ActiveInternalSquads []InternalSquad
}

// InternalSquad represents a user's internal squad.
type InternalSquad struct {
	UUID string
	Name string
}

type userResponse struct {
	Response userItemInfo `json:"response"`
}

type userItemInfo struct {
	Username             string          `json:"username"`
	Tag                  *string         `json:"tag"`
	ExternalSquadUUID    *string         `json:"externalSquadUuid"`
	ActiveInternalSquads []internalSquad `json:"activeInternalSquads"`
}

type internalSquad struct {
	UUID string `json:"uuid"`
	Name string `json:"name"`
}

type apiErrorResponse struct {
	Message  string `json:"message"`
	Error    string `json:"error"`
	Response struct {
		Message string `json:"message"`
		Error   string `json:"error"`
	} `json:"response"`
}

// NewRemnawaveClient creates a new Remnawave client.
func NewRemnawaveClient(baseURL, token, egamesCookie string) (*RemnawaveClient, error) {
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse remnawave base URL: %w", err)
	}
	if parsedURL.Scheme == "" || parsedURL.Host == "" {
		return nil, fmt.Errorf("invalid remnawave base URL: %q", baseURL)
	}

	cookieHeader, err := normalizeCookieHeader(egamesCookie)
	if err != nil {
		return nil, err
	}

	return &RemnawaveClient{
		baseURL:      strings.TrimRight(baseURL, "/"),
		token:        token,
		egamesCookie: cookieHeader,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}, nil
}

// GetUserByShortUUID fetches a user by short UUID.
func (r *RemnawaveClient) GetUserByShortUUID(ctx context.Context, shortUUID string) (*UserData, error) {
	endpoint, err := url.JoinPath(r.baseURL, "api/users/by-short-uuid", shortUUID)
	if err != nil {
		return nil, fmt.Errorf("failed to build user lookup URL: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create user lookup request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+r.token)
	if r.egamesCookie != "" {
		req.Header.Set("Cookie", r.egamesCookie)
	}

	resp, err := r.httpClient.Do(req)
	if err != nil {
		if isNetworkError(err) {
			return nil, fmt.Errorf("%w: %v", ErrPanelUnavailable, err)
		}
		return nil, fmt.Errorf("failed to get user by short uuid: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, remnawaveResponseLimit))
		return nil, fmt.Errorf("%w: status %d: %s", ErrUserNotFound, resp.StatusCode, extractAPIError(body))
	}

	if resp.StatusCode >= http.StatusInternalServerError {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, remnawaveResponseLimit))
		return nil, fmt.Errorf("%w: status %d: %s", ErrPanelUnavailable, resp.StatusCode, extractAPIError(body))
	}

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, remnawaveResponseLimit))
		return nil, fmt.Errorf("failed to get user by short uuid: status %d: %s", resp.StatusCode, extractAPIError(body))
	}

	var payload userResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, remnawaveResponseLimit)).Decode(&payload); err != nil {
		return nil, fmt.Errorf("failed to get user by short uuid: decode response: %w", err)
	}

	return payload.Response.toUserData(), nil
}

func (u userItemInfo) toUserData() *UserData {
	userData := &UserData{
		Username: u.Username,
	}

	if u.Tag != nil {
		userData.Tag = *u.Tag
	}

	if u.ExternalSquadUUID != nil {
		userData.ExternalSquadUUID = *u.ExternalSquadUUID
	}

	for _, squad := range u.ActiveInternalSquads {
		userData.ActiveInternalSquads = append(userData.ActiveInternalSquads, InternalSquad{
			UUID: squad.UUID,
			Name: squad.Name,
		})
	}

	return userData
}

func extractAPIError(body []byte) string {
	bodyText := strings.TrimSpace(string(body))
	if bodyText == "" {
		return "empty response body"
	}

	var apiErr apiErrorResponse
	if err := json.Unmarshal(body, &apiErr); err == nil {
		switch {
		case apiErr.Message != "":
			return apiErr.Message
		case apiErr.Error != "":
			return apiErr.Error
		case apiErr.Response.Message != "":
			return apiErr.Response.Message
		case apiErr.Response.Error != "":
			return apiErr.Response.Error
		}
	}

	return bodyText
}

func normalizeCookieHeader(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", nil
	}

	name, value, ok := strings.Cut(trimmed, "=")
	if !ok {
		return "", fmt.Errorf("invalid EGAMES_COOKIE format: expected key=value")
	}

	name = strings.TrimSpace(name)
	value = strings.TrimSpace(value)
	if name == "" || value == "" {
		return "", fmt.Errorf("invalid EGAMES_COOKIE format: expected non-empty key and value")
	}

	return name + "=" + value, nil
}

func isNetworkError(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true // Timeout, connection refused, DNS error, etc.
	}
	// Also treat generic context deadline/canceled as network error if they happen during dial/request.
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	return false
}

// CheckAvailability ping the panel to check if it's reachable.
func (r *RemnawaveClient) CheckAvailability(ctx context.Context) error {
	endpoint, err := url.JoinPath(r.baseURL, "api/system/health")
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+r.token)
	if r.egamesCookie != "" {
		req.Header.Set("Cookie", r.egamesCookie)
	}

	resp, err := r.httpClient.Do(req)
	if err != nil {
		if isNetworkError(err) {
			return fmt.Errorf("%w: %v", ErrPanelUnavailable, err)
		}
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= http.StatusInternalServerError {
		return fmt.Errorf("%w: status %d", ErrPanelUnavailable, resp.StatusCode)
	}

	// 404, 401, 403, 200 are all considered "available"
	return nil
}
