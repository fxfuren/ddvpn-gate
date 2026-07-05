package service

import (
	"context"
	"errors"
	"strings"

	"github.com/fxfuren/ddvpn-gate/internal/client"
	"github.com/fxfuren/ddvpn-gate/internal/config"
	"github.com/sirupsen/logrus"
)

// AuthResult представляет результат проверки авторизации
type AuthResult struct {
	Allowed bool
	Reason  string
	User    string
}

// ClientRequest содержит заголовки, влияющие на доступ клиента.
type ClientRequest struct {
	Accept    string
	UserAgent string
	DeviceOS  string
}

// AuthService предоставляет методы для проверки авторизации
type AuthService struct {
	client     *client.RemnawaveClient
	cfg        *config.Config
	logger     *logrus.Logger
	panelState *PanelState
}

// NewAuthService создает новый сервис авторизации
func NewAuthService(client *client.RemnawaveClient, cfg *config.Config, logger *logrus.Logger, panelState *PanelState) *AuthService {
	return &AuthService{
		client:     client,
		cfg:        cfg,
		logger:     logger,
		panelState: panelState,
	}
}

// IsPanelAvailable returns true if the panel is currently considered available.
func (s *AuthService) IsPanelAvailable() bool {
	return s.panelState.IsAvailable()
}

// isTagAllowed проверяет, есть ли тег пользователя в списке разрешенных тегов
func (s *AuthService) isTagAllowed(userTag string) bool {
	return isTagInList(userTag, s.cfg.BypassTag)
}

func (s *AuthService) isPCTagAllowed(userTag string) bool {
	return isTagInList(userTag, s.cfg.BypassPCTag)
}

func isTagInList(userTag, configuredTags string) bool {
	if userTag == "" {
		return false
	}

	// Парсим список разрешенных тегов из конфига
	allowedTags := strings.Split(configuredTags, ",")

	userTagTrimmed := strings.TrimSpace(userTag)

	// Проверяем каждый разрешенный тег
	for _, allowedTag := range allowedTags {
		if strings.TrimSpace(allowedTag) == userTagTrimmed {
			return true
		}
	}

	return false
}

// isClientAllowed проверяет, разрешено ли приложение клиента.
func (s *AuthService) isClientAllowed(clientApp string) bool {
	if clientApp == "" {
		return false
	}

	for _, allowedClient := range s.cfg.AllowedClientApps {
		if allowedClient == clientApp {
			return true
		}
	}

	return false
}

// VerifyClientAccess проверяет, можно ли обслуживать запрос по client headers.
func (s *AuthService) VerifyClientAccess(req ClientRequest) AuthResult {
	if !s.panelState.IsAvailable() {
		return AuthResult{Allowed: true, Reason: "panel_unavailable_bypass"}
	}

	if isBrowserRequest(req.Accept) {
		return AuthResult{Allowed: true, Reason: "browser_request"}
	}

	clientApp := detectClientApp(req.UserAgent)
	platform := detectClientPlatform(req.DeviceOS, req.UserAgent)

	if !s.isClientAllowed(clientApp) {
		s.logger.Warnf("⛔ ACCESS DENIED (Client App): User-Agent '%s', detected client '%s', allowed clients: %s",
			req.UserAgent, clientApp, strings.Join(s.cfg.AllowedClientApps, ", "))
		return AuthResult{Allowed: false, Reason: "client_app_not_allowed"}
	}

	if platform == "" {
		s.logger.Warnf("⛔ ACCESS DENIED (Client Platform): User-Agent '%s', X-Device-OS '%s', detected platform '%s'",
			req.UserAgent, req.DeviceOS, platform)
		return AuthResult{Allowed: false, Reason: "client_platform_not_allowed"}
	}

	if !isMobilePlatform(platform) {
		return AuthResult{Allowed: true, Reason: "desktop_client_needs_pc_tag"}
	}

	return AuthResult{Allowed: true, Reason: "mobile_client_allowed"}
}

// ParseShortUUID извлекает shortUUID из URI
func (s *AuthService) ParseShortUUID(uri string) (string, error) {
	// Убираем query параметры
	cleanPath := strings.Split(uri, "?")[0]
	// Убираем trailing slash
	cleanPath = strings.TrimRight(cleanPath, "/")
	// Берем последний сегмент пути
	parts := strings.Split(cleanPath, "/")
	if len(parts) == 0 {
		return "", ErrInvalidURI
	}
	shortUUID := parts[len(parts)-1]

	// Простая валидация длины
	if len(shortUUID) < 8 {
		return "", ErrInvalidShortUUID
	}

	return shortUUID, nil
}

func isBrowserRequest(acceptHeader string) bool {
	return strings.Contains(strings.ToLower(acceptHeader), "text/html")
}

func detectClientApp(userAgent string) string {
	ua := strings.TrimSpace(strings.ToLower(userAgent))
	if ua == "" {
		return ""
	}

	parts := strings.Split(ua, "/")
	if len(parts) == 0 {
		return ""
	}

	return strings.TrimSpace(parts[0])
}

func detectClientPlatform(deviceOS, userAgent string) string {
	if platform := normalizePlatform(deviceOS); platform != "" {
		return platform
	}

	lowerUA := strings.ToLower(userAgent)
	replacer := strings.NewReplacer(
		"/", " ",
		"(", " ",
		")", " ",
		";", " ",
		",", " ",
		"_", " ",
	)

	for _, token := range strings.Fields(replacer.Replace(lowerUA)) {
		if platform := normalizePlatform(token); platform != "" {
			return platform
		}
	}

	return ""
}

func normalizePlatform(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))

	switch {
	case normalized == "":
		return ""
	case strings.Contains(normalized, "android"):
		return "android"
	case strings.Contains(normalized, "ios"), strings.Contains(normalized, "iphone"), strings.Contains(normalized, "ipad"):
		return "ios"
	case strings.Contains(normalized, "windows"):
		return "windows"
	case strings.Contains(normalized, "mac"), strings.Contains(normalized, "darwin"), strings.Contains(normalized, "osx"):
		return "macos"
	case strings.Contains(normalized, "linux"):
		return "linux"
	default:
		return ""
	}
}

func isMobilePlatform(platform string) bool {
	return platform == "ios" || platform == "android"
}

// VerifyAccess проверяет доступ пользователя (для /auth endpoint)
// Проверяет тег ADMIN или соответствие external squad
func (s *AuthService) VerifyAccess(ctx context.Context, shortUUID string) AuthResult {
	return s.VerifyAccessWithPCRequirement(ctx, shortUUID, false)
}

func (s *AuthService) VerifyAccessWithPCRequirement(ctx context.Context, shortUUID string, requirePCTag bool) AuthResult {
	user, err := s.client.GetUserByShortUUID(ctx, shortUUID)
	if err != nil {
		if errors.Is(err, client.ErrPanelUnavailable) {
			s.logger.Errorf("❌ Panel unavailable detected during auth check: %s", err)
			s.panelState.MarkUnavailable(err)
			return AuthResult{Allowed: true, Reason: "panel_unavailable_fallback"}
		}
		// Не логируем 404 ошибки (обычно это favicon/js запросы)
		if !strings.Contains(err.Error(), "404") {
			s.logger.Errorf("❌ API Error checking %s: %s", shortUUID, err)
		}
		return AuthResult{Allowed: false, Reason: "api_error"}
	}

	username := user.Username
	if username == "" {
		username = "Unknown"
	}

	// 1. ПРОВЕРКА ADMIN (TAG)
	if s.isTagAllowed(user.Tag) {
		s.logger.Infof("🔓 ACCESS GRANTED (Admin Tag): User '%s' (Tag: '%s')", username, user.Tag)
		return AuthResult{Allowed: true, Reason: "admin_tag", User: username}
	}

	// 2. ПРОВЕРКА SQUAD
	squadFromAPI := strings.TrimSpace(user.ExternalSquadUUID)
	squadAllowed := strings.TrimSpace(s.cfg.AllowedSquadID)

	if squadFromAPI != "" && squadFromAPI == squadAllowed {
		if requirePCTag && !s.isPCTagAllowed(user.Tag) {
			s.logger.Warnf("â›” ACCESS DENIED (PC Tag): User '%s'\n   Tag: '%s' (Expected PC: '%s')\n   Squad: '%s' (Expected: '%s')",
				username, user.Tag, s.cfg.BypassPCTag, squadFromAPI, squadAllowed)
			return AuthResult{Allowed: false, Reason: "pc_tag_required", User: username}
		}

		s.logger.Infof("✅ ACCESS GRANTED (Squad Match): User '%s'", username)
		return AuthResult{Allowed: true, Reason: "squad_match", User: username}
	}

	// Отказ
	s.logger.Warnf("⛔ ACCESS DENIED: User '%s'\n   Tag: '%s' (Expected: '%s')\n   Squad: '%s' (Expected: '%s')",
		username, user.Tag, s.cfg.BypassTag, squadFromAPI, squadAllowed)
	return AuthResult{Allowed: false, Reason: "access_denied", User: username}
}

// VerifyDefaultAccess проверяет доступ пользователя для default squad (для /auth-default endpoint)
// Проверяет тег ADMIN или наличие default squad в active internal squads
func (s *AuthService) VerifyDefaultAccess(ctx context.Context, shortUUID string) AuthResult {
	user, err := s.client.GetUserByShortUUID(ctx, shortUUID)
	if err != nil {
		if errors.Is(err, client.ErrPanelUnavailable) {
			s.logger.Errorf("❌ Panel unavailable detected during default auth check: %s", err)
			s.panelState.MarkUnavailable(err)
			return AuthResult{Allowed: true, Reason: "panel_unavailable_fallback"}
		}
		// Не логируем 404 ошибки
		if !strings.Contains(err.Error(), "404") {
			s.logger.Errorf("❌ API Error checking %s (default): %s", shortUUID, err)
		}
		return AuthResult{Allowed: false, Reason: "api_error"}
	}

	username := user.Username
	if username == "" {
		username = "Unknown"
	}

	// 1. ПРОВЕРКА ADMIN (TAG)
	if s.isTagAllowed(user.Tag) {
		s.logger.Infof("🔓 ACCESS GRANTED (Admin Tag - Default): User '%s' (Tag: '%s')", username, user.Tag)
		return AuthResult{Allowed: true, Reason: "admin_tag", User: username}
	}

	// 2. ПРОВЕРКА DEFAULT SQUAD (INTERNAL)
	squadDefault := strings.TrimSpace(s.cfg.DefaultSquadID)
	for _, squad := range user.ActiveInternalSquads {
		if strings.TrimSpace(squad.UUID) == squadDefault {
			s.logger.Infof("✅ ACCESS GRANTED (Default Squad): User '%s'", username)
			return AuthResult{Allowed: true, Reason: "default_squad", User: username}
		}
	}

	// Формируем список сквадов для лога
	var squadList []string
	for _, squad := range user.ActiveInternalSquads {
		squadList = append(squadList, squad.Name+" ("+squad.UUID+")")
	}
	squadListStr := "None"
	if len(squadList) > 0 {
		squadListStr = strings.Join(squadList, ", ")
	}

	// Отказ
	s.logger.Warnf("⛔ ACCESS DENIED (Default): User '%s'\n   Tag: '%s' (Expected: '%s')\n   Internal Squads: %s\n   Expected Squad ID: '%s'",
		username, user.Tag, s.cfg.BypassTag, squadListStr, s.cfg.DefaultSquadID)
	return AuthResult{Allowed: false, Reason: "access_denied", User: username}
}
