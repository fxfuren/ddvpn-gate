package service

import (
	"context"
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

// AuthService предоставляет методы для проверки авторизации
type AuthService struct {
	client *client.RemnawaveClient
	cfg    *config.Config
	logger *logrus.Logger
}

// NewAuthService создает новый сервис авторизации
func NewAuthService(client *client.RemnawaveClient, cfg *config.Config, logger *logrus.Logger) *AuthService {
	return &AuthService{
		client: client,
		cfg:    cfg,
		logger: logger,
	}
}

// isTagAllowed проверяет, есть ли тег пользователя в списке разрешенных тегов
func (s *AuthService) isTagAllowed(userTag string) bool {
	if userTag == "" {
		return false
	}

	// Парсим список разрешенных тегов из конфига
	allowedTags := strings.Split(s.cfg.BypassTag, ",")

	userTagTrimmed := strings.TrimSpace(userTag)

	// Проверяем каждый разрешенный тег
	for _, allowedTag := range allowedTags {
		if strings.TrimSpace(allowedTag) == userTagTrimmed {
			return true
		}
	}

	return false
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

// VerifyAccess проверяет доступ пользователя (для /auth endpoint)
// Проверяет тег ADMIN или соответствие external squad
func (s *AuthService) VerifyAccess(ctx context.Context, shortUUID string) AuthResult {
	user, err := s.client.GetUserByShortUUID(ctx, shortUUID)
	if err != nil {
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
