package config

import (
	"fmt"
	"os"
	"strings"
)

// Config содержит все настройки приложения
type Config struct {
	// Server settings
	ServerPort string

	// Remnawave settings
	RemnawaveBaseURL string
	RemnawaveToken   string

	// Access control settings
	AllowedSquadID    string
	DefaultSquadID    string
	BypassTag         string
	AllowedClientApps []string
}

// Load загружает конфигурацию из переменных окружения
func Load() (*Config, error) {
	cfg := &Config{
		ServerPort:        getEnv("SERVER_PORT", "8000"),
		RemnawaveBaseURL:  getEnv("REMNAWAVE_BASE_URL", ""),
		RemnawaveToken:    getEnv("REMNAWAVE_TOKEN", ""),
		AllowedSquadID:    getEnv("ALLOWED_SQUAD_ID", ""),
		DefaultSquadID:    getEnv("DEFAULT_SQUAD_ID", ""),
		BypassTag:         getEnv("BYPASS_TAG", "ADMIN"),
		AllowedClientApps: parseCSVEnv(getEnv("ALLOWED_CLIENT_APPS", "")),
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// validate проверяет обязательные поля конфигурации
func (c *Config) validate() error {
	var missing []string

	if c.RemnawaveBaseURL == "" {
		missing = append(missing, "REMNAWAVE_BASE_URL")
	}
	if c.RemnawaveToken == "" {
		missing = append(missing, "REMNAWAVE_TOKEN")
	}
	if c.AllowedSquadID == "" {
		missing = append(missing, "ALLOWED_SQUAD_ID")
	}
	if c.DefaultSquadID == "" {
		missing = append(missing, "DEFAULT_SQUAD_ID")
	}
	if len(c.AllowedClientApps) == 0 {
		missing = append(missing, "ALLOWED_CLIENT_APPS")
	}

	if len(missing) > 0 {
		return fmt.Errorf("missing required environment variables: %s", strings.Join(missing, ", "))
	}

	return nil
}

// getEnv возвращает значение переменной окружения или значение по умолчанию
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func parseCSVEnv(value string) []string {
	var items []string

	for _, item := range strings.Split(value, ",") {
		normalized := strings.ToLower(strings.TrimSpace(item))
		if normalized == "" {
			continue
		}
		items = append(items, normalized)
	}

	return items
}
