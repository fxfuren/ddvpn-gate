package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fxfuren/ddvpn-gate/internal/client"
	"github.com/fxfuren/ddvpn-gate/internal/config"
	"github.com/fxfuren/ddvpn-gate/internal/handler"
	"github.com/fxfuren/ddvpn-gate/internal/logger"
	"github.com/fxfuren/ddvpn-gate/internal/router"
	"github.com/fxfuren/ddvpn-gate/internal/service"
	"github.com/joho/godotenv"
)

const (
	appName    = "RemnaGate"
	appVersion = "2.0.1"
)

func main() {
	// Загружаем .env файл
	_ = godotenv.Load()

	// Инициализируем логгер
	log := logger.New()

	log.Infof("🚀 Starting %s v%s", appName, appVersion)

	// Загружаем конфигурацию
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("❌ Failed to load config: %v", err)
	}

	// Создаем клиент Remnawave
	remnawaveClient, err := client.NewRemnawaveClient(cfg.RemnawaveBaseURL, cfg.RemnawaveToken, cfg.EgamesCookie)
	if err != nil {
		log.Fatalf("❌ Failed to create Remnawave client: %v", err)
	}

	// Создаем сервисы
	authService := service.NewAuthService(remnawaveClient, cfg, log)

	// Создаем обработчики
	healthHandler := handler.NewHealthHandler()
	authHandler := handler.NewAuthHandler(authService, log)

	// Создаем роутер
	r := router.NewRouter(healthHandler, authHandler)

	// Создаем HTTP сервер
	server := &http.Server{
		Addr:         fmt.Sprintf(":%s", cfg.ServerPort),
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Запускаем сервер в горутине
	go func() {
		log.Infof("🌐 Server listening on port %s", cfg.ServerPort)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("❌ Server failed: %v", err)
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("🛑 Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("❌ Server forced to shutdown: %v", err)
	}

	log.Info("👋 Server stopped gracefully")
}
