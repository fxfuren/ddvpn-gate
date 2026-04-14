package logger

import (
	"os"
	"time"

	"github.com/sirupsen/logrus"
)

// New создает и настраивает новый логгер
func New() *logrus.Logger {
	logger := logrus.New()

	// Вывод в stdout
	logger.SetOutput(os.Stdout)

	// Уровень логирования
	logger.SetLevel(logrus.InfoLevel)

	// Кастомный форматтер
	logger.SetFormatter(&CustomFormatter{})

	return logger
}

// CustomFormatter кастомный форматтер для логов
type CustomFormatter struct{}

// Format форматирует запись лога
func (f *CustomFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")

	levelColor := getColorByLevel(entry.Level)
	levelText := getLevelText(entry.Level)

	log := timestamp + " | " + levelColor + levelText + "\033[0m | " + entry.Message + "\n"

	return []byte(log), nil
}

func getColorByLevel(level logrus.Level) string {
	switch level {
	case logrus.DebugLevel:
		return "\033[36m" // Cyan
	case logrus.InfoLevel:
		return "\033[32m" // Green
	case logrus.WarnLevel:
		return "\033[33m" // Yellow
	case logrus.ErrorLevel, logrus.FatalLevel, logrus.PanicLevel:
		return "\033[31m" // Red
	default:
		return "\033[0m" // Default
	}
}

func getLevelText(level logrus.Level) string {
	switch level {
	case logrus.DebugLevel:
		return "DEBUG   "
	case logrus.InfoLevel:
		return "INFO    "
	case logrus.WarnLevel:
		return "WARNING "
	case logrus.ErrorLevel:
		return "ERROR   "
	case logrus.FatalLevel:
		return "FATAL   "
	case logrus.PanicLevel:
		return "PANIC   "
	default:
		return "UNKNOWN "
	}
}
