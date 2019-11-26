package utils

import (
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/labstack/echo"
	log "github.com/sirupsen/logrus"
)

// Logdata struct for logging
type Logdata struct {
	RequestID string
}

// MakeLogEntry using with logrus
func MakeLogEntry(c echo.Context, l *Logdata) *log.Entry {

	if c == nil && l == nil {
		return log.WithFields(log.Fields{
			"at": time.Now().Format("2006-01-02 15:04:05"),
		})
	} else if c == nil {
		return log.WithFields(log.Fields{
			"at":        time.Now().Format("2006-01-02 15:04:05"),
			"requestid": l.RequestID,
		})
	}

	return log.WithFields(log.Fields{
		"requestid": c.Request().Header.Get("x-request-id"),
		"at":        time.Now().Format("2006-01-02 15:04:05"),
		"method":    c.Request().Method,
		"uri":       c.Request().URL.String(),
		"ip":        c.Request().RemoteAddr,
	})
}

// HashPasswordWithSalt will hash your plain password
func HashPasswordWithSalt(plainPassword string, salt string) (encryptedPassword string) {
	saltedText := fmt.Sprintf("text: '%s', salt: %s", plainPassword, salt)
	s := sha256.New()
	s.Write([]byte(saltedText))
	encrypted := s.Sum(nil)
	encryptedPassword = fmt.Sprintf("%x", encrypted)
	return encryptedPassword
}
