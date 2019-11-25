package utils

import (
	"fmt"
	"time"

	"github.com/labstack/echo"
	log "github.com/sirupsen/logrus"
)

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

func JustTest(l Logdata) {
	fmt.Println(l)
}
