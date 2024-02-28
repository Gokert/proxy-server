package mw

import (
	"github.com/sirupsen/logrus"
	"net/http"
	"time"
)

func AccessLog(logger *logrus.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		reqID := GetRequestID(r.Context())
		logger.WithFields(logrus.Fields{
			"reqID":  reqID,
			"method": r.Method,
			"host":   r.Host,
			"path":   r.URL.Path,
			"header": r.Header,
		}).Infoln("start request processing")

		next.ServeHTTP(w, r)

		logger.WithFields(logrus.Fields{
			"reqID":   reqID,
			"latency": time.Since(start),
		}).Infoln("request processed")
	})
}
