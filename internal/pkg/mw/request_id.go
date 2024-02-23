package mw

import (
	"context"
	"net/http"
)

const requestIDLen = 8

var requestIDKey = struct{}{}

func GetRequestID(ctx context.Context) string {
	reqID, ok := ctx.Value(requestIDKey).(string)
	if ok {
		return reqID
	}

	return ""
}

func SetRequestID(ctx context.Context, reqID string) context.Context {
	return context.WithValue(ctx, requestIDKey, reqID)
}

func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := randomString(requestIDLen)
		r = r.WithContext(SetRequestID(r.Context(), reqID))

		next.ServeHTTP(w, r)
	})
}
