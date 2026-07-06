package httpapi

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLoggingMiddlewareWritesSafeRequestMetadata(t *testing.T) {
	var logs bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&logs, nil))
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(headerRequestID, "req-1")
		w.WriteHeader(http.StatusCreated)
	})
	handler := LoggingMiddleware(log)(next)

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil))

	output := logs.String()
	for _, want := range []string{
		`"msg":"http request"`,
		`"method":"POST"`,
		`"path":"/api/v1/auth/login"`,
		`"status":201`,
		`"request_id":"req-1"`,
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("log output = %q, want %s", output, want)
		}
	}
}
