package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequestIDMiddlewarePreservesIncomingID(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := RequestIDFromContext(r.Context())
		if !ok {
			t.Fatal("request id missing from context")
		}
		if id != "req-1" {
			t.Fatalf("request id = %q, want req-1", id)
		}
		if r.Header.Get(headerRequestID) != "req-1" {
			t.Fatalf("request header id = %q, want req-1", r.Header.Get(headerRequestID))
		}
		w.WriteHeader(http.StatusNoContent)
	})
	handler := RequestIDMiddleware(next)
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set(headerRequestID, "req-1")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Header().Get(headerRequestID) != "req-1" {
		t.Fatalf("response header id = %q, want req-1", response.Header().Get(headerRequestID))
	}
}

func TestRequestIDMiddlewareGeneratesID(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := RequestIDFromContext(r.Context())
		if !ok || id == "" {
			t.Fatalf("request id = %q/%v, want generated id", id, ok)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	handler := RequestIDMiddleware(next)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))

	if response.Header().Get(headerRequestID) == "" {
		t.Fatal("response request id header is empty")
	}
}
