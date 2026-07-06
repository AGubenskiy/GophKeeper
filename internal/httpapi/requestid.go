package httpapi

import (
	"context"
	"net/http"

	"github.com/google/uuid"
)

type requestIDContextKey struct{}

// RequestIDMiddleware attaches a request ID to the request context and response.
func RequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(headerRequestID)
		if id == "" {
			id = uuid.NewString()
		}

		w.Header().Set(headerRequestID, id)
		ctx := context.WithValue(r.Context(), requestIDContextKey{}, id)
		cloned := r.Clone(ctx)
		cloned.Header = r.Header.Clone()
		cloned.Header.Set(headerRequestID, id)

		next.ServeHTTP(w, cloned)
	})
}

// RequestIDFromContext returns a request ID from ctx.
func RequestIDFromContext(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(requestIDContextKey{}).(string)
	return id, ok
}
