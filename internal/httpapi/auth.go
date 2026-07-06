package httpapi

import (
	"context"
	"net/http"
	"strings"

	"github.com/AGubenskiy/GophKeeper/internal/tokens"
)

type principalContextKey struct{}

// TokenVerifier verifies access tokens from HTTP requests.
type TokenVerifier interface {
	VerifyAccess(tokenText string) (tokens.Principal, error)
}

// AuthMiddleware authenticates Bearer tokens and stores the principal in request context.
func AuthMiddleware(verifier TokenVerifier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if verifier == nil {
				writeAPIError(w, r, http.StatusInternalServerError, errorInternal, "auth verifier is not configured")
				return
			}

			tokenText, ok := bearerToken(r.Header.Get("Authorization"))
			if !ok {
				writeAPIError(w, r, http.StatusUnauthorized, errorUnauthorized, "authorization bearer token is required")
				return
			}

			principal, err := verifier.VerifyAccess(tokenText)
			if err != nil {
				writeAPIError(w, r, http.StatusUnauthorized, errorUnauthorized, "authorization bearer token is invalid")
				return
			}

			ctx := ContextWithPrincipal(r.Context(), principal)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ContextWithPrincipal stores a principal in ctx.
func ContextWithPrincipal(ctx context.Context, principal tokens.Principal) context.Context {
	return context.WithValue(ctx, principalContextKey{}, principal)
}

// PrincipalFromContext returns an authenticated principal from ctx.
func PrincipalFromContext(ctx context.Context) (tokens.Principal, bool) {
	principal, ok := ctx.Value(principalContextKey{}).(tokens.Principal)
	return principal, ok
}

func bearerToken(header string) (string, bool) {
	const prefix = "Bearer "

	if !strings.HasPrefix(header, prefix) {
		return "", false
	}
	tokenText := strings.TrimSpace(strings.TrimPrefix(header, prefix))
	if tokenText == "" {
		return "", false
	}
	return tokenText, true
}
