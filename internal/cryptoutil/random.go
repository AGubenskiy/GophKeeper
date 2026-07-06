package cryptoutil

import (
	"crypto/rand"
	"fmt"
	"io"
)

// RandomBytes returns n cryptographically secure random bytes.
func RandomBytes(n int) ([]byte, error) {
	if n <= 0 {
		return nil, fmt.Errorf("random byte count must be positive")
	}

	out := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, out); err != nil {
		return nil, fmt.Errorf("read random bytes: %w", err)
	}
	return out, nil
}
