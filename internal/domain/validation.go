package domain

import (
	"fmt"
	"strings"
	"time"
)

func requireString(field, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%w: %s is required", ErrValidation, field)
	}
	return nil
}

func requireBytes(field string, value []byte) error {
	if len(value) == 0 {
		return fmt.Errorf("%w: %s is required", ErrValidation, field)
	}
	return nil
}

func requireTime(field string, value time.Time) error {
	if value.IsZero() {
		return fmt.Errorf("%w: %s is required", ErrValidation, field)
	}
	return nil
}

func cloneBytes(value []byte) []byte {
	if value == nil {
		return nil
	}
	out := make([]byte, len(value))
	copy(out, value)
	return out
}
