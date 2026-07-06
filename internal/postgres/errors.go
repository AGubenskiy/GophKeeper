package postgres

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/AGubenskiy/GophKeeper/internal/domain"
)

const (
	sqlStateUniqueViolation = "23505"
)

type sqlStateError interface {
	SQLState() string
}

func mapError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ErrNotFound
	}

	var stateErr sqlStateError
	if errors.As(err, &stateErr) && stateErr.SQLState() == sqlStateUniqueViolation {
		return fmt.Errorf("%w: %v", domain.ErrAlreadyExists, err)
	}

	return err
}
