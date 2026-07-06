package domain

import "errors"

var (
	// ErrAlreadyExists reports a duplicate entity.
	ErrAlreadyExists = errors.New("already exists")
	// ErrConflict reports an optimistic concurrency conflict.
	ErrConflict = errors.New("conflict")
	// ErrNotFound reports a missing entity.
	ErrNotFound = errors.New("not found")
	// ErrValidation reports invalid domain data.
	ErrValidation = errors.New("validation error")
)
