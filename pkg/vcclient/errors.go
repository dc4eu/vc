package vcclient

import "errors"

var (
	// ErrInvalidRequest is returned when the request is invalid
	ErrInvalidRequest = errors.New("Invalid request")

	// ErrNotAllowedRequest is returned when the request is not allowed
	ErrNotAllowedRequest = errors.New("Not allowed request")
)
