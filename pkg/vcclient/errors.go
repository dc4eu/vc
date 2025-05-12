package vcclient

import "errors"

var (
	// ErrInvalidRequest is returned when the request is invalid
	ErrInvalidRequest = errors.New("invalid request")

	// ErrNotAllowedRequest is returned when the request is not allowed
	ErrNotAllowedRequest = errors.New("not allowed request")
)
