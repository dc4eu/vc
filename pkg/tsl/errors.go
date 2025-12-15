// Package tsl provides types and errors for Token Status List (TSL) operations
// per draft-ietf-oauth-status-list specification.
package tsl

import "errors"

// ErrHistoricalResolutionNotSupported is returned when the time parameter is provided
// but the server does not maintain historical status lists (Section 8.4).
var ErrHistoricalResolutionNotSupported = errors.New("historical resolution not supported: time parameter provided but this server does not maintain historical status lists")

// ErrInvalidSectionID is returned when the section ID is invalid.
var ErrInvalidSectionID = errors.New("invalid section ID")

// ErrSectionNotFound is returned when the requested section does not exist.
var ErrSectionNotFound = errors.New("section not found")

// ErrInvalidTimeParameter is returned when the time query parameter is not a valid Unix timestamp.
var ErrInvalidTimeParameter = errors.New("invalid time parameter: must be a Unix timestamp")

// ErrTokenGenerationFailed is returned when the Status List Token JWT generation fails.
var ErrTokenGenerationFailed = errors.New("failed to generate status list token")

// ErrInvalidStatusIndex is returned when the status index is out of bounds.
var ErrInvalidStatusIndex = errors.New("invalid status index: out of bounds")

// ErrInvalidStatusValue is returned when the status value is not a valid Status Type (0-2 per Section 7.1).
var ErrInvalidStatusValue = errors.New("invalid status value: must be 0 (VALID), 1 (INVALID), or 2 (SUSPENDED)")
