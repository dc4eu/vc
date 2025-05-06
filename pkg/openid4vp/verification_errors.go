package openid4vp

import "fmt"

type VerificationRejectedError struct {
	Step   string
	Reason string
}

func (e *VerificationRejectedError) Error() string {
	return fmt.Sprintf("verification rejected on '%s': %s", e.Step, e.Reason)
}

type VerificationFailedError struct {
	Step string
	Err  error
}

func (e *VerificationFailedError) Error() string {
	return fmt.Sprintf("verification failed on '%s': %s", e.Step, e.Err.Error())
}

func (e *VerificationFailedError) Unwrap() error {
	return e.Err
}
