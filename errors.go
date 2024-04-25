package gobip352

import "errors"

var (
	// This error is a flag if a function does not really fail but also does not provide an output that can or should be used further.
	// It should not be exposed and should never reach anything outside this module
	noErrJustSkip = errors.New("this should not be raised anywhere")

	AddressHRPError = errors.New("hrp did not match network")

	DecodingLimitExceeded = errors.New("exceeds BIP0352 recommended 1023 character limit")

	ErrVinsEmpty = errors.New("vins were empty")

	ErrNoEligibleVins = errors.New("no eligible vins")
)
