package gobip352

// not exposed, just for internal use
type noErrJustSkip struct{}

func (e noErrJustSkip) Error() string {
	return "This should not be raised anywhere"
}

type AddressHRPError struct{}

func (e AddressHRPError) Error() string {
	return "hrp did not match network"
}

type DecodingLimitExceeded struct{}

func (e DecodingLimitExceeded) Error() string {
	return "exceeds BIP0352 recommended 1023 character limit"
}
