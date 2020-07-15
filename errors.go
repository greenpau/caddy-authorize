package jwt

type strError string

func (e strError) Error() string { return string(e) }
