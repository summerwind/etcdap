package ldap

// ------------------------------------------------------------------
// ExtendedRequest ::= [APPLICATION 23] SEQUENCE {
//      requestName      [0] LDAPOID,
//      requestValue     [1] OCTET STRING OPTIONAL }
// ------------------------------------------------------------------
type ExtendedRequest struct {
	RequestName  LDAPOID
	RequestValue []byte
}

func (er ExtendedRequest) Class() int {
	return 23
}

func (er ExtendedRequest) Tag() int {
	return 0
}

func (er ExtendedRequest) Bytes() []byte {
	return []byte{}
}

func NewExtendedRequest() *ExtendedRequest {
	return nil
}

func ParseExtendedRequest(b []byte) *ExtendedRequest {
	return nil
}
