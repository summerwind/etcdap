package ldap

// ------------------------------------------------------------------
// ExtendedResponse ::= [APPLICATION 24] SEQUENCE {
//      COMPONENTS OF LDAPResult,
//      responseName     [10] LDAPOID OPTIONAL,
//      responseValue    [11] OCTET STRING OPTIONAL }
// ------------------------------------------------------------------
type ExtendedResponse struct {
	ResponseName  LDAPOID
	ResponseValue []byte
}

func (er ExtendedResponse) Class() int {
	return 24
}

func (er ExtendedResponse) Tag() int {
	return 0
}

func (er ExtendedResponse) Bytes() []byte {
	return []byte{}
}

func NewExtendedReponse() *ExtendedResponse {
	return nil
}

func ParseExtendedResponse(b []byte) *ExtendedResponse {
	return nil
}
