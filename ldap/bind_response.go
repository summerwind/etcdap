package ldap

import (
	"bytes"
	"encoding/asn1"
)

// ------------------------------------------------------------------
// BindResponse ::= [APPLICATION 1] SEQUENCE {
//      COMPONENTS OF LDAPResult,
//      serverSaslCreds    [7] OCTET STRING OPTIONAL }
// ------------------------------------------------------------------
type BindResponse struct {
	LDAPResult
	ServerSaslCreds []byte
}

func (br BindResponse) Class() int {
	return 1
}

func (br BindResponse) Tag() int {
	return 1
}

func (br BindResponse) Bytes() (b []byte, err error) {
	var buf bytes.Buffer

	result, err := br.bytes()
	if err != nil {
		return
	}
	_, err = buf.Write(result)
	if err != nil {
		return
	}

	serverSaslCreds, err := asn1.Marshal(br.ServerSaslCreds)
	if err != nil {
		return
	}
	_, err = buf.Write(serverSaslCreds)
	if err != nil {
		return
	}

	seq := asn1.RawValue{
		Class:      0,
		Tag:        16,
		IsCompound: true,
		Bytes:      buf.Bytes(),
	}
	b, err = asn1.Marshal(seq)

	return
}

func NewBindResponse() *BindResponse {
	return nil
}

func ParseBindResponse(b []byte) *BindResponse {
	return nil
}
