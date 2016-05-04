package ldap

import (
	"bytes"
	"encoding/asn1"
)

// ------------------------------------------------------------------
// BindRequest ::= [APPLICATION 0] SEQUENCE {
//      version                 INTEGER (1 ..  127),
//      name                    LDAPDN,
//      authentication          AuthenticationChoice }
// ------------------------------------------------------------------
type BindRequest struct {
	Version        int
	Name           LDAPDN
	Authentication AuthenticationChoice
}

func (br BindRequest) Class() int {
	return 1
}

func (br BindRequest) Tag() int {
	return 0
}

func (br BindRequest) Bytes() (b []byte, err error) {
	var buf bytes.Buffer

	version, err := asn1.Marshal(br.Version)
	if err != nil {
		return
	}
	_, err = buf.Write(version)
	if err != nil {
		return
	}

	name, err := asn1.Marshal(br.Name)
	if err != nil {
		return
	}
	_, err = buf.Write(name)
	if err != nil {
		return
	}

	auth, err := br.Authentication.Bytes()
	if err != nil {
		return
	}
	_, err = buf.Write(auth)
	if err != nil {
		return
	}

	seq := asn1.RawValue{
		Class:      br.Class(),
		Tag:        br.Tag(),
		IsCompound: true,
		Bytes:      buf.Bytes(),
	}
	b, err = asn1.Marshal(seq)

	return
}

func NewBindRequest(version int, name LDAPDN) *BindRequest {
	return &BindRequest{
		Version: version,
		Name:    name,
	}
}

func ParseBindRequest(b []byte) (req *BindRequest, err error) {
	var rawSequence asn1.RawValue

	req = new(BindRequest)

	_, err = asn1.Unmarshal(b, &rawSequence)
	if err != nil {
		err = NewLDAPError(ResultCodeProtocolError, "Invalid sequence")
		return
	}
	if rawSequence.Class != req.Class() {
		err = NewLDAPError(ResultCodeProtocolError, "Invalid class")
		return
	}
	if rawSequence.Tag != req.Tag() {
		err = NewLDAPError(ResultCodeProtocolError, "Invalid tag")
		return
	}

	rest, err := asn1.Unmarshal(rawSequence.Bytes, &req.Version)
	if err != nil {
		err = NewLDAPError(ResultCodeProtocolError, "Invalid version field")
		return
	}

	rest, err = asn1.Unmarshal(rest, &req.Name)
	if err != nil {
		err = NewLDAPError(ResultCodeProtocolError, "Invalid name field")
		return
	}

	var auth asn1.RawValue
	rest, err = asn1.Unmarshal(rest, &auth)
	if err != nil {
		err = NewLDAPError(ResultCodeProtocolError, "Invalid authentication field")
		return
	}

	switch auth.Tag {
	case 0:
		simple, err := ParseSimple(auth.FullBytes)
		if err != nil {
			err = NewLDAPError(ResultCodeProtocolError, "Invalid simple field")
			return nil, err
		}
		req.Authentication = simple
	case 3:
		sasl, err := ParseSaslCredentials(auth.FullBytes)
		if err != nil {
			err = NewLDAPError(ResultCodeProtocolError, "Invalid sasl field")
			return nil, err
		}
		req.Authentication = sasl
	}

	if req.Version != 3 {
		err = NewLDAPError(ResultCodeProtocolError, "Unsupported version")
		return
	}

	return
}

// ------------------------------------------------------------------
// AuthenticationChoice ::= CHOICE {
//      simple                  [0] OCTET STRING,
//                              -- 1 and 2 reserved
//      sasl                    [3] SaslCredentials,
//      ...  }
// ------------------------------------------------------------------
type AuthenticationChoice LDAPField

type Simple []byte

func (s Simple) Class() int {
	return 2
}

func (s Simple) Tag() int {
	return 0
}

func (s Simple) Bytes() (b []byte, err error) {
	simple := asn1.RawValue{
		Class:      s.Class(),
		Tag:        s.Tag(),
		IsCompound: false,
		Bytes:      s,
	}
	b, err = asn1.Marshal(simple)
	return
}

func NewSimple(b []byte) Simple {
	return Simple(b)
}

func ParseSimple(b []byte) (s Simple, err error) {
	return Simple(b), nil
}

// ------------------------------------------------------------------
// SaslCredentials ::= SEQUENCE {
//      mechanism               LDAPString,
//      credentials             OCTET STRING OPTIONAL }
// ------------------------------------------------------------------
type SaslCredentials struct {
	Mechanism   LDAPString
	Credentials []byte
}

func (s SaslCredentials) Class() int {
	return 2
}

func (s SaslCredentials) Tag() int {
	return 3
}

func (s SaslCredentials) Bytes() (b []byte, err error) {
	var buf bytes.Buffer

	mechanism, err := asn1.Marshal(s.Mechanism)
	if err != nil {
		return
	}
	_, err = buf.Write(mechanism)
	if err != nil {
		return
	}

	credentials, err := asn1.Marshal(s.Credentials)
	if err != nil {
		return
	}
	_, err = buf.Write(credentials)
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

func NewSaslCredentials(m string, c []byte) *SaslCredentials {
	return &SaslCredentials{
		Mechanism:   LDAPString(m),
		Credentials: c,
	}
}

func ParseSaslCredentials(b []byte) (sasl *SaslCredentials, err error) {
	var rawSequence asn1.RawValue

	sasl = new(SaslCredentials)

	_, err = asn1.Unmarshal(b, &rawSequence)
	if err != nil {
		err = NewLDAPError(ResultCodeProtocolError, "Invalid sequence")
		return
	}
	if rawSequence.Class != sasl.Class() {
		err = NewLDAPError(ResultCodeProtocolError, "Invalid class")
		return
	}
	if rawSequence.Tag != sasl.Tag() {
		err = NewLDAPError(ResultCodeProtocolError, "Invalid tag")
		return
	}

	rest, err := asn1.Unmarshal(rawSequence.Bytes, &sasl.Mechanism)
	if err != nil {
		err = NewLDAPError(ResultCodeProtocolError, "Invalid mechanism field")
		return
	}

	if len(rest) > 0 {
		rest, err = asn1.Unmarshal(rest, &sasl.Credentials)
		if err != nil {
			err = NewLDAPError(ResultCodeProtocolError, "Invalid credentials field")
			return
		}
	}

	return
}
