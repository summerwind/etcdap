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
	Authentication LDAPField
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

func NewBindRequest() *BindRequest {
	return nil
}

func ParseBindRequest(b []byte) *BindRequest {
	return nil
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

func NewSimple() *Simple {
	return nil
}

func ParseSimple(b []byte) *Simple {
	return nil
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

func NewSaslCredentials() *SaslCredentials {
	return nil
}

func ParseSaslCredentials(b []byte) *SaslCredentials {
	return nil
}
