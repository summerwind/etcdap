package ldap

import (
	"bufio"
	"crypto/tls"
	"encoding/asn1"
	"fmt"
)

type Request struct {
	Message    LDAPMessage
	RemoteAddr string
	TLS        *tls.ConnectionState
}

func readRequest(b *bufio.Reader) (req *Request, err error) {
	req = new(Request)
	var envelope, protocolOp, controls asn1.RawValue

	buf := make([]byte, 2048)
	n, err := b.Read(buf)
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		return
	}

	rest, err := asn1.Unmarshal(buf[:n], &envelope)
	if err != nil {
		err = &LDAPError{
			ResultCode: ResultCodeProtocolError,
			Message:    "Invalid LDAPMessage",
		}
		return
	}

	rest, err = asn1.Unmarshal(envelope.Bytes, &req.Message.MessageID)
	if err != nil {
		err = &LDAPError{
			ResultCode: ResultCodeProtocolError,
			Message:    "Invalid MessageID",
		}
		return
	}

	rest, err = asn1.Unmarshal(rest, &protocolOp)
	if err != nil {
		err = &LDAPError{
			ResultCode: ResultCodeProtocolError,
			Message:    "Invalid ProtocolOp",
		}
		return
	}

	fmt.Println("OK")
	fmt.Printf("Unknown Request: %x\n", protocolOp.Bytes)
	fmt.Printf("ProtocolOp Class: %d\n", protocolOp.Class)
	fmt.Printf("ProtocolOp Tag: %d\n", protocolOp.Tag)
	switch protocolOp.Class {
	case 1:
		bindReq, err := parseBindRequest(protocolOp.Bytes)
		if err != nil {
			return nil, err
		}
		req.Message.ProtocolOp = bindReq
		fmt.Printf("Bind Request: %s\n", bindReq)
	default:
		err = &LDAPError{
			ResultCode: ResultCodeOperationsError,
			Message:    "Unsupported ProtocolOp",
		}
		return
	}

	if len(rest) != 0 {
		rest, err = asn1.Unmarshal(rest, &controls)
		if err != nil {
			err = &LDAPError{
				ResultCode: ResultCodeProtocolError,
				Message:    "Invalid Controls",
			}
			return
		}
	}

	return req, nil
}

func parseBindRequest(buf []byte) (bindReq *BindRequest, err error) {
	var auth asn1.RawValue

	bindReq = new(BindRequest)

	rest, err := asn1.Unmarshal(buf, &bindReq.Version)
	if err != nil {
		err = &LDAPError{
			ResultCode: ResultCodeProtocolError,
			Message:    "Invalid Version",
		}
		return
	}

	rest, err = asn1.Unmarshal(rest, &bindReq.Name)
	if err != nil {
		err = &LDAPError{
			ResultCode: ResultCodeProtocolError,
			Message:    "Invalid Name",
		}
		return
	}

	rest, err = asn1.Unmarshal(rest, &auth)
	if err != nil {
		err = &LDAPError{
			ResultCode: ResultCodeProtocolError,
			Message:    "Invalid Authentication",
		}
		return
	}

	switch auth.Tag {
	case 0:
		var simple Simple
		simple = auth.Bytes
		bindReq.Authentication = simple
	case 3:
		var sasl SaslCredentials
		rest, err = asn1.Unmarshal(auth.Bytes, &sasl.Mechanism)
		if err != nil {
			err = &LDAPError{
				ResultCode: ResultCodeProtocolError,
				Message:    "Invalid Mechanism",
			}
			return
		}

		rest, err = asn1.Unmarshal(rest, &sasl.Credentials)
		if err != nil {
			err = &LDAPError{
				ResultCode: ResultCodeProtocolError,
				Message:    "Invalid Credentials",
			}
			return
		}

		bindReq.Authentication = sasl
	}

	return bindReq, nil
}
