package ldap

import (
	"bufio"
	"crypto/tls"
	"fmt"
)

type Request struct {
	Message    *LDAPMessage
	RemoteAddr string
	TLS        *tls.ConnectionState
}

func readRequest(b *bufio.Reader) (req *Request, err error) {
	req = new(Request)

	buf := make([]byte, 2048)
	n, err := b.Read(buf)
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		return
	}

	msg, _, err := ParseLDAPMessage(buf[:n])
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		return
	}
	req.Message = msg

	return req, nil
}
