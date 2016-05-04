package ldap

import (
	"bytes"
	"encoding/asn1"
	"fmt"
)

type LDAPField interface {
	Class() int
	Tag() int
	Bytes() ([]byte, error)
}

type LDAPError struct {
	ResultCode int
	Message    string
}

func (e LDAPError) Error() string {
	return e.Message
}

func NewLDAPError(rc int, msg string) *LDAPError {
	return &LDAPError{
		ResultCode: rc,
		Message:    msg,
	}
}

// ------------------------------------------------------------------
// LDAPMessage ::= SEQUENCE {
//     messageID       MessageID,
//     protocolOp      CHOICE {
//          bindRequest           BindRequest,
//          bindResponse          BindResponse,
//          unbindRequest         UnbindRequest,
//          searchRequest         SearchRequest,
//          searchResEntry        SearchResultEntry,
//          searchResDone         SearchResultDone,
//          searchResRef          SearchResultReference,
//          modifyRequest         ModifyRequest,
//          modifyResponse        ModifyResponse,
//          addRequest            AddRequest,
//          addResponse           AddResponse,
//          delRequest            DelRequest,
//          delResponse           DelResponse,
//          modDNRequest          ModifyDNRequest,
//          modDNResponse         ModifyDNResponse,
//          compareRequest        CompareRequest,
//          compareResponse       CompareResponse,
//          abandonRequest        AbandonRequest,
//          extendedReq           ExtendedRequest,
//          extendedResp          ExtendedResponse,
//          ...,
//          intermediateResponse  IntermediateResponse },
//     controls       [0] Controls OPTIONAL }
// ------------------------------------------------------------------
const (
	TypeBindRequest = iota
	TypeBindResponse
	TypeUnbindRequest
	TypeSearchRequest
	TypeSearchResultEntry
	TypeSearchResultDone
	TypeSearchResultReference
	TypeModifyRequest
	TypeModifyResponse
	TypeAddRequest
	TypeAddResponse
	TypeDelRequest
	TypeDelResponse
	TypeModifyDNRequest
	TypeModifyDNResponse
	TypeCompareRequest
	TypeCompareResponse
	TypeAbandonRequest
	TypeExtendedRequest
	TypeExtendedResponse
)

type ProtocolOp LDAPField

type LDAPMessage struct {
	MessageID  MessageID
	ProtocolOp ProtocolOp
	Controls   *Controls
}

func (msg LDAPMessage) Bytes() (b []byte, err error) {
	var buf bytes.Buffer

	msgID, err := asn1.Marshal(msg.MessageID)
	if err != nil {
		return
	}
	_, err = buf.Write(msgID)
	if err != nil {
		return
	}

	protocolOp, err := msg.ProtocolOp.Bytes()
	if err != nil {
		return
	}
	_, err = buf.Write(protocolOp)
	if err != nil {
		return
	}

	//controls, err := msg.Controls.Bytes()
	//if err != nil {
	//	return
	//}
	//_, err = buf.Write(controls)
	//if err != nil {
	//	return
	//}

	envelope := asn1.RawValue{
		Class:      0,
		Tag:        16,
		IsCompound: true,
		Bytes:      buf.Bytes(),
	}

	b, err = asn1.Marshal(envelope)
	return
}

func NewLDAPMessage(id MessageID, op ProtocolOp, ctrl *Controls) *LDAPMessage {
	return &LDAPMessage{
		MessageID:  id,
		ProtocolOp: op,
		Controls:   ctrl,
	}
}

func ParseLDAPMessage(b []byte) (msg *LDAPMessage, rest []byte, err error) {
	var rawEnvelope, rawProtocolOp, rawControls asn1.RawValue

	msg = new(LDAPMessage)

	rest, err = asn1.Unmarshal(b, &rawEnvelope)
	if err != nil {
		err = NewLDAPError(ResultCodeProtocolError, "Invalid LDAPMessage")
		return
	}

	r, err := asn1.Unmarshal(rawEnvelope.Bytes, &msg.MessageID)
	if err != nil {
		err = NewLDAPError(ResultCodeProtocolError, "Invalid MessageID")
		return
	}

	r, err = asn1.Unmarshal(r, &rawProtocolOp)
	if err != nil {
		err = NewLDAPError(ResultCodeProtocolError, "Invalid ProtocolOp")
		return
	}

	if len(r) > 0 {
		r, err = asn1.Unmarshal(r, &rawControls)
		if err != nil {
			err = NewLDAPError(ResultCodeProtocolError, "Invalid Controls")
			return
		}
	}

	fmt.Printf("Bytes:      %s - %x\n", len(rawProtocolOp.Bytes), rawProtocolOp.Bytes)
	fmt.Printf("Full Bytes: %s - %x\n", len(rawProtocolOp.FullBytes), rawProtocolOp.FullBytes)
	switch rawProtocolOp.Tag {
	case 0:
		bindReq, err := ParseBindRequest(rawProtocolOp.FullBytes)
		if err != nil {
			return nil, rest, err
		}
		msg.ProtocolOp = bindReq
	case 1:
		bindRes, err := ParseBindResponse(rawProtocolOp.FullBytes)
		if err != nil {
			return nil, rest, err
		}
		msg.ProtocolOp = bindRes
	case 3:
		searchReq, err := ParseSearchRequest(rawProtocolOp.FullBytes)
		if err != nil {
			return nil, rest, err
		}
		msg.ProtocolOp = searchReq
	default:
		err = NewLDAPError(ResultCodeOperationsError, "Unsupported ProtocolOp")
		return
	}

	return
}

// ------------------------------------------------------------------
// MessageID ::= INTEGER (0 ..  maxInt)
// ------------------------------------------------------------------
type MessageID int

// ------------------------------------------------------------------
// LDAPString ::= OCTET STRING -- UTF-8 encoded,
//                             -- [ISO10646] characters
// ------------------------------------------------------------------
type LDAPString []byte

// ------------------------------------------------------------------
// LDAPOID ::= OCTET STRING -- Constrained to <numericoid>
//                          -- [RFC4512]
// ------------------------------------------------------------------
type LDAPOID []byte

// ------------------------------------------------------------------
// LDAPDN ::= LDAPString -- Constrained to <distinguishedName>
//                       -- [RFC4514]
// ------------------------------------------------------------------
type LDAPDN LDAPString

// ------------------------------------------------------------------
// AttributeDescription ::= LDAPString
//                         -- Constrained to <attributedescription>
//                         -- [RFC4512]
// ------------------------------------------------------------------
type AttributeDescription LDAPString

// ------------------------------------------------------------------
// AttributeValue ::= OCTET STRING
// ------------------------------------------------------------------
type AttributeValue []byte

// ------------------------------------------------------------------
// AttributeValueAssertion ::= SEQUENCE {
//      attributeDesc   AttributeDescription,
//      assertionValue  AssertionValue }
// ------------------------------------------------------------------
type AttributeValueAssertion struct {
	AttributeDesc  AttributeDescription
	AssertionValue AssertionValue
}

// ------------------------------------------------------------------
// AssertionValue ::= OCTET STRING
// ------------------------------------------------------------------
type AssertionValue []byte

// ------------------------------------------------------------------
// LDAPResult ::= SEQUENCE {
//              resultCode         ENUMERATED {
//                   success                      (0),
//                   operationsError              (1),
//                   protocolError                (2),
//                   timeLimitExceeded            (3),
//                   sizeLimitExceeded            (4),
//                   compareFalse                 (5),
//                   compareTrue                  (6),
//                   authMethodNotSupported       (7),
//                   strongerAuthRequired         (8),
//                        -- 9 reserved --
//                   referral                     (10),
//                   adminLimitExceeded           (11),
//                   unavailableCriticalExtension (12),
//                   confidentialityRequired      (13),
//                   saslBindInProgress           (14),
//                   noSuchAttribute              (16),
//                   undefinedAttributeType       (17),
//                   inappropriateMatching        (18),
//                   constraintViolation          (19),
//                   attributeOrValueExists       (20),
//                   invalidAttributeSyntax       (21),
//                        -- 22-31 unused --
//                   noSuchObject                 (32),
//                   aliasProblem                 (33),
//                   invalidDNSyntax              (34),
//                        -- 35 reserved for undefined isLeaf --
//                   aliasDereferencingProblem    (36),
//                        -- 37-47 unused --
//                   inappropriateAuthentication  (48),
//                   invalidCredentials           (49),
//                   insufficientAccessRights     (50),
//                   busy                         (51),
//                   unavailable                  (52),
//                   unwillingToPerform           (53),
//                   loopDetect                   (54),
//                        -- 55-63 unused --
//                   namingViolation              (64),
//                   objectClassViolation         (65),
//                   notAllowedOnNonLeaf          (66),
//                   notAllowedOnRDN              (67),
//                   entryAlreadyExists           (68),
//                   objectClassModsProhibited    (69),
//                        -- 70 reserved for CLDAP --
//                   affectsMultipleDSAs          (71),
//                        -- 72-79 unused --
//                   other                        (80),
//                   ...  },
//              matchedDN          LDAPDN,
//              diagnosticMessage  LDAPString,
//              referral           [3] Referral OPTIONAL }
// ------------------------------------------------------------------
const (
	ResultCodeSuccess                      = 0
	ResultCodeOperationsError              = 1
	ResultCodeProtocolError                = 2
	ResultCodeTimeLimitExceeded            = 3
	ResultCodeSizeLimitExceeded            = 4
	ResultCodeCompareFalse                 = 5
	ResultCodeCompareTrue                  = 6
	ResultCodeAuthMethodNotSupported       = 7
	ResultCodeStrongerAuthRequired         = 8
	ResultCodeReferral                     = 10
	ResultCodeAdminLimitExceeded           = 11
	ResultCodeUnavailableCriticalExtension = 12
	ResultCodeConfidentialityRequired      = 13
	ResultCodeSaslBindInProgress           = 14
	ResultCodeNoSuchAttribute              = 16
	ResultCodeUndefinedAttributeType       = 17
	ResultCodeInappropriateMatching        = 18
	ResultCodeConstraintViolation          = 19
	ResultCodeAttributeOrValueExists       = 20
	ResultCodeInvalidAttributeSyntax       = 21
	ResultCodeNoSuchObject                 = 32
	ResultCodeAliasProblem                 = 33
	ResultCodeInvalidDNSyntax              = 34
	ResultCodeAliasDereferencingProblem    = 36
	ResultCodeInappropriateAuthentication  = 48
	ResultCodeInvalidCredentials           = 49
	ResultCodeInsufficientAccessRights     = 50
	ResultCodeBusy                         = 51
	ResultCodeUnavailable                  = 52
	ResultCodeUnwillingToPerform           = 53
	ResultCodeLoopDetect                   = 54
	ResultCodeNamingViolation              = 64
	ResultCodeObjectClassViolation         = 65
	ResultCodeNotAllowedOnNonLeaf          = 66
	ResultCodeNotAllowedOnRDN              = 67
	ResultCodeEntryAlreadyExists           = 68
	ResultCodeObjectClassModsProhibited    = 69
	ResultCodeOffectsMultipleDSAs          = 71
	ResultCodeOther                        = 80
)

type LDAPResult struct {
	ResultCode        int
	MatchedDN         LDAPDN
	DiagnosticMessage LDAPString
	Referral          *Referral
}

func (lr LDAPResult) bytes() (b []byte, err error) {
	var buf bytes.Buffer

	// ResultCode
	resultCode, err := asn1.Marshal(lr.ResultCode)
	if err != nil {
		return
	}
	_, err = buf.Write(resultCode)
	if err != nil {
		return
	}

	// MatchedDN
	matchedDN, err := asn1.Marshal(lr.MatchedDN)
	if err != nil {
		return
	}
	_, err = buf.Write(matchedDN)
	if err != nil {
		return
	}

	// DiagnosticMessage
	diacnosticMsg, err := asn1.Marshal(lr.DiagnosticMessage)
	if err != nil {
		return
	}
	_, err = buf.Write(diacnosticMsg)
	if err != nil {
		return
	}

	// Referral
	if lr.Referral != nil {
		referral, err := lr.Referral.Bytes()
		if err != nil {
			return nil, err
		}
		_, err = buf.Write(referral)
		if err != nil {
			return nil, err
		}
	}

	b = buf.Bytes()

	return
}

func NewLDAPResult(rc int, md LDAPDN, dm LDAPString, ref *Referral) *LDAPResult {
	return &LDAPResult{
		ResultCode:        rc,
		MatchedDN:         md,
		DiagnosticMessage: dm,
		Referral:          ref,
	}
}

func ParseLDAPResult(b []byte) *LDAPResult {
	return nil
}

// ------------------------------------------------------------------
// Referral ::= SEQUENCE SIZE (1..MAX) OF uri URI
// ------------------------------------------------------------------
type Referral []URI

func (ref *Referral) Bytes() (b []byte, err error) {
	var buf bytes.Buffer

	for _, r := range *ref {
		rbuf, err := asn1.Marshal(r)
		if err != nil {
			return nil, err
		}
		_, err = buf.Write(rbuf)
		if err != nil {
			return nil, err
		}
	}

	b = buf.Bytes()

	return
}

func NewReferral() *Referral {
	return nil
}

func ParseReferral(b []byte) *Referral {
	return nil
}

// ------------------------------------------------------------------
// URI ::= LDAPString     -- limited to characters permitted in
//                        -- URIs
// ------------------------------------------------------------------
type URI LDAPString

// ------------------------------------------------------------------
// Controls ::= SEQUENCE OF control Control
// ------------------------------------------------------------------
type Controls []Control

// ------------------------------------------------------------------
// Control ::= SEQUENCE {
//      controlType             LDAPOID,
//      criticality             BOOLEAN DEFAULT FALSE,
//      controlValue            OCTET STRING OPTIONAL }
// ------------------------------------------------------------------
type Control struct {
	ControlType  LDAPOID
	Criticality  bool
	ControlValue []byte
}

func (ctrl *Control) Bytes() (b []byte, err error) {
	return
}

func NewControl() *Control {
	return nil
}

func ParseControl(b []byte) *Control {
	return nil
}
