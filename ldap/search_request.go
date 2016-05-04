package ldap

import (
	"encoding/asn1"
	"fmt"
)

// ------------------------------------------------------------------
// SearchRequest ::= [APPLICATION 3] SEQUENCE {
//      baseObject      LDAPDN,
//      scope           ENUMERATED {
//           baseObject              (0),
//           singleLevel             (1),
//           wholeSubtree            (2),
//           ...  },
//      derefAliases    ENUMERATED {
//           neverDerefAliases       (0),
//           derefInSearching        (1),
//           derefFindingBaseObj     (2),
//           derefAlways             (3) },
//      sizeLimit       INTEGER (0 ..  maxInt),
//      timeLimit       INTEGER (0 ..  maxInt),
//      typesOnly       BOOLEAN,
//      filter          Filter,
//      attributes      AttributeSelection }
// ------------------------------------------------------------------
const (
	ScopeBaseObject = 0
	ScopeSingleLevel
	ScopeWholeSubtree
)

type SearchRequest struct {
	BaseObject   LDAPDN
	Scope        int `asn1:"tag:2"`
	DerefAliases int
	SizeLimit    int
	TimeLimit    int
	TypesOnly    bool
	Filter       Filter
	Attributes   AttributeSelection
}

func (sr SearchRequest) Class() int {
	return 1
}

func (sr SearchRequest) Tag() int {
	return 3
}

func (sr SearchRequest) Bytes() (b []byte, err error) {
	return
}

func NewSearchRequest(version int, name LDAPDN) *SearchRequest {
	return &SearchRequest{}
}

func ParseSearchRequest(b []byte) (req *SearchRequest, err error) {
	var rawSequence asn1.RawValue

	req = new(SearchRequest)

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

	rest, err := asn1.Unmarshal(rawSequence.Bytes, &req.BaseObject)
	if err != nil {
		err = NewLDAPError(ResultCodeProtocolError, "Invalid baseObject field")
		return
	}

	var scope asn1.RawValue
	rest, err = asn1.Unmarshal(rest, &scope)
	if err != nil {
		err = NewLDAPError(ResultCodeProtocolError, "Invalid scope field")
		return
	}
	req.Scope = int(scope.Bytes[0])

	var derefAliases asn1.RawValue
	rest, err = asn1.Unmarshal(rest, &derefAliases)
	if err != nil {
		err = NewLDAPError(ResultCodeProtocolError, "Invalid derefAliases field")
		return
	}
	req.DerefAliases = int(derefAliases.Bytes[0])

	rest, err = asn1.Unmarshal(rest, &req.SizeLimit)
	if err != nil {
		err = NewLDAPError(ResultCodeProtocolError, "Invalid sizeLimit field")
		return
	}

	rest, err = asn1.Unmarshal(rest, &req.TimeLimit)
	if err != nil {
		err = NewLDAPError(ResultCodeProtocolError, "Invalid timeLimit field")
		return
	}

	rest, err = asn1.Unmarshal(rest, &req.TypesOnly)
	if err != nil {
		err = NewLDAPError(ResultCodeProtocolError, "Invalid typesOnly field")
		return
	}

	var filter asn1.RawValue
	rest, err = asn1.Unmarshal(rest, &filter)
	if err != nil {
		err = NewLDAPError(ResultCodeProtocolError, "Invalid filter field")
		return
	}
	f, err := ParseFilter(filter.FullBytes)
	req.Filter = f

	var attributes asn1.RawValue
	rest, err = asn1.Unmarshal(rest, &attributes)
	if err != nil {
		err = NewLDAPError(ResultCodeProtocolError, "Invalid attributes field")
		return
	}
	attrs, err := ParseAttributeSelection(attributes.FullBytes)
	req.Attributes = attrs

	fmt.Printf("Search Request: %s\n", req)

	//if req.Version != 3 {
	//	err = NewLDAPError(ResultCodeProtocolError, "Unsupported version")
	//	return
	//}

	return
}

// ------------------------------------------------------------------
// AttributeSelection ::= SEQUENCE OF selector LDAPString
//                -- The LDAPString is constrained to
//                -- <attributeSelector> in Section 4.5.1.8
// ------------------------------------------------------------------
type AttributeSelection []LDAPString

func ParseAttributeSelection(b []byte) (attr AttributeSelection, err error) {
	var rawSequence asn1.RawValue

	_, err = asn1.Unmarshal(b, &rawSequence)
	if err != nil {
		err = NewLDAPError(ResultCodeProtocolError, "Invalid sequence")
		return
	}

	rest := rawSequence.Bytes
	for len(rest) != 0 {
		var rawAttr asn1.RawValue

		rest, err = asn1.Unmarshal(rest, &rawAttr)
		if err != nil {
			err = NewLDAPError(ResultCodeProtocolError, "Invalid attributes")
			return
		}

		attr = append(attr, LDAPString(rawAttr.Bytes))
	}

	return
}

// ------------------------------------------------------------------
// Filter ::= CHOICE {
//      and             [0] SET SIZE (1..MAX) OF filter Filter,
//      or              [1] SET SIZE (1..MAX) OF filter Filter,
//      not             [2] Filter,
//      equalityMatch   [3] AttributeValueAssertion,
//      substrings      [4] SubstringFilter,
//      greaterOrEqual  [5] AttributeValueAssertion,
//      lessOrEqual     [6] AttributeValueAssertion,
//      present         [7] AttributeDescription,
//      approxMatch     [8] AttributeValueAssertion,
//      extensibleMatch [9] MatchingRuleAssertion,
//      ...  }
// ------------------------------------------------------------------
type Filter LDAPField

func ParseFilter(b []byte) (filter Filter, err error) {
	var rawSequence asn1.RawValue

	_, err = asn1.Unmarshal(b, &rawSequence)
	if err != nil {
		err = NewLDAPError(ResultCodeProtocolError, "Invalid sequence")
		return
	}

	switch rawSequence.Tag {
	case 0:
		fmt.Printf("Filter (0): %x\n", rawSequence.Bytes)
		a, err := ParseAnd(rawSequence.FullBytes)
		if err != nil {
			return nil, err
		}
		fmt.Printf("And: %s\n", a)
		filter = a
	case 1:
		fmt.Printf("Filter (1): %x\n", rawSequence.Bytes)
		o, err := ParseOr(rawSequence.FullBytes)
		if err != nil {
			return nil, err
		}
		fmt.Printf("Or: %s\n", o)
		filter = o
	case 2:
		fmt.Printf("Filter (2): %x\n", rawSequence.Bytes)
	case 3:
		fmt.Printf("Filter (3): %x\n", rawSequence.Bytes)
		em, err := ParseEqualityMatch(rawSequence.FullBytes)
		if err != nil {
			return nil, err
		}
		filter = em
	case 4:
		fmt.Printf("Filter (4): %x\n", rawSequence.Bytes)
	case 5:
		fmt.Printf("Filter (5): %x\n", rawSequence.Bytes)
	case 6:
		fmt.Printf("Filter (6): %x\n", rawSequence.Bytes)
	case 7:
		fmt.Printf("Filter (7): %x\n", rawSequence.Bytes)
		p, err := ParsePresent(rawSequence.FullBytes)
		if err != nil {
			return nil, err
		}
		fmt.Printf("Present: %s\n", p)
		filter = p
	case 8:
		fmt.Printf("Filter (8): %x\n", rawSequence.Bytes)
	case 9:
		fmt.Printf("Filter (9): %x\n", rawSequence.Bytes)
	default:
		err = NewLDAPError(ResultCodeProtocolError, "Invalid tag")
		return
	}

	return
}

type And []Filter

func (a And) Class() int {
	return 2
}

func (a And) Tag() int {
	return 0
}

func (a And) Bytes() ([]byte, error) {
	return nil, nil
}

func ParseAnd(b []byte) (a And, err error) {
	var rawAnd asn1.RawValue

	_, err = asn1.Unmarshal(b, &rawAnd)
	if err != nil {
		err = NewLDAPError(ResultCodeProtocolError, "Invalid and")
		return nil, err
	}

	rest := rawAnd.Bytes
	for len(rest) > 0 {
		var rawFilter asn1.RawValue

		rest, err = asn1.Unmarshal(rest, &rawFilter)
		if err != nil {
			err = NewLDAPError(ResultCodeProtocolError, "Invalid filter")
			return nil, err
		}

		f, err := ParseFilter(rawFilter.FullBytes)
		if err != nil {
			return nil, err
		}

		a = append(a, f)
	}

	return
}

type Or []Filter

func (o Or) Class() int {
	return 2
}

func (o Or) Tag() int {
	return 3
}

func (o Or) Bytes() ([]byte, error) {
	return nil, nil
}

func ParseOr(b []byte) (o Or, err error) {
	var rawOr asn1.RawValue

	_, err = asn1.Unmarshal(b, &rawOr)
	if err != nil {
		err = NewLDAPError(ResultCodeProtocolError, "Invalid or")
		return nil, err
	}

	rest := rawOr.Bytes
	for len(rest) > 0 {
		var rawFilter asn1.RawValue

		rest, err = asn1.Unmarshal(rest, &rawFilter)
		if err != nil {
			err = NewLDAPError(ResultCodeProtocolError, "Invalid filter")
			return nil, err
		}

		f, err := ParseFilter(rawFilter.FullBytes)
		if err != nil {
			return nil, err
		}

		o = append(o, f)
	}

	return
}

type Not Filter

type EqualityMatch AttributeValueAssertion

func (em EqualityMatch) Class() int {
	return 2
}

func (em EqualityMatch) Tag() int {
	return 3
}

func (em EqualityMatch) Bytes() ([]byte, error) {
	return nil, nil
}

func ParseEqualityMatch(b []byte) (em *EqualityMatch, err error) {
	var rawSequence asn1.RawValue

	em = new(EqualityMatch)

	rest, err := asn1.Unmarshal(b, &rawSequence)
	if err != nil {
		err = NewLDAPError(ResultCodeProtocolError, "Invalid sequence")
		return
	}

	rest, err = asn1.Unmarshal(rawSequence.Bytes, &em.AttributeDesc)
	if err != nil {
		err = NewLDAPError(ResultCodeProtocolError, "Invalid attributeDesc field")
		return
	}

	rest, err = asn1.Unmarshal(rest, &em.AssertionValue)
	if err != nil {
		err = NewLDAPError(ResultCodeProtocolError, "Invalid assertionValue field")
		return
	}

	return
}

type Substrings Filter
type GreaterOrEqual Filter
type LessOrEqual Filter

type Present AttributeDescription

func (p Present) Class() int {
	return 2
}

func (p Present) Tag() int {
	return 7
}

func (p Present) Bytes() ([]byte, error) {
	return nil, nil
}

func ParsePresent(b []byte) (p *Present, err error) {
	var rawPresent asn1.RawValue

	_, err = asn1.Unmarshal(b, &rawPresent)
	if err != nil {
		err = NewLDAPError(ResultCodeProtocolError, "Invalid present")
		return
	}

	present := Present(rawPresent.Bytes)
	p = &present

	return
}

type ApproxMatch Filter
type ExtensibleMatch Filter

// ------------------------------------------------------------------
// SubstringFilter ::= SEQUENCE {
//      type           AttributeDescription,
//      substrings     SEQUENCE SIZE (1..MAX) OF substring CHOICE {
//           initial [0] AssertionValue,  -- can occur at most once
//           any     [1] AssertionValue,
//           final   [2] AssertionValue } -- can occur at most once
//      }
// ------------------------------------------------------------------

// ------------------------------------------------------------------
// MatchingRuleAssertion ::= SEQUENCE {
//      matchingRule    [1] MatchingRuleId OPTIONAL,
//      type            [2] AttributeDescription OPTIONAL,
//      matchValue      [3] AssertionValue,
//      dnAttributes    [4] BOOLEAN DEFAULT FALSE }
// ------------------------------------------------------------------
