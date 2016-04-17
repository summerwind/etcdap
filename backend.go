package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/net/context"
	"reflect"
	"strings"
	"unicode"
	"unicode/utf8"

	etcd "github.com/coreos/etcd/client"
)

type Backend interface {
	Get(dn string) (*User, error)
	Search(baseDn string, filter map[string]string) ([]*User, error)
}

type EtcdBackend struct {
	client etcd.Client
	api    etcd.KeysAPI
	prefix string
}

func (be *EtcdBackend) Get(dn string) (*User, error) {
	path, id, err := be.dnToPathAndID(dn)
	if err != nil {
		return nil, err
	}

	opt := etcd.GetOptions{}

	res, err := be.api.Get(context.Background(), path, &opt)
	if err != nil {
		return nil, err
	}

	user := NewUser(dn, id)

	err = json.Unmarshal([]byte(res.Node.Value), &user)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (be *EtcdBackend) Search(baseDn string, filter map[string]string) ([]*User, error) {
	users := []*User{}

	path, _, err := be.dnToPathAndID(baseDn)
	if err != nil {
		return nil, err
	}

	opt := etcd.GetOptions{
		Recursive: true,
	}

	res, err := be.api.Get(context.Background(), path, &opt)
	if err != nil {
		return nil, err
	}

	if res.Node.Nodes == nil {
		return users, nil
	}

	for _, node := range res.Node.Nodes {
		path := node.Key
		dn, id, err := be.pathToDNAndID(path)

		user := NewUser(dn, id)

		err = json.Unmarshal([]byte(node.Value), &user)
		if err != nil {
			return nil, err
		}

		userRef := reflect.ValueOf(*user)
		matched := true
		for k, v := range filter {
			r, n := utf8.DecodeRuneInString(k)
			fn := string(unicode.ToUpper(r)) + k[n:]

			if userRef.FieldByName(fn).String() != v {
				matched = false
			}
		}

		if matched {
			users = append(users, user)
		}
	}

	return users, nil
}

func (be *EtcdBackend) SetPrefix(prefix string) {
	be.prefix = prefix
}

func (be *EtcdBackend) dnToPathAndID(dn string) (string, string, error) {
	path := []string{}
	invalid := false

	parts := strings.Split(dn, ",")

	if len(parts) > 1 {
		domain := []string{}

		for _, part := range parts {
			switch {
			case strings.HasPrefix(part, "dc="):
				splitedPart := strings.Split(part, "=")
				domain = append(domain, splitedPart[1])
			case strings.HasPrefix(part, "ou=") || strings.HasPrefix(part, "cn="):
				splitedPart := strings.Split(part, "=")
				path = append([]string{splitedPart[1]}, path...)
			default:
				invalid = true
				break
			}
		}

		path = append([]string{strings.Join(domain, ".")}, path...)
	} else {
		if strings.HasPrefix(parts[0], "cn=") {
			splitedPart := strings.Split(parts[0], "=")
			path = append(path, splitedPart[1])
		} else {
			invalid = true
		}
	}

	if invalid {
		return "", "", errors.New("Invalid DN")
	}

	return fmt.Sprintf("/%s/%s", be.prefix, strings.Join(path, "/")), path[len(path)-1], nil
}

func (be *EtcdBackend) pathToDNAndID(path string) (string, string, error) {
	dn := []string{}
	id := ""

	// Remove root delimiter
	path = path[1:]

	splitedPath := strings.Split(path, "/")
	splitedPath = splitedPath[1:]

	last := len(splitedPath) - 1
	for i, p := range splitedPath {
		switch {
		case i == 0:
			if strings.Contains(p, ".") {
				for _, domain := range strings.Split(p, ".") {
					dc := fmt.Sprintf("dc=%s", domain)
					dn = append(dn, dc)
				}
			} else {
				o := fmt.Sprintf("o=%s", p)
				dn = append([]string{o}, dn...)
			}
		case i == last:
			cn := fmt.Sprintf("cn=%s", p)
			dn = append([]string{cn}, dn...)
			id = p
		default:
			ou := fmt.Sprintf("ou=%s", p)
			dn = append([]string{ou}, dn...)
		}
	}

	return strings.Join(dn, ","), id, nil
}

func NewEtcdBackend(endpoints []string, prefix string) (*EtcdBackend, error) {
	cfg := etcd.Config{
		Endpoints: endpoints,
		Transport: etcd.DefaultTransport,
	}

	client, err := etcd.New(cfg)
	if err != nil {
		return nil, err
	}

	api := etcd.NewKeysAPI(client)

	return &EtcdBackend{
		client: client,
		api:    api,
		prefix: prefix,
	}, nil
}
