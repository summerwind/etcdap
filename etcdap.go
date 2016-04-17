package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	message "github.com/vjeantet/goldap/message"
	ldap "github.com/vjeantet/ldapserver"
)

const VERSION = "v0.1.0"

func main() {
	listenAddr := flag.String("listen", "0.0.0.0:389", "")
	etcdEndpoints := flag.String("etcd-endpoints", "http://127.0.0.1:2379", "")
	etcdPrefix := flag.String("etcd-prefix", "etcdap", "")
	version := flag.Bool("version", false, "")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS]\n\n", os.Args[0])
		fmt.Println("Options:")
		fmt.Println("  --listen:         The address and port of LDAP gateway (Default: 0.0.0.0:389)")
		fmt.Println("  --etcd-endpoints: A comma-delimited list of etcd endpoints (Default: http://127.0.0.1:2379)")
		fmt.Println("  --etcd-prefix:    Path prefix of etcd (Default: etcdap)")
		fmt.Println("  --version:        Display version information and exit.")
		fmt.Println("  --help:           Display this help and exit.")
		os.Exit(1)
	}

	flag.Parse()

	if *version {
		log.Printf("etcdap %s\n", VERSION)
		os.Exit(0)
	}

	be, err := NewEtcdBackend(strings.Split(*etcdEndpoints, ","), *etcdPrefix)
	if err != nil {
		log.Fatalf("Backend error: %s", err)
		os.Exit(1)
	}

	routes := ldap.NewRouteMux()
	routes.Bind(handleBind(be))
	routes.Search(handleSearch(be))

	server := ldap.NewServer()
	server.Handle(routes)

	ch := make(chan os.Signal)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-ch
		close(ch)
		server.Stop()
		os.Exit(0)
	}()

	err = server.ListenAndServe(*listenAddr)
	if err != nil {
		log.Fatalf("Gateway error: %s", err)
		os.Exit(1)
	}
	server.Stop()
}

func handleBind(be Backend) func(w ldap.ResponseWriter, m *ldap.Message) {
	return func(w ldap.ResponseWriter, m *ldap.Message) {
		req := m.GetBindRequest()
		res := ldap.NewBindResponse(ldap.LDAPResultSuccess)

		dn := string(req.Name())
		pw := string(req.AuthenticationSimple())

		log.Printf("Bind Request: DN=%s", dn)
		if dn == "" && pw == "" {
			w.Write(res)
			log.Printf("Bind Response: Success")
			return
		}

		user, err := be.Get(dn)
		if err != nil {
			log.Printf("Backend error: %s", err)
			res.SetResultCode(ldap.LDAPResultNoSuchObject)
			res.SetDiagnosticMessage("No such object")
			w.Write(res)
			return
		}

		pwHash := sha256.Sum256([]byte(pw))
		if user.Password != hex.EncodeToString(pwHash[:]) {
			msg := "Invalid credentials"
			log.Printf("Bind Response: %s", msg)
			res.SetResultCode(ldap.LDAPResultInvalidCredentials)
			res.SetDiagnosticMessage(msg)
			w.Write(res)
			return
		}

		w.Write(res)
		log.Printf("Bind Response: Success")
	}
}

func handleSearch(be Backend) func(w ldap.ResponseWriter, m *ldap.Message) {
	return func(w ldap.ResponseWriter, m *ldap.Message) {
		req := m.GetSearchRequest()
		res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess)
		filter := map[string]string{}

		log.Printf(
			"Search Request: BaseDn=%s, Filter=%s, Attributes=%s, TimeLimit=%d",
			req.BaseObject(), req.FilterString(), req.Attributes(), req.TimeLimit().Int())

		invalidFilter := false
		switch f := req.Filter().(type) {
		case message.FilterEqualityMatch:
			if f.AttributeDesc() == "cn" {
				filter["cn"] = string(f.AssertionValue())
			} else {
				invalidFilter = true
			}
		default:
			invalidFilter = true
		}

		if invalidFilter {
			log.Printf("Unsupported search filter: %s", req.FilterString())
			res.SetResultCode(ldap.LDAPResultOperationsError)
			w.Write(res)
			return
		}

		users, err := be.Search(string(req.BaseObject()), filter)
		if err != nil {
			log.Printf("Backend error: %s", err)
			res.SetResultCode(ldap.LDAPResultOperationsError)
			w.Write(res)
			return
		}

		for _, user := range users {
			entry := ldap.NewSearchResultEntry(user.Dn)
			for _, attr := range req.Attributes() {
				switch message.AttributeDescription(attr) {
				case "cn":
					entry.AddAttribute("cn", message.AttributeValue(user.Cn))
				case "name":
					entry.AddAttribute("name", message.AttributeValue(user.Name))
				case "email":
					entry.AddAttribute("email", message.AttributeValue(user.Email))
				}
			}
			w.Write(entry)
		}

		w.Write(res)
	}
}
