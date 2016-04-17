# etcdap

**etcdap** is the experimental LDAP gateway for etcd.

## Install

```
$ go get github.com/summerwind/etcdap
```

## Usage

```
Usage: etcdap [OPTIONS]

Options:
  --listen:         The address and port of LDAP gateway (Default: 0.0.0.0:389)
  --etcd-endpoints: A comma-delimited list of etcd endpoints (Default: http://127.0.0.1:2379)
  --etcd-prefix:    Path prefix of etcd (Default: etcdap)
  --version:        Display version information and exit.
```

## Motivation

There are lot of products that support LDAP. But LDAP is bit complex. Operating LDAP servers and manage your directory trees are hard for those who don't have the knowledge of LDAP.

etcdap will solve this problem. As with other products that use etcd, you can manage directory tree by using key and value pair of etcd. This means that it does not require knowlege of LDAP.

## How to use

### Creating manager

Generating password hash for the manager.

```
$ MANAGER_PASS=`echo -n "password" | openssl sha -sha256`
```

Creating the manager on etcd. Note that you need to set the key under */etcdap*. */etcdap* is the default prefix. You can change the default prefix with `--etcd-prefix` option.

```
$ etcdctl set \
    /etcdap/manager \
    "{\"name\": \"Directory Manager\", \"email\": \"admin@example.com\", \"password\": \"${MANAGER_PASS}\"}"
```

Now you can access to the manager by following *DN*.

```
cn=manager
```

### Creating user

Generating password hash for the user.

```
$ USER_PASS=`echo -n "password" | openssl sha -sha256`
```

Creating the directories on etcd. These directories is converted as *DN* or *OU* of LDAP by etcdap.

```
$ etcdctl mkdir /etcdap/example.com
$ etcdctl mkdir /etcdap/example.com/People
```

Creating the user on etcd.

```
$ etcdctl set \
    /etcdap/example.com/People/mark \
    "{\"name\": \"Mark Sato\", \"email\": \"mark@example.com\", \"password\": \"${USER_PASS}\"}"
```

Now you can access to the user by following *DN*.

```
cn=mark,ou=People,dn=example,dn=com
```

## Mapping of DN and etcd path

DN | etcd path
--- | ---
cn=admin | /admin
cn=mark,dc=example,dc=com | /example.com/mark
cn=mark,ou=People,dc=example,dc=com | /example.com/People/mark
cn=mark,ou=Engineer,ou=People,dc=example,dc=com | /example.com/People/Engineer/mark
cn=mark,o=example | /examplemark
cn=mark,ou=People,o=example | /example/People/mark
cn=mark,ou=Engineer,ou=People,o=example | /example/People/Engineer/mark

