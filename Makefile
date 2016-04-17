all:
	mkdir etcdap_darwin_amd64
	GOARCH=amd64 GOOS=darwin go build
	mv etcdap etcdap_darwin_amd64/
	tar cfvz etcdap_darwin_amd64.tar.gz etcdap_darwin_amd64
	rm -rf etcdap_darwin_amd64
	
	mkdir etcdap_linux_amd64
	GOARCH=amd64 GOOS=linux go build
	mv etcdap etcdap_linux_amd64/
	tar cfvz etcdap_linux_amd64.tar.gz etcdap_linux_amd64
	rm -rf etcdap_linux_amd64
