goscanner: *.go git-version scanner/asset/assets.go
	go build
	rm git-version

git-version:
	git rev-parse HEAD > git-version

goget:
	go get -f -u

scanner/asset/assets.go:
	go generate

all : git-version scanner/asset/assets.go goget goscanner
