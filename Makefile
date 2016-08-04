ca: *.go
	go build
format:
	gofmt -w *.go
clean:
	rm -f goca
