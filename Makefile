all: build

build:
	go build -o bin/testing cmd/testing/testing.go
	go build -o bin/delete cmd/delete/delete.go

clean:
	rm -rf bin
