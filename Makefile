
test:
	go test -v ./...



benchmark:
	go test ./... -bench=. -benchtime 100000x -count 5



profiling:
	go test -bench=. -benchtime 100000x -run=^$ -cpuprofile=cpu.prof -memprofile=prof.mem


coverage:
	go test -coverprofile coverage ./...


code-check:
	go vet -v ./...

clean:
	rm -rf coverage


all: test coverage code-check