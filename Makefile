.PHONY: build test race vet bench eval report

build:
	go build -o jevgate .

test:
	go test ./...

# What CI runs.
race:
	go test -race -count=1 ./...

vet:
	go vet ./... && test -z "$$(gofmt -l .)"

bench:
	go test -run '^$$' -bench . -benchmem ./...

# Score the committed judgments. Spends nothing.
report: build
	./jevgate eval -report

# Judge the corpus again. Spends real requests (about $0.015 for 3 runs).
# Delete eval/results.jsonl first for a fresh measurement.
eval: build
	./jevgate eval
