NAME 					:= vc
SERVERS 				:= issuer verifier
LDFLAGS                 := -ldflags "-w -s --extldflags '-static'"


build: build-issuer build-verifier

build-issuer:
	$(info Building issuer)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -v -o ./bin/$(NAME)_issuer ${LDFLAGS} ./cmd/issuer/main.go


build-verifier:
	$(info Building verifier)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -v -o ./bin/$(NAME)_verifier ${LDFLAGS} ./cmd/verifier/main.go

test: test-issuer test-verifier

test-issuer:
	$(info Testing issuer)
	go test -v ./cmd/issuer

test-verifier:
	$(info Testing verifier)
	go test -v ./cmd/verifier

start:
	$(info Run!)
	docker-compose -f docker-compose.yaml up -d

stop:
	$(info stopping VC)
	docker-compose -f docker-compose.yaml rm -s -f

restart: stop start

docker-build-issuer:
	$(info Docker Building issuer)
	docker build --tag vc_issuer:latest --file dockerfiles/issuer .

docker-build-verifier:
	$(info Docker Building verifier)
	docker build --tag vc_verifier:latest --file dockerfiles/verifier .