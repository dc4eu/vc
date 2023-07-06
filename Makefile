NAME 					:= vc
SERVERS 				:= issuer verifier
LDFLAGS                 := -ldflags "-w -s --extldflags '-static'"


build: build-issuer build-verifier build-datastore

build-issuer:
	$(info Building issuer)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -v -o ./bin/$(NAME)_issuer ${LDFLAGS} ./cmd/issuer/main.go


build-verifier:
	$(info Building verifier)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -v -o ./bin/$(NAME)_verifier ${LDFLAGS} ./cmd/verifier/main.go

build-datastore:
	$(info Building datastore)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -v -o ./bin/$(NAME)_datastore ${LDFLAGS} ./cmd/datastore/main.go

test: test-issuer test-verifier test-datastore

test-issuer:
	$(info Testing issuer)
	go test -v ./cmd/issuer

test-verifier:
	$(info Testing verifier)
	go test -v ./cmd/verifier

test-datastore:
	$(info Testing datastore)
	go test -v ./cmd/datastore

start:
	$(info Run!)
	docker-compose -f docker-compose.yaml up -d

stop:
	$(info stopping VC)
	docker-compose -f docker-compose.yaml rm -s -f

restart: stop start

release-tag:
	@date +'%Y%m%d%H%M%S%9N'

ifndef VERSION
VERSION := latest
endif

docker-build: docker-build-issuer docker-build-verifier docker-build-datastore

DOCKER_TAG_ISSUER := docker.sunet.se/dc4eu/issuer:$(VERSION)
DOCKER_TAG_VERIFIER := docker.sunet.se/dc4eu/verifier:$(VERSION)
DOCKER_TAG_DATASTORE := docker.sunet.se/dc4eu/datastore:$(VERSION)

docker-build-issuer:
	$(info Docker Building issuer with tag: $(VERSION))
	docker build --tag $(DOCKER_TAG_ISSUER) --file dockerfiles/issuer .

docker-build-verifier:
	$(info Docker Building verifier with tag: $(VERSION))
	docker build --tag $(DOCKER_TAG_VERIFIER) --file dockerfiles/verifier .

docker-build-datastore:
	$(info Docker Building datastore with tag: $(VERSION))
	docker build --tag $(DOCKER_TAG_DATASTORE) --file dockerfiles/datastore .

docker-push:
	$(info Pushing docker images)
	docker push $(DOCKER_TAG_ISSUER)
	docker push $(DOCKER_TAG_VERIFIER)
	docker push $(DOCKER_TAG_DATASTORE)

clean_redis:
	$(info Cleaning redis volume)
	docker volume rm vc_redis_data 

clean_docker_images:
	$(info Cleaning docker images)
	docker rmi $(DOCKER_TAG_ISSUER) -f
	docker rmi $(DOCKER_TAG_VERIFIER) -f
	docker rmi $(DOCKER_TAG_DATASTORE) -f


ci_build: docker-build docker-push
	$(info CI Build)
