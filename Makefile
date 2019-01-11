DEBUG=1
UID=$(shell id -u)
PWD=$(shell pwd)

DOCKER_FILE?=Dockerfile
DOCKER_IMAGE?=safchain/ebpf-builder

# If you can use docker without being root, you can do "make SUDO="
SUDO=$(shell docker info >/dev/null 2>&1 || echo "sudo -E")

all: build-docker-image build-ebpf-object ebperf collector

build-docker-image:
	$(SUDO) docker build -t $(DOCKER_IMAGE) -f $(DOCKER_FILE) .

build-ebpf-object:
	$(SUDO) docker run --rm -e DEBUG=$(DEBUG) \
		-v $(PWD)/ebpf:/ebpf/ \
		--workdir=/ebpf \
		$(DOCKER_IMAGE) \
		make
	sudo chown -R $(UID):$(UID) ebpf

.PHONY: mon
ebperf: proto
	go install -ldflags="-s -w" ./cmd/ebperf/...

.PHONY: collector
collector:
	go install -ldflags="-s -w" ./cmd/collector/...

api/types/proc.pb.go: api/types/proc.proto
	protoc --go_out=$$GOPATH/src api/types/proc.proto

api/api.pb.go: api/types/proc.proto api/api.proto
	protoc --go_out=plugins=grpc:. api/api.proto

proto: api/types/proc.pb.go api/api.pb.go

delete-docker-image:
	$(SUDO) docker rmi -f $(DOCKER_IMAGE)
