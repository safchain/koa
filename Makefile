DEBUG=1
UID=$(shell id -u)
PWD=$(shell pwd)

DOCKER_FILE?=Dockerfile
DOCKER_IMAGE?=safchain/ebpf-builder

# If you can use docker without being root, you can do "make SUDO="
SUDO=$(shell docker info >/dev/null 2>&1 || echo "sudo -E")

all: build-docker-image build-ebpf-object mon

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
mon: proto
	go build -ldflags="-s -w" cmd/mon.go

proto: probes/malloc/malloc.pb.go probes/io/io.pb.go probes/cpu/cpu.pb.go
	protoc --go_out=.  probes/malloc/malloc.proto
	protoc --go_out=.  probes/io/io.proto
	protoc --go_out=.  probes/cpu/cpu.proto

delete-docker-image:
	$(SUDO) docker rmi -f $(DOCKER_IMAGE)
