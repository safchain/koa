SHELL=/bin/bash -o pipefail
DEST_DIR?=./module
INCLUDE_DIR?=./include
SRC_DIR?=./src
LINUX_HEADERS=$(shell rpm -q kernel-devel --last | head -n 1 | awk -F'kernel-devel-' '{print "/usr/src/kernels/"$$2}' | cut -d " " -f 1)

HFILES:=$(wildcard ${INCLUDE_DIR}/*.h)
CFILES:=$(wildcard ${SRC_DIR}/*.c)
OBJS:=$(CFILES:%.c=%.o)

all:$(OBJS) ${DEST_DIR}/ebpf.go

$(CFILES):$(HFILES)

${SRC_DIR}/%.o:${SRC_DIR}/%.c
	@mkdir -p "$(DEST_DIR)"
	clang -D__KERNEL__ -D__ASM_SYSREG_H \
		-Wno-unused-value \
		-Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Wunused \
		-Wall \
		-Werror \
		-O2 -emit-llvm -c $< \
		$(foreach path,$(LINUX_HEADERS), -I $(path)/arch/x86/include \
		-I $(path)/arch/x86/include/generated -I $(path)/include \
		-I $(path)/include/generated/uapi -I $(path)/arch/x86/include/uapi -I $(path)/include/uapi) \
		-I ${INCLUDE_DIR} \
		-o - | llc -march=bpf -filetype=obj -o $@
	cp $@ ${DEST_DIR}

${DEST_DIR}/ebpf.go:$(OBJS)
	go-bindata -pkg ebpf -prefix "${DEST_DIR}/" -modtime 1 -ignore="${DEST_DIR}/ebpf.go" -o "${DEST_DIR}/ebpf.go" "${DEST_DIR}/..."
