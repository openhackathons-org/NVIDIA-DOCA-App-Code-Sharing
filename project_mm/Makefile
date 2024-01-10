ARCH := $(shell uname -p)

$(info ARCH=$(ARCH))

ROOT_DIR=$(shell pwd)

ifeq ($(ARCH),x86_64)
SUBDIRS=$(shell ls -l | grep ^d | awk '{if($$9 != "build") if($$9 != "include") if($$9 != "proxy_func") if($$9 != "mtcp_conf") print $$9}')
INCLUDE_DIR = -I /opt/mellanox/doca/include -I $(ROOT_DIR)/include -L /opt/mellanox/doca/lib/x86_64-linux-gnu/
DEPS_OBJ =-ldl -lpthread -ldoca_common -ldoca_dma -ldoca_comm_channel
C_FLAGS=-fPIC -O2 -Wno-deprecated-declarations -Wno-implicit-function-declaration -fno-stack-protector -DMTCP_MODE
# -D_FORTIFY_SOURCE=0 -DUIO_MODE
#  -DDEBUG 
BIN=offload_module.so
endif

ifeq ($(ARCH),aarch64)
MTCP_PATH=/home/ubuntu/ACCELERAT_ENGINE/test/mtcp/install
SUBDIRS=$(shell ls -l | grep ^d | awk '{if($$9 != "build") if($$9 != "include") if($$9 != "fakefunc") if($$9 != "mtcp_conf") print $$9}')
INCLUDE_DIR = -I /opt/mellanox/doca/include -I $(ROOT_DIR)/include -I $(MTCP_PATH)/include -L /opt/mellanox/doca/lib/aarch64-linux-gnu/ 
DEPS_OBJ =-ldoca_common -ldoca_dma -ldoca_comm_channel
C_FLAGS=-O2 -Wno-deprecated-declarations -Wno-implicit-function-declaration -fno-stack-protector -DMTCP_MODE 
# -DDEBUG -DUIO_MODE
BIN=proxy_engine
# add for dpdk f-stack

ifeq ($(MTCP_PATH),)
    MTCP_PATH=/usr/local
    $(warning FF_PATH environment variable not defined, default MTCP_PATH=/usr/local)
endif

ifneq ($(shell pkg-config --exists libdpdk && echo 0),0)
$(error "no installation of DPDK found, maybe you shuld export environment variable `PKG_CONFIG_PATH`")
endif

# FINAL_CFLAGS+= -I$(MTCP_PATH)/lib

PKGCONF ?= pkg-config

DEPS_OBJ+= $(shell $(PKGCONF) --static --libs libdpdk)
# DEPS_OBJ+= -L${MTCP_PATH}/lib -Wl,--whole-archive,-lmtcp,--no-whole-archive
DEPS_OBJ+= -L${MTCP_PATH}/lib -Wl,--no-whole-archive
DEPS_OBJ+= -lrt -lm -ldl -lcrypto -lpthread -lnuma -lmtcp -lgmp


endif
	

OBJS_DIR=build/obj

BIN_DIR=build/bin

CUR_SOURCE=${wildcard *.c}

CUR_OBJS=${patsubst %.c, %.o, $(CUR_SOURCE)}

export CC BIN OBJS_DIR BIN_DIR ROOT_DIR INCLUDE_DIR C_FLAGS DEPS_OBJ MTCP_PATH

all : $(SUBDIRS) $(CUR_OBJS) BUILD

$(SUBDIRS) : ECHO
	make -C $@

BUILD:ECHO
	make -C build

ECHO:
	@echo $(SUBDIRS)

$(CUR_OBJS):%.o:%.c
	$(CC) -c $^ -o $(ROOT_DIR)/$(OBJS_DIR)/$@


.PHONY : clean
clean:
	find ./ | xargs file | awk -F: '$$2 ~ /ELF/ { print $$1 }' | xargs rm
