include config.mk

#根目录
export TOP_DIR := $(shell pwd)
#链接目录
export STAGING_DIR := $(abspath staging_dir)
#编译目录
export BUILD_DIR := $(abspath build_dir)
#源码目录
export PACKAGE_DIR := $(abspath package)
#编译输出目录
export OUTPUT_DIR := $(abspath output)
#工具链目录
TOOLCHAIN_DIR := $(abspath $(TOOLCHAIN_PATH))
#安装目录
INSTALL_DIR := $(abspath ../../homefs)

#交叉编译设置
export CC=$(TOOLCHAIN_DIR)/$(CROSS_COMPILE_PRIFIX)gcc
export LD=$(TOOLCHAIN_DIR)/$(CROSS_COMPILE_PRIFIX)ld
export AR=$(TOOLCHAIN_DIR)/$(CROSS_COMPILE_PRIFIX)ar
export CXX=$(TOOLCHAIN_DIR)/$(CROSS_COMPILE_PRIFIX)g++
export STRIP=$(TOOLCHAIN_DIR)/$(CROSS_COMPILE_PRIFIX)strip

export CMAKE_C_COMPILER=$(TOOLCHAIN_DIR)/$(CROSS_COMPILE_PRIFIX)gcc
export CMAKE_PREFIX_PATH=$(STAGING_DIR)

export CFLAGS=-I$(STAGING_DIR)/include -Wall
export LDFLAGS=-L$(STAGING_DIR)/lib -lrt

.PHONY: all prepare clean
all:

#编译目标
PACKAGE := cJSON openssl json-c libubox ubus liblink  mosquitto thing_adapter libcurl ota_sdk mqtt_client thing_service demo_adapter ota_demo 
include $(PACKAGE_DIR)/*/package.mk

$(PACKAGE):%:%_prep %_build %_install
	@echo make $@ done

all: prepare $(PACKAGE)

prepare:
	install -d $(BUILD_DIR)
	install -d $(STAGING_DIR)/include
	install -d $(STAGING_DIR)/lib
	install -d $(OUTPUT_DIR)/bin
	install -d $(OUTPUT_DIR)/lib

clean:
	rm -fr $(BUILD_DIR)
	rm -fr $(STAGING_DIR)
	rm -fr $(OUTPUT_DIR)

install:
	find $(OUTPUT_DIR) -type f | xargs $(STRIP)
	install -d $(INSTALL_DIR)/bin
	install $(OUTPUT_DIR)/bin/* $(INSTALL_DIR)/bin
	install -d $(INSTALL_DIR)/lib
	cp -fpR $(OUTPUT_DIR)/lib/* $(INSTALL_DIR)/lib
