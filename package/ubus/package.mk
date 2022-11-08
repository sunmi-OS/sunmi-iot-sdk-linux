ubus_prep:
	install -d $(BUILD_DIR)/ubus
	cp $(PACKAGE_DIR)/ubus/src/*  $(BUILD_DIR)/ubus/ -fr

ubus_build: ubus_prep
	cd $(BUILD_DIR)/ubus/ && cmake . -DCMAKE_C_COMPILER=$(CMAKE_C_COMPILER) -DCMAKE_PREFIX_PATH=$(CMAKE_PREFIX_PATH)
	$(MAKE) -C $(BUILD_DIR)/ubus/

ubus_install:
	install $(BUILD_DIR)/ubus/libubus.so  $(STAGING_DIR)/lib
	install $(BUILD_DIR)/ubus/*.h $(STAGING_DIR)/include

	install $(BUILD_DIR)/ubus/libubus.so  $(OUTPUT_DIR)/lib
	install $(BUILD_DIR)/ubus/ubus $(OUTPUT_DIR)/bin
	install $(BUILD_DIR)/ubus/ubusd $(OUTPUT_DIR)/bin

ubus_clean:
	rm -fr $(BUILD_DIR)/ubus/
