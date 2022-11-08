libubox_prep:
	install -d $(BUILD_DIR)/libubox
	cp $(PACKAGE_DIR)/libubox/src/*  $(BUILD_DIR)/libubox/ -fr

libubox_build: libubox_prep
	cd $(BUILD_DIR)/libubox/ && cmake . -DCMAKE_C_COMPILER=$(CMAKE_C_COMPILER) -DCMAKE_PREFIX_PATH=$(CMAKE_PREFIX_PATH)
	$(MAKE) -C $(BUILD_DIR)/libubox/

libubox_install:
	install $(BUILD_DIR)/libubox/libblobmsg_json.a  $(STAGING_DIR)/lib
	install $(BUILD_DIR)/libubox/libubox.a  $(STAGING_DIR)/lib
	install $(BUILD_DIR)/libubox/lib*.so  $(STAGING_DIR)/lib

	install -d $(STAGING_DIR)/include/libubox
	install $(BUILD_DIR)/libubox/*.h $(STAGING_DIR)/include/libubox

	install $(BUILD_DIR)/libubox/libubox.so  $(OUTPUT_DIR)/lib
	install $(BUILD_DIR)/libubox/libblobmsg_json.so  $(OUTPUT_DIR)/lib

libubox_clean:
	rm -fr $(BUILD_DIR)/libubox/
