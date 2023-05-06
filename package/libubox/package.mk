libubox_prep:
	install -d $(BUILD_DIR)/libubox
	cp $(PACKAGE_DIR)/libubox/src/*  $(BUILD_DIR)/libubox/ -fr

libubox_build: libubox_prep
	cd $(BUILD_DIR)/libubox/ && cmake . -DCMAKE_C_COMPILER=$(CMAKE_C_COMPILER) -DCMAKE_PREFIX_PATH=$(CMAKE_PREFIX_PATH)
	$(MAKE) -C $(BUILD_DIR)/libubox/

libubox_install:
	cp -a $(BUILD_DIR)/libubox/lib*.so  $(STAGING_DIR)/lib
	cp -a $(BUILD_DIR)/libubox/lib*.so  $(OUTPUT_DIR)/lib

	install -d $(STAGING_DIR)/include/libubox
	install $(BUILD_DIR)/libubox/*.h $(STAGING_DIR)/include/libubox

libubox_clean:
	rm -fr $(BUILD_DIR)/libubox/
