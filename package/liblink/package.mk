liblink_prep:
	install -d $(BUILD_DIR)/liblink
	cp $(PACKAGE_DIR)/liblink/src/*  $(BUILD_DIR)/liblink/ -fr

liblink_build: liblink_prep
	$(MAKE) -C $(BUILD_DIR)/liblink

liblink_install:
	install $(BUILD_DIR)/liblink/liblink.so  $(STAGING_DIR)/lib
	install $(BUILD_DIR)/liblink/liblink.so $(OUTPUT_DIR)/lib

	install -d $(STAGING_DIR)/include/link
	install $(BUILD_DIR)/liblink/*.h $(STAGING_DIR)/include/link

liblink_clean:
	rm -fr $(BUILD_DIR)/liblink/
