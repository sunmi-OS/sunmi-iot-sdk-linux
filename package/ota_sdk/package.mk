ota_sdk_prep:
	install -d $(BUILD_DIR)/ota_sdk
	rsync -a $(PACKAGE_DIR)/ota_sdk/src/*  $(BUILD_DIR)/ota_sdk/

ota_sdk_build: ota_sdk_prep
	$(MAKE) -C $(BUILD_DIR)/ota_sdk

ota_sdk_install:
	cp -a $(BUILD_DIR)/ota_sdk/libota_sdk.so $(OUTPUT_DIR)/lib
	cp -a $(BUILD_DIR)/ota_sdk/libota_sdk.so $(STAGING_DIR)/lib

	install -d $(STAGING_DIR)/include/
	install $(BUILD_DIR)/ota_sdk/ota.h $(STAGING_DIR)/include/

ota_sdk_clean:
	rm -fr $(BUILD_DIR)/ota_sdk/
