cJSON_prep:
	install -d $(BUILD_DIR)/cJSON
	rsync -a $(PACKAGE_DIR)/cJSON/src/*  $(BUILD_DIR)/cJSON/

cJSON_build: cJSON_prep
	$(MAKE) -C $(BUILD_DIR)/cJSON/ all

cJSON_install:
	cp -a $(BUILD_DIR)/cJSON/libcjson.so* $(OUTPUT_DIR)/lib
	cp -a $(BUILD_DIR)/cJSON/libcjson.so* $(STAGING_DIR)/lib
	install -d $(STAGING_DIR)/include/
	install $(BUILD_DIR)/cJSON/cJSON.h $(STAGING_DIR)/include/

cJSON_clean:
	rm -fr $(BUILD_DIR)/cJSON/
