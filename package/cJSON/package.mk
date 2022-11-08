cJSON_prep:
	install -d $(BUILD_DIR)/cJSON
	cp $(PACKAGE_DIR)/cJSON/src/*  $(BUILD_DIR)/cJSON/ -fr

cJSON_build: cJSON_prep
	$(MAKE) -C $(BUILD_DIR)/cJSON/ all

cJSON_install:
	install $(BUILD_DIR)/cJSON/libcjson.a  $(STAGING_DIR)/lib
	install -d $(STAGING_DIR)/include/cjson
	install $(BUILD_DIR)/cJSON/cJSON.h $(STAGING_DIR)/include/cjson

cJSON_clean:
	rm -fr $(BUILD_DIR)/cJSON/
