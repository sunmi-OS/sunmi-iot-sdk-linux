mqtt_client_prep:
	install -d $(BUILD_DIR)/mqtt_client
	cp $(PACKAGE_DIR)/mqtt_client/src/*  $(BUILD_DIR)/mqtt_client/ -fr

mqtt_client_build: mqtt_client_prep
	$(MAKE) -C $(BUILD_DIR)/mqtt_client

mqtt_client_install:
	install $(BUILD_DIR)/mqtt_client/mqtt_client $(OUTPUT_DIR)/bin

mqtt_client_clean:
	rm -fr $(BUILD_DIR)/mqtt_client/
