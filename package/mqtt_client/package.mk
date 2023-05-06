mqtt_client_prep:
	install -d $(BUILD_DIR)/mqtt_client
	rsync -a $(PACKAGE_DIR)/mqtt_client/src/*  $(BUILD_DIR)/mqtt_client/

mqtt_client_build: mqtt_client_prep
	$(MAKE) -C $(BUILD_DIR)/mqtt_client

mqtt_client_install:
	install $(BUILD_DIR)/mqtt_client/mqtt_client $(OUTPUT_DIR)/bin

mqtt_client_clean:
	rm -fr $(BUILD_DIR)/mqtt_client/
