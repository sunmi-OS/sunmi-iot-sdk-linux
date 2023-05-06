mosquitto_prep:
	install -d $(BUILD_DIR)/mosquitto
	rsync -a $(PACKAGE_DIR)/mosquitto/src/*  $(BUILD_DIR)/mosquitto/ 

mosquitto_build: mosquitto_prep
	$(MAKE) -C $(BUILD_DIR)/mosquitto/ WITH_STATIC_LIBRARIES=no WITH_SHARED_LIBRARIES=yes WITH_TLS=yes WITH_THREADING=yes WITH_SRV=no WITH_DOCS=no

mosquitto_install:
	cp -a $(BUILD_DIR)/mosquitto/lib/libmosquitto.so* $(OUTPUT_DIR)/lib
	cp -a $(BUILD_DIR)/mosquitto/lib/libmosquitto.so* $(STAGING_DIR)/lib
	install $(BUILD_DIR)/mosquitto/include/*.h $(STAGING_DIR)/include

mosquitto_clean:
	rm -fr $(BUILD_DIR)/mosquitto/
