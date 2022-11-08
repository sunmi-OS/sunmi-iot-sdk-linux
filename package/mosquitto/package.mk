mosquitto_prep:
	install -d $(BUILD_DIR)/mosquitto
	cp $(PACKAGE_DIR)/mosquitto/src/*  $(BUILD_DIR)/mosquitto/ -fr

mosquitto_build: mosquitto_prep
	$(MAKE) -C $(BUILD_DIR)/mosquitto/ WITH_STATIC_LIBRARIES=yes WITH_SHARED_LIBRARIES=no WITH_TLS=yes WITH_THREADING=yes WITH_SRV=no WITH_DOCS=no

mosquitto_install:
	install $(BUILD_DIR)/mosquitto/lib/libmosquitto.a  $(STAGING_DIR)/lib
	install $(BUILD_DIR)/mosquitto/include/*.h $(STAGING_DIR)/include

mosquitto_clean:
	rm -fr $(BUILD_DIR)/mosquitto/
