thing_service_prep:
	install -d $(BUILD_DIR)/thing_service
	cp $(PACKAGE_DIR)/thing_service/src/*  $(BUILD_DIR)/thing_service/ -fr

thing_service_build: thing_service_prep
	$(MAKE) -C $(BUILD_DIR)/thing_service

thing_service_install:
	install $(BUILD_DIR)/thing_service/thing_service $(OUTPUT_DIR)/bin

thing_service_clean:
	rm -fr $(BUILD_DIR)/thing_service/
