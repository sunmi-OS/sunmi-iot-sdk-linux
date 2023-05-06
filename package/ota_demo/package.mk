ota_demo_prep:
	install -d $(BUILD_DIR)/ota_demo
	rsync -a $(PACKAGE_DIR)/ota_demo/src/*  $(BUILD_DIR)/ota_demo/

ota_demo_build: ota_demo_prep
	$(MAKE) -C $(BUILD_DIR)/ota_demo

ota_demo_install:
	install $(BUILD_DIR)/ota_demo/ota_demo $(OUTPUT_DIR)/bin

ota_demo_clean:
	rm -fr $(BUILD_DIR)/ota_demo/
