thing_adapter_prep:
	install -d $(BUILD_DIR)/thing_adapter
	rsync -a $(PACKAGE_DIR)/thing_adapter/src/*  $(BUILD_DIR)/thing_adapter/

thing_adapter_build: thing_adapter_prep
	$(MAKE) -C $(BUILD_DIR)/thing_adapter

thing_adapter_install:
	cp -a $(BUILD_DIR)/thing_adapter/libadapter.so  $(STAGING_DIR)/lib
	cp -a $(BUILD_DIR)/thing_adapter/libadapter.so $(OUTPUT_DIR)/lib

	install -d $(STAGING_DIR)/include/link
	install $(BUILD_DIR)/thing_adapter/thing_adapter.h $(STAGING_DIR)/include/

thing_adapter_clean:
	rm -fr $(BUILD_DIR)/thing_adapter/
