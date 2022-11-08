demo_adapter_prep:
	install -d $(BUILD_DIR)/demo_adapter
	cp $(PACKAGE_DIR)/demo_adapter/src/*  $(BUILD_DIR)/demo_adapter/ -fr

demo_adapter_build: demo_adapter_prep
	$(MAKE) -C $(BUILD_DIR)/demo_adapter

demo_adapter_install:
	install $(BUILD_DIR)/demo_adapter/demo_adapter $(OUTPUT_DIR)/bin

demo_adapter_clean:
	rm -fr $(BUILD_DIR)/demo_adapter/
