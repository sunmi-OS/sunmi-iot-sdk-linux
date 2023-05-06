openssl_prep:
	install -d $(BUILD_DIR)/openssl
	rsync -a $(PACKAGE_DIR)/openssl/src/*  $(BUILD_DIR)/openssl/

openssl_build: openssl_prep
	( cd $(BUILD_DIR)/openssl/ && chmod +x Configure && ./Configure shared $(OS))
	$(MAKE) -C $(BUILD_DIR)/openssl/ all

openssl_install:
	cp -a $(BUILD_DIR)/openssl/lib*.so* $(OUTPUT_DIR)/lib
	cp -a $(BUILD_DIR)/openssl/lib*.so* $(STAGING_DIR)/lib
	install -d $(STAGING_DIR)/include/openssl
	install $(BUILD_DIR)/openssl/include/openssl/*.h $(STAGING_DIR)/include/openssl

openssl_clean:
	rm -fr $(BUILD_DIR)/openssl/
