openssl_prep:
	install -d $(BUILD_DIR)/openssl
	cp $(PACKAGE_DIR)/openssl/src/*  $(BUILD_DIR)/openssl/ -fr

openssl_build: openssl_prep
	( cd $(BUILD_DIR)/openssl/ && chmod +x Configure && ./Configure $(OS))
	$(MAKE) -C $(BUILD_DIR)/openssl/ all

openssl_install:
	install $(BUILD_DIR)/openssl/*.a  $(STAGING_DIR)/lib
	install -d $(STAGING_DIR)/include/openssl
	install $(BUILD_DIR)/openssl/include/openssl/*.h $(STAGING_DIR)/include/openssl

openssl_clean:
	rm -fr $(BUILD_DIR)/openssl/
