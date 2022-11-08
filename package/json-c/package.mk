json-c_prep:
	install -d $(BUILD_DIR)/json-c
	cp $(PACKAGE_DIR)/json-c/src/*  $(BUILD_DIR)/json-c/ -fr

json-c_build: json-c_prep
	cd $(BUILD_DIR)/json-c/ && chmod +x autogen.sh && ./autogen.sh && ./configure --host=mips-linux-gnu
	#fix config.h.in
	sed -i 's/#undef malloc/\/\/#undef malloc/' $(BUILD_DIR)/json-c/config.h.in
	sed -i 's/#undef realloc/\/\/#undef realloc/' $(BUILD_DIR)/json-c/config.h.in
	$(MAKE) -C $(BUILD_DIR)/json-c

json-c_install:
	cp -fpR $(BUILD_DIR)/json-c/.libs/libjson-c.a  $(STAGING_DIR)/lib
	cp -fpR $(BUILD_DIR)/json-c/.libs/libjson-c.so*  $(STAGING_DIR)/lib
	install -d $(STAGING_DIR)/include/json
	install $(BUILD_DIR)/json-c/*.h $(STAGING_DIR)/include/json	

	cp -fpR $(BUILD_DIR)/json-c/.libs/libjson-c.so*  $(OUTPUT_DIR)/lib

json-c_clean:
	rm -fr $(BUILD_DIR)/json-c/
