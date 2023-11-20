libcurl_prep:
	install -d $(BUILD_DIR)/libcurl
	rsync -a $(PACKAGE_DIR)/libcurl/src/*  $(BUILD_DIR)/libcurl/

libcurl_build: libcurl_prep
	( cd $(BUILD_DIR)/libcurl/ && ./buildconf && chmod +x configure  && LDFLAGS=-R$(STAGING_DIR)/lib ./configure --enable-shared --host=${HOST} --disable-rtsp --disable-libcurl-option --disable-manual --disable-ipv6 --disable-debug --disable-tls-srp --disable-unix-sockets  --disable-verbose --with-ssl="$(STAGING_DIR)" )
	$(MAKE) -C $(BUILD_DIR)/libcurl/

libcurl_install:
	cp -a $(BUILD_DIR)/libcurl/lib/.libs/libcurl.so*  $(STAGING_DIR)/lib
	cp -a $(BUILD_DIR)/libcurl/lib/.libs/libcurl.so*  $(OUTPUT_DIR)/lib
	install -d $(STAGING_DIR)/include/curl
	cp $(BUILD_DIR)/libcurl/include/curl/*.h $(STAGING_DIR)/include/curl

libcurl_clean:
	rm -fr $(BUILD_DIR)/libcurl/
