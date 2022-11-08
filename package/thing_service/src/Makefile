thing_service: thing_service.o device.o service_ubus.o service.o
	$(CC) -o $@ $^ $(LDFLAGS) -lrt -ldl -lpthread -ljson-c -lblobmsg_json -lubox -lubus -llink -lssl -lcrypto -lcjson
