thing_service: thing_service.o device.o service_ubus.o service.o
	$(CC) -o $@ $^ $(LDFLAGS) -lrt  -lpthread -llink -lblobmsg_json -ljson-c -lubox -lubus -lssl -lcrypto -lcjson -ldl
