mqtt_client: mqtt_client.o mqtt.o mqtt_ubus.o
	$(CC) -o $@ $^ $(LDFLAGS) -Werror -lmosquitto -lssl -lcrypto -lrt -ldl -ljson-c -lpthread -lblobmsg_json -lubox -lubus -llink
