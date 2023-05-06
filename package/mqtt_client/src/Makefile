mqtt_client: mqtt_client.o mqtt.o mqtt_ubus.o
	$(CC) -o $@ $^ $(LDFLAGS) -Werror -lmosquitto -llink -lssl -lcrypto -lrt -ldl -lblobmsg_json -ljson-c -lpthread -lubox  -lubus 
