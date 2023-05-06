TARGET:=libota_sdk.so
OBJS := ubus.o download.o crypt.o http.o mqtt.o ota.o

CFLAGS+=-Wno-error=int-to-pointer-cast -Wno-error=pointer-to-int-cast

all: $(TARGET)

%.o: %.c
	$(CC) -fPIC -Wall -Werror $(CFLAGS) -c -o $@ $^ 

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -shared -o $@ $^

