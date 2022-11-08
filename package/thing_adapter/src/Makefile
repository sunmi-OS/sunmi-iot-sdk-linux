TARGET:=libadapter.so
OBJS := thing_adapter.o adapter_ubus.o

all: $(TARGET)

%.o: %.c
	$(CC) -fPIC -Wall -Werror $(CFLAGS) -c -o $@ $^

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -shared -o $@ $^
