TARGET:=liblink.so
OBJS := ubus.o log.o

all: $(TARGET)

%.o: %.c
	$(CC) -fPIC -Wall -Werror $(CFLAGS) -c -o $@ $^

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -shared -o $@ $^

