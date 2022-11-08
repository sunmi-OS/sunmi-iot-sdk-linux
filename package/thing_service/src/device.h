#ifndef _THING_SERVICE_DEVICE_H_
#define _THING_SERVICE_DEVICE_H_

#include "link/common.h"
#include "service_ubus.h"

#define THING_SERVICE_DEVICE_HOST_LEN     (32)
#define THING_SERVICE_DEVICE_ID_LEN     (128)
#define THING_SERVICE_DEVICE_SECRET_LEN     (128)

typedef struct _DEVICE_CONFIG{
    char host[THING_SERVICE_DEVICE_HOST_LEN];
    int port;
    char device_id[THING_SERVICE_DEVICE_ID_LEN];
    char device_secret[THING_SERVICE_DEVICE_SECRET_LEN];
}DEVICE_CONFIG;

int get_timestamp();
int thing_service_get_mqtt_host(char* host);
int thing_service_get_mqtt_port(int* port);
int thing_service_get_mqtt_username(char *device_id, int timestamp, char* username, int len);
int thing_service_get_mqtt_password(char *device_id, char *device_secret, int timestamp, char* password, int len);
int thing_service_get_mqtt_client_id(char *device_id, char* client_id, int len);
int thing_service_set_device_info(char* host, int port, char* device_id, char* device_secret);
int thing_service_get_device_id(char* device_id);
int thing_service_get_device_secret(char* device_secret);
int thing_service_subscribe_mqtt_topics();
int thing_service_config_mqtt();

#endif

