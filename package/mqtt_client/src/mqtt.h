#ifndef _MQTT_CLIENT_MQTT_H_
#define _MQTT_CLIENT_MQTT_H_

#include "link/common.h"

enum mosquitto_client_state {
	mosq_cs_new = 0,
	mosq_cs_connected = 1,
	mosq_cs_disconnecting = 2,
	mosq_cs_active = 3,
	mosq_cs_connect_pending = 4,
	mosq_cs_connect_srv = 5,
	mosq_cs_disconnect_ws = 6,
	mosq_cs_disconnected = 7,
	mosq_cs_socks5_new = 8,
	mosq_cs_socks5_start = 9,
	mosq_cs_socks5_request = 10,
	mosq_cs_socks5_reply = 11,
	mosq_cs_socks5_auth_ok = 12,
	mosq_cs_socks5_userpass_reply = 13,
	mosq_cs_socks5_send_userpass = 14,
	mosq_cs_expiring = 15,
	mosq_cs_duplicate = 17, /* client that has been taken over by another with the same id */
	mosq_cs_disconnect_with_will = 18,
	mosq_cs_disused = 19, /* client that has been added to the disused list to be freed */
	mosq_cs_authenticating = 20, /* Client has sent CONNECT but is still undergoing extended authentication */
	mosq_cs_reauthenticating = 21, /* Client is undergoing reauthentication and shouldn't do anything else until complete */
};

#define MQTT_CONFIG_HOST_LEN        (32)
#define MQTT_CONFIG_USERNAME_LEN    (128)
#define MQTT_CONFIG_PASSWORD_LEN    (128)
#define MQTT_CONFIG_CLIENT_ID_LEN    (64)

typedef struct _MQTT_CONFIG{
    char host[MQTT_CONFIG_HOST_LEN];    /* 连接地址 */
    int  port;                           /* 端口 */
    char username[MQTT_CONFIG_USERNAME_LEN];    /* 用户名 */
    char password[MQTT_CONFIG_PASSWORD_LEN];    /* 密码 */
    char client_id[MQTT_CONFIG_CLIENT_ID_LEN];  /* client id*/
}MQTT_CONFIG;

typedef enum {
    MQTT_STATUS_NOT_CONFIG = 0,
    MQTT_STATUS_DISCONNECTED, 
    MQTT_STATUS_CONNECTED,     
}MQTT_STATUS;

int mqtt_set_config(char* host, int port, char* username, char* password, char* client_id);
int mqtt_get_config(MQTT_CONFIG* config);
int mqtt_proc();
int mqtt_subscribe(char* topic);
int mqtt_get_status(int* status);
int mqtt_publish(char* topic, char* payload, int qos);

#endif
