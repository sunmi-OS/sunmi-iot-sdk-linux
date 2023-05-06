#include <stdio.h>
#include <string.h>
#include <time.h>

#include <openssl/hmac.h>

#include "device.h"
#include "link/common.h"

static int access_type = 1;
static int secure_mode = 1;
static char* sign_method = "hmacSha256";

static DEVICE_CONFIG device_config;

/* 获取当前时间戳 */
int get_timestamp()
{
    return time(NULL);
}

int thing_service_get_mqtt_host(char* host)
{
    if (!host) 
    {
        return -1;
    }
    strncpy(host, device_config.host, THING_SERVICE_DEVICE_HOST_LEN);
    return 0;
}

int thing_service_get_mqtt_port(int* port)
{
    if (!port) 
    {
        return -1;
    }

    *port = device_config.port;
    return 0;
}

/* 计算username */
int thing_service_get_mqtt_username(char *device_id, int timestamp, char* username, int len)
{
    if (!device_id || !username) 
    {
        return -1;
    }

    snprintf(username, len, "smlink_%s_%d_%d_%s_%u", device_id, access_type, secure_mode, sign_method, timestamp);

    return 0;
}

static int hex2str(char *input, uint32_t input_len, char *output, int lowercase)
{
    char *upper = "0123456789ABCDEF";
    char *lower = "0123456789abcdef";
    char *encode = upper;
    int i = 0, j = 0;

    if (lowercase) {
        encode = lower;
    }

    for (i = 0; i < input_len; i++) {
        output[j++] = encode[(input[i] >> 4) & 0xf];
        output[j++] = encode[(input[i]) & 0xf];
    }

    return 0;
}

/* 计算password */
int thing_service_get_mqtt_password(char *device_id, char *device_secret, int timestamp, char* password, int len)
{
    const EVP_MD* engine = EVP_sha256();
    HMAC_CTX ctx;

    char content[128] = {};
    char output[128] = {};
    int output_len = 0;

    snprintf(content, 128, "%s%d%d%u", device_id, access_type, secure_mode, timestamp);

    HMAC_CTX_init(&ctx);
    HMAC_Init_ex(&ctx, (unsigned char*)device_secret, strlen(device_secret), engine, NULL);
    HMAC_Update(&ctx, (unsigned char*)content, strlen(content));
    HMAC_Final(&ctx, (unsigned char*)output, (unsigned int *)&output_len);

    hex2str(output, output_len, password, 1);

    return 0;
}

/* 计算client id */
int thing_service_get_mqtt_client_id(char *device_id, char* client_id, int len)
{
    if (!device_id || !client_id) 
    {
        return -1;
    }

    snprintf(client_id, len, "%s", device_id);
    return 0;
}

int thing_service_set_device_info(char* host, int port, char* device_id, char* device_secret)
{
    if (!host || !device_id || !device_secret) 
    {
        return -1;
    }

#if 0
    /* 判断设备信息是否发生变更 */
    if (!strncmp(device_config.host, host, THING_SERVICE_DEVICE_HOST_LEN) &&
        device_config.port == port &&
        !strncmp(device_config.device_id, device_id, THING_SERVICE_DEVICE_ID_LEN) &&
        !strncmp(device_config.device_secret, device_secret, THING_SERVICE_DEVICE_SECRET_LEN)) 
    {
        return 0;
    }
#endif
    
    strncpy(device_config.host, host, THING_SERVICE_DEVICE_HOST_LEN);
    device_config.port = port;
    strncpy(device_config.device_id, device_id, THING_SERVICE_DEVICE_ID_LEN);
    strncpy(device_config.device_secret, device_secret, THING_SERVICE_DEVICE_SECRET_LEN);

    /* 配置mqtt_client */
    thing_service_config_mqtt();

    return 0;
}

int thing_service_get_device_id(char* device_id)
{
    if (!device_id) 
    {
        return -1;
    }
    strncpy(device_id, device_config.device_id, THING_SERVICE_DEVICE_ID_LEN);
    return 0;
}

int thing_service_get_device_secret(char* device_secret)
{
    if (!device_secret) 
    {
        return -1;
    }
    strncpy(device_secret, device_config.device_secret, THING_SERVICE_DEVICE_SECRET_LEN);
    return 0;
}

/* 配置mqtt */
int thing_service_config_mqtt()
{
    int ret = 0;
    char username[128] = {};
    char password[128] = {};
    char client_id[128] = {};
    int timestamp = get_timestamp();

    struct blob_buf req = {};
    blob_buf_init(&req, 0);

    thing_service_get_mqtt_username(device_config.device_id, timestamp, username, 128);
    thing_service_get_mqtt_password(device_config.device_id, device_config.device_secret, timestamp, password, 128);
    thing_service_get_mqtt_client_id(device_config.device_id, client_id, 128);

    blobmsg_add_string(&req, "host", device_config.host);
    blobmsg_add_u32(&req, "port", device_config.port);

    blobmsg_add_string(&req, "username", username);
    blobmsg_add_string(&req, "password", password);
    blobmsg_add_string(&req, "client_id", client_id);

    if (ubus_call("mqtt_client", "set_config", &req, NULL, 3000) < 0) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR,"ubus_call mqtt_client set_config failed.");
        ret = -1;
        goto out;
    }

out:
	blob_buf_free(&req);
    return ret;
}

int _subscribe_one_topic(char* topic)
{
    int ret = 0;
    struct blob_buf req = {};

    blob_buf_init(&req, 0);
    blobmsg_add_string(&req, "topic", topic);

    if (ubus_call_async("mqtt_client", "subscribe", &req, NULL, NULL) < 0) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR,"ubus_call mqtt_client subscribe failed.");
        ret = -1;
        goto out;
    }

out:
	blob_buf_free(&req);
    return ret;
}

int thing_service_subscribe_mqtt_topics()
{
    char topic[128];
    snprintf(topic, 128, "smlink/%s/thing/command/execute",device_config.device_id);
    _subscribe_one_topic(topic);

    snprintf(topic, 128, "smlink/%s/thing/property/set",device_config.device_id);
    _subscribe_one_topic(topic);

    snprintf(topic, 128, "smlink/%s/thing/property/get",device_config.device_id);
    _subscribe_one_topic(topic);

    snprintf(topic, 128, "smlink/%s/sys/message/send", device_config.device_id);
    _subscribe_one_topic(topic);

    return 0;
}
