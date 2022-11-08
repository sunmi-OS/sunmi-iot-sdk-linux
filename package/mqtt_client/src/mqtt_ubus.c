
#include "link/common.h"
#include "mqtt.h"
#include "mqtt_ubus.h"

/* 获取连接状态 */
static int mqtt_client_status(struct ubus_context *ctx, struct ubus_object *obj,
    struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
	struct blob_buf bbuf = {};

    int status = -1;
    mqtt_get_status(&status);

	blob_buf_init(&bbuf, 0);

    if (MQTT_STATUS_NOT_CONFIG == status) 
    {
        blobmsg_add_string(&bbuf, "status", "not_config");
    }
    else if(MQTT_STATUS_DISCONNECTED == status)
    {
        blobmsg_add_string(&bbuf, "status", "disconnected");
    }
    else if(MQTT_STATUS_CONNECTED == status)
    {
        blobmsg_add_string(&bbuf, "status", "connected");
    }
    else
    {
        blobmsg_add_string(&bbuf, "status", "unknown");
    }

	ubus_send_reply(ctx, req, bbuf.head);
	blob_buf_free(&bbuf);

	return UBUS_STATUS_OK;
}

/* 获取配置 */
static int mqtt_client_get_config(struct ubus_context *ctx, struct ubus_object *obj,
    struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
	struct blob_buf bbuf = {};

    MQTT_CONFIG config = {};
    mqtt_get_config(&config);
    
	blob_buf_init(&bbuf, 0);
    blobmsg_add_string(&bbuf, "host", config.host);
    blobmsg_add_u32(&bbuf, "port", config.port);
    blobmsg_add_string(&bbuf, "username", config.username);
    blobmsg_add_string(&bbuf, "password", config.password);
    blobmsg_add_string(&bbuf, "client_id", config.client_id);

	ubus_send_reply(ctx, req, bbuf.head);
	blob_buf_free(&bbuf);

	return UBUS_STATUS_OK;
}

enum {
	SET_CONFIG_HOST,
	SET_CONFIG_PORT,
	SET_CONFIG_USERNAME,
	SET_CONFIG_PASSWORD,
	SET_CONFIG_CLIENT_ID,
	__SET_CONFIG_MAX,
};

static const struct blobmsg_policy _set_config_policy[] = {
	[SET_CONFIG_HOST] = { .name = "host", .type = BLOBMSG_TYPE_STRING },
	[SET_CONFIG_PORT] = { .name = "port", .type = BLOBMSG_TYPE_INT32 },
	[SET_CONFIG_USERNAME] = { .name = "username", .type = BLOBMSG_TYPE_STRING },
	[SET_CONFIG_PASSWORD] = { .name = "password", .type = BLOBMSG_TYPE_STRING },
	[SET_CONFIG_CLIENT_ID] = { .name = "client_id", .type = BLOBMSG_TYPE_STRING },
};

/* 设置配置 */
static int mqtt_client_set_config(struct ubus_context *ctx, struct ubus_object *obj,
    struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
    char* host = NULL;
    int port = 0;
    char* username = NULL;
    char* password = NULL;
    char* client_id = NULL;

	struct blob_attr *tb[__SET_CONFIG_MAX];
    memset(tb, 0, sizeof(struct blob_attr *) * __SET_CONFIG_MAX);

    blobmsg_parse(_set_config_policy, __SET_CONFIG_MAX, tb, blob_data(msg), blob_len(msg));
    if (!tb[SET_CONFIG_HOST])
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "mqtt host is invalid.");
        return UBUS_STATUS_INVALID_ARGUMENT;
    }
    host = blobmsg_get_string(tb[SET_CONFIG_HOST]);

    if (!tb[SET_CONFIG_PORT])
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "mqtt port is invalid.");
        return UBUS_STATUS_INVALID_ARGUMENT;
    }
    port = blobmsg_get_u32(tb[SET_CONFIG_PORT]);

    if (!tb[SET_CONFIG_USERNAME])
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "mqtt username is invalid.");
        return UBUS_STATUS_INVALID_ARGUMENT;
    }
    username = blobmsg_get_string(tb[SET_CONFIG_USERNAME]);

    if (!tb[SET_CONFIG_PASSWORD])
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "mqtt password is invalid.");
        return UBUS_STATUS_INVALID_ARGUMENT;
    }
    password = blobmsg_get_string(tb[SET_CONFIG_PASSWORD]);

    if (!tb[SET_CONFIG_CLIENT_ID])
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "mqtt client id is invalid.");
        return UBUS_STATUS_INVALID_ARGUMENT;
    }
    client_id = blobmsg_get_string(tb[SET_CONFIG_CLIENT_ID]);

    if(mqtt_set_config(host, port, username, password, client_id) < 0)
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "mqtt_set_config failed.");
        return UBUS_STATUS_INVALID_ARGUMENT;
    }

	return UBUS_STATUS_OK;
}

enum {
	SUBSCRIBE_TOPIC = 0,
	__SUBSCRIBE_MAX,
};

static const struct blobmsg_policy _subscribe_policy[] = {
	[SUBSCRIBE_TOPIC] = { .name = "topic", .type = BLOBMSG_TYPE_STRING },
};

static int mqtt_client_subscribe(struct ubus_context *ctx, struct ubus_object *obj,
    struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
    char* topic = NULL;
	struct blob_attr *tb[__SUBSCRIBE_MAX];
    memset(tb, 0, sizeof(struct blob_attr *) * __SUBSCRIBE_MAX);

    blobmsg_parse(_subscribe_policy, __SUBSCRIBE_MAX, tb, blob_data(msg), blob_len(msg));

    if (!tb[SUBSCRIBE_TOPIC])
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "topic is invalid.");
        return UBUS_STATUS_INVALID_ARGUMENT;
    }
    topic = blobmsg_get_string(tb[SUBSCRIBE_TOPIC]);

    if (mqtt_subscribe(topic) < 0) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "mqtt_subscribe failed.");
        return UBUS_STATUS_UNKNOWN_ERROR;
    }
    
    return UBUS_STATUS_OK;
}

enum {
	PUBLISH_TOPIC = 0,
    PUBLISH_PAYLOAD,
    PUBLISH_QOS,
	__PUBLISH_MAX,
};

static const struct blobmsg_policy _publish_policy[] = {
	[PUBLISH_TOPIC] = { .name = "topic", .type = BLOBMSG_TYPE_STRING },
	[PUBLISH_PAYLOAD] = { .name = "payload", .type = BLOBMSG_TYPE_STRING },
	[PUBLISH_QOS] = { .name = "qos", .type = BLOBMSG_TYPE_INT32 },
};

static int mqtt_client_publish(struct ubus_context *ctx, struct ubus_object *obj,
    struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
    char* topic = NULL;
    char* payload = NULL;
    int qos = 0;

	struct blob_attr *tb[__PUBLISH_MAX];
    memset(tb, 0, sizeof(struct blob_attr *) * __PUBLISH_MAX);

    blobmsg_parse(_publish_policy, __PUBLISH_MAX, tb, blob_data(msg), blob_len(msg));

    if (!tb[PUBLISH_TOPIC])
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "publish topic is invalid.");
        return UBUS_STATUS_INVALID_ARGUMENT;
    }
    topic = blobmsg_get_string(tb[PUBLISH_TOPIC]);

    if (!tb[PUBLISH_PAYLOAD])
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "publish payload is invalid.");
        return UBUS_STATUS_INVALID_ARGUMENT;
    }
    payload = blobmsg_get_string(tb[PUBLISH_PAYLOAD]);    

    if (!tb[PUBLISH_QOS]) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "publish qos is invalid.");
        return UBUS_STATUS_INVALID_ARGUMENT;
    }
    qos = blobmsg_get_u32(tb[PUBLISH_QOS]);   

    if (mqtt_publish(topic, payload, qos) < 0) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "mqtt_subscribe failed.");
        return UBUS_STATUS_UNKNOWN_ERROR;
    }

    return UBUS_STATUS_OK;
}

static const struct ubus_method mqtt_client_methods[] = {
    UBUS_METHOD_NOARG("status", mqtt_client_status),
    UBUS_METHOD_NOARG("get_config", mqtt_client_get_config),
    UBUS_METHOD("set_config", mqtt_client_set_config, _set_config_policy),
    UBUS_METHOD("subscribe", mqtt_client_subscribe, _subscribe_policy),
    UBUS_METHOD("publish", mqtt_client_publish, _publish_policy),
};

static struct ubus_object_type mqtt_client_object_type =
	UBUS_OBJECT_TYPE("mqtt_client", mqtt_client_methods);

static struct ubus_object mqtt_client_object = {
	.name = "mqtt_client",
	.type = &mqtt_client_object_type,
	.methods = mqtt_client_methods,
	.n_methods = ARRAY_SIZE(mqtt_client_methods),
};

/* ubus初始化 */
int mqtt_ubus_init()
{
    if(ubus_init("mqtt_client") < 0)
    {
        return -1;
    }
    ubus_add_module_object(&mqtt_client_object);
    return 0;
}

/* ubus清理 */
int mqtt_ubus_cleanup()
{
    ubus_remove_module_object(&mqtt_client_object);
    ubus_cleanup();
    return 0;
}
