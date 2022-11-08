#include "link/common.h"
#include "service_ubus.h"
#include "device.h"
#include "service.h"

/* 读取device信息 */
static int thing_service_get_device(struct ubus_context *ctx, struct ubus_object *obj,
    struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
    char host[THING_SERVICE_DEVICE_HOST_LEN];
    int port = 0;
    char device_id[THING_SERVICE_DEVICE_ID_LEN];
    char device_secret[THING_SERVICE_DEVICE_SECRET_LEN];

	struct blob_buf bbuf = {};

    thing_service_get_mqtt_host(host);
    thing_service_get_mqtt_port(&port);
    thing_service_get_device_id(device_id);
    thing_service_get_device_secret(device_secret);

    blob_buf_init(&bbuf, 0);
    blobmsg_add_string(&bbuf, "host", host);
    blobmsg_add_u32(&bbuf, "port", port);
    blobmsg_add_string(&bbuf, "device_id", device_id);
    blobmsg_add_string(&bbuf, "device_secret", device_secret);

	ubus_send_reply(ctx, req, bbuf.head);
	blob_buf_free(&bbuf);

	return UBUS_STATUS_OK;
}

enum {
	SET_DEVICE_HOST = 0,
	SET_DEVICE_PORT,
	SET_DEVICE_ID,
	SET_DEVICE_SECRET,
	__SET_DEVICE_MAX,
};

static const struct blobmsg_policy _set_device_policy[] = {
	[SET_DEVICE_HOST] = { .name = "host", .type = BLOBMSG_TYPE_STRING },
	[SET_DEVICE_PORT] = { .name = "port", .type = BLOBMSG_TYPE_INT32 },
	[SET_DEVICE_ID] = { .name = "device_id", .type = BLOBMSG_TYPE_STRING },
	[SET_DEVICE_SECRET] = { .name = "device_secret", .type = BLOBMSG_TYPE_STRING },
};

/* 设置device信息 */
static int thing_service_set_device(struct ubus_context *ctx, struct ubus_object *obj,
    struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
    char* host = NULL;
    int port = 0;
    char* device_id = NULL;
    char* device_secret = NULL;

	struct blob_attr *tb[__SET_DEVICE_MAX];
    memset(tb, 0, sizeof(struct blob_attr *) * __SET_DEVICE_MAX);

    blobmsg_parse(_set_device_policy, __SET_DEVICE_MAX, tb, blob_data(msg), blob_len(msg));
    if (!tb[SET_DEVICE_HOST]) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "thing service host is invalid.");
        return UBUS_STATUS_INVALID_ARGUMENT;
    }
    host = blobmsg_get_string(tb[SET_DEVICE_HOST]);

    if (!tb[SET_DEVICE_PORT]) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "thing service host is invalid.");
        return UBUS_STATUS_INVALID_ARGUMENT;
    }
    port = blobmsg_get_u32(tb[SET_DEVICE_PORT]);

    if (!tb[SET_DEVICE_ID]) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "thing service device_id is invalid.");
        return UBUS_STATUS_INVALID_ARGUMENT;
    }
    device_id = blobmsg_get_string(tb[SET_DEVICE_ID]);
    
    if (!tb[SET_DEVICE_SECRET]) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "thing service device_secret is invalid.");
        return UBUS_STATUS_INVALID_ARGUMENT;
    }
    device_secret = blobmsg_get_string(tb[SET_DEVICE_SECRET]);

    if (thing_service_set_device_info(host, port, device_id, device_secret) < 0) 
    {
        return UBUS_STATUS_UNKNOWN_ERROR;
    }
    
	return UBUS_STATUS_OK;
}

static int thing_service_get_service(struct ubus_context *ctx, struct ubus_object *obj,
    struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
    struct blob_buf bbuf = {};
    blob_buf_init(&bbuf, 0);
    
    if (service_get_list(&bbuf) < 0) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "service_get_list failed.");
        return UBUS_STATUS_UNKNOWN_ERROR;
    }
    
    ubus_send_reply(ctx, req, bbuf.head);
    blob_buf_free(&bbuf);

	return UBUS_STATUS_OK;
}

enum {
	ADD_SERVICE_ID = 0,
	ADD_SERVICE_TYPE,
	__ADD_SERVICE_MAX,
};

static const struct blobmsg_policy _add_service_policy[] = {
	[ADD_SERVICE_ID] = { .name = "service_id", .type = BLOBMSG_TYPE_STRING },
	[ADD_SERVICE_TYPE] = { .name = "service_type", .type = BLOBMSG_TYPE_STRING },
};

static int thing_service_add_service(struct ubus_context *ctx, struct ubus_object *obj,
    struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
    char* service_id = NULL;
    char* service_type = NULL;

	struct blob_attr *tb[__ADD_SERVICE_MAX];
    memset(tb, 0, sizeof(struct blob_attr *) * __ADD_SERVICE_MAX);

    blobmsg_parse(_add_service_policy, __ADD_SERVICE_MAX, tb, blob_data(msg), blob_len(msg));
    if (!tb[ADD_SERVICE_ID]) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "thing service id is invalid.");
        return UBUS_STATUS_INVALID_ARGUMENT;
    }
    service_id = blobmsg_get_string(tb[ADD_SERVICE_ID]);

    if (!tb[ADD_SERVICE_TYPE]) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "thing service type is invalid.");
        return UBUS_STATUS_INVALID_ARGUMENT;
    }
    service_type = blobmsg_get_string(tb[ADD_SERVICE_TYPE]);
    if (service_register(service_id, service_type)) 
    {
        return UBUS_STATUS_UNKNOWN_ERROR;
    }
    return UBUS_STATUS_OK;
}

/* mqtt通知当前已连接 */
static int thing_service_notice_mqtt_on_connect(struct ubus_context *ctx, struct ubus_object *obj,
    struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
    SUNMI_LOG(PRINT_LEVEL_INFO, "mqtt on connect");
    thing_service_subscribe_mqtt_topics();

	return UBUS_STATUS_OK;
}

enum {
	ON_MESSAGE_TOPIC = 0,
	ON_MESSAGE_PAYLOAD,
	__ON_MESSAGE_MAX,
};

static const struct blobmsg_policy _on_message_policy[] = {
	[ON_MESSAGE_TOPIC] = { .name = "topic", .type = BLOBMSG_TYPE_STRING },
	[ON_MESSAGE_PAYLOAD] = { .name = "payload", .type = BLOBMSG_TYPE_STRING },
};

/* mqtt收到消息报文 */
static int thing_service_notice_mqtt_on_message(struct ubus_context *ctx, struct ubus_object *obj,
    struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
    SUNMI_LOG(PRINT_LEVEL_INFO, "mqtt on message");

    char* topic = NULL;
    char* payload = NULL;

	struct blob_attr *tb[__ON_MESSAGE_MAX];
    memset(tb, 0, sizeof(struct blob_attr *) * __ON_MESSAGE_MAX);

    blobmsg_parse(_on_message_policy, __ON_MESSAGE_MAX, tb, blob_data(msg), blob_len(msg));
    if (!tb[ON_MESSAGE_TOPIC]) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "message topic is invalid.");
        return UBUS_STATUS_INVALID_ARGUMENT;
    }
    topic = blobmsg_get_string(tb[ON_MESSAGE_TOPIC]);

    if (!tb[ON_MESSAGE_PAYLOAD]) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "message payload is invalid.");
        return UBUS_STATUS_INVALID_ARGUMENT;
    }
    payload = blobmsg_get_string(tb[ON_MESSAGE_PAYLOAD]);

    SUNMI_LOG(PRINT_LEVEL_INFO, "recv topic=%s", topic);
    SUNMI_LOG(PRINT_LEVEL_INFO, "recv payload=%s", payload);

    if(service_call(topic, payload) < 0)
    {
        return UBUS_STATUS_UNKNOWN_ERROR;
    }

	return UBUS_STATUS_OK;
}

enum {
	SEND_MESSAGE_TOPIC = 0,
	SEND_MESSAGE_PAYLOAD,
	__SEND_MESSAGE_MAX,
};

static const struct blobmsg_policy _send_message_policy[] = {
	[SEND_MESSAGE_TOPIC] = { .name = "topic", .type = BLOBMSG_TYPE_STRING },
	[SEND_MESSAGE_PAYLOAD] = { .name = "payload", .type = BLOBMSG_TYPE_STRING },
};

static int thing_service_send_message(struct ubus_context *ctx, struct ubus_object *obj,
    struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
    SUNMI_LOG(PRINT_LEVEL_INFO, "service send message");

    char* topic = NULL;
    char* payload = NULL;

	struct blob_attr *tb[__SEND_MESSAGE_MAX];
    memset(tb, 0, sizeof(struct blob_attr *) * __SEND_MESSAGE_MAX);

    blobmsg_parse(_send_message_policy, __SEND_MESSAGE_MAX, tb, blob_data(msg), blob_len(msg));
    if (!tb[SEND_MESSAGE_TOPIC]) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "message topic is invalid.");
        return UBUS_STATUS_INVALID_ARGUMENT;
    }
    topic = blobmsg_get_string(tb[SEND_MESSAGE_TOPIC]);

    if (!tb[ON_MESSAGE_PAYLOAD]) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "message payload is invalid.");
        return UBUS_STATUS_INVALID_ARGUMENT;
    }
    payload = blobmsg_get_string(tb[SEND_MESSAGE_PAYLOAD]);

    SUNMI_LOG(PRINT_LEVEL_INFO, "send topic=%s", topic);
    SUNMI_LOG(PRINT_LEVEL_INFO, "send payload=%s", payload);

    if(service_send_mqtt(topic, payload) < 0)
    {
        return UBUS_STATUS_UNKNOWN_ERROR;
    }

	return UBUS_STATUS_OK;
}

static const struct ubus_method thing_service_methods[] = {
    UBUS_METHOD_NOARG("get_device", thing_service_get_device),
    UBUS_METHOD("set_device", thing_service_set_device, _set_device_policy),
    UBUS_METHOD_NOARG("get_service", thing_service_get_service),
    UBUS_METHOD("add_service", thing_service_add_service, _add_service_policy),
    UBUS_METHOD_NOARG("on_connect", thing_service_notice_mqtt_on_connect),
    UBUS_METHOD("on_message", thing_service_notice_mqtt_on_message, _on_message_policy),
    UBUS_METHOD("send_message", thing_service_send_message, _send_message_policy),
};

static struct ubus_object_type thing_service_object_type =
	UBUS_OBJECT_TYPE("thing_service", thing_service_methods);

static struct ubus_object thing_service_object = {
	.name = "thing_service",
	.type = &thing_service_object_type,
	.methods = thing_service_methods,
	.n_methods = ARRAY_SIZE(thing_service_methods),
};

/* ubus初始化 */
int thing_service_ubus_init()
{
    if(ubus_init("thing_service") < 0)
    {
        return -1;
    }
    ubus_add_module_object(&thing_service_object);
    return 0;
}

/* ubus清理 */
int thing_service_ubus_cleanup()
{
    ubus_remove_module_object(&thing_service_object);
    ubus_cleanup();
    return 0;
}
