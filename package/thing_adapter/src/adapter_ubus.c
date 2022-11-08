#include "link/common.h"
#include "adapter_ubus.h"
#include "thing_adapter.h"

int thing_adapter_get_data(THING_ADAPTER* adapter);
int thing_adapter_call(char* topic, char* payload);

/* 获取注册的thing adapter信息 */
static int thing_adapter_get(struct ubus_context *ctx, struct ubus_object *obj,
    struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
    struct blob_buf bbuf = {};
    THING_ADAPTER adapter = {};

    if (thing_adapter_get_data(&adapter) < 0) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "thing_adapter_get_data failed.");
        return UBUS_STATUS_UNKNOWN_ERROR;
    }
    
    blob_buf_init(&bbuf, 0);

    blobmsg_add_string(&bbuf, "service_id", adapter.service_id);
    blobmsg_add_string(&bbuf, "service_type", adapter.service_type);
    blobmsg_add_u32(&bbuf, "execute_command", adapter.execute_command? 1:0 );
    blobmsg_add_u32(&bbuf, "get_property", adapter.get_property? 1:0);
    blobmsg_add_u32(&bbuf, "set_property", adapter.set_property? 1:0);

    ubus_send_reply(ctx, req, bbuf.head);
    blob_buf_free(&bbuf);

	return UBUS_STATUS_OK;
}

enum {
	HANDLE_MESSAGE_TOPIC = 0,
	HANDLE_MESSAGE_PAYLOAD,
	__HANDLE_MESSAGE_MAX,
};

static const struct blobmsg_policy _handle_message_policy[] = {
	[HANDLE_MESSAGE_TOPIC] = { .name = "topic", .type = BLOBMSG_TYPE_STRING },
	[HANDLE_MESSAGE_PAYLOAD] = { .name = "payload", .type = BLOBMSG_TYPE_STRING },
};

static int thing_adapter_handle_message(struct ubus_context *ctx, struct ubus_object *obj,
    struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
    char* topic = NULL;
    char* payload = NULL;

	struct blob_attr *tb[__HANDLE_MESSAGE_MAX];
    memset(tb, 0, sizeof(struct blob_attr *) * __HANDLE_MESSAGE_MAX);

    blobmsg_parse(_handle_message_policy, __HANDLE_MESSAGE_MAX, tb, blob_data(msg), blob_len(msg));
    if (!tb[HANDLE_MESSAGE_TOPIC]) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "message topic is invalid.");
        return UBUS_STATUS_INVALID_ARGUMENT;
    }
    topic = blobmsg_get_string(tb[HANDLE_MESSAGE_TOPIC]);

    if (!tb[HANDLE_MESSAGE_PAYLOAD]) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "message payload is invalid.");
        return UBUS_STATUS_INVALID_ARGUMENT;
    }
    payload = blobmsg_get_string(tb[HANDLE_MESSAGE_PAYLOAD]);

    SUNMI_LOG(PRINT_LEVEL_INFO, "topic=%s", topic);
    SUNMI_LOG(PRINT_LEVEL_INFO, "payload=%s", payload);

    thing_adapter_call(topic, payload);

	return UBUS_STATUS_OK;
}

static const struct ubus_method thing_adapter_methods[] = {
    UBUS_METHOD_NOARG("get", thing_adapter_get),
    UBUS_METHOD("handle_message", thing_adapter_handle_message, _handle_message_policy),
};

static struct ubus_object_type thing_adapter_object_type =
	UBUS_OBJECT_TYPE("thing_adapter", thing_adapter_methods);

static struct ubus_object thing_adapter_object = {
	.name = "thing_adapter",
	.type = &thing_adapter_object_type,
	.methods = thing_adapter_methods,
	.n_methods = ARRAY_SIZE(thing_adapter_methods),
};

/* thing adapter的ubus名称 */
static char ubus_name[256];

/* ubus初始化 */
int thing_adapter_ubus_init(char* service_id)
{
    snprintf(ubus_name, 256, "%s_%s", "thing_adapter", service_id);
    if(ubus_init(ubus_name) < 0)
    {
        return -1;
    }
    thing_adapter_object.name = ubus_name;
    ubus_add_module_object(&thing_adapter_object);
    return 0;
}

/* ubus清理 */
int thing_adapter_ubus_cleanup()
{
    ubus_remove_module_object(&thing_adapter_object);
    ubus_cleanup();
    return 0;
}
