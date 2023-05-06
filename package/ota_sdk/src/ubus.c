#include <libubox/blobmsg.h>
#include <libubus.h>
#include <link/ubus.h>

#include "internal.h"

enum {
	HANDLE_MESSAGE_TOPIC = 0,
	HANDLE_MESSAGE_PAYLOAD,
	__HANDLE_MESSAGE_MAX,
};

static struct mqtt_info ubus_mqtt;

static const struct blobmsg_policy _handle_message_policy[] = {
	[HANDLE_MESSAGE_TOPIC] = { .name = "topic", .type = BLOBMSG_TYPE_STRING },
	[HANDLE_MESSAGE_PAYLOAD] = { .name = "payload", .type = BLOBMSG_TYPE_STRING },
};

int ota_ubus_send_message(char *topic, char *payload)
{
	int ret = 0;
	struct blob_buf req = { };

	if (!topic || !payload) {
		return -1;
	}

	blob_buf_init(&req, 0);
	blobmsg_add_string(&req, "topic", topic);
	blobmsg_add_string(&req, "payload", payload);

	if (ubus_call_async("thing_service", "send_message", &req, NULL, NULL) < 0) {
		LogError("ubus_call mqtt_client publish failed.");
		ret = -1;
		goto out;
	}

out:
	blob_buf_free(&req);
	return ret;
}

static int handle_message(struct ubus_context *ctx, struct ubus_object *obj,
						  struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
	char *topic = NULL;
	char *payload = NULL;

	struct blob_attr *tb[__HANDLE_MESSAGE_MAX];
	memset(tb, 0, sizeof(struct blob_attr *) * __HANDLE_MESSAGE_MAX);

	blobmsg_parse(_handle_message_policy, __HANDLE_MESSAGE_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[HANDLE_MESSAGE_TOPIC]) {
		LogError("message topic is invalid.");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}
	topic = blobmsg_get_string(tb[HANDLE_MESSAGE_TOPIC]);

	if (!tb[HANDLE_MESSAGE_PAYLOAD]) {
		LogError("message payload is invalid.");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}
	payload = blobmsg_get_string(tb[HANDLE_MESSAGE_PAYLOAD]);

	LogInfo("topic=%s", topic);
	LogInfo("payload=%s", payload);

	// 云端推送：包括：1、MGT平台推送；2、商米助手推送
	mqtt_handle_message(topic, payload);

	return UBUS_STATUS_OK;
}

enum {
	START_UPGRADE_TYPE = 0,
	__START_UPGRADE_MAX,
};

static const struct blobmsg_policy _start_upgrade_policy[] = {
	[START_UPGRADE_TYPE] = { .name = "type", .type = BLOBMSG_TYPE_INT32 },
};

static int start_upgrade(struct ubus_context *ctx, struct ubus_object *obj,
						 struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
	char type;
	int policy;
	struct blob_attr *tb[__START_UPGRADE_MAX];

	memset(tb, 0, sizeof(struct blob_attr *) * __START_UPGRADE_MAX);

	blobmsg_parse(_start_upgrade_policy, __START_UPGRADE_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[START_UPGRADE_TYPE]) {
		LogError("type is invalid.");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}
	type = blobmsg_get_u32(tb[START_UPGRADE_TYPE]);

	if (type < UP_FILE_TYPE_FIRMWARE || type > UP_FILE_TYPE_RESOURCE) {
		LogError("type is invalid.");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	LogInfo("type=%d", type);

	//设备端确认升级，例如web页面点击升级
	policy = REQ_POLICY_ARGS_ENCODE(type, 1, 1, 0, 0);
	LogInfo("policy=%x", policy);
	download_process_external_business( (void *)policy);

	return UBUS_STATUS_OK;
}

enum {
	START_INSTALL_TYPE = 0,
	__START_INSTALL_MAX,
};

static const struct blobmsg_policy _start_install_policy[] = {
	[START_INSTALL_TYPE] = { .name = "type", .type = BLOBMSG_TYPE_INT32 },
};

static int start_install(struct ubus_context *ctx, struct ubus_object *obj,
						 struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
	char type;
	struct blob_attr *tb[__START_INSTALL_MAX];

	memset(tb, 0, sizeof(struct blob_attr *) * __START_INSTALL_MAX);

	blobmsg_parse(_start_install_policy, __START_INSTALL_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[START_INSTALL_TYPE]) {
		LogError("type is invalid.");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}
	type = blobmsg_get_u32(tb[START_INSTALL_TYPE]);

	if (type < UP_FILE_TYPE_FIRMWARE || type > UP_FILE_TYPE_RESOURCE) {
		LogError("type is invalid.");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	LogInfo("type=%d", type);

	if (ota_start_install(type)) {
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	return UBUS_STATUS_OK;
}

static int get_upgrade_state(struct ubus_context *ctx, struct ubus_object *obj,
							 struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
	struct blob_buf bbuf = { };
	char state;
	char mode;

	state = download_get_upgrade_state(&mode);

	blob_buf_init(&bbuf, 0);

	blobmsg_add_u32(&bbuf, "state", state);
	blobmsg_add_u32(&bbuf, "mode", mode);

	ubus_send_reply(ctx, req, bbuf.head);
	blob_buf_free(&bbuf);

	return UBUS_STATUS_OK;
}

static int handle_connect(struct ubus_context *ctx, struct ubus_object *obj,
						  struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
	if (mqtt_handle_connect() < 0) {
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	return UBUS_STATUS_OK;
}

static int handle_disconnect(struct ubus_context *ctx, struct ubus_object *obj,
							 struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
	if (mqtt_handle_disconnect() < 0) {
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	return UBUS_STATUS_OK;
}

enum {
	CHECK_VERSION_TYPE = 0,
	__CHECK_VERSION_MAX,
};

static const struct blobmsg_policy _check_version_policy[] = {
	[CHECK_VERSION_TYPE] = { .name = "type", .type = BLOBMSG_TYPE_INT32 },
};

static int check_version(struct ubus_context *ctx, struct ubus_object *obj,
						 struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
	char type;
	struct blob_buf bbuf = { };
	char new_ver[VER_LEN] = { };
	char log[LOG_LEN] = { };

	struct blob_attr *tb[__CHECK_VERSION_MAX];
	memset(tb, 0, sizeof(struct blob_attr *) * __CHECK_VERSION_MAX);

	blobmsg_parse(_check_version_policy, __CHECK_VERSION_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[CHECK_VERSION_TYPE]) {
		LogError("type is invalid.");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	type = blobmsg_get_u32(tb[CHECK_VERSION_TYPE]);
	if (type < UP_FILE_TYPE_FIRMWARE || type > UP_FILE_TYPE_RESOURCE) {
		LogError("type is invalid.");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	LogInfo("type=%d", type);

	if (ota_check_version(type, new_ver, VER_LEN, log, LOG_LEN)) {
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	blob_buf_init(&bbuf, 0);

	blobmsg_add_string(&bbuf, "version", new_ver);
	blobmsg_add_string(&bbuf, "release_log", log);

	ubus_send_reply(ctx, req, bbuf.head);
	blob_buf_free(&bbuf);

	return UBUS_STATUS_OK;
}

enum {
	SET_UPGRADE_STATE = 0,
	SET_UPGRADE_MODE,
	__SET_UPGRADE_STATE_MAX,
};

static const struct blobmsg_policy _set_upgrade_state_policy[] = {
	[SET_UPGRADE_STATE] = { .name = "state", .type = BLOBMSG_TYPE_INT32 },
	[SET_UPGRADE_MODE] = { .name = "mode", .type = BLOBMSG_TYPE_INT32 },
};

static int set_upgrade_state(struct ubus_context *ctx, struct ubus_object *obj,
							 struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
	char state = 0;
	char mode = 0;

	struct blob_attr *tb[__SET_UPGRADE_STATE_MAX];
	memset(tb, 0, sizeof(struct blob_attr *) * __SET_UPGRADE_STATE_MAX);

	blobmsg_parse(_set_upgrade_state_policy, __SET_UPGRADE_STATE_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[SET_UPGRADE_STATE]) {
		LogError("state is invalid.");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	state = blobmsg_get_u32(tb[SET_UPGRADE_STATE]);
	if (state < OTA_STATE_IDLE || state > OTA_STATE_INSTALL_FAIL) {
		LogError("state is invalid.");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	if (!tb[SET_UPGRADE_MODE]) {
		LogError("mode is invalid.");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	mode = blobmsg_get_u32(tb[SET_UPGRADE_MODE]);
	if (mode < UP_METHOD_NONE || mode > UP_METHOD_LOCAL) {
		LogError("mode:%d is invalid.", mode);
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	LogInfo("state=%d, mode=%d", state, mode);
	if (download_set_upgrade_state(state, mode)) {
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	return UBUS_STATUS_OK;
}

static const struct ubus_method ota_methods[] = {
	UBUS_METHOD_NOARG("handle_connect", handle_connect),
	UBUS_METHOD_NOARG("handle_disconnect", handle_disconnect),
	UBUS_METHOD("handle_message", handle_message, _handle_message_policy),
	UBUS_METHOD("start_download", start_upgrade, _start_upgrade_policy),
	UBUS_METHOD("start_install", start_install, _start_install_policy),
	UBUS_METHOD("check_version", check_version, _check_version_policy),
	UBUS_METHOD_NOARG("get_upgrade_state", get_upgrade_state),
	UBUS_METHOD("set_upgrade_state", set_upgrade_state, _set_upgrade_state_policy),
};

static struct ubus_object_type ota_object_type = UBUS_OBJECT_TYPE("ota", ota_methods);

static struct ubus_object ota_object = {
	.name = "ota",
	.type = &ota_object_type,
	.methods = ota_methods,
	.n_methods = ARRAY_SIZE(ota_methods),
};

/* 发送设备信息给thing_service */
static void ota_send_mqtt_info(struct uloop_timeout *timeout)
{
	struct blob_buf req = { };

	blob_buf_init(&req, 0);
	blobmsg_add_string(&req, "host", ubus_mqtt.host);
	blobmsg_add_u32(&req, "port", ubus_mqtt.port);
	blobmsg_add_string(&req, "device_id", ubus_mqtt.device_id);
	blobmsg_add_string(&req, "device_secret", ubus_mqtt.device_secret);

	LogInfo("host: %s", ubus_mqtt.host);
	LogInfo("port: %d", ubus_mqtt.port);
	LogInfo("device_id: %s", ubus_mqtt.device_id);
	LogInfo("device_secret: %s", ubus_mqtt.device_secret);

	if (ubus_call_async("thing_service", "set_device", &req, NULL, NULL) < 0) {
		LogError("ubus_call thing_service set_device failed.");
	}

	blob_buf_free(&req);
}

static void _init_timer(void)
{
	static struct uloop_timeout timeout = {
		.cb = ota_send_mqtt_info,
	};

	uloop_timeout_set(&timeout, 3 * 1000);
}

static void ota_install(struct uloop_timeout *timeout)
{
	download_install_task(-1);
}

void ota_ubus_set_install_timer(int seconds)
{
	static struct uloop_timeout timeout = {
		.cb = ota_install,
	};

	uloop_timeout_set(&timeout, seconds * 1000);
}

static void ota_reset_state(struct uloop_timeout *timeout)
{
	download_set_upgrade_state(0, 0);
}

void ota_ubus_reset_state_machine_timer(int seconds)
{
	static struct uloop_timeout timeout = {
		.cb = ota_reset_state,
	};

	uloop_timeout_set(&timeout, seconds * 1000);
}


/* ubus初始化 */
void* ota_ubus_init(void *arg)
{
	struct mqtt_info *info = (struct mqtt_info *)arg;

	/* uloop初始化 */
	uloop_init();

	if (ubus_init("ota") < 0) {
		return NULL;
	}

	ubus_add_module_object(&ota_object);

	memcpy(&ubus_mqtt, info, sizeof(ubus_mqtt));

	_init_timer();

	uloop_run();
	uloop_done();
	ubus_cleanup();

	return NULL;
}

/* ubus清理 */
int ota_ubus_cleanup()
{
	ubus_remove_module_object(&ota_object);
	ubus_cleanup();
	return 0;
}
