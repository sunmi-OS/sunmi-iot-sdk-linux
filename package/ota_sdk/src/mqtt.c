#include "internal.h"
#include <cjson/cJSON.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

#define SYS_MESSAGE_TOPIC "/sys/message/"

static struct {
	char sn[SN_LEN];
	char model[MODEL_LEN];
	char device_id[128];
	char type_flag;
} dev_root_info;

int mqtt_handle_connect(void)
{
	int i;
	int policy;

	//服务器端后，MQTT连接成功时，主动拉取更新
	LogInfo("upgrade type:%x", dev_root_info.type_flag);
	for (i = 0; i < UP_FILE_TYPE_MAX; i++) {
		if (dev_root_info.type_flag & (1<<i)) {
			LogInfo("upgrade type:%d", i);
			policy = REQ_POLICY_ARGS_ENCODE(i, 1, 0, 0, 1);
			download_process_external_business( (void *)policy);

		}
	}

	return 0;
}

int mqtt_handle_disconnect(void)
{
	LogError("MQTT disconnect");
	return 0;
}

/* 发送事件上报数据 */
static int _mqtt_report_event(cJSON *event_data)
{
	int ret = 0;
	char event_topic[128];
	char id_buf[10] = { };

	cJSON *event_msg = NULL;
	cJSON *data = NULL;
	cJSON *sys = NULL;
	char *event_payload = NULL;

	if (!event_data) {
		LogError("event_data is invalid.");
		ret = -1;
		goto out;
	}

	/* 填充event消息 */
	event_msg = cJSON_CreateObject();
	if (!event_msg) {
		LogError("cJSON_CreateObject report failed");
		ret = -1;
		goto out;
	}

	sys = cJSON_CreateObject();
	if (!sys) {
		LogError("cJSON_CreateObject report failed");
		ret = -1;
		goto out;
	}

	data = cJSON_Duplicate(event_data, true);
	snprintf(id_buf, sizeof(id_buf), "id%d", (int)time(NULL) % 100000);
	cJSON_AddStringToObject(event_msg, "id", id_buf);
	cJSON_AddNumberToObject(event_msg, "ts", (long long)time(NULL) * 1000);
	cJSON_AddStringToObject(event_msg, "version", "1.0");
	cJSON_AddNumberToObject(sys, "reply", (double)0);
	cJSON_AddNumberToObject(sys, "batch", (double)0);
	cJSON_AddItemToObject(event_msg, "sys", sys);
	cJSON_AddItemToObject(event_msg, "data", data);

	/* 返回mqtt数据 */
	snprintf(event_topic, 128, "smlink/%s/sys/message/report", dev_root_info.device_id); /* 返回的topic */
	event_payload = cJSON_PrintUnformatted(event_msg);
	if (!event_payload) {
		LogError("cJSON_PrintUnformatted event_payload failed");
		ret = -1;
		goto out;
	}

	ota_ubus_send_message(event_topic, event_payload);

out:
	if (event_payload) {
		free(event_payload);
	}

	if (sys) {
		cJSON_Delete(sys);
	}

	return ret;
}

int mqtt_report_status(int status, const char *msg)
{
	cJSON *data = NULL;
	cJSON *params = NULL;
	int ret = 0;

	data = cJSON_CreateObject();
	if (!data) {
		LogError("cJSON_CreateObject data failed");
		ret = -1;
		goto out;
	}

	params = cJSON_CreateObject();
	if (!params) {
		LogError("cJSON_CreateObject data failed");
		ret = -1;
		goto out;
	}

	cJSON_AddStringToObject(params, "msn", dev_root_info.sn);
	cJSON_AddStringToObject(params, "model", dev_root_info.model);
	cJSON_AddNumberToObject(params, "status", (double)(status - 1));
	if (msg) {
		cJSON_AddStringToObject(params, "msg", msg);
	} else {
		cJSON_AddStringToObject(params, "msg", "");
	}

	cJSON_AddStringToObject(data, "action", "ota");
	cJSON_AddItemToObject(data, "params", params);

	_mqtt_report_event(data);

out:
	if (params) {
		cJSON_Delete(params);
	}

	return ret;
}

int mqtt_handle_message(char *topic, char *payload)
{
	int ret = 0;
	cJSON *request_msg = NULL;
	cJSON *response_msg = NULL;
	cJSON *request_data = NULL;  /* 请求参数 */
	cJSON *response_data = NULL; /* 返回结果 */

	cJSON *msg_id = NULL;    /* message id */
	cJSON *version = NULL;
	cJSON *action = NULL;   /* action */
	cJSON *params = NULL;
	cJSON *rsp_params = NULL;
	cJSON *sys = NULL;          /* sys参数 */
	cJSON *reply = NULL;        /* reply标志位 */
	cJSON *type = NULL;
	cJSON *update_flag = NULL;

	char response_topic[128];
	char *response_payload = NULL;

	if (!topic || !payload) {
		LogError("topic or payload is NULL.");
		ret = -1;
		goto out;
	}

	if (NULL == strstr(topic, SYS_MESSAGE_TOPIC)) {
		LogError("not ota topic type %s.", topic);
		ret = -1;
		goto out;
	}

	request_msg = cJSON_Parse(payload);
	if (!request_msg || request_msg->type != cJSON_Object) {
		LogError("cJSON_Parse message failed.");
		ret = -1;
		goto out;
	}

	msg_id = cJSON_GetObjectItem(request_msg, "id");
	if (!msg_id || !msg_id->valuestring) {
		LogError("id is NULL.");
		ret = -1;
		goto out;
	}

	version = cJSON_GetObjectItem(request_msg, "version");
	if (!version || !version->valuestring) {
		LogError("version is NULL.");
		ret = -1;
		goto out;
	}

	/* 获取sys参数 */
	sys = cJSON_GetObjectItem(request_msg, "sys");
	if (!sys || cJSON_Object != sys->type) {
		LogError("sys is invalid.");
		ret = -1;
		goto out;
	}

	/* 获取reply参数 */
	reply = cJSON_GetObjectItem(sys, "reply");
	if (!reply) {
		LogError("reply is invalid.");
		ret = -1;
		goto out;
	}

	/* 获取data字段 */
	request_data = cJSON_GetObjectItem(request_msg, "data");
	if (!request_data || cJSON_Object != request_data->type) {
		LogError("data is invalid.");
		ret = -1;
		goto out;
	}

	/* action */
	action = cJSON_GetObjectItem(request_data, "action");
	if (!action || cJSON_String != action->type) {
		LogError("action is invalid.");
		ret = -1;
		goto out;
	}

	if (strcmp(action->valuestring, "ota")) {
		LogError("action is not ota.");
		ret = -1;
		goto out;
	}

	/* params */
	params = cJSON_GetObjectItem(request_data, "params");
	if (!params || cJSON_Object != request_data->type) {
		LogError("params is NULL.");
		ret = -1;
		goto out;
	}

	update_flag = cJSON_GetObjectItem(params, "update_flag");
	if (!update_flag) {
		LogError("update_flag is invalid.");
		ret = -1;
		goto out;
	}

	type = cJSON_GetObjectItem(params, "type");
	if (!type || type->valueint < 1 || type->valueint > 3) {
		LogError("type is invalid.");
		ret = -1;
		goto out;
	}

	//reply置位，需要回复
	if (1 == reply->valueint) {
		/* 初始化response数据 */
		response_data = cJSON_CreateObject();
		cJSON_AddNumberToObject(response_data, "code", 1);
		cJSON_AddStringToObject(response_data, "action", "ota");
		rsp_params = cJSON_Duplicate(params, true);
		cJSON_AddItemToObject(response_data, "params", rsp_params);


		/* 构造返回数据 */
		response_msg = cJSON_CreateObject();
		if (!response_msg) {
			LogError("cJSON_CreateObject response_msg failed");
			ret = -1;
			goto out;
		}
		cJSON_AddStringToObject(response_msg, "id", msg_id->valuestring);
		cJSON_AddNumberToObject(response_msg, "ts", (long long)time(NULL) * 1000);
		cJSON_AddStringToObject(response_msg, "version", version->valuestring);
		cJSON_AddItemToObject(response_msg, "data", response_data);

		response_payload = cJSON_PrintUnformatted(response_msg);
		if (!response_payload) {
			LogError("cJSON_PrintUnformatted response_payload failed");
			ret = -1;
			goto out;
		}

		/* 返回mqtt数据 */
		snprintf(response_topic, 128, "%s_reply", topic); /* 返回的topic */
		ota_ubus_send_message(response_topic, response_payload);
	}


	//如果没有升级标识，则不进行升级
	if (update_flag->valueint) {
		// 先回复消息后，在进行业务操作，避免阻塞
		int policy = REQ_POLICY_ARGS_ENCODE((type->valueint - 1), 0, 0, 0, 1);
		download_process_external_business((void *)policy);
	}
out:
	if (reply && 1 == reply->valueint) {
		if (response_payload) {
			free(response_payload);
		}

		if (rsp_params) {
			cJSON_Delete(rsp_params);
		}
	}

	if (request_msg) {
		cJSON_Delete(request_msg);
	}

	return ret;
}

void mqtt_info_init(struct user_config_info *info, char *devid)
{
	snprintf(dev_root_info.sn, sizeof(dev_root_info.sn), "%s", info->sn);
	snprintf(dev_root_info.model, sizeof(dev_root_info.model), "%s", info->model);
	snprintf(dev_root_info.device_id, sizeof(dev_root_info.device_id), "%s", devid);
	dev_root_info.type_flag = info->type_flag;
	LogInfo("device_id: %s", dev_root_info.device_id);
}


