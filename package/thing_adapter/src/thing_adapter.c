#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/time.h>
#include <unistd.h>

#include "thing_adapter.h"
#include "adapter_ubus.h"

#define THING_TOPIC_EXECUTE_COMMAND "/thing/command/execute"
#define THING_TOPIC_GET_PROPERTY "/thing/property/get"
#define THING_TOPIC_SET_PROPERTY "/thing/property/set"

enum {
    THING_ADAPTER_CALL_NONE = -1,
    THING_ADAPTER_CALL_EXECUTE_COMMAND = 0,
    THING_ADAPTER_CALL_EXECUTE_COMMANDS,
    THING_ADAPTER_CALL_GET_PROPERTY,
    THING_ADAPTER_CALL_SET_PROPERTY,
};

int thing_adapter_get_data(THING_ADAPTER* adapter);
int thing_adapter_call(char* topic, char* payload);

static DEVICE_CONFIG device_config;
static THING_ADAPTER thing_adapter;

int thing_adapter_set_device(char* host, int port, char* device_id, char* device_secret)
{
    if (!host || !device_id || !device_secret) 
    {
        return -1;
    }

    strncpy(device_config.host, host, THING_ADAPTER_DEVICE_HOST_LEN);
    device_config.port = port;
    strncpy(device_config.device_id, device_id, THING_ADAPTER_DEVICE_ID_LEN);
    strncpy(device_config.device_secret, device_secret, THING_ADAPTER_DEVICE_SECRET_LEN);

    return 0;
}

int thing_adapter_register(THING_ADAPTER* adapter)
{
    if (!adapter) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "adapter is NULL.");
        return -1;
    }
    thing_adapter = *adapter;

    return 0;
}

int thing_adapter_get_data(THING_ADAPTER* adapter)
{   
    if (!adapter) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "adapter is NULL.");
        return -1;
    }
    
    *adapter = thing_adapter;
    return 0;
}

/* 发送设备信息给thing_service */
int _send_device_info()
{
    int ret = 0;
    struct blob_buf req = {};

    blob_buf_init(&req, 0);
    blobmsg_add_string(&req, "host", device_config.host);
    blobmsg_add_u32(&req, "port", device_config.port);
    blobmsg_add_string(&req, "device_id", device_config.device_id);
    blobmsg_add_string(&req, "device_secret", device_config.device_secret);

    if (ubus_call_async("thing_service", "set_device", &req, NULL, NULL) < 0) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR,"ubus_call thing_service set_device failed.");
        ret = -1;
        goto out;
    }

out:
	blob_buf_free(&req);
    return ret;
}

int _send_service()
{
    int ret = 0;
    struct blob_buf req = {};

    blob_buf_init(&req, 0);
    blobmsg_add_string(&req, "service_id", thing_adapter.service_id);
    blobmsg_add_string(&req, "service_type", thing_adapter.service_type);

    if (ubus_call_async("thing_service", "add_service", &req, NULL, NULL) < 0) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR,"ubus_call thing_service add_service failed.");
        ret = -1;
        goto out;
    }

out:
	blob_buf_free(&req);
    return ret;
}

static void _connect_thing_service(struct uloop_timeout *timeout)
{
    _send_device_info();
    _send_service();
}

static void _connect_thing_service_timer_init()
{
    static struct uloop_timeout timeout = {
        .cb = _connect_thing_service,
    };

    uloop_timeout_set(&timeout, 3*1000);
}

int thing_adapter_run()
{
    /* ubus初始化 */
    if (thing_adapter_ubus_init(thing_adapter.service_id) < 0) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR,"thing_adapter_ubus_init failed.");
        return -1;
    }

    /* 延迟发起连接mqtt */
    _connect_thing_service_timer_init();

    /* uloop初始化 */
    uloop_init();
    uloop_run();
    uloop_done();

    /* ubus清理 */
    thing_adapter_ubus_cleanup();
    return 0;
}

unsigned int get_timestamp()
{
    return time(NULL);
}

int thing_adapter_send_message(char* topic, char* payload)
{
    int ret = 0;
    if (!topic || !payload) 
    {
        return -1;
    }

    struct blob_buf req = {};
    blob_buf_init(&req, 0);
    blobmsg_add_string(&req, "topic", topic);
    blobmsg_add_string(&req, "payload", payload);

    if (ubus_call_async("thing_service", "send_message", &req, NULL, NULL) < 0) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR,"ubus_call mqtt_client publish failed.");
        ret = -1;
        goto out;
    }

out:
	blob_buf_free(&req);
    return ret;
}

/* 执行回调 */
int thing_adapter_call(char* topic, char* payload)
{
    int call_type = THING_ADAPTER_CALL_NONE;
    int ret = 0;
    cJSON* request_msg = NULL;
    cJSON* response_msg = NULL;
    cJSON* request_data = NULL;  /* 请求参数 */
    cJSON* response_data = NULL; /* 返回结果 */

    cJSON* msg_id = NULL;    /* message id */
    cJSON* version = NULL;
    cJSON* service_id = NULL;   /* service id */
    cJSON* params = NULL;

    char response_topic[128];
    char* response_payload = NULL;

    if (!topic || !payload) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "topic or payload is NULL.");
        ret = -1;
        goto out;
    }

    /* 解析topic，获得调用类型 */
    if (strstr(topic, THING_TOPIC_EXECUTE_COMMAND)) 
    {
        call_type = THING_ADAPTER_CALL_EXECUTE_COMMAND;
    }
    else if(strstr(topic, THING_TOPIC_GET_PROPERTY))
    {
        call_type = THING_ADAPTER_CALL_GET_PROPERTY;
    }
    else if(strstr(topic, THING_TOPIC_SET_PROPERTY))
    {
        call_type = THING_ADAPTER_CALL_SET_PROPERTY;
    }else
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "unknown topic type %s.",topic);
        ret = -1;
        goto out;
    }
    
    request_msg = cJSON_Parse(payload);
    if (!request_msg) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "cJSON_Parse message failed.");
        ret = -1;
        goto out;
    }
    
    msg_id = cJSON_GetObjectItem(request_msg, "id");
    if (!msg_id || !msg_id->valuestring) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "msg_id is NULL.");
        ret = -1;
        goto out;
    }
    //SUNMI_LOG(PRINT_LEVEL_INFO, "msg_id = %s.", msg_id->valuestring);
    
    version = cJSON_GetObjectItem(request_msg, "version");
    if (!version || !version->valuestring) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "version is NULL.");
        ret = -1;
        goto out;
    }
    //SUNMI_LOG(PRINT_LEVEL_INFO, "version = %s.", version->valuestring);

    /* 获取data字段 */
    request_data = cJSON_GetObjectItem(request_msg, "data");
    if (!request_data || cJSON_Object != request_data->type) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "request_data is invalid.");
        ret = -1;
        goto out;
    }

    /* service_id */
    service_id = cJSON_GetObjectItem(request_data, "service_id");
    if (!service_id || cJSON_String != service_id->type)
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "service_id is invalid.");
        ret = -1;
        goto out;
    }

    /* params */
    params = cJSON_GetObjectItem(request_data, "params");
    if (!params)
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "params is NULL.");
        ret = -1;
        goto out;
    }

    /* 区分单命令还是组合命令 */
    if (THING_ADAPTER_CALL_EXECUTE_COMMAND == call_type)
    {
        if (cJSON_Array == params->type) 
        {
            call_type = THING_ADAPTER_CALL_EXECUTE_COMMANDS;
        }
    }
    
    /* 初始化response数据 */
    response_data = cJSON_CreateObject();

    /* 执行回调 */
    if (THING_ADAPTER_CALL_EXECUTE_COMMAND == call_type) 
    {
        if (thing_adapter.execute_command)
        {
            thing_adapter.execute_command(request_data, response_data);
        }
    }
    else if (THING_ADAPTER_CALL_EXECUTE_COMMANDS == call_type) 
    {
        if (thing_adapter.execute_commands)
        {
            thing_adapter.execute_commands(request_data, response_data);
        }
    }     
    else if (THING_ADAPTER_CALL_GET_PROPERTY == call_type)
    {
        if (thing_adapter.get_property)
        {
            thing_adapter.get_property(request_data, response_data);
        }
    }
    else if(THING_ADAPTER_CALL_SET_PROPERTY == call_type)
    {
        if (thing_adapter.set_property)
        {
            thing_adapter.set_property(request_data, response_data);
        }
    }else
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "unknown adapter call type %d.",call_type);
    }
    
    /* 构造返回数据 */
    response_msg = cJSON_CreateObject();
    if (!response_msg)
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "cJSON_CreateObject response_msg failed");
        ret = -1;
        goto out;
    }
    cJSON_AddStringToObject(response_msg, "id", msg_id->valuestring);
    cJSON_AddNumberToObject(response_msg, "ts", (long long)get_timestamp() * 1000);
    cJSON_AddStringToObject(response_msg, "version", version->valuestring);
    cJSON_AddItemToObject(response_msg, "data", response_data);

    response_payload = cJSON_PrintUnformatted(response_msg);
    if (!response_payload) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "cJSON_PrintUnformatted response_payload failed");
        ret = -1;
        goto out;
    }

    SUNMI_LOG(PRINT_LEVEL_INFO, "response_payload = %s", response_payload);

    /* 返回mqtt数据 */
    snprintf(response_topic, 128, "%s_reply", topic); /* 返回的topic */
    thing_adapter_send_message(response_topic, response_payload);

out:
    if (request_msg) 
    {
        cJSON_Delete(request_msg);
    }

    if (response_msg) 
    {
        cJSON_Delete(response_msg);
    }

    if (response_payload) 
    {
        free(response_payload);
    }
    return ret;
}

/* 发送事件上报数据 */
int thing_adapter_send_event(cJSON* event_data)
{
    int ret = 0;
    char event_topic[128];

    cJSON* event_msg = NULL;
    cJSON* data = NULL;
    char* event_payload = NULL;

    if (!event_data) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "event_data is invalid.");
        ret = -1;
        goto out;
    }
    
    /* 填充event消息 */
    event_msg = cJSON_CreateObject();
    if (!event_msg) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "cJSON_CreateObject response_msg failed");
        ret = -1;
        goto out;
    }
    
    data = cJSON_Duplicate(event_data, true);
    //cJSON_AddStringToObject(response_msg, "id", msg_id->valuestring);
    cJSON_AddNumberToObject(event_msg, "ts", (long long)get_timestamp() * 1000);
    cJSON_AddItemToObject(event_msg, "data", data);

    /* 返回mqtt数据 */
    snprintf(event_topic, 128, "smlink/%s/thing/event/report", device_config.device_id); /* 返回的topic */
    event_payload = cJSON_PrintUnformatted(event_msg);
    if (!event_payload) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "cJSON_PrintUnformatted event_payload failed");
        ret = -1;
        goto out;
    }

    thing_adapter_send_message(event_topic, event_payload);

out:
    if (event_msg) 
    {
        cJSON_Delete(event_msg);
    }

    if (event_payload) 
    {
        free(event_payload);
    }
    return ret;
}
