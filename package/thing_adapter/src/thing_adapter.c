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

#define THING_ADAPTER_MAX_NUM      (8)   /* 单个进程注册的最大adapter数量 */

typedef struct{
    struct list_head head;      /* adapter队列头部 */
    int num;                    /* adapter个数 */
    int inited;                 /* 是否初始化 */
    int pid;                     /* adapter进程id */
}ADAPTER_DATA;

typedef struct{
    struct list_head list;             /* 链表头 */
    THING_ADAPTER thing_adapter;
}ADAPTER_ENTRY;

static ADAPTER_DATA adapters;    /* adapter数据结构 */

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
int thing_adapter_on_connect(char* service_id);

static DEVICE_CONFIG device_config;
//static THING_ADAPTER thing_adapter;

static ADAPTER_ENTRY* _find(const char* serivce_id)
{
    ADAPTER_ENTRY* adapter_entry = NULL;

    if (!serivce_id) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "serivce_id is NULL.");
        return NULL;
    }

    /* 遍历查找 */
    list_for_each_entry(adapter_entry, &adapters.head, list)
    {
        if (!strncmp(adapter_entry->thing_adapter.service_id, serivce_id, THING_ADAPTER_SERVICE_ID_LEN))
        {
            return adapter_entry;
        }
    }
    return NULL;
}

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

int thing_adapter_init()
{
    if (adapters.inited) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "adapters is inited.");
        return 0;
    }

    memset(&adapters, 0, sizeof(ADAPTER_DATA));

    /* 初始化链表头 */
    INIT_LIST_HEAD(&adapters.head);

    adapters.pid = getpid();
    adapters.inited = 1;
    return 0;
}

int thing_adapter_cleanup()
{
	ADAPTER_ENTRY *adapter_entry = NULL, *tmp = NULL;

    adapters.inited = false;

    /* 调用子模块清理函数，并卸载模块 */
    list_for_each_entry_safe(adapter_entry, tmp, &adapters.head, list)
    {
        list_del(&adapter_entry->list);
        free(adapter_entry);
        adapters.num--;
    }
    return 0;
}

int thing_adapter_register(THING_ADAPTER* adapter)
{
    ADAPTER_ENTRY* adapter_entry = NULL;
    int ret = 0;

    /* 初始化adatper列表 */
    if (!adapters.inited) 
    {
        thing_adapter_init();
    }
    
    if (!adapter) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "adapter is NULL.");
        return -1;
    }

    /* 检查adapter个数上限 */
    if (adapters.num >= THING_ADAPTER_MAX_NUM) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "adapter list is full.");
        ret = -1;
        goto out;
    }

    /* service_id不能为空 */
    if (!adapter->service_id || strlen(adapter->service_id) <= 0)
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "adapter service_id is invalid.");
        ret = -1;
        goto out;
    }

    /* service_type不能为空 */
    if (!adapter->service_type || strlen(adapter->service_type) <= 0)
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "adapter service_type is invalid.");
        ret = -1;
        goto out;
    }

    /* 判断是否已有重名adapter */
    adapter_entry = _find(adapter->service_id);
    if (adapter_entry) 
    {
        SUNMI_LOG(PRINT_LEVEL_WARN, "adapter service_id is duplicate.");
        ret = -1;
        goto out;
    }

    /* 申请内存，填充数据 */
    adapter_entry = (ADAPTER_ENTRY*)malloc(sizeof(ADAPTER_ENTRY));
    if (!adapter_entry) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "malloc adapter_entry failed.");
        ret = -1;
        goto out;
    }
    memset(adapter_entry, 0, sizeof(ADAPTER_ENTRY));
    adapter_entry->thing_adapter = *adapter;
    list_add_tail(&adapter_entry->list, &adapters.head);
    adapters.num++;

out:
    return ret;
}

int thing_adapter_get_list(struct blob_buf* bbuf)
{
    ADAPTER_ENTRY* adapter_entry = NULL;
    void* array = NULL, *table = NULL;

    blob_buf_init(bbuf, 0);
    array = blobmsg_open_array(bbuf, "service");
    list_for_each_entry(adapter_entry, &adapters.head, list)
    {
        table = blobmsg_open_table(bbuf, "");

        /* 填充模块信息 */
        blobmsg_add_string(bbuf, "service_id", adapter_entry->thing_adapter.service_id);
        blobmsg_add_string(bbuf, "service_type", adapter_entry->thing_adapter.service_type);
        blobmsg_add_u32(bbuf, "execute_command", adapter_entry->thing_adapter.execute_command? 1:0 );
        blobmsg_add_u32(bbuf, "execute_commands", adapter_entry->thing_adapter.execute_commands? 1:0 );
        blobmsg_add_u32(bbuf, "get_property", adapter_entry->thing_adapter.get_property? 1:0);
        blobmsg_add_u32(bbuf, "set_property", adapter_entry->thing_adapter.set_property? 1:0);

        blobmsg_close_table(bbuf, table);
    }
    blobmsg_close_array(bbuf, array);

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

int _send_single_service(char* service_id, char* service_type)
{
    int ret = 0;
    struct blob_buf req = {};

    if (!service_id || !service_type) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR,"service_id or service_type is invalid.");
        ret = -1;
        goto out;
    }
    
    blob_buf_init(&req, 0);
    blobmsg_add_string(&req, "service_id", service_id);
    blobmsg_add_string(&req, "service_type", service_type);
    blobmsg_add_u32(&req, "adapter_id", adapters.pid);

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

int _send_services()
{
    ADAPTER_ENTRY* adapter_entry = NULL;

    if (!adapters.inited) 
    {
        return -1;
    }

    list_for_each_entry(adapter_entry, &adapters.head, list)
    {
        _send_single_service(adapter_entry->thing_adapter.service_id, adapter_entry->thing_adapter.service_type);
    }

    return 0;
}

static void _connect_thing_service(struct uloop_timeout *timeout)
{
    _send_device_info();
    _send_services();
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
    if (thing_adapter_ubus_init(adapters.pid) < 0) 
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
    ADAPTER_ENTRY* adapter_entry = NULL;
    THING_ADAPTER* thing_adapter = NULL;

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
    
    /* 查找对应的adapter */
    adapter_entry = _find(service_id->valuestring);
    if (!adapter_entry) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "cannot find adatper %s", service_id->valuestring);
        ret = -1;
        goto out;
    }
    thing_adapter = &adapter_entry->thing_adapter;

    /* 初始化response数据 */
    response_data = cJSON_CreateObject();

    /* 执行回调 */
    if (THING_ADAPTER_CALL_EXECUTE_COMMAND == call_type) 
    {
        if (thing_adapter->execute_command)
        {
            thing_adapter->execute_command(request_data, response_data);
        }
    }
    else if (THING_ADAPTER_CALL_EXECUTE_COMMANDS == call_type) 
    {
        if (thing_adapter->execute_commands)
        {
            thing_adapter->execute_commands(request_data, response_data);
        }
    }     
    else if (THING_ADAPTER_CALL_GET_PROPERTY == call_type)
    {
        if (thing_adapter->get_property)
        {
            thing_adapter->get_property(request_data, response_data);
        }
    }
    else if(THING_ADAPTER_CALL_SET_PROPERTY == call_type)
    {
        if (thing_adapter->set_property)
        {
            thing_adapter->set_property(request_data, response_data);
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

    //SUNMI_LOG(PRINT_LEVEL_INFO, "response_payload = %s", response_payload);

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

/* 处理mqtt连接回调 */
int thing_adapter_on_connect(char* service_id)
{
    ADAPTER_ENTRY* adapter_entry = NULL;

    if (!service_id) 
    {
        return -1;
    }
    
    if (!adapters.inited) 
    {
        return -1;
    }

    adapter_entry = _find(service_id);
    if (adapter_entry && adapter_entry->thing_adapter.on_connect) 
    {
        adapter_entry->thing_adapter.on_connect();
    }

    return 0;
}

/* 处理mqtt断开回调 */
int thing_adapter_on_disconnect(char* service_id)
{
    ADAPTER_ENTRY* adapter_entry = NULL;

    if (!service_id) 
    {
        return -1;
    }
    
    if (!adapters.inited) 
    {
        return -1;
    }

    adapter_entry = _find(service_id);
    if (adapter_entry && adapter_entry->thing_adapter.on_disconnect) 
    {
        adapter_entry->thing_adapter.on_disconnect();
    }

    return 0;
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

/* 发送属性上报数据 */
int thing_adapter_report_property(cJSON* property_data)
{
    int ret = 0;
    char property_topic[128];

    cJSON* property_msg = NULL;
    cJSON* data = NULL;
    char* property_payload = NULL;

    if (!property_data) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "property_data is invalid.");
        ret = -1;
        goto out;
    }
    
    /* 填充property消息 */
    property_msg = cJSON_CreateObject();
    if (!property_msg) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "cJSON_CreateObject response_msg failed");
        ret = -1;
        goto out;
    }
    
    data = cJSON_Duplicate(property_data, true);
    //cJSON_AddStringToObject(response_msg, "id", msg_id->valuestring);
    cJSON_AddNumberToObject(property_msg, "ts", (long long)get_timestamp() * 1000);
    cJSON_AddItemToObject(property_msg, "data", data);

    /* 返回mqtt数据 */
    snprintf(property_topic, 128, "smlink/%s/thing/property/report", device_config.device_id); /* 返回的topic */
    property_payload = cJSON_PrintUnformatted(property_msg);
    if (!property_payload) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "cJSON_PrintUnformatted property_payload failed");
        ret = -1;
        goto out;
    }

    thing_adapter_send_message(property_topic, property_payload);

out:
    if (property_msg) 
    {
        cJSON_Delete(property_msg);
    }

    if (property_payload) 
    {
        free(property_payload);
    }
    return ret;
}
