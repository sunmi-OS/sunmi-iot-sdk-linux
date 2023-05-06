#include <libubox/list.h>
#include <pthread.h>
#include <time.h>

#include "service.h"

#define SERVICE_MAX_NUM      (8)   /* 最大服务数量 */

typedef struct{
    struct list_head head;      /* 模块队列头部 */
    int num;                    /* 模块个数 */
    int inited;                 /* 是否初始化 */
    pthread_mutex_t lock;       /* 互斥锁 */
}SERVICE_DATA;

static SERVICE_DATA services;    /* 服务数据结构 */

static unsigned int _get_ts()
{
    return time(NULL);
}

static SERVICE* _find(const char* serivce_id)
{
    SERVICE* service = NULL;
    if (!serivce_id) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "serivce_id is NULL.");
        return NULL;
    }

    /* 遍历查找 */
    list_for_each_entry(service, &services.head, list)
    {
        if (!strncmp(service->service_id, serivce_id, THING_SERVICE_ID_LEN))
        {
            return service;
        }
    }
    return NULL;
}

int service_init()
{
    if (services.inited) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "services is inited.");
        return 0;
    }

    memset(&services, 0, sizeof(SERVICE_DATA));

    /* 初始化链表头 */
    INIT_LIST_HEAD(&services.head);

    /* 初始化互斥锁 */
    pthread_mutex_init(&services.lock, NULL);

    service_check_alive_timer_init();

    services.inited = 1;
    return 0;
}

int service_cleanup()
{
	SERVICE *service = NULL, *tmp = NULL;

    services.inited = false;

    /* 调用子模块清理函数，并卸载模块 */
    list_for_each_entry_safe(service, tmp, &services.head, list)
    {
        list_del(&service->list);
        free(service);
        services.num--;
    }

    /* 释放锁 */
    pthread_mutex_destroy(&services.lock);
    return 0;
}

int service_register(char* service_id, char* service_type, int adapter_id)
{
    SERVICE* service = NULL;
    int ret = 0;
    if (!service_id) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "service_id is NULL.");
        return -1;
    }

    if (!services.inited) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "services is not inited.");
        return -1;
    }
    
    pthread_mutex_lock(&services.lock);

    /* 检测service个数上限 */
    if (services.num >= SERVICE_MAX_NUM) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "service list is full.");
        ret = -1;
        goto out;
    }

    /* 模块名称不能为空 */
    if (strlen(service_id) <= 0)
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "service service_id is invalid.");
        ret = -1;
        goto out;
    }

    /* 判断是否已有重名模块 */
    service = _find(service_id);
    if (service) 
    {
        SUNMI_LOG(PRINT_LEVEL_WARN, "service_id is registered.");
        service->adapter_id = adapter_id; /* adapter重新启动，更新id */
        service->alive = 1;
        ret = 0;
        goto out;
    }
    
    service = (SERVICE*)malloc(sizeof(SERVICE));
    if (!service) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "malloc service failed.");
        ret = -1;
        goto out;
    }
    memset(service, 0, sizeof(SERVICE));
    strncpy(service->service_id, service_id, THING_SERVICE_ID_LEN - 1);
    strncpy(service->service_type, service_type, THING_SERVICE_TYPE_LEN - 1);
    service->alive = 1;
    service->adapter_id = adapter_id;

    list_add_tail(&service->list, &services.head);
    services.num++;

    SUNMI_LOG(PRINT_LEVEL_INFO, "service_id=%s, service_type=%s.", service_id, service_type);

out:
    pthread_mutex_unlock(&services.lock);
    return ret;
}

int service_get_adapter_id(char* service_id, int* adapter_id)
{
    SERVICE* service = NULL;
    int ret = 0;

    if (!service_id) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "service_id is NULL.");
        return -1;
    }

    if (!services.inited) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "services is not inited.");
        return -1;
    }

    pthread_mutex_lock(&services.lock);
    service = _find(service_id);
    if (!service) 
    {
        ret = -1;
        goto out;
    }
    *adapter_id = service->adapter_id;
    
out:
    pthread_mutex_unlock(&services.lock);
    return ret;
}

int service_get_list(struct blob_buf* bbuf)
{
    SERVICE *service= NULL;
    void* array = NULL, *table = NULL;

    if (!services.inited) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "adapters is not inited.");
        return -1;
    }
    
    pthread_mutex_lock(&services.lock);

    blob_buf_init(bbuf, 0);
    array = blobmsg_open_array(bbuf, "service");
    list_for_each_entry(service, &services.head, list)
    {
        table = blobmsg_open_table(bbuf, "");

        /* 填充模块信息 */
        blobmsg_add_string(bbuf, "service_id", service->service_id);
        blobmsg_add_string(bbuf, "service_type", service->service_type);
        blobmsg_add_u32(bbuf, "adapter_id", service->adapter_id);
        blobmsg_add_u32(bbuf, "alive", service->alive);

        blobmsg_close_table(bbuf, table);
    }
    blobmsg_close_array(bbuf, array);

    pthread_mutex_unlock(&services.lock);
    return 0;
}

/* 检查adapter是否alive */
void service_check_alive(struct uloop_timeout *timeout)
{
    SERVICE *service= NULL;
    char adapter_ubus_name[256];

    if (!services.inited) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "services is not inited.");
        return;
    }

    pthread_mutex_lock(&services.lock);

    list_for_each_entry(service, &services.head, list)
    {
        snprintf(adapter_ubus_name, 256, "thing_adapter_%d", service->adapter_id);

        if (ubus_check(adapter_ubus_name) < 0)
        {
            if (1 == service->alive) 
            {
                service->alive = 0;
                SUNMI_LOG(PRINT_LEVEL_ERROR, "service %s is terminated.", service->service_id);
            }
        }else
        {
            if (0 == service->alive) 
            {
                service->alive = 1;
                SUNMI_LOG(PRINT_LEVEL_ERROR, "service %s is alive.", service->service_id);
            }
        }
    }

    pthread_mutex_unlock(&services.lock);

    uloop_timeout_set(timeout, 10*1000);
    return;
}

void service_check_alive_timer_init()
{
    static struct uloop_timeout timeout = {
        .cb = service_check_alive,
    };

    uloop_timeout_set(&timeout, 10*1000);
}

int service_send_ack(char* topic, char* payload)
{
    cJSON* request_msg = NULL;   /* 请求报文 */

    cJSON* msg_id = NULL;    /* message id */
    cJSON* version = NULL;  /* version */
    cJSON* data = NULL;
    cJSON* sys = NULL;          /* sys参数 */
    cJSON* reply = NULL;        /* reply标志位 */

    cJSON* ack_msg = NULL;
    char ack_topic[128];
    char* ack_payload = NULL;

    char* target = NULL;

    int ret = 0;

    /* 解析payload */
    request_msg = cJSON_Parse(payload);
    if (!request_msg) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "cJSON_Parse message failed.");
        ret = -1;
        goto out;
    }

    /* 获取 msg_id */
    msg_id = cJSON_GetObjectItem(request_msg, "id");
    if (!msg_id || !msg_id->valuestring) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "msg_id is NULL.");
        ret = -1;
        goto out;
    }
    
    /* 获取 version */
    version = cJSON_GetObjectItem(request_msg, "version");
    if (!version || !version->valuestring) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "version is NULL.");
        ret = -1;
        goto out;
    }

    /* 获取sys字段 */
    sys = cJSON_GetObjectItem(request_msg, "sys");
    if (!sys) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "sys is NULL.");
        ret = -1;
        goto out;
    }

    /* 获取reply参数 */
    reply = cJSON_GetObjectItem(sys, "reply");
    if (!reply)
    {
        ret = -1;
        goto out;
    }

    /* 构建回复报文 */
    ack_msg = cJSON_CreateObject();
    if (!ack_msg) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "cJSON_CreateObject ack_msg failed");
        ret = -1;
        goto out;
    }
    
    /* data为空 */
    data = cJSON_CreateObject();
    if (!data) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "cJSON_CreateObject data failed");
        ret = -1;
        goto out;
    }

    cJSON_AddStringToObject(ack_msg, "id", msg_id->valuestring);
    cJSON_AddNumberToObject(ack_msg, "ts", (long long)_get_ts() * 1000);
    cJSON_AddStringToObject(ack_msg, "version", version->valuestring);
    cJSON_AddItemToObject(ack_msg, "data", data);

    /* 填充topic */
    //printf(ack_topic, 128, "smlink/%s/sys/message/ack", device_config.device_id)
    memset(ack_topic, 0, sizeof(ack_topic));
    strncpy(ack_topic, topic, sizeof(ack_topic));

    if (strlen(ack_topic) <= 7) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "topic is too short");
        ret = -1;
        goto out;
    }
    target = strstr(ack_topic + 7, "/");
    if (!target) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "topic is invalid");
        ret = -1;
        goto out;
    }
    target++;
    *target = '\0'; /* 截至第二个'/' */
    strncat(ack_topic, "sys/message/ack", 128);

    ack_payload = cJSON_PrintUnformatted(ack_msg);
    if (!ack_payload) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "cJSON_PrintUnformatted ack_payload failed");
        ret = -1;
        goto out;
    }
    
    //SUNMI_LOG(PRINT_LEVEL_INFO, "ack_topic = %s",ack_topic);
    //SUNMI_LOG(PRINT_LEVEL_INFO, "ack_payload = %s",ack_payload);
    service_send_mqtt(ack_topic, ack_payload);
        
out:
    if (request_msg) 
    {
        cJSON_Delete(request_msg);
    }

    if (ack_msg) 
    {
        cJSON_Delete(ack_msg);
    }
    
    if (ack_payload) 
    {
        free(ack_payload);
    }
    
    return ret;
}

int service_call(char* topic, char* payload)
{
    int ret = 0;
    struct blob_buf req = {};
    char adapter_ubus_name[256];

    cJSON* request_msg = NULL;   /* 请求报文 */
    cJSON* request_data = NULL;  /* 请求参数 */
    cJSON* service_id = NULL;   /* service id */
    int adapter_id = 0;

    /* 解析payload */
    request_msg = cJSON_Parse(payload);
    if (!request_msg) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "cJSON_Parse message failed.");
        ret = -1;
        goto out;
    }

    /* 获取data字段 */
    request_data = cJSON_GetObjectItem(request_msg, "data");
    if (!request_data) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "request_data is NULL.");
        ret = -1;
        goto out;
    }

    service_id = cJSON_GetObjectItem(request_data, "service_id");
    if (!service_id || !service_id->valuestring)
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "service_id is NULL.");
        ret = -1;
        goto out;
    }

    /* 查找adapter id */
    if(service_get_adapter_id(service_id->valuestring, &adapter_id) < 0)
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "cannot get adapter_id by service_id %s", service_id->valuestring);
        ret = -1;
        goto out;
    }

    blob_buf_init(&req, 0);
    blobmsg_add_string(&req, "topic", topic);
    blobmsg_add_string(&req, "payload", payload);

    snprintf(adapter_ubus_name, 256, "thing_adapter_%d", adapter_id);
    if (ubus_call_async(adapter_ubus_name, "handle_message", &req, NULL, NULL) < 0) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR,"ubus_call thing_service add_service failed.");
        ret = -1;
        goto out;
    }

out:
    if (request_msg) 
    {
        cJSON_Delete(request_msg);
    }
    
    blob_buf_free(&req);
    return ret;
}

/* 发送消息给mqtt客户端 */
int service_send_mqtt(char* topic, char* payload)
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
    blobmsg_add_u32(&req, "qos", 0);

    if (ubus_call_async("mqtt_client", "publish", &req, NULL, NULL) < 0) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR,"ubus_call mqtt_client publish failed.");
        ret = -1;
        goto out;
    }

out:
	blob_buf_free(&req);
    return ret;
}

int _notice_one_service_mqtt_connect(SERVICE *service)
{
    struct blob_buf req = {};
    char adapter_ubus_name[256];
    int ret = 0;

    if (!service) 
    {
        return -1;
    }

    if (service->adapter_id > 0);
    {
        blob_buf_init(&req, 0);
        blobmsg_add_string(&req, "service_id", service->service_id);

        snprintf(adapter_ubus_name, 256, "thing_adapter_%d", service->adapter_id);
        if (ubus_call_async(adapter_ubus_name, "handle_connect", &req, NULL, NULL) < 0) 
        {
            SUNMI_LOG(PRINT_LEVEL_ERROR,"ubus_call thing adapter handle_connect failed.");
            ret = -1;
            goto out;
        }
    }
    
out:
	blob_buf_free(&req);
    return ret;
}

static int _notify_ota_mqtt_connect(void)
{
    struct blob_buf req = { };
    int ret = 0;

    blob_buf_init(&req, 0);

    if (ubus_call_async("ota", "handle_connect", &req, NULL, NULL) < 0)
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "ubus_call thing adapter handle_connect failed.");
        ret = -1;
    }

    blob_buf_free(&req);
    return ret;
}

static int _notify_ota_mqtt_disconnect(void)
{
    struct blob_buf req = { };
    int ret = 0;

    blob_buf_init(&req, 0);

    if (ubus_call_async("ota", "handle_disconnect", &req, NULL, NULL) < 0)
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "ubus_call thing adapter handle_connect failed.");
        ret = -1;
    }

    blob_buf_free(&req);
    return ret;
}



int service_notice_adapter_mqtt_connect()
{
    SERVICE *service= NULL;

    if (!services.inited) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "services is not inited.");
        return -1;
    }

    list_for_each_entry(service, &services.head, list)
    {
        /* 执行回调操作 */
        _notice_one_service_mqtt_connect(service);
    }

    _notify_ota_mqtt_connect();

    return 0;
}

int _notice_one_service_mqtt_disconnect(SERVICE *service)
{
    struct blob_buf req = {};
    char adapter_ubus_name[256];
    int ret = 0;

    if (!service) 
    {
        return -1;
    }

    if (service->adapter_id > 0);
    {
        blob_buf_init(&req, 0);
        blobmsg_add_string(&req, "service_id", service->service_id);

        snprintf(adapter_ubus_name, 256, "thing_adapter_%d", service->adapter_id);
        if (ubus_call_async(adapter_ubus_name, "handle_disconnect", &req, NULL, NULL) < 0) 
        {
            SUNMI_LOG(PRINT_LEVEL_ERROR,"ubus_call thing adapter handle_disconnect failed.");
            ret = -1;
            goto out;
        }
    }
    
out:
	blob_buf_free(&req);
    return ret;
}

int service_notice_adapter_mqtt_disconnect()
{
    SERVICE *service= NULL;

    if (!services.inited) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "services is not inited.");
        return -1;
    }

    list_for_each_entry(service, &services.head, list)
    {
        /* 执行回调操作 */
        _notice_one_service_mqtt_disconnect(service);
    }

    _notify_ota_mqtt_disconnect();

    return 0;
}
