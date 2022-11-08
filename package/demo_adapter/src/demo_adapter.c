#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include "thing_adapter.h"

char* host = "emq-link.sunmi.com";     /* 服务器地址*/
int port = 443;                             /* 服务器端口 */
char* device_id = "xxxxxxxxxxxxxxxxxxxxx";   /* 设备id */
char* device_secret = "xxxxxxxxxxxxxxxxxxxxx"; /* 设备secret */

/* 单条命令执行 */
int demo_execute_command(cJSON* request_data, cJSON* response_data)
{
    cJSON* params = NULL;
    cJSON* command = NULL;

    char* request_data_str = NULL;
    char* response_data_str = NULL;

    /* 打印request_data */
    request_data_str = cJSON_PrintUnformatted(request_data);
    if (request_data_str) 
    {
        printf("request_data_str = %s\n", request_data_str);
        free(request_data_str);
    }

    /* 解析request_data */
    params = cJSON_GetObjectItem(request_data, "params");
    if (!params || cJSON_Object != params->type) 
    {
        printf("params is invalid");
        return -1;
    }

    /* 获取command */
    command = cJSON_GetObjectItem(params, "command");
    if (!command || cJSON_String != command->type) 
    {
        printf("command is invalid");
        return -1;
    }
        
    /* 执行命令操作 */
    printf("execute command = %s.\n", command->valuestring);

    /* 填充response_data */
    cJSON_AddNumberToObject(response_data, "code", 1000);
    cJSON_AddStringToObject(response_data, "msg", "ok");

    /* 打印response_data */
    response_data_str = cJSON_PrintUnformatted(response_data);
    if (response_data_str) 
    {
        printf("response_data_str = %s\n", response_data_str);
        free(response_data_str);
    }

    return 0;
}

/* 多条命令执行 */
int demo_execute_commands(cJSON* request_data, cJSON* response_data)
{
    return 0;
}

/* 属性获取 */
int demo_get_property(cJSON* request_data, cJSON* response_data)
{
    return 0;
}

/* 属性设置 */
int demo_set_property(cJSON* request_data, cJSON* response_data)
{
    return 0;
}

/* 云连接成功回调 */
int demo_on_connect()
{
    printf("demo on connect\n");
    return 0;
}

/* 云连接断开回调 */
int demo_on_disconnect()
{
    printf("demo on disconnect\n");
    return 0;
}

void* demo_send_event_routine(void* arg)
{
    cJSON* event_data = NULL;

    /* 等待一段时间发送event消息 */
    sleep(15);

    /* 构造并发送demo事件 */
    event_data = cJSON_CreateObject();

    cJSON_AddStringToObject(event_data, "demo_event", "demo_event_data");

    /* 调用thing_adapter_send_event发送event事件数据 */
    thing_adapter_send_event(event_data);

    cJSON_Delete(event_data);

    return NULL;
}

/* adapter注册信息 */
static THING_ADAPTER demo_adapter = 
{
    .service_id = "demo_service_id",  /* service_id */
    .service_type = "printer",    /* service_type */
    .execute_command = demo_execute_command, /* 单条命令处理 */
    .execute_commands = demo_execute_commands, /* 多条命令处理 */
    .get_property = demo_get_property,   /* 获取属性 */
    .set_property = demo_set_property,   /* 设置属性 */
    .on_connect = demo_on_connect,   /* 云连接成功回调 */
    .on_disconnect = demo_on_disconnect,   /* 云连接断开回调 */
};

int main()
{
    pthread_t pid = -1;

    /* 设置device信息 */
    thing_adapter_set_device(host, port, device_id, device_secret);

    /* 注册自定义adapter信息 */
    thing_adapter_register(&demo_adapter);

    /* 创建事件上报线程，用于上报event消息 */
    if (pthread_create(&pid, NULL, demo_send_event_routine, NULL) < 0) 
    {
        return -1;
    }
    pthread_detach(pid);

    /* 运行thing adapter服务，该接口不会返回 */
    thing_adapter_run();
    return 0;
}
