#ifndef _THING_ADAPTER_H_
#define _THING_ADAPTER_H_

#include "cjson/cJSON.h"
#include "link/common.h"

#define THING_ADAPTER_SERVICE_ID_LEN    (64)
#define THING_ADAPTER_SERVICE_TYPE_LEN    (64)

#define THING_ADAPTER_DEVICE_HOST_LEN     (32)
#define THING_ADAPTER_DEVICE_ID_LEN     (128)
#define THING_ADAPTER_DEVICE_SECRET_LEN     (128)

/* 设备信息 */
typedef struct _DEVICE_CONFIG{
    char host[THING_ADAPTER_DEVICE_HOST_LEN];   /* 服务器地址 */
    int port;                                   /* 服务器端口 */
    char device_id[THING_ADAPTER_DEVICE_ID_LEN];    /* device id */
    char device_secret[THING_ADAPTER_DEVICE_SECRET_LEN];    /* device secret */
}DEVICE_CONFIG;

/* thing adapter注册信息 */
typedef struct _THING_ADAPTER{
    char service_id[THING_ADAPTER_SERVICE_ID_LEN];  /* 服务id */
    char service_type[THING_ADAPTER_SERVICE_TYPE_LEN];  /* 服务类型 */
    int (*execute_command)(cJSON* request, cJSON* response);    /* 执行单条命令 */
    int (*execute_commands)(cJSON* request, cJSON* response);    /* 执行一组命令 */
    int (*get_property)(cJSON* request, cJSON* response);       /* 获取属性 */
    int (*set_property)(cJSON* request, cJSON* response);       /* 设置属性 */
    int (*on_connect)();    /* 成功连接云服务器的回调 */
    int (*on_disconnect)();    /* 断开云服务器的回调 */
}THING_ADAPTER;

/**
 *\fn     thing_adapter_set_device
 *\brief  设置云服务器和设备信息 
 * 
 * \param[in] host  云服务器地址
 * \param[in] port  云服务器端口
 * \param[in] device_id  设备id
 * \param[in] device_secret  设备secret
 * 
 * \return 0:成功，-1:失败
 **/
int thing_adapter_set_device(char* host, int port, char* device_id, char* device_secret);

/**
 *\fn     thing_adapter_register
 *\brief  注册thing adapter信息和函数回调
 * 
 * \param[in] adapter  adapter注册数据结构
 * 
 * \return 0:成功，-1:失败
 **/
int thing_adapter_register(THING_ADAPTER* adapter);

/**
 *\fn     thing_adapter_run
 *\brief  thing_adapter业务循环，该接口不会返回
 * 
 * 
 * \return 0:成功，-1:失败
 **/
int thing_adapter_run();

/**
 *\fn     thing_adapter_send_event
 *\brief  thing_adapter状态上报
 * 
 * \param[in] event_data
 *       上报信息的json数据结构，注意event_data的内存由调用者释放
 * 
 * \return 0:成功，-1:失败
 **/
int thing_adapter_send_event(cJSON* event_data);

/**
 *\fn     thing_adapter_report_property
 *\brief  thing_adapter属性上报
 * 
 * \param[in] property_data
 *       上报信息的json数据结构，注意property_data的内存由调用者释放
 * 
 * \return 0:成功，-1:失败
 **/
int thing_adapter_report_property(cJSON* property_data);
#endif
