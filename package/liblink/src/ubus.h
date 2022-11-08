#ifndef _LINK_UBUS_H_
#define _LINK_UBUS_H_

#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/socket.h>

#include <libubox/uloop.h>
#include <libubox/usock.h>
#include <libubox/blobmsg_json.h>
#include <libubus.h>

/**
 *\fn     ubus_init
 *\brief  ubus初始化
 * 
 * \param[in] module_name   模块名
 * 
 * \return 0:成功，-1:失败
 **/
int ubus_init(char* module_name);

/**
 *\fn     ubus_cleanup
 *\brief  ubus清理
 * 
 * \return 0:成功，-1:失败
 **/
int ubus_cleanup();

/**
 *\fn     ubus_call
 *\brief  ubus的c接口，能够处理uloop线程和跨线程调用
 * 
 * \param[in] path   ubus调用路径  
 * \param[in] method ubus调用方法
 * \param[in] req    ubus调用参数
 * \param[in] resp   ubus调用返回结构
 * \param[in] timeout 超时时间
 * 
 * \return 0:成功，-1:失败
 **/
int ubus_call(const char* path, const char* method, struct blob_buf* req, struct blob_buf* resp, int timeout);

/**
 *\fn     ubus_call
 *\brief  ubus的异步调用c接口 
 * 
 * \param[in] path   ubus调用路径  
 * \param[in] method ubus调用方法
 * \param[in] req    ubus调用参数
 * \param[in] data_cb 回调函数，异步处理response
 * \param[in] arg 回调函数参数，调用者自定义传入
 * 
 * \return 0:成功，-1:失败
 **/
int ubus_call_async(const char* path, const char* method, struct blob_buf* req, ubus_data_handler_t data_cb, void* arg);

/**
 *\fn     ubus_add_module_object
 *\brief  注册新的ubus object
 * 
 * \param[in] module_obj  待注册的ubus object
 * 
 * \return 0:成功 -1:失败
 **/
int ubus_add_module_object(struct ubus_object* module_obj);

/**
 *\fn     ubus_remove_module_object
 *\brief  取消已注册ubus object
 * 
 * \param[in] module_obj  待取消注册的ubus object
 * 
 * \return 0:成功 -1:失败
 **/
int ubus_remove_module_object(struct ubus_object* module_obj);

/**
 *\fn     ubus_check
 *\brief  判断一个ubus路径是否有效
 * 
 * \param[in] path  ubus路径
 * 
 * \return 0:成功 -1:失败
 **/
int ubus_check(const char* path);
#endif
