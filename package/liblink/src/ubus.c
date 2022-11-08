#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/socket.h>
#include <pthread.h>

#include <libubox/uloop.h>
#include <libubox/usock.h>
#include <libubox/blobmsg_json.h>
#include <libubus.h>
#include <json/json.h>

#include "ubus.h"
#include "log.h"

static char _rpc_unix_socket_path[32];  /* unix sock路径 */
#define UBUS_RPC_MSG_PATH_LEN     (32)                  /* ubus调用path长度 */
#define UBUS_RPC_MSG_METHOD_LEN   (32)                  /* ubus调用method长度 */
#define UBUS_RPC_MSG_DATA_LEN     (64 * 1024)           /* ubus调用data长度 */

/* ubus跨线程调用消息结构 */
struct UBUG_RPC_MSG{
    char path[UBUS_RPC_MSG_PATH_LEN];       /* 路径 */
    char method[UBUS_RPC_MSG_METHOD_LEN];   /* 方法 */
    char data[UBUS_RPC_MSG_DATA_LEN];       /* 数据信息 */
    int async;                              /* 是否异步调用 */
    int timeout;                            /* 超时时间，仅同步操作存在 */
    ubus_data_handler_t data_cb;            /* 异步回调函数，仅异步操作存在 */
    void* arg;                              /* 异步回调函数参数，仅异步操作存在 */
    int errcode;                            /* 错误码 */
};

/* ubus跨线程调用客户端结构 */
struct UBUG_RPC_CLIENT {
	struct list_head list;  /* 链表节点 */
    struct uloop_fd ufd;    /* fd */
};

static struct ubus_context *ubus_ctx; /* ubus context数据结构 */
static pthread_t ubus_tid;            /* ubus 线程id */
static struct uloop_fd ubus_rpc_sfd;  /* 跨线程调用ubus server fd */
static LIST_HEAD(ubus_rpc_clients);   /* client列表 */

/**
 *\fn     _reconnect_timer
 *\brief  ubus重连回调函数
 * 
 * \param[in] timeout  uloop timeout数据结果
 * 
 * \return void
 **/
static void _reconnect_timer(struct uloop_timeout *timeout)
{
    static struct uloop_timeout retry = {
        .cb = _reconnect_timer,
    };

    if (ubus_reconnect(ubus_ctx, NULL) != 0) {
        uloop_timeout_set(&retry, 2000);
        return;
    }

    ubus_add_uloop(ubus_ctx);
}

/**
 *\fn     _connection_lost
 *\brief  ubus丢失连接回调函数
 * 
 * \param[in] ctx  ubus环境句柄
 * 
 * \return void
 **/
static void _connection_lost(struct ubus_context *ctx)
{
    _reconnect_timer(NULL);
}


/* 发送ubus消息 */
static int _ubus_select_write(int fd, struct UBUG_RPC_MSG *msg)
{
    fd_set write_fds;
    struct timeval tv;
    int ret = -1;
    int max_fd = -1;

    /* 初始化fd集 */
    FD_ZERO(&write_fds);
    FD_SET(fd, &write_fds);
    max_fd = fd + 1;

    /* 超时时间设为1s */
    tv.tv_sec = 1;
    tv.tv_usec = 0;

    ret = select(max_fd, NULL, &write_fds, NULL, &tv);

    if (ret < 0) 
    {
        return -1;
    }
    else if(0 == ret) /* timeout */
    {
        return -1;
    }
    else
    {
        if (FD_ISSET(fd, &write_fds)) 
        {
            if(write(fd, msg, sizeof(struct UBUG_RPC_MSG)) < 0)
            {
                return -1;
            }
        }
    }

    return 0;
}

/* 读取ubus返回消息 */
static int _ubus_select_read(int fd, struct UBUG_RPC_MSG *msg)
{
    fd_set read_fds;
    struct timeval tv;
    int ret = -1;
    int max_fd = -1;

    /* 初始化fd集 */
    FD_ZERO(&read_fds);
    FD_SET(fd, &read_fds);
    max_fd = fd + 1;

    /* 超时时间设为ubus timeout + 1 */
    tv.tv_sec = (msg->timeout/1000) + 1;
    tv.tv_usec = 0;

    ret = select(max_fd, &read_fds, NULL, NULL, &tv);

    if (ret < 0) 
    {
        return -1;
    }
    else if(0 == ret) /* timeout */
    {
        return -1;
    }
    else
    {
        if (FD_ISSET(fd, &read_fds)) 
        {
            if(read(fd, msg, sizeof(struct UBUG_RPC_MSG)) < 0)
            {
                return -1;
            }
        }
    }

    return 0;
}

/**
 *\fn     _rpc_remove_client
 *\brief  删除并释放ubus client
 * 
 * \param[in] cl client数据结果
 * 
 * \return void
 **/
static void  _rpc_remove_client(struct UBUG_RPC_CLIENT* cl)
{
    uloop_fd_delete(&cl->ufd);
    close(cl->ufd.fd);
    list_del(&cl->list);
    free(cl);
}

static void _ubus_complete_cb(struct ubus_request *req, int ret)
{
    if (req) {
        free(req);
    }
}

/**
 *\fn     _rpc_invoke_cb
 *\brief  ubus invoke回调函数，保存返回的信息
 * 
 * \param[in] req ubus请求
 * \param[in] type
 * \param[in] msg  返回的数据
 * 
 * \return void
 **/
static void _rpc_invoke_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
    char* data = (char *)req->priv;
    /* 记录ubus返回的数据 */
    char* str = blobmsg_format_json(msg, true);

    if (str) {
        strncpy(data, str, UBUS_RPC_MSG_DATA_LEN);
        free(str);
    }
}

/**
 *\fn     _rpc_client_cb
 *\brief  处理客户端请求，收集数据并通过unix socket返回
 * 
 * \param[in] fd       uloop_fd数据结构
 * \param[in] events   fd事件
 * 
 * \return void
 **/
static void _rpc_client_cb(struct uloop_fd *fd, unsigned int events)
{
    struct UBUG_RPC_CLIENT *cl = container_of(fd, struct UBUG_RPC_CLIENT, ufd);
    struct UBUG_RPC_MSG* msg = NULL;
    int sock_fd = fd->fd;
    unsigned int id = 0;
    int async = 0;
    struct ubus_request* ubus_req = NULL;

    struct blob_buf req = {};
    
    msg = (struct UBUG_RPC_MSG*) malloc (sizeof(struct UBUG_RPC_MSG));
    if (!msg) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "malloc failed");
        goto out;
    }
    
    memset(msg, 0, sizeof(struct UBUG_RPC_MSG));

    if (_ubus_select_read(sock_fd, msg) < 0) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "read failed");
        msg->errcode = -1;
        goto out;
    }

    /* 记录是同步还是异步的请求 */
    async = msg->async;

    /* 查询模块id */
    if (ubus_lookup_id(ubus_ctx, msg->path, &id) < 0)
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "ubus_lookup_id failed");
        msg->errcode = -1;
        goto out;
    }

    if(id == 0)
    {
        SUNMI_LOG(PRINT_LEVEL_WARN, "ubus_lookup_id failed, result id = 0");
        msg->errcode = -1;
        goto out;
    }

    blob_buf_init(&req, 0);
    if(!blobmsg_add_json_from_string(&req, msg->data))
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "blobmsg_add_json_from_string failed!!! ");
        msg->errcode = -1;
        goto out;
    }

    /* 清空data数据 */
    memset(msg->data, 0, UBUS_RPC_MSG_DATA_LEN);

    /* 执行ubus invoke */
    if (async) 
    {
        /* 对于每个异步的ubus call，需求使用单独的ubus_request，内存在_ubus_complete_cb函数中释放 */
        ubus_req = (struct ubus_request*)malloc(sizeof(struct ubus_request));
        if (!ubus_req) {
            msg->errcode = -1;
            goto out;
        }

        ubus_invoke_async(ubus_ctx, id, msg->method, req.head, ubus_req);
        ubus_req->priv = msg->arg;
        ubus_req->data_cb = msg->data_cb;
        ubus_req->complete_cb = _ubus_complete_cb;
        ubus_complete_request_async(ubus_ctx, ubus_req);        
    }else
    {
        if (ubus_invoke(ubus_ctx, id, msg->method, req.head, _rpc_invoke_cb, &msg->data, msg->timeout) != 0)
        {
            SUNMI_LOG(PRINT_LEVEL_ERROR, "ubus_invoke failed");
            msg->errcode = -1;
            goto out;
        }
    }

    msg->errcode = 0;
out:
    if (msg) {
        if (_ubus_select_write(sock_fd, msg) < 0) 
        {
            SUNMI_LOG(PRINT_LEVEL_ERROR, "write failed");
        }
        
        free(msg);
    }
    blob_buf_free(&req);
    _rpc_remove_client(cl);
}

/**
 *\fn     _rpc_add_client
 *\brief  申请并新增client连接
 * 
 * \param[in] client_fd 客户端socket fd
 * 
 * \return client数据结构 NULL:申请失败
 **/
static struct UBUG_RPC_CLIENT* _rpc_add_client(int client_fd)
{
    struct UBUG_RPC_CLIENT* cl = NULL;
    cl = (struct UBUG_RPC_CLIENT*) malloc (sizeof(struct UBUG_RPC_CLIENT));
    if (!cl) 
    {
        return NULL;
    }
    
    memset(cl, 0, sizeof(struct UBUG_RPC_CLIENT));
    cl->ufd.fd = client_fd;
    cl->ufd.cb = _rpc_client_cb;
    uloop_fd_add(&cl->ufd, ULOOP_READ);
    list_add_tail(&cl->list, &ubus_rpc_clients);
    return cl;
}

/**
 *\fn     _rpc_server_cb
 *\brief  ubus跨线程调用server回调函数，创建新的client连接
 * 
 * \param[in] fd     uloop_fd数据结构
 * \param[in] events fd事件
 * 
 * \return void
 **/
static void _rpc_server_cb(struct uloop_fd *fd, unsigned int events)
{
	int client_fd = accept(fd->fd, NULL, 0);
    if (client_fd < 0) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "accept failed");
        return;
    }
    /* 新增client连接 */
    _rpc_add_client(client_fd);
}

/**
 *\fn     _rpc_init
 *\brief  跨线程ubus初始化
 * 
 * \param[in] module_name  模块名称
 * 
 * \return 0:成功，-1:失败
 **/
static int _rpc_init(char* module_name)
{
    snprintf(_rpc_unix_socket_path, 32, "/var/run/%s.sock", module_name);
    unlink(_rpc_unix_socket_path);
    /* 创建server socket */
    ubus_rpc_sfd.cb = _rpc_server_cb;
    ubus_rpc_sfd.fd = usock(USOCK_UNIX | USOCK_SERVER | USOCK_NONBLOCK, _rpc_unix_socket_path, NULL);
    if (ubus_rpc_sfd.fd < 0) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "usock server failed");
        return -1;
    }
    /* 添加uloop fd */
    uloop_fd_add(&ubus_rpc_sfd, ULOOP_READ);
    return 0;
}

/**
 *\fn     _rpc_cleanup
 *\brief  跨线程ubus清理
 * 
 * \return 0:成功，-1:失败
 **/
static int _rpc_cleanup()
{
    struct UBUG_RPC_CLIENT* cl, *tmp;

    /* 释放所有client */
	list_for_each_entry_safe(cl, tmp, &ubus_rpc_clients, list) {
		_rpc_remove_client(cl);
	}

    /* 清理server fd */
    uloop_fd_delete(&ubus_rpc_sfd);
    close(ubus_rpc_sfd.fd);
    unlink(_rpc_unix_socket_path);
    return 0;
}

/**
 *\fn     _rpc_call
 *\brief  将ubus请求发送给uloop所在的线程进行调用
 * 
 * \param[in] path   ubus调用路径  
 * \param[in] method ubus调用方法
 * \param[in] req    ubus调用参数
 * \param[in] resp   ubus调用返回结构
 * \param[in] timeout 超时时间
 * 
 * \return 0:成功，-1:失败
 **/
static int _rpc_call(const char* path, const char* method, struct blob_buf* req, struct blob_buf* resp, int timeout)
{
    struct UBUG_RPC_MSG* msg = NULL;
    int sock_fd = -1;
    int ret = 0;
    char* req_str = NULL;

    msg = (struct UBUG_RPC_MSG*) malloc (sizeof(struct UBUG_RPC_MSG));
    if (!msg) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "malloc failed");
        ret = -1;
        goto out;
    }

    /* 创建unix socket */
    sock_fd = usock(USOCK_UNIX, _rpc_unix_socket_path, NULL);
    if (sock_fd < 0) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "usock client failed");
        ret = -1;
        goto out;
    }
  
    /* 填充报文 */
    memset(msg, 0, sizeof(struct UBUG_RPC_MSG));
    strncpy(msg->path, path, UBUS_RPC_MSG_PATH_LEN);
    strncpy(msg->method, method, UBUS_RPC_MSG_METHOD_LEN);
    msg->async = 0;

    if (req)
    {
        req_str = blobmsg_format_json(req->head, true);
        if (req_str) {
            strncpy(msg->data, req_str, UBUS_RPC_MSG_DATA_LEN);
        }else
        {
            SUNMI_LOG(PRINT_LEVEL_ERROR, "blobmsg_format_json failed");
            ret = -1;
            goto out;
        }
    }
    msg->timeout = timeout;

    /* 发送请求 */
    if (_ubus_select_write(sock_fd, msg) < 0) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "usock write failed");
        ret = -1;
        goto out;
    }
    
    /* 接收uloop进程的回复 */
    if (_ubus_select_read(sock_fd, msg) < 0) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "usock read failed");
        ret = -1;
        goto out;
    }

    if (msg->errcode != 0) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "ubus rpc call failed... ");
        ret = -1;
        goto out;
    }
    
    /* 存储返回的json数据 */
    if (resp) 
    {
        blob_buf_init(resp, 0);
        if (!blobmsg_add_json_from_string(resp, msg->data))
        {
            SUNMI_LOG(PRINT_LEVEL_ERROR, "blobmsg_add_json_from_string failed... ");
            ret = -1;
            goto out;
        }
    }

out:
    if (sock_fd > 0) 
    {
        close(sock_fd);
    }

    if (req_str) 
    {
        free(req_str);
    }
    
    if (msg) 
    {
        free(msg);
    }
    
    return ret;
}

static int _rpc_call_async(const char* path, const char* method, struct blob_buf* req, ubus_data_handler_t data_cb, void* arg)
{
    struct UBUG_RPC_MSG* msg = NULL;
    int sock_fd = -1;
    int ret = 0;
    char* req_str = NULL;

    msg = (struct UBUG_RPC_MSG*) malloc (sizeof(struct UBUG_RPC_MSG));
    if (!msg) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "malloc failed");
        ret = -1;
        goto out;
    }

    /* 创建unix socket */
    sock_fd = usock(USOCK_UNIX, _rpc_unix_socket_path, NULL);
    if (sock_fd < 0) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "usock client failed");
        ret = -1;
        goto out;
    }
  
    /* 填充报文 */
    memset(msg, 0, sizeof(struct UBUG_RPC_MSG));
    strncpy(msg->path, path, UBUS_RPC_MSG_PATH_LEN);
    strncpy(msg->method, method, UBUS_RPC_MSG_METHOD_LEN);
    msg->async = 1;
    msg->data_cb = data_cb;
    msg->arg = arg;

    if (req)
    {
        req_str = blobmsg_format_json(req->head, true);
        if (req_str) {
            strncpy(msg->data, req_str, UBUS_RPC_MSG_DATA_LEN);
        }else
        {
            SUNMI_LOG(PRINT_LEVEL_ERROR, "blobmsg_format_json failed");
            ret = -1;
            goto out;
        }
    }

    /* 发送请求 */
    if (_ubus_select_write(sock_fd, msg) < 0) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "usock write failed");
        ret = -1;
        goto out;
    }
    
    /* 接收uloop进程的回复 */
    if (_ubus_select_read(sock_fd, msg) < 0) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "usock read failed");
        ret = -1;
        goto out;
    }

    if (msg->errcode != 0) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "ubus rpc call failed... ");
        ret = -1;
        goto out;
    }

out:
    if (sock_fd > 0) 
    {
        close(sock_fd);
    }

    if (req_str) 
    {
        free(req_str);
    }
    
    if (msg) 
    {
        free(msg);
    }
    return ret;
}

/**
 *\fn     _local_invoke_cb
 *\brief  保存invoke返回的数据
 * 
 * \param[in] req   ubus请求数据结构
 * \param[in] type
 * \param[in] msg   ubus返回的数据
 * 
 * \return void
 **/
static void _local_invoke_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
    struct blob_buf* resp = (struct blob_buf*)req->priv;
    char* str = NULL;

    if (resp) 
    {
        /* 记录ubus返回的数据 */
        str = blobmsg_format_json(msg, true);

        if (str) {
            if (!blobmsg_add_json_from_string(resp, str))
            {
                SUNMI_LOG(PRINT_LEVEL_ERROR, "blobmsg_add_json_from_string failed... ");
            }
            free(str);
        }
    }
}

/**
 *\fn     _local_call
 *\brief  本地调用ubus的c接口
 * 
 * \param[in] path   ubus调用路径  
 * \param[in] method ubus调用方法
 * \param[in] req    ubus调用参数
 * \param[in] resp   ubus调用返回结构
 * \param[in] timeout 超时时间
 * 
 * \return 0:成功，-1:失败
 **/
static int _local_call(const char* path, const char* method, struct blob_buf* req, struct blob_buf* resp, int timeout)
{
    int ret = -1;
    unsigned int id = -1;

    /* 查询模块id */
    if (ubus_lookup_id(ubus_ctx, path, &id) < 0)
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "ubus_lookup_id failed");
        ret = -1;
        goto out;
    }

    if (resp) 
    {
        blob_buf_init(resp, 0);
    }

    /* 执行ubus invoke */
    if(ubus_invoke(ubus_ctx, id, method, req->head, _local_invoke_cb, resp, timeout) != 0)
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "ubus_invoke failed");
        ret = -1;
        goto out;
    }

    ret = 0;
out:
    return ret;
}

static int _local_call_async(const char* path, const char* method, struct blob_buf* req, ubus_data_handler_t data_cb, void* arg)
{
    int ret = -1;
    unsigned int id = -1;
    struct ubus_request* ubus_req = NULL;

    /* 查询模块id */
    if (ubus_lookup_id(ubus_ctx, path, &id) < 0)
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "ubus_lookup_id failed");
        ret = -1;
        goto out;
    }

	/* 对于每个异步的ubus call，需求使用单独的ubus_request，内存在_ubus_complete_cb函数中释放 */
	ubus_req = (struct ubus_request*)malloc(sizeof(struct ubus_request));
	if (!ubus_req) {
		ret = -1;
		goto out;
	}

	ubus_invoke_async(ubus_ctx, id, method, req->head, ubus_req);
    ubus_req->priv = arg;
	ubus_req->data_cb = data_cb;
	ubus_req->complete_cb = _ubus_complete_cb;
	ubus_complete_request_async(ubus_ctx, ubus_req);

    ret = 0;
out:
    return ret;
}

/**
 *\fn     ubus_init
 *\brief  ubus初始化
 * 
 * \param[in] module_name   模块名 
 * 
 * \return 0:成功，-1:失败
 **/
int ubus_init(char* module_name)
{
    /* ubus连接 */
	ubus_ctx = ubus_connect(NULL);

    /* 1秒后再试一次 */
    if (!ubus_ctx) 
    {
        sleep(1);
        ubus_ctx = ubus_connect(NULL);
    }
    
	if (!ubus_ctx) {
		SUNMI_LOG(PRINT_LEVEL_ERROR, "Failed to connect to ubus");
		return -1;
	}

    /* 记录uloop tid */
    ubus_tid = pthread_self();
    ubus_ctx->connection_lost = _connection_lost;
    ubus_add_uloop(ubus_ctx);

    /* 跨线程rpc初始化 */
    if (_rpc_init(module_name) < 0) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "_rpc_init failed");
        return -1;
    }
    
    return 0;
}

/**
 *\fn     ubus_cleanup
 *\brief  ubus清理
 * 
 * \return 0:成功，-1:失败
 **/
int ubus_cleanup()
{
    /* 跨线程rpc清理 */
    _rpc_cleanup();

    /* 释放内存 */
	if (ubus_ctx)
    {
		ubus_free(ubus_ctx);
    }

    return 0;
}

/**
 *\fn     ubus_call
 *\brief 
 *        ubus的同步调用c接口，能够处理uloop和跨线程调用
 * 
 * \param[in] path   ubus调用路径  
 * \param[in] method ubus调用方法
 * \param[in] req    ubus调用参数
 * \param[in] resp   ubus调用返回结构
 * \param[in] timeout 超时时间
 * 
 * \return 0:成功，-1:失败
 **/
int ubus_call(const char* path, const char* method, struct blob_buf* req, struct blob_buf* resp, int timeout)
{
    pthread_t tid = pthread_self();
    if (pthread_equal(tid, ubus_tid)) 
    {
        return _local_call(path, method, req, resp, timeout);
    }
    
    return _rpc_call(path, method, req, resp, timeout);
}

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
int ubus_call_async(const char* path, const char* method, struct blob_buf* req, ubus_data_handler_t data_cb, void* arg)
{
    pthread_t tid = pthread_self();
    if (pthread_equal(tid, ubus_tid)) 
    {
        return _local_call_async(path, method, req, data_cb, arg);
    }
    
    return _rpc_call_async(path, method, req, data_cb, arg);
}

/**
 *\fn     ubus_add_module_object
 *\brief  注册新的ubus object
 * 
 * \param[in] module_obj  待注册的ubus object
 * 
 * \return 0:成功 -1:失败
 **/
int ubus_add_module_object(struct ubus_object* module_obj)
{
    return ubus_add_object(ubus_ctx, module_obj);
}

/**
 *\fn     ubus_remove_module_object
 *\brief  取消已注册ubus object
 * 
 * \param[in] module_obj  待取消注册的ubus object
 * 
 * \return 0:成功 -1:失败
 **/
int ubus_remove_module_object(struct ubus_object* module_obj)
{
    return ubus_remove_object(ubus_ctx, module_obj);
}

/**
 *\fn     ubus_check
 *\brief  判断一个ubus路径是否有效
 * 
 * \param[in] path  ubus路径
 * 
 * \return 0:成功 -1:失败
 **/
int ubus_check(const char* path)
{
    uint32_t id = 0;
    if (ubus_lookup_id(ubus_ctx, path, &id) < 0)
    {
        return -1;
    }

    if (0 == id) 
    {
        return -1;
    }
    
    return 0;
}
