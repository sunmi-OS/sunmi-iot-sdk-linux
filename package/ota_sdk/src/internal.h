#ifndef _INTERNAL_H_
#define _INTERNAL_H_

#include "ota.h"
#include <libubox/uloop.h>
#include <openssl/md5.h>
#include <curl/curl.h>
#include <cjson/cJSON.h>
#include <link/log.h>

#define MD5_LEN	33
#define URL_LEN	256
#define VER_LEN	16
#define LOG_LEN	1024
#define FILE_NAME_LEN	128

#define LogError(format, args...) SUNMI_LOG(PRINT_LEVEL_ERROR, format, ##args)
#define LogInfo(format, args...) SUNMI_LOG(PRINT_LEVEL_INFO, format, ##args)

#define REQ_POLICY_ARGS_ENCODE(type, active, external, check_version, reset) \
((type << 4)|(active << 3)|(external << 2)|(check_version << 1)|(reset << 0))
#define REQ_POLICY_ARGS_DECODE(type, active, external, check_version, reset, policy) \
do {\
	type = (policy >> 4); \
	active = !!(policy & (1 << 3));\
	external = !!(policy & (1 << 2)); \
	check_version = !!(policy & (1 << 1));\
	reset = !!(policy & (1 << 0));\
} while (0)

enum {
	OTA_STATE_IDLE = 0,
	OTA_STATE_HTTP_REQUESTING,
	OTA_STATE_HTTP_REQUEST_OK,
	OTA_STATE_HTTP_REQUEST_FAIL,
	OTA_STATE_DOWNLOADING,
	OTA_STATE_DOWNLOAD_OK = 5,
	OTA_STATE_DOWNLOAD_FAIL,
	OTA_STATE_CHECKING,
	OTA_STATE_CHECK_OK,
	OTA_STATE_CHECK_FAIL,
	OTA_STATE_INSTALLING = 10,
	OTA_STATE_INSTALL_OK,
	OTA_STATE_INSTALL_FAIL,
};

enum {
	CLOUD_TYPE_NONE,
	CLOUD_TYPE_DEV,
	CLOUD_TYPE_TEST,
	CLOUD_TYPE_UAT,
	CLOUD_TYPE_ONLINE,
	CLOUD_TYPE_MAX
};

//升级包类型
enum {
	UP_FILE_TYPE_FIRMWARE,
	UP_FILE_TYPE_APPLICATION,
	UP_FILE_TYPE_RESOURCE,
	UP_FILE_TYPE_MAX
};
#define UP_FILE_TYPE_FIRMWARE_MASK	0x7
#define UP_FILE_TYPE_FIRMWARE_BIT (1<<0)
#define UP_FILE_TYPE_APPLICATION_BIT (1<<1)
#define UP_FILE_TYPE_RESOURCE_BIT (1<<2)

#define RECV_BUFF_LEN	(8*1024)
#define SEND_BUFF_LEN	(2*1024)

//升级方式
enum {
	UP_METHOD_NONE,
	UP_METHOD_OTA,
	UP_METHOD_LOCAL,
	UP_METHOD_MAX
};

struct device_cfg {
	struct user_config_info user_cfg;
	int 	initialized;
	char	orig_zipfile[FILE_NAME_LEN];
	char	fail_retry_times;
	char	fail_retry_interval; //失败后重试时间间隔，单位秒
	char	state; //当前状态: 参考OTA_STATE_XXX定义
	char	mode; //当前的升级方式：0-ota，1-local
};

#define HOST_NAME_LEN	128
#define DEV_ID_LEN	128
#define DEV_SECRET_LEN	128

struct mqtt_info {
	char host[HOST_NAME_LEN];  /* 服务器地址 */
	int port;   /* 服务器端口 */
	char device_id[DEV_ID_LEN];
	char device_secret[DEV_SECRET_LEN];
};

struct _triple_key {
	char sign_key[MD5_DIGEST_LENGTH * 2 + 1];
	char encrypt_key[MD5_DIGEST_LENGTH * 2 + 1];
	char decrypt_key[MD5_DIGEST_LENGTH * 2 + 1];
};

/* mqtt interfaces */
int mqtt_handle_connect(void);
int mqtt_handle_disconnect(void);
int mqtt_report_status(int status, const char *msg);
int mqtt_handle_message(char *topic, char *payload);
void mqtt_info_init(struct user_config_info *info, char *devid);

/* download interfaces */
int download_init_cfg(struct user_config_info *info);
int download_pull_upgrade_info(int type, bool active, bool external, bool check_version, bool reset);
int download_get_upgrade_state(char *mode);
int download_set_upgrade_state(char state, char mode);
int download_install_task(int type);
int download_ota_check_version(int type, char *new_version, int ver_len, char *log, int log_len);
int download_progress_callback(void *p, curl_off_t download_total, curl_off_t download_now,
							   curl_off_t ul_total, curl_off_t ul_now);
void download_process_external_business(void *args);

/* http interfaces */
int http_download_file(char *name, const char *url, uint32_t file_size);
char* http_req_upgrade_info(const char *version);
void http_init(const char *sn, const char *model, const char *product_id, int cloud_type);
int http_get_mqtt_info(struct mqtt_info *dev_info);
void http_exit(void);

/* crypt interfaces */
bool crypt_sign(const char *context, const char  *deviceId, int time, const char *Model,
				int Nonce, const char *signKey, unsigned char *XSign);
bool crypt_aes256_encrypt(const char *context, const char *key, char *body);
int crypt_gen_triple_key_from_devinfo(const char *devid, const char *dev_sec, struct _triple_key *outkey);
bool crypt_aes256_decrypt(const char *context, const char *key, char *body);
int crypt_md5_file(const char *file, char *md5);


/* ubus interfaces */
void* ota_ubus_init(void *arg);
int ota_ubus_cleanup(void);
int ota_ubus_send_message(char *topic, char *payload);
void ota_ubus_set_install_timer(int seconds);
void ota_ubus_reset_state_machine_timer(int seconds);


#endif /* _INTERNAL_H_ */
