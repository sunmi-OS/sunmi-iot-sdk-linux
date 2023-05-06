/*
 * 参考：https://alidocs.dingtalk.com/i/nodes/od245kZmnOeW4qLL75oeVYbzxL6R0wMQ# 「SUNMI设备鉴权方案」
*/
#define _GNU_SOURCE
#include <string.h>
#include <stdlib.h>
#include <link/common.h>
#include <curl/curl.h>
#include <cjson/cJSON.h>
#include <openssl/hmac.h>
#include <openssl/aes.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include "internal.h"

/*
 * 获取到device id 和secret之后，根据和云端的约定算法，计算出后续通信过程中使用到的key：
 * 加密key、解密key、签名key
*/
static struct _triple_key triple_key;

enum {
	DEV_CAT_POS = 1,
	DEV_CAT_IOT = 2,
	DEV_CAT_EXT = 3
};

/*
 * 获取mqtt 的host和port的https地址，需要跟云端约定给出
*/
static const char *mqtt_cloud_urls[CLOUD_TYPE_MAX] = {
	[CLOUD_TYPE_DEV]		= "https://api.dev.sunmi.com/cpt/device/v1/link/cloudInfo",
	[CLOUD_TYPE_TEST] 		= "https://api.test.sunmi.com/cpt/device/v1/link/cloudInfo",
	[CLOUD_TYPE_UAT] 		= "https://api.uat.sunmi.com/cpt/device/v1/link/cloudInfo",
	[CLOUD_TYPE_ONLINE] 	= "https://api.sunmi.com/cpt/device/v1/link/cloudInfo"
};

/*
 * 获取device id 和secret的https地址，需要跟云端约定给出
*/
static const char *devinfo_cloud_urls[CLOUD_TYPE_MAX] = {
	[CLOUD_TYPE_DEV]     = "https://api.dev.sunmi.com/cpt/device/vx/info/deviceid",
	[CLOUD_TYPE_TEST]    = "https://api.test.sunmi.com/cpt/device/vx/info/deviceid",
	[CLOUD_TYPE_UAT]     = "https://api.uat.sunmi.com/cpt/device/vx/info/deviceid",
	[CLOUD_TYPE_ONLINE]  = "https://api.sunmi.com/cpt/device/vx/info/deviceid"
};

/*
 * 获取device id和secret的相关key，由于是第一次通信，涉及到的key需要跟云端
 * 约定硬编码
*/
static struct _triple_key devinfo_keys[CLOUD_TYPE_MAX] = {
	[CLOUD_TYPE_DEV] = {
		.sign_key 	 = "***",
		.encrypt_key = "***",
		.decrypt_key = "***",
	},
	[CLOUD_TYPE_TEST] = {
		.sign_key = "***",
		.encrypt_key = "***",
		.decrypt_key = "***",
	},
	[CLOUD_TYPE_UAT] = {
		.sign_key = "***",
		.encrypt_key = "***",
		.decrypt_key = "***",
	},
	[CLOUD_TYPE_ONLINE] = {
		.sign_key = "***",
		.encrypt_key = "***",
		.decrypt_key = "***",
	}
};

/* ota 云地址，云端给出 */
static const char *ota_cloud_urls[CLOUD_TYPE_MAX] = {
	[CLOUD_TYPE_DEV]     = "https://api.dev.sunmi.com/v3/ota/iot/firmware/updateCheck",
	[CLOUD_TYPE_TEST]    = "https://api.test.sunmi.com/v3/ota/iot/firmware/updateCheck",
	[CLOUD_TYPE_UAT]     = "https://api.uat.sunmi.com/v3/ota/iot/firmware/updateCheck",
	[CLOUD_TYPE_ONLINE]  = "https://api.sunmi.com/v3/ota/iot/firmware/updateCheck"
};

struct http_resp_cache {
	char *data;
	size_t size;
};
static struct http_resp_cache http_resp_header;
static struct http_resp_cache http_resp_data;

static struct {
	char	sn[SN_LEN];
	char	model[MODEL_LEN];
	char	product_id[PRODUCT_ID_LEN];
	char	devid[DEV_ID_LEN];
	int		cloud_type;
}header_info;


#define ADD_HEADER_FIELD_NUMBER(header, key, value)\
do\
{\
	char tmp_buf[128];\
	snprintf(tmp_buf, sizeof(tmp_buf), "%s: %d", key, value);\
	header = curl_slist_append(header, tmp_buf);\
}\
while(0)

#define ADD_HEADER_FIELD_STRING(header, key, value)\
do\
{\
	char tmp_buf[256];\
	snprintf(tmp_buf, sizeof(tmp_buf), "%s: %s", key, value);\
	header = curl_slist_append(header, tmp_buf);\
}\
while(0)

#define ADD_BODY_FIELD_NUMBER(body, key, value) cJSON_AddNumberToObject(body, key, value)
#define ADD_BODY_FIELD_STRING(body, key, value) cJSON_AddStringToObject(body, key, value)

static size_t http_resp_callback(void *data, size_t size, size_t nmemb, void *clientp)
{
	size_t realsize = size * nmemb;
	struct http_resp_cache *mem = (struct http_resp_cache *)clientp;

	char *ptr = realloc(mem->data, mem->size + realsize + 1);
	if (ptr == NULL) {
		return 0;  /* out of memory! */
	}

	mem->data = ptr;
	memcpy(&(mem->data[mem->size]), data, realsize);
	mem->size += realsize;
	mem->data[mem->size] = 0;

	return realsize;
}

static void reset_resp_cache(void)
{
	if (http_resp_data.data) {
		free(http_resp_data.data);
		http_resp_data.data = NULL;
		http_resp_data.size = 0;
	}

	if (http_resp_header.data) {
		free(http_resp_header.data);
		http_resp_header.data = NULL;
		http_resp_header.size = 0;
	}
}

static inline bool body_encrypt(void)
{
	return !!strcasestr(http_resp_header.data, "X-Response-Encrypt: true");
}

static inline void destroy_curl_resource(struct curl_slist *header, CURL *curl)
{
	if (header) {
		curl_slist_free_all(header);
	}

	if (curl) {
		curl_easy_cleanup(curl);
	}
}

static void _hex2string_(const uint8_t *src, int length, char *des)
{
	int i, pos = 0;

	for (i = 0; i < length; i++) {
		pos += sprintf(des + pos, "%02x", src[i]);
	}

	return;
}



static void _set_curl_params(CURL **curl, const char *url, struct curl_slist *headers, char *body, bool https)
{
	curl_easy_setopt(*curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(*curl, CURLOPT_URL, url); //设置URL地址
	//curl_easy_setopt(*curl, CURLOPT_HEADER, 0L);  //需要同时解析http 的header和body，不能设置该选项
	curl_easy_setopt(*curl, CURLOPT_VERBOSE, 0); //设置值为1启用调试输出

	curl_easy_setopt(*curl, CURLOPT_WRITEFUNCTION, http_resp_callback); //设置HTTP请求body的数据输出函数
	curl_easy_setopt(*curl, CURLOPT_WRITEDATA, &http_resp_data);
	curl_easy_setopt(*curl, CURLOPT_HEADERFUNCTION, http_resp_callback); //设置HTTP请求header的数据输出函数
	curl_easy_setopt(*curl, CURLOPT_HEADERDATA, &http_resp_header);

	curl_easy_setopt(*curl, CURLOPT_CONNECTTIMEOUT_MS, 1000 * 40);
	curl_easy_setopt(*curl, CURLOPT_TIMEOUT, 40L);
	curl_easy_setopt(*curl, CURLOPT_NOSIGNAL, 1L);
	curl_easy_setopt(*curl, CURLOPT_POST, 1L);

	if (NULL != body) {
		curl_easy_setopt(*curl, CURLOPT_POSTFIELDS, body);
		curl_easy_setopt(*curl, CURLOPT_POSTFIELDSIZE, strlen(body));
	}

	// 目前暂时不校验双方证书
	if (https) {
		curl_easy_setopt(*curl, CURLOPT_SSL_VERIFYPEER, 0);
		curl_easy_setopt(*curl, CURLOPT_SSL_VERIFYHOST, 0); //https 请求
	}
}

static void _build_http_base_header(struct curl_slist **header, int *nonce, int *sys_time, bool json)
{
	char type[20] = { };

	*sys_time = (int)time(NULL); //获取系统时间
	srand((unsigned)time(NULL));
	*nonce = rand() % 900000 + 100000;

	if (json == 1) {
		snprintf(type, sizeof(type), "application/json");
	} else {
		snprintf(type, sizeof(type), "text/plain");
	}

	ADD_HEADER_FIELD_STRING(*header, "Content-Type", type);
	ADD_HEADER_FIELD_STRING(*header, "X-Client-Name", header_info.product_id);
	ADD_HEADER_FIELD_STRING(*header, "X-Client-Version", "1.0");
	ADD_HEADER_FIELD_NUMBER(*header, "X-Timestamp", *sys_time);
	ADD_HEADER_FIELD_NUMBER(*header, "X-Nonce", *nonce);
	ADD_HEADER_FIELD_STRING(*header, "X-Client-Model", header_info.model);

	LogInfo("Content-Type: %s", type);
	LogInfo("X-Client-Name: %s", header_info.product_id);
	LogInfo("X-Client-Version: %s", "1.0");
	LogInfo("X-Timestamp: %d", *sys_time);
	LogInfo("X-Nonce: %d", *nonce);
	LogInfo("X-Client-Model: %s", header_info.model);

}


static int _build_devinfo_body(char *body)
{
	cJSON  *payload = NULL;
	char *str_payload = NULL;
	char body_sn[SN_LEN + 16] = { 0 };
	int ret = 0;

	payload = cJSON_CreateObject();
	if (NULL == payload) {
		LogError("cJSON_CreateObject error");
		ret = -1;
		goto out;
	}

	ADD_BODY_FIELD_STRING(payload, "base_os", "SUNMI");
	ADD_BODY_FIELD_STRING(payload, "os_name", "linux");
	ADD_BODY_FIELD_STRING(payload, "sn", header_info.sn);
	snprintf(body_sn, sizeof(body_sn), "%s%s%s", "{\"sn\":\"", header_info.sn, "\"}");
	ADD_BODY_FIELD_STRING(payload, "device_attribute", body_sn);
	ADD_BODY_FIELD_NUMBER(payload, "category", DEV_CAT_IOT);

	str_payload = cJSON_Print(payload); //需要释放内存
	if (strlen(str_payload) > SEND_BUFF_LEN) {
		LogError("send payload to long, %zu, should be %d\n", strlen(str_payload), SEND_BUFF_LEN);
		ret = -1;
		goto out;
	}
	LogInfo("body:\n%s\n", str_payload);

	/* 加密body */
	if (!crypt_aes256_encrypt(str_payload, devinfo_keys[header_info.cloud_type].encrypt_key, body)) {
		LogError("aes256_crypt error");
		ret = -1;
	}

out:
	if (str_payload) {
		free(str_payload);
		str_payload = NULL;
	}
	if (payload != NULL) {
		cJSON_Delete(payload);
	}

	return ret;
}


static void add_sign(char *sign_key, int sys_time, int nonce, char *body, char *devid, char *hex_sign)
{
	unsigned char raw_sign[HMAC_MAX_MD_CBLOCK] = { 0 };

	crypt_sign(body, devid, sys_time, header_info.model, nonce, sign_key, raw_sign);
	_hex2string_((unsigned char *)raw_sign, 32, hex_sign);  //签名转16进制表示
}

static int _http_get_devid_secret(void)
{
	struct curl_slist *header = NULL;
	char body[SEND_BUFF_LEN] = { 0 };
	int sys_time; //获取系统时间
	int nonce;
	char hex_sign[HMAC_MAX_MD_CBLOCK] = { 0 };
	CURL *curl = NULL;
	int ret = 0;

	/* 构建http header */
	_build_http_base_header(&header, &nonce, &sys_time, true);

	/* 构建http的body */
	if (_build_devinfo_body(body)) {
		LogError("build http body failed");
		ret = -1;
		goto out;
	}

	//LogInfo("body:%zu\n%s\n", strlen(body), body);
	//生成签名
	add_sign(devinfo_keys[header_info.cloud_type].sign_key, sys_time, nonce, body, NULL, hex_sign);
	ADD_HEADER_FIELD_STRING(header, "X-Sign", hex_sign);
	LogInfo("sign:\n%s\n", hex_sign);

	//设置curl选项
	curl = curl_easy_init();
	if (!curl) {
		LogError("curl_easy_init error");
		ret = -1;
		goto out;
	}

	_set_curl_params(&curl, devinfo_cloud_urls[header_info.cloud_type], header, body, true);

	//curl发起http请求
	ret = curl_easy_perform(curl);
	if (ret) {
		LogError("curl error %d-%s", ret, curl_easy_strerror(ret));
		if (ret == CURLE_COULDNT_RESOLVE_HOST) {
			res_init();
		}
	} else {
		//LogInfo("rsp data:%zu \n%s\n", http_resp_data.size, http_resp_data.data);
	}

out:
	destroy_curl_resource(header, curl);

	return ret;
}

static int http_get_devid_secret(struct mqtt_info *dev_info)
{
	int ret = 0;
	char de_body[RECV_BUFF_LEN] = { 0 }; //存储解密后的数据
	cJSON *root = NULL;
	cJSON *CJSON_data = NULL;
	cJSON *CJSON_device_id = NULL;
	cJSON *CJSON_device_secret = NULL;

	if (_http_get_devid_secret() != 0) {
		LogError("obtain device id and secret failed");
		return -1;
	}

	if (http_resp_header.size <= 0 || http_resp_data.size <= 0) {
		LogError("http rsp invalid");
		ret = -1;
		goto out;
	}

	if (http_resp_header.size > RECV_BUFF_LEN - 1 || http_resp_data.size > RECV_BUFF_LEN - 1) {
		LogError("rsp len too long, hdr:%zu, data:%zu", http_resp_header.size, http_resp_data.size);
		ret = -1;
		goto out;
	}

	LogInfo("devid secret resp hdr:\n%s\n", http_resp_header.data);
	//LogInfo("devid secret resp data:\n%s\n", http_resp_data.data);

	//解析响应结果
	if (body_encrypt()) {
		crypt_aes256_decrypt(http_resp_data.data, devinfo_keys[header_info.cloud_type].decrypt_key, de_body);
	} else {
		snprintf(de_body, RECV_BUFF_LEN, "%s", http_resp_data.data);
	}

	LogInfo("decrypted deviceid and secret resp:\n%s\n", de_body);

	root  = cJSON_Parse(de_body);
	if (root == NULL || root->type != cJSON_Object) {
		LogError("de_body cJSON_Parse error");
		ret = -1;
		goto out;
	}
	CJSON_data = cJSON_GetObjectItem(root, "data");
	if (CJSON_data == NULL || CJSON_data->type != cJSON_Object) {
		LogError("CJSON_data error");
		ret = 1;
		goto out;
	}
	CJSON_device_id = cJSON_GetObjectItem(CJSON_data, "device_id");
	if (CJSON_device_id == NULL || CJSON_device_id->type != cJSON_String) {
		LogError("CJSON_device_id error");
		ret = -1;
		goto out;
	}

	if (strlen(CJSON_device_id->valuestring) > DEV_ID_LEN - 1) {
		LogError("device id len to long, %zu, should be %d", strlen(CJSON_device_id->valuestring), DEV_ID_LEN);
		ret = -1;
		goto out;
	}

	snprintf(dev_info->device_id, sizeof(dev_info->device_id), "%s", CJSON_device_id->valuestring);
	snprintf(header_info.devid, sizeof(header_info.devid), "%s", CJSON_device_id->valuestring);

	CJSON_device_secret = cJSON_GetObjectItem(CJSON_data, "device_secret");
	if (CJSON_device_secret == NULL || CJSON_device_secret->type != cJSON_String) {
		LogError("CJSON_device_secret error");
		ret = -1;
		goto out;
	}

	if (strlen(CJSON_device_secret->valuestring) > DEV_SECRET_LEN - 1) {
		LogError("device id len to long, %zu, should be %d", strlen(CJSON_device_secret->valuestring), DEV_SECRET_LEN);
		ret = -1;
		goto out;
	}

	snprintf(dev_info->device_secret, sizeof(dev_info->device_secret), "%s", CJSON_device_secret->valuestring);

	LogInfo("deviceId = %s", dev_info->device_id);
	LogInfo("device_secret = %s", dev_info->device_secret);

out:
	if (root != NULL) {
		cJSON_Delete(root);
	}

	reset_resp_cache();

	return ret;
}

static int _http_get_mqtt_cfg(struct mqtt_info *dev_info)
{
	struct curl_slist *header = NULL;
	char body[SEND_BUFF_LEN] = { 0 };
	int sys_time; //获取系统时间
	int nonce;
	char hex_sign[HMAC_MAX_MD_CBLOCK] = { 0 };
	CURL *curl = NULL;
	cJSON  *payload = NULL;
	char *str_payload = NULL;
	int ret = 0;

	crypt_gen_triple_key_from_devinfo(dev_info->device_id, dev_info->device_secret, &triple_key);

	LogInfo("device id:%s\n", dev_info->device_id);

	/* 构建http header */
	_build_http_base_header(&header, &nonce, &sys_time, false);
	ADD_HEADER_FIELD_STRING(header, "X-DeviceId", dev_info->device_id);
	ADD_HEADER_FIELD_STRING(header, "X-Language", "zh-CN");
	ADD_HEADER_FIELD_STRING(header, "X-Timezone", "GMT+08:00");

	/* 构建http的body */
	payload = cJSON_CreateObject();
	if (NULL == payload) {
		LogError("cJSON_CreateObject error");
		ret = -1;
		goto out;
	}

	ADD_BODY_FIELD_STRING(payload, "base_os", "SUNMI");
	ADD_BODY_FIELD_STRING(payload, "os_name", "linux");
	ADD_BODY_FIELD_NUMBER(payload, "category", DEV_CAT_IOT);
	str_payload = cJSON_Print(payload); //需要释放内存
	if (strlen(str_payload) > SEND_BUFF_LEN) {
		LogError("req data to long, %zu", strlen(str_payload));
		ret = -1;
		goto out;
	}
	LogInfo("mqtt req:\n%s\n", str_payload);

	if (!crypt_aes256_encrypt(str_payload, triple_key.encrypt_key, body)) { //获取打印机信息设置封装成body
		LogError("aes256_crypt error");
		ret = -1;
		goto out;
	}

	//LogInfo("encrypted payload: %zu\n%s\n", strlen(body), body);

	//生成签名
	add_sign(triple_key.sign_key, sys_time, nonce, body, dev_info->device_id, hex_sign);
	ADD_HEADER_FIELD_STRING(header, "X-Sign", hex_sign);

	//设置curl选项
	curl = curl_easy_init();
	if (!curl) {
		LogError("curl_easy_init error");
		ret = -1;
		goto out;
	}

	LogInfo("url: %s", mqtt_cloud_urls[header_info.cloud_type]);
	_set_curl_params(&curl, mqtt_cloud_urls[header_info.cloud_type], header, body, true);

	//curl发起http请求
	ret = curl_easy_perform(curl);
	if (ret) {
		LogError("curl error %d-%s", ret, curl_easy_strerror(ret));
		if (ret == CURLE_COULDNT_RESOLVE_HOST) {
			res_init();
		}
	} else {
		//LogInfo("rsp data:\n%s\n", http_resp_data.data);
	}

out:
	destroy_curl_resource(header, curl);
	if (payload) {
		cJSON_Delete(payload);
	}
	if (str_payload) {
		free(str_payload);
		str_payload = NULL;
	}

	return ret;
}

static int http_get_mqtt_cfg(struct mqtt_info *dev_info)
{
	char de_body[RECV_BUFF_LEN] = { 0 };  //存储解密后的数据
	cJSON *re_root = NULL;
	cJSON *CJSON_data = NULL;
	cJSON *link_config = NULL;
	cJSON *servers = NULL;
	cJSON *cjsonTmp = NULL;
	int ret = 0;

	if (_http_get_mqtt_cfg(dev_info)) {
		LogError("get host and port fail");
		return -1;
	}

	LogInfo("mqtt rsp hdr:\n%s\n", http_resp_header.data);

	if (http_resp_header.size <= 0 || http_resp_data.size <= 0) {
		LogError("http rsp invalid");
		ret = -1;
		goto out;
	}

	if (http_resp_header.size > RECV_BUFF_LEN - 1 || http_resp_data.size > RECV_BUFF_LEN - 1) {
		LogError("rsp len too long, hdr:%zu, data:%zu", http_resp_header.size, http_resp_data.size);
		ret = -1;
		goto out;
	}

	//解析响应结果
	if (body_encrypt()) {
		crypt_aes256_decrypt(http_resp_data.data, triple_key.decrypt_key, de_body);
	} else {
		snprintf(de_body, sizeof(de_body), "%s", http_resp_data.data);
	}

	LogInfo("mqtt rsp data:\n%s\n", de_body);
	re_root  = cJSON_Parse(de_body);
	if (re_root == NULL || re_root->type != cJSON_Object) {
		LogError("de_body cJSON_Parse error");
		ret = -1;
		goto out;
	}
	CJSON_data = cJSON_GetObjectItem(re_root, "data");
	if (CJSON_data == NULL || cJSON_Object != CJSON_data->type) {
		LogError("CJSON_data error");
		ret = -1;
		goto out;
	}
	link_config = cJSON_GetObjectItem(CJSON_data, "link_config");
	if (!link_config || (cJSON_Object != link_config->type)) {
		LogError("link_config is error  %d %d", link_config->type, cJSON_Object);
		ret = -1;
		goto out;
	}
	servers = cJSON_GetObjectItem(link_config, "servers");
	if (servers == NULL || servers->type != cJSON_Array) {
		LogError("servers is error");
		ret = -1;
		goto out;
	}
	cjsonTmp = cJSON_GetArrayItem(servers, 0);
	if (cjsonTmp == NULL || cjsonTmp->type != cJSON_Object) {
		LogError("cjsonTmp is error");
		ret = -1;
		goto out;
	}

	if (strlen(cJSON_GetValueString(cjsonTmp, "host", "")) > HOST_NAME_LEN - 1) {
		LogError("host name len to long, %zu, should be %d",
				 strlen(cJSON_GetValueString(cjsonTmp, "host", "")), HOST_NAME_LEN);
		ret = -1;
		goto out;
	}

	snprintf(dev_info->host, sizeof(dev_info->host), "%s", cJSON_GetValueString(cjsonTmp, "host", ""));
	LogInfo("host = %s", dev_info->host);

	dev_info->port = cJSON_GetValueInt(cjsonTmp, "port", 0);
	LogInfo("port = %d", dev_info->port);

out:
	if (re_root != NULL) {
		cJSON_Delete(re_root);
	}

	reset_resp_cache();

	return ret;
}

int http_get_mqtt_info(struct mqtt_info *dev_info)
{

	if (http_get_devid_secret(dev_info)) {
		LogError("get device id and secret fail");
		return -1;
	}

	if (http_get_mqtt_cfg(dev_info)) {
		LogError("get host and port fail");
		return -1;
	}

	return 0;
}

static int _http_req_ota_info(const char *version)
{
	struct curl_slist *header = NULL;
	char body[SEND_BUFF_LEN] = { 0 };
	int sys_time; //获取系统时间
	int nonce;
	char hex_sign[HMAC_MAX_MD_CBLOCK] = { 0 };
	CURL *curl = NULL;
	cJSON  *payload = NULL;
	char *str_payload = NULL;
	int ret = 0;

	/* 构建http header */
	_build_http_base_header(&header, &nonce, &sys_time, false);
	ADD_HEADER_FIELD_STRING(header, "X-DeviceId", header_info.devid);

	// 以下三个字段是跟云端约定好的默认值
	ADD_HEADER_FIELD_STRING(header, "X-Language", "zh-CN");
	ADD_HEADER_FIELD_STRING(header, "X-Timezone", "Asia/Shanghai");
	ADD_HEADER_FIELD_STRING(header, "X-Region", "CN");

	LogInfo("X-DeviceId: %s", header_info.devid);
	LogInfo("X-Language: %s", "zh-CN");
	LogInfo("X-Timezone: %s", "Asia/Shanghai");
	LogInfo("X-Region: %s", "CN");


	/* 构建http的body */
	payload = cJSON_CreateObject();
	if (NULL == payload) {
		LogError("cJSON_CreateObject error");
		ret = -1;
		goto out;
	}
	ADD_BODY_FIELD_STRING(payload, "msn", header_info.sn);
	ADD_BODY_FIELD_STRING(payload, "model", header_info.model);
	ADD_BODY_FIELD_STRING(payload, "ver_fw", version);
	str_payload = cJSON_Print(payload); //需要释放内存
	if (strlen(str_payload) > SEND_BUFF_LEN) {
		LogError("req data to long, %zu", strlen(str_payload));
		ret = -1;
		goto out;
	}
	LogInfo("payload:\n%s\n", str_payload);

	if (!crypt_aes256_encrypt(str_payload, triple_key.encrypt_key, body)) { //获取打印机信息设置封装成body
		LogError("aes256_crypt error");
		ret = -1;
		goto out;
	}

	//LogInfo("encrypt_key: %s\n", triple_key.encrypt_key);
	//LogInfo("encrypted payload:%zu\n%s\n", strlen(body), body);

	//生成签名
	add_sign(triple_key.sign_key, sys_time, nonce, body, header_info.devid, hex_sign);
	ADD_HEADER_FIELD_STRING(header, "X-Sign", hex_sign);

	LogInfo("sign: %s", hex_sign);

	//设置curl选项
	curl = curl_easy_init();
	if (!curl) {
		LogError("curl_easy_init error");
		ret = -1;
		goto out;
	}

	_set_curl_params(&curl, ota_cloud_urls[header_info.cloud_type], header, body, true);

	//curl发起http请求
	ret = curl_easy_perform(curl);
	if (ret) {
		LogError("curl error: %d-%s", ret, curl_easy_strerror(ret));
		if (ret == CURLE_COULDNT_RESOLVE_HOST) {
			res_init();
		}
	} else {
		//LogInfo("rsp data:\n%s\n", http_resp_data.data);
	}

out:
	destroy_curl_resource(header, curl);
	if (payload) {
		cJSON_Delete(payload);
	}
	if (str_payload) {
		free(str_payload);
	}

	return ret;
}


char* http_req_upgrade_info(const char *version)
{
	char *de_body = NULL; //存储解密后的数据
	char need_free = 0;

	if (_http_req_ota_info(version)) {
		LogError("_http_req_ota_info return failed");
		goto out;
	}

	de_body = malloc(RECV_BUFF_LEN);
	if (NULL == de_body) {
		LogError("malloc failed");
		goto out;
	}
	memset(de_body, 0, RECV_BUFF_LEN);

	if (http_resp_header.size <= 0 || http_resp_data.size <= 0) {
		LogError("http rsp invalid");
		need_free = 1;
		goto out;
	}

	if (http_resp_header.size > RECV_BUFF_LEN - 1 || http_resp_data.size > RECV_BUFF_LEN - 1) {
		LogError("rsp len too long, hdr:%zu, data:%zu", http_resp_header.size, http_resp_data.size);
		need_free = 1;
		goto out;
	}

	LogInfo("rsp header:\n%s\n", http_resp_header.data);

	//解析响应结果
	if (body_encrypt()) {
		LogInfo("data encrypted, need decrypted");
		if (crypt_aes256_decrypt(http_resp_data.data, triple_key.decrypt_key, de_body) == false) {
			need_free = 1;
			goto out;
		}
	} else {
		snprintf(de_body, RECV_BUFF_LEN, "%s", http_resp_data.data);
	}
	LogInfo("decrypted rsp data:\n%s\n", de_body);

out:
	if (de_body && need_free) {
		free(de_body);
		de_body = NULL;
	}
	reset_resp_cache();

	return de_body;
}

static size_t _fwrite_callback(char *buff, size_t size, size_t nmemb, FILE *fp)
{
	return fwrite(buff, size, nmemb, fp);
}

int http_download_file(char *name, const char *url, uint32_t file_size)
{
	int ret = 0;
	uint32_t current_size = 0;
	struct curl_slist *headers = NULL;
	CURL *curl = NULL;
	FILE *fp = NULL;
	char curl_option[32] = { };

	fp = fopen(name, "a");
	if (!fp) {
		LogError("fopen %s file fail", name);
		ret = -1;
		goto out;
	} else {
		current_size = ftell(fp);
		LogInfo("current_size[%d]--->task_size[%d]", current_size, file_size);
	}

	/* 构建http头 */
	headers = curl_slist_append(headers, "Content-Type: application/binary");
	headers = curl_slist_append(headers, "Expect:");

	curl = curl_easy_init();
	if (NULL == curl) {
		ret = -1;
		LogError("curl_easy_init fail");
		goto out;
	}
	/* set curl option */
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 1000 * 50L);
	curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME,  120L);
	curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, 20L);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT,         0L);
	snprintf(curl_option, sizeof(curl_option), "%d-", current_size);
	curl_easy_setopt(curl, CURLOPT_RANGE,             curl_option);
	curl_easy_setopt(curl, CURLOPT_BUFFERSIZE,        1024 * 10);
	curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE,  (curl_off_t)(file_size));
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,     _fwrite_callback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA,         fp);
	curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION,  download_progress_callback);
	curl_easy_setopt(curl, CURLOPT_NOPROGRESS,        0L);
	curl_easy_setopt(curl, CURLOPT_VERBOSE,           1L);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL,          1L);

	ret = curl_easy_perform(curl);

	if (ret != CURLE_OK) {
		LogError("curl error[%d] error string[%s]", ret, curl_easy_strerror(ret));
		if (ret == CURLE_COULDNT_RESOLVE_HOST) {
			res_init();
		}
		ret = -1;
		goto out;
	} else {
		LogInfo("[CURL EASY PERFORM SUCCESS]");
	}

out:
	if (fp) {
		fclose(fp);
	}

	destroy_curl_resource(headers, curl);

	return ret;
}

void http_init(const char *sn, const char *model, const char *product_id, int cloud_type)
{
	snprintf(header_info.sn, sizeof(header_info.sn), "%s", sn);
	snprintf(header_info.model, sizeof(header_info.model), "%s", model);
	snprintf(header_info.product_id, sizeof(header_info.product_id), "%s", product_id);
	header_info.cloud_type = cloud_type;

	curl_global_init(CURL_GLOBAL_ALL);
}

void http_exit(void)
{
	curl_global_cleanup();
}
