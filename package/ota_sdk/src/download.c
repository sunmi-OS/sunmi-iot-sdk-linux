#include "internal.h"
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <sys/vfs.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <curl/curl.h>
#include <cjson/cJSON.h>
#include <link/common.h>
#include <pthread.h>

struct download_task_item {
	int  size;         // 文件大小:byte
	char md5[MD5_LEN];              // 文件md5值
	char url[URL_LEN];             // 下载文件服务器地址
	int  type;                 // 升级文件类型：1-固件，2-应用，3-资源包
	char ver_fw[VER_LEN];              // 目标文件版本号
	char update_description[LOG_LEN];
	int  upgrade_strategy;      //升级策略, 1-强制升级，2-普通升级
#define		FORCE_INSTALL 1
#define		NORMAL_INSTALL 2
	int update_verify; // 强制升级，忽略下载和安装策略，经过用户确认过的升级
	bool update_flag; // true:有更新包，false：无更新包
	int net_type;              // 升级允许网络类型:1-表示所有网络 2-表示非移动数据
#define DLD_NET_TYPE_ALL		1
#define DLD_NET_TYPE_NONMOBILE	2
	int update_start_time;      //整点时间（0-23）
	int update_end_time;    //整点时间（0-23）
};

struct version_info {
	char model[MODEL_LEN*10];
	char version[VER_LEN];
	char type[32];
	char vender[32];
};

static int download_validate_file(char *file, unsigned int size, char *md5);

static struct download_task_item download_task;

//保持状态给外部查询，最后由外部复位
static bool keep_state = false;

static struct device_cfg current_dev_info;

static inline void _clear_download_task(void)
{
	LogInfo("=======clear state=========");
	if (!access(current_dev_info.orig_zipfile, F_OK)) {
		unlink(current_dev_info.orig_zipfile);
	}

	if (!keep_state) {
		current_dev_info.state = OTA_STATE_IDLE;
		current_dev_info.mode = UP_METHOD_NONE; //默认处于OTA升级模式
	}

	memset(&download_task, 0, sizeof(download_task));
}

static inline bool net_match(char net_type)
{
	if (net_type == DLD_NET_TYPE_NONMOBILE && current_dev_info.user_cfg.has_mobile) {
		return  !current_dev_info.user_cfg.current_route_is_mobile();
	}

	return true;
}

static inline int in_valid_time(int start_time, int end_time)
{
	time_t current_time = time(NULL);

	struct tm *local_time = localtime(&current_time);

	if (NULL == local_time) {
		return -1;
	}

	LogInfo("force upgrade time duration: %d-%d", start_time, end_time);
	if (start_time < end_time) {
		end_time += 24;
	}

	LogInfo("current time (hour): %d", local_time->tm_hour);

	if (local_time->tm_hour >= start_time && local_time->tm_hour <= end_time) {
		return 0;
	}

	if (start_time < local_time->tm_hour) {
		start_time += 24;
	}

	return (start_time - local_time->tm_hour) * 60 * 60;
}

static inline bool has_new_ver(char type, char *new_ver)
{
	int main_ver, sub_ver, last_ver;
	int dev_main_ver, dev_sub_ver, dev_last_ver;
	char dev_cur_ver[VER_LEN] = { };

	if (!current_dev_info.user_cfg.ops[(int)type].get_current_version) {
		return false;
	}

	current_dev_info.user_cfg.ops[(int)type].get_current_version(dev_cur_ver, VER_LEN);
	sscanf(dev_cur_ver, "%d.%d.%d", &dev_main_ver, &dev_sub_ver, &dev_last_ver);
	dev_main_ver = (dev_main_ver << 20) + (dev_sub_ver << 10) + dev_last_ver;
	LogInfo("current version: %s, %x", dev_cur_ver, dev_main_ver);

	sscanf(new_ver, "%d.%d.%d", &main_ver, &sub_ver, &last_ver);
	main_ver = (main_ver << 20) + (sub_ver << 10) + last_ver;
	LogInfo("new version: %s, %x", new_ver, main_ver);

	return main_ver > dev_main_ver;
}

static unsigned int util_sys_tick(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC_RAW, &ts);

	return (unsigned int)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

int download_install_task(int type)
{
	int ret = 0;
	char *result = NULL;
	char version[VER_LEN] = {};

	struct download_task_item *item = &download_task;

	//对于定时任务到期后触发的安装，传递的type值约定为-1，表示取上一次下载的type
	if (type == -1) {
		type = item->type;
	}

	if (type != item->type) {
		LogError("type unmatch, target type: %d, current type:%d", item->type, type);
		ret = -1;
		goto out;
	}

	if (current_dev_info.state != OTA_STATE_CHECK_OK) {
		LogError("state unmatch, current state:%d, should be 8", current_dev_info.state);
		ret = -1;
		goto out;
	}

	LogInfo("installing upgrade file");
	current_dev_info.state = OTA_STATE_INSTALLING;
	mqtt_report_status(OTA_STATE_INSTALLING, NULL);

	//因为有可能直接调用安装接口，所以需要进一步校验
	if (download_validate_file(current_dev_info.orig_zipfile, item->size, item->md5)) {
		LogError("invalid image");
		ret = -1;
		goto out;
	}

	if (current_dev_info.user_cfg.ops[item->type].install &&
		current_dev_info.user_cfg.ops[item->type].install(current_dev_info.orig_zipfile)) {
		current_dev_info.state = OTA_STATE_INSTALL_FAIL;
		mqtt_report_status(OTA_STATE_INSTALL_FAIL, "install failed");
		LogError("install failed");
		ret = -1;
		goto out;
	}

	LogInfo("installing upgrade file ok");
	//如果需要强制重启，则用户在post_install里面实现，此处代码执行不到，重启后设备才上报
	current_dev_info.state = OTA_STATE_INSTALL_OK;
	mqtt_report_status(OTA_STATE_INSTALL_OK, NULL);

	// 上报版本信息, 即使需要重启，多一次上报也不影响
	if (current_dev_info.user_cfg.ops[type].get_current_version) {
		current_dev_info.user_cfg.ops[type].get_current_version(version, VER_LEN);
	}
	result = http_req_upgrade_info(version);
	if (result) {
		free(result);
		result = NULL;
	}

out:
	if (ret) {
		LogInfo("install failed");
	} else {
		LogInfo("install ok");
	}
	_clear_download_task();
	return ret;
}

static int _check_fs_freesize(int input_size, const char *fs_disk_path, void *output_size)
{
	int ret = -1;
	struct statfs data_fs_stat;
	unsigned long free_flash_size;

	if ((ret = statfs(fs_disk_path, &data_fs_stat))) {
		LogError("get data partition accur error %s", strerror(errno));
		return -1;
	}

	free_flash_size = data_fs_stat.f_bfree * data_fs_stat.f_bsize;
	if (input_size > free_flash_size) {
		if (output_size) {
			*(unsigned long *)output_size = free_flash_size;
		}
		return -2;
	}

	return 0;
}

static int download_validate_file(char *file, unsigned int size, char *md5)
{
	struct stat st = { };
	char md5txt[33] = { };
	int ret = 0;

	current_dev_info.state = OTA_STATE_CHECKING;

	if (file == NULL) {
		LogError("file no exist");
		ret = -1;
		goto out;
	}

	//检查文件的访问权限
	if (access(file, F_OK | R_OK) != 0) {
		LogError("no access for %s or no exist", file);
		ret = -1;
		goto out;
	}

	//检查文件的大小
	if (stat(file, &st) != 0 || st.st_size != size) {
		LogError("%s size unmatch, %d-->%ld", file, size, st.st_size);
		ret = -1;
		goto out;
	}

	//检查文件的md5
	if (crypt_md5_file(file, md5txt) < 0 || strcmp(md5txt, md5)) {
		LogError("md5 check failed\n");
		ret = -1;
		goto out;
	}

out:
	if (ret) {
		LogInfo("check failed");
		_clear_download_task();
	}
	return ret;
}

int download_progress_callback(void *p, curl_off_t download_total, curl_off_t download_now,
							   curl_off_t ul_total, curl_off_t ul_now)
{
	static uint32_t timenow = 0;
	static uint8_t unique_task_reach_full = 0;

	//下载过程中，如果空间不够，则退出下载
	if (0 != _check_fs_freesize(download_now, current_dev_info.user_cfg.download_path, NULL)) {
		LogError("no space during downloading");
		return 1;
	}

	if (download_total != download_now) {
		unique_task_reach_full = 0;
	}

	if (unique_task_reach_full == 0 && download_total != 0 &&
		download_now != 0 && (download_total == download_now)) {
		LogInfo("Downloading from rest total %-10lldbytes to %-10lldbytes"
				"===================>>progress[100%%]", (long long)download_total, (long long)download_now);
		unique_task_reach_full = 1;
		return 0;
	}

	if (util_sys_tick() - timenow > 7 * 1000 && download_total) { /* show progress every 7 seconds */
		timenow = util_sys_tick();
		LogInfo("Downloading from rest total %-10lldbytes to %-10lldbytes"
				"===================>>progress[%.0f%%]",
				(long long)download_total, (long long)download_now, (((double)download_now / (double)download_total) * 100));
	}

	return 0;
}

static int decide_install(struct download_task_item *item)
{
	//商米助手等经过用户确认的推送，不需要考虑策略，直接安装
	if (item->update_verify) {
		LogInfo("verify upgrade, start install");
		return download_install_task(item->type);
	}

	//对于普通升级，需要用户确认才安装， 如果该产品需要确认，则通知用户，否则继续安装
	if (item->upgrade_strategy != FORCE_INSTALL) {
		if (current_dev_info.user_cfg.ops[item->type].confirm_install) {
			current_dev_info.user_cfg.ops[item->type].wait_confirm_install(item->type);
			LogInfo("need user confirm to install");
			return 0;
		}
	}

	//如果是强制安装，且需要在设定的时间段内，则需要判断是否在设定的时间范围内
	if (item->upgrade_strategy == FORCE_INSTALL && current_dev_info.user_cfg.ops[item->type].use_force_upgrade_duration) {
		int interval = in_valid_time(item->update_start_time, item->update_end_time);
		if (interval < 0) {
			LogError("localtime get time failed");
			return -1;
		}

		if (interval > 0) {
			//设置定时器，等待触发
			LogInfo("timer to upgrade, waiting");
			ota_ubus_set_install_timer(interval);
			return 0;
		}
	}

	return download_install_task(item->type);
}

static int _download_task(struct download_task_item *item)
{
	uint32_t timenow    = 0;   //下载失败时间戳
	uint8_t fail_times = 0;
	int ret = 0;
	char url[URL_LEN] = { };
	int size = item->size;
	char md5[MD5_LEN] = {};

	snprintf(url, sizeof(url), "%s", item->url);
	snprintf(md5, sizeof(md5), "%s", item->md5);

	//下载正式开始之前，检查空间大小是否够用
	if (0 != _check_fs_freesize(item->size, current_dev_info.user_cfg.download_path, NULL)) {
		mqtt_report_status(OTA_STATE_DOWNLOAD_FAIL, "there is no space");
		LogError("file system free space is too small");
		ret = -1;
		goto out;
	}

retry:
	/* 如果是之前中断的任务, 60秒后才继续重试 */
	if (current_dev_info.state == OTA_STATE_DOWNLOADING) {
		while (util_sys_tick() - timenow < current_dev_info.fail_retry_interval * 1000) {
			sleep(current_dev_info.fail_retry_interval - (util_sys_tick() - timenow) / 1000);
		}
	}

	/* 如果是新任务, 改变当前任务的状态 */
	if (current_dev_info.state == OTA_STATE_HTTP_REQUEST_OK) {
		current_dev_info.state = OTA_STATE_DOWNLOADING;
		LogInfo("downloading upgrade file");
	}

	ret = http_download_file(current_dev_info.orig_zipfile, url, size);
	LogInfo("File_Downloader url[%s] size[%d] ret[%d]", url, size, ret);

	if (ret == CURLE_OK) {
		LogInfo("download upgrade file ok");
		current_dev_info.state = OTA_STATE_DOWNLOAD_OK;
		mqtt_report_status(OTA_STATE_DOWNLOAD_OK, NULL);
		//下载成功，进行文件校验
		if (download_validate_file(current_dev_info.orig_zipfile, size, md5) == 0) {
			current_dev_info.state = OTA_STATE_CHECK_OK;
			mqtt_report_status(OTA_STATE_CHECK_OK, NULL);
			LogInfo("check upgrade file ok");

			//校验通过，进入安装阶段
			return decide_install(item);
		}
	}

	/* 下载失败或者校验的情况 */
	timenow = util_sys_tick();
	if (++fail_times < current_dev_info.fail_retry_times) {
		LogInfo("download failed, %d times retry", fail_times);
		goto retry;
	} else {
		LogError("try download 3 times, failed");

		if (ret) {
			mqtt_report_status(OTA_STATE_DOWNLOAD_FAIL, "curl request failed");
			current_dev_info.state = OTA_STATE_DOWNLOAD_FAIL;
		} else {
			mqtt_report_status(OTA_STATE_CHECK_FAIL, "checksum failed");
			current_dev_info.state = OTA_STATE_CHECK_FAIL;
		}
	}

out:
	if (ret) {
		LogInfo("download progress failed, reset state");
		_clear_download_task();
	}
	return ret;
}

static int _parse_http_req(char *result)
{
	cJSON *root = NULL;
	cJSON *body = NULL;
	int  net_type;
	int  size;
	int  type;
	int  upgrade_strategy;
	char *md5    = NULL;
	char *ver_fw    = NULL;
	char *url    = NULL;
	bool update_flag;
	char *update_description = NULL;
	int update_verify;
	int update_start_time = 0;
	int update_end_time = 0;
	cJSON *code = 0;

	struct download_task_item *item = &download_task;
	int ret = 0;

	LogInfo("data: \n%s", result);

	body  = cJSON_Parse(result);
	if (body == NULL) {
		LogError("cJSON_Parse error");
		ret = -1;
		goto out;
	}

	//查看响应报文的code和msg
	code  = cJSON_GetObjectItem(body, "code");
	if (code == NULL || code->type != cJSON_Number) {
		LogError("cJSON_Parse error, no valid code field");
		ret = -1;
		goto out;
	}
	LogInfo("rsp code:%d", code->valueint);

	//云端默认 success code都是1
	if (code->valueint != 1) {
		LogError("cJSON_Parse error, no valid code field");
		ret = -1;
		goto out;
	}

	root  = cJSON_GetObjectItem(body, "data");
	if (root == NULL || root->type != cJSON_Object) {
		LogError("cJSON_Parse error");
		ret = -1;
		goto out;
	}

	update_flag = cJSON_GetValueInt(root, "update_flag", 0);
	if (false != update_flag && true != update_flag) {
		LogError("update_flag is invalid");
		ret = -1;
		goto out;
	}
	LogInfo("update_flag:%d", update_flag);
	if (update_flag == 0) {
		ret = 0;
		goto out;
	}

	update_verify = cJSON_GetValueInt(root, "update_verify", 0);
	LogInfo("update_verify:%d", update_verify);

	upgrade_strategy    = cJSON_GetValueInt(root, "upgrade_strategy", 0);
	if (upgrade_strategy != 1 && upgrade_strategy != 2) {
		LogError("upgrade strategy is invalid: %d", upgrade_strategy);
		ret = -1;
		goto out;
	}
	LogInfo("upgrade_strategy:%d", upgrade_strategy);

	//强制升级必须携带时间
	if (upgrade_strategy == FORCE_INSTALL) {
		update_start_time = cJSON_GetValueInt(root, "update_start_time", 0);
		update_end_time = cJSON_GetValueInt(root, "update_end_time", 0);
		LogInfo("update_start_time:%d", update_start_time);
		LogInfo("update_end_time:%d", update_end_time);
	}

	size    = cJSON_GetValueInt(root, "size", 0);
	if (size <= 0) {
		LogError("size is invalid");
		ret = -1;
		goto out;
	}
	LogInfo("size:%d", size);

	md5    = cJSON_GetValueString(root, "md5", NULL);
	if (NULL == md5) {
		LogError("md5 is invalid");
		ret = -1;
		goto out;
	}
	LogInfo("md5:%s", md5);

	url    = cJSON_GetValueString(root, "url", NULL);
	if (NULL == url) {
		LogError("url is invalid");
		ret = -1;
		goto out;
	}
	LogInfo("url:%s", url);

	net_type = cJSON_GetValueInt(root, "net_type",  0);
	if (net_type != DLD_NET_TYPE_ALL && net_type != DLD_NET_TYPE_NONMOBILE) {
		LogError("net_type is invalid");
		ret = -1;
		goto out;
	}
	LogInfo("net_type:%d", net_type);

	type    = cJSON_GetValueInt(root, "type", 0);
	if (type < UP_FILE_TYPE_FIRMWARE || type > UP_FILE_TYPE_RESOURCE) {
		LogError("image type is invalid");
		ret = -1;
		goto out;
	}
	LogInfo("type:%d", type);

	ver_fw    = cJSON_GetValueString(root, "ver_fw", NULL);
	if (NULL == ver_fw) {
		LogError("version is invalid");
		ret = -1;
		goto out;
	}
	LogInfo("ver_fw:%s", ver_fw);

	update_description    = cJSON_GetValueString(root, "update_description", NULL);
	if (NULL == update_description) {
		LogError("log is invalid");
		ret = -1;
		goto out;
	}
	LogInfo("update_description:%s", update_description);

	item->size    = size;
	item->type    = type - 1; //后续用type当做索引定位数组，从0开始
	item->net_type = net_type;
	item->update_flag = update_flag;
	item->update_verify = update_verify;
	item->update_start_time = update_start_time;
	item->update_end_time = update_end_time;
	item->upgrade_strategy = upgrade_strategy;
	snprintf(item->md5, sizeof(item->md5), "%s", md5);
	snprintf(item->ver_fw, sizeof(item->ver_fw), "%s", ver_fw);
	snprintf(item->url, sizeof(item->url), "%s", url);
	snprintf(item->update_description, sizeof(item->update_description), "%s", update_description);

out:
	if (body != NULL) {
		cJSON_Delete(body);
	}

	return ret;
}

/**
 * \fn        download_pull_upgrade_info
 * \brief
 *
 * \param[in] type: 升级包类型
 * \param[in] active: true：主动发起，false：被动发起（推送）
 * \param[in] external: true：SDK外部发起（例如web，或者用户确认后的升级）false：内部发起
 * \param[in] check_version: false：获取升级信息后，继续下载升级文件, true: 只是为了检查版本，所以不需要进行后续的下载
 * active	external	场景
 * 0		0			内部被动，升级信息推送后，发起申请，需要联合update_verify判断，因为有可能是商米助手确认后，需要强制升级
 * 0		1			外部发起都是主动的，没有对应场景
 * 1		0			内部主动，有可能是服务启动时候
 * 1		1			外部主动发起，因为有可能只是检查版本信息，所以需要check_version参数判断是否继续下载
 *
 * \return    int 0: 成功，-1：失败
 */
int download_pull_upgrade_info(int type, bool active, bool external, bool check_version, bool reset)
{
	int request_times = 0;
	char version[VER_LEN] = { };
	int ret = 0;
	char *result = NULL;

	keep_state = !reset;
	if (keep_state) {
		ota_ubus_reset_state_machine_timer(120);
	}

	// 获取设备当前的升级包对应的版本号
	if (current_dev_info.user_cfg.ops[type].get_current_version) {
		current_dev_info.user_cfg.ops[type].get_current_version(version, VER_LEN);
	} else {
		LogError("user no register get current version callback");
		return 0;
	}

	if (current_dev_info.state != OTA_STATE_IDLE) {
		LogError("There is another upgrade progress state:%d", current_dev_info.state);
		ret = -1;
		goto out;
	}

	LogInfo("requesting upgrade info");
	// http请求，并返回等待返回结果
	current_dev_info.state = OTA_STATE_HTTP_REQUESTING;
	do {
		result = http_req_upgrade_info(version);
		if (result) {
			break;
		}
	} while (++request_times < current_dev_info.fail_retry_times);

	//请求没有响应
	if (request_times == current_dev_info.fail_retry_times) {
		current_dev_info.state = OTA_STATE_HTTP_REQUEST_FAIL;
		mqtt_report_status(OTA_STATE_HTTP_REQUEST_FAIL, "http request failed");
		LogError("http request failed");
		ret = -1;
		goto out;
	}

	//解析http响应结果
	ret = _parse_http_req(result);
	if (ret) {
		current_dev_info.state = OTA_STATE_HTTP_REQUEST_FAIL;
		mqtt_report_status(OTA_STATE_HTTP_REQUEST_FAIL, "http response parse failed");
		LogError("parse http data failed");
		//释放存放结果的buffer
		if (result) {
			free(result);
			result = NULL;
		}
		ret = -1;
		goto out;
	} else {
		current_dev_info.state = OTA_STATE_HTTP_REQUEST_OK;
		LogInfo("requesting upgrade info ok");
	}

	//释放存放结果的buffer
	if (result) {
		free(result);
	}

	//如果只是检查版本
	if (active && external && check_version) {
        //需要在拷贝完输出信息后，清除状态
		LogInfo("check version complete");
		return 0;
	}

	/* 如果没有更新的版本，则不需要升级 */
	if (download_task.update_flag == false) {
		LogInfo("no need upgrade, update_flag is false");
		_clear_download_task();
		return 0;
	}

	if (!(current_dev_info.user_cfg.type_flag & (1<<download_task.type))) {
		LogInfo("type unmatch");
		_clear_download_task();
		return 0;
	}

	// 如果有新版本，才进行后续的升级动作
	if (!has_new_ver(type, download_task.ver_fw)) {
		LogInfo("no newer version");
		ret = -1;
		goto out;
	}

	//web或者经过用户确认后触发设备发起的请求
	if (active && external && !check_version) {
		//经过用户确认过的升级，静默下载、安装
		download_task.update_verify = 1;

		LogInfo("active request, not need confirm");
		goto START_DOWNLOAD;
	}

	// 如果是经过商米助手等经过用户确认后的升级，则强行升级
	if (download_task.update_verify) {
		LogInfo("verify upgrade, start downloading");
		goto START_DOWNLOAD;
	}

	//设备启动发起的更新请求，遵循升级策略
	if (active && !external) {
		if (!net_match(download_task.net_type)) {
			current_dev_info.state = OTA_STATE_DOWNLOAD_FAIL;
			mqtt_report_status(OTA_STATE_DOWNLOAD_FAIL, "net forbid");
			LogError("current net is mobile, forbid download");
			ret = -1;
			goto out;
		}

		if (current_dev_info.user_cfg.ops[type].confirm_download) {
			current_dev_info.user_cfg.ops[type].wait_confirm_download(download_task.type);
			ret = -1;
			LogInfo("need user confirm to download");
			goto out;
		}

		goto START_DOWNLOAD;
	}

	if (!external && !active) {
		// 如果是正常推送的升级，则需要遵循所有的升级策略
		if (!net_match(download_task.net_type)) {
			current_dev_info.state = OTA_STATE_DOWNLOAD_FAIL;
			mqtt_report_status(OTA_STATE_DOWNLOAD_FAIL, "net forbid");
			LogError("current net is mobile, forbid download");
			ret = -1;
			goto out;
		}

		if (current_dev_info.user_cfg.ops[type].confirm_download) {
			current_dev_info.user_cfg.ops[type].wait_confirm_download(download_task.type);
			LogInfo("need user confirm to download");
			ret = -1;
			goto out;
		}
	}

START_DOWNLOAD:
	ret = _download_task(&download_task);
	if (ret == 0) {
		LogInfo("download task complete");
		return 0;
	}

out:
	if (ret) {
		LogInfo("request failed, reset state");
		_clear_download_task();
	}
	return ret;
}

int download_ota_check_version(int type, char *new_version, int ver_len, char *log, int log_len)
{
	if (new_version == NULL || ver_len <= 0) {
		LogError("input args invalid");
		return -1;
	}

	if (0 == download_pull_upgrade_info(type, true, true, true, true)) {
		snprintf(new_version, ver_len, "%s", download_task.ver_fw);
		if (log && log_len > 0) {
			snprintf(log, log_len, "%s", download_task.update_description);
		}
		//需要在拷贝完输出信息后，清除状态
		_clear_download_task();
		return 0;
	}

	return -1;
}

int download_get_upgrade_state(char *mode)
{
	if (mode) {
		*mode = current_dev_info.mode;
	}

	return current_dev_info.state;
}

int download_set_upgrade_state(char state, char mode)
{
	current_dev_info.state = state;
	current_dev_info.mode = mode;

	return 0;
}

static void* _process_business_entry(void *args)
{
	int policy = (int)args;

	int type;
	bool active;
	bool external;
	bool check_version;
	bool reset;

	REQ_POLICY_ARGS_DECODE(type, active, external, check_version, reset, policy);
	LogInfo("policy:%x, type:%d, active:%d, external:%d, check_version:%d, reset:%d\n",
			policy, type, active, external, check_version, reset);

	download_pull_upgrade_info(type, active, external, check_version, reset);

	return NULL;
}

void download_process_external_business(void *args)
{
	pthread_t tid;
	int ret;

	ret = pthread_create(&tid, NULL, _process_business_entry, args);
	if (ret) {
		LogError("pthread_create error");
	}
	pthread_detach(tid);
}


int download_init_cfg(struct user_config_info *info)
{
	if (current_dev_info.initialized != 0) {
		return -1;
	}

	snprintf(current_dev_info.orig_zipfile, sizeof(current_dev_info.orig_zipfile), "%s/update.zip", info->download_path);
	memcpy(&current_dev_info.user_cfg, info, sizeof(current_dev_info.user_cfg));
	current_dev_info.fail_retry_times = 3;
	current_dev_info.fail_retry_interval = 60;
	current_dev_info.initialized = 1;

	return 0;
}

