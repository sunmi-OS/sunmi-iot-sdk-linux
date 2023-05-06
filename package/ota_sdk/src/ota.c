#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include "internal.h"

static int _validate_params(struct user_config_info *info)
{
	if (NULL == info) {
		LogError("parameter can't be NULL ");
		return -1;
	}

	if (strlen(info->download_path) <= 0 || strlen(info->download_path) > PATH_LEN - 1) {
		LogError("download path len invalid %zu", strlen(info->download_path));
		return -1;
	}

	if (info->download_path[0] != '/') {
		LogError("upgrade file path must be absolute path ");
		return -1;
	}

	if (strlen(info->product_id) <= 0 || strlen(info->product_id) > PRODUCT_ID_LEN - 1) {
		LogError("product ID invalid %zu", strlen(info->product_id));
		return -1;
	}

	//用户没有配置，默认为ONLINE环境
	if (info->cloud_type == CLOUD_TYPE_NONE) {
		info->cloud_type = CLOUD_TYPE_ONLINE;
	}

	if (info->cloud_type < CLOUD_TYPE_DEV || info->cloud_type > CLOUD_TYPE_ONLINE) {
		LogError("cloud_type[1-4] is invalid %d ", info->cloud_type);
		return -1;
	}

	if (strlen(info->sn) <= 0 || strlen(info->sn) > SN_LEN - 1) {
		LogError("product sn len is invalid %zu", strlen(info->sn));
		return -1;
	}

	if (strlen(info->model) <= 0 || strlen(info->model) > MODEL_LEN - 1) {
		LogError("product model len is invalid %zu", strlen(info->model));
		return -1;
	}

	if (info->has_mobile) {
		if (NULL == info->current_route_is_mobile) {
			LogError("current_route_is_mobile can't be empty ");
			return -1;
		}
	}

	if (!(info->type_flag & UP_FILE_TYPE_FIRMWARE_MASK)) {
		info->type_flag = UP_FILE_TYPE_FIRMWARE_BIT;
	}

	//固件升级包
	if (info->type_flag & UP_FILE_TYPE_FIRMWARE_BIT) {
		if (NULL == info->ops[0].install) {
			LogError("firmware install callback can't be NULL ");
			return -1;
		}

		if (NULL == info->ops[0].get_current_version) {
			LogError("firmware version_compare callback can't be NULL ");
			return -1;
		}

		if (info->ops[0].confirm_download) {
			if (NULL == info->ops[0].wait_confirm_download) {
				LogError("firmware confirm_upgrade callback can't be NULL ");
				return -1;
			}
		}

		if (info->ops[0].confirm_install) {
			if (NULL == info->ops[0].wait_confirm_install) {
				LogError("firmware confirm_upgrade callback can't be NULL ");
				return -1;
			}
		}
	}

	//应用升级包
	if (info->type_flag & UP_FILE_TYPE_APPLICATION_BIT) {
		if (NULL == info->ops[1].install) {
			LogError("application install callback can't be NULL ");
			return -1;
		}

		if (NULL == info->ops[1].get_current_version) {
			LogError("application version_compare callback can't be NULL ");
			return -1;
		}

		if (info->ops[1].confirm_download) {
			if (NULL == info->ops[1].wait_confirm_download) {
				LogError("application confirm_upgrade callback can't be NULL ");
				return -1;
			}
		}

		if (info->ops[1].confirm_install) {
			if (NULL == info->ops[1].wait_confirm_install) {
				LogError("firmware confirm_upgrade callback can't be NULL ");
				return -1;
			}
		}
	}

	//资源升级包
	if (info->type_flag & UP_FILE_TYPE_RESOURCE_BIT) {
		if (NULL == info->ops[2].install) {
			LogError("resource install callback can't be NULL ");
			return -1;
		}

		if (NULL == info->ops[2].get_current_version) {
			LogError("resource version_compare callback can't be NULL ");
			return -1;
		}

		if (info->ops[2].confirm_download) {
			if (NULL == info->ops[2].wait_confirm_download) {
				LogError("resource confirm_upgrade callback can't be NULL ");
				return -1;
			}
		}

		if (info->ops[2].confirm_install) {
			if (NULL == info->ops[2].wait_confirm_install) {
				LogError("firmware confirm_upgrade callback can't be NULL ");
				return -1;
			}
		}
	}

	return 0;
}

int ota_init(struct user_config_info *info)
{
	static struct mqtt_info  mqtt_cfg = { };//别的线程需要访问，所以定义为静态变量
	pthread_t tid;

	if (-1 == _validate_params(info)) {
		LogError("input params invalid ");
		return -1;
	}

	http_init(info->sn, info->model, info->product_id, info->cloud_type);

	if (download_init_cfg(info) == -1) {
		return -1;
	}

	while (http_get_mqtt_info(&mqtt_cfg)) {
		LogError("obtaining device id , secret and mqtt host port, please waiting ");
		sleep(3);
	}

	mqtt_info_init(info, mqtt_cfg.device_id);

	if (pthread_create(&tid, NULL, ota_ubus_init, (void *)&mqtt_cfg)) {
		return -1;
	}

	pthread_detach(tid);

	return 0;
}

int ota_exit(void)
{
	http_exit();
	return ota_ubus_cleanup();
}

int ota_check_version(int type, char *new_version, int ver_len, char *log, int log_len)
{
	return download_ota_check_version(type, new_version, ver_len, log, log_len);
}

int ota_start_download(int type)
{
	if (type < UP_FILE_TYPE_FIRMWARE || type > UP_FILE_TYPE_RESOURCE) {
		LogError("type is invalid: %d", type);
		return -1;
	}

	return download_pull_upgrade_info(type, true, true, false, true);
}

int ota_start_install(int type)
{
	return download_install_task(type);
}
