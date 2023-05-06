#include <ota.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>

#define INSTALL_FILE	"/tmp/update.bin"

#define LogError(format, args...) printf("[%s-%d] "format"\n", __func__, __LINE__, ##args)
#define LogInfo(format, args...) printf("[%s-%d] "format"\n", __func__, __LINE__, ##args)

static int ap_install(char *file);
static int ap_get_current_version(char *version, int len);

static void ap_wait_confirm_install(int type) {
	LogInfo("recv confirm install notificaion");
	return;
}

static struct user_config_info cfg = {
	.product_id = "demo_id",
	.download_path = "/tmp",
	.sn = "N424229G00448",
	.model = "NT310",
	.has_mobile = 0,
	.type_flag = (1 << 0),
	.cloud_type = 2, // test 环境

	.ops[0] = {
		.confirm_install = 1,
		.install = ap_install,
		.get_current_version = ap_get_current_version,
		.wait_confirm_install = ap_wait_confirm_install,
	},
};

static int ap_install(char *file)
{
	//1. 解析压缩包
	//2. 校验合法性
	//3. 进行安装
	//4. 根据需要释放重启
	LogInfo("======installing complete=======");

	return 0;
}

static int ap_get_current_version(char *version, int len)
{
	snprintf(version, len, "1.0.0");

	return 0;
}

int main(int argc, char **argv)
{
	int ret;

	ret = ota_init(&cfg);
	if (ret) {
		return -1;
	}

	while (1) {
		sleep(1);
	}

	return 0;
}
