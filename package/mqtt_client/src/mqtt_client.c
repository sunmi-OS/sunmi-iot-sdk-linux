#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "link/common.h"
#include "mqtt_ubus.h"
#include "mqtt.h"

int main(int argc, char *argv[])
{
    mqtt_proc();

    /* ubus初始化 */
    if(mqtt_ubus_init() < 0)
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "mqtt_ubus_init failed.");
        return -1;
    }

    /* uloop初始化 */
    uloop_init();
    uloop_run();
    uloop_done();

    /* ubus清理 */
    mqtt_ubus_cleanup();

	return 0;
}

