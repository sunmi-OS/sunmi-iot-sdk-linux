#include <stdio.h>

#include "device.h"
#include "service_ubus.h"
#include "link/common.h"
#include "service.h"

int main()
{
    service_init();

    /* uloop初始化 */
    uloop_init();

    /* ubus初始化 */
    if (thing_service_ubus_init() < 0) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "thing_service_ubus_init failed.");
        return -1;
    }

    uloop_run();
    uloop_done();

    /* ubus清理 */
    thing_service_ubus_cleanup();

    service_cleanup();
    return 0;
}


