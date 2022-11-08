#ifndef _THING_ADAPTER_UBUS_H_
#define _THING_ADAPTER_UBUS_H_

#include "link/common.h"

int thing_adapter_ubus_init(char* service_id);
int thing_adapter_ubus_cleanup();

#endif
