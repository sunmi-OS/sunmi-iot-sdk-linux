#ifndef _THING_SERVICE_SERVICE_H_
#define _THING_SERVICE_SERVICE_H_

#include "link/common.h"

#define THING_SERVICE_ID_LEN    (64)
#define THING_SERVICE_TYPE_LEN    (64)

typedef struct _SERVICE{
    struct list_head list;             /* 链表头 */
    char service_id[THING_SERVICE_ID_LEN];
    char service_type[THING_SERVICE_TYPE_LEN];
    int alive; /* 是否在线 */
}SERVICE;

int service_init();
int service_cleanup();
int service_register(char* service_id, char* service_type);
int service_get_list(struct blob_buf* bbuf);
void service_check_alive_timer_init();
int service_send_mqtt(char* topic, char* payload);
#endif
