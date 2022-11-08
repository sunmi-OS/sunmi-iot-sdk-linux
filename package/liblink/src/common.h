#ifndef _LINK_COMMON_H_
#define _LINK_COMMON_H_

#include "log.h"
#include "ubus.h"
#include "cjson/cJSON.h"

#define cJSON_GetValueInt(it,name,defValue) ({ \
	int v = defValue; \
	cJSON *o = cJSON_GetObjectItem(it,name); \
	if( o ) { \
		if( o->type == cJSON_Number ) v = o->valueint; \
		else if( o->type == cJSON_False )	v = 0; \
		else if( o->type == cJSON_True ) v = 1; \
	} \
	v; \
})
#define cJSON_GetValueString(it,name,def) ({ \
	char *v = NULL; \
	cJSON *o = cJSON_GetObjectItem(it,name); \
	if( o && o->type==cJSON_String ) v=o->valuestring; \
	(v?v:def); \
})

#endif
