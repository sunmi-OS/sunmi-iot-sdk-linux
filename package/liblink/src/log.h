#ifndef _LINK_LOG_H_
#define _LINK_LOG_H_

#include <sys/types.h>
#include <time.h>


typedef enum _LOG_PRINT_LEVEL{
	PRINT_LEVEL_DISABLE = 0,
	PRINT_LEVEL_ERROR,                      //必须上传的严重错误log
	PRINT_LEVEL_INFO,                       //不是错误但有必要上传的log
	PRINT_LEVEL_WARN,                       //警告和不必上传的错误log
	PRINT_LEVEL_DEBUG,                      //调试用log
	PRINT_LEVEL_DETAIL,                     //会刷屏的详细log
	PRINT_LEVEL_MAX
}LOG_PRINT_LEVEL;

/* 日志打印接口 */
#define SUNMI_LOG(level, fmt, arg...)  \
	do { \
		const char *log_level_flag[PRINT_LEVEL_MAX] = {"", "error", "info", "warn", "debug", "detail"}; \
		sunmi_log(level, "[%s] [%s] " fmt "\n", log_level_flag[level], __FUNCTION__, ##arg); \
	}while(0)

void sunmi_log(int level, const char *fmt, ...);
void set_print_level(int level);
#endif
