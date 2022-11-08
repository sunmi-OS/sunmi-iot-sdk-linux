#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <time.h>

#include "log.h"

static int _print_level = PRINT_LEVEL_WARN;

/* log打印接口，当设置的打印级别大于等于当前log的级别时会打印出来 */
void sunmi_log(int level, const char *fmt, ...)
{
    va_list args;
    FILE* fp = NULL;
    char buf[1024];

    if (_print_level < level)
    {
        return;
    }

    va_start(args, fmt);

    vsnprintf(buf, sizeof(buf), fmt, args);

    fp = fopen("/dev/console", "w");
    if (fp)
    {
        fwrite(buf, strlen(buf), 1, fp);
        fclose(fp);
    }

    va_end(args);
}

/* 设置打印级别 */
void set_print_level(int level)
{
    _print_level = level;
}

