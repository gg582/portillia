#include <portillia/utils/log.h>
#include <stdio.h>
#include <time.h>
#include <stdarg.h>
#include <string.h>

void portillia_log(portillia_log_level level, const char *fmt, ...) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char time_str[20];
    strftime(time_str, sizeof(time_str), "%I:%M%p", tm_info);
    if (time_str[0] == '0') {
        memmove(time_str, time_str + 1, strlen(time_str));
    }

    const char *level_str = "INF";
    switch (level) {
        case LOG_LEVEL_DEBUG: level_str = "DBG"; break;
        case LOG_LEVEL_INFO:  level_str = "INF"; break;
        case LOG_LEVEL_WARN:  level_str = "WRN"; break;
        case LOG_LEVEL_ERROR: level_str = "ERR"; break;
    }

    fprintf(stderr, "%s %s ", time_str, level_str);
    
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    
    fprintf(stderr, "\n");
}
