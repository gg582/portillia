#ifndef PORTILLIA_LOG_H
#define PORTILLIA_LOG_H

#include <stdio.h>

typedef enum {
    PORTILLIA_LOG_DEBUG,
    PORTILLIA_LOG_INFO,
    PORTILLIA_LOG_WARN,
    PORTILLIA_LOG_ERROR
} portillia_log_level;

/**
 * @brief Logs a message to stderr in a format similar to Go's zerolog ConsoleWriter.
 * @param level The log level (DEBUG, INFO, WARN, ERROR).
 * @param fmt The format string.
 * @param ... Additional arguments for the format string.
 */
void portillia_log(portillia_log_level level, const char *fmt, ...);

#define LOG_DEBUG(...) portillia_log(PORTILLIA_LOG_DEBUG, __VA_ARGS__)
#define LOG_INFO(...)  portillia_log(PORTILLIA_LOG_INFO, __VA_ARGS__)
#define LOG_WARN(...)  portillia_log(PORTILLIA_LOG_WARN, __VA_ARGS__)
#define LOG_ERROR(...) portillia_log(PORTILLIA_LOG_ERROR, __VA_ARGS__)

#endif // PORTILLIA_LOG_H
