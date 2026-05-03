/**
 * @file log.h
 * @brief Thread-safe logging utilities for Portillia.
 */

#ifndef PORTILLIA_UTILS_LOG_H
#define PORTILLIA_UTILS_LOG_H

#include <stdio.h>

/**
 * @brief Log levels.
 */
typedef enum {
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARN,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_DEBUG
} portillia_log_level;

/**
 * @brief Logs a message with a specific level.
 */
void portillia_log(portillia_log_level level, const char *fmt, ...);

#define LOG_INFO(...) portillia_log(LOG_LEVEL_INFO, __VA_ARGS__)
#define LOG_WARN(...) portillia_log(LOG_LEVEL_WARN, __VA_ARGS__)
#define LOG_ERROR(...) portillia_log(LOG_LEVEL_ERROR, __VA_ARGS__)
#define LOG_DEBUG(...) portillia_log(LOG_LEVEL_DEBUG, __VA_ARGS__)

#endif // PORTILLIA_UTILS_LOG_H