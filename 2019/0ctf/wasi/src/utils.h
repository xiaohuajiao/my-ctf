#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <stdint.h>

#define LOG_DEBUG 0

#define LOG(fmt, ...) do { \
    if (LOG_DEBUG) fprintf(stderr, fmt, ##__VA_ARGS__); \
} while (0)

uint32_t read_n_until(char *buf, uint32_t n, char end);
int read_int();

#endif
