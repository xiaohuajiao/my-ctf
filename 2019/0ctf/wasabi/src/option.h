#ifndef OPTION_H
#define OPTION_H

#include <stdint.h>

#define MAX_OPTION_NAME_SIZE  (0x40)
struct Option
{
    uint32_t inused;
    uint32_t rest;
    uint32_t reserved;
    void (*func)();
    uint32_t content_size;
    char *content;
};

#define MAX_OPTION_NUM  (16U)
struct Options
{
    struct Option **options;
    uint32_t num_of_valid_option;
};


void init_options();

#endif
