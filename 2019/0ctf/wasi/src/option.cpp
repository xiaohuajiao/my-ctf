#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "option.h"
#include "utils.h"
//#include "dlmalloc.h"
#include "sha.h"
#include "config.h"
#include "step2.h"
#include "step3.h"
#include "zerology.h"

extern struct Options g_options;
extern Zerology *g_zerology;

#define CHECK_OPTION(option) { \
    if (!option->inused || option->rest == 0) return ; \
} while (0)

static void add_option();
static void edit_option();
static void del_option();
static void quit_option();
static void get_flag();

void init_options()
{
    g_options.options = (struct Option **)malloc(sizeof(struct Option*) * MAX_OPTION_NUM);
    if (!g_options.options)
        _exit(0);

    g_options.num_of_valid_option = 0;

    memset(g_options.options, 0, sizeof(struct Option*) * MAX_OPTION_NUM);

#define REGISTER_OPTION(buf, handler) do { \
    struct Option *option = (struct Option *)malloc(sizeof(struct Option)); \
    if (!option) _exit(0); \
    option->inused = 1; \
    option->rest = 0x10; \
    option->func = handler; \
    option->content_size = 0x10; \
    option->content = (char *)malloc(0x10); \
    if (!option->content) _exit(0); \
    memset(option->content, 0, 0x10); \
    strncpy(option->content, buf, strlen(buf)); \
    g_options.options[g_options.num_of_valid_option++] = option; \
} while (0)

    REGISTER_OPTION("Add  Option", add_option);
    REGISTER_OPTION("Edit Option", edit_option);
    REGISTER_OPTION("Del  Option", del_option);
    REGISTER_OPTION("Get  Flag", get_flag);
    REGISTER_OPTION("Quit", quit_option);
}

static void add_option()
{
    if (g_options.num_of_valid_option >= MAX_OPTION_NUM)
        return;

    puts("Option content size:");
    uint32_t content_size = read_int();
    content_size = (content_size & 0xf) ? (((content_size/0x10)+1) * 0x10): content_size;

    if (content_size >= 0x80 || content_size == 0)
    {
        puts("Invalid content size");
        return ;
    }

    struct Option *new_option = (struct Option *)malloc(sizeof(struct Option));
    if (!new_option)
        return ;

    char *content = (char *)malloc(content_size);
    if (!content)
    {
        free(new_option);
        return ;
    }

    new_option->inused = 1;
    new_option->rest = 8;
    new_option->func = (void (*)())-1;
    new_option->content_size = content_size;
    new_option->content = content;

    printf("Option content:\n");
    read_n_until(new_option->content, new_option->content_size, '\n');

    g_options.options[g_options.num_of_valid_option++] = new_option;
}

#define REQUEST_OPTION(idx, option) do { \
    puts("Option idx:"); \
    idx = read_int(); \
    if (idx == 0 || idx > g_options.num_of_valid_option) { \
        puts("Invalid option index"); \
        return ; \
    } \
    option = g_options.options[--idx]; \
    if (!option) return ; \
} while (0)

static void edit_option()
{
    struct Option *option = NULL;
    uint32_t idx = 0;
    REQUEST_OPTION(idx, option);

    puts("Option content size:");
    uint32_t content_size = read_int();

    // BUG: Overflow at most 15 bytes
    if (content_size > 0 && ((content_size & 0xfffffff0) <= option->content_size))
    {
        content_size = (content_size & 0xf) ? (((content_size/0x10)+1) * 0x10): content_size;
    }
    else
    {
        puts("Invalid Content size");
        return ;
    }

    puts("New option content:");
    read_n_until(option->content, content_size, '\n');
}

static void del_option()
{
    struct Option *option = NULL;
    uint32_t idx = 0;

    REQUEST_OPTION(idx, option);

    option->inused = 0;
    option->rest = 0;
    option->func = (void (*)())0;

    if (option->content)
    {
        memset(option->content, 0, option->content_size);
        free(option->content);
        option->content = NULL;
    }

    option->content_size = 0;
    free(option);

    // left shift 1
    if (idx < g_options.num_of_valid_option-1)
    {
        uint32_t i;
        for (i = idx; i < g_options.num_of_valid_option-1; ++i)
        {
            g_options.options[i] = g_options.options[i+1];
        }
    }
    g_options.options[--g_options.num_of_valid_option] = NULL;
}

static void quit_option()
{
    _exit(0);
}

#define STEP2_INPUT_SIZE        (0x100)
static void get_flag()
{
    puts("Now i'd like to have a zongzi, which flavor do you want?");

    // read user input
    char user_input[STEP2_INPUT_SIZE] = {0};
    fgets(user_input, STEP2_INPUT_SIZE-1, stdin);
    if (user_input[strlen(user_input)-1] == '\n')
    {
        user_input[strlen(user_input)-1] = '\x00';
    }

    // calc sha512 and compare it with our target
    uint8_t md[0x100] = {0};
    SHA512((const unsigned char *)user_input, strlen(user_input), md);

/*
    puts("my sha512:");
    for (uint32_t i = 0; i < 0x40; i++) printf("%02x", (uint8_t)(md[i]));
    puts("");
    puts("TARGET sha512:");
    for (uint32_t i = 0; i < 0x40; i++) printf("%02x", (uint8_t)(STEP2_SHA512[i]));
    puts("");
*/
    if (memcmp(md, STEP2_SHA512, SHA512_DIGEST_LENGTH) != 0)
    {
        puts("Wait, wait, wait... This is not so good >.<");
        return;
    }

    char flag[0x100] = {0};
    DEC_FLAG2(flag);
    printf("So u like this flavor, right? %s\n", flag);

    step3();
}
