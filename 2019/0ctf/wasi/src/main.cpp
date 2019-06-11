#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>
#include <string.h>

#include "option.h"
#include "utils.h"
#include "step1.h"


struct Options g_options;

void init()
{
    setvbuf(stdin,0,2,0);
    setvbuf(stdout,0,2,0);

#ifndef WASI
    srand(time(0));
    malloc(rand() & 0xfff0);
#else
    uint16_t offset = 0;
    __wasi_random_get(&offset, sizeof(offset));
    malloc(offset & 0xfff0);
#endif
}

extern uint8_t g_memory[];

void init_vm_memory()
{
    memcpy(g_memory+1, "Amazing,gogogo!\n", 16);
}

/*
void init_zerology()
{
    if (g_zerology)
    {
        delete g_zerology;
        g_zerology = NULL;
    }

    g_zerology = new Zerology;

    // random vm
#ifndef WASI
    srand(time(0));
    malloc(rand() & 0xfff0);
#else
    uint16_t offset = 0;
    __wasi_random_get(&offset, sizeof(offset));
    malloc(offset & 0xfff0);
#endif
}
*/

int main()
{
    uint32_t idx;
    struct Option *option;

    init();

    // first reverse challenge
    if (step1() == STEP1_FAIL)
    {
        puts("Hah, enjoy and try again");
        return 0;
    }

    //init_zerology();
    init_vm_memory();
    init_options();

    while (1)
    {
        puts("");
        for (idx = 0; idx < g_options.num_of_valid_option; ++idx)
        {
            option = g_options.options[idx];
            if (option->inused == 0 || option->rest == 0)
                continue;
            printf("%d. %s\n", idx+1, option->content);
        }

        idx = read_int();
        if (idx == 0 || idx > g_options.num_of_valid_option)
        {
            puts("Invalid option");
            continue;
        }
        option = g_options.options[idx-1];
        if (option->inused == 0 || option->rest == 0)
        {
            puts("Invalid option");
            continue;
        }

        option->rest--;
        option->func();
    }

    return 0;
}
