#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include "step1.h"
#include "config.h"


static int bwt(char *input, uint32_t input_size, char *output, uint32_t *output_size)
{
    if (!input || !output || !output_size)
        return 0;

    if (strchr(input, START_CHR) || strchr(input, END_CHR) || input_size >= MAX_INPUT_SIZE)
    {
        puts("Invalid username");
        return 0;
    }

    for (uint32_t i = 0; i < input_size; i++)
    {
        if (isdigit(input[i]))
        {
            puts("Invalid username");
            return 0;
        }
    }

    // init output
    memset(output, 0, input_size+3);

    // create and init input
    char input_ex[MAX_INPUT_SIZE+3] = {0};
    input_ex[0] = START_CHR;
    input_ex[input_size+1] = END_CHR;
    memcpy(input_ex+1, input, input_size);

    uint32_t ex_length = input_size+2;

    // create && init sort table
    uint32_t indexes[MAX_INPUT_SIZE+2];

    for (uint32_t i = 0; i < ex_length; i++)
    {
        indexes[i] = i;
    }

    // create && init table
    char *table[MAX_INPUT_SIZE+2] = {0};

    for (uint32_t i = 0; i < MAX_INPUT_SIZE+2; i++)
    {
        table[i] = new char[MAX_INPUT_SIZE+3];
        memset(table[i], 0, MAX_INPUT_SIZE+3);
    }

    for (uint32_t i = 0; i < ex_length; i++)
    {
        for (uint32_t j = 0; j < ex_length; j++)
        {
            table[j][(j+i) % (ex_length)] = input_ex[i];
        }
    }

    // selection sort
    for (uint32_t i = 0; i < ex_length-1; i++)
    {
        uint32_t min = i;
        for (uint32_t j = i+1; j < ex_length; j++)
        {
            if (strcmp(table[indexes[j]], table[indexes[min]]) < 0)
            {
                min = j;
            }
        }
        uint32_t tmp = indexes[min];
        indexes[min] = indexes[i];
        indexes[i] = tmp;
    }

    // generate transform output
    for (uint32_t i = 0; i < ex_length; i++)
    {
        output[i] = table[indexes[i]][ex_length-1];
    }
    *output_size = ex_length;

#ifdef STEP1_DEBUG
    for (uint32_t i = 0; i < ex_length; i++)
    {
        printf("%d, ", indexes[i]);
    }
    puts("");

    for (uint32_t i = 0; i < ex_length; i++)
    {
        for (uint32_t j = 0; j < ex_length+1; j++)
        {
            printf("%02x", table[i][j]);
        }
        puts("");
    }

    for (uint32_t i = 0; i < ex_length; i++)
    {
        printf("%02x", output[i]);
    }
    puts("");
#endif

    for (uint32_t i = 0; i < MAX_INPUT_SIZE+2; i++)
    {
        delete [](table[i]);
    }
    return 1;
}

static int rle(char *input, uint32_t in_size, char *output, uint32_t *out_size)
{
    if (!input || !output || !out_size || in_size < 1 || *out_size < 1)
    {
        return 0;
    }

    uint32_t last_num = 1;
    char last_chr = input[0];

    for (uint32_t i = 1; i < in_size; i++)
    {
        if (input[i] == last_chr)
        {
            last_num++;
            continue;
        }
        else
        {
            // break before overflow
            if (strlen(output) >= *out_size-2)
            {
                last_num = 0;
                break;
            }
            snprintf(output+strlen(output), *out_size-strlen(output),
                    "%c%d", last_chr, last_num);
            last_num = 1;
            last_chr = input[i];
        }
    }

    if (last_num > 0)
    {
        snprintf(output+strlen(output), *out_size-strlen(output),
                "%c%d", last_chr, last_num);
    }

    *out_size = strlen(output);
    return 1;
}

int32_t step1()
{
    char user_input[MAX_INPUT_SIZE] = {0};

    puts("Do you like wasabi?");
    fgets(user_input, MAX_INPUT_SIZE-1, stdin);
    if (user_input[strlen(user_input)-1] == '\n')
    {
        user_input[strlen(user_input)-1] = '\x00';
    }

    // do bwt transform
    char bwt_output[MAX_INPUT_SIZE+3] = {0};
    uint32_t bwt_out_size = MAX_INPUT_SIZE+3;
    if (!bwt(user_input, strlen(user_input), bwt_output, &bwt_out_size))
    {
        return STEP1_FAIL;
    }

    // do RLE compression
    char rle_output[(MAX_INPUT_SIZE+3)*4] = {0};
    uint32_t rle_out_size = (MAX_INPUT_SIZE+3)*4;
    if (!rle(bwt_output, bwt_out_size, rle_output, &rle_out_size))
    {
        return STEP1_FAIL;
    }

#ifdef STEP1_DEBUG
    printf("output(%d): %s\n", rle_out_size, rle_output);
    for (uint32_t i = 0; i < rle_out_size; i++)
    {
        printf("%02x", rle_output[i]);
    }
    puts("");
#endif

    // expect: im_hungry_pls_help_e
    uint8_t key[] = {0x77, 0x2, 0x9, 0x52, 0x40, 0x5c, 0x16, 0x6e, 0x19, 0x1, 0x26, 0x62, 0x37, 0x5, 0x6, 0x76, 0x6, 0x50, 0x36, 0x6d, 0x29, 0x52, 0x31, 0x57, 0x5f, 0x65, 0xa, 0x45, 0x13, 0x6e, 0x5e, 0x1, 0x6e, 0x8, 0x38, 0x57, 0x5d, 0x5f, 0x5c, 0x5d, 0x1, 0x10};
    const char *welcome = "W3lc0me_t0_Sh4nGhai_0cTf/Tctf_2019_f1n4ls!";

    for (uint32_t i = 0; i < rle_out_size; i++)
    {
        rle_output[i] ^= key[i % STEP1_KEY_SIZE];
    }

#ifdef STEP1_DEBUG
    printf("%s\n", rle_output);
#endif

    if (strncmp(welcome, rle_output,strlen(welcome)) == 0)
    {
        printf("Congraz and flag is flag{%s}\n", user_input);
        return STEP1_SUC;
    }
    return STEP1_FAIL;
}

#ifdef STEP1_DEBUG
int main()
{
    return step1();
}
#endif
