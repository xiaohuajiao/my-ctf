#ifndef BWT_H
#define BWT_H

#include <stdint.h>

#define MAX_INPUT_SIZE  0x100
#define STEP1_KEY_SIZE  42

#define START_CHR       ('\x19')
#define END_CHR         ('\x20')
//#define START_CHR       ('^')
//#define END_CHR         ('|')

#define STEP1_SUC       (1)
#define STEP1_FAIL      (2)

//#define STEP1_DEBUG

int32_t step1();

#endif
