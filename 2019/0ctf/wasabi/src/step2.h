
#ifndef STEP2_H
#define STEP2_H

#include <stdint.h>

uint8_t cipher_flag[] = "\x3e\x81\x34\x00\x8b\xfc\xbc\x9c\x41\x21\x3a\xa4\xcb\x4f\x30\xfe\xeb\x3d\x2c\x3f\x9b\x4a\xd4\x40\x51\xac\x3c\xe0\xf5\xcb\x7d\x4f\xf3\x5c\x05\x54\xc0\x13\xdb\x78\x85\x54\xb9\xbd\xc4\x34\x4b\xaf\x0d\x6a\x97\xf2\x0f\xf0\x71\x62\x32\x1a\x90\x5e\x93\x77\x14\xe9\x91\x76\x94\x47\x51\x97\x3e\xab\xfd\x5f\xfb\x69\x12\x7e\x78";

#define DEC_FLAG2(flag) do { \
    uint8_t key[79] = {0}; \
    key[0] = 0x58; \
    key[1] = 0xed; \
    key[2] = 0x55; \
    key[3] = 0x67; \
    key[4] = 0xf0; \
    key[5] = 0xcc; \
    key[6] = 0x8d; \
    key[7] = 0xf8; \
    key[8] = 0x1e; \
    key[9] = 0x69; \
    key[10] = 0x9; \
    key[11] = 0x90; \
    key[12] = 0xbb; \
    key[13] = 0x10; \
    key[14] = 0x5f; \
    key[15] = 0x88; \
    key[16] = 0xd8; \
    key[17] = 0x4f; \
    key[18] = 0x4a; \
    key[19] = 0x53; \
    key[20] = 0xab; \
    key[21] = 0x3d; \
    key[22] = 0x8b; \
    key[23] = 0x33; \
    key[24] = 0x25; \
    key[25] = 0x9d; \
    key[26] = 0x50; \
    key[27] = 0x8c; \
    key[28] = 0xaa; \
    key[29] = 0xa2; \
    key[30] = 0x13; \
    key[31] = 0x10; \
    key[32] = 0xc1; \
    key[33] = 0x6c; \
    key[34] = 0x34; \
    key[35] = 0x6d; \
    key[36] = 0x9f; \
    key[37] = 0x44; \
    key[38] = 0x9a; \
    key[39] = 0x2b; \
    key[40] = 0xc8; \
    key[41] = 0xb; \
    key[42] = 0xd8; \
    key[43] = 0xd3; \
    key[44] = 0xa0; \
    key[45] = 0x6b; \
    key[46] = 0x27; \
    key[47] = 0xca; \
    key[48] = 0x79; \
    key[49] = 0x4d; \
    key[50] = 0xe4; \
    key[51] = 0xad; \
    key[52] = 0x6a; \
    key[53] = 0x9e; \
    key[54] = 0x1b; \
    key[55] = 0x52; \
    key[56] = 0x4b; \
    key[57] = 0x45; \
    key[58] = 0xe4; \
    key[59] = 0x36; \
    key[60] = 0xf6; \
    key[61] = 0x28; \
    key[62] = 0x25; \
    key[63] = 0x9a; \
    key[64] = 0xe5; \
    key[65] = 0x29; \
    key[66] = 0xed; \
    key[67] = 0x22; \
    key[68] = 0x30; \
    key[69] = 0xe5; \
    key[70] = 0x61; \
    key[71] = 0xc4; \
    key[72] = 0x9b; \
    key[73] = 0x0; \
    key[74] = 0xac; \
    key[75] = 0x28; \
    key[76] = 0x41; \
    key[77] = 0x37; \
    key[78] = 0x5; \
    for (uint32_t i = 0; i < 79; ++i) { \
        flag[i] = cipher_flag[i] ^ key[i]; \
    } \
} while (0)
#endif
    