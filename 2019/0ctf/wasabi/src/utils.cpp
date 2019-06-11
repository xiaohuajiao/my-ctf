#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

uint32_t read_n_until(char *buf, uint32_t n, char end)
{
    uint32_t i;
    char ch;

    for (i = 0; i < n; ++i)
    {
        int ret = read(0, &ch, 1);
        if (ret == -1 || ch == end)
        {
            break;
        }
        buf[i] = ch;
    }
    if (i < n)
        buf[i] = '\x00';
    else
        buf[n-1] = '\x00';
    return i;
}

int read_int()
{
    char buf[0x10];
    read_n_until(buf, sizeof(buf), '\n');
    return atoi(buf);
}
