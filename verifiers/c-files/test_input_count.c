#include <stdint.h>
#include "emulator.h"

// Single elf for the byte-check tests. The first input word holds the number of data bytes to check, and the data to
// check follows that word. Each data byte i must equal i modulo 256.
int main(int x)
{

    uint8_t *z = (uint8_t *)INPUT_ADDRESS;

    // First word: number of data bytes to check. The bytes to check start right after it.
    uint32_t count = *((uint32_t *)z);
    uint8_t *data = z + 4;

    for (uint32_t i = 0; i < count; i++)
    {
        if (data[i] != (uint8_t)i)
        {
            return 0x1;
        }
    }

    return 0x0;
}
