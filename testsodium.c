#include <sodium.h>
#include <stdio.h>

int main (void)
{
    if (sodium_init() < 0) {
        printf("could not initialize");
    }

    unsigned char message[4] = "test";
    unsigned char sk[32] = {0x34, 0xEB, 0xA3, 0x9F, 0xC5, 0xA1, 0xB4, 
                            0x1D, 0x64, 0x12, 0xCE, 0xC3, 0xD2, 0x0A,
                            0x7F, 0xA8, 0x24, 0x24, 0x2A, 0xDC, 0x1E,
                            0x6C, 0x04, 0x48, 0xCE, 0x91, 0xB3, 0xC4, 
                            0x84, 0xCC, 0x7A, 0xC6};

    unsigned char sig[crypto_sign_BYTES];
    
    crypto_sign_detached(sig, NULL, message, 4, sk);

    int i;
    for (i=0; i<64; i++)
    {
        printf("%02X", sig[i]);
    }
    printf("\n");
}
