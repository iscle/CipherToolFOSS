#include <string.h>
#include <stdio.h>
#include "aes_so.h"

/**************************************************************************
 *  DEFINITIONS
 **************************************************************************/
#define MOD                             "AES_SO"
#define CIPHER_BLOCK_SIZE               (16)

#define CT_AES128_LEN                   16      // 16B (AES128)
#define CT_AES192_LEN                   24      // 24B (AES192)
#define CT_AES256_LEN                   32      // 32B (AES256)

/**************************************************************************
 *  INTERNAL DEFINIITION
 **************************************************************************/
#define MASK 0xFF
#define T_SZ 256

#define EXP(x, y) (x^y)

/**************************************************************************
 *  GLOBAL VARIABLES
 **************************************************************************/
unsigned int aes_key_len = 0;

static unsigned char FS[T_SZ];
static unsigned long FT0[T_SZ];
static unsigned long FT1[T_SZ];
static unsigned long FT2[T_SZ];
static unsigned long FT3[T_SZ];

static unsigned char RS[T_SZ];
static unsigned long RT0[T_SZ];
static unsigned long RT1[T_SZ];
static unsigned long RT2[T_SZ];
static unsigned long RT3[T_SZ];

static unsigned long RCON[10];

static int aes_init_done = 0;

static int pow[T_SZ];
static int log[T_SZ];

#define A_F(X0, X1, X2, X3, Y0, Y1, Y2, Y3)     \
{                                               \
    X0 = *RK++ ^ FT0[ ( Y0       ) & MASK ] ^   \
                 FT1[ ( Y1 >>  8 ) & MASK ] ^   \
                 FT2[ ( Y2 >> 16 ) & MASK ] ^   \
                 FT3[ ( Y3 >> 24 ) & MASK ];    \
                                                \
    X1 = *RK++ ^ FT0[ ( Y1       ) & MASK ] ^   \
                 FT1[ ( Y2 >>  8 ) & MASK ] ^   \
                 FT2[ ( Y3 >> 16 ) & MASK ] ^   \
                 FT3[ ( Y0 >> 24 ) & MASK ];    \
                                                \
    X2 = *RK++ ^ FT0[ ( Y2       ) & MASK ] ^   \
                 FT1[ ( Y3 >>  8 ) & MASK ] ^   \
                 FT2[ ( Y0 >> 16 ) & MASK ] ^   \
                 FT3[ ( Y1 >> 24 ) & MASK ];    \
                                                \
    X3 = *RK++ ^ FT0[ ( Y3       ) & MASK ] ^   \
                 FT1[ ( Y0 >>  8 ) & MASK ] ^   \
                 FT2[ ( Y1 >> 16 ) & MASK ] ^   \
                 FT3[ ( Y2 >> 24 ) & MASK ];    \
}

#define A_R(X0, X1, X2, X3, Y0, Y1, Y2, Y3)     \
{                                               \
    X0 = *RK++ ^ RT0[ ( Y0       ) & MASK ] ^   \
                 RT1[ ( Y3 >>  8 ) & MASK ] ^   \
                 RT2[ ( Y2 >> 16 ) & MASK ] ^   \
                 RT3[ ( Y1 >> 24 ) & MASK ];    \
                                                \
    X1 = *RK++ ^ RT0[ ( Y1       ) & MASK ] ^   \
                 RT1[ ( Y0 >>  8 ) & MASK ] ^   \
                 RT2[ ( Y3 >> 16 ) & MASK ] ^   \
                 RT3[ ( Y2 >> 24 ) & MASK ];    \
                                                \
    X2 = *RK++ ^ RT0[ ( Y2       ) & MASK ] ^   \
                 RT1[ ( Y1 >>  8 ) & MASK ] ^   \
                 RT2[ ( Y0 >> 16 ) & MASK ] ^   \
                 RT3[ ( Y3 >> 24 ) & MASK ];    \
                                                \
    X3 = *RK++ ^ RT0[ ( Y3       ) & MASK ] ^   \
                 RT1[ ( Y2 >>  8 ) & MASK ] ^   \
                 RT2[ ( Y1 >> 16 ) & MASK ] ^   \
                 RT3[ ( Y0 >> 24 ) & MASK ];    \
}


/**************************************************************************
 *  MTK SECRET
 **************************************************************************/
static unsigned int g_AES_IV[4] = {
        0x6c8d3259, 0x86911412, 0x55975412, 0x6c8d3257
};

static unsigned int g_AES_IV_TEMP[4] = {
        0x0, 0x0, 0x0, 0x0
};

unsigned int g_AES_Key[4] = {
        0x0, 0x0, 0x0, 0x0
};


/**************************************************************************
 *  INTERNAL VARIABLES
 **************************************************************************/
a_ctx aes;

#ifndef G_U_LE
#define G_U_LE(n, b, i)                           \
{                                               \
    (n) = ( (unsigned long) (b)[(i)    ]       )        \
        | ( (unsigned long) (b)[(i) + 1] <<  8 )        \
        | ( (unsigned long) (b)[(i) + 2] << 16 )        \
        | ( (unsigned long) (b)[(i) + 3] << 24 );       \
}
#endif

#ifndef P_U_LE
#define P_U_LE(n, b, i)                           \
{                                               \
    (b)[(i)    ] = (unsigned char) ( (n)       );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 3] = (unsigned char) ( (n) >> 24 );       \
}
#endif

#define ROTL8(x) ( ( x << 8 ) & 0xFFFFFFFF ) | ( x >> 24 )
#define XTIME(x) ( ( x << 1 ) ^ ( ( x & 0x80 ) ? 0x1B : 0x00 ) )
#define MUL(x, y) ( ( x && y ) ? pow[(log[x]+log[y]) % 255] : 0 )

/**************************************************************************
 *  FUNCTIONS
 **************************************************************************/
static void a_gen_tables(void) {
    int i, x, y, z;

    for (i = 0, x = 1; i < T_SZ; i++) {
        pow[i] = x;
        log[x] = i;
        x = (x ^ XTIME(x)) & MASK;
    }

    for (i = 0, x = 1; i < 10; i++) {
        RCON[i] = (unsigned long) x;
        x = XTIME(x) & MASK;
    }

    FS[0x00] = 0x63;
    RS[0x63] = 0x00;

    for (i = 1; i < T_SZ; i++) {
        x = pow[255 - log[i]];

        y = x;
        y = ((y << 1) | (y >> 7)) & MASK;
        x ^= y;
        y = ((y << 1) | (y >> 7)) & MASK;
        x ^= y;
        y = ((y << 1) | (y >> 7)) & MASK;
        x ^= y;
        y = ((y << 1) | (y >> 7)) & MASK;
        x ^= y ^ 0x63;

        FS[i] = (unsigned char) x;
        RS[x] = (unsigned char) i;
    }

    for (i = 0; i < T_SZ; i++) {
        x = FS[i];
        y = XTIME(x) & MASK;
        z = (y ^ x) & MASK;

        FT0[i] = ((unsigned long) y) ^
                 ((unsigned long) x << 8) ^
                 ((unsigned long) x << 16) ^
                 ((unsigned long) z << 24);

        FT1[i] = ROTL8(FT0[i]);
        FT2[i] = ROTL8(FT1[i]);
        FT3[i] = ROTL8(FT2[i]);

        x = RS[i];

        RT0[i] = ((unsigned long) MUL(0x0E, x)) ^
                 ((unsigned long) MUL(0x09, x) << 8) ^
                 ((unsigned long) MUL(0x0D, x) << 16) ^
                 ((unsigned long) MUL(0x0B, x) << 24);

        RT1[i] = ROTL8(RT0[i]);
        RT2[i] = ROTL8(RT1[i]);
        RT3[i] = ROTL8(RT2[i]);
    }
}


int a_enc(a_ctx *ctx, const unsigned char *key, unsigned int keysize) {
    unsigned int i;
    unsigned long *RK;

    if (aes_init_done == 0) {
        a_gen_tables();
        aes_init_done = 1;
    }

    switch (keysize) {
        case 128:
            ctx->nr = 10;
            break;
        case 192:
            ctx->nr = 12;
            break;
        case 256:
            ctx->nr = 14;
            break;
        default :
            return (-1);
    }

    ctx->rk = RK = ctx->buf;

    for (i = 0; i < (keysize >> 5); i++) {
        G_U_LE(RK[i], key, i << 2);
    }

    switch (ctx->nr) {
        case 10:

            for (i = 0; i < 10; i++, RK += 4) {
                RK[4] = RK[0] ^ RCON[i] ^
                        ((unsigned long) FS[(RK[3] >> 8) & MASK]) ^
                        ((unsigned long) FS[(RK[3] >> 16) & MASK] << 8) ^
                        ((unsigned long) FS[(RK[3] >> 24) & MASK] << 16) ^
                        ((unsigned long) FS[(RK[3]) & MASK] << 24);

                RK[5] = EXP(RK[1], RK[4]);
                RK[6] = EXP(RK[2], RK[5]);
                RK[7] = EXP(RK[3], RK[6]);
            }
            break;

        case 12:

            for (i = 0; i < 8; i++, RK += 6) {
                RK[6] = RK[0] ^ RCON[i] ^
                        ((unsigned long) FS[(RK[5] >> 8) & MASK]) ^
                        ((unsigned long) FS[(RK[5] >> 16) & MASK] << 8) ^
                        ((unsigned long) FS[(RK[5] >> 24) & MASK] << 16) ^
                        ((unsigned long) FS[(RK[5]) & MASK] << 24);

                RK[7] = EXP(RK[1], RK[6]);
                RK[8] = EXP(RK[2], RK[7]);
                RK[9] = EXP(RK[3], RK[8]);
                RK[10] = EXP(RK[4], RK[9]);
                RK[11] = EXP(RK[5], RK[10]);
            }
            break;

        case 14:

            for (i = 0; i < 7; i++, RK += 8) {
                RK[8] = RK[0] ^ RCON[i] ^
                        ((unsigned long) FS[(RK[7] >> 8) & MASK]) ^
                        ((unsigned long) FS[(RK[7] >> 16) & MASK] << 8) ^
                        ((unsigned long) FS[(RK[7] >> 24) & MASK] << 16) ^
                        ((unsigned long) FS[(RK[7]) & MASK] << 24);

                RK[9] = EXP(RK[1], RK[8]);
                RK[10] = EXP(RK[2], RK[9]);
                RK[11] = EXP(RK[3], RK[10]);

                RK[12] = RK[4] ^
                         ((unsigned long) FS[(RK[11]) & MASK]) ^
                         ((unsigned long) FS[(RK[11] >> 8) & MASK] << 8) ^
                         ((unsigned long) FS[(RK[11] >> 16) & MASK] << 16) ^
                         ((unsigned long) FS[(RK[11] >> 24) & MASK] << 24);

                RK[13] = EXP(RK[5], RK[12]);
                RK[14] = EXP(RK[6], RK[13]);
                RK[15] = EXP(RK[7], RK[14]);
            }
            break;

        default:

            break;
    }

    return (0);
}

int a_dec(a_ctx *ctx, const unsigned char *key, unsigned int keysize) {
    int i, j;
    a_ctx cty;
    unsigned long *RK;
    unsigned long *SK;
    int ret;

    switch (keysize) {
        case 128:
            ctx->nr = 10;
            break;
        case 192:
            ctx->nr = 12;
            break;
        case 256:
            ctx->nr = 14;
            break;
        default :
            return (-1);
    }

    ctx->rk = RK = ctx->buf;

    ret = a_enc(&cty, key, keysize);
    if (ret != 0)
        return (ret);

    SK = cty.rk + cty.nr * 4;

    *RK++ = *SK++;
    *RK++ = *SK++;
    *RK++ = *SK++;
    *RK++ = *SK++;

    for (i = ctx->nr - 1, SK -= 8; i > 0; i--, SK -= 8) {
        for (j = 0; j < 4; j++, SK++) {
            *RK++ = RT0[FS[(*SK) & MASK]] ^
                    RT1[FS[(*SK >> 8) & MASK]] ^
                    RT2[FS[(*SK >> 16) & MASK]] ^
                    RT3[FS[(*SK >> 24) & MASK]];
        }
    }

    *RK++ = *SK++;
    *RK++ = *SK++;
    *RK++ = *SK++;
    *RK++ = *SK++;

    memset(&cty, 0, sizeof(a_ctx));

    return (0);
}

int a_crypt_ecb(a_ctx *ctx,
                int mode,
                const unsigned char input[16],
                unsigned char output[16]) {
    int i;
    unsigned long *RK, X0, X1, X2, X3, Y0, Y1, Y2, Y3;

    RK = ctx->rk;

    G_U_LE(X0, input, 0);
    X0 ^= *RK++;
    G_U_LE(X1, input, 4);
    X1 ^= *RK++;
    G_U_LE(X2, input, 8);
    X2 ^= *RK++;
    G_U_LE(X3, input, 12);
    X3 ^= *RK++;

    /* ----------- */
    /* AES_DECRYPT */
    /* ----------- */
    if (mode == AES_DECRYPT) {
        for (i = (ctx->nr >> 1) - 1; i > 0; i--) {
            A_R(Y0, Y1, Y2, Y3, X0, X1, X2, X3);
            A_R(X0, X1, X2, X3, Y0, Y1, Y2, Y3);
        }

        A_R(Y0, Y1, Y2, Y3, X0, X1, X2, X3);

        X0 = *RK++ ^ \
                ((unsigned long) RS[(Y0) & MASK]) ^
             ((unsigned long) RS[(Y3 >> 8) & MASK] << 8) ^
             ((unsigned long) RS[(Y2 >> 16) & MASK] << 16) ^
             ((unsigned long) RS[(Y1 >> 24) & MASK] << 24);

        X1 = *RK++ ^ \
                ((unsigned long) RS[(Y1) & MASK]) ^
             ((unsigned long) RS[(Y0 >> 8) & MASK] << 8) ^
             ((unsigned long) RS[(Y3 >> 16) & MASK] << 16) ^
             ((unsigned long) RS[(Y2 >> 24) & MASK] << 24);

        X2 = *RK++ ^ \
                ((unsigned long) RS[(Y2) & MASK]) ^
             ((unsigned long) RS[(Y1 >> 8) & MASK] << 8) ^
             ((unsigned long) RS[(Y0 >> 16) & MASK] << 16) ^
             ((unsigned long) RS[(Y3 >> 24) & MASK] << 24);

        X3 = *RK++ ^ \
                ((unsigned long) RS[(Y3) & MASK]) ^
             ((unsigned long) RS[(Y2 >> 8) & MASK] << 8) ^
             ((unsigned long) RS[(Y1 >> 16) & MASK] << 16) ^
             ((unsigned long) RS[(Y0 >> 24) & MASK] << 24);
    } else /* AES_ENCRYPT */
    {
        for (i = (ctx->nr >> 1) - 1; i > 0; i--) {
            A_F(Y0, Y1, Y2, Y3, X0, X1, X2, X3);
            A_F(X0, X1, X2, X3, Y0, Y1, Y2, Y3);
        }

        A_F(Y0, Y1, Y2, Y3, X0, X1, X2, X3);

        X0 = *RK++ ^ \
                ((unsigned long) FS[(Y0) & MASK]) ^
             ((unsigned long) FS[(Y1 >> 8) & MASK] << 8) ^
             ((unsigned long) FS[(Y2 >> 16) & MASK] << 16) ^
             ((unsigned long) FS[(Y3 >> 24) & MASK] << 24);

        X1 = *RK++ ^ \
                ((unsigned long) FS[(Y1) & MASK]) ^
             ((unsigned long) FS[(Y2 >> 8) & MASK] << 8) ^
             ((unsigned long) FS[(Y3 >> 16) & MASK] << 16) ^
             ((unsigned long) FS[(Y0 >> 24) & MASK] << 24);

        X2 = *RK++ ^ \
                ((unsigned long) FS[(Y2) & MASK]) ^
             ((unsigned long) FS[(Y3 >> 8) & MASK] << 8) ^
             ((unsigned long) FS[(Y0 >> 16) & MASK] << 16) ^
             ((unsigned long) FS[(Y1 >> 24) & MASK] << 24);

        X3 = *RK++ ^ \
                ((unsigned long) FS[(Y3) & MASK]) ^
             ((unsigned long) FS[(Y0 >> 8) & MASK] << 8) ^
             ((unsigned long) FS[(Y1 >> 16) & MASK] << 16) ^
             ((unsigned long) FS[(Y2 >> 24) & MASK] << 24);
    }

    P_U_LE(X0, output, 0);
    P_U_LE(X1, output, 4);
    P_U_LE(X2, output, 8);
    P_U_LE(X3, output, 12);

    return (0);
}

int a_crypt_cbc(a_ctx *ctx,
                int mode,
                size_t length,
                unsigned char iv[16],
                const unsigned char *input,
                unsigned char *output) {
    int i;
    unsigned char temp[16];

    if (length % 16)
        return (-2);

    if (mode == AES_DECRYPT) {
        while (length > 0) {
            memcpy(temp, input, 16);
            a_crypt_ecb(ctx, mode, input, output);

            for (i = 0; i < 16; i++)
                output[i] = (unsigned char) (output[i] ^ iv[i]);

            memcpy(iv, temp, 16);

            input += 16;
            output += 16;
            length -= 16;
        }
    } else {
        while (length > 0) {
            for (i = 0; i < 16; i++)
                output[i] = (unsigned char) (input[i] ^ iv[i]);

            a_crypt_ecb(ctx, mode, output, output);
            memcpy(iv, output, 16);

            input += 16;
            output += 16;
            length -= 16;

        }
    }

    return (0);
}

/**************************************************************************
 *  SO FUNCTION - ENCRYPTION
 **************************************************************************/
int aes_so_enc(unsigned char *ip_buf, unsigned int ip_len, unsigned char *op_buf, unsigned int op_len) {
    unsigned int i = 0;
    unsigned int ret = 0;

    if (ip_len != op_len) {
        printf("[%s] error, ip len should be equal to op len\n", MOD);
        return -1;
    }

    if (0 != ip_len % CIPHER_BLOCK_SIZE) {
        printf("[%s] error, ip len should be mutiple of %d bytes\n", MOD, CIPHER_BLOCK_SIZE);
        return -1;
    }


    if (0 == g_AES_Key[0]) {
        printf("[%s] Enc Key Is ZERO. Fail\n", MOD);
        goto _err;
    }

    ret = a_enc(&aes, (unsigned char *) g_AES_Key, aes_key_len * 8);

    if (ret != 0) {
        printf("a_enc error -%02X\n", -ret);
        goto _err;
    }

    for (i = 0; i != ip_len; i += CIPHER_BLOCK_SIZE) {
        ret = a_crypt_cbc(&aes, AES_ENCRYPT, CIPHER_BLOCK_SIZE, (unsigned char *) g_AES_IV_TEMP, ip_buf + i,
                          op_buf + i);
        if (ret != 0) {
            printf("hairtunes: a_cbc error -%02X\n", -ret);
            goto _err;
        }
    }

    return 0;

    _err:

    return -1;
}

/**************************************************************************
 *  SO FUNCTION - DECRYPTION
 **************************************************************************/
int aes_so_dec(unsigned char *ip_buf, unsigned int ip_len, unsigned char *op_buf, unsigned int op_len) {
    unsigned int i = 0;
    unsigned int ret = 0;

    if (ip_len != op_len) {
        printf("[%s] error, ip len should be equal to op len\n", MOD);
        return -1;
    }

    if (0 != ip_len % CIPHER_BLOCK_SIZE) {
        printf("[%s] error, ip len should be mutiple of %d bytes\n", MOD, CIPHER_BLOCK_SIZE);
        return -1;
    }

    if (0 == g_AES_Key[0]) {
        printf("[%s] Dec Key Is ZERO. Fail\n", MOD);
        goto _err;
    }

    ret = a_dec(&aes, (unsigned char *) g_AES_Key, aes_key_len * 8);
    if (ret != 0) {
        printf("a_dec error -%02X\n", -ret);
        goto _err;
    }

    for (i = 0; i != ip_len; i += CIPHER_BLOCK_SIZE) {
        ret = a_crypt_cbc(&aes, AES_DECRYPT, 0x10, (unsigned char *) g_AES_IV_TEMP, ip_buf + i, op_buf + i);
        if (ret != 0) {
            printf("hairtunes: a_cbc error -%02X\n", -ret);
            goto _err;
        }
    }

    return 0;

    _err:

    return -1;

}

/**************************************************************************
 *  SO FUNCTION - KEY INITIALIZATION
 **************************************************************************/
/* WARNING ! this function is not the same as cipher tool */
int aes_so_init_key(unsigned char *key_buf, unsigned int key_len) {
    unsigned int i = 0;
    unsigned char temp[CT_AES128_LEN * 2];
    unsigned int n = 0;
    unsigned int val = 0;
    unsigned char c;
    int j = 0;
    unsigned char fmt_str[2] = {0};


    if (0 == key_buf) {
        printf("[%s] Init Key Is ZERO. Fail\n", MOD);
        goto _err;
    }

    /* -------------------------------------------------- */
    /* check key length                                   */
    /* -------------------------------------------------- */
    switch (key_len) {
        case CT_AES128_LEN:
            break;
        case CT_AES192_LEN:
        case CT_AES256_LEN:
            printf("[%s] Only AES 128 is supported\n", MOD);
            goto _err;
        default:
            printf("[%s] Len Invalid %d\n", MOD, key_len);
            goto _err;
    }

    aes_key_len = key_len;

    /* -------------------------------------------------- */
    /* copy key to temporarily buffer                     */
    /* -------------------------------------------------- */
    memcpy(temp, key_buf, CT_AES128_LEN * 2);

    /* -------------------------------------------------- */
    /* revert string to accomodate OpenSSL format         */
    /* -------------------------------------------------- */
    for (i = 0; i < key_len * 2; i += 8) {
        c = temp[i];
        temp[i] = temp[i + 6];
        temp[i + 6] = c;
        c = temp[i + 1];
        temp[i + 1] = temp[i + 7];
        temp[i + 7] = c;

        c = temp[i + 2];
        temp[i + 2] = temp[i + 4];
        temp[i + 4] = c;
        c = temp[i + 3];
        temp[i + 3] = temp[i + 5];
        temp[i + 5] = c;
    }

    /* -------------------------------------------------- */
    /* convert key value from string format to hex format */
    /* -------------------------------------------------- */

    i = 0;
    n = 0;

    while (n < key_len * 2) {

        for (j = 0; j < 8; j++) {
            fmt_str[0] = temp[n + j];
            sscanf(fmt_str, "%x", &val);
            g_AES_Key[i] = g_AES_Key[i] * 16;
            g_AES_Key[i] += val;
        }

        /* get next key value */
        i++;
        n += 8;
    }

    /* -------------------------------------------------- */
    /* reinit IV                                          */
    /* -------------------------------------------------- */
    for (i = 0; i < 4; i++) {
        g_AES_IV_TEMP[i] = g_AES_IV[i];
    }

    /* dump information for debugging */
    for (i = 0; i < 1; i++) {
        printf("0x%x\n", g_AES_Key[i]);
    }

    for (i = 0; i < 1; i++) {
        printf("0x%x\n", g_AES_IV_TEMP[i]);
    }

    return 0;

    _err:

    return -1;

}

/**************************************************************************
 *  SO FUNCTION - VECTOR INITIALIZATION
 **************************************************************************/
int aes_so_init_vector(void) {
    unsigned int i = 0;

    /* -------------------------------------------------- */
    /* reinit IV                                          */
    /* -------------------------------------------------- */
    for (i = 0; i < 4; i++) {
        g_AES_IV_TEMP[i] = g_AES_IV[i];
    }

    /* dump information for debugging */
    for (i = 0; i < 1; i++) {
        printf("0x%x\n", g_AES_Key[i]);
    }

    for (i = 0; i < 1; i++) {
        printf("0x%x\n", g_AES_IV_TEMP[i]);
    }

    return 0;
}
