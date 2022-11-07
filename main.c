#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "sec_aes.h"

FILE *g_gen_fd;
char g_gen_hdr;
uint8_t g_cic[12];
uint32_t aes_ver;

int enc(char *in_file, char *out_file, uint32_t param_3, uint32_t param_4) {
    FILE *__stream;
    FILE *__s;
    size_t sVar1;
    int iVar2;
    uint32_t *puVar3;
    unsigned char *output_buf;
    uint32_t uVar5;
    uint local_c4;
    uint32_t local_c0[32];
    unsigned char local_30[16];
    unsigned char local_20[16];

    memset(local_20, 0, sizeof(local_20));
    memset(local_30, 0, sizeof(local_30));
    local_c4 = 0;
    puVar3 = local_c0;
    for (iVar2 = 32; iVar2 != 0; iVar2 = iVar2 + -1) {
        *puVar3 = 0;
        puVar3 = puVar3 + 1;
    }
    __stream = fopen(in_file, "r");
    if (__stream == (FILE *) 0x0) {
        printf("[%s] %s not found\n", "CipherTool", in_file);
    } else {
        printf("[%s] Read \'%s\'\n", "CipherTool", in_file);
        __s = fopen(out_file, "wb");
        if (__s == (FILE *) 0x0) {
            printf("[%s] %s not found\n", "CipherTool", out_file);
        } else {
            printf("[%s] Write \'%s\'\n", "CipherTool", out_file);
            local_c0[14] = aes_ver;
            local_c0[15] = param_4;
            local_c0[0] = 0x63636363;
            local_c0[11] = 0x80;
            fseek(__stream, 0, 2);
            local_c0[10] = ftell(__stream);
            local_c0[12] = *(int *) &g_cic[4];
            if (*(int *) &g_cic[8] == 0) {
                *(int *) &g_cic[8] = local_c0[10] - *(int *) &g_cic[4];
                printf("[%s] all image will be processed, cipher length = \'%d\'\n", "CipherTool", *(int *) &g_cic[8]
                );
            }
            if (*(int *) &g_cic[4] < local_c0[10]) {
                if (local_c0[10] < *(int *) &g_cic[8] + *(int *) &g_cic[4]) {
                    printf("[%s] IMG len (%d) < cipher len (%d) + cipher off (%d)\n", "CipherTool", local_c0[10],
                           *(int *) &g_cic[8], *(int *) &g_cic[4]);
                    *(int *) &g_cic[8] = local_c0[10] - *(int *) &g_cic[4] & 0xfffffff0;
                    printf("[%s] adjust cipher len to (%d)\n", "CipherTool", *(int *) &g_cic[8]);
                }
                local_c0[13] = *(int *) &g_cic[8];
                fwrite(local_c0, 1, 0x80, __s);
                fseek(__stream, 0, 0);
                printf("[%s] hdr.cust_name     = %s\n", "CipherTool", (const char *) (local_c0 + 1));
                printf("[%s] hdr.img_off       = %d\n", "CipherTool", local_c0[11]);
                printf("[%s] hdr.img_len       = %d\n", "CipherTool", local_c0[10]);
                printf("[%s] hdr.c_off         = %d\n", "CipherTool", local_c0[12]);
                printf("[%s] hdr.c_len         = %d\n", "CipherTool", local_c0[13]);
                printf("[%s] hdr.aes_ver       = %d\n", "CipherTool", local_c0[14]);
                printf("[%s] hdr.vector_cfg    = %d\n", "CipherTool", local_c0[15]);
                while (1) {
                    sVar1 = fread(local_20, 1, 0x10, __stream);
                    if (sVar1 == 0) break;
                    if ((local_c4 < local_c0[12]) || (local_c0[12] + local_c0[13] <= local_c4)) {
                        if (local_c0[10] < local_c4 + 0x10) {
                            printf("[%s] adjust final write len from (%d) to (%d)\n", "CipherTool", 0x10,
                                   local_c0[10] - local_c4);
                            fwrite(local_20, 1, local_c0[10] - local_c4, __s);
                        } else {
                            fwrite(local_20, 1, 0x10, __s);
                        }
                    } else {
                        output_buf = local_30;
                        uVar5 = param_4;
                        iVar2 = lib_aes_enc(local_20, 0x10, output_buf, 0x10);
                        if (iVar2 != 0) {
                            printf("[%s] AES ENC error\n", "CipherTool");
                            goto LAB_08049776;
                        }
                        fwrite(local_30, 1, 0x10, __s);
                    }
                    local_c4 = local_c4 + 0x10;
                }
                fclose(__stream);
                fclose(__s);
                iVar2 = 0;
                goto LAB_0804977b;
            }
            printf("[%s] IMG len (%d) <= cipher off (%d)\n", "CipherTool", local_c0[10], *(int *) &g_cic[4]);
            printf("[%s] invalid cipher off\n", "CipherTool");
        }
    }
    LAB_08049776:
    iVar2 = -1;
    LAB_0804977b:
    return iVar2;
}

int dec(char *in_file, char *out_file, uint32_t param_3) {
    uint32_t uVar1;
    FILE *__stream;
    FILE *__s;
    size_t sVar2;
    int iVar3;
    uint32_t *puVar4;
    uint32_t uVar6;
    uint local_c4;
    uint32_t local_c0[32];
    unsigned char local_30[16];
    unsigned char local_20[16];
    unsigned char *output_buf;

    memset(local_20, 0, sizeof(local_20));
    memset(local_30, 0, sizeof(local_30));
    local_c4 = 0;
    puVar4 = local_c0;
    for (iVar3 = 32; iVar3 != 0; iVar3 = iVar3 + -1) {
        *puVar4 = 0;
        puVar4 = puVar4 + 1;
    }
    __stream = fopen(in_file, "r");
    if (__stream == (FILE *) 0x0) {
        printf("[%s] %s not found\n", "CipherTool", in_file);
    } else {
        printf("[%s] Read \'%s\'\n", "CipherTool", in_file);
        __s = fopen(out_file, "wb");
        if (__s != (FILE *) 0x0) {
            printf("[%s] Write \'%s\'\n", "CipherTool", out_file);
            fread(local_c0, 1, 128, __stream);
            uVar1 = local_c0[15];
            printf("[%s] hdr.cust_name     = %s\n", "CipherTool", (const char *)(local_c0 + 1));
            printf("[%s] hdr.img_off       = %d\n", "CipherTool", local_c0[11]);
            printf("[%s] hdr.img_len       = %d\n", "CipherTool", local_c0[10]);
            printf("[%s] hdr.c_off         = %d\n", "CipherTool", local_c0[12]);
            printf("[%s] hdr.c_len         = %d\n", "CipherTool", local_c0[13]);
            printf("[%s] hdr.vector_cfg    = %d\n", "CipherTool", local_c0[15]);
            fseek(__stream, 128, 0);
            while (1) {
                sVar2 = fread(local_20, 1, 0x10, __stream);
                if (sVar2 == 0) break;
                if ((local_c4 < local_c0[12]) || (local_c0[12] + local_c0[13] <= local_c4)) {
                    if (local_c0[10] < local_c4 + 0x10) {
                        printf("[%s] adjust final write len from (%d) to (%d)\n", "CipherTool", 0x10,
                               local_c0[10] - local_c4);
                        fwrite(local_20, 1, local_c0[10] - local_c4, __s);
                    } else {
                        fwrite(local_20, 1, 0x10, __s);
                    }
                } else {
                    output_buf = local_30;
                    uVar6 = uVar1;
                    iVar3 = lib_aes_dec(local_20, 16, output_buf, 16);
                    if (iVar3 != 0) {
                        printf("[%s] AES DEC error\n", "CipherTool");
                        goto LAB_08049ba5;
                    }
                    fwrite(local_30, 1, 16, __s);
                }
                local_c4 = local_c4 + 0x10;
            }
            fclose(__stream);
            fclose(__s);
            iVar3 = 0;
            goto LAB_08049baa;
        }
        printf("[%s] %s not found\n", "CipherTool", out_file);
    }
    LAB_08049ba5:
    iVar3 = -1;
    LAB_08049baa:
    return iVar3;
}

int imp_key(char *param_1, char *param_2) {
    FILE *pFVar1;
    unsigned int uVar2;
    FILE *__stream;
    char *pcVar3;
    size_t sVar4;
    char *pcVar5;
    int iVar6;
    uint32_t local_16c;
    char local_15c[300];
    uint32_t local_30[8];

    uVar2 = 0;
    memset(local_30, 0, 0x20);
    local_16c = 0;
    __stream = fopen(param_1, "r");
    if (__stream == (FILE *) 0x0) {
        printf("[%s] %s not found\n", "CipherTool", param_1);
    } else {
        printf("[%s] %s found\n", "CipherTool", param_1);
        while (pcVar5 = fgets(local_15c, 300, __stream), pcVar5 != (char *) 0x0) {
            pcVar5 = strtok(local_15c, " ");
            strtok((char *) 0x0, " ");
            pcVar3 = strtok((char *) 0x0, " \n");
            iVar6 = memcmp(pcVar5, "CUSTOM_AES_256", 0xe);
            if (iVar6 == 0) {
                printf("[%s] import CUSTOM_AES_256 (Legacy)\n", "CipherTool");
                aes_ver = 0;
                local_16c = 0x20;
                memcpy(local_30, pcVar3, 0x20);
                if (g_gen_hdr == '\x01') {
                    fwrite("#define ", 1, 8, g_gen_fd);
                    pFVar1 = g_gen_fd;
                    sVar4 = strlen(param_2);
                    fwrite(param_2, 1, sVar4, pFVar1);
                    fwrite("_", 1, 1, g_gen_fd);
                    fwrite("CUSTOM_AES_256", 1, 0xe, g_gen_fd);
                    fwrite(" \"", 1, 2, g_gen_fd);
                    pFVar1 = g_gen_fd;
                    sVar4 = strlen((char *) local_30);
                    fwrite(local_30, 1, sVar4, pFVar1);
                    fwrite("\"\n", 1, 2, g_gen_fd);
                }
            } else {
                iVar6 = memcmp(pcVar5, "CUSTOM_AES_128", 0xe);
                if (iVar6 != 0) {
                    printf("[%s] %s format error - key init fail\n", "CipherTool", param_1);
                    goto LAB_08048d40;
                }
                printf("[%s] import CUSTOM_AES_128 (SO)\n", "CipherTool");
                aes_ver = 1;
                local_16c = 0x10;
                memcpy(local_30, pcVar3, 0x20);
                if (g_gen_hdr == '\x01') {
                    fwrite("#define ", 1, 8, g_gen_fd);
                    pFVar1 = g_gen_fd;
                    sVar4 = strlen(param_2);
                    fwrite(param_2, 1, sVar4, pFVar1);
                    fwrite("_", 1, 1, g_gen_fd);
                    fwrite("CUSTOM_AES_128", 1, 0xe, g_gen_fd);
                    fwrite(" \"", 1, 2, g_gen_fd);
                    pFVar1 = g_gen_fd;
                    sVar4 = strlen((char *) local_30);
                    fwrite(local_30, 1, sVar4, pFVar1);
                    fwrite("\"\n", 1, 2, g_gen_fd);
                }
            }
        }
        iVar6 = lib_aes_init_key(local_30, local_16c, aes_ver);
        if (iVar6 == 0) {
            fclose(__stream);
            iVar6 = 0;
            goto LAB_08048d45;
        }
        printf("[%s] Key init error\n", "CipherTool");
    }
    LAB_08048d40:
    iVar6 = -1;
    LAB_08048d45:
    return iVar6;
}


int imp_cfg(char *param_1) {
    FILE *pFVar1;
    FILE *__stream;
    char *pcVar2;
    char *__nptr;
    size_t sVar3;
    char *pcVar4;
    int iVar5;
    char local_13c[300];

    __stream = fopen(param_1, "r");
    if (__stream == (FILE *) 0x0) {
        printf("[%s] %s not found\n", "CipherTool", param_1);
    } else {
        printf("[%s] %s found\n", "CipherTool", param_1);
        do {
            while (1) {
                while (1) {
                    pcVar4 = fgets(local_13c, 300, __stream);
                    if (pcVar4 == (char *) 0x0) {
                        printf("[%s] cfg.enc   = %d\n", "CipherTool", (int) g_cic[0]);
                        printf("[%s] cfg.off   = %d\n", "CipherTool", *(int *) &g_cic[4]/*g_cic._4_4_*/);
                        printf("[%s] cfg.len   = %d\n", "CipherTool", *(int *) &g_cic[8]/*g_cic._8_4_*/);
                        fclose(__stream);
                        iVar5 = 0;
                        goto LAB_080491b6;
                    }
                    pcVar4 = strtok(local_13c, " ");
                    pcVar2 = strtok((char *) 0x0, " ");
                    __nptr = strtok((char *) 0x0, " \n");
                    iVar5 = memcmp(pcVar4, "CIPHER_OFFSET", 0xd);
                    if (iVar5 != 0) break;
                    *(int *) &g_cic[4] = atoi(__nptr);
                    if ((*(int *) &g_cic[4] & 0xf) != 0) {
                        printf("[%s] Err. off should be multiple of %d \'%d\'\n", "CipherTool", 0x10,
                               *(int *) &g_cic[4] & 0xf /*g_cic._4_4_ & 0xf*/);
                        goto LAB_080491b1;
                    }
                    if (g_gen_hdr == '\x01') {
                        fwrite("#define ", 1, 8, g_gen_fd);
                        fwrite("CIPHER_OFFSET", 1, 0xd, g_gen_fd);
                        fwrite(" \"", 1, 2, g_gen_fd);
                        pFVar1 = g_gen_fd;
                        sVar3 = strlen(__nptr);
                        fwrite(__nptr, 1, sVar3, pFVar1);
                        fwrite("\"\n", 1, 2, g_gen_fd);
                    }
                }
                iVar5 = memcmp(pcVar4, "CIPHER_LENGTH", 0xd);
                if (iVar5 != 0) break;
                *(int *) &g_cic[8] = atoi(__nptr);
                if ((*(int *) &g_cic[8] & 0xf) != 0) {
                    printf("[%s] Err. len should be multiple of %d", "CipherTool", 0x10);
                    goto LAB_080491b1;
                }
                if (g_gen_hdr == '\x01') {
                    fwrite("#define ", 1, 8, g_gen_fd);
                    fwrite("CIPHER_LENGTH", 1, 0xd, g_gen_fd);
                    fwrite(" \"", 1, 2, g_gen_fd);
                    pFVar1 = g_gen_fd;
                    sVar3 = strlen(__nptr);
                    fwrite(__nptr, 1, sVar3, pFVar1);
                    fwrite("\"\n", 1, 2, g_gen_fd);
                }
            }
        } while ((*pcVar4 == ';') || (pcVar2 == (char *) 0x0));
        printf("[%s] %s format error - init cfg fail (%s)\n", "CipherTool", param_1, pcVar4);
    }
    LAB_080491b1:
    iVar5 = -1;
    LAB_080491b6:
    return iVar5;
}

int main(int argc, char *argv[]) {
    size_t sVar1;
    FILE *pFVar2;
    int ret;
    uint32_t local_68;
    int local_64[16];

    local_68 = 0;
    printf("\n=========================================\n");
    printf("[Android Cipher (Enc/Dec) Tool]\n\n");
    printf("Built at %s\n", "Wed Mar 7 20:58:19 CST 2012");
    printf("=========================================\n\n");
    if (argc == 6) {
        g_cic[1] = '\0';
        ret = memcmp(argv[1], "ENC_RESET_SIGNED_BIN", 0x14);
        if (ret == 0) {
            g_cic[0] = 1;
            g_cic[1] = 1;
            local_68 = 1;
            printf("[%s] signed binary encryption with reset vector...\n", "CipherTool");
        } else {
            ret = memcmp(argv[1], "ENC_RESET", 9);
            if (ret == 0) {
                g_cic[0] = 1;
                local_68 = 1;
                printf("[%s] encryption with reset vector...\n", "CipherTool");
            } else {
                ret = memcmp(argv[1], "ENC_SIGNED_BIN", 0xe);
                if (ret == 0) {
                    g_cic[0] = 1;
                    g_cic[1] = 1;
                    printf("[%s] signed binary encryption ...\n", "CipherTool");
                } else {
                    ret = memcmp(argv[1], "ENC", 3);
                    if (ret == 0) {
                        g_cic[0] = 1;
                        printf("[%s] encryption ...\n", "CipherTool");
                    } else {
                        ret = memcmp(argv[1], "DEC", 3);
                        if (ret == 0) {
                            g_cic[0] = '\0';
                            printf("[%s] decryption ...\n", "CipherTool");
                        } else {
                            ret = memcmp(argv[1], "GEN_HEADER", 10);
                            if (ret != 0) {
                                printf("[%s] wrong operation (%s)\n", "CipherTool", argv[1]);
                                goto LAB_0804a1fd;
                            }
                            printf("[%s] generate hdr file ...\n", "CipherTool");
                            g_gen_hdr = 1;
                        }
                    }
                }
            }
        }
        if (g_gen_hdr == 1) {
            g_gen_fd = fopen(argv[4], "wb");
            fwrite("// [", 1, 4, g_gen_fd);
            pFVar2 = g_gen_fd;
            sVar1 = strlen(argv[4]);
            fwrite(argv[4], 1, sVar1, pFVar2);
            fwrite("]\n// BUILD TIME : ", 1, 0x12, g_gen_fd);
            fwrite("Wed Mar 7 20:58:19 CST 2012", 1, 0x1b, g_gen_fd);
            fwrite("\n", 1, 1, g_gen_fd);
        }
        ret = imp_key(argv[2], argv[5]);
        if (ret == 0) {
            ret = imp_cfg(argv[3]);
            if (ret == 0) {
                if (g_gen_hdr != '\0') {
                    LAB_0804a1f6:
                    ret = 0;
                    goto LAB_0804a202;
                }
                pFVar2 = fopen(argv[4], "r");
                sVar1 = fread(local_64, 1, 0x40, pFVar2);
                if (sVar1 == 0) {
                    printf("\n[%s] %s is empty\n", "CipherTool", argv[3]);
                } else {
                    if ((local_64[0] == 0x53535353) && (g_cic[0] != '\0')) {
                        if (g_cic[1] == '\0') {
                            printf("signed already (0x%x)\n", 0x53535353);
                            goto LAB_0804a1f6;
                        }
                        printf("bin has been signed (0x%x)\n", 0x53535353);
                    }
                    if ((local_64[0] == 0x63636363) && (g_cic[0] != '\0')) {
                        printf("processed already (0x%x)\n", 0x63636363);
                        goto LAB_0804a1f6;
                    }
                    if (g_cic[0] == 1) {
                        ret = enc(argv[4], argv[5], 1, local_68);
                        if (ret == 0) goto LAB_0804a1f6;
                        printf("\n[%s] cipher error\n", "CipherTool");
                    } else if (g_cic[0] == '\0') {
                        ret = dec(argv[4], argv[5], 0);
                        if (ret == 0) goto LAB_0804a1f6;
                        printf("\n[%s] cipher error\n", "CipherTool");
                    } else {
                        printf("[%s] Wrong operation\n", "CipherTool");
                    }
                }
            } else {
                printf("[%s] import config error\n", "CipherTool");
            }
        } else {
            printf("[%s] import key error\n", "CipherTool");
        }
    } else {
        printf("Usage:    Encode or Decode Image .. \n");
        printf("          ./CipherTool [ENC, ENC_SIGNED_BIN, ENC_RESET, ENC_RESET_SIGNED_BIN or DEC] [KEY]  [CONFIG] [INPUT_IMAGE] [OUTPUT_IMAGE]\n\n");
        printf("Example:\n");
        printf("          ./CipherTool ENC CIPHER_KEY.ini CIPHER_CFG.ini modem.bin cipher_modem.bin\n");
        printf("          ./CipherTool ENC_SIGNED_BIN CIPHER_KEY.ini CIPHER_CFG.ini modem-sign.bin cipher_m odem.bin\n");
        printf("          ./CipherTool ENC_RESET CIPHER_KEY.ini CIPHER_CFG.ini modem.bin cipher_modem.bin\n");
        printf("          ./CipherTool ENC_RESET_SIGNED_BIN CIPHER_KEY.ini CIPHER_CFG.ini modem-sign.bin ci pher_modem.bin\n");
        printf("          ./CipherTool DEC CIPHER_KEY.ini CIPHER_CFG.ini cipher_modem.bin plain_moden\n\n");
        printf("Usage:    Output Key Information for Linking .. \n");
        printf("          ./CipherTool [GEN_HEADER] [KEY] [CONFIG] [OUTPUT_C_HEADER] [OUTPUT_PREFIX]\n\n");
        printf("Example:\n");
        printf("          ./CipherTool GEN_HEADER CIPHER_KEY.ini CIPHER_CFG.ini GEN_CIPHER_KEY.h IMG\n");
    }
    LAB_0804a1fd:
    ret = -1;
    LAB_0804a202:
    return ret;
}
