/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/tongsuo-mini/blob/main/LICENSE
 */
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <tongsuo/minisuo.h>
#include <tongsuo/ascon.h>
#include <tongsuo/mem.h>

int main(void)
{
    int ret = 1;
    void *ctx = NULL;
    const char *plaintext = "hello world, 12345678";
    const char *ad = "0123456789abcdef";
    unsigned char *key = tsm_hex2buf("0123456789abcdef0123456789abcdef");
    unsigned char *iv = tsm_hex2buf("0123456789abcdef0123456789abcdef");
    unsigned char out[1024];
    unsigned char tag[TSM_ASCON_AEAD_TAG_LEN];
    size_t outl, tmplen;
    void *ctx_dec = NULL;
    unsigned char dec_out[1024];
    size_t dec_outl = 0;

    if (key == NULL || iv == NULL) {
        goto err;
    }

    ctx = tsm_ascon_aead_ctx_new();
    if (ctx == NULL) {
        goto err;
    }

    if (tsm_ascon_aead_init(ctx, TSM_ASCON_AEAD_128, key, iv, TSM_CIPH_FLAG_ENCRYPT) != TSM_OK
        || tsm_ascon_aead_update(ctx, (const unsigned char *)ad, strlen(ad), NULL, NULL) != TSM_OK
        || tsm_ascon_aead_update(ctx,
                                 (const unsigned char *)plaintext,
                                 strlen(plaintext),
                                 out,
                                 &outl)
               != TSM_OK
        || tsm_ascon_aead_final(ctx, out + outl, &tmplen) != TSM_OK) {
        goto err;
    }

    outl += tmplen;

    if (tsm_ascon_aead_get_tag(ctx, tag) != TSM_OK) {
        goto err;
    }

    printf("ASCON_AEAD_Encrypt(%s)=", plaintext);

    for (size_t i = 0; i < outl; i++) {
        printf("%02x", out[i]);
    }

    for (size_t i = 0; i < TSM_ASCON_AEAD_TAG_LEN; i++) {
        printf("%02x", tag[i]);
    }

    printf("\n");

    ctx_dec = tsm_ascon_aead_ctx_new();
    if (ctx == NULL) {
        goto err;
    }

    if (tsm_ascon_aead_init(ctx_dec, TSM_ASCON_AEAD_128, key, iv, TSM_CIPH_FLAG_DECRYPT) != TSM_OK
        || tsm_ascon_aead_set_tag(ctx_dec, tag)
        || tsm_ascon_aead_update(ctx_dec, (const unsigned char *)ad, strlen(ad), NULL, NULL) != TSM_OK
        || tsm_ascon_aead_update(ctx_dec,
                                 out,
                                 3,
                                 dec_out + dec_outl,
                                 &tmplen)
               != TSM_OK
        || (dec_outl += tmplen, 0)
        || tsm_ascon_aead_update(ctx_dec,
                                 out + 3,
                                 outl - 3,
                                 dec_out + dec_outl,
                                 &tmplen)
               != TSM_OK
        || (dec_outl += tmplen, 0)
        || tsm_ascon_aead_final(ctx_dec, dec_out + dec_outl, &tmplen) != TSM_OK) {
        goto err;
    }

    dec_outl += tmplen;

    dec_out[dec_outl] = 0;
    printf("ASCON_AEAD_Decrypt=%s", dec_out);

    printf("\n");

    ret = 0;
err:
    tsm_ascon_aead_ctx_free(ctx);
    tsm_ascon_aead_ctx_free(ctx_dec);
    tsm_free(key);
    tsm_free(iv);
    return ret;
}
