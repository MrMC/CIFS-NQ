/*********************************************************************
 *
 *           Copyright (c) 2004 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Cryptographic library and password handling
 *                 contains DES, MD4 and MD5 algorithms implementation
 *                 and higher level LM, NTLM, LMv2 and NTLMv2 security
 *--------------------------------------------------------------------
 * DEPENDENCIES  : None
 *--------------------------------------------------------------------
 * CREATION DATE : 10-Jun-2004
 * CREATED BY    : Igor Gokhman
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "cmfscifs.h"
#include "cmapi.h"
#include "cmcrypt.h"

#ifdef UD_NQ_INCLUDESMB2
#include "cmsmb2.h"
#endif

/* message digest context */

typedef struct
{
    NQ_UINT32 a;
    NQ_UINT32 b;
    NQ_UINT32 c;
    NQ_UINT32 d;
} MD4Context;

#define HMAC_MAX_MD_CBLOCK 64

typedef struct
{
    MD5Context md5;
    NQ_BYTE iPad[HMAC_MAX_MD_CBLOCK + 1];
    NQ_BYTE oPad[HMAC_MAX_MD_CBLOCK + 1];
} HMAC_MD5Context;

/* static functions */

static void HMACMD5_Init(HMAC_MD5Context *ctx, const NQ_BYTE *key, NQ_UINT len);
static void HMACMD5_Init_RFC2104(HMAC_MD5Context *ctx, const NQ_BYTE *key, NQ_UINT len);
static void HMACMD5_Update(HMAC_MD5Context *ctx, const NQ_BYTE *data, NQ_UINT len);
static void HMACMD5_Final(HMAC_MD5Context *ctx, NQ_BYTE *md);

static void MD4_Transform(MD4Context *ctx, NQ_BYTE *buffer);
static void copy64(NQ_UINT32 *M, NQ_BYTE *in);
static void copy4(NQ_BYTE *out, NQ_UINT32 x);
static void MD5_Init(MD5Context *ctx);
static void MD5_Update(MD5Context *ctx, const NQ_BYTE *buf, NQ_UINT len);
static void MD5_Final(MD5Context *ctx, NQ_BYTE *digest);
static void NQ_E_P16(NQ_BYTE *p14, NQ_BYTE *p16);
static void NQ_E_P24(NQ_BYTE *p21, const NQ_BYTE *c8, NQ_BYTE *p24);

/*
 *====================================================================
 * PURPOSE: MD4 algorithm implementation
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT signature buffer
 *          IN     data to sign
 *          IN     data length
 *
 * RETURNS: none
 *
 * NOTES:   none
 *====================================================================
 */

void
cmMD4(
    NQ_BYTE *out,
    NQ_BYTE *in,
    NQ_UINT   n
    )
{
    MD4Context ctx;
    NQ_BYTE buffer[128];
    NQ_UINT32 M[16];
    NQ_UINT32 b = (NQ_UINT32)(n * 8);

    ctx.a = 0x67452301;
    ctx.b = 0xefcdab89;
    ctx.c = 0x98badcfe;
    ctx.d = 0x10325476;

    while (n > 64) {
        MD4_Transform(&ctx, in);
        in += 64;
        n -= 64;
    }

    syMemset(buffer, 0, sizeof(buffer));
    syMemcpy(buffer, in, n);
    buffer[n] = 0x80;

    if (n <= 55) {
        copy4(buffer+56, b);
        MD4_Transform(&ctx, buffer);
    } else {
        copy4(buffer+120, b);
        MD4_Transform(&ctx, buffer);
        MD4_Transform(&ctx, buffer+64);
    }

    syMemset(buffer, 0, sizeof(buffer));
    copy64(M, buffer);
    copy4(out, ctx.a);
    copy4(out+4, ctx.b);
    copy4(out+8, ctx.c);
    copy4(out+12, ctx.d);

    syMemset(&ctx, 0, sizeof(ctx));
}

/*
 *====================================================================
 * PURPOSE: MD5 algorithm implementation
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT signature buffer
 *          IN     data to sign
 *          IN     data length
 *
 * RETURNS: none
 *
 * NOTES:   none
 *====================================================================
 */

void
cmMD5(
    NQ_BYTE *out,
    NQ_BYTE *in,
    NQ_UINT n
    )
{
    MD5Context ctx;

    MD5_Init(&ctx);
    MD5_Update(&ctx, in, n);
    MD5_Final(&ctx, out);
}

/*
 *====================================================================
 * PURPOSE: MD5 hash function based message authentication code impl.
 *--------------------------------------------------------------------
 * PARAMS:  IN     key
 *          IN     key length
 *          IN     data to sign
 *          IN     data length
 *          IN/OUT signature buffer
 *
 * RETURNS: none
 *
 * NOTES:   none
 *====================================================================
 */

void
cmHMACMD5(
    const NQ_BYTE *key,
    NQ_UINT key_len,
    const NQ_BYTE *data,
    NQ_UINT data_len,
    NQ_BYTE *md
    )
{
    HMAC_MD5Context ctx;

    HMACMD5_Init(&ctx, key, key_len);
    HMACMD5_Update(&ctx, data, data_len);
    HMACMD5_Final(&ctx, md);
}

/*
 *====================================================================
 * PURPOSE: create v2 hash
 *--------------------------------------------------------------------
 * PARAMS:  IN  domain name
 *          IN  user name
 *          IN  *hashed* password
 *          OUT v2 hash
 *
 * RETURNS: NONE
 *
 * NOTES:
 *====================================================================
 */

void
cmCreateV2Hash(
    const NQ_TCHAR *domain,
    NQ_BOOL caseSensitiveDomain,
    const NQ_TCHAR *user,
    const NQ_BYTE  *password,
    NQ_UINT pwdlen,
    NQ_BYTE *hash
   )
{
    NQ_WCHAR data[CM_BUFFERLENGTH(NQ_WCHAR, CM_USERNAMELENGTH + CM_NQ_HOSTNAMESIZE)];

    cmTcharToUnicode(data, user);

    if (caseSensitiveDomain)
        cmWStrupr(data);

    cmTcharToUnicode(data + cmWStrlen(data), domain);

    if (!caseSensitiveDomain)
        cmWStrupr(data);

    cmHMACMD5(password, pwdlen, (NQ_BYTE*)data, (NQ_UINT)(cmWStrlen(data) * sizeof(NQ_WCHAR)), hash);
}

/*********************************************************************
 * Encryption
 ********************************************************************/

/*
 *====================================================================
 * PURPOSE: Encrypt plain text password
 *--------------------------------------------------------------------
 * PARAMS:  IN     plain text password
 *          IN     key
 *          IN/OUT encrypted password
 *
 * RETURNS: none
 *
 * NOTES:   none
 *====================================================================
 */

void
cmEncryptPlainTextPassword(
    const NQ_BYTE *password,
    const NQ_BYTE *key,
    NQ_BYTE *encrypted
    )
{
    NQ_BYTE hshPasswdBuf[16];

    cmHashPassword(password, hshPasswdBuf);
    cmEncryptHashedPassword(hshPasswdBuf, key, encrypted);
}

/*
 *====================================================================
 * PURPOSE: Hash plain text password
 *--------------------------------------------------------------------
 * PARAMS:  IN     plain text password
 *          IN/OUT hashed password
 *
 * RETURNS: none
 *
 * NOTES:   none
 *====================================================================
 */

void
cmHashPassword(
    const NQ_BYTE *password,
    NQ_BYTE hashed[16]
    )
{
    NQ_BYTE ptPasswdBuf[15];
    NQ_BYTE hshPasswdBuf[21];
    NQ_INT i;

    syMemset(ptPasswdBuf,cmWChar('\0'), sizeof(ptPasswdBuf));
    syMemset(hshPasswdBuf,cmWChar('\0'), sizeof(hshPasswdBuf));
    syStrncpy((NQ_CHAR *) ptPasswdBuf, (NQ_CHAR *)password, sizeof(ptPasswdBuf) - 1);
    for (i = 0; ptPasswdBuf[i] != 0; i++)
    {
        ptPasswdBuf[i] = (NQ_BYTE)syToupper(ptPasswdBuf[i]);
    }
    NQ_E_P16(ptPasswdBuf, hshPasswdBuf);
    syMemcpy(hashed, hshPasswdBuf, 16);
}

/*
 *====================================================================
 * PURPOSE: Encrypt hashed password
 *--------------------------------------------------------------------
 * PARAMS:  IN     hashed password
 *          IN     key
 *          IN/OUT encrypted password
 *
 * RETURNS: none
 *
 * NOTES:   none
 *====================================================================
 */

void
cmEncryptHashedPassword(
    const NQ_BYTE hashed[16],
    const NQ_BYTE key[8],
    NQ_BYTE encrypted[24]
    )
{
    NQ_BYTE hshPasswdBuf[21];

    syMemset(hshPasswdBuf,cmWChar('\0'),sizeof(hshPasswdBuf));
    syMemcpy(hshPasswdBuf, hashed, 16);
    NQ_E_P24(hshPasswdBuf, key, encrypted);
}

/*
 *====================================================================
 * PURPOSE: encrypt hashed LM password
 *--------------------------------------------------------------------
 * PARAMS:  IN  *hashed* LM password to encrypt
 *          IN  encryption key
 *          IN  buffer where encrypted password will be stored (at least 24 bytes)
 *          OUT encrypted password length
 *
 * RETURNS: NONE
 *
 * NOTES:
 *====================================================================
 */

void
cmEncryptLMPassword(
    const NQ_BYTE *key,
    const NQ_BYTE *password,
    NQ_BYTE *encrypted,
    NQ_UINT16 *len
    )
{
    cmEncryptHashedPassword(password, key, encrypted);
    *len = CM_CRYPT_ENCLMPWDSIZE;
}

/*
 *====================================================================
 * PURPOSE: encrypt hashed NTLM password
 *--------------------------------------------------------------------
 * PARAMS:  IN  encryption key
 *          IN  *hashed* NTLM password to encrypt
 *          OUT buffer where encrypted password will be stored (at least 24 bytes)
 *          OUT encrypted password length
 *
 * RETURNS: NONE
 *
 * NOTES:
 *====================================================================
 */

void
cmEncryptNTLMPassword(
    const NQ_BYTE *key,
    const NQ_BYTE *password,
    NQ_BYTE *encrypted,
    NQ_UINT16 *enclen
    )
{
    cmEncryptHashedPassword(password, key, encrypted);
    *enclen = CM_CRYPT_ENCNTLMPWDSIZE;
}

/*
 *====================================================================
 * PURPOSE: encrypt hashed NTLM password
 *--------------------------------------------------------------------
 * PARAMS:  IN  encryption key
 *          IN/OUT  IN - encrypted password OUT - decrypted password
 *          IN whether to perform MD5 before
 *
 * RETURNS: None
 *
 * NOTES:   password is 516 bytes long. Next 16 bytes are for crypted
 *          digest. After decryption the last four bytes of the password
 *          (from offset 512) contain password length. Decrypted password
 *          starts from byte (512 - length).
 *====================================================================
 */

void
cmDecryptPassword(
    const NQ_BYTE *key,
    NQ_BYTE *password,
    NQ_BOOL doMd5
    )
{
    MD5Context context; /* working context for MD5 */
    NQ_BYTE coKey[16];  /* new key */

    if (doMd5)
    {
        MD5_Init(&context);
        MD5_Update(&context, password + 516, 16);
        MD5_Update(&context, key, SMB_SESSIONKEY_LENGTH);
        MD5_Final(&context, coKey);
    }
    else
    {
        syMemset(coKey, 0, sizeof(coKey));
        syMemcpy(coKey, key, SMB_SESSIONKEY_LENGTH);
    }
    cmArcfourCrypt(password, 516, coKey, sizeof(coKey));
}

/*
 *====================================================================
 * PURPOSE: encrypt hashed NTLM password v2
 *--------------------------------------------------------------------
 * PARAMS:  IN  working connection
 *          IN  hashed NTLM password
 *          OUT encrypted password length
 *
 * RETURNS: NONE
 *
 * NOTES:
 *====================================================================
 */

void
cmEncryptNTLMv2Password(
    const NQ_BYTE *key,
    const NQ_BYTE *v2hash,
    const NQ_BYTE *blob,
    NQ_UINT16 bloblen,
    NQ_BYTE   *encrypted,
    NQ_UINT16 *enclen
    )
{
    HMAC_MD5Context ctx;

    HMACMD5_Init(&ctx, v2hash, 16);
    HMACMD5_Update(&ctx, key, 8);
    HMACMD5_Update(&ctx, blob, bloblen);
    HMACMD5_Final(&ctx, encrypted);
    *enclen = CM_CRYPT_ENCLMv2HMACSIZE;
}

/* message signing */

/*
 *====================================================================
 * PURPOSE: Create message authentication code
 *--------------------------------------------------------------------
 * PARAMS:  IN     key
 *          IN     key length
 *          IN     message sequence number
 *          IN     encrypted password or NULL
 *          IN     encrypted password length
 *          IN     data buffer
 *          IN     data length
 *          IN/OUT message signature (pointer inside data buffer)
 *
 * RETURNS: none
 *
 * NOTES:   none
 *====================================================================
 */

void
cmCreateMAC(
    const NQ_BYTE *key,
    NQ_COUNT       keyLen,
    NQ_UINT32      sequence,
    const NQ_BYTE *password,
    NQ_COUNT       passwordLen,
    const NQ_BYTE *data,           /* actually the packet header */
    NQ_UINT        length,
    NQ_BYTE       *signature
    )
{
    MD5Context ctx;
    NQ_BYTE hash[16];
    NQ_UINT32 sn = cmHtol32(sequence);

    TRCB();
    
    syMemset(&ctx, 0, sizeof(MD5Context));
    
    TRC3P("key length = %d, seq: %ld, length: %d", keyLen, sequence, length);
    TRCDUMP("key", key, (NQ_UINT)keyLen);

    syMemset(signature, 0, SMB_SECURITY_SIGNATURE_LENGTH);
    cmPutUint32(signature, sn);

    MD5_Init(&ctx);
    MD5_Update(&ctx, key, keyLen);
    if (NULL != password)
    {
        TRC1P("password: length = %d", passwordLen);
        TRCDUMP("password", password, (NQ_UINT)passwordLen);

        MD5_Update(&ctx, password, passwordLen);
    }
    MD5_Update(&ctx, data, length);
    MD5_Final(&ctx, hash);

    syMemcpy(signature, hash, SMB_SECURITY_SIGNATURE_LENGTH);

    TRCDUMP("signature", signature, SMB_SECURITY_SIGNATURE_LENGTH);

    TRCE();
}

/*
 *====================================================================
 * PURPOSE: Check message authentication code
 *--------------------------------------------------------------------
 * PARAMS:  IN     key
 *          IN     key length
 *          IN     message sequence number
 *          IN     encrypted password or NULL
 *          IN     encrypted password length
 *          IN     data buffer
 *          IN     data length
 *          IN/OUT message signature (pointer inside data buffer)
 *
 * RETURNS: none
 *
 * NOTES:   none
 *====================================================================
 */

NQ_BOOL
cmCheckMAC(
    const NQ_BYTE *key,
    NQ_COUNT       keyLen,
    NQ_UINT32      sequence,
    const NQ_BYTE *password,
    NQ_COUNT       passwordLen,
    const NQ_BYTE *data,
    NQ_UINT        length,
    NQ_BYTE       *signature
    )
{
    NQ_BYTE temp[SMB_SECURITY_SIGNATURE_LENGTH];

    syMemcpy(temp, signature, SMB_SECURITY_SIGNATURE_LENGTH);
    TRCDUMP("received signature", temp, SMB_SECURITY_SIGNATURE_LENGTH);
    
    cmCreateMAC(key, keyLen, sequence, password, passwordLen, data, length, signature);

    return syMemcmp(temp, signature, SMB_SECURITY_SIGNATURE_LENGTH) == 0;
}

/*********************************************************************
 * DES
 ********************************************************************/

static const NQ_BYTE perm1[56] = {
    57, 49, 41, 33, 25, 17,  9,
     1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27,
    19, 11,  3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
     7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29,
    21, 13,  5, 28, 20, 12,  4};

static const NQ_BYTE perm2[48] = {
    14, 17, 11, 24,  1,  5,
     3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8,
    16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32};

static const NQ_BYTE perm3[64] = {
    58, 50, 42, 34, 26, 18, 10,  2,
    60, 52, 44, 36, 28, 20, 12,  4,
    62, 54, 46, 38, 30, 22, 14,  6,
    64, 56, 48, 40, 32, 24, 16,  8,
    57, 49, 41, 33, 25, 17,  9,  1,
    59, 51, 43, 35, 27, 19, 11,  3,
    61, 53, 45, 37, 29, 21, 13,  5,
    63, 55, 47, 39, 31, 23, 15,  7};

static const NQ_BYTE perm4[48] = {
    32,  1,  2,  3,  4,  5,
     4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1};

static const NQ_BYTE perm5[32] = {
    16,  7, 20, 21,
    29, 12, 28, 17,
     1, 15, 23, 26,
     5, 18, 31, 10,
     2,  8, 24, 14,
    32, 27,  3,  9,
    19, 13, 30,  6,
    22, 11,  4, 25};

static const NQ_BYTE perm6[64] ={
    40,  8, 48, 16, 56, 24, 64, 32,
    39,  7, 47, 15, 55, 23, 63, 31,
    38,  6, 46, 14, 54, 22, 62, 30,
    37,  5, 45, 13, 53, 21, 61, 29,
    36,  4, 44, 12, 52, 20, 60, 28,
    35,  3, 43, 11, 51, 19, 59, 27,
    34,  2, 42, 10, 50, 18, 58, 26,
    33,  1, 41,  9, 49, 17, 57, 25};

static const NQ_BYTE sc[16] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

static const NQ_BYTE sbox[8][4][16] = {
    {{14, 4,  13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7},
     { 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8},
     { 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0},
     {15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13}},

    {{15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10},
     { 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5},
     { 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15},
     {13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9}},

    {{10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8},
     {13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1},
     {13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7},
     { 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12}},

    {{ 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15},
     {13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9},
     {10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4},
     { 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14}},

    {{ 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9},
     {14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6},
     { 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14},
     {11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3}},

    {{12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11},
     {10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8},
     { 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6},
     { 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13}},

    {{ 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1},
     {13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6},
     { 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2},
     { 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12}},

    {{13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7},
     { 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2},
     { 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8},
     { 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11}}};

static
void
permute(
    NQ_CHAR *out,
    NQ_CHAR *in,
    const NQ_BYTE *p,
    NQ_INT n
   )
{
    NQ_INT i;

    for (i = 0; i < n; i++)
        out[i] = in[p[i] - 1];
}

static
void
lshift(
    NQ_CHAR *d,
    NQ_INT count,
    NQ_INT n
   )
{
    NQ_CHAR out[64];
    NQ_INT i;

    for (i = 0; i < n; i++)
        out[i] = d[(i + count) % n];
    for (i = 0; i < n; i++)
        d[i] = out[i];
}

static
void
concat(
    NQ_CHAR *out,
    NQ_CHAR *in1,
    NQ_CHAR *in2,
    NQ_INT l1,
    NQ_INT l2
   )
{
    while (l1--)
        *out++ = *in1++;
    while (l2--)
        *out++ = *in2++;
}

static
void
xorArray(
    NQ_CHAR *out,
    NQ_CHAR *in1,
    NQ_CHAR *in2,
    NQ_INT n
   )
{
    NQ_INT i;

    for (i = 0; i < n; i++)
        out[i] = in1[i] ^ in2[i];
}

static
void
dohash(
    NQ_CHAR *out,
    NQ_CHAR *in,
    NQ_CHAR *key,
    NQ_INT forw
   )
{
    NQ_INT i, j, k;
    NQ_CHAR pk1[56];
    NQ_CHAR c[28];
    NQ_CHAR d[28];
    NQ_CHAR cd[56];
    NQ_CHAR ki[16][48];
    NQ_CHAR pd1[64];
    NQ_CHAR l[32], r[32];
    NQ_CHAR rl[64];

    permute(pk1, key, perm1, 56);

    for (i = 0; i < 28; i++)
        c[i] = pk1[i];
    for (i = 0; i < 28; i++)
        d[i] = pk1[i+28];

    for (i = 0; i < 16; i++)
    {
        lshift(c, sc[i], 28);
        lshift(d, sc[i], 28);

        concat(cd, c, d, 28, 28);
        permute(ki[i], cd, perm2, 48);
    }

    permute(pd1, in, perm3, 64);

    for (j = 0; j < 32; j++)
    {
        l[j] = pd1[j];
        r[j] = pd1[j + 32];
    }

    for (i=0;i<16;i++)
    {
        NQ_CHAR er[48];
        NQ_CHAR erk[48];
        NQ_CHAR b[8][6];
        NQ_CHAR cb[32];
        NQ_CHAR pcb[32];
        NQ_CHAR r2[32];

        permute(er, r, perm4, 48);

        xorArray(erk, er, ki[forw ? i : 15 - i], 48);

        for (j = 0; j < 8; j++)
            for (k = 0; k < 6; k++)
                b[j][k] = erk[j * 6 + k];

        for (j = 0; j < 8; j++)
        {
            NQ_INT m, n;

            m = (b[j][0] << 1) | b[j][5];

            n = (b[j][1] << 3) | (b[j][2] << 2) | (b[j][3] << 1) | b[j][4];

            for (k = 0; k < 4; k++)
                b[j][k] = (sbox[j][m][n] & (1 << (3 - k))) ? 1 : 0;
        }

        for (j = 0; j < 8; j++)
            for (k = 0; k < 4; k++)
                cb[j * 4 + k] = b[j][k];
        permute(pcb, cb, perm5, 32);

        xorArray(r2, l, pcb, 32);

        for (j = 0; j < 32; j++)
            l[j] = r[j];

        for (j = 0; j < 32; j++)
            r[j] = r2[j];
    }

    concat(rl, r, l, 32, 32);
    permute(out, rl, perm6, 64);
}

static
void
str_to_key(
    const NQ_BYTE *str,
    NQ_BYTE *key
   )
{
    NQ_INT i;

    key[0] = str[0] >> 1;
    key[1] = (NQ_BYTE)((str[0] & 0x01) << 6) | (str[1] >> 2);
    key[2] = (NQ_BYTE)((str[1] & 0x03) << 5) | (str[2] >> 3);
    key[3] = (NQ_BYTE)((str[2] & 0x07) << 4) | (str[3] >> 4);
    key[4] = (NQ_BYTE)((str[3] & 0x0F) << 3) | (str[4] >> 5);
    key[5] = (NQ_BYTE)((str[4] & 0x1F) << 2) | (str[5] >> 6);
    key[6] = (NQ_BYTE)((str[5] & 0x3F) << 1) | (str[6] >> 7);
    key[7] = str[6] & 0x7F;

    for (i = 0; i < 8; i++)
    {
        key[i] = (NQ_BYTE)(key[i] << 1);
    }
}

static
void
smbhash(
    NQ_BYTE *out,
    const NQ_BYTE *in,
    const NQ_BYTE *key,
    NQ_INT forw
   )
{
    NQ_INT i;
    NQ_CHAR outb[64];
    NQ_CHAR inb[64];
    NQ_CHAR keyb[64];
    NQ_BYTE key2[8];

    str_to_key(key, key2);

    for (i = 0; i < 64; i++)
    {
        inb[i] = (in[i / 8] & (1 << (7 - (i % 8)))) ? 1 : 0;
        keyb[i] = (key2[i / 8] & (1 << (7 - (i % 8)))) ? 1 : 0;
        outb[i] = 0;
    }

    dohash(outb, inb, keyb, forw);

    for (i = 0; i < 8; i++)
    {
        out[i] = 0;
    }

    for (i = 0; i < 64; i++)
    {
        if (outb[i])
            out[i / 8] |= (NQ_BYTE)(1 << (7 - (i % 8)));
    }
}

static
void
NQ_E_P16(
    NQ_BYTE *p14,
    NQ_BYTE *p16
   )
{
    NQ_BYTE sp8[8] = {0x4b, 0x47, 0x53, 0x21, 0x40, 0x23, 0x24, 0x25};
    smbhash(p16, sp8, p14, 1);
    smbhash(p16 + 8, sp8, p14 + 7, 1);
}

static
void
NQ_E_P24(
    NQ_BYTE *p21,
    const NQ_BYTE *c8,
    NQ_BYTE *p24
   )
{
    smbhash(p24, c8, p21, 1);
    smbhash(p24 + 8, c8, p21 + 7, 1);
    smbhash(p24 + 16, c8, p21 + 14, 1);
}

/*********************************************************************
 * MD4
 ********************************************************************/

static
NQ_UINT32
lrotate(
    NQ_UINT32 x,
    NQ_INT s
    )
{
    return ((x<<s)&0xFFFFFFFF) | (x>>(32-s));
}

static
void
copy64(
    NQ_UINT32 *M,
    NQ_BYTE *in
    )
{
    NQ_INT i;

    for (i=0;i<16;i++)
        M[i] = (NQ_UINT32)((in[i*4+3]<<24) | (in[i*4+2]<<16) | (in[i*4+1]<<8) | (in[i*4+0]<<0));
}

static
void
copy4(
    NQ_BYTE *out,
    NQ_UINT32 x
    )
{
    out[0] = (NQ_BYTE)x&0xFF;
    out[1] = (NQ_BYTE)(x>>8)&0xFF;
    out[2] = (NQ_BYTE)(x>>16)&0xFF;
    out[3] = (NQ_BYTE)(x>>24)&0xFF;
}

#define MD4_F(x,y,z) ((x&y)|((~x)&z))
#define MD4_G(x,y,z) ((x&y)|(x&z)|(y&z))
#define MD4_H(x,y,z) (x^y^z)
#define MD4_STEP1(a,b,c,d,k,s) a = lrotate(a + MD4_F(b,c,d) + in[k], s)
#define MD4_STEP2(a,b,c,d,k,s) a = lrotate(a + MD4_G(b,c,d) + in[k] + (NQ_UINT32)0x5A827999,s)
#define MD4_STEP3(a,b,c,d,k,s) a = lrotate(a + MD4_H(b,c,d) + in[k] + (NQ_UINT32)0x6ED9EBA1,s)

static
void
MD4_Transform(
        MD4Context *ctx,
        NQ_BYTE *buffer
        )
{
    NQ_UINT32 A, B, C, D;
        NQ_UINT32 in[16];

        copy64(in, buffer);

    A = ctx->a;
    B = ctx->b;
    C = ctx->c;
    D = ctx->d;

    MD4_STEP1(A,B,C,D,  0,  3);  MD4_STEP1(D,A,B,C,  1,  7);
    MD4_STEP1(C,D,A,B,  2, 11);  MD4_STEP1(B,C,D,A,  3, 19);
    MD4_STEP1(A,B,C,D,  4,  3);  MD4_STEP1(D,A,B,C,  5,  7);
    MD4_STEP1(C,D,A,B,  6, 11);  MD4_STEP1(B,C,D,A,  7, 19);
    MD4_STEP1(A,B,C,D,  8,  3);  MD4_STEP1(D,A,B,C,  9,  7);
    MD4_STEP1(C,D,A,B, 10, 11);  MD4_STEP1(B,C,D,A, 11, 19);
    MD4_STEP1(A,B,C,D, 12,  3);  MD4_STEP1(D,A,B,C, 13,  7);
    MD4_STEP1(C,D,A,B, 14, 11);  MD4_STEP1(B,C,D,A, 15, 19);
    MD4_STEP2(A,B,C,D,  0,  3);  MD4_STEP2(D,A,B,C,  4,  5);
    MD4_STEP2(C,D,A,B,  8,  9);  MD4_STEP2(B,C,D,A, 12, 13);
    MD4_STEP2(A,B,C,D,  1,  3);  MD4_STEP2(D,A,B,C,  5,  5);
    MD4_STEP2(C,D,A,B,  9,  9);  MD4_STEP2(B,C,D,A, 13, 13);
    MD4_STEP2(A,B,C,D,  2,  3);  MD4_STEP2(D,A,B,C,  6,  5);
    MD4_STEP2(C,D,A,B, 10,  9);  MD4_STEP2(B,C,D,A, 14, 13);
    MD4_STEP2(A,B,C,D,  3,  3);  MD4_STEP2(D,A,B,C,  7,  5);
    MD4_STEP2(C,D,A,B, 11,  9);  MD4_STEP2(B,C,D,A, 15, 13);
    MD4_STEP3(A,B,C,D,  0,  3);  MD4_STEP3(D,A,B,C,  8,  9);
    MD4_STEP3(C,D,A,B,  4, 11);  MD4_STEP3(B,C,D,A, 12, 15);
    MD4_STEP3(A,B,C,D,  2,  3);  MD4_STEP3(D,A,B,C, 10,  9);
    MD4_STEP3(C,D,A,B,  6, 11);  MD4_STEP3(B,C,D,A, 14, 15);
    MD4_STEP3(A,B,C,D,  1,  3);  MD4_STEP3(D,A,B,C,  9,  9);
    MD4_STEP3(C,D,A,B,  5, 11);  MD4_STEP3(B,C,D,A, 13, 15);
    MD4_STEP3(A,B,C,D,  3,  3);  MD4_STEP3(D,A,B,C, 11,  9);
    MD4_STEP3(C,D,A,B,  7, 11);  MD4_STEP3(B,C,D,A, 15, 15);

    ctx->a += A;
    ctx->b += B;
    ctx->c += C;
    ctx->d += D;
}

/*********************************************************************
 * MD5
 ********************************************************************/

#define MD5_F1(x, y, z) (z ^ (x & (y ^ z)))
#define MD5_F2(x, y, z) MD5_F1(z, x, y)
#define MD5_F3(x, y, z) (x ^ y ^ z)
#define MD5_F4(x, y, z) (y ^ (x | ~z))

#define MD5_STEP(f, w, x, y, z, data, s) \
    ( w += f(x, y, z) + data,  w = w<<s | w>>(32-s),  w += x )

static
void
MD5_Transform(
        NQ_UINT32 buf[4],
        NQ_UINT32 const in[16]
        )
{
    register NQ_UINT32 a, b, c, d;

    a = buf[0];
    b = buf[1];
    c = buf[2];
    d = buf[3];

    MD5_STEP(MD5_F1, a, b, c, d, cmHtol32(in[0]) + 0xd76aa478, 7);
    MD5_STEP(MD5_F1, d, a, b, c, cmHtol32(in[1]) + 0xe8c7b756, 12);
    MD5_STEP(MD5_F1, c, d, a, b, cmHtol32(in[2]) + 0x242070db, 17);
    MD5_STEP(MD5_F1, b, c, d, a, cmHtol32(in[3]) + 0xc1bdceee, 22);
    MD5_STEP(MD5_F1, a, b, c, d, cmHtol32(in[4]) + 0xf57c0faf, 7);
    MD5_STEP(MD5_F1, d, a, b, c, cmHtol32(in[5]) + 0x4787c62a, 12);
    MD5_STEP(MD5_F1, c, d, a, b, cmHtol32(in[6]) + 0xa8304613, 17);
    MD5_STEP(MD5_F1, b, c, d, a, cmHtol32(in[7]) + 0xfd469501, 22);
    MD5_STEP(MD5_F1, a, b, c, d, cmHtol32(in[8]) + 0x698098d8, 7);
    MD5_STEP(MD5_F1, d, a, b, c, cmHtol32(in[9]) + 0x8b44f7af, 12);
    MD5_STEP(MD5_F1, c, d, a, b, cmHtol32(in[10]) + 0xffff5bb1, 17);
    MD5_STEP(MD5_F1, b, c, d, a, cmHtol32(in[11]) + 0x895cd7be, 22);
    MD5_STEP(MD5_F1, a, b, c, d, cmHtol32(in[12]) + 0x6b901122, 7);
    MD5_STEP(MD5_F1, d, a, b, c, cmHtol32(in[13]) + 0xfd987193, 12);
    MD5_STEP(MD5_F1, c, d, a, b, cmHtol32(in[14]) + 0xa679438e, 17);
    MD5_STEP(MD5_F1, b, c, d, a, cmHtol32(in[15]) + 0x49b40821, 22);

    MD5_STEP(MD5_F2, a, b, c, d, cmHtol32(in[1]) + 0xf61e2562, 5);
    MD5_STEP(MD5_F2, d, a, b, c, cmHtol32(in[6]) + 0xc040b340, 9);
    MD5_STEP(MD5_F2, c, d, a, b, cmHtol32(in[11]) + 0x265e5a51, 14);
    MD5_STEP(MD5_F2, b, c, d, a, cmHtol32(in[0]) + 0xe9b6c7aa, 20);
    MD5_STEP(MD5_F2, a, b, c, d, cmHtol32(in[5]) + 0xd62f105d, 5);
    MD5_STEP(MD5_F2, d, a, b, c, cmHtol32(in[10]) + 0x02441453, 9);
    MD5_STEP(MD5_F2, c, d, a, b, cmHtol32(in[15]) + 0xd8a1e681, 14);
    MD5_STEP(MD5_F2, b, c, d, a, cmHtol32(in[4]) + 0xe7d3fbc8, 20);
    MD5_STEP(MD5_F2, a, b, c, d, cmHtol32(in[9]) + 0x21e1cde6, 5);
    MD5_STEP(MD5_F2, d, a, b, c, cmHtol32(in[14]) + 0xc33707d6, 9);
    MD5_STEP(MD5_F2, c, d, a, b, cmHtol32(in[3]) + 0xf4d50d87, 14);
    MD5_STEP(MD5_F2, b, c, d, a, cmHtol32(in[8]) + 0x455a14ed, 20);
    MD5_STEP(MD5_F2, a, b, c, d, cmHtol32(in[13]) + 0xa9e3e905, 5);
    MD5_STEP(MD5_F2, d, a, b, c, cmHtol32(in[2]) + 0xfcefa3f8, 9);
    MD5_STEP(MD5_F2, c, d, a, b, cmHtol32(in[7]) + 0x676f02d9, 14);
    MD5_STEP(MD5_F2, b, c, d, a, cmHtol32(in[12]) + 0x8d2a4c8a, 20);

    MD5_STEP(MD5_F3, a, b, c, d, cmHtol32(in[5]) + 0xfffa3942, 4);
    MD5_STEP(MD5_F3, d, a, b, c, cmHtol32(in[8]) + 0x8771f681, 11);
    MD5_STEP(MD5_F3, c, d, a, b, cmHtol32(in[11]) + 0x6d9d6122, 16);
    MD5_STEP(MD5_F3, b, c, d, a, cmHtol32(in[14]) + 0xfde5380c, 23);
    MD5_STEP(MD5_F3, a, b, c, d, cmHtol32(in[1]) + 0xa4beea44, 4);
    MD5_STEP(MD5_F3, d, a, b, c, cmHtol32(in[4]) + 0x4bdecfa9, 11);
    MD5_STEP(MD5_F3, c, d, a, b, cmHtol32(in[7]) + 0xf6bb4b60, 16);
    MD5_STEP(MD5_F3, b, c, d, a, cmHtol32(in[10]) + 0xbebfbc70, 23);
    MD5_STEP(MD5_F3, a, b, c, d, cmHtol32(in[13]) + 0x289b7ec6, 4);
    MD5_STEP(MD5_F3, d, a, b, c, cmHtol32(in[0]) + 0xeaa127fa, 11);
    MD5_STEP(MD5_F3, c, d, a, b, cmHtol32(in[3]) + 0xd4ef3085, 16);
    MD5_STEP(MD5_F3, b, c, d, a, cmHtol32(in[6]) + 0x04881d05, 23);
    MD5_STEP(MD5_F3, a, b, c, d, cmHtol32(in[9]) + 0xd9d4d039, 4);
    MD5_STEP(MD5_F3, d, a, b, c, cmHtol32(in[12]) + 0xe6db99e5, 11);
    MD5_STEP(MD5_F3, c, d, a, b, cmHtol32(in[15]) + 0x1fa27cf8, 16);
    MD5_STEP(MD5_F3, b, c, d, a, cmHtol32(in[2]) + 0xc4ac5665, 23);

    MD5_STEP(MD5_F4, a, b, c, d, cmHtol32(in[0]) + 0xf4292244, 6);
    MD5_STEP(MD5_F4, d, a, b, c, cmHtol32(in[7]) + 0x432aff97, 10);
    MD5_STEP(MD5_F4, c, d, a, b, cmHtol32(in[14]) + 0xab9423a7, 15);
    MD5_STEP(MD5_F4, b, c, d, a, cmHtol32(in[5]) + 0xfc93a039, 21);
    MD5_STEP(MD5_F4, a, b, c, d, cmHtol32(in[12]) + 0x655b59c3, 6);
    MD5_STEP(MD5_F4, d, a, b, c, cmHtol32(in[3]) + 0x8f0ccc92, 10);
    MD5_STEP(MD5_F4, c, d, a, b, cmHtol32(in[10]) + 0xffeff47d, 15);
    MD5_STEP(MD5_F4, b, c, d, a, cmHtol32(in[1]) + 0x85845dd1, 21);
    MD5_STEP(MD5_F4, a, b, c, d, cmHtol32(in[8]) + 0x6fa87e4f, 6);
    MD5_STEP(MD5_F4, d, a, b, c, cmHtol32(in[15]) + 0xfe2ce6e0, 10);
    MD5_STEP(MD5_F4, c, d, a, b, cmHtol32(in[6]) + 0xa3014314, 15);
    MD5_STEP(MD5_F4, b, c, d, a, cmHtol32(in[13]) + 0x4e0811a1, 21);
    MD5_STEP(MD5_F4, a, b, c, d, cmHtol32(in[4]) + 0xf7537e82, 6);
    MD5_STEP(MD5_F4, d, a, b, c, cmHtol32(in[11]) + 0xbd3af235, 10);
    MD5_STEP(MD5_F4, c, d, a, b, cmHtol32(in[2]) + 0x2ad7d2bb, 15);
    MD5_STEP(MD5_F4, b, c, d, a, cmHtol32(in[9]) + 0xeb86d391, 21);


    buf[0] += a;
    buf[1] += b;
    buf[2] += c;
    buf[3] += d;
}

static
void
MD5_Init(
    MD5Context *ctx
    )
{
    ctx->buf[0] = 0x67452301;
    ctx->buf[1] = 0xefcdab89;
    ctx->buf[2] = 0x98badcfe;
    ctx->buf[3] = 0x10325476;

    ctx->bits[0] = 0;
    ctx->bits[1] = 0;
}

static
void
MD5_Update(
    MD5Context *ctx,
    const NQ_BYTE *buf,
    NQ_UINT len
    )
{
    NQ_UINT32 t;

    t = ctx->bits[0];
    if ((ctx->bits[0] = t + ((NQ_UINT32)len << 3)) < t)
        ctx->bits[1]++;
    ctx->bits[1] += len >> 29;

    t = (t >> 3) & 0x3f;

    if (t) 
    {
        NQ_BYTE *p = (NQ_BYTE *) ctx->in + t;

        t = 64-t;
        if (len < t) 
        {
            syMemmove(p, buf, len);
            return;
        }
        syMemmove(p, buf, t);
        MD5_Transform(ctx->buf, (NQ_UINT32 *) ctx->in);
        buf += t;
        len -= t;
    }

    while (len >= 64) 
    {
        syMemmove(ctx->in, buf, 64);
        MD5_Transform(ctx->buf, (NQ_UINT32 *) ctx->in);
        buf += 64;
        len -= 64;
    }

    syMemmove(ctx->in, buf, len);
}

static
void
MD5_Final(
    MD5Context *ctx,
    NQ_BYTE *digest
    )
{
    NQ_UINT count, i;
    NQ_BYTE *p;
  
    count = (ctx->bits[0] >> 3) & 0x3F;

    p = ctx->in + count;
    *p++ = 0x80;

    count = 64 - 1 - count;

    if (count < 8) 
    {
        syMemset(p, 0, count);
        MD5_Transform(ctx->buf, (NQ_UINT32 *) ctx->in);

        syMemset(ctx->in, 0, 56);
    } 
    else 
    {
        syMemset(p, 0, count-8);
    }

    ((NQ_UINT32 *) ctx->in)[14] = cmHtol32(ctx->bits[0]);
    ((NQ_UINT32 *) ctx->in)[15] = cmHtol32(ctx->bits[1]);

    MD5_Transform(ctx->buf, (NQ_UINT32 *) ctx->in);
    
    for(i = 0; i < 4; i++)
        ctx->buf[i] = cmHtol32(ctx->buf[i]);
    
    syMemmove(digest, ctx->buf, 16);
    syMemset(ctx, 0, sizeof(ctx));
}

/*********************************************************************
 * HMAC_MD5
 ********************************************************************/

#define EVP_MAX_MD_SIZE         (16+20)

static
void
HMACMD5_Init(
    HMAC_MD5Context *ctx,
    const NQ_BYTE *key,
    NQ_UINT len
    )
{
    NQ_INT i;

    syMemset(ctx->iPad, 0, sizeof(ctx->iPad));
    syMemset(ctx->oPad, 0, sizeof(ctx->iPad));
    syMemcpy(ctx->iPad, key, len);
    syMemcpy(ctx->oPad, key, len);

    for (i=0; i<HMAC_MAX_MD_CBLOCK; i++) {
        ctx->iPad[i] ^= 0x36;
        ctx->oPad[i] ^= 0x5c;
    }

    MD5_Init(&ctx->md5);
    MD5_Update(&ctx->md5, ctx->iPad, 64);
}

static
void
HMACMD5_Init_RFC2104(
    HMAC_MD5Context *ctx,
    const NQ_BYTE *key,
    NQ_UINT len
    )
{
    NQ_BYTE tmp[16];

    if (len > 64)
    {
        MD5Context md5;

        MD5_Init(&md5);
        MD5_Update(&md5, key, len);
        MD5_Final(&md5, tmp);
        key = tmp;
        len = 16;
    }

    HMACMD5_Init(ctx, key, len);
}

static
void
HMACMD5_Update(
    HMAC_MD5Context *ctx,
    const NQ_BYTE *data,
    NQ_UINT len
    )
{
    MD5_Update(&(ctx->md5), data, len);
}

static
void
HMACMD5_Final(
    HMAC_MD5Context *ctx,
    NQ_BYTE *md
    )
{
    MD5Context tempCtx;

    MD5_Final(&ctx->md5, md);

    MD5_Init(&tempCtx);
    MD5_Update(&tempCtx, ctx->oPad, 64);
    MD5_Update(&tempCtx, md, 16);
    MD5_Final(&tempCtx ,md);
}

/*
 *====================================================================
 * PURPOSE: Crypt using ARC4 algorithm
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT data
 *          IN data length
 *          IN key
 *          IN key length
 *
 * RETURNS: none
 *
 * NOTES:   none
 *====================================================================
 */
void
cmArcfourCrypt(
    NQ_BYTE* data,
    NQ_UINT dataLen,
    const NQ_BYTE *key,
    NQ_UINT keyLen
    )
{
    NQ_BYTE sBox[258];
    NQ_BYTE idxI = 0, idxJ = 0, j = 0;
    NQ_UINT idx;

    for (idx = 0; idx < 256; idx++)
    {
        sBox[idx] = (NQ_BYTE)idx;
    }
    for (idx = 0; idx < 256; idx++)
    {
        NQ_BYTE tc;

        j = (NQ_BYTE)(j + sBox[idx] + key[idx % keyLen]);

        tc = sBox[idx];
        sBox[idx] = sBox[j];
        sBox[j] = tc;
    }
    sBox[257] = sBox[256] = 0;

    for (idx = 0; idx < dataLen; idx++)
    {
        NQ_BYTE tc;
        NQ_BYTE t;

        idxI = (idxI == 255) ? 0 : idxI + 1;
        idxJ = (NQ_BYTE)(idxJ + sBox[idxI]);
        tc = sBox[idxI];
        sBox[idxI] = sBox[idxJ];
        sBox[idxJ] = tc;
        t = (NQ_BYTE)(sBox[idxI] + sBox[idxJ]);
        data[idx] = data[idx] ^ sBox[t];
    }
    sBox[256] = idxI;
    sBox[257] = idxJ;
}

/*
 *====================================================================
 * PURPOSE: Generate NTLMv2 session key
 *--------------------------------------------------------------------
 * PARAMS:  IN start of the client response
 *          IN pointer to NTLM hashed password
 *          IN/OUT encrypted password
 *
 * RETURNS: none
 *
 * NOTES:   none
 *====================================================================
 */

void
cmGenerateNTLMv2SessionKey(
    const NQ_BYTE* v2hash,
    const NQ_BYTE* encrypted,
    NQ_BYTE* out
    )
{
    HMAC_MD5Context ctx;

    TRCB();

    HMACMD5_Init(&ctx, v2hash, 16);
    HMACMD5_Update(&ctx, encrypted, 16);
    HMACMD5_Final(&ctx, out);

    TRCE();
}

/*
 *====================================================================
 * PURPOSE: Generate random byte sequence
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT buffer
 *          IN  buffer size
 *
 * RETURNS: none
 *
 * NOTES:   none
 *====================================================================
 */

void
cmCreateRandomByteSequence(
    NQ_BYTE *buffer,
    NQ_UINT32 size
    )
{
    for (; size > 0; --size, ++buffer)
        *buffer = (NQ_BYTE)syRand();
}

void cmSmbCalculateMessageSignature(
    const NQ_BYTE *key,
    NQ_UINT keyLen,
    NQ_UINT32      sequence,
    const NQ_BYTE *buffer1,
    NQ_UINT size1,
    const NQ_BYTE *buffer2,
    NQ_UINT size2,
    const NQ_BYTE *password,
    NQ_COUNT       passwordLen,
    NQ_BYTE *signature
    )
{
    MD5Context ctx;
    NQ_BYTE hash[16];
    NQ_UINT32 sn = cmHtol32(sequence);

    TRCB();
    
    syMemset(&ctx, 0, sizeof(MD5Context));
    
    TRC("seq: %ld", sequence);
    TRCDUMP("key", key, (NQ_UINT)keyLen);

    syMemset(signature, 0, SMB_SECURITY_SIGNATURE_LENGTH);
    cmPutUint32(signature, sn);

    MD5_Init(&ctx);
    MD5_Update(&ctx, key, keyLen);
    if (NULL != password)
    {
        TRC1P("password: length = %d", passwordLen);
        TRCDUMP("password", password, (NQ_UINT)passwordLen);

        MD5_Update(&ctx, password, passwordLen);
    }
    MD5_Update(&ctx, buffer1, size1);
    if (NULL != buffer2)
        MD5_Update(&ctx, buffer2, size2);
    MD5_Final(&ctx, hash);

    syMemcpy(signature, hash, SMB_SECURITY_SIGNATURE_LENGTH);

    TRCDUMP("signature", signature, SMB_SECURITY_SIGNATURE_LENGTH);

    TRCE();
}

#ifdef UD_NQ_INCLUDESMB2

#define SHA256_DIGEST_SIZE 32
#define SHA256_BLOCK_SIZE  64

#define SHFR(x, n)    (x >> n)
#define ROTR(x, n)   ((x >> n) | (x << ((sizeof(x) << 3) - n)))
#define ROTL(x, n)   ((x << n) | (x >> ((sizeof(x) << 3) - n)))
#define CH(x, y, z)  ((x & y) ^ (~x & z))
#define MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))

#define SHA256_F1(x) (ROTR(x,  2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define SHA256_F2(x) (ROTR(x,  6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SHA256_F3(x) (ROTR(x,  7) ^ ROTR(x, 18) ^ SHFR(x,  3))
#define SHA256_F4(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ SHFR(x, 10))

#define UNPACK32(x, str)                      \
{                                             \
    *((str) + 3) = (NQ_BYTE) ((x)      );       \
    *((str) + 2) = (NQ_BYTE) ((x) >>  8);       \
    *((str) + 1) = (NQ_BYTE) ((x) >> 16);       \
    *((str) + 0) = (NQ_BYTE) ((x) >> 24);       \
}

#define PACK32(str, x)                        \
{                                             \
    *(x) =   ((NQ_UINT32) *((str) + 3)      )    \
           | ((NQ_UINT32) *((str) + 2) <<  8)    \
           | ((NQ_UINT32) *((str) + 1) << 16)    \
           | ((NQ_UINT32) *((str) + 0) << 24);   \
}

NQ_UINT32 sha256_h0[8] =
            {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
             0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

NQ_UINT32 sha256_k[64] =
            {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
             0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
             0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
             0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
             0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
             0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
             0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
             0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
             0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
             0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
             0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
             0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
             0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
             0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
             0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
             0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

typedef struct {
    NQ_UINT tot_len;
    NQ_UINT len;
    NQ_BYTE block[2 * SHA256_BLOCK_SIZE];
    NQ_UINT32 h[8];
} sha256_ctx;

static void sha256_transf(sha256_ctx *ctx, const NQ_BYTE *message, NQ_UINT block_nb)
{
    NQ_UINT32 w[64];
    NQ_UINT32 wv[8];
    NQ_UINT32 t1, t2;
    const NQ_BYTE *sub_block;
    NQ_UINT i, j;

    for (i = 0; i < (int) block_nb; i++) {
        sub_block = message + (i << 6);

        for (j = 0; j < 16; j++) {
            PACK32(&sub_block[j << 2], &w[j]);
        }

        for (j = 16; j < 64; j++) {
            w[j] =  SHA256_F4(w[j - 2]) + w[j - 7] + SHA256_F3(w[j - 15]) + w[j - 16];
        }

        for (j = 0; j < 8; j++) {
            wv[j] = ctx->h[j];
        }

        for (j = 0; j < 64; j++) {
            t1 = wv[7] + SHA256_F2(wv[4]) + CH(wv[4], wv[5], wv[6])
                + sha256_k[j] + w[j];
            t2 = SHA256_F1(wv[0]) + MAJ(wv[0], wv[1], wv[2]);
            wv[7] = wv[6];
            wv[6] = wv[5];
            wv[5] = wv[4];
            wv[4] = wv[3] + t1;
            wv[3] = wv[2];
            wv[2] = wv[1];
            wv[1] = wv[0];
            wv[0] = t1 + t2;
        }

        for (j = 0; j < 8; j++) {
            ctx->h[j] += wv[j];
        }
    }
}

#if 0
static void sha256(const NQ_BYTE *message, NQ_UINT len, NQ_BYTE *digest)
{
    sha256_ctx ctx;

    sha256_init(&ctx);
    sha256_update(&ctx, message, len);
    sha256_final(&ctx, digest);
}
#endif

static void sha256_init(sha256_ctx *ctx)
{
    NQ_UINT i;

    for (i = 0; i < 8; i++) {
        ctx->h[i] = sha256_h0[i];
    }

    ctx->len = 0;
    ctx->tot_len = 0;
}

static void sha256_update(sha256_ctx *ctx, const NQ_BYTE *message, NQ_UINT len)
{
    NQ_UINT block_nb, new_len, rem_len, tmp_len;
    const NQ_BYTE *shifted_message;

    tmp_len = SHA256_BLOCK_SIZE - ctx->len;
    rem_len = len < tmp_len ? len : tmp_len;

    syMemcpy(&ctx->block[ctx->len], message, rem_len);

    if (ctx->len + len < SHA256_BLOCK_SIZE) {
        ctx->len += len;
        return;
    }

    new_len = len - rem_len;
    block_nb = new_len / SHA256_BLOCK_SIZE;

    shifted_message = message + rem_len;

    sha256_transf(ctx, ctx->block, 1);
    sha256_transf(ctx, shifted_message, block_nb);

    rem_len = new_len % SHA256_BLOCK_SIZE;

    syMemcpy(ctx->block, &shifted_message[block_nb << 6], rem_len);

    ctx->len = rem_len;
    ctx->tot_len += (block_nb + 1) << 6;
}

static void sha256_final(sha256_ctx *ctx, NQ_BYTE *digest)
{
    NQ_UINT block_nb, pm_len, len_b, i;

    block_nb = (1 + ((SHA256_BLOCK_SIZE - 9)
                     < (ctx->len % SHA256_BLOCK_SIZE)));

    len_b = (ctx->tot_len + ctx->len) << 3;
    pm_len = block_nb << 6;

    syMemset(ctx->block + ctx->len, 0, pm_len - ctx->len);
    ctx->block[ctx->len] = 0x80;
    UNPACK32(len_b, ctx->block + pm_len - 4);

    sha256_transf(ctx, ctx->block, block_nb);

    for (i = 0 ; i < 8; i++) {
        UNPACK32(ctx->h[i], &digest[i << 2]);
    }
}

void cmSmb2CalculateMessageSignature(
    const NQ_BYTE *key,
    NQ_UINT keyLen,
    const NQ_BYTE *buffer1,
    NQ_UINT size1,
    const NQ_BYTE *buffer2,
    NQ_UINT size2,
    NQ_BYTE *signature
    )
{
    /* signature buffer must be 16 bytes long */
    sha256_ctx ctx;
    NQ_BYTE ipad[SHA256_BLOCK_SIZE];
    NQ_BYTE opad[SHA256_BLOCK_SIZE];
    NQ_BYTE hash[SHA256_DIGEST_SIZE];
    NQ_UINT i;

    LOGFB(CM_TRC_LEVEL_FUNC_TOOL);
    
    TRCDUMP("key", key, (NQ_UINT)keyLen);

    syMemset(ipad, 0x36, sizeof(ipad));
    syMemset(opad, 0x5C, sizeof(opad));

    for (i = 0; i < keyLen; ++i)
    {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }

    syMemset(signature, 0, SMB2_SECURITY_SIGNATURE_SIZE);

    /* inner */
    sha256_init(&ctx);
    sha256_update(&ctx, ipad, sizeof(ipad));
    sha256_update(&ctx, buffer1, size1);
    if (buffer2 != NULL)
        sha256_update(&ctx, buffer2, size2);
    sha256_final(&ctx, hash);

    /* outer */
    sha256_init(&ctx);
    sha256_update(&ctx, opad, sizeof(opad));
    sha256_update(&ctx, hash, sizeof(hash));
    sha256_final(&ctx, hash);

    syMemcpy(signature, hash, SMB2_SECURITY_SIGNATURE_SIZE);
    TRCDUMP("signature", signature, SMB2_SECURITY_SIGNATURE_SIZE);

    LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
}
#endif /* UD_NQ_INCLUDESMB2 */


/* generate session key and next client and server challenge */
void cmGenerateNetlogonCredentials
(
    const NQ_BYTE *clientChallenge,
    const NQ_BYTE *serverChallenge,
    const NQ_BYTE *key,
    NQ_BYTE *clientChallengeNew,
    NQ_BYTE *serverChallengeNew,
    NQ_BYTE *sessKey
    )
{
    NQ_BYTE zero[4], tmp[16];
    HMAC_MD5Context ctx;
    MD5Context md5;
    
    /* Generate the session key */

    syMemset(sessKey, 0, 16);
    syMemset(zero, 0, sizeof(zero));
    
    HMACMD5_Init_RFC2104(&ctx, key, 16);
    MD5_Init(&md5);
    MD5_Update(&md5, zero, sizeof(zero));
    MD5_Update(&md5, clientChallenge, 8);
    MD5_Update(&md5, serverChallenge, 8);
    MD5_Final(&md5, tmp);
    HMACMD5_Update(&ctx, tmp, sizeof(tmp));
    HMACMD5_Final(&ctx, sessKey);

    /* Generate the next client and server creds. */
    
    cmDES112(clientChallengeNew, clientChallenge, sessKey);          
    cmDES112(serverChallengeNew, serverChallenge, sessKey); 
}

void 
cmDES112(
    NQ_BYTE *out, 
    const NQ_BYTE *in, 
    const NQ_BYTE *key
    )
{
    NQ_BYTE tmp[8];
    
    smbhash(tmp, in, key, 1);
    smbhash(out, tmp, key + 7, 1);
}

/*
 *====================================================================
 * PURPOSE: Create signing context  SMB
 *--------------------------------------------------------------------
 * PARAMS:  
 *          IN/OUT MD5 context
 *          IN     session key 
 *          IN     session key length
 *          IN     client response data (password)
 *          IN     client response data length (password length)
 *
 * RETURNS: none
 *
 * NOTES:   none
 *====================================================================
 */

void 
cmCreateSigningContext(
    MD5Context    *ctx,
    const NQ_BYTE *key,
    NQ_COUNT       keyLen,
    const NQ_BYTE *password,
    NQ_COUNT       passwordLen    
)
{
    TRCB(); 

    syMemset(ctx, 0, sizeof(MD5Context));
   
    MD5_Init(ctx);
    MD5_Update(ctx, key, keyLen);
    if (NULL != password)
        MD5_Update(ctx, password, passwordLen);

    TRCE();
}


/*
 *====================================================================
 * PURPOSE: Create message authentication code using saved MD5 context
 *--------------------------------------------------------------------
 * PARAMS:  IN     saved MD5 context
 *          IN     message sequence number
 *          IN     data buffer
 *          IN     data length
 *          IN/OUT message signature (pointer inside data buffer)
 *
 * RETURNS: none
 *
 * NOTES:   none
 *====================================================================
 */

void
cmCreateMACByContext(
    MD5Context    *ctx,    
    NQ_UINT32      sequence,
    const NQ_BYTE *data,          
    NQ_UINT        length,
    NQ_BYTE       *signature
    )
{
    NQ_BYTE hash[16];
    NQ_UINT32 sn = cmHtol32(sequence);

    TRCB();
    
    syMemset(signature, 0, SMB_SECURITY_SIGNATURE_LENGTH);
    cmPutUint32(signature, sn);

    MD5_Update(ctx, data, length);
    MD5_Final(ctx, hash);

    syMemcpy(signature, hash, SMB_SECURITY_SIGNATURE_LENGTH);

    TRCDUMP("signature", signature, SMB_SECURITY_SIGNATURE_LENGTH);

    TRCE();
}


/*
 *====================================================================
 * PURPOSE: Check message authentication code using saved MD5 context
 *--------------------------------------------------------------------
 * PARAMS:  IN     saved MD5 context
 *          IN     message sequence number
 *          IN     data buffer
 *          IN     data length
 *          IN     message signature (pointer inside data buffer)
 *
 * RETURNS: TRUE for valid signature, FALSE otherwise
 *
 * NOTES:   none
 *====================================================================
 */

NQ_BOOL
cmCheckMACByContext(
    MD5Context    *ctx,    
    NQ_UINT32      sequence,
    const NQ_BYTE *data,
    NQ_UINT        length,
    NQ_BYTE       *signature
    )
{
    NQ_BYTE temp[SMB_SECURITY_SIGNATURE_LENGTH];

    syMemcpy(temp, signature, SMB_SECURITY_SIGNATURE_LENGTH);   
    cmCreateMACByContext(ctx, sequence, data, length, signature);

    return syMemcmp(temp, signature, SMB_SECURITY_SIGNATURE_LENGTH) == 0;
}


