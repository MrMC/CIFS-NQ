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
#include "cmbufman.h"

#ifdef UD_NQ_INCLUDESMB2
#include "cmsmb2.h"
#endif

/* 	#define AES_SMALL_TABLES */ /* for AES GCM - when uncommented it will use less memory and more operations.*/

/* pointers to crypters that may be changed to external ones */

static void md4Internal(const NQ_BYTE * dataIn, NQ_BYTE * dataOut, NQ_COUNT length);
static void md5Internal(const CMBlob * key, const CMBlob * key1, const CMBlob dataFragments[], NQ_COUNT numFragments, NQ_BYTE * buffer, NQ_COUNT bufferSize);
static void hmacmd5Internal(const CMBlob * key, const CMBlob * key1, const CMBlob dataFragments[], NQ_COUNT numFragments, NQ_BYTE * buffer, NQ_COUNT bufferSize);
#ifdef UD_NQ_INCLUDESMB2
static void sha256Internal(const CMBlob * key, const CMBlob * key1, const CMBlob dataFragments[], NQ_COUNT numFragments, NQ_BYTE * buffer, NQ_COUNT bufferSize);
#ifdef UD_NQ_INCLUDESMB3
static void sha512Internal(const CMBlob * key, const CMBlob * key1, const CMBlob dataFragments[], NQ_COUNT numFragments, NQ_BYTE * buffer, NQ_COUNT bufferSize, NQ_BYTE *sha512_CtxBuf);
static void aes128cmacInternal(const CMBlob * key, const CMBlob * key1, const CMBlob dataFragments[], NQ_COUNT numFragments, NQ_BYTE * buffer, NQ_COUNT bufferSize);
static void aes128ccmEncryptionInternal(const CMBlob * key, const CMBlob * key1, const CMBlob * prefix, CMBlob * message, NQ_BYTE * auth);
static NQ_BOOL aes128ccmDecryptionInternal(const CMBlob * key, const CMBlob * key1, const CMBlob * prefix, CMBlob * message, const NQ_BYTE * auth);
static void aes128GcmEncryptInternal(const CMBlob *key, const CMBlob *key1, const CMBlob *prefix, CMBlob *message, NQ_BYTE *auth, NQ_BYTE *keyBuffer, NQ_BYTE *encMsgBuffer);
static NQ_BOOL aes128GcmDecryptInternal(const CMBlob *key, const CMBlob *key1, const CMBlob *prefix, CMBlob *message, const NQ_BYTE * auth, NQ_BYTE *keyBuffer, NQ_BYTE *encMsgBuffer);
#endif /* UD_NQ_INCLUDESMB3 */
#endif /* UD_NQ_INCLUDESMB2 */

void
cmArcfourPrepareState(
    const NQ_BYTE *key,
    NQ_UINT keyLen,
	NQ_BYTE * state
    );
void
cmArcfourCryptWithState(
    NQ_BYTE* data,
    NQ_UINT dataLen,
	NQ_BYTE * state
    );

#define NTLM_CLIENT_SIGN_CONST "session key to client-to-server signing key magic constant"
#define NTLM_CLIENT_SEAL_CONST "session key to client-to-server sealing key magic constant"
#define NTLM_SERVER_SIGN_CONST "session key to server-to-client signing key magic constant"
#define NTLM_SERVER_SEAL_CONST "session key to server-to-client sealing key magic constant"

static const CMCrypterList internalCrypters = 
{
	md4Internal, 
	md5Internal,
	hmacmd5Internal,
#ifdef UD_NQ_INCLUDESMB2
	sha256Internal,
#ifdef UD_NQ_INCLUDESMB3
	aes128cmacInternal,
	sha512Internal,
	aes128ccmEncryptionInternal,  
	aes128ccmDecryptionInternal,
	aes128GcmEncryptInternal,
	aes128GcmDecryptInternal
#else /* UD_NQ_INCLUDESMB3 */
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL
#endif /* UD_NQ_INCLUDESMB3 */
#else /* UD_NQ_INCLUDESMB2 */
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL
#endif /* UD_NQ_INCLUDESMB2 */
};

static CMCrypterList currentCrypters = 
{
	md4Internal, 
	md5Internal,
	hmacmd5Internal,
#ifdef UD_NQ_INCLUDESMB2
	sha256Internal,
#ifdef UD_NQ_INCLUDESMB3
	aes128cmacInternal,
	sha512Internal,
	aes128ccmEncryptionInternal, 
	aes128ccmDecryptionInternal,
	aes128GcmEncryptInternal,
	aes128GcmDecryptInternal
#else /* UD_NQ_INCLUDESMB3 */
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL
#endif /* UD_NQ_INCLUDESMB3 */
#else /* UD_NQ_INCLUDESMB2 */
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL
#endif /* UD_NQ_INCLUDESMB2 */
};

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
/*static void HMACMD5_Init_RFC2104(HMAC_MD5Context *ctx, const NQ_BYTE *key, NQ_UINT len);*/
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

void cmSetExternalCrypters(const CMCrypterList * newCrypters)
{
	if (newCrypters->md4 != NULL)
		currentCrypters.md4 = newCrypters->md4;
	if (newCrypters->md5 != NULL)
		currentCrypters.md5 = newCrypters->md5;
	if (newCrypters->hmacmd5 != NULL)
		currentCrypters.hmacmd5 = newCrypters->hmacmd5;
	if (newCrypters->sha256 != NULL)
		currentCrypters.sha256 = newCrypters->sha256;
	if (newCrypters->aes128cmac != NULL)
		currentCrypters.aes128cmac = newCrypters->aes128cmac;
	if (newCrypters->sha512 != NULL)
		currentCrypters.sha512 = newCrypters->sha512;
	if (newCrypters->aes128ccmEncryption != NULL)
		currentCrypters.aes128ccmEncryption = newCrypters->aes128ccmEncryption;
	if (newCrypters->aes128ccmDecryption != NULL)
		currentCrypters.aes128ccmDecryption = newCrypters->aes128ccmDecryption;
	if (newCrypters->aes128gcmEncryption != NULL)
		currentCrypters.aes128gcmEncryption = newCrypters->aes128gcmEncryption;
	if (newCrypters->aes128gcmDecryption != NULL)
		currentCrypters.aes128gcmDecryption = newCrypters->aes128gcmDecryption;
}

void cmResetExternalCrypters(void)
{
	currentCrypters = internalCrypters;
}

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
	(*currentCrypters.md4)(in, out, n);
}

static void md4Internal(const NQ_BYTE * in, NQ_BYTE * out, NQ_COUNT n)
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
        MD4_Transform(&ctx, (NQ_BYTE *)in);
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
	CMBlob	fragment;
	
	fragment.data = in;
	fragment.len = n;

	(*currentCrypters.md5)(NULL , NULL , &fragment , 1 ,out , 16);
}

static void md5Internal(const CMBlob * key, const CMBlob * key1, const CMBlob dataFragments[], NQ_COUNT numFragments, NQ_BYTE * buffer, NQ_COUNT bufferSize)
{
    MD5Context ctx;
    NQ_COUNT i;

    MD5_Init(&ctx);
    for (i = 0; i < numFragments; i++)
    {
    	if (dataFragments[i].data != NULL && dataFragments[i].len > 0 )
    		MD5_Update(&ctx , dataFragments[i].data , dataFragments[i].len);
    }
    MD5_Final(&ctx, buffer);
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
	CMBlob fragments[1];
	CMBlob keyBlob;

	fragments[0].data = (NQ_BYTE *)data;
	fragments[0].len = data_len;
	keyBlob.data = (NQ_BYTE *)key;
	keyBlob.len = key_len;

	(*currentCrypters.hmacmd5)(&keyBlob, NULL, fragments, 1, md, 16);
}

static void hmacmd5Internal(const CMBlob * key, const CMBlob * key1, const CMBlob dataFragments[], NQ_COUNT numFragments, NQ_BYTE * buffer, NQ_COUNT bufferSize)
{
    HMAC_MD5Context ctx;
	NQ_COUNT i;

	/* key1 and bufferSize are not used */
    HMACMD5_Init(&ctx, key->data, key->len);
    for (i = 0; i < numFragments; i++)
    	if (dataFragments[i].data != NULL && dataFragments[i].len > 0 )
    		HMACMD5_Update(&ctx, dataFragments[i].data, dataFragments[i].len);
    HMACMD5_Final(&ctx, buffer);
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
    const NQ_WCHAR *domain,
    NQ_BOOL caseSensitiveDomain,
    const NQ_WCHAR *user,
    const NQ_BYTE  *password,
    NQ_UINT pwdlen,
    NQ_BYTE *hash
   )
{
    NQ_WCHAR data[CM_BUFFERLENGTH(NQ_WCHAR, CM_USERNAMELENGTH + CM_NQ_HOSTNAMESIZE)];

    cmWStrcpy(data, user);

    if (caseSensitiveDomain)
        cmWStrupr(data);

    cmWStrcpy(data + cmWStrlen(data), domain);

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
 * PURPOSE: Encrypt hashed NTLM password
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
 * PURPOSE: Encrypt hashed NTLM password
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
    NQ_BYTE coKey[16];  /* new key */

    if (doMd5)
    {
    	CMBlob fragments[2];
		
		fragments[0].data = password+516;
		fragments[0].len = 16;
		fragments[1].data = (NQ_BYTE *)key;
		fragments[1].len = SMB_SESSIONKEY_LENGTH;
    	(*currentCrypters.md5)(NULL, NULL, fragments, 2, coKey, 16);
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
 * PURPOSE: Encrypt hashed NTLM password v2
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
    CMBlob  v2Hkey;
	CMBlob	fragments[2];
	v2Hkey.data = (NQ_BYTE *)v2hash;
	v2Hkey.len = 16;
	fragments[0].data = (NQ_BYTE *)key;
	fragments[0].len = 8;
	fragments[1].data = (NQ_BYTE *)blob;
	fragments[1].len = bloblen;

    (*currentCrypters.hmacmd5)(&v2Hkey, NULL, fragments, 2, encrypted, CM_CRYPT_ENCLMv2HMACSIZE);
    *enclen = CM_CRYPT_ENCLMv2HMACSIZE;
}

void
cmCalculateNtlmSigningKey(
	NQ_BYTE	* sessionKey,
	NQ_BYTE * outKey,
	NQ_UINT16 flag
	)
{
	CMBlob		fragments[2];

	switch (flag)
	{
	case CM_CRYPT_NTLM_TO_SERVER_SIGNING:
	{
		fragments[0].data = (NQ_BYTE *)sessionKey;
		fragments[0].len = SMB_SESSIONKEY_LENGTH;
		fragments[1].data = (NQ_BYTE *)NTLM_CLIENT_SIGN_CONST;
		fragments[1].len = (NQ_COUNT)syStrlen((NQ_CHAR *)NTLM_CLIENT_SIGN_CONST) + 1;
		(*currentCrypters.md5)(NULL , NULL , fragments , 2 ,outKey , SMB_SESSIONKEY_LENGTH);
	}
	break;
	case CM_CRYPT_NTLM_FROM_SERVER_SIGNING:
	{
		fragments[0].data = (NQ_BYTE *)sessionKey;
		fragments[0].len = SMB_SESSIONKEY_LENGTH;
		fragments[1].data = (NQ_BYTE *)NTLM_SERVER_SIGN_CONST;
		fragments[1].len = (NQ_COUNT)syStrlen((NQ_CHAR *)NTLM_SERVER_SIGN_CONST) + 1;
		(*currentCrypters.md5)(NULL , NULL , fragments , 2 ,outKey , SMB_SESSIONKEY_LENGTH);
	}
	break;
	case CM_CRYPT_NTLM_TO_SERVER_SEALING:
	{
		NQ_BYTE digest[16];
		fragments[0].data = (NQ_BYTE *)sessionKey;
		fragments[0].len = SMB_SESSIONKEY_LENGTH;
		fragments[1].data = (NQ_BYTE *)NTLM_CLIENT_SEAL_CONST;
		fragments[1].len = (NQ_COUNT)syStrlen((NQ_CHAR *)NTLM_CLIENT_SEAL_CONST) + 1;
		(*currentCrypters.md5)(NULL , NULL , fragments , 2 ,digest , SMB_SESSIONKEY_LENGTH);

		cmArcfourPrepareState(digest , 16 , outKey);
	}
	break;
	case CM_CRYPT_NTLM_FROM_SERVER_SEALING:
	{
		NQ_BYTE digest[16];
		fragments[0].data = (NQ_BYTE *)sessionKey;
		fragments[0].len = SMB_SESSIONKEY_LENGTH;
		fragments[1].data = (NQ_BYTE *)NTLM_SERVER_SEAL_CONST;
		fragments[1].len = (NQ_COUNT)syStrlen((NQ_CHAR *)NTLM_SERVER_SEAL_CONST) + 1;
		(*currentCrypters.md5)(NULL , NULL , fragments , 2 ,digest , SMB_SESSIONKEY_LENGTH);

		cmArcfourPrepareState(digest , 16 , outKey);
	}
	break;
	default:
		LOGERR(CM_TRC_LEVEL_ERROR, "  illegal flag");
	}
}

void
cmCalculateDcerpcSignature(
	NQ_BYTE	* data,
	NQ_UINT16 dataLen,
	NQ_BYTE * signingKey,
	NQ_BYTE * sealingKey,
	NQ_UINT32 sequence,
	NQ_BYTE * signature
	)
{
	CMBlob 	fragments[2];
	NQ_BYTE	seqNum[4];
	NQ_UINT32 *	pSeqBuf;
    CMBlob 	keyBlob;

	syMemset(seqNum, 0, sizeof(seqNum));
	pSeqBuf = (NQ_UINT32 *)&seqNum;
	cmPutUint32(pSeqBuf , sequence);

	fragments[0].data = seqNum;
	fragments[0].len = sizeof(seqNum);
	fragments[1].data = (NQ_BYTE *)data;
	fragments[1].len = dataLen;
	keyBlob.data = (NQ_BYTE *)signingKey;
	keyBlob.len = SMB_SESSIONKEY_LENGTH;

	(*currentCrypters.hmacmd5)(&keyBlob, NULL, fragments, 2, signature, SMB_SESSIONKEY_LENGTH);

	cmArcfourCryptWithState(signature , 8 , sealingKey);
}


/* message signing */
#if 0
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
    CMBlob	fragments[3];

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
    
    syMemset(&ctx, 0, sizeof(MD5Context));
    

    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "key length = %d, seq: %ld, length: %d", keyLen, sequence, length);
    LOGDUMP("key", key, (NQ_UINT)keyLen);

    syMemset(signature, 0, SMB_SECURITY_SIGNATURE_LENGTH);
    cmPutUint32(signature, sn);

    MD5_Init(&ctx);
    MD5_Update(&ctx, key, keyLen);
    if (NULL != password)
    {
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "password: length = %d", passwordLen);
        LOGDUMP("password", password, (NQ_UINT)passwordLen);

        MD5_Update(&ctx, password, passwordLen);
    }
    MD5_Update(&ctx, data, length);
    MD5_Final(&ctx, hash);

    syMemcpy(signature, hash, SMB_SECURITY_SIGNATURE_LENGTH);

    LOGDUMP("signature", signature, SMB_SECURITY_SIGNATURE_LENGTH);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
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
    LOGDUMP("received signature", temp, SMB_SECURITY_SIGNATURE_LENGTH);
    
    cmCreateMAC(key, keyLen, sequence, password, passwordLen, data, length, signature);

    return syMemcmp(temp, signature, SMB_SECURITY_SIGNATURE_LENGTH) == 0;
}
#endif
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
        NQ_CHAR cBlock[32];
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
                cBlock[j * 4 + k] = b[j][k];
        permute(pcb, cBlock, perm5, 32);

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

    key[0] = (NQ_BYTE)(str[0] >> 1);
    key[1] = (NQ_BYTE)((str[0] & 0x01) << 6) | (NQ_BYTE)(str[1] >> 2);
    key[2] = (NQ_BYTE)((str[1] & 0x03) << 5) | (NQ_BYTE)(str[2] >> 3);
    key[3] = (NQ_BYTE)((str[2] & 0x07) << 4) | (NQ_BYTE)(str[3] >> 4);
    key[4] = (NQ_BYTE)((str[3] & 0x0F) << 3) | (NQ_BYTE)(str[4] >> 5);
    key[5] = (NQ_BYTE)((str[4] & 0x1F) << 2) | (NQ_BYTE)(str[5] >> 6);
    key[6] = (NQ_BYTE)((str[5] & 0x3F) << 1) | (NQ_BYTE)(str[6] >> 7);
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
        len = (NQ_UINT)(len - t);
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
    NQ_UINT32 *t;
  
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

    t = (NQ_UINT32 *)ctx->in;
    t[14] = cmHtol32(ctx->bits[0]);
    t[15] = cmHtol32(ctx->bits[1]);

    MD5_Transform(ctx->buf, (NQ_UINT32 *) ctx->in);
    
    for(i = 0; i < 4; i++)
        ctx->buf[i] = cmHtol32(ctx->buf[i]);
    
    syMemmove(digest, ctx->buf, 16);
    syMemset(ctx, 0, sizeof(MD5Context));
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
#if 0
static
void
HMACMD5_Init_RFC2104(
    HMAC_MD5Context *ctx,
    const NQ_BYTE *key,
    NQ_UINT len
    )
{
    NQ_BYTE temp[16];

    if (len > 64)
    {
        MD5Context md5;

        MD5_Init(&md5);
        MD5_Update(&md5, key, len);
        MD5_Final(&md5, temp);
        key = temp;
        len = 16;
    }

    HMACMD5_Init(ctx, key, len);
}
#endif
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
 * PURPOSE: encrypt using ARC4 algorithm
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

        idxI = (NQ_BYTE)((idxI == 255) ? 0 : idxI + 1);
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
 * PURPOSE: Prepare ARC4 state
 *--------------------------------------------------------------------
 * PARAMS:  IN key
 *          IN key length
 *			IN/OUT state
 *
 * RETURNS: none
 *
 * NOTES:   none
 *====================================================================
 */
void
cmArcfourPrepareState(
    const NQ_BYTE *key,
    NQ_UINT keyLen,
	NQ_BYTE * state
    )
{
	NQ_UINT idx;
	NQ_BYTE j = 0;

	for (idx = 0; idx < 256; idx++)
	{
		state[idx] = (NQ_BYTE)idx;
	}
	for (idx = 0; idx < 256; idx++)
	{
		NQ_BYTE tc;

		j = (NQ_BYTE)(j + state[idx] + key[idx % keyLen]);

		tc = state[idx];
		state[idx] = state[j];
		state[j] = tc;
	}
}

/*
 *====================================================================
 * PURPOSE: Encrypt using ARC4 state
 *--------------------------------------------------------------------
 * PARAMS:  IN data
 *          IN data length
 *			IN/OUT state
 *
 * RETURNS: none
 *
 * NOTES:   none
 *====================================================================
 */

void
cmArcfourCryptWithState(
    NQ_BYTE* data,
    NQ_UINT dataLen,
	NQ_BYTE * state
    )
{
	NQ_BYTE idxI = 0, idxJ = 0;
	NQ_UINT idx;

	idxI = state[256];
	idxJ = state[257];

	state[257] = state[256] = 0;
	for (idx = 0; idx < dataLen; idx++)
	{
		NQ_BYTE tc;
		NQ_BYTE t;

		idxI = (NQ_BYTE)((idxI == 255) ? 0 : idxI + 1);
		idxJ = (NQ_BYTE)(idxJ + state[idxI]);
		tc = state[idxI];
		state[idxI] = state[idxJ];
		state[idxJ] = tc;
		t = (NQ_BYTE)(state[idxI] + state[idxJ]);
		data[idx] = data[idx] ^ state[t];
	}
	state[256] = idxI;
	state[257] = idxJ;

}
/*
 *====================================================================
 * PURPOSE: Generate extended security session key
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
cmGenerateExtSecuritySessionKey(
    const NQ_BYTE* v2hash,
    const NQ_BYTE* encrypted,
    NQ_BYTE* out
    )
{
    CMBlob	key;
    CMBlob	fragment;
	key.data = (NQ_BYTE *)v2hash;
	key.len = 16;
	fragment.data = (NQ_BYTE *)encrypted;
	fragment.len = 16;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "v2hash:%p encrypted:%p out:%p", v2hash, encrypted, out);
    (*currentCrypters.hmacmd5)(&key, NULL, &fragment, 1, out, 16);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
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
    NQ_BYTE hash[16];
    NQ_UINT32 sn = cmHtol32(sequence);
    CMBlob	fragments[4];

	fragments[0].data = (NQ_BYTE *)key;
	fragments[0].len = keyLen;
	fragments[1].data = (NQ_BYTE *)password;
	fragments[1].len = passwordLen;
	fragments[2].data = (NQ_BYTE *)buffer1;
	fragments[2].len = size1;
	fragments[3].data = (NQ_BYTE *)buffer2;
	fragments[3].len = size2;
	
	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "key:%p keyLen:%u sequence:%u buffer1:%p size1:%u buffer2:%p size2:%u password:%p passwordLen:%d signature:%p", key, keyLen, sequence, buffer1, size1, buffer2, size2, password, passwordLen, signature);
    
    
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "seq: %ld", sequence);
    LOGDUMP("key", key, (NQ_UINT)keyLen);

    syMemset(signature, 0, SMB_SECURITY_SIGNATURE_LENGTH);
    cmPutUint32(signature, sn);

    (*currentCrypters.md5)(NULL , NULL, fragments , 4 , hash , SMB_SECURITY_SIGNATURE_LENGTH);

    syMemcpy(signature, hash, SMB_SECURITY_SIGNATURE_LENGTH);

    LOGDUMP("signature", signature, SMB_SECURITY_SIGNATURE_LENGTH);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
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

    for (i = 0; i < block_nb; ++i) 
    {
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
static void sha256Internal(const CMBlob * key, const CMBlob * key1, const CMBlob dataFragments[], NQ_COUNT numFragments, NQ_BYTE * buffer, NQ_COUNT bufferSize)
{
    sha256_ctx ctx;
	NQ_COUNT i;


    sha256_init(&ctx);
	for (i = 0; i < numFragments; i++)
		if (dataFragments[i].data != NULL && dataFragments[i].len > 0)
			sha256_update(&ctx, dataFragments[i].data, dataFragments[i].len);
    sha256_final(&ctx, buffer);
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
    NQ_BYTE ipad[SHA256_BLOCK_SIZE];
    NQ_BYTE opad[SHA256_BLOCK_SIZE];
    NQ_BYTE hash[SHA256_DIGEST_SIZE];
    NQ_UINT i;
    CMBlob	frag1[3];
    CMBlob	frag2[2];

	frag1[0].data = ipad;
	frag1[0].len = sizeof(ipad);
	frag1[1].data = (NQ_BYTE *)buffer1;
	frag1[1].len = size1;
	frag1[2].data = (NQ_BYTE *)buffer2;
	frag1[2].len = size2;
	frag2[0].data = opad;
	frag2[0].len = sizeof(opad);
	frag2[1].data = hash;
	frag2[1].len = sizeof(hash);

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "key:%p keyLen:%u buffer1:%p size1:%u buffer2:%p size2:%u signature:%p", key, keyLen, buffer1, size1, buffer2, size2, signature);
    
    LOGDUMP("key", key, (NQ_UINT)keyLen);

    syMemset(ipad, 0x36, sizeof(ipad));
    syMemset(opad, 0x5C, sizeof(opad));

    for (i = 0; i < keyLen; ++i)
    {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }

    syMemset(signature, 0, SMB2_SECURITY_SIGNATURE_SIZE);

    (*currentCrypters.sha256)(NULL , NULL , frag1 , 3 , hash , sizeof(hash));
    (*currentCrypters.sha256)(NULL , NULL , frag2 , 2 , hash , sizeof(hash));

    syMemcpy(signature, hash, SMB2_SECURITY_SIGNATURE_SIZE);
    LOGDUMP("signature", signature, SMB2_SECURITY_SIGNATURE_SIZE);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
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
    NQ_BYTE zero[4], temp[16];
    CMBlob frag1[3];
    CMBlob frag2;
	CMBlob keyBlob;

	frag1[0].data = zero;
	frag1[0].len = 4;
	frag1[1].data = (NQ_BYTE *)clientChallenge;
	frag1[1].len = 8;
	frag1[2].data = (NQ_BYTE *)serverChallenge;
	frag1[2].len = 8;
	frag2.data = temp;
	frag2.len = 16; 
	keyBlob.data = (NQ_BYTE *)key;
	keyBlob.len = 16;
    
    /* Generate the session key */
    syMemset(sessKey, 0, 16);
    syMemset(zero, 0, sizeof(zero));
    
    (*currentCrypters.md5)(NULL, NULL, frag1, 3, temp, 16);
    (*currentCrypters.hmacmd5)(&keyBlob, NULL, &frag2, 1, sessKey, 16);

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
    NQ_BYTE temp[8];
    
    smbhash(temp, in, key, 1);
    smbhash(out, temp, key + 7, 1);
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
#if 0
void 
cmCreateSigningContext(
    MD5Context    *ctx,
    const NQ_BYTE *key,
    NQ_COUNT       keyLen,
    const NQ_BYTE *password,
    NQ_COUNT       passwordLen    
)
{
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON); 

    syMemset(ctx, 0, sizeof(MD5Context));
   
    MD5_Init(ctx);
    MD5_Update(ctx, key, keyLen);
    if (NULL != password)
        MD5_Update(ctx, password, passwordLen);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
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

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
    
    syMemset(signature, 0, SMB_SECURITY_SIGNATURE_LENGTH);
    cmPutUint32(signature, sn);

    MD5_Update(ctx, data, length);
    MD5_Final(ctx, hash);

    syMemcpy(signature, hash, SMB_SECURITY_SIGNATURE_LENGTH);

    LOGDUMP("signature", signature, SMB_SECURITY_SIGNATURE_LENGTH);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
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
#endif
#ifdef UD_NQ_INCLUDESMB3
 /****************************************************************/
  /* AES-CMAC with AES-128 bit                                    */
  /* CMAC     Algorithm described in SP800-38B                    */

  /****************************************************************/

static const NQ_UINT32 AES_SBox[256] = {
    0x63636363, 0x7C7C7C7C, 0x77777777, 0x7B7B7B7B, 0xF2F2F2F2, 0x6B6B6B6B, 0x6F6F6F6F, 0xC5C5C5C5,
    0x30303030, 0x01010101, 0x67676767, 0x2B2B2B2B, 0xFEFEFEFE, 0xD7D7D7D7, 0xABABABAB, 0x76767676,
    0xCACACACA, 0x82828282, 0xC9C9C9C9, 0x7D7D7D7D, 0xFAFAFAFA, 0x59595959, 0x47474747, 0xF0F0F0F0,
    0xADADADAD, 0xD4D4D4D4, 0xA2A2A2A2, 0xAFAFAFAF, 0x9C9C9C9C, 0xA4A4A4A4, 0x72727272, 0xC0C0C0C0,
    0xB7B7B7B7, 0xFDFDFDFD, 0x93939393, 0x26262626, 0x36363636, 0x3F3F3F3F, 0xF7F7F7F7, 0xCCCCCCCC,
    0x34343434, 0xA5A5A5A5, 0xE5E5E5E5, 0xF1F1F1F1, 0x71717171, 0xD8D8D8D8, 0x31313131, 0x15151515,
    0x04040404, 0xC7C7C7C7, 0x23232323, 0xC3C3C3C3, 0x18181818, 0x96969696, 0x05050505, 0x9A9A9A9A,
    0x07070707, 0x12121212, 0x80808080, 0xE2E2E2E2, 0xEBEBEBEB, 0x27272727, 0xB2B2B2B2, 0x75757575,
    0x09090909, 0x83838383, 0x2C2C2C2C, 0x1A1A1A1A, 0x1B1B1B1B, 0x6E6E6E6E, 0x5A5A5A5A, 0xA0A0A0A0,
    0x52525252, 0x3B3B3B3B, 0xD6D6D6D6, 0xB3B3B3B3, 0x29292929, 0xE3E3E3E3, 0x2F2F2F2F, 0x84848484,
    0x53535353, 0xD1D1D1D1, 0x00000000, 0xEDEDEDED, 0x20202020, 0xFCFCFCFC, 0xB1B1B1B1, 0x5B5B5B5B,
    0x6A6A6A6A, 0xCBCBCBCB, 0xBEBEBEBE, 0x39393939, 0x4A4A4A4A, 0x4C4C4C4C, 0x58585858, 0xCFCFCFCF,
    0xD0D0D0D0, 0xEFEFEFEF, 0xAAAAAAAA, 0xFBFBFBFB, 0x43434343, 0x4D4D4D4D, 0x33333333, 0x85858585,
    0x45454545, 0xF9F9F9F9, 0x02020202, 0x7F7F7F7F, 0x50505050, 0x3C3C3C3C, 0x9F9F9F9F, 0xA8A8A8A8,
    0x51515151, 0xA3A3A3A3, 0x40404040, 0x8F8F8F8F, 0x92929292, 0x9D9D9D9D, 0x38383838, 0xF5F5F5F5,
    0xBCBCBCBC, 0xB6B6B6B6, 0xDADADADA, 0x21212121, 0x10101010, 0xFFFFFFFF, 0xF3F3F3F3, 0xD2D2D2D2,
    0xCDCDCDCD, 0x0C0C0C0C, 0x13131313, 0xECECECEC, 0x5F5F5F5F, 0x97979797, 0x44444444, 0x17171717,
    0xC4C4C4C4, 0xA7A7A7A7, 0x7E7E7E7E, 0x3D3D3D3D, 0x64646464, 0x5D5D5D5D, 0x19191919, 0x73737373,
    0x60606060, 0x81818181, 0x4F4F4F4F, 0xDCDCDCDC, 0x22222222, 0x2A2A2A2A, 0x90909090, 0x88888888,
    0x46464646, 0xEEEEEEEE, 0xB8B8B8B8, 0x14141414, 0xDEDEDEDE, 0x5E5E5E5E, 0x0B0B0B0B, 0xDBDBDBDB,
    0xE0E0E0E0, 0x32323232, 0x3A3A3A3A, 0x0A0A0A0A, 0x49494949, 0x06060606, 0x24242424, 0x5C5C5C5C,
    0xC2C2C2C2, 0xD3D3D3D3, 0xACACACAC, 0x62626262, 0x91919191, 0x95959595, 0xE4E4E4E4, 0x79797979,
    0xE7E7E7E7, 0xC8C8C8C8, 0x37373737, 0x6D6D6D6D, 0x8D8D8D8D, 0xD5D5D5D5, 0x4E4E4E4E, 0xA9A9A9A9,
    0x6C6C6C6C, 0x56565656, 0xF4F4F4F4, 0xEAEAEAEA, 0x65656565, 0x7A7A7A7A, 0xAEAEAEAE, 0x08080808,
    0xBABABABA, 0x78787878, 0x25252525, 0x2E2E2E2E, 0x1C1C1C1C, 0xA6A6A6A6, 0xB4B4B4B4, 0xC6C6C6C6,
    0xE8E8E8E8, 0xDDDDDDDD, 0x74747474, 0x1F1F1F1F, 0x4B4B4B4B, 0xBDBDBDBD, 0x8B8B8B8B, 0x8A8A8A8A,
    0x70707070, 0x3E3E3E3E, 0xB5B5B5B5, 0x66666666, 0x48484848, 0x03030303, 0xF6F6F6F6, 0x0E0E0E0E,
    0x61616161, 0x35353535, 0x57575757, 0xB9B9B9B9, 0x86868686, 0xC1C1C1C1, 0x1D1D1D1D, 0x9E9E9E9E,
    0xE1E1E1E1, 0xF8F8F8F8, 0x98989898, 0x11111111, 0x69696969, 0xD9D9D9D9, 0x8E8E8E8E, 0x94949494,
    0x9B9B9B9B, 0x1E1E1E1E, 0x87878787, 0xE9E9E9E9, 0xCECECECE, 0x55555555, 0x28282828, 0xDFDFDFDF,
    0x8C8C8C8C, 0xA1A1A1A1, 0x89898989, 0x0D0D0D0D, 0xBFBFBFBF, 0xE6E6E6E6, 0x42424242, 0x68686868,
    0x41414141, 0x99999999, 0x2D2D2D2D, 0x0F0F0F0F, 0xB0B0B0B0, 0x54545454, 0xBBBBBBBB, 0x16161616,
};

static const NQ_UINT32 AES_128_Rcon[10] = {
	0x01000000, 0x02000000, 0x04000000, 0x08000000,	0x10000000, 0x20000000, 0x40000000, 0x80000000,	0x1B000000, 0x36000000
};

static const NQ_UINT32 AES_Table_1[256] = {
    0xC66363A5, 0xF87C7C84, 0xEE777799, 0xF67B7B8D, 0xFFF2F20D, 0xD66B6BBD, 0xDE6F6FB1, 0x91C5C554,
    0x60303050, 0x02010103, 0xCE6767A9, 0x562B2B7D, 0xE7FEFE19, 0xB5D7D762, 0x4DABABE6, 0xEC76769A,
    0x8FCACA45, 0x1F82829D, 0x89C9C940, 0xFA7D7D87, 0xEFFAFA15, 0xB25959EB, 0x8E4747C9, 0xFBF0F00B,
    0x41ADADEC, 0xB3D4D467, 0x5FA2A2FD, 0x45AFAFEA, 0x239C9CBF, 0x53A4A4F7, 0xE4727296, 0x9BC0C05B,
    0x75B7B7C2, 0xE1FDFD1C, 0x3D9393AE, 0x4C26266A, 0x6C36365A, 0x7E3F3F41, 0xF5F7F702, 0x83CCCC4F,
    0x6834345C, 0x51A5A5F4, 0xD1E5E534, 0xF9F1F108, 0xE2717193, 0xABD8D873, 0x62313153, 0x2A15153F,
    0x0804040C, 0x95C7C752, 0x46232365, 0x9DC3C35E, 0x30181828, 0x379696A1, 0x0A05050F, 0x2F9A9AB5,
    0x0E070709, 0x24121236, 0x1B80809B, 0xDFE2E23D, 0xCDEBEB26, 0x4E272769, 0x7FB2B2CD, 0xEA75759F,
    0x1209091B, 0x1D83839E, 0x582C2C74, 0x341A1A2E, 0x361B1B2D, 0xDC6E6EB2, 0xB45A5AEE, 0x5BA0A0FB,
    0xA45252F6, 0x763B3B4D, 0xB7D6D661, 0x7DB3B3CE, 0x5229297B, 0xDDE3E33E, 0x5E2F2F71, 0x13848497,
    0xA65353F5, 0xB9D1D168, 0x00000000, 0xC1EDED2C, 0x40202060, 0xE3FCFC1F, 0x79B1B1C8, 0xB65B5BED,
    0xD46A6ABE, 0x8DCBCB46, 0x67BEBED9, 0x7239394B, 0x944A4ADE, 0x984C4CD4, 0xB05858E8, 0x85CFCF4A,
    0xBBD0D06B, 0xC5EFEF2A, 0x4FAAAAE5, 0xEDFBFB16, 0x864343C5, 0x9A4D4DD7, 0x66333355, 0x11858594,
    0x8A4545CF, 0xE9F9F910, 0x04020206, 0xFE7F7F81, 0xA05050F0, 0x783C3C44, 0x259F9FBA, 0x4BA8A8E3,
    0xA25151F3, 0x5DA3A3FE, 0x804040C0, 0x058F8F8A, 0x3F9292AD, 0x219D9DBC, 0x70383848, 0xF1F5F504,
    0x63BCBCDF, 0x77B6B6C1, 0xAFDADA75, 0x42212163, 0x20101030, 0xE5FFFF1A, 0xFDF3F30E, 0xBFD2D26D,
    0x81CDCD4C, 0x180C0C14, 0x26131335, 0xC3ECEC2F, 0xBE5F5FE1, 0x359797A2, 0x884444CC, 0x2E171739,
    0x93C4C457, 0x55A7A7F2, 0xFC7E7E82, 0x7A3D3D47, 0xC86464AC, 0xBA5D5DE7, 0x3219192B, 0xE6737395,
    0xC06060A0, 0x19818198, 0x9E4F4FD1, 0xA3DCDC7F, 0x44222266, 0x542A2A7E, 0x3B9090AB, 0x0B888883,
    0x8C4646CA, 0xC7EEEE29, 0x6BB8B8D3, 0x2814143C, 0xA7DEDE79, 0xBC5E5EE2, 0x160B0B1D, 0xADDBDB76,
    0xDBE0E03B, 0x64323256, 0x743A3A4E, 0x140A0A1E, 0x924949DB, 0x0C06060A, 0x4824246C, 0xB85C5CE4,
    0x9FC2C25D, 0xBDD3D36E, 0x43ACACEF, 0xC46262A6, 0x399191A8, 0x319595A4, 0xD3E4E437, 0xF279798B,
    0xD5E7E732, 0x8BC8C843, 0x6E373759, 0xDA6D6DB7, 0x018D8D8C, 0xB1D5D564, 0x9C4E4ED2, 0x49A9A9E0,
    0xD86C6CB4, 0xAC5656FA, 0xF3F4F407, 0xCFEAEA25, 0xCA6565AF, 0xF47A7A8E, 0x47AEAEE9, 0x10080818,
    0x6FBABAD5, 0xF0787888, 0x4A25256F, 0x5C2E2E72, 0x381C1C24, 0x57A6A6F1, 0x73B4B4C7, 0x97C6C651,
    0xCBE8E823, 0xA1DDDD7C, 0xE874749C, 0x3E1F1F21, 0x964B4BDD, 0x61BDBDDC, 0x0D8B8B86, 0x0F8A8A85,
    0xE0707090, 0x7C3E3E42, 0x71B5B5C4, 0xCC6666AA, 0x904848D8, 0x06030305, 0xF7F6F601, 0x1C0E0E12,
    0xC26161A3, 0x6A35355F, 0xAE5757F9, 0x69B9B9D0, 0x17868691, 0x99C1C158, 0x3A1D1D27, 0x279E9EB9,
    0xD9E1E138, 0xEBF8F813, 0x2B9898B3, 0x22111133, 0xD26969BB, 0xA9D9D970, 0x078E8E89, 0x339494A7,
    0x2D9B9BB6, 0x3C1E1E22, 0x15878792, 0xC9E9E920, 0x87CECE49, 0xAA5555FF, 0x50282878, 0xA5DFDF7A,
    0x038C8C8F, 0x59A1A1F8, 0x09898980, 0x1A0D0D17, 0x65BFBFDA, 0xD7E6E631, 0x844242C6, 0xD06868B8,
    0x824141C3, 0x299999B0, 0x5A2D2D77, 0x1E0F0F11, 0x7BB0B0CB, 0xA85454FC, 0x6DBBBBD6, 0x2C16163A,
};
static const NQ_UINT32 AES_Table_2[256] = {
    0xA5C66363, 0x84F87C7C, 0x99EE7777, 0x8DF67B7B, 0x0DFFF2F2, 0xBDD66B6B, 0xB1DE6F6F, 0x5491C5C5,
    0x50603030, 0x03020101, 0xA9CE6767, 0x7D562B2B, 0x19E7FEFE, 0x62B5D7D7, 0xE64DABAB, 0x9AEC7676,
    0x458FCACA, 0x9D1F8282, 0x4089C9C9, 0x87FA7D7D, 0x15EFFAFA, 0xEBB25959, 0xC98E4747, 0x0BFBF0F0,
    0xEC41ADAD, 0x67B3D4D4, 0xFD5FA2A2, 0xEA45AFAF, 0xBF239C9C, 0xF753A4A4, 0x96E47272, 0x5B9BC0C0,
    0xC275B7B7, 0x1CE1FDFD, 0xAE3D9393, 0x6A4C2626, 0x5A6C3636, 0x417E3F3F, 0x02F5F7F7, 0x4F83CCCC,
    0x5C683434, 0xF451A5A5, 0x34D1E5E5, 0x08F9F1F1, 0x93E27171, 0x73ABD8D8, 0x53623131, 0x3F2A1515,
    0x0C080404, 0x5295C7C7, 0x65462323, 0x5E9DC3C3, 0x28301818, 0xA1379696, 0x0F0A0505, 0xB52F9A9A,
    0x090E0707, 0x36241212, 0x9B1B8080, 0x3DDFE2E2, 0x26CDEBEB, 0x694E2727, 0xCD7FB2B2, 0x9FEA7575,
    0x1B120909, 0x9E1D8383, 0x74582C2C, 0x2E341A1A, 0x2D361B1B, 0xB2DC6E6E, 0xEEB45A5A, 0xFB5BA0A0,
    0xF6A45252, 0x4D763B3B, 0x61B7D6D6, 0xCE7DB3B3, 0x7B522929, 0x3EDDE3E3, 0x715E2F2F, 0x97138484,
    0xF5A65353, 0x68B9D1D1, 0x00000000, 0x2CC1EDED, 0x60402020, 0x1FE3FCFC, 0xC879B1B1, 0xEDB65B5B,
    0xBED46A6A, 0x468DCBCB, 0xD967BEBE, 0x4B723939, 0xDE944A4A, 0xD4984C4C, 0xE8B05858, 0x4A85CFCF,
    0x6BBBD0D0, 0x2AC5EFEF, 0xE54FAAAA, 0x16EDFBFB, 0xC5864343, 0xD79A4D4D, 0x55663333, 0x94118585,
    0xCF8A4545, 0x10E9F9F9, 0x06040202, 0x81FE7F7F, 0xF0A05050, 0x44783C3C, 0xBA259F9F, 0xE34BA8A8,
    0xF3A25151, 0xFE5DA3A3, 0xC0804040, 0x8A058F8F, 0xAD3F9292, 0xBC219D9D, 0x48703838, 0x04F1F5F5,
    0xDF63BCBC, 0xC177B6B6, 0x75AFDADA, 0x63422121, 0x30201010, 0x1AE5FFFF, 0x0EFDF3F3, 0x6DBFD2D2,
    0x4C81CDCD, 0x14180C0C, 0x35261313, 0x2FC3ECEC, 0xE1BE5F5F, 0xA2359797, 0xCC884444, 0x392E1717,
    0x5793C4C4, 0xF255A7A7, 0x82FC7E7E, 0x477A3D3D, 0xACC86464, 0xE7BA5D5D, 0x2B321919, 0x95E67373,
    0xA0C06060, 0x98198181, 0xD19E4F4F, 0x7FA3DCDC, 0x66442222, 0x7E542A2A, 0xAB3B9090, 0x830B8888,
    0xCA8C4646, 0x29C7EEEE, 0xD36BB8B8, 0x3C281414, 0x79A7DEDE, 0xE2BC5E5E, 0x1D160B0B, 0x76ADDBDB,
    0x3BDBE0E0, 0x56643232, 0x4E743A3A, 0x1E140A0A, 0xDB924949, 0x0A0C0606, 0x6C482424, 0xE4B85C5C,
    0x5D9FC2C2, 0x6EBDD3D3, 0xEF43ACAC, 0xA6C46262, 0xA8399191, 0xA4319595, 0x37D3E4E4, 0x8BF27979,
    0x32D5E7E7, 0x438BC8C8, 0x596E3737, 0xB7DA6D6D, 0x8C018D8D, 0x64B1D5D5, 0xD29C4E4E, 0xE049A9A9,
    0xB4D86C6C, 0xFAAC5656, 0x07F3F4F4, 0x25CFEAEA, 0xAFCA6565, 0x8EF47A7A, 0xE947AEAE, 0x18100808,
    0xD56FBABA, 0x88F07878, 0x6F4A2525, 0x725C2E2E, 0x24381C1C, 0xF157A6A6, 0xC773B4B4, 0x5197C6C6,
    0x23CBE8E8, 0x7CA1DDDD, 0x9CE87474, 0x213E1F1F, 0xDD964B4B, 0xDC61BDBD, 0x860D8B8B, 0x850F8A8A,
    0x90E07070, 0x427C3E3E, 0xC471B5B5, 0xAACC6666, 0xD8904848, 0x05060303, 0x01F7F6F6, 0x121C0E0E,
    0xA3C26161, 0x5F6A3535, 0xF9AE5757, 0xD069B9B9, 0x91178686, 0x5899C1C1, 0x273A1D1D, 0xB9279E9E,
    0x38D9E1E1, 0x13EBF8F8, 0xB32B9898, 0x33221111, 0xBBD26969, 0x70A9D9D9, 0x89078E8E, 0xA7339494,
    0xB62D9B9B, 0x223C1E1E, 0x92158787, 0x20C9E9E9, 0x4987CECE, 0xFFAA5555, 0x78502828, 0x7AA5DFDF,
    0x8F038C8C, 0xF859A1A1, 0x80098989, 0x171A0D0D, 0xDA65BFBF, 0x31D7E6E6, 0xC6844242, 0xB8D06868,
    0xC3824141, 0xB0299999, 0x775A2D2D, 0x111E0F0F, 0xCB7BB0B0, 0xFCA85454, 0xD66DBBBB, 0x3A2C1616,
};
static const NQ_UINT32 AES_Table_3[256] = {
    0x63A5C663, 0x7C84F87C, 0x7799EE77, 0x7B8DF67B, 0xF20DFFF2, 0x6BBDD66B, 0x6FB1DE6F, 0xC55491C5,
    0x30506030, 0x01030201, 0x67A9CE67, 0x2B7D562B, 0xFE19E7FE, 0xD762B5D7, 0xABE64DAB, 0x769AEC76,
    0xCA458FCA, 0x829D1F82, 0xC94089C9, 0x7D87FA7D, 0xFA15EFFA, 0x59EBB259, 0x47C98E47, 0xF00BFBF0,
    0xADEC41AD, 0xD467B3D4, 0xA2FD5FA2, 0xAFEA45AF, 0x9CBF239C, 0xA4F753A4, 0x7296E472, 0xC05B9BC0,
    0xB7C275B7, 0xFD1CE1FD, 0x93AE3D93, 0x266A4C26, 0x365A6C36, 0x3F417E3F, 0xF702F5F7, 0xCC4F83CC,
    0x345C6834, 0xA5F451A5, 0xE534D1E5, 0xF108F9F1, 0x7193E271, 0xD873ABD8, 0x31536231, 0x153F2A15,
    0x040C0804, 0xC75295C7, 0x23654623, 0xC35E9DC3, 0x18283018, 0x96A13796, 0x050F0A05, 0x9AB52F9A,
    0x07090E07, 0x12362412, 0x809B1B80, 0xE23DDFE2, 0xEB26CDEB, 0x27694E27, 0xB2CD7FB2, 0x759FEA75,
    0x091B1209, 0x839E1D83, 0x2C74582C, 0x1A2E341A, 0x1B2D361B, 0x6EB2DC6E, 0x5AEEB45A, 0xA0FB5BA0,
    0x52F6A452, 0x3B4D763B, 0xD661B7D6, 0xB3CE7DB3, 0x297B5229, 0xE33EDDE3, 0x2F715E2F, 0x84971384,
    0x53F5A653, 0xD168B9D1, 0x00000000, 0xED2CC1ED, 0x20604020, 0xFC1FE3FC, 0xB1C879B1, 0x5BEDB65B,
    0x6ABED46A, 0xCB468DCB, 0xBED967BE, 0x394B7239, 0x4ADE944A, 0x4CD4984C, 0x58E8B058, 0xCF4A85CF,
    0xD06BBBD0, 0xEF2AC5EF, 0xAAE54FAA, 0xFB16EDFB, 0x43C58643, 0x4DD79A4D, 0x33556633, 0x85941185,
    0x45CF8A45, 0xF910E9F9, 0x02060402, 0x7F81FE7F, 0x50F0A050, 0x3C44783C, 0x9FBA259F, 0xA8E34BA8,
    0x51F3A251, 0xA3FE5DA3, 0x40C08040, 0x8F8A058F, 0x92AD3F92, 0x9DBC219D, 0x38487038, 0xF504F1F5,
    0xBCDF63BC, 0xB6C177B6, 0xDA75AFDA, 0x21634221, 0x10302010, 0xFF1AE5FF, 0xF30EFDF3, 0xD26DBFD2,
    0xCD4C81CD, 0x0C14180C, 0x13352613, 0xEC2FC3EC, 0x5FE1BE5F, 0x97A23597, 0x44CC8844, 0x17392E17,
    0xC45793C4, 0xA7F255A7, 0x7E82FC7E, 0x3D477A3D, 0x64ACC864, 0x5DE7BA5D, 0x192B3219, 0x7395E673,
    0x60A0C060, 0x81981981, 0x4FD19E4F, 0xDC7FA3DC, 0x22664422, 0x2A7E542A, 0x90AB3B90, 0x88830B88,
    0x46CA8C46, 0xEE29C7EE, 0xB8D36BB8, 0x143C2814, 0xDE79A7DE, 0x5EE2BC5E, 0x0B1D160B, 0xDB76ADDB,
    0xE03BDBE0, 0x32566432, 0x3A4E743A, 0x0A1E140A, 0x49DB9249, 0x060A0C06, 0x246C4824, 0x5CE4B85C,
    0xC25D9FC2, 0xD36EBDD3, 0xACEF43AC, 0x62A6C462, 0x91A83991, 0x95A43195, 0xE437D3E4, 0x798BF279,
    0xE732D5E7, 0xC8438BC8, 0x37596E37, 0x6DB7DA6D, 0x8D8C018D, 0xD564B1D5, 0x4ED29C4E, 0xA9E049A9,
    0x6CB4D86C, 0x56FAAC56, 0xF407F3F4, 0xEA25CFEA, 0x65AFCA65, 0x7A8EF47A, 0xAEE947AE, 0x08181008,
    0xBAD56FBA, 0x7888F078, 0x256F4A25, 0x2E725C2E, 0x1C24381C, 0xA6F157A6, 0xB4C773B4, 0xC65197C6,
    0xE823CBE8, 0xDD7CA1DD, 0x749CE874, 0x1F213E1F, 0x4BDD964B, 0xBDDC61BD, 0x8B860D8B, 0x8A850F8A,
    0x7090E070, 0x3E427C3E, 0xB5C471B5, 0x66AACC66, 0x48D89048, 0x03050603, 0xF601F7F6, 0x0E121C0E,
    0x61A3C261, 0x355F6A35, 0x57F9AE57, 0xB9D069B9, 0x86911786, 0xC15899C1, 0x1D273A1D, 0x9EB9279E,
    0xE138D9E1, 0xF813EBF8, 0x98B32B98, 0x11332211, 0x69BBD269, 0xD970A9D9, 0x8E89078E, 0x94A73394,
    0x9BB62D9B, 0x1E223C1E, 0x87921587, 0xE920C9E9, 0xCE4987CE, 0x55FFAA55, 0x28785028, 0xDF7AA5DF,
    0x8C8F038C, 0xA1F859A1, 0x89800989, 0x0D171A0D, 0xBFDA65BF, 0xE631D7E6, 0x42C68442, 0x68B8D068,
    0x41C38241, 0x99B02999, 0x2D775A2D, 0x0F111E0F, 0xB0CB7BB0, 0x54FCA854, 0xBBD66DBB, 0x163A2C16,
};
static const NQ_UINT32 AES_Table_4[256] = {

    0x6363A5C6, 0x7C7C84F8, 0x777799EE, 0x7B7B8DF6, 0xF2F20DFF, 0x6B6BBDD6, 0x6F6FB1DE, 0xC5C55491,
    0x30305060, 0x01010302, 0x6767A9CE, 0x2B2B7D56, 0xFEFE19E7, 0xD7D762B5, 0xABABE64D, 0x76769AEC,
    0xCACA458F, 0x82829D1F, 0xC9C94089, 0x7D7D87FA, 0xFAFA15EF, 0x5959EBB2, 0x4747C98E, 0xF0F00BFB,
    0xADADEC41, 0xD4D467B3, 0xA2A2FD5F, 0xAFAFEA45, 0x9C9CBF23, 0xA4A4F753, 0x727296E4, 0xC0C05B9B,
    0xB7B7C275, 0xFDFD1CE1, 0x9393AE3D, 0x26266A4C, 0x36365A6C, 0x3F3F417E, 0xF7F702F5, 0xCCCC4F83,
    0x34345C68, 0xA5A5F451, 0xE5E534D1, 0xF1F108F9, 0x717193E2, 0xD8D873AB, 0x31315362, 0x15153F2A,
    0x04040C08, 0xC7C75295, 0x23236546, 0xC3C35E9D, 0x18182830, 0x9696A137, 0x05050F0A, 0x9A9AB52F,
    0x0707090E, 0x12123624, 0x80809B1B, 0xE2E23DDF, 0xEBEB26CD, 0x2727694E, 0xB2B2CD7F, 0x75759FEA,
    0x09091B12, 0x83839E1D, 0x2C2C7458, 0x1A1A2E34, 0x1B1B2D36, 0x6E6EB2DC, 0x5A5AEEB4, 0xA0A0FB5B,
    0x5252F6A4, 0x3B3B4D76, 0xD6D661B7, 0xB3B3CE7D, 0x29297B52, 0xE3E33EDD, 0x2F2F715E, 0x84849713,
    0x5353F5A6, 0xD1D168B9, 0x00000000, 0xEDED2CC1, 0x20206040, 0xFCFC1FE3, 0xB1B1C879, 0x5B5BEDB6,
    0x6A6ABED4, 0xCBCB468D, 0xBEBED967, 0x39394B72, 0x4A4ADE94, 0x4C4CD498, 0x5858E8B0, 0xCFCF4A85,
    0xD0D06BBB, 0xEFEF2AC5, 0xAAAAE54F, 0xFBFB16ED, 0x4343C586, 0x4D4DD79A, 0x33335566, 0x85859411,
    0x4545CF8A, 0xF9F910E9, 0x02020604, 0x7F7F81FE, 0x5050F0A0, 0x3C3C4478, 0x9F9FBA25, 0xA8A8E34B,
    0x5151F3A2, 0xA3A3FE5D, 0x4040C080, 0x8F8F8A05, 0x9292AD3F, 0x9D9DBC21, 0x38384870, 0xF5F504F1,
    0xBCBCDF63, 0xB6B6C177, 0xDADA75AF, 0x21216342, 0x10103020, 0xFFFF1AE5, 0xF3F30EFD, 0xD2D26DBF,
    0xCDCD4C81, 0x0C0C1418, 0x13133526, 0xECEC2FC3, 0x5F5FE1BE, 0x9797A235, 0x4444CC88, 0x1717392E,
    0xC4C45793, 0xA7A7F255, 0x7E7E82FC, 0x3D3D477A, 0x6464ACC8, 0x5D5DE7BA, 0x19192B32, 0x737395E6,
    0x6060A0C0, 0x81819819, 0x4F4FD19E, 0xDCDC7FA3, 0x22226644, 0x2A2A7E54, 0x9090AB3B, 0x8888830B,
    0x4646CA8C, 0xEEEE29C7, 0xB8B8D36B, 0x14143C28, 0xDEDE79A7, 0x5E5EE2BC, 0x0B0B1D16, 0xDBDB76AD,
    0xE0E03BDB, 0x32325664, 0x3A3A4E74, 0x0A0A1E14, 0x4949DB92, 0x06060A0C, 0x24246C48, 0x5C5CE4B8,
    0xC2C25D9F, 0xD3D36EBD, 0xACACEF43, 0x6262A6C4, 0x9191A839, 0x9595A431, 0xE4E437D3, 0x79798BF2,
    0xE7E732D5, 0xC8C8438B, 0x3737596E, 0x6D6DB7DA, 0x8D8D8C01, 0xD5D564B1, 0x4E4ED29C, 0xA9A9E049,
    0x6C6CB4D8, 0x5656FAAC, 0xF4F407F3, 0xEAEA25CF, 0x6565AFCA, 0x7A7A8EF4, 0xAEAEE947, 0x08081810,
    0xBABAD56F, 0x787888F0, 0x25256F4A, 0x2E2E725C, 0x1C1C2438, 0xA6A6F157, 0xB4B4C773, 0xC6C65197,
    0xE8E823CB, 0xDDDD7CA1, 0x74749CE8, 0x1F1F213E, 0x4B4BDD96, 0xBDBDDC61, 0x8B8B860D, 0x8A8A850F,
    0x707090E0, 0x3E3E427C, 0xB5B5C471, 0x6666AACC, 0x4848D890, 0x03030506, 0xF6F601F7, 0x0E0E121C,
    0x6161A3C2, 0x35355F6A, 0x5757F9AE, 0xB9B9D069, 0x86869117, 0xC1C15899, 0x1D1D273A, 0x9E9EB927,
    0xE1E138D9, 0xF8F813EB, 0x9898B32B, 0x11113322, 0x6969BBD2, 0xD9D970A9, 0x8E8E8907, 0x9494A733,
    0x9B9BB62D, 0x1E1E223C, 0x87879215, 0xE9E920C9, 0xCECE4987, 0x5555FFAA, 0x28287850, 0xDFDF7AA5,
    0x8C8C8F03, 0xA1A1F859, 0x89898009, 0x0D0D171A, 0xBFBFDA65, 0xE6E631D7, 0x4242C684, 0x6868B8D0,
    0x4141C382, 0x9999B029, 0x2D2D775A, 0x0F0F111E, 0xB0B0CB7B, 0x5454FCA8, 0xBBBBD66D, 0x16163A2C,
};

#define AES_Get32(buf) (((NQ_UINT32)(buf)[0] << 24) ^ ((NQ_UINT32)(buf)[1] << 16) ^ ((NQ_UINT32)(buf)[2] <<  8) ^ ((NQ_UINT32)(buf)[3]))
#define AES_Put32(buf, in) { (buf)[0] = (NQ_BYTE)((in) >> 24);\
							(buf)[1] = (NQ_BYTE)((in) >> 16);\
							(buf)[2] = (NQ_BYTE)((in) >>  8);\
							(buf)[3] = (NQ_BYTE)(in); }
static void AES_128_ExpandKey(NQ_UINT32 expandedKey[44], const NQ_BYTE key[16])
{
	NQ_INT  	i = 0;
	NQ_UINT32 	temp;

	expandedKey[0] = AES_Get32(key);
	expandedKey[1] = AES_Get32(key + 4);
	expandedKey[2] = AES_Get32(key + 8);
	expandedKey[3] = AES_Get32(key + 12);

	for (i = 0; i < 10; i++)
	{
		temp  = expandedKey[(i*4)+3];
		expandedKey[(i*4) + 4] = expandedKey[(i*4)] ^
			(AES_SBox[(temp >> 16) & 0xff] & 0xff000000) ^
			(AES_SBox[(temp >>  8) & 0xff] & 0x00ff0000) ^
			(AES_SBox[(temp      ) & 0xff] & 0x0000ff00) ^
			(AES_SBox[(temp >> 24)       ] & 0x000000ff) ^
			AES_128_Rcon[i];
		expandedKey[(i*4) + 5] = expandedKey[(i*4) + 1] ^ expandedKey[(i*4) + 4];
		expandedKey[(i*4) + 6] = expandedKey[(i*4) + 2] ^ expandedKey[(i*4) + 5];
		expandedKey[(i*4) + 7] = expandedKey[(i*4) + 3] ^ expandedKey[(i*4) + 6];
	}
}
static void AES_Encryption( NQ_BYTE state[16] , NQ_UINT32 key[44] , NQ_BYTE out[16])
{
	NQ_UINT32 st0, st1, st2, st3, tmp0, tmp1, tmp2, tmp3;

    /*	get state into 4 UINT32 */
	st0 = AES_Get32(state)      ^ key[0];
	st1 = AES_Get32(state +  4) ^ key[1];
	st2 = AES_Get32(state +  8) ^ key[2];
	st3 = AES_Get32(state + 12) ^ key[3];

    /* first round */
	tmp0 = AES_Table_1[st0 >> 24]  ^ AES_Table_2[(st1 >> 16) & 0xff]  ^ AES_Table_3[(st2 >> 8) & 0xff]  ^ AES_Table_4[st3 & 0xff]  ^ key[ 4];
	tmp1 = AES_Table_1[st1 >> 24]  ^ AES_Table_2[(st2 >> 16) & 0xff]  ^ AES_Table_3[(st3 >> 8) & 0xff]  ^ AES_Table_4[st0 & 0xff]  ^ key[ 5];
	tmp2 = AES_Table_1[st2 >> 24]  ^ AES_Table_2[(st3 >> 16) & 0xff]  ^ AES_Table_3[(st0 >> 8) & 0xff]  ^ AES_Table_4[st1 & 0xff]  ^ key[ 6];
	tmp3 = AES_Table_1[st3 >> 24]  ^ AES_Table_2[(st0 >> 16) & 0xff]  ^ AES_Table_3[(st1 >> 8) & 0xff]  ^ AES_Table_4[st2 & 0xff]  ^ key[ 7];
	/* second round */
	st0  = AES_Table_1[tmp0 >> 24] ^ AES_Table_2[(tmp1 >> 16) & 0xff] ^ AES_Table_3[(tmp2 >> 8) & 0xff] ^ AES_Table_4[tmp3 & 0xff] ^ key[ 8];
	st1  = AES_Table_1[tmp1 >> 24] ^ AES_Table_2[(tmp2 >> 16) & 0xff] ^ AES_Table_3[(tmp3 >> 8) & 0xff] ^ AES_Table_4[tmp0 & 0xff] ^ key[ 9];
	st2  = AES_Table_1[tmp2 >> 24] ^ AES_Table_2[(tmp3 >> 16) & 0xff] ^ AES_Table_3[(tmp0 >> 8) & 0xff] ^ AES_Table_4[tmp1 & 0xff] ^ key[10];
	st3  = AES_Table_1[tmp3 >> 24] ^ AES_Table_2[(tmp0 >> 16) & 0xff] ^ AES_Table_3[(tmp1 >> 8) & 0xff] ^ AES_Table_4[tmp2 & 0xff] ^ key[11];
    /* third round */
	tmp0 = AES_Table_1[st0 >> 24]  ^ AES_Table_2[(st1 >> 16) & 0xff]  ^ AES_Table_3[(st2 >> 8) & 0xff]  ^ AES_Table_4[st3 & 0xff]  ^ key[12];
	tmp1 = AES_Table_1[st1 >> 24]  ^ AES_Table_2[(st2 >> 16) & 0xff]  ^ AES_Table_3[(st3 >> 8) & 0xff]  ^ AES_Table_4[st0 & 0xff]  ^ key[13];
	tmp2 = AES_Table_1[st2 >> 24]  ^ AES_Table_2[(st3 >> 16) & 0xff]  ^ AES_Table_3[(st0 >> 8) & 0xff]  ^ AES_Table_4[st1 & 0xff]  ^ key[14];
	tmp3 = AES_Table_1[st3 >> 24]  ^ AES_Table_2[(st0 >> 16) & 0xff]  ^ AES_Table_3[(st1 >> 8) & 0xff]  ^ AES_Table_4[st2 & 0xff]  ^ key[15];
	/* 4th round */
	st0  = AES_Table_1[tmp0 >> 24] ^ AES_Table_2[(tmp1 >> 16) & 0xff] ^ AES_Table_3[(tmp2 >> 8) & 0xff] ^ AES_Table_4[tmp3 & 0xff] ^ key[16];
	st1  = AES_Table_1[tmp1 >> 24] ^ AES_Table_2[(tmp2 >> 16) & 0xff] ^ AES_Table_3[(tmp3 >> 8) & 0xff] ^ AES_Table_4[tmp0 & 0xff] ^ key[17];
	st2  = AES_Table_1[tmp2 >> 24] ^ AES_Table_2[(tmp3 >> 16) & 0xff] ^ AES_Table_3[(tmp0 >> 8) & 0xff] ^ AES_Table_4[tmp1 & 0xff] ^ key[18];
	st3  = AES_Table_1[tmp3 >> 24] ^ AES_Table_2[(tmp0 >> 16) & 0xff] ^ AES_Table_3[(tmp1 >> 8) & 0xff] ^ AES_Table_4[tmp2 & 0xff] ^ key[19];
    /* 5th round */
	tmp0 = AES_Table_1[st0 >> 24]  ^ AES_Table_2[(st1 >> 16) & 0xff]  ^ AES_Table_3[(st2 >> 8) & 0xff]  ^ AES_Table_4[st3 & 0xff]  ^ key[20];
	tmp1 = AES_Table_1[st1 >> 24]  ^ AES_Table_2[(st2 >> 16) & 0xff]  ^ AES_Table_3[(st3 >> 8) & 0xff]  ^ AES_Table_4[st0 & 0xff]  ^ key[21];
	tmp2 = AES_Table_1[st2 >> 24]  ^ AES_Table_2[(st3 >> 16) & 0xff]  ^ AES_Table_3[(st0 >> 8) & 0xff]  ^ AES_Table_4[st1 & 0xff]  ^ key[22];
	tmp3 = AES_Table_1[st3 >> 24]  ^ AES_Table_2[(st0 >> 16) & 0xff]  ^ AES_Table_3[(st1 >> 8) & 0xff]  ^ AES_Table_4[st2 & 0xff]  ^ key[23];
	/* 6th round */
	st0  = AES_Table_1[tmp0 >> 24] ^ AES_Table_2[(tmp1 >> 16) & 0xff] ^ AES_Table_3[(tmp2 >> 8) & 0xff] ^ AES_Table_4[tmp3 & 0xff] ^ key[24];
	st1  = AES_Table_1[tmp1 >> 24] ^ AES_Table_2[(tmp2 >> 16) & 0xff] ^ AES_Table_3[(tmp3 >> 8) & 0xff] ^ AES_Table_4[tmp0 & 0xff] ^ key[25];
	st2  = AES_Table_1[tmp2 >> 24] ^ AES_Table_2[(tmp3 >> 16) & 0xff] ^ AES_Table_3[(tmp0 >> 8) & 0xff] ^ AES_Table_4[tmp1 & 0xff] ^ key[26];
	st3  = AES_Table_1[tmp3 >> 24] ^ AES_Table_2[(tmp0 >> 16) & 0xff] ^ AES_Table_3[(tmp1 >> 8) & 0xff] ^ AES_Table_4[tmp2 & 0xff] ^ key[27];
    /* 7th round */
	tmp0 = AES_Table_1[st0 >> 24]  ^ AES_Table_2[(st1 >> 16) & 0xff]  ^ AES_Table_3[(st2 >> 8) & 0xff]  ^ AES_Table_4[st3 & 0xff]  ^ key[28];
	tmp1 = AES_Table_1[st1 >> 24]  ^ AES_Table_2[(st2 >> 16) & 0xff]  ^ AES_Table_3[(st3 >> 8) & 0xff]  ^ AES_Table_4[st0 & 0xff]  ^ key[29];
	tmp2 = AES_Table_1[st2 >> 24]  ^ AES_Table_2[(st3 >> 16) & 0xff]  ^ AES_Table_3[(st0 >> 8) & 0xff]  ^ AES_Table_4[st1 & 0xff]  ^ key[30];
	tmp3 = AES_Table_1[st3 >> 24]  ^ AES_Table_2[(st0 >> 16) & 0xff]  ^ AES_Table_3[(st1 >> 8) & 0xff]  ^ AES_Table_4[st2 & 0xff]  ^ key[31];
	/* 8th round */
	st0  = AES_Table_1[tmp0 >> 24] ^ AES_Table_2[(tmp1 >> 16) & 0xff] ^ AES_Table_3[(tmp2 >> 8) & 0xff] ^ AES_Table_4[tmp3 & 0xff] ^ key[32];
	st1  = AES_Table_1[tmp1 >> 24] ^ AES_Table_2[(tmp2 >> 16) & 0xff] ^ AES_Table_3[(tmp3 >> 8) & 0xff] ^ AES_Table_4[tmp0 & 0xff] ^ key[33];
	st2  = AES_Table_1[tmp2 >> 24] ^ AES_Table_2[(tmp3 >> 16) & 0xff] ^ AES_Table_3[(tmp0 >> 8) & 0xff] ^ AES_Table_4[tmp1 & 0xff] ^ key[34];
	st3  = AES_Table_1[tmp3 >> 24] ^ AES_Table_2[(tmp0 >> 16) & 0xff] ^ AES_Table_3[(tmp1 >> 8) & 0xff] ^ AES_Table_4[tmp2 & 0xff] ^ key[35];
    /* 9th round */
	tmp0 = AES_Table_1[st0 >> 24]  ^ AES_Table_2[(st1 >> 16) & 0xff]  ^ AES_Table_3[(st2 >> 8) & 0xff]  ^ AES_Table_4[st3 & 0xff]  ^ key[36];
	tmp1 = AES_Table_1[st1 >> 24]  ^ AES_Table_2[(st2 >> 16) & 0xff]  ^ AES_Table_3[(st3 >> 8) & 0xff]  ^ AES_Table_4[st0 & 0xff]  ^ key[37];
	tmp2 = AES_Table_1[st2 >> 24]  ^ AES_Table_2[(st3 >> 16) & 0xff]  ^ AES_Table_3[(st0 >> 8) & 0xff]  ^ AES_Table_4[st1 & 0xff]  ^ key[38];
	tmp3 = AES_Table_1[st3 >> 24]  ^ AES_Table_2[(st0 >> 16) & 0xff]  ^ AES_Table_3[(st1 >> 8) & 0xff]  ^ AES_Table_4[st2 & 0xff]  ^ key[39];

	st0  =	(AES_SBox[(tmp0 >> 24)       ] & 0xff000000) ^ (AES_SBox[(tmp1 >> 16) & 0xff] & 0x00ff0000) ^
			(AES_SBox[(tmp2 >>  8) & 0xff] & 0x0000ff00) ^ (AES_SBox[(tmp3      ) & 0xff] & 0x000000ff) ^ key[40];
	st1  =	(AES_SBox[(tmp1 >> 24)       ] & 0xff000000) ^ (AES_SBox[(tmp2 >> 16) & 0xff] & 0x00ff0000) ^
			(AES_SBox[(tmp3 >>  8) & 0xff] & 0x0000ff00) ^ (AES_SBox[(tmp0      ) & 0xff] & 0x000000ff) ^ key[41];
	st2  =	(AES_SBox[(tmp2 >> 24)       ] & 0xff000000) ^ (AES_SBox[(tmp3 >> 16) & 0xff] & 0x00ff0000) ^
			(AES_SBox[(tmp0 >>  8) & 0xff] & 0x0000ff00) ^ (AES_SBox[(tmp1      ) & 0xff] & 0x000000ff) ^ key[42];
	st3  = 	(AES_SBox[(tmp3 >> 24)       ] & 0xff000000) ^ (AES_SBox[(tmp0 >> 16) & 0xff] & 0x00ff0000) ^
			(AES_SBox[(tmp1 >>  8) & 0xff] & 0x0000ff00) ^ (AES_SBox[(tmp2      ) & 0xff] & 0x000000ff) ^ key[43];
	AES_Put32(out     , st0);
	AES_Put32(out +  4, st1);
	AES_Put32(out +  8, st2);
	AES_Put32(out + 12, st3);
}

static void AES_128_Encrypt(NQ_BYTE state[16] ,NQ_BYTE key[16] , NQ_BYTE encrypted[16])
{
	NQ_UINT32	expandedKey[44];

	AES_128_ExpandKey(expandedKey, key);
	AES_Encryption(state , expandedKey , encrypted);
}

  /* Basic Functions */
/* For CMAC Calculation */
NQ_BYTE const_Rb[16] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87
};

static void AES_XOR_128( const NQ_BYTE *a, const NQ_BYTE *b, NQ_BYTE *out)
{
	NQ_INT i;

	for (i=0;i<16; i++)
	{
		out[i] = a[i] ^ b[i];
	}
}

static void AES_CMAC_ShiftBitLeft(NQ_BYTE *input,NQ_BYTE *output)
{
	NQ_INT	i;
	NQ_BYTE	overflow = 0;

	for ( i = 15; i >= 0; i--)
	{
		output[i] = (NQ_BYTE)(input[i] << 1);
		output[i] |= overflow;
		overflow = (input[i] & 0x80)?1:0;
	}
	return;
}

static void AES_CMAC_GenSubKey(NQ_BYTE *key, NQ_BYTE *K1, NQ_BYTE *K2)
{
	NQ_BYTE L[16];
	NQ_BYTE Z[16];
	NQ_BYTE temp[16];

	syMemset(&Z , 0 , 16);

	AES_128_Encrypt(Z,key,L);

	if ( (L[0] & 0x80) == 0 )
	{
		AES_CMAC_ShiftBitLeft(L,K1);
	}
	else
	{
		AES_CMAC_ShiftBitLeft(L,temp);
		AES_XOR_128(temp,const_Rb,K1);
	}

	if ( (K1[0] & 0x80) == 0 )
	{
		AES_CMAC_ShiftBitLeft(K1,K2);
	}
	else
	{
		AES_CMAC_ShiftBitLeft(K1,temp);
		AES_XOR_128(temp,const_Rb,K2);
	}
	return;
}

static void AES_CMAC_Padding ( const NQ_BYTE * lastByte, NQ_BYTE * pad, NQ_UINT length )
{
	NQ_UINT         i;

	for (i = 0; i < 16; i++ )
	{
	  if ( i < length )
	  {
		  pad[i] = lastByte[i];
	  }
	  else if ( i == length )
	  {
		  pad[i] = 0x80;
	  }
	  else
	  {
		  pad[i] = 0x00;
	  }
	}
}


typedef struct{
	NQ_UINT	numOfRounds;
	NQ_BYTE mainKey[16];
	NQ_BYTE	X[16];
	NQ_BYTE M_Last[16];
	NQ_BYTE extra[16];
	NQ_BYTE key1[16];
	NQ_BYTE key2[16];
	NQ_UINT leftover;
	NQ_INT 	flag;
}cmac_context;

static void aes_cmac_init( const NQ_BYTE * key, NQ_UINT length, cmac_context * context)
{
	syMemset(context->mainKey , 0 , 16);
	syMemset(context->key1 , 0 , 16);
	syMemset(context->key2 , 0 , 16);
	syMemset(context->X , 0 , 16);
	syMemset(context->M_Last , 0 , 16);
	syMemset(context->extra , 0 , 16);
	context->leftover = FALSE;

	syMemcpy( context->mainKey, key , 16);

	AES_CMAC_GenSubKey(context->mainKey , context->key1 , context->key2);

	context->numOfRounds = (length + 15) / 16;
	if ( context->numOfRounds == 0 )
	{
	  context->numOfRounds = 1;
	  context->flag = 0;
	}
	else
	{
		context->flag = (length % 16) == 0 ? 1 : 0;
	}
}

static void aes_cmac_update(cmac_context * ctx , const NQ_BYTE * buffer ,  NQ_UINT length)
{
	NQ_UINT currentRounds = 0;
	NQ_COUNT	i = 0;
	NQ_BYTE Y[16];

	syMemset( &Y , 0 , 16);
	if (!ctx->leftover)
	{
		currentRounds = length / 16;

		for (i = 0; i < currentRounds; i++)
		{
			if (ctx->numOfRounds - 1 == 0 && ctx->flag && (length % 16) == 0)
			{
				syMemcpy(&ctx->extra , &buffer[16 * i] , 16);
				ctx->leftover = 16;
				return;
			}
			AES_XOR_128(ctx->X,&buffer[16*i],Y);
			AES_128_Encrypt(Y,ctx->mainKey ,ctx->X);
			ctx->numOfRounds--;

		}

		if ((length % 16) != 0)
		{
			ctx->leftover = length % 16;
			syMemset(ctx->extra , 0 , 16);
			syMemcpy(ctx->extra , buffer + (16 * currentRounds) , length % 16);
		}
	}
	else
	{
		NQ_UINT newLength = 0;
		NQ_BYTE temp[16];
		NQ_BYTE * nb;

		syMemset(&temp , 0 , 16);
		syMemcpy(&temp , ctx->extra , ctx->leftover);
		syMemcpy(&temp[ctx->leftover] , buffer , length >= (16 - ctx->leftover) ? 16 - ctx->leftover : length);

		newLength = (length > (16 - ctx->leftover)) ? length - (16 - ctx->leftover) : 0;
		nb = (newLength != 0) ? (NQ_BYTE *)buffer + (16 - ctx->leftover) : NULL;
		currentRounds = (newLength / 16);

		if (newLength == 0)
		{
			ctx->leftover += length;
			syMemcpy(&ctx->extra , &temp , ctx->leftover );
			return;
		}
		AES_XOR_128(ctx->X,(NQ_BYTE *)&temp,Y);
		AES_128_Encrypt(Y, ctx->mainKey ,ctx->X);
		ctx->numOfRounds--;

		for (i = 0; i < currentRounds; i++)
		{
			if (ctx->numOfRounds - 1 == 0 && ctx->flag)
			{
				syMemcpy(&ctx->extra, &nb[16 * i], 16);
				ctx->leftover = 16;
				return;
			}
			AES_XOR_128(ctx->X,&nb[16*i],Y);
			AES_128_Encrypt(Y, ctx->mainKey ,ctx->X);
			ctx->numOfRounds--;
		}

		ctx->leftover = newLength % 16;
		if (ctx->leftover != 0)
		{
			syMemset(ctx->extra , 0 , 16);
			syMemcpy(ctx->extra , nb + (16 * currentRounds) , ctx->leftover);
		}
	}
}

static void aes_cmac_final(cmac_context * ctx , NQ_BYTE * mac)
{
	NQ_BYTE Y[16];

	syMemset( &Y , 0 , 16);

	if (ctx->leftover > 0)
	{
		if (ctx->leftover < 16)
		{
			NQ_BYTE padded[16];

			AES_CMAC_Padding((NQ_BYTE *)&ctx->extra, padded, ctx->leftover);
			AES_XOR_128(padded, ctx->key2 , ctx->M_Last);

		}
		else
		{
			AES_XOR_128((NQ_BYTE *)&ctx->extra, ctx->key1, ctx->M_Last);
		}
	}

	AES_XOR_128(ctx->X, ctx->M_Last, Y);
	AES_128_Encrypt(Y, ctx->mainKey , ctx->X);
	syMemcpy( mac , ctx->X , 16);
}

void cmSmb311CalcMessagesHash(    
    const NQ_BYTE *buffer,
    NQ_UINT size,   
    NQ_BYTE *digest,
	NQ_BYTE *ctxBuff
	)
{
	CMBlob fragments[2];

	/* start with incoming digest result - 1st round its all zero */
	fragments[0].data = digest;
	fragments[0].len = SMB3_PREAUTH_INTEG_HASH_LENGTH;
	
	/* buffer */ 
	fragments[1].data = (NQ_BYTE*)buffer;
	fragments[1].len = size;

	(*currentCrypters.sha512)(NULL, NULL, fragments, 2, digest, SMB3_PREAUTH_INTEG_HASH_LENGTH, ctxBuff);
}


void cmSmb3CalculateMessageSignature(
    const NQ_BYTE *key,
    NQ_UINT keyLen,
    const NQ_BYTE *buffer1,
    NQ_UINT size1,
    const NQ_BYTE *buffer2,
    NQ_UINT size2,
    NQ_BYTE *signature
    )
{
	CMBlob fragments[2];
	CMBlob keyBlob;

	fragments[0].data = (NQ_BYTE *)buffer1;
	fragments[0].len = size1;
	fragments[1].data = (NQ_BYTE *)buffer2;
	fragments[1].len = size2;
	keyBlob.data = (NQ_BYTE *)key;
	keyBlob.len = keyLen;

	(*currentCrypters.aes128cmac)(&keyBlob, NULL, fragments, 2, signature, SMB2_SECURITY_SIGNATURE_SIZE);
}

static void aes128cmacInternal(const CMBlob * key, const CMBlob * key1, const CMBlob dataFragments[], NQ_COUNT numFragments, NQ_BYTE * buffer, NQ_COUNT bufferSize)
{
    NQ_BYTE 	sig[16];
	cmac_context context;
	NQ_UINT size = 0 , i;


	LOGDUMP("key" , key->data , key->len);
    syMemset(buffer, 0, bufferSize); /* zero out the previous signature*/
	for (i = 0; i < numFragments; i++)
	{
		if (dataFragments[i].data != NULL)
			size += dataFragments[i].len;
	}
	aes_cmac_init(key->data, size, &context);
	for (i = 0; i < numFragments; i++)
	{
		if (dataFragments[i].data != NULL && dataFragments[i].len > 0)
			aes_cmac_update(&context , dataFragments[i].data , dataFragments[i].len);
	}
	aes_cmac_final(&context , (NQ_BYTE *)&sig);
	LOGDUMP("signature" , sig , bufferSize);
    syMemcpy(buffer, sig, bufferSize);

}

/*
 *====================================================================
 * PURPOSE: Ker Derivation for SMB3 keys
 *--------------------------------------------------------------------
 * PARAMS:  IN     Session Key
 *          IN     Key length
 *          IN     Label
 *          IN     Label length
 *          IN     Context
 *          IN     Context length
 *          OUT	   Derived key
 *
 * RETURNS: none
 *====================================================================
 */

void cmKeyDerivation(const NQ_BYTE * key , NQ_UINT keyLen , NQ_BYTE * label , NQ_UINT labelLen , NQ_BYTE * context , NQ_UINT contextLen , NQ_BYTE * derivedKey)
{
	NQ_BYTE temp1[4] = { 0x00 , 0x00 , 0x00 , 0x01};
	NQ_BYTE temp2[4] = { 0x00 , 0x00 , 0x00 , 0x80};
	NQ_BYTE zero = 0x00;
	NQ_BYTE ipad[SHA256_BLOCK_SIZE];
	NQ_BYTE opad[SHA256_BLOCK_SIZE];
	NQ_BYTE digest[SHA256_DIGEST_SIZE];
	NQ_UINT i;
	CMBlob fragments1[6];
	CMBlob fragments2[2];
	
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "key:%p keyLen:%d label:%s labelLen:%d context:%p contextLen:%d derivedKey:%p", key, keyLen, (NQ_CHAR *)label, labelLen, context, contextLen, derivedKey);

    LOGDUMP("key", key, keyLen);

	fragments1[0].data = ipad;
	fragments1[0].len = sizeof(ipad);
	fragments1[1].data = temp1;
	fragments1[1].len = sizeof(temp1);
	fragments1[2].data = label;
	fragments1[2].len = labelLen;
	fragments1[3].data = &zero;
	fragments1[3].len = 1;
	fragments1[4].data = context;
	fragments1[4].len = contextLen;
	fragments1[5].data = temp2;
	fragments1[5].len = sizeof(temp2);
	fragments2[0].data = opad;
	fragments2[0].len = sizeof(opad);
	fragments2[1].data = digest;
	fragments2[1].len = sizeof(digest);

	syMemset(ipad, 0x36, sizeof(ipad));
	syMemset(opad, 0x5C, sizeof(opad));

	for (i = 0; i < keyLen; ++i)
	{
		ipad[i] ^= key[i];
		opad[i] ^= key[i];
	}

	(*currentCrypters.sha256)(NULL, NULL, fragments1, 6, digest, sizeof(digest));
	(*currentCrypters.sha256)(NULL, NULL, fragments2, 2, digest, sizeof(digest));

	syMemcpy(derivedKey, digest , 16);

    LOGDUMP("derivedKey", derivedKey, 16);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

/* AES_CCM 128 Defines */
#define AES_BLOCK_SIZE 16
#define AES_128_CCM_M 16
#define AES_128_CCM_L 4
#define AES_128_CCM_M_tag (AES_128_CCM_M - 2) / 2
#define AES_128_CCM_L_tag (AES_128_CCM_L - 1)

/*
 *====================================================================
 * PURPOSE: Encrypt SMB3 Message with AES_CCM
 *--------------------------------------------------------------------
 * PARAMS:  IN     Encrypting Key
 *          IN     Nonce
 *          IN     SMB3 Message
 *          IN     SMB3 Message length
 *          IN     Additional Message (SMB2 TRANSFORM HEADER excluding protocolID , Signature , Nonce)
 *          IN     Additional Message length
 *          OUT	   Encrypted authentication value (signature for TF-Header)
 *
 * RETURNS: none
 *====================================================================
 */

void AES_128_CCM_Encrypt(NQ_BYTE * key , NQ_BYTE * nonce , NQ_BYTE * msgBuf , NQ_UINT msgLen, NQ_BYTE * addBuf , NQ_UINT addLen , NQ_BYTE * outMac)
{
	CMBlob keyBlob, key1Blob, prefixBlob, msgBlob;

	keyBlob.data = (NQ_BYTE *) key;
	keyBlob.len = 16;
	key1Blob.data = (NQ_BYTE *) nonce;
	key1Blob.len = SMB2_AES128_CCM_NONCE_SIZE;
	prefixBlob.data = addBuf;
	prefixBlob.len = addLen;
	msgBlob.data = msgBuf;
	msgBlob.len = msgLen;

	(*currentCrypters.aes128ccmEncryption)(&keyBlob, &key1Blob, &prefixBlob, &msgBlob, outMac);
}
	
static void aes128ccmEncryptionInternal(const CMBlob * key, const CMBlob * key1, const CMBlob * prefix, CMBlob * message, NQ_BYTE * auth)
{
	NQ_UINT lm = (message->len % AES_BLOCK_SIZE) == 0 ? message->len / AES_BLOCK_SIZE : message->len / AES_BLOCK_SIZE + 1;
	NQ_UINT la = (prefix->len % AES_BLOCK_SIZE) == 0 ? prefix->len / AES_BLOCK_SIZE : prefix->len / AES_BLOCK_SIZE + 1;
	NQ_INT 	written = 0;
	NQ_UINT remaining  = 0,  i = 0 , B_offset = 0 ;
	NQ_BYTE	* B = NULL , * X = NULL;
	NQ_BYTE S0[16];
	NQ_BYTE * writer = NULL;

	B = (NQ_BYTE *)syMalloc((lm + la + 2 +1) * AES_BLOCK_SIZE);
	X = (NQ_BYTE *)syMalloc((lm + la + 2) * AES_BLOCK_SIZE);
	if (B == NULL || X == NULL)
    {
		LOGERR(CM_TRC_LEVEL_ERROR, "  AES_CCM_Encrypt: Couldn't allocate memory");
		goto Exit;
    }
	syMemset(B , 0 , (lm + la + 2 + 1) * AES_BLOCK_SIZE);
	syMemset(X , 0 , (lm + la + 2) * AES_BLOCK_SIZE);
	syMemset(auth , 0 , 16);

	/* Setting Block 0 */
	B[0] = AES_128_CCM_L_tag + 8 * AES_128_CCM_M_tag;
	B[0] = (NQ_BYTE)(prefix->len > 0 ? B[0] + 64 : B[0]);
	syMemcpy(&B[1] , key1->data , key1->len);
	cmPutUint32((NQ_BYTE *)&B[AES_128_CCM_M - AES_128_CCM_L] , cmHtob32((NQ_UINT32)message->len));

	/* X_1 */
	AES_128_Encrypt(&B[0] , key->data , &X[0]);
	/* Setting Block 1 with sizes  */
	if (prefix->len >= 0xFF00)
	{
		B[16] = 0xFF;
		B[17] =	0xFE;
		cmPutUint32((NQ_BYTE *)&B[18] , cmHtob32((NQ_UINT32)prefix->len));
		B_offset = 6;
		writer = &B[22];
	}
	else if (prefix->len > 0)
	{
		cmPutUint16((NQ_BYTE *)&B[16] , (NQ_UINT16)cmHtob16(prefix->len));
		B_offset = 2;
		writer = &B[18];
	}
	/* Filling B */
	syMemcpy(writer , prefix->data , prefix->len);
	writer += prefix->len;
	remaining = (prefix->len + B_offset) % AES_BLOCK_SIZE;
	if (remaining > 0)
	{
		syMemset(writer , 0 , 16 - remaining);
		writer += 16 - remaining;
	}
	syMemcpy(writer , message->data , message->len);
	writer += message->len;

	written = (NQ_INT) (writer - &B[0]);
	written = (written % 16 == 0) ? written / AES_BLOCK_SIZE : written /AES_BLOCK_SIZE + 1;
	/* Filling X */
	for (i = 1; i < (NQ_UINT)written  ; i++)
	{
		AES_XOR_128(&B[i*16] , &X[(i-1)*16] , &B[i*16]);
		AES_128_Encrypt(&B[i*16]  , key->data , &X[i*16]);
	}
	for (i =0 ; i < lm + 1 ; i++)
	{
		NQ_BYTE A[16] , S[16];
        NQ_BYTE *p;

		if (i == 0)
		{
			A[0] = AES_128_CCM_L_tag;
            p = (NQ_BYTE *)&A[1];
			syMemcpy(p, key1->data , 11);
		}
        p = (NQ_BYTE *)&A[(AES_128_CCM_M - AES_128_CCM_L)];
		cmPutUint32(p, cmHtob32((NQ_UINT32)i));
		AES_128_Encrypt((NQ_BYTE *)A , key->data , (NQ_BYTE *)S);
		if (i == 0)
			syMemcpy(S0 , S , 16);
		if (i > 0 )
		{
			if (i == lm && message->len % AES_BLOCK_SIZE != 0)
			{
				NQ_COUNT j;
				for (j = 0; j < message->len % AES_BLOCK_SIZE; j++)
					message->data[((lm - 1) * AES_BLOCK_SIZE) + j] = message->data[((lm - 1) * AES_BLOCK_SIZE) + j] ^ S[j];
			}

			else
				AES_XOR_128((NQ_BYTE *)&message->data[(i - 1) * AES_BLOCK_SIZE] , (NQ_BYTE *)S ,(NQ_BYTE *)&message->data[(i - 1) * AES_BLOCK_SIZE]);
		}

	}

	AES_XOR_128((NQ_BYTE *)&X[(written - 1)*AES_BLOCK_SIZE] ,(NQ_BYTE *)S0 , (NQ_BYTE *)auth );

Exit:
	cmMemoryFree(X);
	cmMemoryFree(B);
}

/*
 *====================================================================
 * PURPOSE: Decryption SMB3 Message with AES_CCM
 *--------------------------------------------------------------------
 * PARAMS:  IN     Encrypting Key
 *          IN     Nonce
 *          IN     SMB3 Message
 *          IN     SMB3 Message length
 *          IN     Additional Message (SMB2 TRANSFORM HEADER excluding protocolID , Signature , Nonce)
 *          IN     Additional Message length
 *          OUT	   Encrypted authentication value (signature for TF-Header)
 *
 * RETURNS: TRUE  -> if calculated authentication value equals to received value.
 * 			FALSE -> if calculated value differs from received. The Decrypted messages should be IGNORED in this case
 *====================================================================
 */

NQ_BOOL AES_128_CCM_Decrypt(NQ_BYTE * key , NQ_BYTE * nonce , NQ_BYTE * msgBuf , NQ_UINT msgLen , NQ_BYTE * addBuf , NQ_UINT addLen , NQ_BYTE * authValue)
{
	CMBlob keyBlob, key1Blob, prefixBlob, msgBlob;

	keyBlob.data = (NQ_BYTE *) key;
	keyBlob.len = 16;
	key1Blob.data = (NQ_BYTE *) nonce;
	key1Blob.len = SMB2_AES128_CCM_NONCE_SIZE;
	prefixBlob.data = addBuf;
	prefixBlob.len = addLen;
	msgBlob.data = msgBuf;
	msgBlob.len = msgLen;

	return (*currentCrypters.aes128ccmDecryption)(&keyBlob, &key1Blob, &prefixBlob, &msgBlob, authValue);
}

static NQ_BOOL aes128ccmDecryptionInternal(const CMBlob * key, const CMBlob * key1, const CMBlob * prefix, CMBlob * message, const NQ_BYTE * auth)
{
	NQ_UINT		lm = (message->len % 16) == 0 ? message->len / 16 : message->len / 16 + 1;
	NQ_UINT  	la = (prefix->len % 16) == 0 ? prefix->len / 16 : prefix->len / 16 + 1;
	NQ_UINT 	i = 0 ,remaining  = 0 , B_offset = 0;
	NQ_INT		written = 0;
	NQ_BYTE		T[16] , S0[16];
	NQ_BYTE	*   B = NULL , * X = NULL;
	NQ_BYTE * 	writer = NULL;
	NQ_BOOL result = FALSE;

	B = (NQ_BYTE *)cmMemoryAllocate((lm + la + 2 +1) * 16);
	X = (NQ_BYTE *)cmMemoryAllocate((lm + la + 2) * 16);
	if (B == NULL || X == NULL)
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "  AES_CCM_Encrypt: Couldn't allocate memory");
		goto Exit;
	}
	syMemset(B , 0 , (lm + la + 2 + 1) * 16);
	syMemset(X , 0 , (lm + la + 2) * 16);

	for (i =0 ; i < lm + 1 ; i++)
	{
		NQ_BYTE A[16] , S[16];
        NQ_BYTE *p;

		A[0] = AES_128_CCM_L_tag;
        p = (NQ_BYTE *)&A[1];
		syMemcpy(p, key1->data , 11);
        p = (NQ_BYTE *)&A[AES_128_CCM_M - AES_128_CCM_L];
		cmPutUint32(p, cmHtob32((NQ_UINT32)i));
		AES_128_Encrypt((NQ_BYTE *)A , key->data , (NQ_BYTE *)S);
		if (i == 0)
			syMemcpy(S0 , S , 16);
		if (i > 0 )
		{
			if (i == lm && message->len % 16 != 0)
			{
				NQ_COUNT j;

				for (j = 0; j < message->len % 16; j++)
					message->data[((lm - 1) * 16) + j] = message->data[((lm - 1) * 16) + j] ^ S[j];
			}
			else
				AES_XOR_128((NQ_BYTE *)&message->data[(i - 1) * 16] , (NQ_BYTE *)S ,(NQ_BYTE *)&message->data[(i - 1) * 16]);
		}
	}

	/* Recovering T */
	AES_XOR_128((NQ_BYTE *)auth ,(NQ_BYTE *)&S0 , (NQ_BYTE *)&T );

	/* Setting Block 0 */
	B[0] = AES_128_CCM_L_tag + 8 * AES_128_CCM_M_tag;
	B[0] = (NQ_BYTE)(prefix->len > 0 ? B[0] + 64 : B[0]);
	syMemcpy(&B[1] , key1->data , key1->len);
	cmPutUint32((NQ_BYTE *)&B[AES_128_CCM_M - AES_128_CCM_L] , cmHtob32((NQ_UINT32)message->len));

	/* X_1 */
	AES_128_Encrypt(&B[0] , key->data , &X[0]);
	/* Setting Block 1 with sizes  */
	if (prefix->len >= 0xFF00)
	{
		B[16] = 0xFF;
		B[17] =	0xFE;
		cmPutUint32((NQ_BYTE *)&B[18] , cmHtob32((NQ_UINT32)prefix->len));
		B_offset = 6;
		writer = &B[22];
	}
	else if (prefix->len > 0)
	{
		cmPutUint16((NQ_BYTE *)&B[16] ,(NQ_UINT16)cmHtob16(prefix->len));
		B_offset = 2;
		writer = &B[18];
	}

	/* Filling B */
	syMemcpy(writer , prefix->data , prefix->len);
	writer += prefix->len;
	remaining = (prefix->len + B_offset) % 16;
	if (remaining > 0)
	{
		syMemset(writer , 0 , 16 - remaining);
		writer += 16 - remaining;
	}
	syMemcpy(writer , message->data , message->len);
	writer += message->len;

	written = (NQ_INT) (writer - &B[0]);
	written = (written % 16 == 0) ? written / 16 : written /16 + 1;

	/* Filling X */
	for (i = 1; i < (NQ_UINT)written  ; i++)
	{
		AES_XOR_128(&B[i*16] , &X[(i-1)*16] , &B[i*16]);
		AES_128_Encrypt(&B[i*16]  , key->data , &X[i*16]);
	}

	result = syMemcmp(&T , &X[(written -1) * 16] , 16) == 0;

Exit:
	cmMemoryFree(B);
	cmMemoryFree(X);
	return result;
}


NQ_BOOL cmSmb3DecryptMessage(
    NQ_BYTE *key,
    NQ_BYTE *nonce,
    NQ_BYTE *crptMsg,
    NQ_UINT msgLen,
    NQ_BYTE *authMsg,
    NQ_UINT authLen,
    NQ_BYTE *signature,
	NQ_BOOL IsAesGCM
    )
{
	if (IsAesGCM)
		return aes128GcmDecrypt(key, nonce, crptMsg , msgLen , authMsg , authLen ,signature, NULL, NULL);

	return AES_128_CCM_Decrypt(key , nonce , crptMsg , msgLen , authMsg , authLen ,signature);
}

void cmSmb3EncryptMessage(
    NQ_BYTE *key,
    NQ_BYTE *nonce,
    NQ_BYTE *msg,
    NQ_UINT msgLen,
    NQ_BYTE *authMsg,
    NQ_UINT authLen,
    NQ_BYTE *signature,
	NQ_BOOL isAesGCM
    )
{
	if (isAesGCM)
		aes128GcmEncrypt(key, nonce, msg, msgLen, authMsg, authLen, signature, NULL, NULL);
	else
		AES_128_CCM_Encrypt(key, nonce, msg, msgLen, authMsg, authLen, signature);
}
#endif /* UD_NQ_INCLUDESMB3 */

#ifdef UD_NQ_INCLUDESMB3


#define GET_BE_BYTES_FROM32(a) ((((NQ_UINT32) (a)[0]) << 24) | (((NQ_UINT32) (a)[1]) << 16) | \
				  (((NQ_UINT32) (a)[2]) << 8) | ((NQ_UINT32) (a)[3]))
#define PUT_BE_BYTES_IN32(a, val)					\
		 {							 \
			 (a)[0] = (NQ_BYTE) ((((NQ_UINT32) (val)) >> 24));	 \
			 (a)[1] = (NQ_BYTE) ((((NQ_UINT32) (val)) >> 16));	 \
			 (a)[2] = (NQ_BYTE) ((((NQ_UINT32) (val)) >> 8));	 \
			 (a)[3] = (NQ_BYTE) (((NQ_UINT32) (val)) & 0xff);	 \
		 }
#ifdef SY_INT64
#define PUT_BE_BYTES_MUL8_IN64(a, val)				\
		 {				 \
			(a)[0] = 0;	 \
			(a)[1] = 0;	 \
			(a)[2] = 0;	 \
			(a)[3] = (NQ_BYTE) (((SY_UINT64) (val)) >> 29);	 \
			(a)[4] = (NQ_BYTE) (((SY_UINT64) (val)) >> 21);	 \
			(a)[5] = (NQ_BYTE) (((SY_UINT64) (val)) >> 13);	 \
			(a)[6] = (NQ_BYTE) (((SY_UINT64) (val)) >> 5); 	 \
			(a)[7] = (NQ_BYTE) (((SY_UINT64) (val) << 3) & 0xff);	 \
		 }
#else
#define PUT_BE_BYTES_MUL8_IN64(a, val)	\
		 {						 		\
			 (a)[0] = (NQ_BYTE) (0);	 	\
			 (a)[1] = (NQ_BYTE) (0);	 	\
			 (a)[2] = (NQ_BYTE) (0);	 	\
			 (a)[3] = (NQ_BYTE) (((NQ_UINT32) (val)) >> 29); \
			 (a)[4] = (NQ_BYTE) (((NQ_UINT32) (val)) >> 21); \
			 (a)[5] = (NQ_BYTE) (((NQ_UINT32) (val)) >> 13); \
			 (a)[6] = (NQ_BYTE) (((NQ_UINT32) (val)) >> 5);  \
			 (a)[7] = (NQ_BYTE) (((NQ_UINT32) (val) << 3) & 0xff);	 \
		 }
#endif

#define LSHIFT(x) (1 << (x))
#define AES_BLOCK_SIZE 16

extern const NQ_UINT32 Te0[256];
extern const NQ_UINT32 Te1[256];
extern const NQ_UINT32 Te2[256];
extern const NQ_UINT32 Te3[256];
extern const NQ_UINT32 Te4[256];
extern const NQ_UINT32 Td0[256];
extern const NQ_UINT32 Td1[256];
extern const NQ_UINT32 Td2[256];
extern const NQ_UINT32 Td3[256];
extern const NQ_UINT32 Td4[256];
extern const NQ_UINT32 rcon[10];
extern const NQ_BYTE Td4s[256];
extern const NQ_BYTE rcons[10];
#ifndef AES_SMALL_TABLES
#define RCON(i) rcon[(i)]
#define TE0(i) Te0[((i) >> 24) & 0xff]
#define TE1(i) Te1[((i) >> 16) & 0xff]
#define TE2(i) Te2[((i) >> 8) & 0xff]
#define TE3(i) Te3[(i) & 0xff]
#define TE41(i) (Te4[((i) >> 24) & 0xff] & 0xff000000)
#define TE42(i) (Te4[((i) >> 16) & 0xff] & 0x00ff0000)
#define TE43(i) (Te4[((i) >> 8) & 0xff] & 0x0000ff00)
#define TE44(i) (Te4[(i) & 0xff] & 0x000000ff)
#define TE421(i) (Te4[((i) >> 16) & 0xff] & 0xff000000)
#define TE432(i) (Te4[((i) >> 8) & 0xff] & 0x00ff0000)
#define TE443(i) (Te4[(i) & 0xff] & 0x0000ff00)
#define TE414(i) (Te4[((i) >> 24) & 0xff] & 0x000000ff)
#define TE411(i) (Te4[((i) >> 24) & 0xff] & 0xff000000)
#define TE422(i) (Te4[((i) >> 16) & 0xff] & 0x00ff0000)
#define TE433(i) (Te4[((i) >> 8) & 0xff] & 0x0000ff00)
#define TE444(i) (Te4[(i) & 0xff] & 0x000000ff)
#define TE4(i) (Te4[(i)] & 0x000000ff)
#define TD0(i) Td0[((i) >> 24) & 0xff]
#define TD1(i) Td1[((i) >> 16) & 0xff]
#define TD2(i) Td2[((i) >> 8) & 0xff]
#define TD3(i) Td3[(i) & 0xff]
#define TD41(i) (Td4[((i) >> 24) & 0xff] & 0xff000000)
#define TD42(i) (Td4[((i) >> 16) & 0xff] & 0x00ff0000)
#define TD43(i) (Td4[((i) >> 8) & 0xff] & 0x0000ff00)
#define TD44(i) (Td4[(i) & 0xff] & 0x000000ff)
#define TD0_(i) Td0[(i) & 0xff]
#define TD1_(i) Td1[(i) & 0xff]
#define TD2_(i) Td2[(i) & 0xff]
#define TD3_(i) Td3[(i) & 0xff]
#else /* AES_SMALL_TABLES */
#define RCON(i) (rcons[(i)] << 24)
static inline NQ_UINT32 rotr(NQ_UINT32 val, NQ_INT bits)
{
	return (val >> bits) | (val << (32 - bits));
}
#define TE0(i) Te0[((i) >> 24) & 0xff]
#define TE1(i) rotr(Te0[((i) >> 16) & 0xff], 8)
#define TE2(i) rotr(Te0[((i) >> 8) & 0xff], 16)
#define TE3(i) rotr(Te0[(i) & 0xff], 24)
#define TE41(i) ((Te0[((i) >> 24) & 0xff] << 8) & 0xff000000)
#define TE42(i) (Te0[((i) >> 16) & 0xff] & 0x00ff0000)
#define TE43(i) (Te0[((i) >> 8) & 0xff] & 0x0000ff00)
#define TE44(i) ((Te0[(i) & 0xff] >> 8) & 0x000000ff)
#define TE421(i) ((Te0[((i) >> 16) & 0xff] << 8) & 0xff000000)
#define TE432(i) (Te0[((i) >> 8) & 0xff] & 0x00ff0000)
#define TE443(i) (Te0[(i) & 0xff] & 0x0000ff00)
#define TE414(i) ((Te0[((i) >> 24) & 0xff] >> 8) & 0x000000ff)
#define TE411(i) ((Te0[((i) >> 24) & 0xff] << 8) & 0xff000000)
#define TE422(i) (Te0[((i) >> 16) & 0xff] & 0x00ff0000)
#define TE433(i) (Te0[((i) >> 8) & 0xff] & 0x0000ff00)
#define TE444(i) ((Te0[(i) & 0xff] >> 8) & 0x000000ff)
#define TE4(i) ((Te0[(i)] >> 8) & 0x000000ff)
#define TD0(i) Td0[((i) >> 24) & 0xff]
#define TD1(i) rotr(Td0[((i) >> 16) & 0xff], 8)
#define TD2(i) rotr(Td0[((i) >> 8) & 0xff], 16)
#define TD3(i) rotr(Td0[(i) & 0xff], 24)
#define TD41(i) (Td4s[((i) >> 24) & 0xff] << 24)
#define TD42(i) (Td4s[((i) >> 16) & 0xff] << 16)
#define TD43(i) (Td4s[((i) >> 8) & 0xff] << 8)
#define TD44(i) (Td4s[(i) & 0xff])
#define TD0_(i) Td0[(i) & 0xff]
#define TD1_(i) rotr(Td0[(i) & 0xff], 8)
#define TD2_(i) rotr(Td0[(i) & 0xff], 16)
#define TD3_(i) rotr(Td0[(i) & 0xff], 24)
#endif /* AES_SMALL_TABLES */
#ifdef _MSC_VER
#define SWAP(x) (_lrotl(x, 8) & 0x00ff00ff | _lrotr(x, 8) & 0xff00ff00)
#define GETU32(p) SWAP(*((NQ_UINT32 *)(p)))
#define PUTU32(ct, st) { *((NQ_UINT32 *)(ct)) = SWAP((st)); }
#else /*_MSC_VER */
#define GETU32(pt) (((NQ_UINT32)(pt)[0] << 24) ^ ((NQ_UINT32)(pt)[1] << 16) ^ \
((NQ_UINT32)(pt)[2] <<  8) ^ ((NQ_UINT32)(pt)[3]))
#define PUTU32(ct, st) { \
(ct)[0] = (NQ_BYTE)((st) >> 24); (ct)[1] = (NQ_BYTE)((st) >> 16); \
(ct)[2] = (NQ_BYTE)((st) >>  8); (ct)[3] = (NQ_BYTE)(st); }
#endif /* _MSC_VER */
#define AES_PRIV_NR_POS (4 * 15)
NQ_INT rijndaelKeySetupEnc(NQ_UINT32 rk[], const NQ_BYTE cipherKey[], NQ_INT keyBits);


/*
 
 * - added option (AES_SMALL_TABLES) for reducing code size by about 8 kB at
 *   cost of reduced throughput (quite small difference on Pentium 4,
 *   10-25% when using -O1 or -O2 optimization)
 */

const NQ_UINT32 Te0[256] = {
    0xc66363a5U, 0xf87c7c84U, 0xee777799U, 0xf67b7b8dU,
    0xfff2f20dU, 0xd66b6bbdU, 0xde6f6fb1U, 0x91c5c554U,
    0x60303050U, 0x02010103U, 0xce6767a9U, 0x562b2b7dU,
    0xe7fefe19U, 0xb5d7d762U, 0x4dababe6U, 0xec76769aU,
    0x8fcaca45U, 0x1f82829dU, 0x89c9c940U, 0xfa7d7d87U,
    0xeffafa15U, 0xb25959ebU, 0x8e4747c9U, 0xfbf0f00bU,
    0x41adadecU, 0xb3d4d467U, 0x5fa2a2fdU, 0x45afafeaU,
    0x239c9cbfU, 0x53a4a4f7U, 0xe4727296U, 0x9bc0c05bU,
    0x75b7b7c2U, 0xe1fdfd1cU, 0x3d9393aeU, 0x4c26266aU,
    0x6c36365aU, 0x7e3f3f41U, 0xf5f7f702U, 0x83cccc4fU,
    0x6834345cU, 0x51a5a5f4U, 0xd1e5e534U, 0xf9f1f108U,
    0xe2717193U, 0xabd8d873U, 0x62313153U, 0x2a15153fU,
    0x0804040cU, 0x95c7c752U, 0x46232365U, 0x9dc3c35eU,
    0x30181828U, 0x379696a1U, 0x0a05050fU, 0x2f9a9ab5U,
    0x0e070709U, 0x24121236U, 0x1b80809bU, 0xdfe2e23dU,
    0xcdebeb26U, 0x4e272769U, 0x7fb2b2cdU, 0xea75759fU,
    0x1209091bU, 0x1d83839eU, 0x582c2c74U, 0x341a1a2eU,
    0x361b1b2dU, 0xdc6e6eb2U, 0xb45a5aeeU, 0x5ba0a0fbU,
    0xa45252f6U, 0x763b3b4dU, 0xb7d6d661U, 0x7db3b3ceU,
    0x5229297bU, 0xdde3e33eU, 0x5e2f2f71U, 0x13848497U,
    0xa65353f5U, 0xb9d1d168U, 0x00000000U, 0xc1eded2cU,
    0x40202060U, 0xe3fcfc1fU, 0x79b1b1c8U, 0xb65b5bedU,
    0xd46a6abeU, 0x8dcbcb46U, 0x67bebed9U, 0x7239394bU,
    0x944a4adeU, 0x984c4cd4U, 0xb05858e8U, 0x85cfcf4aU,
    0xbbd0d06bU, 0xc5efef2aU, 0x4faaaae5U, 0xedfbfb16U,
    0x864343c5U, 0x9a4d4dd7U, 0x66333355U, 0x11858594U,
    0x8a4545cfU, 0xe9f9f910U, 0x04020206U, 0xfe7f7f81U,
    0xa05050f0U, 0x783c3c44U, 0x259f9fbaU, 0x4ba8a8e3U,
    0xa25151f3U, 0x5da3a3feU, 0x804040c0U, 0x058f8f8aU,
    0x3f9292adU, 0x219d9dbcU, 0x70383848U, 0xf1f5f504U,
    0x63bcbcdfU, 0x77b6b6c1U, 0xafdada75U, 0x42212163U,
    0x20101030U, 0xe5ffff1aU, 0xfdf3f30eU, 0xbfd2d26dU,
    0x81cdcd4cU, 0x180c0c14U, 0x26131335U, 0xc3ecec2fU,
    0xbe5f5fe1U, 0x359797a2U, 0x884444ccU, 0x2e171739U,
    0x93c4c457U, 0x55a7a7f2U, 0xfc7e7e82U, 0x7a3d3d47U,
    0xc86464acU, 0xba5d5de7U, 0x3219192bU, 0xe6737395U,
    0xc06060a0U, 0x19818198U, 0x9e4f4fd1U, 0xa3dcdc7fU,
    0x44222266U, 0x542a2a7eU, 0x3b9090abU, 0x0b888883U,
    0x8c4646caU, 0xc7eeee29U, 0x6bb8b8d3U, 0x2814143cU,
    0xa7dede79U, 0xbc5e5ee2U, 0x160b0b1dU, 0xaddbdb76U,
    0xdbe0e03bU, 0x64323256U, 0x743a3a4eU, 0x140a0a1eU,
    0x924949dbU, 0x0c06060aU, 0x4824246cU, 0xb85c5ce4U,
    0x9fc2c25dU, 0xbdd3d36eU, 0x43acacefU, 0xc46262a6U,
    0x399191a8U, 0x319595a4U, 0xd3e4e437U, 0xf279798bU,
    0xd5e7e732U, 0x8bc8c843U, 0x6e373759U, 0xda6d6db7U,
    0x018d8d8cU, 0xb1d5d564U, 0x9c4e4ed2U, 0x49a9a9e0U,
    0xd86c6cb4U, 0xac5656faU, 0xf3f4f407U, 0xcfeaea25U,
    0xca6565afU, 0xf47a7a8eU, 0x47aeaee9U, 0x10080818U,
    0x6fbabad5U, 0xf0787888U, 0x4a25256fU, 0x5c2e2e72U,
    0x381c1c24U, 0x57a6a6f1U, 0x73b4b4c7U, 0x97c6c651U,
    0xcbe8e823U, 0xa1dddd7cU, 0xe874749cU, 0x3e1f1f21U,
    0x964b4bddU, 0x61bdbddcU, 0x0d8b8b86U, 0x0f8a8a85U,
    0xe0707090U, 0x7c3e3e42U, 0x71b5b5c4U, 0xcc6666aaU,
    0x904848d8U, 0x06030305U, 0xf7f6f601U, 0x1c0e0e12U,
    0xc26161a3U, 0x6a35355fU, 0xae5757f9U, 0x69b9b9d0U,
    0x17868691U, 0x99c1c158U, 0x3a1d1d27U, 0x279e9eb9U,
    0xd9e1e138U, 0xebf8f813U, 0x2b9898b3U, 0x22111133U,
    0xd26969bbU, 0xa9d9d970U, 0x078e8e89U, 0x339494a7U,
    0x2d9b9bb6U, 0x3c1e1e22U, 0x15878792U, 0xc9e9e920U,
    0x87cece49U, 0xaa5555ffU, 0x50282878U, 0xa5dfdf7aU,
    0x038c8c8fU, 0x59a1a1f8U, 0x09898980U, 0x1a0d0d17U,
    0x65bfbfdaU, 0xd7e6e631U, 0x844242c6U, 0xd06868b8U,
    0x824141c3U, 0x299999b0U, 0x5a2d2d77U, 0x1e0f0f11U,
    0x7bb0b0cbU, 0xa85454fcU, 0x6dbbbbd6U, 0x2c16163aU,
};
#ifndef AES_SMALL_TABLES
const NQ_UINT32 Te1[256] = {
    0xa5c66363U, 0x84f87c7cU, 0x99ee7777U, 0x8df67b7bU,
    0x0dfff2f2U, 0xbdd66b6bU, 0xb1de6f6fU, 0x5491c5c5U,
    0x50603030U, 0x03020101U, 0xa9ce6767U, 0x7d562b2bU,
    0x19e7fefeU, 0x62b5d7d7U, 0xe64dababU, 0x9aec7676U,
    0x458fcacaU, 0x9d1f8282U, 0x4089c9c9U, 0x87fa7d7dU,
    0x15effafaU, 0xebb25959U, 0xc98e4747U, 0x0bfbf0f0U,
    0xec41adadU, 0x67b3d4d4U, 0xfd5fa2a2U, 0xea45afafU,
    0xbf239c9cU, 0xf753a4a4U, 0x96e47272U, 0x5b9bc0c0U,
    0xc275b7b7U, 0x1ce1fdfdU, 0xae3d9393U, 0x6a4c2626U,
    0x5a6c3636U, 0x417e3f3fU, 0x02f5f7f7U, 0x4f83ccccU,
    0x5c683434U, 0xf451a5a5U, 0x34d1e5e5U, 0x08f9f1f1U,
    0x93e27171U, 0x73abd8d8U, 0x53623131U, 0x3f2a1515U,
    0x0c080404U, 0x5295c7c7U, 0x65462323U, 0x5e9dc3c3U,
    0x28301818U, 0xa1379696U, 0x0f0a0505U, 0xb52f9a9aU,
    0x090e0707U, 0x36241212U, 0x9b1b8080U, 0x3ddfe2e2U,
    0x26cdebebU, 0x694e2727U, 0xcd7fb2b2U, 0x9fea7575U,
    0x1b120909U, 0x9e1d8383U, 0x74582c2cU, 0x2e341a1aU,
    0x2d361b1bU, 0xb2dc6e6eU, 0xeeb45a5aU, 0xfb5ba0a0U,
    0xf6a45252U, 0x4d763b3bU, 0x61b7d6d6U, 0xce7db3b3U,
    0x7b522929U, 0x3edde3e3U, 0x715e2f2fU, 0x97138484U,
    0xf5a65353U, 0x68b9d1d1U, 0x00000000U, 0x2cc1ededU,
    0x60402020U, 0x1fe3fcfcU, 0xc879b1b1U, 0xedb65b5bU,
    0xbed46a6aU, 0x468dcbcbU, 0xd967bebeU, 0x4b723939U,
    0xde944a4aU, 0xd4984c4cU, 0xe8b05858U, 0x4a85cfcfU,
    0x6bbbd0d0U, 0x2ac5efefU, 0xe54faaaaU, 0x16edfbfbU,
    0xc5864343U, 0xd79a4d4dU, 0x55663333U, 0x94118585U,
    0xcf8a4545U, 0x10e9f9f9U, 0x06040202U, 0x81fe7f7fU,
    0xf0a05050U, 0x44783c3cU, 0xba259f9fU, 0xe34ba8a8U,
    0xf3a25151U, 0xfe5da3a3U, 0xc0804040U, 0x8a058f8fU,
    0xad3f9292U, 0xbc219d9dU, 0x48703838U, 0x04f1f5f5U,
    0xdf63bcbcU, 0xc177b6b6U, 0x75afdadaU, 0x63422121U,
    0x30201010U, 0x1ae5ffffU, 0x0efdf3f3U, 0x6dbfd2d2U,
    0x4c81cdcdU, 0x14180c0cU, 0x35261313U, 0x2fc3ececU,
    0xe1be5f5fU, 0xa2359797U, 0xcc884444U, 0x392e1717U,
    0x5793c4c4U, 0xf255a7a7U, 0x82fc7e7eU, 0x477a3d3dU,
    0xacc86464U, 0xe7ba5d5dU, 0x2b321919U, 0x95e67373U,
    0xa0c06060U, 0x98198181U, 0xd19e4f4fU, 0x7fa3dcdcU,
    0x66442222U, 0x7e542a2aU, 0xab3b9090U, 0x830b8888U,
    0xca8c4646U, 0x29c7eeeeU, 0xd36bb8b8U, 0x3c281414U,
    0x79a7dedeU, 0xe2bc5e5eU, 0x1d160b0bU, 0x76addbdbU,
    0x3bdbe0e0U, 0x56643232U, 0x4e743a3aU, 0x1e140a0aU,
    0xdb924949U, 0x0a0c0606U, 0x6c482424U, 0xe4b85c5cU,
    0x5d9fc2c2U, 0x6ebdd3d3U, 0xef43acacU, 0xa6c46262U,
    0xa8399191U, 0xa4319595U, 0x37d3e4e4U, 0x8bf27979U,
    0x32d5e7e7U, 0x438bc8c8U, 0x596e3737U, 0xb7da6d6dU,
    0x8c018d8dU, 0x64b1d5d5U, 0xd29c4e4eU, 0xe049a9a9U,
    0xb4d86c6cU, 0xfaac5656U, 0x07f3f4f4U, 0x25cfeaeaU,
    0xafca6565U, 0x8ef47a7aU, 0xe947aeaeU, 0x18100808U,
    0xd56fbabaU, 0x88f07878U, 0x6f4a2525U, 0x725c2e2eU,
    0x24381c1cU, 0xf157a6a6U, 0xc773b4b4U, 0x5197c6c6U,
    0x23cbe8e8U, 0x7ca1ddddU, 0x9ce87474U, 0x213e1f1fU,
    0xdd964b4bU, 0xdc61bdbdU, 0x860d8b8bU, 0x850f8a8aU,
    0x90e07070U, 0x427c3e3eU, 0xc471b5b5U, 0xaacc6666U,
    0xd8904848U, 0x05060303U, 0x01f7f6f6U, 0x121c0e0eU,
    0xa3c26161U, 0x5f6a3535U, 0xf9ae5757U, 0xd069b9b9U,
    0x91178686U, 0x5899c1c1U, 0x273a1d1dU, 0xb9279e9eU,
    0x38d9e1e1U, 0x13ebf8f8U, 0xb32b9898U, 0x33221111U,
    0xbbd26969U, 0x70a9d9d9U, 0x89078e8eU, 0xa7339494U,
    0xb62d9b9bU, 0x223c1e1eU, 0x92158787U, 0x20c9e9e9U,
    0x4987ceceU, 0xffaa5555U, 0x78502828U, 0x7aa5dfdfU,
    0x8f038c8cU, 0xf859a1a1U, 0x80098989U, 0x171a0d0dU,
    0xda65bfbfU, 0x31d7e6e6U, 0xc6844242U, 0xb8d06868U,
    0xc3824141U, 0xb0299999U, 0x775a2d2dU, 0x111e0f0fU,
    0xcb7bb0b0U, 0xfca85454U, 0xd66dbbbbU, 0x3a2c1616U,
};
const NQ_UINT32 Te2[256] = {
    0x63a5c663U, 0x7c84f87cU, 0x7799ee77U, 0x7b8df67bU,
    0xf20dfff2U, 0x6bbdd66bU, 0x6fb1de6fU, 0xc55491c5U,
    0x30506030U, 0x01030201U, 0x67a9ce67U, 0x2b7d562bU,
    0xfe19e7feU, 0xd762b5d7U, 0xabe64dabU, 0x769aec76U,
    0xca458fcaU, 0x829d1f82U, 0xc94089c9U, 0x7d87fa7dU,
    0xfa15effaU, 0x59ebb259U, 0x47c98e47U, 0xf00bfbf0U,
    0xadec41adU, 0xd467b3d4U, 0xa2fd5fa2U, 0xafea45afU,
    0x9cbf239cU, 0xa4f753a4U, 0x7296e472U, 0xc05b9bc0U,
    0xb7c275b7U, 0xfd1ce1fdU, 0x93ae3d93U, 0x266a4c26U,
    0x365a6c36U, 0x3f417e3fU, 0xf702f5f7U, 0xcc4f83ccU,
    0x345c6834U, 0xa5f451a5U, 0xe534d1e5U, 0xf108f9f1U,
    0x7193e271U, 0xd873abd8U, 0x31536231U, 0x153f2a15U,
    0x040c0804U, 0xc75295c7U, 0x23654623U, 0xc35e9dc3U,
    0x18283018U, 0x96a13796U, 0x050f0a05U, 0x9ab52f9aU,
    0x07090e07U, 0x12362412U, 0x809b1b80U, 0xe23ddfe2U,
    0xeb26cdebU, 0x27694e27U, 0xb2cd7fb2U, 0x759fea75U,
    0x091b1209U, 0x839e1d83U, 0x2c74582cU, 0x1a2e341aU,
    0x1b2d361bU, 0x6eb2dc6eU, 0x5aeeb45aU, 0xa0fb5ba0U,
    0x52f6a452U, 0x3b4d763bU, 0xd661b7d6U, 0xb3ce7db3U,
    0x297b5229U, 0xe33edde3U, 0x2f715e2fU, 0x84971384U,
    0x53f5a653U, 0xd168b9d1U, 0x00000000U, 0xed2cc1edU,
    0x20604020U, 0xfc1fe3fcU, 0xb1c879b1U, 0x5bedb65bU,
    0x6abed46aU, 0xcb468dcbU, 0xbed967beU, 0x394b7239U,
    0x4ade944aU, 0x4cd4984cU, 0x58e8b058U, 0xcf4a85cfU,
    0xd06bbbd0U, 0xef2ac5efU, 0xaae54faaU, 0xfb16edfbU,
    0x43c58643U, 0x4dd79a4dU, 0x33556633U, 0x85941185U,
    0x45cf8a45U, 0xf910e9f9U, 0x02060402U, 0x7f81fe7fU,
    0x50f0a050U, 0x3c44783cU, 0x9fba259fU, 0xa8e34ba8U,
    0x51f3a251U, 0xa3fe5da3U, 0x40c08040U, 0x8f8a058fU,
    0x92ad3f92U, 0x9dbc219dU, 0x38487038U, 0xf504f1f5U,
    0xbcdf63bcU, 0xb6c177b6U, 0xda75afdaU, 0x21634221U,
    0x10302010U, 0xff1ae5ffU, 0xf30efdf3U, 0xd26dbfd2U,
    0xcd4c81cdU, 0x0c14180cU, 0x13352613U, 0xec2fc3ecU,
    0x5fe1be5fU, 0x97a23597U, 0x44cc8844U, 0x17392e17U,
    0xc45793c4U, 0xa7f255a7U, 0x7e82fc7eU, 0x3d477a3dU,
    0x64acc864U, 0x5de7ba5dU, 0x192b3219U, 0x7395e673U,
    0x60a0c060U, 0x81981981U, 0x4fd19e4fU, 0xdc7fa3dcU,
    0x22664422U, 0x2a7e542aU, 0x90ab3b90U, 0x88830b88U,
    0x46ca8c46U, 0xee29c7eeU, 0xb8d36bb8U, 0x143c2814U,
    0xde79a7deU, 0x5ee2bc5eU, 0x0b1d160bU, 0xdb76addbU,
    0xe03bdbe0U, 0x32566432U, 0x3a4e743aU, 0x0a1e140aU,
    0x49db9249U, 0x060a0c06U, 0x246c4824U, 0x5ce4b85cU,
    0xc25d9fc2U, 0xd36ebdd3U, 0xacef43acU, 0x62a6c462U,
    0x91a83991U, 0x95a43195U, 0xe437d3e4U, 0x798bf279U,
    0xe732d5e7U, 0xc8438bc8U, 0x37596e37U, 0x6db7da6dU,
    0x8d8c018dU, 0xd564b1d5U, 0x4ed29c4eU, 0xa9e049a9U,
    0x6cb4d86cU, 0x56faac56U, 0xf407f3f4U, 0xea25cfeaU,
    0x65afca65U, 0x7a8ef47aU, 0xaee947aeU, 0x08181008U,
    0xbad56fbaU, 0x7888f078U, 0x256f4a25U, 0x2e725c2eU,
    0x1c24381cU, 0xa6f157a6U, 0xb4c773b4U, 0xc65197c6U,
    0xe823cbe8U, 0xdd7ca1ddU, 0x749ce874U, 0x1f213e1fU,
    0x4bdd964bU, 0xbddc61bdU, 0x8b860d8bU, 0x8a850f8aU,
    0x7090e070U, 0x3e427c3eU, 0xb5c471b5U, 0x66aacc66U,
    0x48d89048U, 0x03050603U, 0xf601f7f6U, 0x0e121c0eU,
    0x61a3c261U, 0x355f6a35U, 0x57f9ae57U, 0xb9d069b9U,
    0x86911786U, 0xc15899c1U, 0x1d273a1dU, 0x9eb9279eU,
    0xe138d9e1U, 0xf813ebf8U, 0x98b32b98U, 0x11332211U,
    0x69bbd269U, 0xd970a9d9U, 0x8e89078eU, 0x94a73394U,
    0x9bb62d9bU, 0x1e223c1eU, 0x87921587U, 0xe920c9e9U,
    0xce4987ceU, 0x55ffaa55U, 0x28785028U, 0xdf7aa5dfU,
    0x8c8f038cU, 0xa1f859a1U, 0x89800989U, 0x0d171a0dU,
    0xbfda65bfU, 0xe631d7e6U, 0x42c68442U, 0x68b8d068U,
    0x41c38241U, 0x99b02999U, 0x2d775a2dU, 0x0f111e0fU,
    0xb0cb7bb0U, 0x54fca854U, 0xbbd66dbbU, 0x163a2c16U,
};
const NQ_UINT32 Te3[256] = {
    0x6363a5c6U, 0x7c7c84f8U, 0x777799eeU, 0x7b7b8df6U,
    0xf2f20dffU, 0x6b6bbdd6U, 0x6f6fb1deU, 0xc5c55491U,
    0x30305060U, 0x01010302U, 0x6767a9ceU, 0x2b2b7d56U,
    0xfefe19e7U, 0xd7d762b5U, 0xababe64dU, 0x76769aecU,
    0xcaca458fU, 0x82829d1fU, 0xc9c94089U, 0x7d7d87faU,
    0xfafa15efU, 0x5959ebb2U, 0x4747c98eU, 0xf0f00bfbU,
    0xadadec41U, 0xd4d467b3U, 0xa2a2fd5fU, 0xafafea45U,
    0x9c9cbf23U, 0xa4a4f753U, 0x727296e4U, 0xc0c05b9bU,
    0xb7b7c275U, 0xfdfd1ce1U, 0x9393ae3dU, 0x26266a4cU,
    0x36365a6cU, 0x3f3f417eU, 0xf7f702f5U, 0xcccc4f83U,
    0x34345c68U, 0xa5a5f451U, 0xe5e534d1U, 0xf1f108f9U,
    0x717193e2U, 0xd8d873abU, 0x31315362U, 0x15153f2aU,
    0x04040c08U, 0xc7c75295U, 0x23236546U, 0xc3c35e9dU,
    0x18182830U, 0x9696a137U, 0x05050f0aU, 0x9a9ab52fU,
    0x0707090eU, 0x12123624U, 0x80809b1bU, 0xe2e23ddfU,
    0xebeb26cdU, 0x2727694eU, 0xb2b2cd7fU, 0x75759feaU,
    0x09091b12U, 0x83839e1dU, 0x2c2c7458U, 0x1a1a2e34U,
    0x1b1b2d36U, 0x6e6eb2dcU, 0x5a5aeeb4U, 0xa0a0fb5bU,
    0x5252f6a4U, 0x3b3b4d76U, 0xd6d661b7U, 0xb3b3ce7dU,
    0x29297b52U, 0xe3e33eddU, 0x2f2f715eU, 0x84849713U,
    0x5353f5a6U, 0xd1d168b9U, 0x00000000U, 0xeded2cc1U,
    0x20206040U, 0xfcfc1fe3U, 0xb1b1c879U, 0x5b5bedb6U,
    0x6a6abed4U, 0xcbcb468dU, 0xbebed967U, 0x39394b72U,
    0x4a4ade94U, 0x4c4cd498U, 0x5858e8b0U, 0xcfcf4a85U,
    0xd0d06bbbU, 0xefef2ac5U, 0xaaaae54fU, 0xfbfb16edU,
    0x4343c586U, 0x4d4dd79aU, 0x33335566U, 0x85859411U,
    0x4545cf8aU, 0xf9f910e9U, 0x02020604U, 0x7f7f81feU,
    0x5050f0a0U, 0x3c3c4478U, 0x9f9fba25U, 0xa8a8e34bU,
    0x5151f3a2U, 0xa3a3fe5dU, 0x4040c080U, 0x8f8f8a05U,
    0x9292ad3fU, 0x9d9dbc21U, 0x38384870U, 0xf5f504f1U,
    0xbcbcdf63U, 0xb6b6c177U, 0xdada75afU, 0x21216342U,
    0x10103020U, 0xffff1ae5U, 0xf3f30efdU, 0xd2d26dbfU,
    0xcdcd4c81U, 0x0c0c1418U, 0x13133526U, 0xecec2fc3U,
    0x5f5fe1beU, 0x9797a235U, 0x4444cc88U, 0x1717392eU,
    0xc4c45793U, 0xa7a7f255U, 0x7e7e82fcU, 0x3d3d477aU,
    0x6464acc8U, 0x5d5de7baU, 0x19192b32U, 0x737395e6U,
    0x6060a0c0U, 0x81819819U, 0x4f4fd19eU, 0xdcdc7fa3U,
    0x22226644U, 0x2a2a7e54U, 0x9090ab3bU, 0x8888830bU,
    0x4646ca8cU, 0xeeee29c7U, 0xb8b8d36bU, 0x14143c28U,
    0xdede79a7U, 0x5e5ee2bcU, 0x0b0b1d16U, 0xdbdb76adU,
    0xe0e03bdbU, 0x32325664U, 0x3a3a4e74U, 0x0a0a1e14U,
    0x4949db92U, 0x06060a0cU, 0x24246c48U, 0x5c5ce4b8U,
    0xc2c25d9fU, 0xd3d36ebdU, 0xacacef43U, 0x6262a6c4U,
    0x9191a839U, 0x9595a431U, 0xe4e437d3U, 0x79798bf2U,
    0xe7e732d5U, 0xc8c8438bU, 0x3737596eU, 0x6d6db7daU,
    0x8d8d8c01U, 0xd5d564b1U, 0x4e4ed29cU, 0xa9a9e049U,
    0x6c6cb4d8U, 0x5656faacU, 0xf4f407f3U, 0xeaea25cfU,
    0x6565afcaU, 0x7a7a8ef4U, 0xaeaee947U, 0x08081810U,
    0xbabad56fU, 0x787888f0U, 0x25256f4aU, 0x2e2e725cU,
    0x1c1c2438U, 0xa6a6f157U, 0xb4b4c773U, 0xc6c65197U,
    0xe8e823cbU, 0xdddd7ca1U, 0x74749ce8U, 0x1f1f213eU,
    0x4b4bdd96U, 0xbdbddc61U, 0x8b8b860dU, 0x8a8a850fU,
    0x707090e0U, 0x3e3e427cU, 0xb5b5c471U, 0x6666aaccU,
    0x4848d890U, 0x03030506U, 0xf6f601f7U, 0x0e0e121cU,
    0x6161a3c2U, 0x35355f6aU, 0x5757f9aeU, 0xb9b9d069U,
    0x86869117U, 0xc1c15899U, 0x1d1d273aU, 0x9e9eb927U,
    0xe1e138d9U, 0xf8f813ebU, 0x9898b32bU, 0x11113322U,
    0x6969bbd2U, 0xd9d970a9U, 0x8e8e8907U, 0x9494a733U,
    0x9b9bb62dU, 0x1e1e223cU, 0x87879215U, 0xe9e920c9U,
    0xcece4987U, 0x5555ffaaU, 0x28287850U, 0xdfdf7aa5U,
    0x8c8c8f03U, 0xa1a1f859U, 0x89898009U, 0x0d0d171aU,
    0xbfbfda65U, 0xe6e631d7U, 0x4242c684U, 0x6868b8d0U,
    0x4141c382U, 0x9999b029U, 0x2d2d775aU, 0x0f0f111eU,
    0xb0b0cb7bU, 0x5454fca8U, 0xbbbbd66dU, 0x16163a2cU,
};
const NQ_UINT32 Te4[256] = {
    0x63636363U, 0x7c7c7c7cU, 0x77777777U, 0x7b7b7b7bU,
    0xf2f2f2f2U, 0x6b6b6b6bU, 0x6f6f6f6fU, 0xc5c5c5c5U,
    0x30303030U, 0x01010101U, 0x67676767U, 0x2b2b2b2bU,
    0xfefefefeU, 0xd7d7d7d7U, 0xababababU, 0x76767676U,
    0xcacacacaU, 0x82828282U, 0xc9c9c9c9U, 0x7d7d7d7dU,
    0xfafafafaU, 0x59595959U, 0x47474747U, 0xf0f0f0f0U,
    0xadadadadU, 0xd4d4d4d4U, 0xa2a2a2a2U, 0xafafafafU,
    0x9c9c9c9cU, 0xa4a4a4a4U, 0x72727272U, 0xc0c0c0c0U,
    0xb7b7b7b7U, 0xfdfdfdfdU, 0x93939393U, 0x26262626U,
    0x36363636U, 0x3f3f3f3fU, 0xf7f7f7f7U, 0xccccccccU,
    0x34343434U, 0xa5a5a5a5U, 0xe5e5e5e5U, 0xf1f1f1f1U,
    0x71717171U, 0xd8d8d8d8U, 0x31313131U, 0x15151515U,
    0x04040404U, 0xc7c7c7c7U, 0x23232323U, 0xc3c3c3c3U,
    0x18181818U, 0x96969696U, 0x05050505U, 0x9a9a9a9aU,
    0x07070707U, 0x12121212U, 0x80808080U, 0xe2e2e2e2U,
    0xebebebebU, 0x27272727U, 0xb2b2b2b2U, 0x75757575U,
    0x09090909U, 0x83838383U, 0x2c2c2c2cU, 0x1a1a1a1aU,
    0x1b1b1b1bU, 0x6e6e6e6eU, 0x5a5a5a5aU, 0xa0a0a0a0U,
    0x52525252U, 0x3b3b3b3bU, 0xd6d6d6d6U, 0xb3b3b3b3U,
    0x29292929U, 0xe3e3e3e3U, 0x2f2f2f2fU, 0x84848484U,
    0x53535353U, 0xd1d1d1d1U, 0x00000000U, 0xededededU,
    0x20202020U, 0xfcfcfcfcU, 0xb1b1b1b1U, 0x5b5b5b5bU,
    0x6a6a6a6aU, 0xcbcbcbcbU, 0xbebebebeU, 0x39393939U,
    0x4a4a4a4aU, 0x4c4c4c4cU, 0x58585858U, 0xcfcfcfcfU,
    0xd0d0d0d0U, 0xefefefefU, 0xaaaaaaaaU, 0xfbfbfbfbU,
    0x43434343U, 0x4d4d4d4dU, 0x33333333U, 0x85858585U,
    0x45454545U, 0xf9f9f9f9U, 0x02020202U, 0x7f7f7f7fU,
    0x50505050U, 0x3c3c3c3cU, 0x9f9f9f9fU, 0xa8a8a8a8U,
    0x51515151U, 0xa3a3a3a3U, 0x40404040U, 0x8f8f8f8fU,
    0x92929292U, 0x9d9d9d9dU, 0x38383838U, 0xf5f5f5f5U,
    0xbcbcbcbcU, 0xb6b6b6b6U, 0xdadadadaU, 0x21212121U,
    0x10101010U, 0xffffffffU, 0xf3f3f3f3U, 0xd2d2d2d2U,
    0xcdcdcdcdU, 0x0c0c0c0cU, 0x13131313U, 0xececececU,
    0x5f5f5f5fU, 0x97979797U, 0x44444444U, 0x17171717U,
    0xc4c4c4c4U, 0xa7a7a7a7U, 0x7e7e7e7eU, 0x3d3d3d3dU,
    0x64646464U, 0x5d5d5d5dU, 0x19191919U, 0x73737373U,
    0x60606060U, 0x81818181U, 0x4f4f4f4fU, 0xdcdcdcdcU,
    0x22222222U, 0x2a2a2a2aU, 0x90909090U, 0x88888888U,
    0x46464646U, 0xeeeeeeeeU, 0xb8b8b8b8U, 0x14141414U,
    0xdedededeU, 0x5e5e5e5eU, 0x0b0b0b0bU, 0xdbdbdbdbU,
    0xe0e0e0e0U, 0x32323232U, 0x3a3a3a3aU, 0x0a0a0a0aU,
    0x49494949U, 0x06060606U, 0x24242424U, 0x5c5c5c5cU,
    0xc2c2c2c2U, 0xd3d3d3d3U, 0xacacacacU, 0x62626262U,
    0x91919191U, 0x95959595U, 0xe4e4e4e4U, 0x79797979U,
    0xe7e7e7e7U, 0xc8c8c8c8U, 0x37373737U, 0x6d6d6d6dU,
    0x8d8d8d8dU, 0xd5d5d5d5U, 0x4e4e4e4eU, 0xa9a9a9a9U,
    0x6c6c6c6cU, 0x56565656U, 0xf4f4f4f4U, 0xeaeaeaeaU,
    0x65656565U, 0x7a7a7a7aU, 0xaeaeaeaeU, 0x08080808U,
    0xbabababaU, 0x78787878U, 0x25252525U, 0x2e2e2e2eU,
    0x1c1c1c1cU, 0xa6a6a6a6U, 0xb4b4b4b4U, 0xc6c6c6c6U,
    0xe8e8e8e8U, 0xddddddddU, 0x74747474U, 0x1f1f1f1fU,
    0x4b4b4b4bU, 0xbdbdbdbdU, 0x8b8b8b8bU, 0x8a8a8a8aU,
    0x70707070U, 0x3e3e3e3eU, 0xb5b5b5b5U, 0x66666666U,
    0x48484848U, 0x03030303U, 0xf6f6f6f6U, 0x0e0e0e0eU,
    0x61616161U, 0x35353535U, 0x57575757U, 0xb9b9b9b9U,
    0x86868686U, 0xc1c1c1c1U, 0x1d1d1d1dU, 0x9e9e9e9eU,
    0xe1e1e1e1U, 0xf8f8f8f8U, 0x98989898U, 0x11111111U,
    0x69696969U, 0xd9d9d9d9U, 0x8e8e8e8eU, 0x94949494U,
    0x9b9b9b9bU, 0x1e1e1e1eU, 0x87878787U, 0xe9e9e9e9U,
    0xcecececeU, 0x55555555U, 0x28282828U, 0xdfdfdfdfU,
    0x8c8c8c8cU, 0xa1a1a1a1U, 0x89898989U, 0x0d0d0d0dU,
    0xbfbfbfbfU, 0xe6e6e6e6U, 0x42424242U, 0x68686868U,
    0x41414141U, 0x99999999U, 0x2d2d2d2dU, 0x0f0f0f0fU,
    0xb0b0b0b0U, 0x54545454U, 0xbbbbbbbbU, 0x16161616U,
};
#endif /* AES_SMALL_TABLES */
const NQ_UINT32 Td0[256] = {
    0x51f4a750U, 0x7e416553U, 0x1a17a4c3U, 0x3a275e96U,
    0x3bab6bcbU, 0x1f9d45f1U, 0xacfa58abU, 0x4be30393U,
    0x2030fa55U, 0xad766df6U, 0x88cc7691U, 0xf5024c25U,
    0x4fe5d7fcU, 0xc52acbd7U, 0x26354480U, 0xb562a38fU,
    0xdeb15a49U, 0x25ba1b67U, 0x45ea0e98U, 0x5dfec0e1U,
    0xc32f7502U, 0x814cf012U, 0x8d4697a3U, 0x6bd3f9c6U,
    0x038f5fe7U, 0x15929c95U, 0xbf6d7aebU, 0x955259daU,
    0xd4be832dU, 0x587421d3U, 0x49e06929U, 0x8ec9c844U,
    0x75c2896aU, 0xf48e7978U, 0x99583e6bU, 0x27b971ddU,
    0xbee14fb6U, 0xf088ad17U, 0xc920ac66U, 0x7dce3ab4U,
    0x63df4a18U, 0xe51a3182U, 0x97513360U, 0x62537f45U,
    0xb16477e0U, 0xbb6bae84U, 0xfe81a01cU, 0xf9082b94U,
    0x70486858U, 0x8f45fd19U, 0x94de6c87U, 0x527bf8b7U,
    0xab73d323U, 0x724b02e2U, 0xe31f8f57U, 0x6655ab2aU,
    0xb2eb2807U, 0x2fb5c203U, 0x86c57b9aU, 0xd33708a5U,
    0x302887f2U, 0x23bfa5b2U, 0x02036abaU, 0xed16825cU,
    0x8acf1c2bU, 0xa779b492U, 0xf307f2f0U, 0x4e69e2a1U,
    0x65daf4cdU, 0x0605bed5U, 0xd134621fU, 0xc4a6fe8aU,
    0x342e539dU, 0xa2f355a0U, 0x058ae132U, 0xa4f6eb75U,
    0x0b83ec39U, 0x4060efaaU, 0x5e719f06U, 0xbd6e1051U,
    0x3e218af9U, 0x96dd063dU, 0xdd3e05aeU, 0x4de6bd46U,
    0x91548db5U, 0x71c45d05U, 0x0406d46fU, 0x605015ffU,
    0x1998fb24U, 0xd6bde997U, 0x894043ccU, 0x67d99e77U,
    0xb0e842bdU, 0x07898b88U, 0xe7195b38U, 0x79c8eedbU,
    0xa17c0a47U, 0x7c420fe9U, 0xf8841ec9U, 0x00000000U,
    0x09808683U, 0x322bed48U, 0x1e1170acU, 0x6c5a724eU,
    0xfd0efffbU, 0x0f853856U, 0x3daed51eU, 0x362d3927U,
    0x0a0fd964U, 0x685ca621U, 0x9b5b54d1U, 0x24362e3aU,
    0x0c0a67b1U, 0x9357e70fU, 0xb4ee96d2U, 0x1b9b919eU,
    0x80c0c54fU, 0x61dc20a2U, 0x5a774b69U, 0x1c121a16U,
    0xe293ba0aU, 0xc0a02ae5U, 0x3c22e043U, 0x121b171dU,
    0x0e090d0bU, 0xf28bc7adU, 0x2db6a8b9U, 0x141ea9c8U,
    0x57f11985U, 0xaf75074cU, 0xee99ddbbU, 0xa37f60fdU,
    0xf701269fU, 0x5c72f5bcU, 0x44663bc5U, 0x5bfb7e34U,
    0x8b432976U, 0xcb23c6dcU, 0xb6edfc68U, 0xb8e4f163U,
    0xd731dccaU, 0x42638510U, 0x13972240U, 0x84c61120U,
    0x854a247dU, 0xd2bb3df8U, 0xaef93211U, 0xc729a16dU,
    0x1d9e2f4bU, 0xdcb230f3U, 0x0d8652ecU, 0x77c1e3d0U,
    0x2bb3166cU, 0xa970b999U, 0x119448faU, 0x47e96422U,
    0xa8fc8cc4U, 0xa0f03f1aU, 0x567d2cd8U, 0x223390efU,
    0x87494ec7U, 0xd938d1c1U, 0x8ccaa2feU, 0x98d40b36U,
    0xa6f581cfU, 0xa57ade28U, 0xdab78e26U, 0x3fadbfa4U,
    0x2c3a9de4U, 0x5078920dU, 0x6a5fcc9bU, 0x547e4662U,
    0xf68d13c2U, 0x90d8b8e8U, 0x2e39f75eU, 0x82c3aff5U,
    0x9f5d80beU, 0x69d0937cU, 0x6fd52da9U, 0xcf2512b3U,
    0xc8ac993bU, 0x10187da7U, 0xe89c636eU, 0xdb3bbb7bU,
    0xcd267809U, 0x6e5918f4U, 0xec9ab701U, 0x834f9aa8U,
    0xe6956e65U, 0xaaffe67eU, 0x21bccf08U, 0xef15e8e6U,
    0xbae79bd9U, 0x4a6f36ceU, 0xea9f09d4U, 0x29b07cd6U,
    0x31a4b2afU, 0x2a3f2331U, 0xc6a59430U, 0x35a266c0U,
    0x744ebc37U, 0xfc82caa6U, 0xe090d0b0U, 0x33a7d815U,
    0xf104984aU, 0x41ecdaf7U, 0x7fcd500eU, 0x1791f62fU,
    0x764dd68dU, 0x43efb04dU, 0xccaa4d54U, 0xe49604dfU,
    0x9ed1b5e3U, 0x4c6a881bU, 0xc12c1fb8U, 0x4665517fU,
    0x9d5eea04U, 0x018c355dU, 0xfa877473U, 0xfb0b412eU,
    0xb3671d5aU, 0x92dbd252U, 0xe9105633U, 0x6dd64713U,
    0x9ad7618cU, 0x37a10c7aU, 0x59f8148eU, 0xeb133c89U,
    0xcea927eeU, 0xb761c935U, 0xe11ce5edU, 0x7a47b13cU,
    0x9cd2df59U, 0x55f2733fU, 0x1814ce79U, 0x73c737bfU,
    0x53f7cdeaU, 0x5ffdaa5bU, 0xdf3d6f14U, 0x7844db86U,
    0xcaaff381U, 0xb968c43eU, 0x3824342cU, 0xc2a3405fU,
    0x161dc372U, 0xbce2250cU, 0x283c498bU, 0xff0d9541U,
    0x39a80171U, 0x080cb3deU, 0xd8b4e49cU, 0x6456c190U,
    0x7bcb8461U, 0xd532b670U, 0x486c5c74U, 0xd0b85742U,
};
#ifndef AES_SMALL_TABLES
const NQ_UINT32 Td1[256] = {
    0x5051f4a7U, 0x537e4165U, 0xc31a17a4U, 0x963a275eU,
    0xcb3bab6bU, 0xf11f9d45U, 0xabacfa58U, 0x934be303U,
    0x552030faU, 0xf6ad766dU, 0x9188cc76U, 0x25f5024cU,
    0xfc4fe5d7U, 0xd7c52acbU, 0x80263544U, 0x8fb562a3U,
    0x49deb15aU, 0x6725ba1bU, 0x9845ea0eU, 0xe15dfec0U,
    0x02c32f75U, 0x12814cf0U, 0xa38d4697U, 0xc66bd3f9U,
    0xe7038f5fU, 0x9515929cU, 0xebbf6d7aU, 0xda955259U,
    0x2dd4be83U, 0xd3587421U, 0x2949e069U, 0x448ec9c8U,
    0x6a75c289U, 0x78f48e79U, 0x6b99583eU, 0xdd27b971U,
    0xb6bee14fU, 0x17f088adU, 0x66c920acU, 0xb47dce3aU,
    0x1863df4aU, 0x82e51a31U, 0x60975133U, 0x4562537fU,
    0xe0b16477U, 0x84bb6baeU, 0x1cfe81a0U, 0x94f9082bU,
    0x58704868U, 0x198f45fdU, 0x8794de6cU, 0xb7527bf8U,
    0x23ab73d3U, 0xe2724b02U, 0x57e31f8fU, 0x2a6655abU,
    0x07b2eb28U, 0x032fb5c2U, 0x9a86c57bU, 0xa5d33708U,
    0xf2302887U, 0xb223bfa5U, 0xba02036aU, 0x5ced1682U,
    0x2b8acf1cU, 0x92a779b4U, 0xf0f307f2U, 0xa14e69e2U,
    0xcd65daf4U, 0xd50605beU, 0x1fd13462U, 0x8ac4a6feU,
    0x9d342e53U, 0xa0a2f355U, 0x32058ae1U, 0x75a4f6ebU,
    0x390b83ecU, 0xaa4060efU, 0x065e719fU, 0x51bd6e10U,
    0xf93e218aU, 0x3d96dd06U, 0xaedd3e05U, 0x464de6bdU,
    0xb591548dU, 0x0571c45dU, 0x6f0406d4U, 0xff605015U,
    0x241998fbU, 0x97d6bde9U, 0xcc894043U, 0x7767d99eU,
    0xbdb0e842U, 0x8807898bU, 0x38e7195bU, 0xdb79c8eeU,
    0x47a17c0aU, 0xe97c420fU, 0xc9f8841eU, 0x00000000U,
    0x83098086U, 0x48322bedU, 0xac1e1170U, 0x4e6c5a72U,
    0xfbfd0effU, 0x560f8538U, 0x1e3daed5U, 0x27362d39U,
    0x640a0fd9U, 0x21685ca6U, 0xd19b5b54U, 0x3a24362eU,
    0xb10c0a67U, 0x0f9357e7U, 0xd2b4ee96U, 0x9e1b9b91U,
    0x4f80c0c5U, 0xa261dc20U, 0x695a774bU, 0x161c121aU,
    0x0ae293baU, 0xe5c0a02aU, 0x433c22e0U, 0x1d121b17U,
    0x0b0e090dU, 0xadf28bc7U, 0xb92db6a8U, 0xc8141ea9U,
    0x8557f119U, 0x4caf7507U, 0xbbee99ddU, 0xfda37f60U,
    0x9ff70126U, 0xbc5c72f5U, 0xc544663bU, 0x345bfb7eU,
    0x768b4329U, 0xdccb23c6U, 0x68b6edfcU, 0x63b8e4f1U,
    0xcad731dcU, 0x10426385U, 0x40139722U, 0x2084c611U,
    0x7d854a24U, 0xf8d2bb3dU, 0x11aef932U, 0x6dc729a1U,
    0x4b1d9e2fU, 0xf3dcb230U, 0xec0d8652U, 0xd077c1e3U,
    0x6c2bb316U, 0x99a970b9U, 0xfa119448U, 0x2247e964U,
    0xc4a8fc8cU, 0x1aa0f03fU, 0xd8567d2cU, 0xef223390U,
    0xc787494eU, 0xc1d938d1U, 0xfe8ccaa2U, 0x3698d40bU,
    0xcfa6f581U, 0x28a57adeU, 0x26dab78eU, 0xa43fadbfU,
    0xe42c3a9dU, 0x0d507892U, 0x9b6a5fccU, 0x62547e46U,
    0xc2f68d13U, 0xe890d8b8U, 0x5e2e39f7U, 0xf582c3afU,
    0xbe9f5d80U, 0x7c69d093U, 0xa96fd52dU, 0xb3cf2512U,
    0x3bc8ac99U, 0xa710187dU, 0x6ee89c63U, 0x7bdb3bbbU,
    0x09cd2678U, 0xf46e5918U, 0x01ec9ab7U, 0xa8834f9aU,
    0x65e6956eU, 0x7eaaffe6U, 0x0821bccfU, 0xe6ef15e8U,
    0xd9bae79bU, 0xce4a6f36U, 0xd4ea9f09U, 0xd629b07cU,
    0xaf31a4b2U, 0x312a3f23U, 0x30c6a594U, 0xc035a266U,
    0x37744ebcU, 0xa6fc82caU, 0xb0e090d0U, 0x1533a7d8U,
    0x4af10498U, 0xf741ecdaU, 0x0e7fcd50U, 0x2f1791f6U,
    0x8d764dd6U, 0x4d43efb0U, 0x54ccaa4dU, 0xdfe49604U,
    0xe39ed1b5U, 0x1b4c6a88U, 0xb8c12c1fU, 0x7f466551U,
    0x049d5eeaU, 0x5d018c35U, 0x73fa8774U, 0x2efb0b41U,
    0x5ab3671dU, 0x5292dbd2U, 0x33e91056U, 0x136dd647U,
    0x8c9ad761U, 0x7a37a10cU, 0x8e59f814U, 0x89eb133cU,
    0xeecea927U, 0x35b761c9U, 0xede11ce5U, 0x3c7a47b1U,
    0x599cd2dfU, 0x3f55f273U, 0x791814ceU, 0xbf73c737U,
    0xea53f7cdU, 0x5b5ffdaaU, 0x14df3d6fU, 0x867844dbU,
    0x81caaff3U, 0x3eb968c4U, 0x2c382434U, 0x5fc2a340U,
    0x72161dc3U, 0x0cbce225U, 0x8b283c49U, 0x41ff0d95U,
    0x7139a801U, 0xde080cb3U, 0x9cd8b4e4U, 0x906456c1U,
    0x617bcb84U, 0x70d532b6U, 0x74486c5cU, 0x42d0b857U,
};
const NQ_UINT32 Td2[256] = {
    0xa75051f4U, 0x65537e41U, 0xa4c31a17U, 0x5e963a27U,
    0x6bcb3babU, 0x45f11f9dU, 0x58abacfaU, 0x03934be3U,
    0xfa552030U, 0x6df6ad76U, 0x769188ccU, 0x4c25f502U,
    0xd7fc4fe5U, 0xcbd7c52aU, 0x44802635U, 0xa38fb562U,
    0x5a49deb1U, 0x1b6725baU, 0x0e9845eaU, 0xc0e15dfeU,
    0x7502c32fU, 0xf012814cU, 0x97a38d46U, 0xf9c66bd3U,
    0x5fe7038fU, 0x9c951592U, 0x7aebbf6dU, 0x59da9552U,
    0x832dd4beU, 0x21d35874U, 0x692949e0U, 0xc8448ec9U,
    0x896a75c2U, 0x7978f48eU, 0x3e6b9958U, 0x71dd27b9U,
    0x4fb6bee1U, 0xad17f088U, 0xac66c920U, 0x3ab47dceU,
    0x4a1863dfU, 0x3182e51aU, 0x33609751U, 0x7f456253U,
    0x77e0b164U, 0xae84bb6bU, 0xa01cfe81U, 0x2b94f908U,
    0x68587048U, 0xfd198f45U, 0x6c8794deU, 0xf8b7527bU,
    0xd323ab73U, 0x02e2724bU, 0x8f57e31fU, 0xab2a6655U,
    0x2807b2ebU, 0xc2032fb5U, 0x7b9a86c5U, 0x08a5d337U,
    0x87f23028U, 0xa5b223bfU, 0x6aba0203U, 0x825ced16U,
    0x1c2b8acfU, 0xb492a779U, 0xf2f0f307U, 0xe2a14e69U,
    0xf4cd65daU, 0xbed50605U, 0x621fd134U, 0xfe8ac4a6U,
    0x539d342eU, 0x55a0a2f3U, 0xe132058aU, 0xeb75a4f6U,
    0xec390b83U, 0xefaa4060U, 0x9f065e71U, 0x1051bd6eU,
    0x8af93e21U, 0x063d96ddU, 0x05aedd3eU, 0xbd464de6U,
    0x8db59154U, 0x5d0571c4U, 0xd46f0406U, 0x15ff6050U,
    0xfb241998U, 0xe997d6bdU, 0x43cc8940U, 0x9e7767d9U,
    0x42bdb0e8U, 0x8b880789U, 0x5b38e719U, 0xeedb79c8U,
    0x0a47a17cU, 0x0fe97c42U, 0x1ec9f884U, 0x00000000U,
    0x86830980U, 0xed48322bU, 0x70ac1e11U, 0x724e6c5aU,
    0xfffbfd0eU, 0x38560f85U, 0xd51e3daeU, 0x3927362dU,
    0xd9640a0fU, 0xa621685cU, 0x54d19b5bU, 0x2e3a2436U,
    0x67b10c0aU, 0xe70f9357U, 0x96d2b4eeU, 0x919e1b9bU,
    0xc54f80c0U, 0x20a261dcU, 0x4b695a77U, 0x1a161c12U,
    0xba0ae293U, 0x2ae5c0a0U, 0xe0433c22U, 0x171d121bU,
    0x0d0b0e09U, 0xc7adf28bU, 0xa8b92db6U, 0xa9c8141eU,
    0x198557f1U, 0x074caf75U, 0xddbbee99U, 0x60fda37fU,
    0x269ff701U, 0xf5bc5c72U, 0x3bc54466U, 0x7e345bfbU,
    0x29768b43U, 0xc6dccb23U, 0xfc68b6edU, 0xf163b8e4U,
    0xdccad731U, 0x85104263U, 0x22401397U, 0x112084c6U,
    0x247d854aU, 0x3df8d2bbU, 0x3211aef9U, 0xa16dc729U,
    0x2f4b1d9eU, 0x30f3dcb2U, 0x52ec0d86U, 0xe3d077c1U,
    0x166c2bb3U, 0xb999a970U, 0x48fa1194U, 0x642247e9U,
    0x8cc4a8fcU, 0x3f1aa0f0U, 0x2cd8567dU, 0x90ef2233U,
    0x4ec78749U, 0xd1c1d938U, 0xa2fe8ccaU, 0x0b3698d4U,
    0x81cfa6f5U, 0xde28a57aU, 0x8e26dab7U, 0xbfa43fadU,
    0x9de42c3aU, 0x920d5078U, 0xcc9b6a5fU, 0x4662547eU,
    0x13c2f68dU, 0xb8e890d8U, 0xf75e2e39U, 0xaff582c3U,
    0x80be9f5dU, 0x937c69d0U, 0x2da96fd5U, 0x12b3cf25U,
    0x993bc8acU, 0x7da71018U, 0x636ee89cU, 0xbb7bdb3bU,
    0x7809cd26U, 0x18f46e59U, 0xb701ec9aU, 0x9aa8834fU,
    0x6e65e695U, 0xe67eaaffU, 0xcf0821bcU, 0xe8e6ef15U,
    0x9bd9bae7U, 0x36ce4a6fU, 0x09d4ea9fU, 0x7cd629b0U,
    0xb2af31a4U, 0x23312a3fU, 0x9430c6a5U, 0x66c035a2U,
    0xbc37744eU, 0xcaa6fc82U, 0xd0b0e090U, 0xd81533a7U,
    0x984af104U, 0xdaf741ecU, 0x500e7fcdU, 0xf62f1791U,
    0xd68d764dU, 0xb04d43efU, 0x4d54ccaaU, 0x04dfe496U,
    0xb5e39ed1U, 0x881b4c6aU, 0x1fb8c12cU, 0x517f4665U,
    0xea049d5eU, 0x355d018cU, 0x7473fa87U, 0x412efb0bU,
    0x1d5ab367U, 0xd25292dbU, 0x5633e910U, 0x47136dd6U,
    0x618c9ad7U, 0x0c7a37a1U, 0x148e59f8U, 0x3c89eb13U,
    0x27eecea9U, 0xc935b761U, 0xe5ede11cU, 0xb13c7a47U,
    0xdf599cd2U, 0x733f55f2U, 0xce791814U, 0x37bf73c7U,
    0xcdea53f7U, 0xaa5b5ffdU, 0x6f14df3dU, 0xdb867844U,
    0xf381caafU, 0xc43eb968U, 0x342c3824U, 0x405fc2a3U,
    0xc372161dU, 0x250cbce2U, 0x498b283cU, 0x9541ff0dU,
    0x017139a8U, 0xb3de080cU, 0xe49cd8b4U, 0xc1906456U,
    0x84617bcbU, 0xb670d532U, 0x5c74486cU, 0x5742d0b8U,
};
const NQ_UINT32 Td3[256] = {
    0xf4a75051U, 0x4165537eU, 0x17a4c31aU, 0x275e963aU,
    0xab6bcb3bU, 0x9d45f11fU, 0xfa58abacU, 0xe303934bU,
    0x30fa5520U, 0x766df6adU, 0xcc769188U, 0x024c25f5U,
    0xe5d7fc4fU, 0x2acbd7c5U, 0x35448026U, 0x62a38fb5U,
    0xb15a49deU, 0xba1b6725U, 0xea0e9845U, 0xfec0e15dU,
    0x2f7502c3U, 0x4cf01281U, 0x4697a38dU, 0xd3f9c66bU,
    0x8f5fe703U, 0x929c9515U, 0x6d7aebbfU, 0x5259da95U,
    0xbe832dd4U, 0x7421d358U, 0xe0692949U, 0xc9c8448eU,
    0xc2896a75U, 0x8e7978f4U, 0x583e6b99U, 0xb971dd27U,
    0xe14fb6beU, 0x88ad17f0U, 0x20ac66c9U, 0xce3ab47dU,
    0xdf4a1863U, 0x1a3182e5U, 0x51336097U, 0x537f4562U,
    0x6477e0b1U, 0x6bae84bbU, 0x81a01cfeU, 0x082b94f9U,
    0x48685870U, 0x45fd198fU, 0xde6c8794U, 0x7bf8b752U,
    0x73d323abU, 0x4b02e272U, 0x1f8f57e3U, 0x55ab2a66U,
    0xeb2807b2U, 0xb5c2032fU, 0xc57b9a86U, 0x3708a5d3U,
    0x2887f230U, 0xbfa5b223U, 0x036aba02U, 0x16825cedU,
    0xcf1c2b8aU, 0x79b492a7U, 0x07f2f0f3U, 0x69e2a14eU,
    0xdaf4cd65U, 0x05bed506U, 0x34621fd1U, 0xa6fe8ac4U,
    0x2e539d34U, 0xf355a0a2U, 0x8ae13205U, 0xf6eb75a4U,
    0x83ec390bU, 0x60efaa40U, 0x719f065eU, 0x6e1051bdU,
    0x218af93eU, 0xdd063d96U, 0x3e05aeddU, 0xe6bd464dU,
    0x548db591U, 0xc45d0571U, 0x06d46f04U, 0x5015ff60U,
    0x98fb2419U, 0xbde997d6U, 0x4043cc89U, 0xd99e7767U,
    0xe842bdb0U, 0x898b8807U, 0x195b38e7U, 0xc8eedb79U,
    0x7c0a47a1U, 0x420fe97cU, 0x841ec9f8U, 0x00000000U,
    0x80868309U, 0x2bed4832U, 0x1170ac1eU, 0x5a724e6cU,
    0x0efffbfdU, 0x8538560fU, 0xaed51e3dU, 0x2d392736U,
    0x0fd9640aU, 0x5ca62168U, 0x5b54d19bU, 0x362e3a24U,
    0x0a67b10cU, 0x57e70f93U, 0xee96d2b4U, 0x9b919e1bU,
    0xc0c54f80U, 0xdc20a261U, 0x774b695aU, 0x121a161cU,
    0x93ba0ae2U, 0xa02ae5c0U, 0x22e0433cU, 0x1b171d12U,
    0x090d0b0eU, 0x8bc7adf2U, 0xb6a8b92dU, 0x1ea9c814U,
    0xf1198557U, 0x75074cafU, 0x99ddbbeeU, 0x7f60fda3U,
    0x01269ff7U, 0x72f5bc5cU, 0x663bc544U, 0xfb7e345bU,
    0x4329768bU, 0x23c6dccbU, 0xedfc68b6U, 0xe4f163b8U,
    0x31dccad7U, 0x63851042U, 0x97224013U, 0xc6112084U,
    0x4a247d85U, 0xbb3df8d2U, 0xf93211aeU, 0x29a16dc7U,
    0x9e2f4b1dU, 0xb230f3dcU, 0x8652ec0dU, 0xc1e3d077U,
    0xb3166c2bU, 0x70b999a9U, 0x9448fa11U, 0xe9642247U,
    0xfc8cc4a8U, 0xf03f1aa0U, 0x7d2cd856U, 0x3390ef22U,
    0x494ec787U, 0x38d1c1d9U, 0xcaa2fe8cU, 0xd40b3698U,
    0xf581cfa6U, 0x7ade28a5U, 0xb78e26daU, 0xadbfa43fU,
    0x3a9de42cU, 0x78920d50U, 0x5fcc9b6aU, 0x7e466254U,
    0x8d13c2f6U, 0xd8b8e890U, 0x39f75e2eU, 0xc3aff582U,
    0x5d80be9fU, 0xd0937c69U, 0xd52da96fU, 0x2512b3cfU,
    0xac993bc8U, 0x187da710U, 0x9c636ee8U, 0x3bbb7bdbU,
    0x267809cdU, 0x5918f46eU, 0x9ab701ecU, 0x4f9aa883U,
    0x956e65e6U, 0xffe67eaaU, 0xbccf0821U, 0x15e8e6efU,
    0xe79bd9baU, 0x6f36ce4aU, 0x9f09d4eaU, 0xb07cd629U,
    0xa4b2af31U, 0x3f23312aU, 0xa59430c6U, 0xa266c035U,
    0x4ebc3774U, 0x82caa6fcU, 0x90d0b0e0U, 0xa7d81533U,
    0x04984af1U, 0xecdaf741U, 0xcd500e7fU, 0x91f62f17U,
    0x4dd68d76U, 0xefb04d43U, 0xaa4d54ccU, 0x9604dfe4U,
    0xd1b5e39eU, 0x6a881b4cU, 0x2c1fb8c1U, 0x65517f46U,
    0x5eea049dU, 0x8c355d01U, 0x877473faU, 0x0b412efbU,
    0x671d5ab3U, 0xdbd25292U, 0x105633e9U, 0xd647136dU,
    0xd7618c9aU, 0xa10c7a37U, 0xf8148e59U, 0x133c89ebU,
    0xa927eeceU, 0x61c935b7U, 0x1ce5ede1U, 0x47b13c7aU,
    0xd2df599cU, 0xf2733f55U, 0x14ce7918U, 0xc737bf73U,
    0xf7cdea53U, 0xfdaa5b5fU, 0x3d6f14dfU, 0x44db8678U,
    0xaff381caU, 0x68c43eb9U, 0x24342c38U, 0xa3405fc2U,
    0x1dc37216U, 0xe2250cbcU, 0x3c498b28U, 0x0d9541ffU,
    0xa8017139U, 0x0cb3de08U, 0xb4e49cd8U, 0x56c19064U,
    0xcb84617bU, 0x32b670d5U, 0x6c5c7448U, 0xb85742d0U,
};
const NQ_UINT32 Td4[256] = {
    0x52525252U, 0x09090909U, 0x6a6a6a6aU, 0xd5d5d5d5U,
    0x30303030U, 0x36363636U, 0xa5a5a5a5U, 0x38383838U,
    0xbfbfbfbfU, 0x40404040U, 0xa3a3a3a3U, 0x9e9e9e9eU,
    0x81818181U, 0xf3f3f3f3U, 0xd7d7d7d7U, 0xfbfbfbfbU,
    0x7c7c7c7cU, 0xe3e3e3e3U, 0x39393939U, 0x82828282U,
    0x9b9b9b9bU, 0x2f2f2f2fU, 0xffffffffU, 0x87878787U,
    0x34343434U, 0x8e8e8e8eU, 0x43434343U, 0x44444444U,
    0xc4c4c4c4U, 0xdedededeU, 0xe9e9e9e9U, 0xcbcbcbcbU,
    0x54545454U, 0x7b7b7b7bU, 0x94949494U, 0x32323232U,
    0xa6a6a6a6U, 0xc2c2c2c2U, 0x23232323U, 0x3d3d3d3dU,
    0xeeeeeeeeU, 0x4c4c4c4cU, 0x95959595U, 0x0b0b0b0bU,
    0x42424242U, 0xfafafafaU, 0xc3c3c3c3U, 0x4e4e4e4eU,
    0x08080808U, 0x2e2e2e2eU, 0xa1a1a1a1U, 0x66666666U,
    0x28282828U, 0xd9d9d9d9U, 0x24242424U, 0xb2b2b2b2U,
    0x76767676U, 0x5b5b5b5bU, 0xa2a2a2a2U, 0x49494949U,
    0x6d6d6d6dU, 0x8b8b8b8bU, 0xd1d1d1d1U, 0x25252525U,
    0x72727272U, 0xf8f8f8f8U, 0xf6f6f6f6U, 0x64646464U,
    0x86868686U, 0x68686868U, 0x98989898U, 0x16161616U,
    0xd4d4d4d4U, 0xa4a4a4a4U, 0x5c5c5c5cU, 0xccccccccU,
    0x5d5d5d5dU, 0x65656565U, 0xb6b6b6b6U, 0x92929292U,
    0x6c6c6c6cU, 0x70707070U, 0x48484848U, 0x50505050U,
    0xfdfdfdfdU, 0xededededU, 0xb9b9b9b9U, 0xdadadadaU,
    0x5e5e5e5eU, 0x15151515U, 0x46464646U, 0x57575757U,
    0xa7a7a7a7U, 0x8d8d8d8dU, 0x9d9d9d9dU, 0x84848484U,
    0x90909090U, 0xd8d8d8d8U, 0xababababU, 0x00000000U,
    0x8c8c8c8cU, 0xbcbcbcbcU, 0xd3d3d3d3U, 0x0a0a0a0aU,
    0xf7f7f7f7U, 0xe4e4e4e4U, 0x58585858U, 0x05050505U,
    0xb8b8b8b8U, 0xb3b3b3b3U, 0x45454545U, 0x06060606U,
    0xd0d0d0d0U, 0x2c2c2c2cU, 0x1e1e1e1eU, 0x8f8f8f8fU,
    0xcacacacaU, 0x3f3f3f3fU, 0x0f0f0f0fU, 0x02020202U,
    0xc1c1c1c1U, 0xafafafafU, 0xbdbdbdbdU, 0x03030303U,
    0x01010101U, 0x13131313U, 0x8a8a8a8aU, 0x6b6b6b6bU,
    0x3a3a3a3aU, 0x91919191U, 0x11111111U, 0x41414141U,
    0x4f4f4f4fU, 0x67676767U, 0xdcdcdcdcU, 0xeaeaeaeaU,
    0x97979797U, 0xf2f2f2f2U, 0xcfcfcfcfU, 0xcecececeU,
    0xf0f0f0f0U, 0xb4b4b4b4U, 0xe6e6e6e6U, 0x73737373U,
    0x96969696U, 0xacacacacU, 0x74747474U, 0x22222222U,
    0xe7e7e7e7U, 0xadadadadU, 0x35353535U, 0x85858585U,
    0xe2e2e2e2U, 0xf9f9f9f9U, 0x37373737U, 0xe8e8e8e8U,
    0x1c1c1c1cU, 0x75757575U, 0xdfdfdfdfU, 0x6e6e6e6eU,
    0x47474747U, 0xf1f1f1f1U, 0x1a1a1a1aU, 0x71717171U,
    0x1d1d1d1dU, 0x29292929U, 0xc5c5c5c5U, 0x89898989U,
    0x6f6f6f6fU, 0xb7b7b7b7U, 0x62626262U, 0x0e0e0e0eU,
    0xaaaaaaaaU, 0x18181818U, 0xbebebebeU, 0x1b1b1b1bU,
    0xfcfcfcfcU, 0x56565656U, 0x3e3e3e3eU, 0x4b4b4b4bU,
    0xc6c6c6c6U, 0xd2d2d2d2U, 0x79797979U, 0x20202020U,
    0x9a9a9a9aU, 0xdbdbdbdbU, 0xc0c0c0c0U, 0xfefefefeU,
    0x78787878U, 0xcdcdcdcdU, 0x5a5a5a5aU, 0xf4f4f4f4U,
    0x1f1f1f1fU, 0xddddddddU, 0xa8a8a8a8U, 0x33333333U,
    0x88888888U, 0x07070707U, 0xc7c7c7c7U, 0x31313131U,
    0xb1b1b1b1U, 0x12121212U, 0x10101010U, 0x59595959U,
    0x27272727U, 0x80808080U, 0xececececU, 0x5f5f5f5fU,
    0x60606060U, 0x51515151U, 0x7f7f7f7fU, 0xa9a9a9a9U,
    0x19191919U, 0xb5b5b5b5U, 0x4a4a4a4aU, 0x0d0d0d0dU,
    0x2d2d2d2dU, 0xe5e5e5e5U, 0x7a7a7a7aU, 0x9f9f9f9fU,
    0x93939393U, 0xc9c9c9c9U, 0x9c9c9c9cU, 0xefefefefU,
    0xa0a0a0a0U, 0xe0e0e0e0U, 0x3b3b3b3bU, 0x4d4d4d4dU,
    0xaeaeaeaeU, 0x2a2a2a2aU, 0xf5f5f5f5U, 0xb0b0b0b0U,
    0xc8c8c8c8U, 0xebebebebU, 0xbbbbbbbbU, 0x3c3c3c3cU,
    0x83838383U, 0x53535353U, 0x99999999U, 0x61616161U,
    0x17171717U, 0x2b2b2b2bU, 0x04040404U, 0x7e7e7e7eU,
    0xbabababaU, 0x77777777U, 0xd6d6d6d6U, 0x26262626U,
    0xe1e1e1e1U, 0x69696969U, 0x14141414U, 0x63636363U,
    0x55555555U, 0x21212121U, 0x0c0c0c0cU, 0x7d7d7d7dU,
};
const NQ_UINT32 rcon[] = {
	0x01000000, 0x02000000, 0x04000000, 0x08000000,
	0x10000000, 0x20000000, 0x40000000, 0x80000000,
	0x1B000000, 0x36000000, /* for 128-bit blocks, Rijndael never uses more than 10 rcon values */
};
#else /* AES_SMALL_TABLES */
const NQ_BYTE Td4s[256] = {
    0x52U, 0x09U, 0x6aU, 0xd5U, 0x30U, 0x36U, 0xa5U, 0x38U,
    0xbfU, 0x40U, 0xa3U, 0x9eU, 0x81U, 0xf3U, 0xd7U, 0xfbU,
    0x7cU, 0xe3U, 0x39U, 0x82U, 0x9bU, 0x2fU, 0xffU, 0x87U,
    0x34U, 0x8eU, 0x43U, 0x44U, 0xc4U, 0xdeU, 0xe9U, 0xcbU,
    0x54U, 0x7bU, 0x94U, 0x32U, 0xa6U, 0xc2U, 0x23U, 0x3dU,
    0xeeU, 0x4cU, 0x95U, 0x0bU, 0x42U, 0xfaU, 0xc3U, 0x4eU,
    0x08U, 0x2eU, 0xa1U, 0x66U, 0x28U, 0xd9U, 0x24U, 0xb2U,
    0x76U, 0x5bU, 0xa2U, 0x49U, 0x6dU, 0x8bU, 0xd1U, 0x25U,
    0x72U, 0xf8U, 0xf6U, 0x64U, 0x86U, 0x68U, 0x98U, 0x16U,
    0xd4U, 0xa4U, 0x5cU, 0xccU, 0x5dU, 0x65U, 0xb6U, 0x92U,
    0x6cU, 0x70U, 0x48U, 0x50U, 0xfdU, 0xedU, 0xb9U, 0xdaU,
    0x5eU, 0x15U, 0x46U, 0x57U, 0xa7U, 0x8dU, 0x9dU, 0x84U,
    0x90U, 0xd8U, 0xabU, 0x00U, 0x8cU, 0xbcU, 0xd3U, 0x0aU,
    0xf7U, 0xe4U, 0x58U, 0x05U, 0xb8U, 0xb3U, 0x45U, 0x06U,
    0xd0U, 0x2cU, 0x1eU, 0x8fU, 0xcaU, 0x3fU, 0x0fU, 0x02U,
    0xc1U, 0xafU, 0xbdU, 0x03U, 0x01U, 0x13U, 0x8aU, 0x6bU,
    0x3aU, 0x91U, 0x11U, 0x41U, 0x4fU, 0x67U, 0xdcU, 0xeaU,
    0x97U, 0xf2U, 0xcfU, 0xceU, 0xf0U, 0xb4U, 0xe6U, 0x73U,
    0x96U, 0xacU, 0x74U, 0x22U, 0xe7U, 0xadU, 0x35U, 0x85U,
    0xe2U, 0xf9U, 0x37U, 0xe8U, 0x1cU, 0x75U, 0xdfU, 0x6eU,
    0x47U, 0xf1U, 0x1aU, 0x71U, 0x1dU, 0x29U, 0xc5U, 0x89U,
    0x6fU, 0xb7U, 0x62U, 0x0eU, 0xaaU, 0x18U, 0xbeU, 0x1bU,
    0xfcU, 0x56U, 0x3eU, 0x4bU, 0xc6U, 0xd2U, 0x79U, 0x20U,
    0x9aU, 0xdbU, 0xc0U, 0xfeU, 0x78U, 0xcdU, 0x5aU, 0xf4U,
    0x1fU, 0xddU, 0xa8U, 0x33U, 0x88U, 0x07U, 0xc7U, 0x31U,
    0xb1U, 0x12U, 0x10U, 0x59U, 0x27U, 0x80U, 0xecU, 0x5fU,
    0x60U, 0x51U, 0x7fU, 0xa9U, 0x19U, 0xb5U, 0x4aU, 0x0dU,
    0x2dU, 0xe5U, 0x7aU, 0x9fU, 0x93U, 0xc9U, 0x9cU, 0xefU,
    0xa0U, 0xe0U, 0x3bU, 0x4dU, 0xaeU, 0x2aU, 0xf5U, 0xb0U,
    0xc8U, 0xebU, 0xbbU, 0x3cU, 0x83U, 0x53U, 0x99U, 0x61U,
    0x17U, 0x2bU, 0x04U, 0x7eU, 0xbaU, 0x77U, 0xd6U, 0x26U,
    0xe1U, 0x69U, 0x14U, 0x63U, 0x55U, 0x21U, 0x0cU, 0x7dU,
};
const NQ_BYTE rcons[] = {
	0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
	/* for 128-bit blocks, Rijndael never uses more than 10 rcon values */
};
#endif /* AES_SMALL_TABLES */
/**
 * Expand the cipher key into the encryption key schedule.
 *
 * @return	the number of rounds for the given cipher key size.
 */
NQ_INT rijndaelKeySetupEnc(NQ_UINT32 rk[], const NQ_BYTE cipherKey[], NQ_INT keyBits)
{
	NQ_INT i;
	NQ_UINT32 temp;
	rk[0] = GETU32(cipherKey     );
	rk[1] = GETU32(cipherKey +  4);
	rk[2] = GETU32(cipherKey +  8);
	rk[3] = GETU32(cipherKey + 12);
	if (keyBits == 128) {
		for (i = 0; i < 10; i++) {
			temp  = rk[3];
			rk[4] = rk[0] ^ TE421(temp) ^ TE432(temp) ^
				TE443(temp) ^ TE414(temp) ^ (NQ_UINT32)RCON(i);
			rk[5] = rk[1] ^ rk[4];
			rk[6] = rk[2] ^ rk[5];
			rk[7] = rk[3] ^ rk[6];
			rk += 4;
		}
		return 10;
	}
	rk[4] = GETU32(cipherKey + 16);
	rk[5] = GETU32(cipherKey + 20);
	if (keyBits == 192) {
		for (i = 0; i < 8; i++) {
			temp  = rk[5];
			rk[6] = rk[0] ^ (NQ_UINT32)TE421(temp) ^ (NQ_UINT32)TE432(temp) ^
				(NQ_UINT32)TE443(temp) ^ (NQ_UINT32)TE414(temp) ^ (NQ_UINT32)RCON(i);
			rk[7] = rk[1] ^ rk[6];
			rk[8] = rk[2] ^ rk[7];
			rk[9] = rk[3] ^ rk[8];
			if (i == 7)
				return 12;
			rk[10] = rk[4] ^ rk[9];
			rk[11] = rk[5] ^ rk[10];
			rk += 6;
		}
	}
	rk[6] = GETU32(cipherKey + 24);
	rk[7] = GETU32(cipherKey + 28);
	if (keyBits == 256) {
		for (i = 0; i < 7; i++) {
			temp  = rk[7];
			rk[8] = rk[0] ^ (NQ_UINT32)TE421(temp) ^ (NQ_UINT32)TE432(temp) ^
				(NQ_UINT32)TE443(temp) ^ (NQ_UINT32)TE414(temp) ^ (NQ_UINT32)RCON(i);
			rk[9] = rk[1] ^ rk[8];
			rk[10] = rk[2] ^ rk[9];
			rk[11] = rk[3] ^ rk[10];
			if (i == 6)
				return 14;
			temp  = rk[11];
			rk[12] = rk[4] ^ (NQ_UINT32)TE411(temp) ^ (NQ_UINT32)TE422(temp) ^
				(NQ_UINT32)TE433(temp) ^ (NQ_UINT32)TE444(temp);
			rk[13] = rk[5] ^ rk[12];
			rk[14] = rk[6] ^ rk[13];
			rk[15] = rk[7] ^ rk[14];
			rk += 8;
		}
	}
	return -1;
}

static void rijndaelEncrypt(const NQ_UINT32 rk[], NQ_INT Nr, const NQ_BYTE pt[16], NQ_BYTE ct[16])
{
	NQ_UINT32 s0, s1, s2, s3, t0, t1, t2, t3;
#ifndef FULL_UNROLL
	NQ_INT r;
#endif /* ?FULL_UNROLL */
	/*
	 * map byte array block to cipher state
	 * and add initial round key:
	 */
	s0 = GETU32(pt     ) ^ rk[0];
	s1 = GETU32(pt +  4) ^ rk[1];
	s2 = GETU32(pt +  8) ^ rk[2];
	s3 = GETU32(pt + 12) ^ rk[3];
#define ROUND(i,d,s) \
d##0 = TE0(s##0) ^ TE1(s##1) ^ TE2(s##2) ^ TE3(s##3) ^ rk[4 * i]; \
d##1 = TE0(s##1) ^ TE1(s##2) ^ TE2(s##3) ^ TE3(s##0) ^ rk[4 * i + 1]; \
d##2 = TE0(s##2) ^ TE1(s##3) ^ TE2(s##0) ^ TE3(s##1) ^ rk[4 * i + 2]; \
d##3 = TE0(s##3) ^ TE1(s##0) ^ TE2(s##1) ^ TE3(s##2) ^ rk[4 * i + 3]
#ifdef FULL_UNROLL
	ROUND(1,t,s);
	ROUND(2,s,t);
	ROUND(3,t,s);
	ROUND(4,s,t);
	ROUND(5,t,s);
	ROUND(6,s,t);
	ROUND(7,t,s);
	ROUND(8,s,t);
	ROUND(9,t,s);
	if (Nr > 10) {
		ROUND(10,s,t);
		ROUND(11,t,s);
		if (Nr > 12) {
			ROUND(12,s,t);
			ROUND(13,t,s);
		}
	}
	rk += Nr << 2;
#else  /* !FULL_UNROLL */
	/* Nr - 1 full rounds: */
	r = Nr >> 1;
	for (;;) {
		ROUND(1,t,s);
		rk += 8;
		if (--r == 0)
			break;
		ROUND(0,s,t);
	}
#endif /* FULL_UNROLL */
#undef ROUND
	/*
	 * apply last round and
	 * map cipher state to byte array block:
	 */
	s0 = TE41(t0) ^ TE42(t1) ^ TE43(t2) ^ TE44(t3) ^ rk[0];
	PUTU32(ct     , s0);
	s1 = TE41(t1) ^ TE42(t2) ^ TE43(t3) ^ TE44(t0) ^ rk[1];
	PUTU32(ct +  4, s1);
	s2 = TE41(t2) ^ TE42(t3) ^ TE43(t0) ^ TE44(t1) ^ rk[2];
	PUTU32(ct +  8, s2);
	s3 = TE41(t3) ^ TE42(t0) ^ TE43(t1) ^ TE44(t2) ^ rk[3];
	PUTU32(ct + 12, s3);
}
static void * aesEncryptInit(const NQ_BYTE *key, NQ_COUNT len, NQ_BYTE* keyBuffer)
{
	NQ_UINT32 *rk;
	NQ_INT res;
	rk = (NQ_UINT32*)keyBuffer;
	if (NULL == rk)
		rk = (NQ_UINT32*)cmBufManTake(AES_PRIV_SIZE);

	if (NULL == rk)
		goto Error1;

	res = rijndaelKeySetupEnc(rk, key, (NQ_INT)len * 8);
	if (res < 0)
		goto Error;

	rk[AES_PRIV_NR_POS] = (NQ_UINT32)res;
	return rk;

Error:
	cmBufManGive((NQ_BYTE*)rk);

Error1:
	return NULL;
}
static void aesEncrypt(void *ctx, const NQ_BYTE *plain, NQ_BYTE *encrypted)
{
	NQ_UINT32 *rk = (NQ_UINT32 *)ctx;
	rijndaelEncrypt((const NQ_UINT32 *)ctx, (NQ_INT)rk[AES_PRIV_NR_POS], plain, encrypted);
}
static void aesEncrypt_deinit(void *ctx, NQ_BOOL isExternalKeyBuf)
{
	if (!isExternalKeyBuf)
		cmBufManGive((NQ_BYTE *)ctx);
}

/*
 * Galois/Counter Mode (GCM) and GMAC with AES
 *
 * Copyright (c) 2012, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 *
#include "includes.h"
#include "common.h"
#include "aes.h"
#include "aes_wrap.h"
*/
static void inc32(NQ_BYTE *block)
{
	NQ_UINT32 val;
	val = GET_BE_BYTES_FROM32(block + AES_BLOCK_SIZE - 4);
	val++;
	PUT_BE_BYTES_IN32(block + AES_BLOCK_SIZE - 4, val);
}
static void xor_block(NQ_BYTE *dst, const NQ_BYTE *src)
{
	NQ_UINT32 *d = (NQ_UINT32 *) dst;
	NQ_UINT32 *s = (NQ_UINT32 *) src;
	*d++ ^= *s++;
	*d++ ^= *s++;
	*d++ ^= *s++;
	*d++ ^= *s++;
}
static void shiftRblock(NQ_BYTE *v)
{
	NQ_UINT32 val;
	val = GET_BE_BYTES_FROM32(v + 12);
	val >>= 1;
	if (v[11] & 0x01)
		val |= 0x80000000;
	PUT_BE_BYTES_IN32(v + 12, val);
	val = GET_BE_BYTES_FROM32(v + 8);
	val >>= 1;
	if (v[7] & 0x01)
		val |= 0x80000000;
	PUT_BE_BYTES_IN32(v + 8, val);
	val = GET_BE_BYTES_FROM32(v + 4);
	val >>= 1;
	if (v[3] & 0x01)
		val |= 0x80000000;
	PUT_BE_BYTES_IN32(v + 4, val);
	val = GET_BE_BYTES_FROM32(v);
	val >>= 1;
	PUT_BE_BYTES_IN32(v, val);
}
/* Multiplication in GF(2^128) */
static void gf_mult(const NQ_BYTE *x, const NQ_BYTE *y, NQ_BYTE *z)
{
	NQ_BYTE v[16];
	NQ_INT i, j;
	syMemset(z, 0, 16); /* Z_0 = 0^128 */
	syMemcpy(v, y, 16); /* V_0 = Y */
	for (i = 0; i < 16; i++) {
		for (j = 0; j < 8; j++) {
			if (x[i] & LSHIFT(7 - j)) {
				/* Z_(i + 1) = Z_i XOR V_i */
				xor_block(z, v);
			} else {
				/* Z_(i + 1) = Z_i */
			}
			if (v[15] & 0x01) {
				/* V_(i + 1) = (V_i >> 1) XOR R */
				shiftRblock(v);
				/* R = 11100001 || 0^120 */
				v[0] ^= 0xe1;
			} else {
				/* V_(i + 1) = V_i >> 1 */
				 shiftRblock(v);
			}
		}
	}
}
static void gcmHashInit(NQ_BYTE *y)
{
	/* Y_0 = 0^128 */
	syMemset(y, 0, 16);
}
static void gcmHash(const NQ_BYTE *h, const NQ_BYTE *x, NQ_COUNT xlen, NQ_BYTE *y)
{
	NQ_COUNT m, i;
	const NQ_BYTE *xpos = x;
	NQ_BYTE temp[16];
	m = xlen / 16;
	for (i = 0; i < m; i++) {
		/* Y_i = (Y^(i-1) XOR X_i) dot hash */
		xor_block(y, xpos);
		xpos += 16;
		/* dot operation:
		 * multiplication operation for binary Galois (finite) field of
		 * 2^128 elements */
		gf_mult(y, h, temp);
		syMemcpy(y, temp, 16);
	}
	if (x + xlen > xpos) {
		/* Add zero padded last block */
		NQ_COUNT last = (NQ_COUNT)(x + xlen - xpos);
		syMemcpy(temp, xpos, last);
		syMemset(temp + last, 0, sizeof(temp) - last);
		/* Y_i = (Y^(i-1) XOR X_i) dot hash */
		xor_block(y, temp);
		/* dot operation:
		 * multiplication operation for binary Galois (finite) field of
		 * 2^128 elements */
		gf_mult(y, h, temp);
		syMemcpy(y, temp, 16);
	}
	/* Return Y_m */
}
static void aesGCtr(void *aes, const NQ_BYTE *incb, const NQ_BYTE *x, NQ_COUNT xlen, NQ_BYTE *y)
{
	NQ_COUNT i, n, last;
	NQ_BYTE cBlock[AES_BLOCK_SIZE], temp[AES_BLOCK_SIZE];
	const NQ_BYTE *xpos = x;
	NQ_BYTE *ypos = y;
	if (xlen == 0)
		return;
	n = xlen / 16;
	syMemcpy(cBlock, incb, AES_BLOCK_SIZE);
	/* Full blocks */
	for (i = 0; i < n; i++) {
		aesEncrypt(aes, cBlock, ypos);
		xor_block(ypos, xpos);
		xpos += AES_BLOCK_SIZE;
		ypos += AES_BLOCK_SIZE;
		inc32(cBlock);
	}
	last = (NQ_COUNT)(x + xlen - xpos);
	if (last) {
		/* Last, partial block */
		aesEncrypt(aes, cBlock, temp);
		for (i = 0; i < last; i++)
			*ypos++ = *xpos++ ^ temp[i];
	}
}
static void* aesGcmInitHashSubkey(const NQ_BYTE *key, NQ_COUNT key_len, NQ_BYTE *hash, NQ_BYTE* keyBuffer)
{
	void *aes;
	aes = aesEncryptInit(key, key_len, keyBuffer);
	if (aes == NULL)
		goto Error;

	/* Generate hash subkey hash = AES_K(0^128) */
	syMemset(hash, 0, AES_BLOCK_SIZE);
	aesEncrypt(aes, hash, hash);
	LOGDUMP("Hash subkey hash for gcmHash",	hash, AES_BLOCK_SIZE);
	return aes;

	Error:
	return NULL;
}
static void aesGcmPreparej0(const NQ_BYTE *iv, NQ_COUNT ivLen, const NQ_BYTE *hash, NQ_BYTE *J0)
{
/* this version is only for ivLen == 12 */
	/* Prepare block J_0 = IV || 0^31 || 1 [len(IV) = 96] */
	syMemcpy(J0, iv, ivLen);
	syMemset(J0 + ivLen, 0, AES_BLOCK_SIZE - ivLen);
	J0[AES_BLOCK_SIZE - 1] = 0x01;
}
static void aesGcmCtr(void *aes, const NQ_BYTE *J0, const NQ_BYTE *in, NQ_COUNT len, NQ_BYTE *out)
{
	NQ_BYTE J0inc[AES_BLOCK_SIZE];
	if (len == 0)
		return;
	syMemcpy(J0inc, J0, AES_BLOCK_SIZE);
	inc32(J0inc);
	aesGCtr(aes, J0inc, in, len, out);
}

static void aesGcmGHash(const NQ_BYTE *hash, const NQ_BYTE *aad, NQ_COUNT aad_len, const NQ_BYTE *encrypted,
							NQ_COUNT encrypted_len, NQ_BYTE *S)
{
	NQ_BYTE lenBuf[16];
	/*
	 * u = 128 * ceil[len(C)/128] - len(C)
	 * v = 128 * ceil[len(A)/128] - len(A)
	 * S = gcmHash_H(A || 0^v || C || 0^u || [len(A)]64 || [len(C)]64)
	 * (i.e., zero padded to block size A || C and lengths of each in bits)
	 */
	gcmHashInit(S);
	gcmHash(hash, aad, aad_len, S);
	gcmHash(hash, encrypted, encrypted_len, S);
	PUT_BE_BYTES_MUL8_IN64(lenBuf, aad_len);
	PUT_BE_BYTES_MUL8_IN64(lenBuf + 8, encrypted_len);
	gcmHash(hash, lenBuf, sizeof(lenBuf), S);
	LOGDUMP("S = gcmHash_H(...)", S, 16);
}
/**
 * aesGcmAuthEncrypt - GCM-AE_K(IV, P, A)
 */
static NQ_INT aesGcmAuthEncrypt(const NQ_BYTE *key, NQ_COUNT key_len, const NQ_BYTE *iv, NQ_COUNT ivLen, const NQ_BYTE *plain,
			NQ_COUNT plain_len, const NQ_BYTE *aad, NQ_COUNT aad_len, NQ_BYTE *encrypted, NQ_BYTE *tag)
{
	NQ_BYTE hash[AES_BLOCK_SIZE];
	NQ_BYTE J0[AES_BLOCK_SIZE];
	NQ_BYTE S[16];
	void *aes;

	aes = aesGcmInitHashSubkey(key, key_len, hash, NULL);
	if (aes == NULL)
		goto Error;

	aesGcmPreparej0(iv, ivLen, hash, J0);
	/* C = GCTR_K(inc_32(J_0), P) */
	aesGcmCtr(aes, J0, plain, plain_len, encrypted);
	aesGcmGHash(hash, aad, aad_len, encrypted, plain_len, S);
	/* T = MSB_t(GCTR_K(J_0, S)) */
	aesGCtr(aes, J0, S, sizeof(S), tag);
	/* Return (C, T) */
	aesEncrypt_deinit(aes, FALSE);

	return 0;

Error:
	return -1;
}

static void aes128GcmEncryptInternal(const CMBlob *key, const CMBlob *IV, const CMBlob *AAD, CMBlob *message, NQ_BYTE *auth, NQ_BYTE *keyBuffer, NQ_BYTE *encMsgBuffer)
{
	NQ_BYTE hash[AES_BLOCK_SIZE];
	NQ_BYTE J0[AES_BLOCK_SIZE];
	NQ_BYTE S[16];
	NQ_BYTE *encrypted;
	void *aes;
	NQ_BOOL  isExternalKeyBuf = FALSE, isExternalMsgBuf = FALSE;
	
	if (keyBuffer)
		isExternalKeyBuf = TRUE;

	if (encMsgBuffer)
	{
		isExternalMsgBuf = TRUE;
		encrypted = encMsgBuffer;
	}
	else
		encrypted = cmBufManTake(message->len);

	if (NULL == encrypted)
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "GCM Encrypt: memory allocation failed. size: %d", message->len);		
		goto Exit;
	}

	aes = aesGcmInitHashSubkey(key->data, key->len, hash, keyBuffer);
	if (aes == NULL)
		goto Error1;

	aesGcmPreparej0(IV->data, IV->len, hash, J0);
	/* C = GCTR_K(inc_32(J_0), P) */
	aesGcmCtr(aes, J0, message->data, message->len, encrypted);
	aesGcmGHash(hash, AAD->data, AAD->len, encrypted, message->len, S);
	/* T = MSB_t(GCTR_K(J_0, S)) */
	aesGCtr(aes, J0, S, sizeof(S), auth);
	syMemcpy(message->data, encrypted, message->len);

	/* Return (C, T) */
	aesEncrypt_deinit(aes, isExternalKeyBuf);

Error1:
	if (!isExternalMsgBuf)
		cmBufManGive(encrypted);

	Exit:
	return;
}


void aes128GcmEncrypt(NQ_BYTE *key , NQ_BYTE *nonce , NQ_BYTE *msgBuf , NQ_UINT msgLen, NQ_BYTE *addBuf , NQ_UINT addLen , NQ_BYTE *outMac, NQ_BYTE *keyBuffer, NQ_BYTE *msgBuffer)
{
	CMBlob keyBlob, IVBlob, AADBlob, msgBlob;

	keyBlob.data = (NQ_BYTE *) key;
	keyBlob.len = SMB_SESSIONKEY_LENGTH;
	IVBlob.data = (NQ_BYTE *) nonce;
	IVBlob.len = SMB2_AES128_GCM_NONCE_SIZE;
	AADBlob.data = addBuf;
	AADBlob.len = addLen;
	msgBlob.data = msgBuf;
	msgBlob.len = msgLen;

	(*currentCrypters.aes128gcmEncryption)(&keyBlob, &IVBlob, &AADBlob, &msgBlob, outMac, keyBuffer, msgBuffer);
}

static NQ_BOOL aes128GcmDecryptInternal(const CMBlob * key, const CMBlob * IV, const CMBlob *AAD, CMBlob *message, const NQ_BYTE * auth, NQ_BYTE *keyBuffer, NQ_BYTE *msgBuffer)
{
	NQ_BYTE hash[AES_BLOCK_SIZE];
	NQ_BYTE J0[AES_BLOCK_SIZE];
	NQ_BYTE S[16], T[16];
	void *aes;
	NQ_BYTE* plainText;
	NQ_BOOL result, isExternalKeyBuf = FALSE, isExternalMsgBuf = FALSE;


	if (keyBuffer)
		isExternalKeyBuf = TRUE;

	aes = aesGcmInitHashSubkey(key->data, key->len, hash, keyBuffer);
	if (aes == NULL)
		goto Error;

	if (msgBuffer)
	{
		plainText = msgBuffer;
		isExternalMsgBuf = TRUE;
	}
	else
		plainText = cmBufManTake(message->len);

	if (NULL == plainText)
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "GCM: memory allocation failed. size: %d", message->len);
		aesEncrypt_deinit(aes, isExternalKeyBuf);
		goto Error;
	}
	
	aesGcmPreparej0(IV->data, IV->len, hash, J0);
	/* P = GCTR_K(inc_32(J_0), C) */

	aesGcmCtr(aes, J0, message->data, message->len, plainText);

	aesGcmGHash(hash, AAD->data, AAD->len, message->data, message->len, S);
	/* T' = MSB_t(GCTR_K(J_0, S)) */
	aesGCtr(aes, J0, S, sizeof(S), T);
	aesEncrypt_deinit(aes, isExternalKeyBuf);
	
	/* copy decrypted message to message buffer. over run Encrypted message. */
	syMemcpy(message->data, plainText, message->len);
	if(!isExternalMsgBuf)
		cmBufManGive(plainText);
	result = (syMemcmp(auth, T, 16) == 0);

	return result;

Error:
	return -1;
}

NQ_BOOL aes128GcmDecrypt(NQ_BYTE * key , NQ_BYTE * nonce , NQ_BYTE * msgBuf , NQ_UINT msgLen, NQ_BYTE * addBuf , NQ_UINT addLen , NQ_BYTE * outMac, NQ_BYTE *keyBuffer, NQ_BYTE *msgBuffer)
{
	CMBlob keyBlob, IVBlob, AADBlob, msgBlob;

	keyBlob.data = (NQ_BYTE *) key;
	keyBlob.len = SMB_SESSIONKEY_LENGTH;
	IVBlob.data = (NQ_BYTE *) nonce;
	IVBlob.len = SMB2_AES128_GCM_NONCE_SIZE;
	AADBlob.data = addBuf;
	AADBlob.len = addLen;
	msgBlob.data = msgBuf;
	msgBlob.len = msgLen;

	return (*currentCrypters.aes128gcmDecryption)(&keyBlob, &IVBlob, &AADBlob, &msgBlob, outMac, keyBuffer, msgBuffer);
}


#ifdef NQ_DEBUG
/* AES GCM test vectors */ 
/************************/
static const NQ_BYTE key1 [] = {0xc9, 0x39, 0xcc, 0x13, 0x39, 0x7c, 0x1d, 0x37, 0xde, 0x6a, 0xe0, 0xe1, 0xcb, 0x7c, 0x42, 0x3c};
static const NQ_BYTE nonce1 [] = {0xb3, 0xd8, 0xcc, 0x01, 0x7c, 0xbb, 0x89, 0xb3, 0x9e, 0x0f, 0x67, 0xe2};
static const NQ_BYTE plainText1 [] = {0xc3, 0xb3, 0xc4, 0x1f, 0x11, 0x3a, 0x31, 0xb7, 0x3d, 0x9a, 0x5c, 0xd4, 0x32, 0x10, 0x30, 0x69};
static const NQ_BYTE aad1 [] = {0x24, 0x82, 0x56, 0x02, 0xbd, 0x12, 0xa9, 0x84, 0xe0, 0x09, 0x2d, 0x3e, 0x44, 0x8e, 0xda, 0x5f}; 
static const NQ_BYTE encryptededText1 [] = {0x93, 0xfe, 0x7d, 0x9e, 0x9b, 0xfd, 0x10, 0x34, 0x8a, 0x56, 0x06, 0xe5, 0xca, 0xfa, 0x73, 0x54};
static const NQ_BYTE signature1 [] = {0x00, 0x32, 0xa1, 0xdc, 0x85, 0xf1, 0xc9, 0x78, 0x69, 0x25, 0xa2, 0xe7, 0x1d, 0x82, 0x72, 0xdd};

static const NQ_BYTE key2 [] = {0x56, 0x2a, 0xe8, 0xaa, 0xdb, 0x8d, 0x23, 0xe0, 0xf2, 0x71, 0xa9, 0x9a, 0x7d, 0x1b, 0xd4, 0xd1};
static const NQ_BYTE nonce2 [] = {0xf7, 0xa5, 0xe2, 0x39, 0x94, 0x13, 0xb8, 0x9b, 0x6a, 0xd3, 0x1a, 0xff};
static const NQ_BYTE plainText2 [] = {0xbb, 0xdc, 0x35, 0x04, 0xd8, 0x03, 0x68, 0x2a, 0xa0, 0x8a, 0x77, 0x3c, 0xde, 0x5f, 0x23, 0x1a};
static const NQ_BYTE aad2 [] = {0x2b, 0x96, 0x80, 0xb8, 0x86, 0xb3, 0xef, 0xb7, 0xc6, 0x35, 0x4b, 0x38, 0xc6, 0x3b, 0x53, 0x73}; 
static const NQ_BYTE encryptededText2 [] = {0xe2, 0xb7, 0xe5, 0xed, 0x5f, 0xf2, 0x7f, 0xc8, 0x66, 0x41, 0x48, 0xf5, 0xa6, 0x28, 0xa4, 0x6d};
static const NQ_BYTE signature2 [] = {0xcb, 0xf2, 0x01, 0x51, 0x84, 0xff, 0xfb, 0x82, 0xf2, 0x65, 0x1c, 0x36};

void testAesGCM(void)
{
	NQ_BYTE signature[20];
	NQ_BYTE encryptionResult[20];
	
	aesGcmAuthEncrypt(key1, sizeof(key1), nonce1, sizeof(nonce1), plainText1, sizeof(plainText1), aad1, sizeof(aad1), encryptionResult, signature);
	if (syMemcmp(encryptionResult, encryptededText1, sizeof(encryptededText1)) == 0)
		printf ("Aes GCM - test 1 encryption correct.\n");
	else
		printf ("Aes GCM - test 1 BAAAAAAD encryption.\n");
	if (syMemcmp(signature, signature1, sizeof(signature1)) == 0)
		printf ("Aes GCM - test 1 signature correct.\n");
	else
		printf ("Aes GCM - test 1 BAAAAAAD signature.\n");

	aesGcmAuthEncrypt(key2, sizeof(key2), nonce2, sizeof(nonce2), plainText2, sizeof(plainText2), aad2, sizeof(aad2), encryptionResult, signature);
	if (syMemcmp(encryptionResult, encryptededText2, sizeof(encryptededText2)) == 0)
		printf ("Aes GCM - test 2 encryption correct.\n");
	else
		printf ("Aes GCM - test 2 BAAAAAAD encryption.\n");
	if (syMemcmp(signature, signature2, sizeof(signature2)) == 0)
		printf ("Aes GCM - test 2 signature correct.\n");
	else
		printf ("Aes GCM - test 2 BAAAAAAD signature.\n");
}


#endif /* NQ_DEBUG */ 
#endif /* UD_NQ_INCLUDESMB3 */

#ifdef UD_NQ_INCLUDESMB3
/* define 64 bit type */

#ifdef SY_INT64
#define SHA_U64 SY_UINT64
#else
#ifdef SY_PRAGMAPACK_DEFINED
#pragma pack(1)
#endif
#ifdef SY_BIGENDIANHOST
typedef struct {
	NQ_UINT32 high;
    NQ_UINT32 low;
} SY_PACK_ATTR SHA_U64;
#else
typedef struct {
    NQ_UINT32 low;
    NQ_UINT32 high;
} SY_PACK_ATTR SHA_U64;
#endif
#ifdef SY_PRAGMAPACK_DEFINED
#pragma pack()
#endif
#endif


#define SHA512_DIGEST_SIZE 64
#define SHA512_BLOCK_SIZE  128
#ifdef SY_INT64
#define ADD_U64U64(a, b) a+=b;
#define ADD_U64SIZET(a, b) a+=b;
#define MUL8_U64(result, a) result = a * 8;

#define ROR64(x,n) (SHFR(x,n) | (x << (64 - n)))
#define CH1(x,y,z) ((z) ^ ((x) & ((y) ^ (z))))
#define MAJ2(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define SHA512_F1(x) (ROR64(x, 28) ^ ROR64(x, 34) ^ ROR64(x, 39))
#define SHA512_F2(x) (ROR64(x, 14) ^ ROR64(x, 18) ^ ROR64(x, 41))
#define SHA512_F3(x) (ROR64(x, 1) ^ ROR64(x, 8) ^ SHFR(x, 7))
#define SHA512_F4(x) (ROR64(x, 19) ^ ROR64(x, 61) ^ SHFR(x, 6))
#else
#define ADD_U64U64(a, b)\
	{\
		NQ_UINT32 low = a.low;\
		a.low += b.low;\
		if (a.low < low || a.low < b.low)\
			a.high++;\
		a.high += b.high;\
	}
#define ADD_U64SIZET(a, b)\
	{\
		NQ_UINT32 old = a.low;\
		a.low += b;\
		if (a.low < old || a.low < b)\
			a.high++;\
	}
#define MUL8_U64(result, a)\
		result.low = a.low << 3;\
		result.high = (a.high << 3) | (a.low >> 29);
#define CH1(res, x, y, z)\
	res.low = ((z.low) ^ ((x.low) & ((y.low) ^ (z.low))));\
	res.high = ((z.high) ^ ((x.high) & ((y.high) ^ (z.high))));
#define ROR64(src, dst, n)\
		(dst.low = n > 32 ? src.low << (64 - n) | src.high >> (n - 32) :\
		           src.low >> n | src.high << (32 - n));\
		 (dst.high = n > 32 ? src.low >> (n - 32) | src.high << (64 - n):\
				    src.high >> n | src.low << (32 - n));
#define MAJ2(dst, x, y, z) dst.low = (((x.low) & (y.low)) | ((x.low) & (z.low)) | ((y.low) & (z.low)));\
						dst.high = (((x.high) & (y.high)) | ((x.high) & (z.high)) | ((y.high) & (z.high)));
#define SHA512_F1(res, x)\
{\
	SHA_U64 t1;\
	ROR64(x, res, 28)\
	ROR64(x, t1, 34)\
	res.low ^= t1.low;\
	res.high ^= t1.high;\
	ROR64(x, t1, 39)\
	res.low ^= t1.low;\
	res.high ^= t1.high;\
}
#define SHA512_F2(res, x)\
{\
	SHA_U64 t1;\
	ROR64(x, res, 14)\
	ROR64(x, t1, 18)\
	res.low ^= t1.low;\
	res.high ^= t1.high;\
	ROR64(x, t1, 41)\
	res.low ^= t1.low;\
	res.high ^= t1.high;\
}
#define SHA512_F3(res, x)\
{\
	SHA_U64 t1;\
	ROR64(x, res, 1)\
	ROR64(x, t1, 8)\
	res.low ^= t1.low;\
	res.high ^= t1.high;\
	SHIFTR64(x, t1, 7)\
	res.low ^= t1.low;\
	res.high ^= t1.high;\
}
#define SHA512_F4(res, x)\
{\
	SHA_U64 t1;\
	ROR64(x, res, 19)\
	ROR64(x, t1, 61)\
	res.low ^= t1.low;\
	res.high ^= t1.high;\
	SHIFTR64(x, t1, 6)\
	res.low ^= t1.low;\
	res.high ^= t1.high;\
}
#endif


/* padding */ 
static const NQ_BYTE pad[128] =
{
    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* round constants */
#ifdef SY_INT64
static const SY_UINT64 k[80] =
{
    0x428A2F98D728AE22ULL, 0x7137449123EF65CDULL, 0xB5C0FBCFEC4D3B2FULL, 0xE9B5DBA58189DBBCULL,
    0x3956C25BF348B538ULL, 0x59F111F1B605D019ULL, 0x923F82A4AF194F9BULL, 0xAB1C5ED5DA6D8118ULL,
    0xD807AA98A3030242ULL, 0x12835B0145706FBEULL, 0x243185BE4EE4B28CULL, 0x550C7DC3D5FFB4E2ULL,
    0x72BE5D74F27B896FULL, 0x80DEB1FE3B1696B1ULL, 0x9BDC06A725C71235ULL, 0xC19BF174CF692694ULL,
    0xE49B69C19EF14AD2ULL, 0xEFBE4786384F25E3ULL, 0x0FC19DC68B8CD5B5ULL, 0x240CA1CC77AC9C65ULL,
    0x2DE92C6F592B0275ULL, 0x4A7484AA6EA6E483ULL, 0x5CB0A9DCBD41FBD4ULL, 0x76F988DA831153B5ULL,
    0x983E5152EE66DFABULL, 0xA831C66D2DB43210ULL, 0xB00327C898FB213FULL, 0xBF597FC7BEEF0EE4ULL,
    0xC6E00BF33DA88FC2ULL, 0xD5A79147930AA725ULL, 0x06CA6351E003826FULL, 0x142929670A0E6E70ULL,
    0x27B70A8546D22FFCULL, 0x2E1B21385C26C926ULL, 0x4D2C6DFC5AC42AEDULL, 0x53380D139D95B3DFULL,
    0x650A73548BAF63DEULL, 0x766A0ABB3C77B2A8ULL, 0x81C2C92E47EDAEE6ULL, 0x92722C851482353BULL,
    0xA2BFE8A14CF10364ULL, 0xA81A664BBC423001ULL, 0xC24B8B70D0F89791ULL, 0xC76C51A30654BE30ULL,
    0xD192E819D6EF5218ULL, 0xD69906245565A910ULL, 0xF40E35855771202AULL, 0x106AA07032BBD1B8ULL,
    0x19A4C116B8D2D0C8ULL, 0x1E376C085141AB53ULL, 0x2748774CDF8EEB99ULL, 0x34B0BCB5E19B48A8ULL,
    0x391C0CB3C5C95A63ULL, 0x4ED8AA4AE3418ACBULL, 0x5B9CCA4F7763E373ULL, 0x682E6FF3D6B2B8A3ULL,
    0x748F82EE5DEFB2FCULL, 0x78A5636F43172F60ULL, 0x84C87814A1F0AB72ULL, 0x8CC702081A6439ECULL,
    0x90BEFFFA23631E28ULL, 0xA4506CEBDE82BDE9ULL, 0xBEF9A3F7B2C67915ULL, 0xC67178F2E372532BULL,
    0xCA273ECEEA26619CULL, 0xD186B8C721C0C207ULL, 0xEADA7DD6CDE0EB1EULL, 0xF57D4F7FEE6ED178ULL,
    0x06F067AA72176FBAULL, 0x0A637DC5A2C898A6ULL, 0x113F9804BEF90DAEULL, 0x1B710B35131C471BULL,
    0x28DB77F523047D84ULL, 0x32CAAB7B40C72493ULL, 0x3C9EBE0A15C9BEBCULL, 0x431D67C49C100D4CULL,
    0x4CC5D4BECB3E42B6ULL, 0x597F299CFC657E2AULL, 0x5FCB6FAB3AD6FAECULL, 0x6C44198C4A475817ULL
};
#else
#ifdef SY_LITTLEENDIANHOST
static const SHA_U64 k[80] =
{
	{0xD728AE22, 0x428A2F98}, {0x23EF65CD, 0x71374491}, {0xEC4D3B2F, 0xB5C0FBCF}, {0x8189DBBC, 0xE9B5DBA5},
	{0xF348B538, 0x3956C25B}, {0xB605D019, 0x59F111F1}, {0xAF194F9B, 0x923F82A4}, {0xDA6D8118, 0xAB1C5ED5},
	{0xA3030242, 0xD807AA98}, {0x45706FBE, 0x12835B01}, {0x4EE4B28C, 0x243185BE}, {0xD5FFB4E2, 0x550C7DC3},
	{0xF27B896F, 0x72BE5D74}, {0x3B1696B1, 0x80DEB1FE}, {0x25C71235, 0x9BDC06A7}, {0xCF692694, 0xC19BF174},
	{0x9EF14AD2, 0xE49B69C1}, {0x384F25E3, 0xEFBE4786}, {0x8B8CD5B5, 0x0FC19DC6}, {0x77AC9C65, 0x240CA1CC},
	{0x592B0275, 0x2DE92C6F}, {0x6EA6E483, 0x4A7484AA}, {0xBD41FBD4, 0x5CB0A9DC}, {0x831153B5, 0x76F988DA},
	{0xEE66DFAB, 0x983E5152}, {0x2DB43210, 0xA831C66D}, {0x98FB213F, 0xB00327C8}, {0xBEEF0EE4, 0xBF597FC7},
	{0x3DA88FC2, 0xC6E00BF3}, {0x930AA725, 0xD5A79147}, {0xE003826F, 0x06CA6351}, {0x0A0E6E70, 0x14292967},
	{0x46D22FFC, 0x27B70A85}, {0x5C26C926, 0x2E1B2138}, {0x5AC42AED, 0x4D2C6DFC}, {0x9D95B3DF, 0x53380D13},
	{0x8BAF63DE, 0x650A7354}, {0x3C77B2A8, 0x766A0ABB}, {0x47EDAEE6, 0x81C2C92E}, {0x1482353B, 0x92722C85},
	{0x4CF10364, 0xA2BFE8A1}, {0xBC423001, 0xA81A664B}, {0xD0F89791, 0xC24B8B70}, {0x0654BE30, 0xC76C51A3},
	{0xD6EF5218, 0xD192E819}, {0x5565A910, 0xD6990624}, {0x5771202A, 0xF40E3585}, {0x32BBD1B8, 0x106AA070},
	{0xB8D2D0C8, 0x19A4C116}, {0x5141AB53, 0x1E376C08}, {0xDF8EEB99, 0x2748774C}, {0xE19B48A8, 0x34B0BCB5},
	{0xC5C95A63, 0x391C0CB3}, {0xE3418ACB, 0x4ED8AA4A}, {0x7763E373, 0x5B9CCA4F}, {0xD6B2B8A3, 0x682E6FF3},
	{0x5DEFB2FC, 0x748F82EE}, {0x43172F60, 0x78A5636F}, {0xA1F0AB72, 0x84C87814}, {0x1A6439EC, 0x8CC70208},
	{0x23631E28, 0x90BEFFFA}, {0xDE82BDE9, 0xA4506CEB}, {0xB2C67915, 0xBEF9A3F7}, {0xE372532B, 0xC67178F2},
	{0xEA26619C, 0xCA273ECE}, {0x21C0C207, 0xD186B8C7}, {0xCDE0EB1E, 0xEADA7DD6}, {0xEE6ED178, 0xF57D4F7F},
	{0x72176FBA, 0x06F067AA}, {0xA2C898A6, 0x0A637DC5}, {0xBEF90DAE, 0x113F9804}, {0x131C471B, 0x1B710B35},
	{0x23047D84, 0x28DB77F5}, {0x40C72493, 0x32CAAB7B}, {0x15C9BEBC, 0x3C9EBE0A}, {0x9C100D4C, 0x431D67C4},
	{0xCB3E42B6, 0x4CC5D4BE}, {0xFC657E2A, 0x597F299C}, {0x3AD6FAEC, 0x5FCB6FAB}, {0x4A475817, 0x6C44198C}
};
#else
static const SHA_U64 k[80] =
{
	{0x428A2F98, 0xD728AE22}, {0x71374491, 0x23EF65CD}, {0xB5C0FBCF, 0xEC4D3B2F}, {0xE9B5DBA5, 0x8189DBBC},
	{0x3956C25B, 0xF348B538}, {0x59F111F1, 0xB605D019}, {0x923F82A4, 0xAF194F9B}, {0xAB1C5ED5, 0xDA6D8118},
	{0xD807AA98, 0xA3030242}, {0x12835B01, 0x45706FBE}, {0x243185BE, 0x4EE4B28C}, {0x550C7DC3, 0xD5FFB4E2},
	{0x72BE5D74, 0xF27B896F}, {0x80DEB1FE, 0x3B1696B1}, {0x9BDC06A7, 0x25C71235}, {0xC19BF174, 0xCF692694},
	{0xE49B69C1, 0x9EF14AD2}, {0xEFBE4786, 0x384F25E3}, {0x0FC19DC6, 0x8B8CD5B5}, {0x240CA1CC, 0x77AC9C65},
	{0x2DE92C6F, 0x592B0275}, {0x4A7484AA, 0x6EA6E483}, {0x5CB0A9DC, 0xBD41FBD4}, {0x76F988DA, 0x831153B5},
	{0x983E5152, 0xEE66DFAB}, {0xA831C66D, 0x2DB43210}, {0xB00327C8, 0x98FB213F}, {0xBF597FC7, 0xBEEF0EE4},
	{0xC6E00BF3, 0x3DA88FC2}, {0xD5A79147, 0x930AA725}, {0x06CA6351, 0xE003826F}, {0x14292967, 0x0A0E6E70},
	{0x27B70A85, 0x46D22FFC}, {0x2E1B2138, 0x5C26C926}, {0x4D2C6DFC, 0x5AC42AED}, {0x53380D13, 0x9D95B3DF},
	{0x650A7354, 0x8BAF63DE}, {0x766A0ABB, 0x3C77B2A8}, {0x81C2C92E, 0x47EDAEE6}, {0x92722C85, 0x1482353B},
	{0xA2BFE8A1, 0x4CF10364}, {0xA81A664B, 0xBC423001}, {0xC24B8B70, 0xD0F89791}, {0xC76C51A3, 0x0654BE30},
	{0xD192E819, 0xD6EF5218}, {0xD6990624, 0x5565A910}, {0xF40E3585, 0x5771202A}, {0x106AA070, 0x32BBD1B8},
	{0x19A4C116, 0xB8D2D0C8}, {0x1E376C08, 0x5141AB53}, {0x2748774C, 0xDF8EEB99}, {0x34B0BCB5, 0xE19B48A8},
	{0x391C0CB3, 0xC5C95A63}, {0x4ED8AA4A, 0xE3418ACB}, {0x5B9CCA4F, 0x7763E373}, {0x682E6FF3, 0xD6B2B8A3},
	{0x748F82EE, 0x5DEFB2FC}, {0x78A5636F, 0x43172F60}, {0x84C87814, 0xA1F0AB72}, {0x8CC70208, 0x1A6439EC},
	{0x90BEFFFA, 0x23631E28}, {0xA4506CEB, 0xDE82BDE9}, {0xBEF9A3F7, 0xB2C67915}, {0xC67178F2, 0xE372532B},
	{0xCA273ECE, 0xEA26619C}, {0xD186B8C7, 0x21C0C207}, {0xEADA7DD6, 0xCDE0EB1E}, {0xF57D4F7F, 0xEE6ED178},
	{0x06F067AA, 0x72176FBA}, {0x0A637DC5, 0xA2C898A6}, {0x113F9804, 0xBEF90DAE}, {0x1B710B35, 0x131C471B},
	{0x28DB77F5, 0x23047D84}, {0x32CAAB7B, 0x40C72493}, {0x3C9EBE0A, 0x15C9BEBC}, {0x431D67C4, 0x9C100D4C},
	{0x4CC5D4BE, 0xCB3E42B6}, {0x597F299C, 0xFC657E2A}, {0x5FCB6FAB, 0x3AD6FAEC}, {0x6C44198C, 0x4A475817}
};
#endif /* SY_LITTLEENDIANHOST */
#endif /* SY_INT64 */

typedef struct {
	union 
	{
		SHA_U64  h [8];
		NQ_BYTE digest [64];
	}_un1;	
	 
	union 
	{
		SHA_U64   w [80];
		NQ_BYTE  buffer [128];
	}_un2;	
	 
	NQ_COUNT len; /* currrent data length in buffer */
	 
	SHA_U64 totalLen;
} sha512_ctx;

static void sha512_processBlock(sha512_ctx *context);
static void sha512_init(sha512_ctx *context);
static void sha512_update(sha512_ctx *context, const void *data, NQ_COUNT length);
static void sha512_final(sha512_ctx *context, NQ_BYTE *digest);

/**
* Init SHA-512 context
* context - Pointer SHA-512 context
**/
static void sha512_init(sha512_ctx *context)
{
   /*  initial hash value */
#ifdef SY_INT64
	SET_CONST64(context->_un1.h[0], 0x6A09E667F3BCC908ULL)
	SET_CONST64(context->_un1.h[1], 0xBB67AE8584CAA73BULL)
	SET_CONST64(context->_un1.h[2], 0x3C6EF372FE94F82BULL)
	SET_CONST64(context->_un1.h[3], 0xA54FF53A5F1D36F1ULL)
	SET_CONST64(context->_un1.h[4], 0x510E527FADE682D1ULL)
	SET_CONST64(context->_un1.h[5], 0x9B05688C2B3E6C1FULL)
	SET_CONST64(context->_un1.h[6], 0x1F83D9ABFB41BD6BULL)
	SET_CONST64(context->_un1.h[7], 0x5BE0CD19137E2179ULL)
	SET_CONST64(context->totalLen, 0)
#else /* SY_INT64 */
	SET_CONST64(context->_un1.h[0], 0xF3BCC908, 0x6A09E667)
	SET_CONST64(context->_un1.h[1], 0x84CAA73B, 0xBB67AE85)
	SET_CONST64(context->_un1.h[2], 0xFE94F82B, 0x3C6EF372)
	SET_CONST64(context->_un1.h[3], 0x5F1D36F1, 0xA54FF53A)
	SET_CONST64(context->_un1.h[4], 0xADE682D1, 0x510E527F)
	SET_CONST64(context->_un1.h[5], 0x2B3E6C1F, 0x9B05688C)
	SET_CONST64(context->_un1.h[6], 0xFB41BD6B, 0x1F83D9AB)
	SET_CONST64(context->_un1.h[7], 0x137E2179, 0x5BE0CD19)

	/* Total length of the message */
	SET_CONST64(context->totalLen, 0, 0)
#endif /* SY_INT64 */

    /* Number of bytes in the working buffer */
    context->len = 0;
}

/**
 * Update the SHA-512 context with a portion of the message being hashed
 * context -SHA-512 context
 * data - buffer being hashed
 * length - data buffer length
 **/
 
static void sha512_update(sha512_ctx *context, const void *data, NQ_COUNT length)
{
    /* Process incoming data */
    while(length > 0)
    {
        /* Buffer can hold up to 128 bytes */
        NQ_COUNT len = length < (128 - context->len)? length : (128 - context->len);

        /* Copy data to buffer */
        syMemcpy(context->_un2.buffer + context->len, data, len);
 
        /* Update context */
        context->len += len;
        ADD_U64SIZET(context->totalLen, len)
        /* Advance data pointer */
        data = (NQ_BYTE *) data + len;
        /* Remaining bytes for received data */
        length -= len;
 
        /* Process message in 16-word blocks */
        if(context->len == 128)
        {
            /* digest buffer */
            sha512_processBlock(context);

            /* buffer is empty */
            context->len = 0;
        }
    }
}

/**
* Finalize SHA-512 message digest
* context - Pointer to context
* digest - Calculated digest result
**/
static void sha512_final(sha512_ctx *context, NQ_BYTE *digest)
{
#ifdef SY_LITTLEENDIANHOST
    NQ_UINT i;
#endif
    NQ_COUNT paddingSize;
    SHA_U64 totalLen;
 
    /* Length of the original message (before padding) */
    MUL8_U64(totalLen, context->totalLen)
 
    /* Pad the message so that two bytes are left for closure */
    paddingSize = (context->len < 112) ? (112 - context->len) : (128 + 112 - context->len);

    /* Append padding */
    sha512_update(context, pad, paddingSize);
 
    /* Append the length of the original message */
#ifdef SY_INT64
    SET_CONST64(context->_un2.w[14], 0)
#else
    SET_CONST64(context->_un2.w[14], 0, 0)
#endif

#ifdef SY_LITTLEENDIANHOST
	/* in little endian the assignment is swapped because in process block there is swap back of the whole buffer. */
    SWAP64(context->_un2.w[15], totalLen)
#else
	SET_64(context->_un2.w[15], totalLen)
#endif

	/* Calculate the message digest */
	sha512_processBlock(context);

    /* Convert from host byte order to big-endian byte order if needed */
#ifdef SY_LITTLEENDIANHOST
    for(i = 0; i < 8; i++)
       SWAP64(context->_un1.h[i],context->_un1.h[i]);
#endif
    /* Copy the resulting digest */
    if(digest != NULL)
        syMemcpy(digest, context->_un1.digest, SHA512_DIGEST_SIZE);
    else
        printf("digest is null\n");
}

static void sha512_processBlock(sha512_ctx *context)
{
	NQ_UINT t;
	SHA_U64 temp1;
	SHA_U64 temp2;
	volatile SHA_U64 *w = context->_un2.w;
 
	/* Initialize the 8 working registers */
	SHA_U64 a, b, c, d, e, f, g, h;
	SET_64 (a, context->_un1.h[0])
	SET_64 (b, context->_un1.h[1])
	SET_64 (c, context->_un1.h[2])
	SET_64 (d, context->_un1.h[3])
	SET_64 (e, context->_un1.h[4])
	SET_64 (f, context->_un1.h[5])
	SET_64 (g, context->_un1.h[6])
	SET_64 (h, context->_un1.h[7])


	/* process message that was copied to the buffer. 8 * 64 bit. 32 bit machines the 64 bit divided to hi, low */
#ifdef SY_LITTLEENDIANHOST
	/* Convert from big-endian byte order to host byte order if needed */
	for(t = 0; t < 16; t++)
	   SWAP64(w[t], w[t])
#endif

	/* Prepare the message schedule */
	for(t = 16; t < 80; t++)
	{
#ifdef SY_INT64
	    w[t] = SHA512_F4(w[t - 2]) + w[t - 7] + SHA512_F3(w[t - 15]) + w[t - 16];
#else
	    SHA_U64 _t1;
	    SHA512_F4(w[t], w[t-2])
	    ADD_U64U64(w[t], w[t-7])
		ADD_U64U64(w[t], w[t - 16])
	    SHA512_F3(_t1, w[t - 15])
   		ADD_U64U64(w[t], _t1)
#endif
	}
	/* SHA-512 hash computation */
	for(t = 0; t < 80; t++)
	{
	    /* Calculate T1 and T2 */
#ifdef SY_INT64
       temp1 = h + SHA512_F2(e) + CH1(e, f, g) + k[t] + w[t];
       temp2 = SHA512_F1(a) + MAJ2(a, b, c);
#else
       SHA_U64 t1;
       SHA512_F2(temp1, e)
       ADD_U64U64(temp1, h)
       CH1(t1, e, f, g)
       ADD_U64U64(temp1, t1)
	   ADD_U64U64(temp1, k[t])
       ADD_U64U64(temp1, w[t])
       SHA512_F1(temp2, a)
       MAJ2(t1, a, b, c)
       ADD_U64U64(temp2, t1)
#endif
	   /* Update the working registers */
	   SET_64(h, g)
	   SET_64(g, f)
       SET_64(f, e)

#ifdef SY_INT64
	   e = temp1 + d;
#else
       ADD_U64U64(d, temp1)
       SET_64(e, d);
#endif
       SET_64(d, c)
       SET_64(c, b)
       SET_64(b, a)
#ifdef SY_INT64
	   a = temp1 + temp2;
#else
       ADD_U64U64(temp1, temp2)
       SET_64(a, temp1)
#endif
 	}
  
 	/* Update the hash value */
	ADD_U64U64(context->_un1.h[0], a)
	ADD_U64U64(context->_un1.h[1], b)
	ADD_U64U64(context->_un1.h[2], c)
	ADD_U64U64(context->_un1.h[3], d)
	ADD_U64U64(context->_un1.h[4], e)
	ADD_U64U64(context->_un1.h[5], f)
	ADD_U64U64(context->_un1.h[6], g)
	ADD_U64U64(context->_un1.h[7], h)
}


static void sha512Internal(const CMBlob * key, const CMBlob * key1, const CMBlob dataFragments[], NQ_COUNT numFragments, NQ_BYTE * buffer, NQ_COUNT bufferSize, NQ_BYTE *sha512_CtxBuf)
{
	sha512_ctx *ctx;
	NQ_COUNT i;
	NQ_BOOL isExternalCtxBuff = FALSE;

	if (sha512_CtxBuf)
	{
		ctx = (sha512_ctx *)sha512_CtxBuf;
		isExternalCtxBuff = TRUE;
	}
	else
		ctx = (sha512_ctx *)cmBufManTake(sizeof(sha512_ctx));

	if (ctx == NULL)
		goto Exit;

	sha512_init(ctx);

	for (i = 0; i < numFragments; ++i)
	{
		if (dataFragments[i].data != NULL && dataFragments[i].len > 0)
		{
			sha512_update(ctx, dataFragments[i].data, dataFragments[i].len);
		}
	}
	
    sha512_final(ctx, buffer);

    if (!isExternalCtxBuff)
    	cmBufManGive((NQ_BYTE *)ctx);
Exit:
	return;
}

#ifdef NQ_DEBUG
static void sha512_compute(void* buffer, NQ_COUNT bufferSize, NQ_BYTE* digestResult)
{
	static sha512_ctx context;

	sha512_init(&context);
	sha512_update(&context, buffer, bufferSize);

	sha512_final(&context, digestResult);

    /* Copy the resulting digest */
	if(digestResult != NULL)
		syMemcpy(digestResult, context._un1.digest, SHA512_DIGEST_SIZE);
	else
	    printf("digest is null\n");
}


/*
*
* test vectors taken from: http://www.di-mgt.com.au/sha_testvectors.html
*
*/

/* sha512 - test vector 1 */
static const NQ_CHAR sha512_tv1 [] = "abc"; /* = 0x616263 - test vector 1 */
static const NQ_BYTE sha512_tv1_digest [] = 
{ 
    0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba,
    0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
    0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2,
    0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
    0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8,
    0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
    0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
    0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f
};

/* sha512 - test vector 2 */
static const NQ_CHAR sha512_tv2 [] = "";

static const NQ_BYTE sha512_tv2_digest [] =
{
    0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd,
    0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80, 0x07,
    0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc,
    0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce,
    0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0, 
    0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f,
    0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81, 
    0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e
};



/* sha512 - test vector 3 */
static const NQ_CHAR sha512_tv3 [] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";


static const NQ_BYTE sha512_tv3_digest [] =
{
    0x20, 0x4a, 0x8f, 0xc6, 0xdd, 0xa8, 0x2f, 0x0a, 0x0c, 0xed, 0x7b, 0xeb, 0x8e, 0x08, 0xa4, 0x16,
    0x57, 0xc1, 0x6e, 0xf4, 0x68, 0xb2, 0x28, 0xa8, 0x27, 0x9b, 0xe3, 0x31, 0xa7, 0x03, 0xc3, 0x35,
    0x96, 0xfd, 0x15, 0xc1, 0x3b, 0x1b, 0x07, 0xf9, 0xaa, 0x1d, 0x3b, 0xea, 0x57, 0x78, 0x9c, 0xa0,
    0x31, 0xad, 0x85, 0xc7, 0xa7, 0x1d, 0xd7, 0x03, 0x54, 0xec, 0x63, 0x12, 0x38, 0xca, 0x34, 0x45
};


/* sha512 - test vector 4 */
static const NQ_CHAR sha512_tv4 [] = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";

static const NQ_BYTE sha512_tv4_digest [] =
{
    0x8e, 0x95, 0x9b, 0x75, 0xda, 0xe3, 0x13, 0xda, 0x8c, 0xf4, 0xf7, 0x28, 0x14, 0xfc, 0x14, 0x3f, 
    0x8f, 0x77, 0x79, 0xc6, 0xeb, 0x9f, 0x7f, 0xa1, 0x72, 0x99, 0xae, 0xad, 0xb6, 0x88, 0x90, 0x18,
    0x50, 0x1d, 0x28, 0x9e, 0x49, 0x00, 0xf7, 0xe4, 0x33, 0x1b, 0x99, 0xde, 0xc4, 0xb5, 0x43, 0x3a,
    0xc7, 0xd3, 0x29, 0xee, 0xb6, 0xdd, 0x26, 0x54, 0x5e, 0x96, 0xe5, 0x5b, 0x87, 0x4b, 0xe9, 0x09
};


void testSha512(void)
{
	NQ_BYTE digestResult [SHA512_DIGEST_SIZE];

	/* test vector 1 */ 
	sha512_compute((void *) sha512_tv1, (NQ_COUNT)syStrlen(sha512_tv1), digestResult);
	if (syMemcmp(digestResult, sha512_tv1_digest, SHA512_DIGEST_SIZE) == 0)
		printf ("sha512 - vector 1 test success.\n\n");
	else
		printf ("sha512 - vector 1 test fail.\n");

	/* test vector 2 */
	sha512_compute((void *) sha512_tv2, (NQ_COUNT)syStrlen(sha512_tv2), digestResult);
	if (syMemcmp(digestResult, sha512_tv2_digest, SHA512_DIGEST_SIZE) == 0)
		printf ("sha512 - vector 2 test success.\n\n");
	else
		printf ("sha512 - vector 2 test fail.\n");

	/* test vector 3 */
	sha512_compute((void *) sha512_tv3, (NQ_COUNT)syStrlen(sha512_tv3), digestResult);
	if (syMemcmp(digestResult, sha512_tv3_digest, SHA512_DIGEST_SIZE) == 0)
		printf ("sha512 - vector 3 test success.\n\n");
	else
		printf ("sha512 - vector 3 test fail. len:%d\n", syStrlen(sha512_tv3));
	

	/* test vector 4 */
	sha512_compute((void *) sha512_tv4, (NQ_COUNT)syStrlen(sha512_tv4), digestResult);
	if (syMemcmp(digestResult, sha512_tv4_digest, SHA512_DIGEST_SIZE) == 0)
		printf ("sha512 - vector 4 test success.\n\n");
	else
		printf ("sha512 - vector 4 test fail. len:%d\n", syStrlen(sha512_tv4));
}


/************************
* CALC MESSAGE HASH TESTS
************************/

static const NQ_BYTE packet1 [] =
{
	0xFE, 0x53, 0x4D, 0x42, 0x40, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x24, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3F, 0x00, 0x00, 0x00, 0xEC, 0xD8, 0x6F, 0x32,
	0x62, 0x76, 0x02, 0x4F, 0x9F, 0x77, 0x52, 0xB8, 0x9B, 0xB3, 0x3F, 0x3A, 0x70, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x02, 0x10, 0x02, 0x00, 0x03, 0x02, 0x03, 0x11, 0x03, 0x00, 0x00, 0x01, 0x00, 0x26, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x20, 0x00, 0x01, 0x00, 0xFA, 0x49, 0xE6, 0x57, 0x8F, 0x1F, 0x3A, 0x9F, 0x4C, 0xD3, 0xE9, 0xCC, 0x14, 0xA6, 0x7A, 0xA8, 0x84, 0xB3, 0xD0, 0x58, 0x44, 0xE0, 0xE5, 0xA1, 0x18, 0x22, 0x5C, 0x15, 0x88, 0x7F, 0x32, 0xFF, 0x00, 0x00,
	0x02, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x02, 0x00, 0x01, 0x00
};

static const NQ_BYTE digest1 [] =
{
	0xDD, 0x94, 0xEF, 0xC5, 0x32, 0x1B, 0xB6, 0x18, 0xA2, 0xE2, 0x08, 0xBA, 0x89, 0x20, 0xD2, 0xF4, 0x22, 0x99, 0x25, 0x26, 0x94, 0x7A, 0x40, 0x9B, 0x50, 0x37, 0xDE, 0x1E, 0x0F, 0xE8, 0xC7, 0x36, 0x2B, 0x8C, 0x47, 0x12, 0x25, 0x94, 0xCD, 0xE0,
	0xCE, 0x26, 0xAA, 0x9D, 0xFC, 0x8B, 0xCD, 0xBD, 0xE0, 0x62, 0x19, 0x57, 0x67, 0x26, 0x23, 0x35, 0x1A, 0x75, 0x40, 0xF1, 0xE5, 0x4A, 0x04, 0x26
};

static const NQ_BYTE packet2 [] =
{
	0xFE, 0x53, 0x4D, 0x42, 0x40, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41, 0x00, 0x01, 0x00, 0x11, 0x03, 0x02, 0x00, 0x39, 0xCB, 0xCA, 0xF3, 0x29, 0x71, 0x49, 0x42,
	0xBD, 0xCE, 0x5D, 0x60, 0xF0, 0x9A, 0xB3, 0xFB, 0x2F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80, 0x00, 0xD8, 0xDA, 0xE5, 0xAD, 0xCB, 0xAE, 0xD0, 0x01, 0x09, 0x09, 0x4A, 0xB0, 0x95, 0xAE, 0xD0, 0x01,
	0x80, 0x00, 0x40, 0x01, 0xC0, 0x01, 0x00, 0x00, 0x60, 0x82, 0x01, 0x3C, 0x06, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02, 0xA0, 0x82, 0x01, 0x30, 0x30, 0x82, 0x01, 0x2C, 0xA0, 0x1A, 0x30, 0x18, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82,
	0x37, 0x02, 0x02, 0x1E, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0A, 0xA2, 0x82, 0x01, 0x0C, 0x04, 0x82, 0x01, 0x08, 0x4E, 0x45, 0x47, 0x4F, 0x45, 0x58, 0x54, 0x53, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x60, 0x00, 0x00, 0x00, 0x70, 0x00, 0x00, 0x00, 0x7C, 0x7C, 0xC0, 0xFD, 0x06, 0xD6, 0x36, 0x2D, 0x02, 0xDD, 0xE1, 0xCF, 0x34, 0x3B, 0xFE, 0x29, 0x29, 0x00, 0xF4, 0x97, 0x50, 0xB4, 0xAA, 0x97, 0x93, 0x4D, 0x9C, 0x42, 0x96, 0xB2, 0x6E, 0x51,
	0xFD, 0x37, 0x04, 0x71, 0xB2, 0x35, 0xE1, 0x5A, 0x50, 0xDA, 0xE1, 0x5B, 0xD5, 0x48, 0x9C, 0x87, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x5C, 0x33, 0x53, 0x0D, 0xEA, 0xF9, 0x0D, 0x4D, 0xB2, 0xEC, 0x4A, 0xE3, 0x78, 0x6E, 0xC3, 0x08, 0x4E, 0x45, 0x47, 0x4F, 0x45, 0x58, 0x54, 0x53, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x98, 0x00, 0x00, 0x00,
	0x7C, 0x7C, 0xC0, 0xFD, 0x06, 0xD6, 0x36, 0x2D, 0x02, 0xDD, 0xE1, 0xCF, 0x34, 0x3B, 0xFE, 0x29, 0x5C, 0x33, 0x53, 0x0D, 0xEA, 0xF9, 0x0D, 0x4D, 0xB2, 0xEC, 0x4A, 0xE3, 0x78, 0x6E, 0xC3, 0x08, 0x40, 0x00, 0x00, 0x00, 0x58, 0x00, 0x00, 0x00,
	0x30, 0x56, 0xA0, 0x54, 0x30, 0x52, 0x30, 0x27, 0x80, 0x25, 0x30, 0x23, 0x31, 0x21, 0x30, 0x1F, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x18, 0x54, 0x6F, 0x6B, 0x65, 0x6E, 0x20, 0x53, 0x69, 0x67, 0x6E, 0x69, 0x6E, 0x67, 0x20, 0x50, 0x75, 0x62,
	0x6C, 0x69, 0x63, 0x20, 0x4B, 0x65, 0x79, 0x30, 0x27, 0x80, 0x25, 0x30, 0x23, 0x31, 0x21, 0x30, 0x1F, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x18, 0x54, 0x6F, 0x6B, 0x65, 0x6E, 0x20, 0x53, 0x69, 0x67, 0x6E, 0x69, 0x6E, 0x67, 0x20, 0x50, 0x75,
	0x62, 0x6C, 0x69, 0x63, 0x20, 0x4B, 0x65, 0x79, 0x01, 0x00, 0x26, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x20, 0x00, 0x01, 0x00, 0x60, 0xA3, 0xC3, 0xB9, 0x5C, 0x3C, 0x7C, 0xCD, 0x51, 0xEC, 0x53, 0x66, 0x48, 0xD9, 0xB3, 0xAC, 0x74, 0xC4,
	0x83, 0xCA, 0x5B, 0x65, 0x38, 0x5A, 0x25, 0x11, 0x17, 0xBE, 0xB3, 0x07, 0x12, 0xE5, 0x00, 0x00, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00
};

static const NQ_BYTE digest2 [] = 
{
	0x32, 0x4B, 0xFA, 0x92, 0xA4, 0xF3, 0xA1, 0x90, 0xE4, 0x66, 0xEB, 0xEA, 0x08, 0xD9, 0xC1, 0x10, 0xDC, 0x88, 0xBF, 0xED, 0x75, 0x8D, 0x98, 0x46, 0xEC, 0xC6, 0xF5, 0x41, 0xCC, 0x1D, 0x02, 0xAE, 0x3C, 0x94, 0xA7, 0x9F, 0x36, 0x01, 0x1E, 0x99,
	0x7E, 0x13, 0xF8, 0x41, 0xB9, 0x1B, 0x50, 0x95, 0x7A, 0xD0, 0x7B, 0x19, 0xC8, 0xE2, 0x53, 0x9C, 0x0B, 0x23, 0xFD, 0xAE, 0x09, 0xD2, 0xC5, 0x13
};


void testCalcMessageHash(void)
{
	NQ_BYTE digestResult [SHA512_DIGEST_SIZE];
	
	syMemset(&digestResult, 0, sizeof(digestResult));

	/* packet 1 */ 
	cmSmb311CalcMessagesHash(packet1, sizeof(packet1), digestResult, NULL);

	if (syMemcmp(digestResult, digest1, SHA512_DIGEST_SIZE) == 0)
		printf ("\n\nsha512 - packet1 digest good.\n");
	else
		printf ("sha512 - packet1 digest fail.\n");
	
	/* packet 2 */ 
	cmSmb311CalcMessagesHash(packet2, sizeof(packet2), digestResult, NULL);

	if (syMemcmp(digestResult, digest2, SHA512_DIGEST_SIZE) == 0)
		printf ("sha512 - packet2 digest good.\n");
	else
		printf ("sha512 - packet2 digest fail.\n");
}

/*********************
* KEY DERVIATION TESTS
**********************/

static const NQ_BYTE sessionKey [] = 
{
	0x27, 0x0E, 0x1B, 0xA8, 0x96, 0x58, 0x5E, 0xEB, 0x7A, 0xF3, 0x47, 0x2D, 0x3B, 0x4C, 0x75, 0xA7
};


static NQ_BYTE preauthIntegcmHash [] = 
{
	0x0D, 0xD1, 0x36, 0x28, 0xCC, 0x3E, 0xD2, 0x18, 0xEF, 0x9D, 0xF9, 0x77, 0x2D, 0x43, 0x6D, 0x08, 0x87, 0xAB, 0x98, 0x14, 0xBF, 0xAE, 0x63, 0xA8, 0x0A, 0xA8, 0x45, 0xF3, 0x69, 0x09, 0xDB, 0x79, 0x28, 0x62, 0x2D, 0xDD, 0xAD, 0x52, 0x2D, 0x97,
	0x51, 0x64, 0x0A, 0x45, 0x97, 0x62, 0xC5, 0xA9, 0xD6, 0xBB, 0x08, 0x4C, 0xBB, 0x3C, 0xE6, 0xBD, 0xAD, 0xEF, 0x5D, 0x5B, 0xCE, 0x3C, 0x6C, 0x01
};

static const NQ_BYTE expectedSignKeyResult [] = 
{
	0x73, 0xFE, 0x7A, 0x9A, 0x77, 0xBE, 0xF0, 0xBD, 0xE4, 0x9C, 0x65, 0x0D, 0x8C, 0xCB, 0x5F, 0x76
};

static NQ_BYTE packetToSign [] =
{
	0xFE, 0x53, 0x4D, 0x42, 0x40, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x80, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x19, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x48, 0x00, 0x1D, 0x00, 0xA1, 0x1B, 0x30, 0x19, 0xA0, 0x03, 0x0A, 0x01,
	0x00, 0xA3, 0x12, 0x04, 0x10, 0x01, 0x00, 0x00, 0x00, 0x3B, 0x45, 0x3C, 0xDC, 0x35, 0x24, 0x16, 0x42, 0x00, 0x00, 0x00, 0x00
};

static const NQ_BYTE expectedHeaderSig [] =
{
	0xEB, 0xE1, 0x46, 0xDA, 0x12, 0x0B, 0xA2, 0x5F, 0xC3, 0x37, 0x6A, 0x49, 0xDF, 0xE3, 0x1B, 0xC1
};

void testSignKeyDerivationAndSigning(void)
{
	NQ_BYTE signingKey[SMB_SESSIONKEY_LENGTH];  /* a key for SIZE_Ts */
	NQ_BYTE headerSignature[SMB_SESSIONKEY_LENGTH];

	cmKeyDerivation(sessionKey, sizeof(sessionKey), (NQ_BYTE*)"SMBSigningKey\0",	 14 , preauthIntegcmHash, SMB3_PREAUTH_INTEG_HASH_LENGTH , signingKey);

	if (syMemcmp(expectedSignKeyResult, signingKey, sizeof(signingKey)) == 0)
		printf ("correct signing key created.\n");
	else
		printf ("BAD signing key created.\n");

	/* calculate header signature */
	cmSmb3CalculateMessageSignature(signingKey, sizeof(signingKey), packetToSign, sizeof(packetToSign), NULL, 0, headerSignature);

	if (syMemcmp(expectedHeaderSig, headerSignature, sizeof(headerSignature)) == 0)
		printf ("correct header signature created.\n");
	else
		printf ("BAAAAAAAAAAAAAAD header signature created.\n");
}
#endif /* NQ_DEBUG */

#endif /* UD_NQ_INCLUDESMB3 */
