/*************************************************************************
 * Copyright 2011-2012 by Visuality Systems, Ltd.
 *
 *                     All Rights Reserved
 *
 * This item is the property of Visuality Systems, Ltd., and contains
 * confidential, proprietary, and trade-secret information. It may not
 * be transferred from the custody or control of Visuality Systems, Ltd.,
 * except as expressly authorized in writing by an officer of Visuality
 * Systems, Ltd. Neither this item nor the information it contains may
 * be used, transferred, reproduced, published, or disclosed, in whole
 * or in part, and directly or indirectly, except as expressly authorized
 * by an officer of Visuality Systems, Ltd., pursuant to written agreement.
 **************************************************************************/

#include "amcrypt.h"
#include "cmcrypt.h"

/* -- Typedefs and structures -- */

typedef struct 
{
	const NQ_BYTE * key; 				/* encryption key pointer */
	const AMCredentialsW * credentials;	/* credentaisl pointer */
	const CMBlob * names;				/* optional names blob for NTLMv2 */
	NQ_BYTE lmHash[16];					/* hashed LM password */
	NQ_BYTE ntlmHash[16];				/* hased NTLM password */
	
} Context;

typedef NQ_BOOL (*EncryptPassword)(const Context * context, AMCrypt * crypt);

typedef struct 
{
	NQ_UINT code;				/* crypter code */
	EncryptPassword routine;	/* encryption algorithm routine */ 
} CrypterDescriptor;

/* -- Forward definitions -- */

static NQ_BOOL encryptNone(const Context * context, AMCrypt * crypt);
static NQ_BOOL encryptLM(const Context * context, AMCrypt * crypt);
static NQ_BOOL encryptNTLM(const Context * context, AMCrypt * crypt);
static NQ_BOOL encryptLMv2(const Context * context, AMCrypt * crypt);
static NQ_BOOL encryptNTLMv2(const Context * context, AMCrypt * crypt);

/* -- Static data -- */

static const CrypterDescriptor crypters[] =
{
    { AM_CRYPTER_NONE, encryptNone },
    { AM_CRYPTER_LM, encryptLM },
    { AM_CRYPTER_LM2, encryptLMv2 },
    { AM_CRYPTER_NTLM, encryptNTLM },
    { AM_CRYPTER_NTLM2, encryptNTLMv2 },
};

/* -- Static fucntions -- */

static NQ_BOOL encryptNone(const Context * context, AMCrypt * crypt)
{
	return TRUE;
}

static NQ_BOOL encryptLM(const Context * context, AMCrypt * crypt)
{
    NQ_UINT16   passLen;
 	crypt->pass1.len = 24;
 	if (NULL == crypt->pass1.data || NULL == crypt->macKey.data || NULL == crypt->response.data)
		return FALSE;
	cmEncryptLMPassword(context->key, context->lmHash, crypt->pass1.data, &passLen);
    crypt->pass1.len = passLen;
    syMemset(crypt->macKey.data, 0, 16);
    syMemcpy(crypt->macKey.data, crypt->pass1.data, 8);
    crypt->macKey.len = 8;
    syMemcpy(crypt->response.data, crypt->pass1.data, 24);
    return TRUE;
}
static NQ_BOOL encryptNTLM(const Context * context, AMCrypt * crypt)
{
    NQ_UINT16   passLen;
 	if (NULL == crypt->pass2.data || NULL == crypt->macKey.data || NULL == crypt->response.data)
		return FALSE;
    cmEncryptNTLMPassword(context->key, context->ntlmHash, crypt->pass2.data, &passLen);
    crypt->pass2.len = passLen;
    cmMD4(crypt->macKey.data, (NQ_BYTE *)context->ntlmHash, 16);
    crypt->macKey.len = 16;
    syMemcpy(crypt->response.data, crypt->pass2.data, 24);
    return TRUE;
}

static NQ_BOOL v2Hash(const Context * context, NQ_BYTE * v2Hash)
{
	NQ_WCHAR * data;

	data = cmMemoryAllocate(sizeof(context->credentials->user) + sizeof(context->credentials->domain.name));
    if (NULL == data)
    	return FALSE;
    cmWStrcpy(data, context->credentials->user);
    if (cmWStrchr(context->credentials->user, cmWChar('@')) == NULL)
        cmWStrcat(data, context->credentials->domain.name);
	cmWStrupr(data);

    cmHMACMD5(context->ntlmHash, 16, (NQ_BYTE*)data, (NQ_UINT)(cmWStrlen(data) * sizeof(NQ_WCHAR)), v2Hash);
    cmMemoryFree(data);
    return TRUE;
}

static void createNTLMv2Blip(NQ_BYTE *blip)
{
    NQ_INT i;

    for (i = 0; i < 8; blip[i++] = (NQ_BYTE)syRand())
    {};
}

static NQ_BOOL encryptLMv2(const Context * context, AMCrypt * crypt)
{
    NQ_BYTE v2hash[16];
    NQ_BYTE blip[8];
    NQ_BYTE data[16];
    NQ_BYTE hmac[16];

    createNTLMv2Blip(blip);
    syMemcpy(data, context->key, 8);
    syMemcpy(data + 8, blip, 8);
	if (NULL == crypt->pass1.data || NULL == crypt->macKey.data || NULL == crypt->response.data)
		return FALSE;
    v2Hash(context, v2hash);
    cmHMACMD5(v2hash, sizeof(v2hash), data, sizeof(data), hmac);
    syMemcpy(crypt->pass1.data, hmac, sizeof(hmac));
    syMemcpy(crypt->pass1.data + sizeof(hmac), blip, sizeof(blip));
    crypt->pass1.len = sizeof(hmac) + sizeof(blip);
    cmHMACMD5(v2hash, sizeof(v2hash), hmac, sizeof(hmac), crypt->macKey.data);
    syMemcpy(crypt->response.data, crypt->pass1.data, 24);
    return TRUE;
}

static void createNTLMv2Blob(const Context * context, CMBlob * blob)
{
    NQ_UINT32 timeLow;
    NQ_UINT32 timeHigh;

    /* header */
    cmPutUint32(&blob->data[0], cmHtol32(0x00000101)); 

    /* timestamp */
    cmCifsTimeToUTC((NQ_UINT32)syGetTime(), &timeLow, &timeHigh);
    timeLow = cmHtol32(timeLow);
    timeHigh = cmHtol32(timeHigh);
    cmPutUint32(&blob->data[ 8], timeLow);
    cmPutUint32(&blob->data[12], timeHigh);
    blob->len = 16;

    /* blip */
    createNTLMv2Blip(&blob->data[blob->len]);
    blob->len = blob->len + 8 + 4; /* 8 + Unknown */
    
    /* Target info names blob */
    if (NULL != context->names)
    {
        syMemcpy(&blob->data[blob->len], context->names->data, context->names->len);
        blob->len = blob->len + context->names->len;
        return;
    }
    /* EOL + Unknown */
    blob->len = blob->len + 4 + 4;
}

static NQ_BOOL encryptNTLMv2(const Context * context, AMCrypt * crypt)
{
    NQ_BYTE v2hash[16];
    CMBlob blob;	/* part of the response without HMAC */
    NQ_BYTE * data;   /* encryption key + blob */
    NQ_BYTE hmac[16];

    blob.len = crypt->pass2.len - 16;
    blob.data = cmMemoryAllocate(blob.len);
    if (NULL == blob.data)
    {
    	return FALSE;
    }
    data = cmMemoryAllocate(crypt->pass2.len - 8);
    if (NULL == data)
    {
    	cmMemoryFree(blob.data);
    	return FALSE;
    }

	if (NULL == crypt->pass2.data || NULL == crypt->macKey.data || NULL == crypt->response.data)
    {
        cmMemoryFree(data);
	    cmMemoryFree(blob.data);
		return FALSE;
    }
    syMemset(blob.data, 0, 36);
    createNTLMv2Blob(context, &blob);    
    syMemcpy(data, context->key, 8);
    syMemcpy(data + 8, blob.data, blob.len);
    v2Hash(context, v2hash);
    cmHMACMD5(v2hash, sizeof(v2hash), data, (NQ_UINT)(8 + blob.len), hmac);
    syMemcpy(crypt->pass2.data, hmac, sizeof(hmac));
    syMemcpy(crypt->pass2.data + sizeof(hmac), blob.data, blob.len);
    cmHMACMD5(v2hash, sizeof(v2hash), hmac, sizeof(hmac), crypt->macKey.data);
    crypt->pass2.len = (NQ_COUNT)(sizeof(hmac) + blob.len);
    crypt->response.len = crypt->pass2.len;
    syMemcpy(crypt->response.data, crypt->pass2.data, crypt->response.len);
    cmMemoryFree(data);
	cmMemoryFree(blob.data);
	return TRUE;
}

static NQ_COUNT getPassLenByCrypter(NQ_UINT crypter)
{
	switch (crypter)
	{
	case AM_CRYPTER_NONE:
		return 0;
	case AM_CRYPTER_LM:
		return 24;
	case AM_CRYPTER_LM2:
		return 24;
	case AM_CRYPTER_NTLM:
		return 24;
	case AM_CRYPTER_NTLM2:
		return CM_CRYPT_MAX_NTLMV2NTLMSSPRESPONSESIZE - 200;
	default:
		return 0;
	}
}

static NQ_BOOL cryptByCrypter(NQ_UINT crypter, Context * pContext, AMCrypt * pCrypt)
{
	NQ_INT i;
	
	for (i = 0; i < sizeof(crypters)/sizeof(crypters[0]); i++)
	{
		if (crypters[i].code == crypter)
		{
			return crypters[i].routine(pContext, pCrypt);
		}
	}
	return FALSE;
}

static void createCrypt(NQ_UINT crypt1, NQ_UINT crypt2, AMCrypt * crypt)
{
    crypt->pass1.len = getPassLenByCrypter(crypt1);
    crypt->pass1.data = cmMemoryAllocate(crypt->pass1.len);
    crypt->pass2.len = getPassLenByCrypter(crypt2);
    crypt->pass2.data = cmMemoryAllocate(crypt->pass2.len);
   	crypt->macKey.len = 16;

   	crypt->macKey.data = cmMemoryAllocate(crypt->macKey.len);
   	crypt->response.len = (crypt->pass2.len == 0) ? ((crypt->pass1.len == 0) ? 0 : crypt->pass1.len ) : crypt->pass2.len;
   	crypt->response.data = cmMemoryAllocate(crypt->response.len);
   	if (NULL != crypt->macKey.data)
        syMemset(crypt->macKey.data, 0, crypt->macKey.len);
   	if (NULL != crypt->response.data)
       	syMemset(crypt->response.data, 0, crypt->response.len);
}

static void createContext(Context * context, const AMCredentialsW * credentials, const NQ_BYTE * key, const CMBlob * names)
{
	NQ_CHAR * passwordA;	/* ASCII password */

	context->credentials = credentials;
	context->key = key;
	context->names = names;
	passwordA = cmMemoryCloneWStringAsAscii(credentials->password);
	if (NULL == passwordA)
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
		return;
	}
	cmHashPassword((NQ_BYTE *)passwordA, context->lmHash);
    cmMD4(context->ntlmHash, (NQ_BYTE *)credentials->password, (NQ_UINT)(cmWStrlen(credentials->password) * sizeof(NQ_WCHAR)));
    cmMemoryFree(passwordA);
}

/* -- API functions -- */

NQ_BOOL amCryptEncrypt(
		const AMCredentialsW * credentials, 
		NQ_UINT crypt1, 
		NQ_UINT crypt2, 
		const NQ_BYTE * encryptionKey, 
		CMBlob * names, 
		AMCrypt * crypt
		)
{
	Context context;	/* encryption context */
	createCrypt(crypt1, crypt2, crypt);
	createContext(&context, credentials, encryptionKey, names);
	if (!cryptByCrypter(crypt1, &context, crypt))
		return FALSE;
	if (!cryptByCrypter(crypt2, &context, crypt))
		return FALSE;
	return TRUE;
}

void amCryptDispose(AMCrypt * crypt)
{
	cmMemoryFreeBlob(&crypt->pass1);
	cmMemoryFreeBlob(&crypt->pass2);
	cmMemoryFreeBlob(&crypt->macKey);
	cmMemoryFreeBlob(&crypt->response);
}
