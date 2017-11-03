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

#include "ccapi.h"
#include "ccsmb20.h"
#include "ccsmb30.h"
#include "cctransport.h"
#include "ccserver.h"
#include "ccuser.h"
#include "ccshare.h"
#include "ccfile.h"
#include "ccutils.h"
#include "ccerrors.h"
#include "ccparams.h"
#include "ccsmb2common.h"
#include "ccsearch.h"
#include "ccinfo.h"
#include "cmthread.h"
#include "cmfsutil.h"
#include "cmsmb2.h"
#include "cmbufman.h"
#include "cmcrypt.h"
#include "cmsdescr.h"

#ifdef UD_NQ_INCLUDECIFSCLIENT
#ifdef UD_NQ_INCLUDESMB311


/* CCCifsSmb methods */
static void keyDerivation(void * user);
static NQ_BOOL validateNegotiate(void *pServ, void *_pUser, void *pShare);
#ifdef UD_CC_INCLUDESECURITYDESCRIPTORS
static NQ_STATUS doQuerySecurityDescriptor(CCFile * pFile, CMSdSecurityDescriptor * sd);
#endif /* UD_CC_INCLUDESECURITYDESCRIPTORS */

static  CCCifsSmb dialect;

static const Command commandDescriptors[] = /* SMB2 descriptor */
{
		{ 128, 36, 65, NULL, NULL}, 				/* SMB2 NEGOTIATE 0x0000 */
		{ 26, 25, 9, NULL, NULL},					/* SMB2 SESSION_SETUP 0x0001 */
		{ 6, 4, 4, NULL, NULL},					    /* SMB2 LOGOFF 0x0002 */
		{ 10, 9, 16, NULL, NULL},					/* SMB2 TREE_CONNECT 0x0003 */
		{ 6, 4, 4, NULL, NULL},					    /* SMB2 TREE_DISCONNECT 0x0004 */
		{ 4096, 57, 89, NULL, NULL},				/* SMB2 CREATE 0x0005 */
		{ 26, 24, 60, NULL, NULL},				    /* SMB2 CLOSE 0x0006 */
		{ 26, 24, 4, NULL, NULL},					/* SMB2 FLUSH 0x0007 */
		{ 64, 49, 17, NULL, NULL},		    		/* SMB2 READ 0x0008 */
		{ 64, 49, 17, NULL, NULL},		    		/* SMB2 WRITE 0x0009 */
		{ 0, 0, 0, NULL, NULL},					    /* SMB2 LOCK 0x000A */
		{ 100, 57, 49, NULL, NULL},				    /* SMB2 IOCTL 0x000B */
		{ 0, 0, 0, NULL, NULL},					    /* SMB2 CANCEL 0x000C */
		{ 4, 4, 4, NULL, NULL},					    /* SMB2 ECHO 0x000D */
		{ 40, 33, 9, NULL, NULL},					/* SMB2 QUERY_DIRECTORY 0x000E */
		{ 0, 0, 0, NULL, NULL},					    /* SMB2 CHANGE_NOTIFY 0x000F */
		{ 44, 41, 9, NULL, NULL},					/* SMB2 QUERY_INFO 0x0010 */
		{ 80, 33, 2, NULL, NULL},					/* SMB2 SET_INFO 0x0011 */
		{ 100, 24, 0, NULL, NULL },					/* SMB2 OPLOCK_BREAK 0x0012 */
};

/* -- API Functions */

NQ_BOOL ccSmb311Start()
{
	CCCifsSmb 	tempDialect;

	syMemcpy(&tempDialect ,ccSmb30GetCifs(), sizeof(CCCifsSmb));

	tempDialect.name = SMB3_1_1_DIALECTSTRING;
	tempDialect.revision = SMB3_1_1_DIALECTREVISION;
	tempDialect.keyDerivation = keyDerivation;
	tempDialect.validateNegotiate = validateNegotiate;
#ifdef UD_CC_INCLUDESECURITYDESCRIPTORS
	tempDialect.doQuerySecurityDescriptor = (NQ_STATUS (*)(void * pFile, CMSdSecurityDescriptor * sd))doQuerySecurityDescriptor;
#endif /* UD_CC_INCLUDESECURITYDESCRIPTORS */
	syMemcpy(&dialect , &tempDialect , sizeof(CCCifsSmb));

	return TRUE;
}

NQ_BOOL ccSmb311Shutdown()
{
	return TRUE;
}

const CCCifsSmb * ccSmb311GetCifs(void)
{
	return &dialect;
}

#ifdef UD_CC_INCLUDESECURITYDESCRIPTORS
static void writeHeader(Request * pRequest)
{
	cmSmb2HeaderWrite(&pRequest->header, &pRequest->writer);
	cmBufferWriteUint16(&pRequest->writer, commandDescriptors[pRequest->command].requestStructSize);
}

/* -- Static functions -- */

static NQ_UINT16 calculateCreditCharge(CCServer * pServer, NQ_UINT32 requestLength)
{
    NQ_UINT16 creditCharge;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "server:%p requestLength:%d", pServer, requestLength);

    creditCharge = (NQ_UINT16)((requestLength > 0) ? (1 + ((requestLength - 1) / 65536)) : 1);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "credit charge:%d", creditCharge);
    return creditCharge;
}

static NQ_BOOL prepareSingleRequest(CCServer * pServer, CCUser * pUser, Request * pRequest, NQ_UINT16 command)
{
	NQ_BYTE * pBuffer;		/* allocated request buffer */
	NQ_COUNT bufferSize;	/* this buffer size */
	NQ_BOOL result = FALSE; /* return value */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "server:%p user:%p request:%p command:0x%x", pServer, pUser, pRequest, command);

	/* this call:
	 * - allocates request buffer
	 * - creates request header
	 */
	/* allocate buffer for request */
	bufferSize = (NQ_COUNT)(commandDescriptors[command].requestBufferSize + SMB2_HEADERSIZE + 4);
	pBuffer = cmBufManTake(bufferSize);
	if (NULL == pBuffer)
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
		goto Exit;
	}
	cmBufferWriterInit(&pRequest->writer, pBuffer, bufferSize);
	pRequest->buffer = pBuffer;
	pRequest->command = command;
	pRequest->tail.data = NULL;
	pRequest->tail.len = 0;
	pRequest->encrypt = (NULL == pUser) ? FALSE : pUser->isEncrypted;
	cmBufferWriterSkip(&pRequest->writer, 4);	/* NBT header */
	cmSmb2HeaderInitForRequest(&pRequest->header, &pRequest->writer, command);
#ifdef UD_NQ_INCLUDESMB3
    if (pServer && (pServer->capabilities & CC_CAP_LARGEMTU))
    {
        pRequest->header.creditCharge = 1;
    }
#endif /* UD_NQ_INCLUDESMB3 */
	if (NULL == pUser)
    {
        pRequest->header.sid.low = 0;
        pRequest->header.sid.high = 0;
    }
    else
    {
        pRequest->header.sid = pUser->uid;
    }
    pRequest->header.flags = (NQ_UINT16)((command != SMB2_CMD_SESSIONSETUP && pServer && ccServerUseSignatures(pServer) && pUser && ccUserUseSignatures(pUser))
                                ? SMB2_FLAG_SIGNED : 0
#ifdef UD_CC_INCLUDEDFS
                                | ((pServer && (pServer->capabilities & CC_CAP_DFS)) ? SMB2_FLAG_DFS_OPERATIONS : 0)
#endif /* UD_CC_INCLUDEDFS */
                                );
	result = TRUE;

Exit:
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result ? "TRUE" : "FALSE");
	return result;
}
#endif /* UD_CC_INCLUDESECURITYDESCRIPTORS */
static void keyDerivation(void * user)
{
	CCUser * pUser = (CCUser *)user;

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "user:%p", pUser);

	if (pUser->macSessionKey.data != NULL)
	{
		if (pUser->macSessionKey.len > pUser->server->smb->maxSigningKeyLen)
			pUser->macSessionKey.len = pUser->server->smb->maxSigningKeyLen;  /* restrict bigger keys */

		cmMemoryFreeBlob(&pUser->encryptionKey);
		cmMemoryFreeBlob(&pUser->decryptionKey);
		cmMemoryFreeBlob(&pUser->applicationKey);

		pUser->encryptionKey.data = (NQ_BYTE *)cmMemoryAllocate(sizeof(NQ_BYTE) * SMB2_SECURITY_SIGNATURE_SIZE);
		pUser->encryptionKey.len = SMB2_SECURITY_SIGNATURE_SIZE;
		pUser->decryptionKey.data = (NQ_BYTE *)cmMemoryAllocate(sizeof(NQ_BYTE) * SMB2_SECURITY_SIGNATURE_SIZE);
		pUser->decryptionKey.len = SMB2_SECURITY_SIGNATURE_SIZE;
		pUser->applicationKey.data = (NQ_BYTE *)cmMemoryAllocate(sizeof(NQ_BYTE) * SMB2_SECURITY_SIGNATURE_SIZE);
		pUser->applicationKey.len = SMB2_SECURITY_SIGNATURE_SIZE;

		LOGDUMP("mac preauth",pUser->preauthIntegHashVal, sizeof(pUser->preauthIntegHashVal));
		LOGDUMP("mac sesssion key",pUser->macSessionKey.data, pUser->macSessionKey.len );
		cmKeyDerivation(pUser->macSessionKey.data, pUser->encryptionKey.len , (NQ_BYTE*)"SMBS2CCipherKey\0", 16 , pUser->preauthIntegHashVal, SMB3_PREAUTH_INTEG_HASH_LENGTH , (NQ_BYTE *)pUser->encryptionKey.data );
		cmKeyDerivation(pUser->macSessionKey.data, pUser->decryptionKey.len , (NQ_BYTE*)"SMBC2SCipherKey\0", 16 , pUser->preauthIntegHashVal, SMB3_PREAUTH_INTEG_HASH_LENGTH , (NQ_BYTE *)pUser->decryptionKey.data );
		cmKeyDerivation(pUser->macSessionKey.data, pUser->applicationKey.len, (NQ_BYTE*)"SMBAppKey\0",       10 , pUser->preauthIntegHashVal, SMB3_PREAUTH_INTEG_HASH_LENGTH , (NQ_BYTE *)pUser->applicationKey.data);
		cmKeyDerivation(pUser->macSessionKey.data, pUser->macSessionKey.len , (NQ_BYTE*)"SMBSigningKey\0",   14 , pUser->preauthIntegHashVal, SMB3_PREAUTH_INTEG_HASH_LENGTH , (NQ_BYTE *)pUser->macSessionKey.data );
		LOGDUMP("mac encryption key",pUser->encryptionKey.data, pUser->encryptionKey.len );
		LOGDUMP("mac decryption key",pUser->decryptionKey.data, pUser->decryptionKey.len );
		LOGDUMP("mac app key",pUser->applicationKey.data, pUser->applicationKey.len );
		LOGDUMP("mac sesssion key after",pUser->macSessionKey.data, pUser->macSessionKey.len );
	}

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

static NQ_BOOL validateNegotiate(void *pServ, void *_pUser, void *pShare)
{
	return TRUE;
}

#ifdef UD_CC_INCLUDESECURITYDESCRIPTORS
static NQ_BOOL prepareSingleRequestByShare(Request * pRequest, const CCShare * pShare, NQ_UINT16 command, NQ_UINT32 dataLen)
{
	NQ_BOOL result = FALSE;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "pRequest:%p pShare:%p command:0x%X dataLen:%d", pRequest, pShare, command, dataLen);

	if (!prepareSingleRequest(pShare->user->server, pShare->user, pRequest, command))
	{
		goto Exit;
	}
	pRequest->encrypt = pShare->user->isEncrypted ? TRUE : pShare->encrypt;
#ifdef UD_CC_INCLUDEDFS
    if (pShare->flags & CC_SHARE_IN_DFS)
        pRequest->header.flags |= SMB2_FLAG_DFS_OPERATIONS;
    else
        pRequest->header.flags =  (NQ_UINT32)(pRequest->header.flags & (NQ_UINT32)~SMB2_FLAG_DFS_OPERATIONS);
#endif /* UD_CC_INCLUDEDFS */
#ifdef UD_NQ_INCLUDESMB3
    if (pShare->user->server->capabilities & CC_CAP_LARGEMTU)
    {
        switch (command)
        {
        case SMB2_CMD_READ:
        case SMB2_CMD_WRITE:
        case SMB2_CMD_QUERYDIRECTORY:
            pRequest->header.creditCharge = calculateCreditCharge(pShare->user->server, dataLen);
            break;
        default:
            pRequest->header.creditCharge = 1;
            break;
        }
        if (pRequest->header.creditCharge > 1)
            pRequest->header.credits = pRequest->header.creditCharge;
    }
#endif /* UD_NQ_INCLUDESMB3 */
	pRequest->header.tid = pShare->tid;
	result = TRUE;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result ? "TRUE" : "FALSE");
	return result;
}

static NQ_STATUS writeQueryInfoRequest(
		Request * pRequest,
		CCFile * pFile,
		NQ_BYTE infoType,
		NQ_BYTE infoClass,
		NQ_UINT32 maxResLen,
		NQ_UINT32 addInfo
		)
{
	NQ_STATUS result = NQ_ERR_OUTOFMEMORY;

	if (!prepareSingleRequestByShare(pRequest, pFile->share, SMB2_CMD_QUERYINFO, 0))
	{
		goto Exit;
	}

	/* compose request */
	writeHeader(pRequest);
	cmBufferWriteByte(&pRequest->writer, infoType);		/* information type */
	cmBufferWriteByte(&pRequest->writer, infoClass);	/* information class */
	cmBufferWriteUint32(&pRequest->writer, maxResLen);	/* output buffer length */
	cmBufferWriteUint16(&pRequest->writer, 0);			/* input buffer offset  */
	cmBufferWriteUint16(&pRequest->writer, 0);			/* reserved */
	cmBufferWriteUint32(&pRequest->writer, 0);			/* input buffer length */
	cmBufferWriteUint32(&pRequest->writer, addInfo);	/* output buffer length */
	cmBufferWriteUint32(&pRequest->writer, 0);			/* flags */
	cmBufferWriteBytes(&pRequest->writer, pFile->fid, sizeof(pFile->fid));	/* file ID */
	result = NQ_SUCCESS;

Exit:
	return result;
}

static NQ_STATUS doQuerySecurityDescriptor(CCFile * pFile, CMSdSecurityDescriptor * sd)
{
	Request request;		/* request descriptor */
	Response response;		/* response descriptor */
	CCServer * pServer;		/* server object pointer */
	NQ_STATUS res;			/* exchange result */
	NQ_UINT32 responseSize;	/* required response size */
	CMRpcPacketDescriptor in;	/* for parsing SD */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "file:%p sd:%p", pFile, sd);

	request.buffer = NULL;
	response.buffer = NULL;

	pServer = pFile->share->user->server;

	/* query with zero buffer to get SD length */
	res = writeQueryInfoRequest(&request, pFile, SMB2_INFO_SECURITY, 0, 0, SMB2_SIF_OWNER | SMB2_SIF_GROUP | SMB2_SIF_DACL);
	if (NQ_SUCCESS != res)
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
		res = NQ_ERR_OUTOFMEMORY;
		goto Exit;
	}
	request.tail.data = NULL;
	request.tail.len = 0;

	res = pServer->smb->sendReceive(pServer, pFile->share->user, &request, &response);
    cmBufManGive(request.buffer);
    request.buffer = NULL;
	if (NQ_ERR_MOREDATA != res)
	{
		goto Exit;
	}

	/* parse error response */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT16));	/* ErrorContextCount - should be 1 + reserved */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT32));	/* ByteCount - should be 12 */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT32));	/* ErrorDataLength - should be 4 */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT32));	/* ErrorId - should be 0 */
	cmBufferReadUint32(&response.reader, &responseSize);		/* required buffer size */
    cmBufManGive(response.buffer);
    response.buffer = NULL;
	if (responseSize > UD_CM_SECURITYDESCRIPTORLENGTH)
	{
		LOGERR(CM_TRC_LEVEL_FUNC_COMMON," requested buffer size (%d) is larger then maximum SD buffer (%d)" , responseSize , UD_CM_SECURITYDESCRIPTORLENGTH);
		goto Exit;
	}
	/* query with required buffer */
	res = writeQueryInfoRequest(&request, pFile, SMB2_INFO_SECURITY, 0, responseSize, SMB2_SIF_OWNER | SMB2_SIF_GROUP | SMB2_SIF_DACL);
	if (NQ_SUCCESS != res)
	{
		LOGERR(CM_TRC_LEVEL_FUNC_COMMON," writeQueryInfoRequest() failed");
		goto Exit;
	}
	request.tail.data = NULL;
	request.tail.len = 0;

	res = pServer->smb->sendReceive(pServer, pFile->share->user, &request, &response);
	if (NQ_SUCCESS != res)
	{
		LOGERR(CM_TRC_LEVEL_FUNC_COMMON," sendReceive() failed");
		goto Exit;
	}

	/* parse response */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT16));	/* offset */
	cmBufferReadUint32(&response.reader, &sd->length);	/* length */
	cmRpcSetDescriptor(&in, cmBufferReaderGetPosition(&response.reader), FALSE);
	cmSdParseSecurityDescriptor(&in, sd);			/* security descriptor */

Exit:
	cmBufManGive(request.buffer);
	cmBufManGive(response.buffer);
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", res);
	return res;
}
#endif /* UD_CC_INCLUDESECURITYDESCRIPTORS */

#endif /* UD_NQ_INCLUDESMB311 */
#endif /* UD_NQ_INCLUDECIFSCLIENT */
