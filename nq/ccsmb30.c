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
#ifdef UD_NQ_INCLUDESMB3


/* special callbacks */
static void writeCallback(CCServer * pServer, Match * pContext);
static void readCallback(CCServer * pServer, Match * pContext);
/* notification handles */
static void handleBreakNotification(CCServer * pServer, Response * pResponse, CCFile *pFile);
static void handleWaitingNotifyResponse(void *pServer, void *pFile);

static NQ_BOOL checkMessageSignatureSMB3(CCUser *pUser, NQ_BYTE *pHeaderIn, NQ_COUNT headerDataLength, NQ_BYTE* buffer, NQ_COUNT bufLength);

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
	{ 64, 49, 17, readCallback, NULL},		    /* SMB2 READ 0x0008 */	 
	{ 64, 49, 17, writeCallback, NULL},		    /* SMB2 WRITE 0x0009 */		 
	{ 0, 0, 0, NULL, NULL},					    /* SMB2 LOCK 0x000A */		 
	{ 100, 57, 49, NULL, NULL},				    /* SMB2 IOCTL 0x000B */		 
	{ 0, 0, 0, NULL, NULL},					    /* SMB2 CANCEL 0x000C */		 
	{ 4, 4, 4, NULL, NULL},					    /* SMB2 ECHO 0x000D */		 
	{ 40, 33, 9, NULL, NULL},					/* SMB2 QUERY_DIRECTORY 0x000E */
	{ 0, 0, 0, NULL, NULL},					    /* SMB2 CHANGE_NOTIFY 0x000F */		 
	{ 44, 41, 9, NULL, NULL},					/* SMB2 QUERY_INFO 0x0010 */
	{ 80, 33, 2, NULL, NULL},					/* SMB2 SET_INFO 0x0011 */		 
	{ 100, 24, 0, NULL, handleBreakNotification },/* SMB2 OPLOCK_BREAK 0x0012 */
};


/* CCCifsSmb methods */
static NQ_STATUS sendRequest(CCServer * pServer, CCUser * pUser, Request * pRequest, Match * pMatch, NQ_BOOL (*callback)(CMItem * pItem));
static NQ_STATUS sendReceive(CCServer * pServer, CCUser * pUser, Request * pRequest, Response * pResponse);
static void anyResponseCallback(void * transport);

static void keyDerivation(void * user);
static NQ_BOOL validateNegotiate(void *pServ, void *_pUser, void* _pShareIPC);

static  CCCifsSmb dialect;

/* -- API Functions */

NQ_BOOL ccSmb30Start(void)
{
	CCCifsSmb 	tempDialect;

	syMemcpy(&tempDialect ,ccSmb20GetCifs(), sizeof(CCCifsSmb));

	tempDialect.name = SMB3_DIALECTSTRING;
	tempDialect.revision = SMB3_DIALECTREVISION;
	tempDialect.anyResponseCallback = anyResponseCallback;
	tempDialect.sendRequest = (NQ_STATUS (*)(void * pServer, void * pUser, void * pRequest, void * pMatch, NQ_BOOL (*callback)(CMItem * pItem)))sendRequest;
	tempDialect.sendReceive = (NQ_STATUS (*)(void * pServer, void * pUser, void * pRequest, void * pResponse))sendReceive;
	tempDialect.handleWaitingNotifyResponses = handleWaitingNotifyResponse;
	tempDialect.keyDerivation = keyDerivation;
	tempDialect.validateNegotiate = validateNegotiate;

	syMemcpy(&dialect , &tempDialect , sizeof(CCCifsSmb));

	return TRUE;
}

NQ_BOOL ccSmb30Shutdown(void)
{
	return TRUE;
}

const CCCifsSmb * ccSmb30GetCifs(void)
{
	return &dialect;
}


/* -- Static functions -- */

static void ccComposeEncryptionNonce(NQ_BYTE * buf ,NQ_UINT32 midLow)
{
	CMBufferWriter	writer;
	CMTime	time;

	if (buf == NULL)
	{
		return;
	}

	/* although nonce size different for AES GCM and AES CCM,
	 * this nonce algorithm qualifies for both. */

	cmBufferWriterInit(&writer,buf, SMB2_AES128_CCM_NONCE_SIZE);
	cmGetCurrentTime(&time);
	cmBufferWriteUint32(&writer,time.low);
	cmBufferWriterSkip(&writer,3);
	cmBufferWriteUint32(&writer,midLow);

	return;
}


static void keyDerivation(void * user)
{
	CCUser * pUser = (CCUser *)user;

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "user:%p pUser->macSessionKey.data:%p", pUser, pUser->macSessionKey.data);

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
		cmKeyDerivation( pUser->macSessionKey.data, pUser->encryptionKey.len  , (NQ_BYTE*)"SMB2AESCCM\0" , 11 , (NQ_BYTE*)"ServerOut\0" , 10, (NQ_BYTE *)pUser->encryptionKey.data );
		cmKeyDerivation( pUser->macSessionKey.data, pUser->decryptionKey.len  , (NQ_BYTE*)"SMB2AESCCM\0" , 11 , (NQ_BYTE*)"ServerIn \0" , 10, (NQ_BYTE *)pUser->decryptionKey.data );
		cmKeyDerivation( pUser->macSessionKey.data, pUser->applicationKey.len , (NQ_BYTE*)"SMB2APP\0"    , 8  , (NQ_BYTE*)"SmbRpc\0"    , 7 , (NQ_BYTE *)pUser->applicationKey.data );
		cmKeyDerivation( pUser->macSessionKey.data, pUser->macSessionKey.len  , (NQ_BYTE*)"SMB2AESCMAC\0", 12 , (NQ_BYTE*)"SmbSign\0"   , 8 , (NQ_BYTE *)pUser->macSessionKey.data );
	}

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "");
}

static NQ_STATUS sendRequest(CCServer * pServer, CCUser * pUser, Request * pRequest, Match * pMatch, NQ_BOOL (*callback)(CMItem * pItem))
{
	NQ_UINT32 packetLen;		/* packet length of both in and out packets */
	CMBufferWriter writer;      /* to write down MID */
    Context * pContext;         /* server context */
    NQ_STATUS result = NQ_SUCCESS; /* return value */
    NQ_BYTE * encryptedBuf = NULL; /* encrypted buffer */
    NQ_COUNT creditCharge = 1;

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "server:%p user:%p request:%p match:%p", pServer, pUser, pRequest, pMatch);
	if (pServer->smbContext == NULL)
	{
		LOGERR(CM_TRC_LEVEL_ERROR, " smbContext in CCServer object is missing");
		result = NQ_ERR_NOTCONNECTED;
		goto Exit;
	}

	if (pServer->capabilities & CC_CAP_LARGEMTU)
	{
		creditCharge = pRequest->header.creditCharge;
	}

    if (!ccServerWaitForCredits(pServer, creditCharge))
    {
		result = NQ_ERR_TIMEOUT;
		goto Exit;
    }    

    cmListItemTake(&pServer->item);
    ccTransportLock(&pServer->transport);

    if (!pServer->transport.connected || !pUser->logged)
	{
    	if (!pServer->transport.connected)
    	{
			LOGERR(CM_TRC_LEVEL_ERROR, " transport isn't connected");
			result = NQ_ERR_NOTCONNECTED;
			goto Exit;
    	}
    	if (!pUser->logged && pRequest->header.command != SMB2_CMD_SESSIONSETUP)
    	{
    		LOGERR(CM_TRC_LEVEL_ERROR, "User: %s isn't logged, probably reconnect failed.", cmWDump(pUser->credentials->user));
			result = NQ_ERR_NOTCONNECTED;
			goto Error;
    	}
	}
    /* set response as not received */
    pMatch->response->wasReceived = FALSE;

    /* write down MID */
    pContext = (Context *)pServer->smbContext;
    pRequest->header.mid = pMatch->mid = pContext->mid;
    packetLen = cmBufferWriterGetDataCount(&pRequest->writer) - 4;	/* NBT header */
    cmBufferWriterInit(&writer, pRequest->buffer + SEQNUMBEROFFSET, (NQ_COUNT)packetLen);
    cmBufferWriteUint64(&writer, &pContext->mid);
 
    /* add match to list only after mid was set */
    cmListItemAdd(&pServer->expectedResponses, (CMItem *)pMatch, callback);

    /* prepare MID for next request */
    cmU64AddU32(&pContext->mid, (NQ_UINT32)(pRequest->header.creditCharge > 0 ? pRequest->header.creditCharge : 1));

	/* compose signature */
	if (!pRequest->encrypt && ccServerUseSignatures(pServer) && ccUserUseSignatures(pUser) 
        && (pRequest->header.command != SMB2_CMD_SESSIONSETUP))
	{
		cmSmb3CalculateMessageSignature(
			pUser->macSessionKey.data,
			pUser->macSessionKey.len,
			pRequest->buffer + 4,
			(NQ_UINT)packetLen,
			pRequest->tail.data,
			pRequest->tail.len,
			pRequest->header._start + SMB2_SECURITY_SIGNATURE_OFFSET
			);
	}

#ifdef UD_NQ_INCLUDESMBCAPTURE
    pServer->captureHdr.receiving = FALSE;
    cmCapturePacketWriteStart(&pServer->captureHdr , (NQ_UINT)(packetLen + pRequest->tail.len));
    cmCapturePacketWritePacket( pRequest->buffer + 4, (NQ_UINT)packetLen);
    if (pRequest->tail.len > 0)
    	cmCapturePacketWritePacket(pRequest->tail.data, pRequest->tail.len);
    cmCapturePacketWriteEnd();
#endif /* UD_NQ_INCLUDESMBCAPTURE */
    
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Request: command=%u, credit charge=%d, credits req=%d, mid=%u/%u, sid.low=0x%x, signed:%d, async:%d, pid(async.high)=0x%x, tid(async.low)=0x%x",
        pRequest->header.command, pRequest->header.creditCharge, pRequest->header.credits, pRequest->header.mid.high, pRequest->header.mid.low, pRequest->header.sid.low, (pRequest->header.flags & SMB2_FLAG_SIGNED) > 0,
        (pRequest->header.flags & SMB2_FLAG_ASYNC_COMMAND) > 0,
        pRequest->header.flags & SMB2_FLAG_ASYNC_COMMAND ? pRequest->header.aid.high : pRequest->header.pid,
        pRequest->header.flags & SMB2_FLAG_ASYNC_COMMAND ? pRequest->header.aid.low : pRequest->header.tid);

	if (pRequest->encrypt && ccUserUseSignatures(pUser) && pRequest->header.command != SMB2_CMD_SESSIONSETUP)
	{
		NQ_UINT32 msgLen = packetLen + pRequest->tail.len;

		encryptedBuf = (NQ_BYTE *)cmMemoryAllocate((NQ_UINT)(msgLen + SMB2_TRANSFORMHEADER_SIZE + 4));
		if (encryptedBuf != NULL)
		{
			CMSmb2TransformHeader	transformHeader;
			CMBufferWriter	writer;
			NQ_BYTE		*	msgPoint , * addPoint;

			syMemset(&transformHeader , 0 , SMB2_TRANSFORMHEADER_SIZE);
			transformHeader.encryptionArgorithm = SMB2_ENCRYPTION_AES128_CCM;
			transformHeader.originalMsgSize = msgLen;
			transformHeader.sid = pUser->uid;
			ccComposeEncryptionNonce(transformHeader.nonce , pMatch->mid.low);
			cmBufferWriterInit(&writer , encryptedBuf + 4 , (NQ_COUNT)(msgLen + SMB2_TRANSFORMHEADER_SIZE));
			addPoint = cmBufferWriterGetPosition(&writer);
			addPoint +=20;
			cmSmb2TransformHeaderWrite(&transformHeader , &writer);
			msgPoint = cmBufferWriterGetPosition(&writer);
			cmBufferWriteBytes(&writer , pRequest->buffer + 4  , (NQ_COUNT)packetLen);
			cmBufferWriteBytes(&writer , pRequest->tail.data , pRequest->tail.len);
			cmSmb3EncryptMessage(pUser->decryptionKey.data, transformHeader.nonce, msgPoint, (NQ_UINT)msgLen, addPoint,
				SMB2_TRANSFORMHEADER_SIZE - 20 , addPoint - 16, pUser->server->isAesGcm);

			if (!ccTransportSend(
							&pServer->transport,
							encryptedBuf,
							(NQ_COUNT)(msgLen + SMB2_TRANSFORMHEADER_SIZE),
							(NQ_COUNT)(msgLen + SMB2_TRANSFORMHEADER_SIZE)
							)
						)
			{
				result = (NQ_STATUS)syGetLastError();
				goto Error;
			}
		}
		else
		{
			sySetLastError(NQ_ERR_NOMEM);
			LOGERR(CM_TRC_LEVEL_ERROR, "Allocating memory for encrypted buffer failed.");
			result = NQ_ERR_NOMEM;
			goto Error;
		}
	}
	else
	{
#ifdef UD_NQ_INCLUDESMB311
		if (pUser->isPreauthIntegOn && pRequest->header.command == SMB2_CMD_SESSIONSETUP && pServer->smb->revision == SMB3_1_1_DIALECTREVISION)
		{
			/* calculate message hash - all messages till session setup success */
			NQ_BYTE *packetBuf;
			if (pRequest->tail.len > 0)
			{
				packetBuf = cmBufManTake((packetLen + pRequest->tail.len));
				if (packetBuf == NULL)
				{
					sySetLastError(NQ_ERR_NOMEM);
					LOGERR(CM_TRC_LEVEL_ERROR, "Allocating memory for hashing message failed.");
					result = NQ_ERR_NOMEM;
					goto Error;
				}
				syMemcpy(packetBuf, (pRequest->buffer + 4), packetLen);
				syMemcpy(packetBuf + packetLen, pRequest->tail.data, pRequest->tail.len);
				cmSmb311CalcMessagesHash(packetBuf, (packetLen + pRequest->tail.len), pUser->preauthIntegHashVal, NULL);
				cmBufManGive(packetBuf);
			}
			else
				cmSmb311CalcMessagesHash((pRequest->buffer + 4), packetLen, pUser->preauthIntegHashVal, NULL);
		}
#endif /* UD_NQ_INCLUDESMB311 */

		if (!ccTransportSend(
				&pServer->transport,
				pRequest->buffer,
				(NQ_COUNT)(packetLen + pRequest->tail.len),
				(NQ_COUNT)packetLen
				)
			)
		{
			result = (NQ_STATUS)syGetLastError();
			goto Error;
		}

		if (0 != pRequest->tail.len &&
			!ccTransportSendTail(&pServer->transport, pRequest->tail.data, pRequest->tail.len)
			)
		{
			result = (NQ_STATUS)syGetLastError();
			goto Error;
		}
	}

Error:
	ccTransportUnlock(&pServer->transport);
	cmMemoryFree(encryptedBuf);

Exit:
	cmListItemGive(&pServer->item);
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
	return result;
}

static NQ_STATUS sendReceive(CCServer * pServer, CCUser * pUser, Request * pRequest, Response * pResponse)
{
	NQ_STATUS res;				/* send result */
    CMThread * pThread;         /* current thread */
    Match * pMatch;             /* match structure pointer */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "server:%p user:%p request:%p response:%p", pServer, pUser, pRequest, pResponse);

	pResponse->buffer = NULL;
    pThread = cmThreadGetCurrent();
    if (NULL == pThread)
	{
		LOGERR(CM_TRC_LEVEL_ERROR, ">>>No thread object.");
		res = NQ_ERR_GETDATA;
		goto Exit;
	}
    pMatch = (Match *)cmThreadGetContextAsStatItem(pThread, sizeof(Match));
    if (NULL == pMatch)
    {
		LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
		res = NQ_ERR_OUTOFMEMORY;
		goto Exit;
    }
    pMatch->thread = pThread;
	pMatch->response = pResponse;
	pMatch->cond = &pThread->syncCond;
    pMatch->server = pServer;
	pMatch->userId = pUser->uid;
	pMatch->isResponseAllocated = FALSE;
	pMatch->item.locks = 0;
	pMatch->matchExtraInfo = MATCHINFO_NONE;

	cmThreadCondClear(pMatch->cond); /* Cleaning up the condition socket before sending*/

	res = pServer->smb->sendRequest(pServer, pUser, pRequest, pMatch, NULL);
	if (NQ_SUCCESS != res)
	{
		if (NULL != pMatch->thread->element.item.guard)
		{
			syMutexDelete(pMatch->thread->element.item.guard);
			cmMemoryFree(pMatch->thread->element.item.guard);
			pMatch->thread->element.item.guard = NULL;
		}
	    cmListItemRemove((CMItem *)pMatch);
		goto Exit;
	}

    if (!cmThreadCondWait(pMatch->cond, ccConfigGetTimeout()))
	{
		if ((!pServer->transport.connected || NULL == pResponse->buffer)
            && pRequest->command != SMB2_CMD_NEGOTIATE && pRequest->command != SMB2_CMD_SESSIONSETUP
           )
        {
            if (!ccServerReconnect(pServer))
            {
				res = NQ_ERR_NOTCONNECTED;
				goto Exit;
            }
        }
		else
		{
			pServer->smb->signalAllMatch(&pServer->transport);
		}
		res = NQ_ERR_TIMEOUT;
		goto Exit;
	}

    if (pServer->connectionBroke)
    {
    	if (!ccServerReconnect(pServer))
		{
			res = NQ_ERR_NOTCONNECTED;
			goto Exit;
		}

    	cmListItemTake((CMItem *) pServer);
		pServer->connectionBroke = FALSE;
		cmListItemGive((CMItem *)pServer);
		res = NQ_ERR_TIMEOUT;
		goto Exit;
    }

	/* check connection */
    if (!pServer->transport.connected)
    {
	    pServer->smb->signalAllMatch(&pServer->transport);
        if (pRequest->command != SMB2_CMD_NEGOTIATE && pRequest->command != SMB2_CMD_SESSIONSETUP)
        {
            if (ccServerReconnect(pServer))
            {
				/* simulate timeout - causing retry */
				res = NQ_ERR_TIMEOUT;
				goto Exit;
            }
        }
		res = NQ_ERR_NOTCONNECTED;
		goto Exit;
    }

    if (FALSE == pMatch->response->wasReceived)
    {
    	if (NULL != pMatch->thread->element.item.guard)
		{
			syMutexDelete(pMatch->thread->element.item.guard);
			cmMemoryFree(pMatch->thread->element.item.guard);
			pMatch->thread->element.item.guard = NULL;
		}
    	res = NQ_ERR_GETDATA;
		cmListItemRemove((CMItem *)pMatch);
		goto Exit;
    }

    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Response: command=%u, credit charge=%d, credits granted=%d, mid=%u/%u, sid.low=0x%x, status=0x%x, signed:%d, async:%d, pid(async.high)=0x%x, tid(async.low)=0x%x",
        pResponse->header.command, pResponse->header.creditCharge, pResponse->header.credits, pResponse->header.mid.high, pResponse->header.mid.low, pResponse->header.sid.low, pResponse->header.status, (pResponse->header.flags & SMB2_FLAG_SIGNED) > 0,
        (pResponse->header.flags & SMB2_FLAG_ASYNC_COMMAND) > 0,
        pResponse->header.flags & SMB2_FLAG_ASYNC_COMMAND ? pResponse->header.aid.high : pResponse->header.pid,
        pResponse->header.flags & SMB2_FLAG_ASYNC_COMMAND ? pResponse->header.aid.low : pResponse->header.tid);

#ifdef UD_NQ_INCLUDESMB311
    if (pUser->isPreauthIntegOn && pResponse->header.command == SMB2_CMD_SESSIONSETUP && pServer->smb->revision == SMB3_1_1_DIALECTREVISION)
	{
    	if ((NULL == pResponse->buffer) && (pResponse->tailLen > 0))
    	{
    		/* dialect 3.1.1 if signature fails in this stage we should fail the session setup */
			LOGERR(CM_TRC_LEVEL_ERROR, "Received empty data in response.");
			res = NQ_ERR_GETDATA;
			goto Exit;
    	}

    	if (pResponse->header.status != SMB_STATUS_SUCCESS)
		{
			NQ_BYTE *buf = cmBufManTake((NQ_COUNT)HEADERANDSTRUCT_SIZE + pResponse->tailLen);
			syMemcpy(buf, &pMatch->hdrBuf, HEADERANDSTRUCT_SIZE);

			if (pResponse->tailLen > 0)
				syMemcpy(buf + HEADERANDSTRUCT_SIZE, pResponse->buffer, pResponse->tailLen);

			cmSmb311CalcMessagesHash(buf, (NQ_COUNT)HEADERANDSTRUCT_SIZE + pResponse->tailLen, pUser->preauthIntegHashVal, NULL);
			cmBufManGive(buf);
		}
		else /* session setup success */
		{
			/* on dialect 3.1.1 and above, the last session setup (when success) should be signed and validated */
			if (!pUser->isAnonymous)
			{
				if (NULL == pUser->macSessionKey.data)
				{
					/* dialect 3.1.1 if signature fails in this stage we should fail the session setup */
					LOGERR(CM_TRC_LEVEL_ERROR, "No user signatures. Fail session setup.");
					res = NQ_ERR_SIGNATUREFAIL;
					goto Exit;
				}
				pServer->smb->keyDerivation(pUser);

				pUser->isPreauthIntegOn = FALSE; /* hashing process done. turn off hash flag */

				if (FALSE == checkMessageSignatureSMB3(pUser, pMatch->hdrBuf, (NQ_UINT)HEADERANDSTRUCT_SIZE, pResponse->buffer, pResponse->tailLen))
				{
					/* dialect 3.1.1 if signature fails in this stage we should fail the session setup */
					LOGERR(CM_TRC_LEVEL_ERROR, "Signature mismatch in session setup success packet. Fail session.");
					res = NQ_ERR_SIGNATUREFAIL;
					goto Exit;
				}
			}
		}
	}
#endif /* UD_NQ_INCLUDESMB311 */

    /* check signatures */
    if (!pRequest->encrypt && ccServerUseSignatures(pServer) && ccUserUseSignatures(pUser) 
        && (pResponse->header.flags & SMB2_FLAG_SIGNED) && (pResponse->header.command != SMB2_CMD_SESSIONSETUP))
	{
    	/* on reconnect all encryption data is erased. we have to take server and avoid calling during reconnect */
    	cmListItemTake(&pServer->item);
    	if (FALSE == checkMessageSignatureSMB3(pUser, pMatch->hdrBuf, (NQ_UINT)HEADERANDSTRUCT_SIZE, pResponse->buffer, pResponse->tailLen))
		{
    		cmListItemGive(&pServer->item);
			LOGERR(CM_TRC_LEVEL_ERROR, "Signature mismatch in incoming packet");
			res = NQ_ERR_SIGNATUREFAIL;
			goto Exit;
		}
    	cmListItemGive(&pServer->item);
	}

	res = (NQ_STATUS)ccErrorsStatusToNq(pResponse->header.status, TRUE);

	sySetLastError((NQ_UINT32)res);

Exit:
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", res);
	return res;
}

/*
 * Callback for waiting break Item dispose:
 *  - free response memory
 */
static NQ_BOOL waitingResponseItemDispose(CMItem * pItem)
{
	waitingResponse *pRespItem = (waitingResponse *)pItem;

	cmBufManGive((NQ_BYTE *)pRespItem->notifyResponse->buffer);
	cmBufManGive((NQ_BYTE *)pRespItem->notifyResponse);
    return TRUE;
}

/*
	 * Server sends notify responses == response without request. Ex: break notification
	 * If file ID for sent response isn't found. we save the response and try again on newly created files.
	 * To avoid missing a break notification that is handled while file creation on our side still in process.
	 */
static void handleWaitingNotifyResponse(void *pserver, void *pfile)
{
	CMIterator responseIterator;
	CCFile *pFile = (CCFile *) pfile;
	CCServer *pServer = (CCServer *) pserver;

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	cmListIteratorStart(&pServer->waitingNotifyResponses, &responseIterator);

	while(cmListIteratorHasNext(&responseIterator))
	{
		waitingResponse *pResponsItem;
		pResponsItem = (waitingResponse *) cmListIteratorNext(&responseIterator);
		if (0 == syMemcmp(pResponsItem->fid, pFile->fid, sizeof(pFile->fid)))
		{
			/* parse notification */
			if(NULL == commandDescriptors[pResponsItem->notifyResponse->header.command].notificationHandle)
			{
				LOGERR(CM_TRC_LEVEL_ERROR, "Wrong response saved in list, %d", pResponsItem->notifyResponse->header.command);
				cmListIteratorTerminate(&responseIterator);
				return;
			}
			LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Handling waiting response.");
			commandDescriptors[pResponsItem->notifyResponse->header.command].notificationHandle(pServer, pResponsItem->notifyResponse, pFile);
			cmListItemRemoveAndDispose((CMItem *)pResponsItem);
		}
	}
	cmListIteratorTerminate(&responseIterator);

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}


static void handleNotification(CCServer *pServer, CMSmb2Header *header, CMBlob *decryptPacket)
{
	Response* pResponse;
	NQ_BYTE * pFid;             				/* pointer to file ID in the notification */
	CCFile *pFile;
#ifdef UD_NQ_INCLUDESMBCAPTURE
	NQ_BOOL closePacketCapture = TRUE;
#endif

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	pResponse = (Response *) cmBufManTake(sizeof (Response));
	if (NULL == pResponse)
	{
		sySetLastError(NQ_ERR_NOMEM);
		LOGERR(CM_TRC_LEVEL_ERROR, "Allocating memory for waiting response failed.");
		goto Exit;
	}

	/* this is a notification == response without request */
	if (decryptPacket->data != NULL)
	{
		/* handle notification should release transport when done - for decrypted packet case. reading from transport is done already */
		ccTransportReceiveEnd(&pServer->transport);

		pResponse->tailLen = (NQ_COUNT)(decryptPacket->len - HEADERANDSTRUCT_SIZE);
		pResponse->buffer = (NQ_BYTE *)cmBufManTake(pResponse->tailLen);
		if (NULL == pResponse->buffer)
		{
			sySetLastError(NQ_ERR_NOMEM);
			LOGERR(CM_TRC_LEVEL_ERROR, "Allocating memory for waiting response failed.");
			cmMemoryFreeBlob(decryptPacket);
			goto Exit1;
		}

		syMemcpy(pResponse->buffer, decryptPacket->data + HEADERANDSTRUCT_SIZE, pResponse->tailLen);

		cmMemoryFreeBlob(decryptPacket);
	}
	else if (pServer->transport.recv.remaining > 0)
	{

		if (pServer->smbContext == NULL)
		{
			LOGERR(CM_TRC_LEVEL_ERROR, " smbContext in CCServer object is missing");
			goto Error;
		}

		pResponse->tailLen = pServer->transport.recv.remaining;
		pResponse->buffer = (NQ_BYTE *)cmBufManTake(pResponse->tailLen);
		if (NULL == pResponse->buffer)
		{
			sySetLastError(NQ_ERR_NOMEM);
			LOGERR(CM_TRC_LEVEL_ERROR, "Allocating memory for waiting response failed.");
			goto Error;
		}

		if (pResponse->tailLen != ccTransportReceiveBytes(&pServer->transport, pResponse->buffer, pResponse->tailLen))
		{
			LOGERR(CM_TRC_LEVEL_ERROR, "Transport receive error.");
			goto Error;
		}

		ccTransportReceiveEnd(&pServer->transport);
	}

#ifdef UD_NQ_INCLUDESMBCAPTURE
	cmCapturePacketWritePacket(pResponse->buffer, pResponse->tailLen);
	cmCapturePacketWriteEnd();
	closePacketCapture = FALSE;
#endif /* UD_NQ_INCLUDESMBCAPTURE */

	cmBufferReaderInit(&pResponse->reader, pResponse->buffer, pResponse->tailLen);

	pResponse->header = *header;

	/* parse notification and find fid */
	cmBufferReaderSkip(&pResponse->reader, 6);	/* oplock + reserved + reserved 2 */
	pFid = cmBufferReaderGetPosition(&pResponse->reader);

	/* init reader again to take it back to start of packet */
	cmBufferReaderInit(&pResponse->reader, pResponse->buffer, pResponse->tailLen);

	cmListItemTake((CMItem *)pServer);

	/* handle or save notification response */
	pFile = ccFileFindById(pServer, pFid);

	if (NULL == pFile)
	{
		/* save this response for later handling. relevant file create might be happening concurrently */
		waitingResponse *pWaitingResponse;

		LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "File ID not found, saving response.");
		pWaitingResponse = (waitingResponse *) cmListItemCreateAndAdd(&pServer->waitingNotifyResponses, sizeof(waitingResponse),
					NULL, waitingResponseItemDispose, CM_LISTITEM_NOLOCK);

		cmListItemGive((CMItem *)pServer);
		if (NULL == pWaitingResponse)
		{
			sySetLastError(NQ_ERR_NOMEM);
			LOGERR(CM_TRC_LEVEL_ERROR, "Allocating memory for waiting response failed.");
			goto Exit1;
		}

		pWaitingResponse->notifyResponse = pResponse;
		syMemcpy(pWaitingResponse->fid, pFid, sizeof(pWaitingResponse->fid));

		goto Exit;
	}

	cmListItemGive((CMItem *)pServer);
	/* file found - handle notification message */
	commandDescriptors[header->command].notificationHandle(pServer, pResponse, pFile);

	goto Exit1;

Error:
	ccTransportReceiveEnd(&pServer->transport);

Exit1:
#ifdef UD_NQ_INCLUDESMBCAPTURE
	if (closePacketCapture)
		cmCapturePacketWriteEnd();
#endif /* UD_NQ_INCLUDESMBCAPTURE */

	if (NULL != pResponse->buffer)
		cmBufManGive((NQ_BYTE *)pResponse->buffer);
	cmBufManGive((NQ_BYTE *)pResponse);

Exit:

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

static void anyResponseCallback(void * transport)
{
	CCTransport * 	pTransport = (CCTransport *)transport; 	/* casted to transport entry */
	CCServer * 		pServer;						/* casted pointer */
	CMIterator 		iterator;						/* iterates through expected responses */
	CMSmb2Header 	header;							/* response header */
	CMBufferReader 	reader;							/* to parse header */
	NQ_COUNT 		res;							/* bytes read */
	NQ_BYTE 		buffer[HEADERANDSTRUCT_SIZE];	/* header + structure size */
	CMBlob          decryptPacket = {NULL, 0};
    NQ_BYTE*        tHdr = NULL;


	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "transport:%p", transport);

	decryptPacket.data = NULL;
	decryptPacket.len = 0;
	pServer = (CCServer *)pTransport->context;
	
    if (!pTransport->connected) /* proceed disconnect */
    {
    	LOGERR(CM_TRC_LEVEL_ERROR, "Connection broken with %s", cmWDump(pServer->item.name));

        /* match with request */
    	cmListItemTake((CMItem *)pServer);
    	cmListIteratorStart(&pServer->expectedResponses, &iterator);
	    while (cmListIteratorHasNext(&iterator))
	    {
		    Match * pMatch;
    		
		    pMatch = (Match *)cmListIteratorNext(&iterator);
		    if (pMatch->cond != NULL)
		    	cmThreadCondSignal(pMatch->cond);
		    if (pMatch->isResponseAllocated)
		    {
		    	cmMemoryFree(pMatch->response);
		    	pMatch->response = NULL;
		    }
	    }
	    cmListIteratorTerminate(&iterator);
	    if (NULL != pTransport->cleanupCallback)
	    	(*pTransport->cleanupCallback)(pTransport->cleanupContext);
	    cmListItemGive((CMItem *)pServer);

    	LOGERR(CM_TRC_LEVEL_ERROR, "Response not matched. server: %s", cmWDump(pServer->item.name));
        goto Exit;
    }

    /* read & parse SMB signature */
	res = ccTransportReceiveBytes(pTransport, buffer, 4);
	if ((NQ_COUNT)NQ_FAIL == res)
	{
        goto Error;
	}
    if (0 == syMemcmp(buffer, cmSmb2TrnsfrmHdrProtocolId, sizeof(cmSmb2TrnsfrmHdrProtocolId)))
    {	
    	CMSmb2TransformHeader	transHeader;
		CMIterator				userItr;
		CCUser			*		pUser = NULL;
		CMList					fakeUserList;
	   
		tHdr = (NQ_BYTE *)cmMemoryAllocate(SMB2_TRANSFORMHEADER_SIZE);
		if (NULL == tHdr)
		{
			goto Error;
		}

		syMemcpy(tHdr ,cmSmb2TrnsfrmHdrProtocolId , 4 );
		res = ccTransportReceiveBytes(pTransport, tHdr+4, SMB2_TRANSFORMHEADER_SIZE - 4);
		if ((NQ_COUNT)NQ_FAIL == res)
		{
			goto Error;
		}

		cmBufferReaderInit(&reader , tHdr ,SMB2_TRANSFORMHEADER_SIZE);
		cmSmb2TransformHeaderRead(&transHeader, &reader);
		/* Create Fake List with the same values as pServer->users to avoid deadlock (mutex is different)*/
		fakeUserList.first = pServer->users.first;
		fakeUserList.last = pServer->users.last;
		fakeUserList.isUsed = TRUE;
		syMutexCreate(&fakeUserList.guard);
		cmListIteratorStart(&fakeUserList,&userItr);
		while (cmListIteratorHasNext(&userItr) && pUser == NULL)
		{
			CCUser * pTemp = (CCUser *)cmListIteratorNext(&userItr);

			if (cmU64Cmp(&transHeader.sid,&pTemp->uid) == 0)
			{
				pUser = pTemp;
				break;
			}
		}
		cmListIteratorTerminate(&userItr);
		syMutexDelete(&fakeUserList.guard);
		if (pUser == NULL)
		{
			goto Error;
		}
		/* decrypt packet here*/ 
		decryptPacket.data = (NQ_BYTE *)cmMemoryAllocate((NQ_UINT)transHeader.originalMsgSize);
		decryptPacket.len = (NQ_COUNT)transHeader.originalMsgSize;
		res = ccTransportReceiveBytes(pTransport, decryptPacket.data , (NQ_COUNT)transHeader.originalMsgSize);
		if ((NQ_COUNT)NQ_FAIL == res)
		{
			goto Error;
		}
		
		if (FALSE == cmSmb3DecryptMessage(pUser->encryptionKey.data,
									transHeader.nonce,
									decryptPacket.data,
									decryptPacket.len,
									tHdr + 20,
									(NQ_COUNT)(SMB2_TRANSFORMHEADER_SIZE - 20),
									transHeader.signature,
									pUser->server->isAesGcm
									))
		{
			goto Error;
		}
		cmMemoryFree(tHdr);
		tHdr = NULL;
		syMemcpy(buffer , decryptPacket.data , sizeof(buffer));
	}
	else
	{
		res = ccTransportReceiveBytes(pTransport, &buffer[4], sizeof(buffer) - 4);
		if ((NQ_COUNT)NQ_FAIL == res)
		{
			goto Error;
		}
	}

#ifdef UD_NQ_INCLUDESMBCAPTURE
	pServer->captureHdr.receiving = TRUE;
	cmCapturePacketWriteStart(&pServer->captureHdr , (NQ_UINT)(decryptPacket.data != NULL ? decryptPacket.len : HEADERANDSTRUCT_SIZE + pServer->transport.recv.remaining));
	cmCapturePacketWritePacket( buffer, HEADERANDSTRUCT_SIZE);
#endif /* UD_NQ_INCLUDESMBCAPTURE */
	cmBufferReaderInit(&reader, buffer, res); /* starting from SMB header */
	cmSmb2HeaderRead(&header, &reader);

	/* match with request */
	cmListIteratorStart(&pServer->expectedResponses, &iterator);
	while (cmListIteratorHasNext(&iterator))
	{
		Match * pMatch;
		
		pMatch = (Match *)cmListIteratorNext(&iterator);
		if (pMatch->server == pServer && 0 == cmU64Cmp(&pMatch->mid, &header.mid)) 
		{
			NQ_UINT16 length;			/* structure length */
			
			cmListIteratorTerminate(&iterator);
			pMatch->response->header = header; /* header start address will be wrong */
			cmBufferReadUint16(&reader, &length); /* structure size */
			if (SMB_STATUS_SUCCESS == header.status && length != commandDescriptors[header.command].responseStructSize)
			{
				LOGERR( CM_TRC_LEVEL_ERROR, 
						"Unexpected structure length in response: %d, expected %d command %d",
						length,
						commandDescriptors[header.command].responseStructSize,
						header.command
						);
				pMatch->response->header.status = SMB_STATUS_INVALID;
			}
			/* check for interim response */
			if ((header.flags & SMB2_FLAG_ASYNC_COMMAND) && (header.status == SMB_STATUS_PENDING))
			{
#ifdef UD_NQ_INCLUDESMBCAPTURE
				NQ_BYTE * tempBuf;
				NQ_COUNT len = 0;

				if (decryptPacket.data != NULL)
				{
					len = (NQ_COUNT)(decryptPacket.len - HEADERANDSTRUCT_SIZE);
					tempBuf = (NQ_BYTE *)cmMemoryAllocate(len);
					if (NULL == tempBuf)
					{
					    LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
					    goto Error;
					}
					syMemcpy(tempBuf , decryptPacket.data + HEADERANDSTRUCT_SIZE , len);
				}
				else
				{
					len = pServer->transport.recv.remaining;
					tempBuf = (NQ_BYTE *)cmMemoryAllocate(len);
					if (NULL == tempBuf)
					{
					    LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
					    goto Error;
					}
					ccTransportReceiveBytes(&pServer->transport, tempBuf, len);
				}
				cmCapturePacketWritePacket(tempBuf , len);
				cmCapturePacketWriteEnd();
				cmMemoryFree(tempBuf);
#endif /* UD_NQ_INCLUDESMBCAPTURE */
				ccTransportReceiveEnd(pTransport);
				if (header.command == SMB2_CMD_WRITE || header.command == SMB2_CMD_READ)
				{
					WriteMatch	*	wMatch = NULL;
					void 		**	tmp = NULL;
					NQ_BOOL		*	isPending = NULL;

					wMatch = (WriteMatch *)pMatch;

					tmp = (void **)((CMItem *)wMatch->context + 1);
					isPending = (NQ_BOOL *)*tmp;

					*isPending = TRUE;

					/* when pending response received the timeout is extended. */
					wMatch->setTimeout = wMatch->setTimeout + (wMatch->setTimeout * PENDING_TIMEOUT_EXTENTION);
				}
				ccTransportDiscardReceive(pTransport);
			}
			else
			{
				if (NULL != pMatch->thread->element.item.guard)
				{
					syMutexDelete(pMatch->thread->element.item.guard);
					cmMemoryFree(pMatch->thread->element.item.guard);
					pMatch->thread->element.item.guard = NULL;
				}
				cmListItemRemove((CMItem *)pMatch);
				if (pServer->useSigning)
					syMemcpy(pMatch->hdrBuf, buffer, HEADERANDSTRUCT_SIZE);
                pMatch->thread->status = header.status;
                if (NULL != commandDescriptors[header.command].callback)
				{
                    Response * pResponse = pMatch->response;  /* associated response */

                	if (decryptPacket.data != NULL)
					{
                		pResponse->tailLen = (NQ_COUNT)(decryptPacket.len - HEADERANDSTRUCT_SIZE);
                		pResponse->buffer = cmBufManTake(pResponse->tailLen);
						if (NULL == pResponse->buffer)
						{
						    LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
						    goto ErrorAndCredits;
						}
						syMemcpy(pResponse->buffer , decryptPacket.data + HEADERANDSTRUCT_SIZE , pResponse->tailLen);
					}
					else
                    {
						pResponse->tailLen = pServer->transport.recv.remaining;
                        pResponse->buffer = NULL;
                    }

                	pMatch->response->wasReceived = TRUE;
                	commandDescriptors[header.command].callback(pServer, pMatch);
				}
				else
				{	
					if (decryptPacket.data != NULL)
					{
						/* this packet was encrypted */
						Response * pResponse = pMatch->response;  /* associated response */

						pResponse->tailLen = (NQ_COUNT)(decryptPacket.len - HEADERANDSTRUCT_SIZE);
						pResponse->buffer = cmBufManTake(pResponse->tailLen);
						if (NULL != pResponse->buffer)
			    		{
							syMemcpy(pResponse->buffer , decryptPacket.data + HEADERANDSTRUCT_SIZE , pResponse->tailLen);
#ifdef UD_NQ_INCLUDESMBCAPTURE
							cmCapturePacketWritePacket( pResponse->buffer, pResponse->tailLen);
#endif /* UD_NQ_INCLUDESMBCAPTURE */
							cmBufferReaderInit(&pResponse->reader, pResponse->buffer, pResponse->tailLen);
							pResponse->header._start = 	/* set virtual header start */
									pResponse->buffer -
									HEADERANDSTRUCT_SIZE;	/* shift back on header size and more structure size */
			    		}
					}
					else if (pServer->transport.recv.remaining > 0 )
	                {
						Response * pResponse = pMatch->response;  /* associated response */
						NQ_COUNT receivedBytes;

						pResponse->tailLen = pServer->transport.recv.remaining;
						pResponse->buffer = cmBufManTake(pResponse->tailLen);
						if (NULL != pResponse->buffer)
						{
							if (pResponse->tailLen == (receivedBytes = ccTransportReceiveBytes(&pServer->transport, pResponse->buffer, pResponse->tailLen)))
							{
#ifdef UD_NQ_INCLUDESMBCAPTURE
								cmCapturePacketWritePacket( pResponse->buffer, pResponse->tailLen);
#endif /* UD_NQ_INCLUDESMBCAPTURE */
								cmBufferReaderInit(&pResponse->reader, pResponse->buffer, pResponse->tailLen);
								pResponse->header._start = 	/* set virtual header start */
									pResponse->buffer -
									HEADERANDSTRUCT_SIZE;	/* shift back on header size and more structure size */
#ifdef UD_NQ_INCLUDESMB311
								/* Message header is required for hash calculation - all messages till session setup success */
								if (pServer->smb->revision == SMB3_1_1_DIALECTREVISION && header.command == SMB2_CMD_SESSIONSETUP)
								{
									syMemcpy(pMatch->hdrBuf, &buffer, HEADERANDSTRUCT_SIZE);
								}
#endif
							}
							else
							{
								LOGERR(CM_TRC_LEVEL_ERROR, ">>>Number of network recieved bytes: %d not as expected: %d.", receivedBytes, pResponse->tailLen);
								goto ErrorAndCredits;
							}
						}
						else
						{
						    LOGERR(CM_TRC_LEVEL_ERROR, ">>>Out of memory");
						    goto ErrorAndCredits;
						}
					}
					else
					{
						pMatch->response->tailLen = 0;
					}
#ifdef UD_NQ_INCLUDESMBCAPTURE
					cmCapturePacketWriteEnd();
#endif /* UD_NQ_INCLUDESMBCAPTURE */
	                ccTransportReceiveEnd(&pServer->transport);
	                pMatch->response->wasReceived = TRUE;
					cmThreadCondSignal(pMatch->cond);
				}
			}
            if (header.credits > 0)
                ccServerPostCredits(pServer, header.credits);
			goto Exit;
		} /*if (pMatch->server == pServer && 0 == cmU64Cmp(&pMatch->mid, &header.mid))*/
	}
	cmListIteratorTerminate(&iterator);
    if (NULL != commandDescriptors[header.command].notificationHandle)
    {
    	handleNotification(pServer, &header, &decryptPacket);
    	goto Exit;
    }
    else
    {
#ifdef UD_NQ_INCLUDESMBCAPTURE
		cmCapturePacketWriteEnd();
#endif /* UD_NQ_INCLUDESMBCAPTURE */
		LOGERR(CM_TRC_LEVEL_ERROR, "Response not matched. Mid: %d:%d server: %s", header.mid.high, header.mid.low, cmWDump(pServer->item.name));
    }
ErrorAndCredits:
	/* for some reason the match wasn't found. or some other error occurred. still update credits. */
	if (header.credits > 0)
	{
		ccServerPostCredits(pServer, header.credits);
	}
Error:
	ccTransportReceiveEnd(&pServer->transport);
#ifdef UD_NQ_INCLUDESMBCAPTURE
	cmCapturePacketWriteEnd();
#endif /* UD_NQ_INCLUDESMBCAPTURE */

Exit:
	cmMemoryFree(tHdr);
	cmMemoryFreeBlob(&decryptPacket);
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}


static void writeCallback(CCServer * pServer, Match * pContext)
{
	WriteMatch * pMatch = (WriteMatch *)pContext;	/* casted pointer */
	NQ_BYTE buffer[20];								/* buffer for structure */
	NQ_UINT tailLen = pServer->transport.recv.remaining;	/* bytes remaining */
	Response * pResponse = pContext->response;				/* response structure pointer */
	NQ_UINT32 count = 0;     								/* bytes written */
    NQ_UINT32     currentTime;                    /* Current Time for checking timed-out responses*/

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "server:%p context:%p", pServer, pContext);

	/* receive the rest of command */
	if (pResponse->buffer != NULL)
	{
		syMemcpy(&buffer , pResponse->buffer , pResponse->tailLen > 20 ? 20 : pResponse->tailLen );
		cmBufManGive(pResponse->buffer);
#ifdef UD_NQ_INCLUDESMBCAPTURE
		count = 1;
#endif /* UD_NQ_INCLUDESMBCAPTURE */
	}
	else if ( tailLen != ccTransportReceiveBytes(&pServer->transport, buffer, tailLen))
	{
    	ccTransportReceiveEnd(&pServer->transport);
		goto Exit;
	}
    ccTransportReceiveEnd(&pServer->transport);
#ifdef UD_NQ_INCLUDESMBCAPTURE
    cmCapturePacketWritePacket( buffer, (NQ_UINT)(count == 1 ? pResponse->tailLen : tailLen));
	cmCapturePacketWriteEnd();
#endif /* UD_NQ_INCLUDESMBCAPTURE */
	cmBufferReaderInit(&pResponse->reader, buffer, tailLen);

	/* parse the response */
	if (SMB_STATUS_SUCCESS == pResponse->header.status)
	{
		cmBufferReaderSkip(&pResponse->reader, sizeof(NQ_UINT16));	/* reserved */
		cmBufferReadUint32(&pResponse->reader, &count);	/* count */
	}
    currentTime = (NQ_UINT32)syGetTimeInSec();

    /* call up */
	if ((pMatch->timeCreated + pMatch->setTimeout) > currentTime)
    {
	    pMatch->callback(pResponse->header.status == 0 ? 0 : (NQ_STATUS)ccErrorsStatusToNq(pResponse->header.status, TRUE), (NQ_UINT)count, pMatch->context);
    }
	/* release context */
	if (NULL != pMatch->match.thread->element.item.guard)
	{
		syMutexDelete(pMatch->match.thread->element.item.guard);
		cmMemoryFree(pMatch->match.thread->element.item.guard);
		pMatch->match.thread->element.item.guard = NULL;
	}
	cmMemoryFree(pMatch->match.response);
    cmListItemDispose((CMItem *)pMatch);

Exit:
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

static void readCallback(CCServer * pServer, Match * pContext)
{
#define READSTRUCT_SIZE 14
	ReadMatch * pMatch = (ReadMatch *)pContext;		/* casted pointer */
	NQ_BYTE buffer[64];								/* buffer for structure and padding */
	Response * pResponse = pContext->response;		/* response structure pointer */
	NQ_UINT32 count = 0;							/* bytes read */
	NQ_BYTE offset;									/* data offset */
    NQ_UINT32 currentTime;                    	/* Current Time for checking timed-out responses*/

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "server:%p context:%p", pServer, pContext);

	/* receive the structure but not the buffer (payload) */
	if (pResponse->buffer != 0)
	{
		if (pResponse->tailLen < READSTRUCT_SIZE )
		{
#ifdef UD_NQ_INCLUDESMBCAPTURE
			cmCapturePacketWritePacket( buffer, pResponse->tailLen);
#endif /* UD_NQ_INCLUDESMBCAPTURE */
			count = 0;
		}
		else
		{
			syMemcpy(&buffer , pResponse->buffer ,READSTRUCT_SIZE );
#ifdef UD_NQ_INCLUDESMBCAPTURE
			cmCapturePacketWritePacket( buffer,READSTRUCT_SIZE );
#endif /* UD_NQ_INCLUDESMBCAPTURE */
			cmBufferReaderInit(&pResponse->reader, buffer, sizeof(buffer));
			cmBufferReadByte(&pResponse->reader, &offset);				/* data offset */
			cmBufferReaderSkip(&pResponse->reader, sizeof(NQ_BYTE));	/* reserved */
			cmBufferReadUint32(&pResponse->reader, &count);	/* data length */
			syMemcpy(pMatch->buffer , pResponse->buffer + READSTRUCT_SIZE + (offset - (SMB2_HEADERSIZE + 16)), count );
#ifdef UD_NQ_INCLUDESMBCAPTURE
			cmCapturePacketWritePacket( pMatch->buffer, (NQ_UINT)count);
#endif /* UD_NQ_INCLUDESMBCAPTURE */
		}
		cmBufManGive(pResponse->buffer);
	}
	else if (pResponse->tailLen < READSTRUCT_SIZE)
	{
#ifdef UD_NQ_INCLUDESMBCAPTURE
		NQ_COUNT res =
#endif /* UD_NQ_INCLUDESMBCAPTURE */
		ccTransportReceiveBytes(&pServer->transport, buffer, pResponse->tailLen );
#ifdef UD_NQ_INCLUDESMBCAPTURE
		if (res > 0)
		{
			cmCapturePacketWritePacket(buffer,res );
		}
#endif /* UD_NQ_INCLUDESMBCAPTURE */
		count = 0;
	}
	else if (READSTRUCT_SIZE == ccTransportReceiveBytes(&pServer->transport, buffer, READSTRUCT_SIZE))
	{
#ifdef UD_NQ_INCLUDESMBCAPTURE
		cmCapturePacketWritePacket( buffer,READSTRUCT_SIZE );
#endif /* UD_NQ_INCLUDESMBCAPTURE */
		/* parse the response */
		cmBufferReaderInit(&pResponse->reader, buffer, sizeof(buffer));
		if (SMB_STATUS_SUCCESS == pResponse->header.status)
		{
			cmBufferReadByte(&pResponse->reader, &offset);				/* data offset */
			cmBufferReaderSkip(&pResponse->reader, sizeof(NQ_BYTE));	/* reserved */
			cmBufferReadUint32(&pResponse->reader, &count);	/* data length */
		    offset = (NQ_BYTE)(offset - (SMB2_HEADERSIZE + 16));	/* bytes to skip */
		    if (offset > 0 )
		    {
			    ccTransportReceiveBytes(&pServer->transport, buffer, (NQ_COUNT)offset);	/* read padding */
#ifdef UD_NQ_INCLUDESMBCAPTURE
				cmCapturePacketWritePacket(buffer,offset );
#endif /* UD_NQ_INCLUDESMBCAPTURE */
		    }
		    ccTransportReceiveBytes(&pServer->transport, pMatch->buffer, (NQ_COUNT)count);	/* read into application buffer */
#ifdef UD_NQ_INCLUDESMBCAPTURE
		    cmCapturePacketWritePacket(pMatch->buffer, (NQ_UINT)count);
#endif /* UD_NQ_INCLUDESMBCAPTURE */
		}
	}
	else
	{
		count = 0;
	}
    ccTransportReceiveEnd(&pServer->transport);
#ifdef UD_NQ_INCLUDESMBCAPTURE
	cmCapturePacketWriteEnd();
#endif /* UD_NQ_INCLUDESMBCAPTURE */

	currentTime = (NQ_UINT32)syGetTimeInSec();

    /* call up */
	if ((pMatch->timeCreated + pMatch->setTimeout) > currentTime)
    {
        pMatch->callback(pResponse->header.status == SMB_STATUS_SUCCESS ? 0 : (NQ_STATUS)ccErrorsStatusToNq(pResponse->header.status, TRUE), (NQ_UINT)count, pMatch->context, count < pMatch->count);
    }
	else
	{
		/* response timed out */
		LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Read response arrived after timeout. Mid:%d Expected:%d arrived:%d. Will not be handled.",
				pMatch->match.mid, (pMatch->timeCreated + pMatch->setTimeout), currentTime);
	}

	/* release */
	if (NULL != pMatch->match.thread->element.item.guard)
	{
		syMutexDelete(pMatch->match.thread->element.item.guard);
		cmMemoryFree(pMatch->match.thread->element.item.guard);
		pMatch->match.thread->element.item.guard = NULL;
	}
	cmMemoryFree(pMatch->match.response);
    cmListItemDispose((CMItem *)pMatch);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

static void handleBreakNotification(CCServer * pServer, Response * notifyResponse, CCFile *pFile)
{
	Request request;		    /* request descriptor */
	NQ_COUNT packetLen;		    /* packet length of both in and out packets */
    NQ_BYTE oplockLevel;        /* new oplock level */
    CCUser * pUser;             /* user pointer */
    CCShare * pShare;           /* share pointer */
    Context * pContext;         /* SMB context */
    NQ_UINT64   negMid = {0xffffffff , 0xffffffff}; /* -1 mid */
	NQ_BYTE * encryptedBuf = NULL;

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "server:%p response:%p", pServer, notifyResponse);


    /* parse notification */
    cmBufferReadByte(&notifyResponse->reader, &oplockLevel);	/* oplock */

    if ((0 == oplockLevel && pFile->grantedOplock == SMB2_OPLOCK_LEVEL_II)|| cmU64Cmp(&notifyResponse->header.mid ,&negMid )!= 0)
    {
    	/* don't have to reply - only update oplock */
    	pFile->grantedOplock = oplockLevel;
        goto Exit2;
    }

    pFile->grantedOplock = oplockLevel;
    if (pFile->durableState == DURABLE_GRANTED)
	{
		pFile->durableState = DURABLE_CANCELED;
		pFile->durableFlags = 0;
		cmGenerateUuid(&pFile->durableHandle); /* New Handle*/
	}

    pShare = pFile->share;
    pUser = pShare->user;
    request.buffer = NULL;

    /* compose ack */
	if (!ccSmb20PrepareSingleRequestByShare(&request, pShare, SMB2_CMD_OPLOCKBREAK, 0))
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "ccSmb20PrepareSingleRequestByShare() failed");
        goto Exit;
	}

	cmSmb2HeaderWrite(&request.header, &request.writer);
	cmBufferWriteUint16(&request.writer, commandDescriptors[request.command].requestStructSize);
	cmBufferWriteByte(&request.writer, oplockLevel);        /* oplock */
	cmBufferWriteZeroes(&request.writer, 5);	            /* reserved + reserved 2 */
	cmBufferWriteBytes(&request.writer, pFile->fid, sizeof(pFile->fid));/* file id */
	packetLen = cmBufferWriterGetDataCount(&request.writer) - 4;	/* NBT header */

    /* write down MID */
    pContext = (Context *)pServer->smbContext;
    request.header.mid = pContext->mid;
    cmBufferWriterSetPosition(&request.writer, request.buffer + SEQNUMBEROFFSET);
    cmBufferWriteUint64(&request.writer, &pContext->mid);

    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Request: command=%u, credit charge=%d, credits req=%d, mid=%u/%u, sid.low=0x%x, signed:%d, async:%d, pid(async.high)=0x%x, tid(async.low)=0x%x",
        request.header.command, request.header.creditCharge, request.header.credits, request.header.mid.high, request.header.mid.low, request.header.sid.low, (request.header.flags & SMB2_FLAG_SIGNED) > 0,
        (request.header.flags & SMB2_FLAG_ASYNC_COMMAND) > 0,
        request.header.flags & SMB2_FLAG_ASYNC_COMMAND ? request.header.aid.high : request.header.pid,
        request.header.flags & SMB2_FLAG_ASYNC_COMMAND ? request.header.aid.low : request.header.tid);

    /* prepare MID for next request */
    cmU64Inc(&pContext->mid);

	/* compose signature */
	if (!request.encrypt && ccServerUseSignatures(pServer) && ccUserUseSignatures(pUser))
	{
		cmSmb3CalculateMessageSignature(
			pUser->macSessionKey.data,
			pUser->macSessionKey.len,
			request.buffer + 4,
			packetLen,
			NULL,
			0,
			request.header._start + SMB2_SECURITY_SIGNATURE_OFFSET
			);
	}

#ifdef UD_NQ_INCLUDESMBCAPTURE
    pServer->captureHdr.receiving = FALSE;
    cmCapturePacketWriteStart(&pServer->captureHdr , packetLen);
    cmCapturePacketWritePacket( request.buffer + 4, packetLen);
    cmCapturePacketWriteEnd();
#endif /* UD_NQ_INCLUDESMBCAPTURE */
    ccTransportLock(&pServer->transport);
    if (request.encrypt )
	{
		encryptedBuf = (NQ_BYTE *)cmMemoryAllocate(packetLen + SMB2_TRANSFORMHEADER_SIZE + 4);
		if (encryptedBuf != NULL)
		{
			CMSmb2TransformHeader	transformHeader;
			CMBufferWriter	writer;
			NQ_BYTE		*	msgPoint , * addPoint;

			syMemset(&transformHeader , 0 , SMB2_TRANSFORMHEADER_SIZE);
			transformHeader.encryptionArgorithm = SMB2_ENCRYPTION_AES128_CCM;
			transformHeader.originalMsgSize = packetLen;
			transformHeader.sid = pUser->uid;
			ccComposeEncryptionNonce(transformHeader.nonce , request.header.mid.low);
			cmBufferWriterInit(&writer , encryptedBuf + 4 , packetLen + SMB2_TRANSFORMHEADER_SIZE);
			addPoint = cmBufferWriterGetPosition(&writer);
			addPoint +=20;
			cmSmb2TransformHeaderWrite(&transformHeader , &writer);
			msgPoint = cmBufferWriterGetPosition(&writer);
			cmBufferWriteBytes(&writer , request.buffer + 4  , packetLen);
			cmSmb3EncryptMessage(pUser->decryptionKey.data , transformHeader.nonce , msgPoint , packetLen, addPoint ,
				SMB2_TRANSFORMHEADER_SIZE - 20 , addPoint - 16, pUser->server->isAesGcm);

			if (!ccTransportSendSync(
							&pServer->transport,
							encryptedBuf,
							packetLen + SMB2_TRANSFORMHEADER_SIZE,
							packetLen + SMB2_TRANSFORMHEADER_SIZE
							)
						)
			{
				LOGERR(CM_TRC_LEVEL_ERROR, "ccSmb20PrepareSingleRequestByShare() failed");
		        goto Error;
			}
		}
	}
    else
    {
    /* send and receive. [DAVIDS NOTE: Function doesn't actually receive] Since we running inside the receiving thread - this is done inlined */

		if (!ccTransportSendSync(
				&pServer->transport,
				request.buffer,
				packetLen,
				packetLen
				)
			)
		{
			goto Error;
		}
    }

Error:
    ccTransportUnlock(&pServer->transport);
Exit:
	cmBufManGive(request.buffer);
	cmMemoryFree(encryptedBuf);
Exit2:
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return;
}

static NQ_BOOL validateNegotiate(void *pServ, void *_pUser, void* _pShareIPC)
{
	Request request;		/* request descriptor */
	Response response;		/* response descriptor */
	NQ_STATUS res = NQ_FAIL;			/* exchange result */
	NQ_BYTE * pInputOffset;		/* pointer to the input offset field in the request */
	NQ_UINT32 offset, temp32Uint;		/* offset relative to the header */
	NQ_UINT16 temp16Uint;
	NQ_BYTE * pTemp;		/* pointer in the buffer */
	CCShare   *pShare = (CCShare *)_pShareIPC;
	CCServer *pServer = (CCServer *)pServ;
	CCUser *pUser = (CCUser *)_pUser;
	const AMCredentialsW * pCredentials = pUser->credentials;
	NQ_UINT16 actualDialects = 0;
	NQ_COUNT i;
	NQ_BOOL result = FALSE;
	NQ_BYTE serverGUID[16];
	NQ_UINT32 capabilities = 0;

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "pServer: %p pUser: %p", pServer, pUser);

	if (!ccUserUseSignatures(pUser))
	{
		/* if we can't sign a packet with this user, we don't perform negotiation validation */
		result = TRUE;
		goto Exit2;
	}

	request.buffer = NULL;
	response.buffer = NULL;

	if (NULL == _pShareIPC)
	{
		pShare = ccShareConnectIpc(pServer, &pCredentials);
		if (NULL == pShare)
		{
			goto Exit2;
		}
	}

	/* the share connect IPC should have performed the negotiate validate. so recheck it here. */
	if (TRUE == pServer->isNegotiationValidated)
	{
		return TRUE;
	}

	if (!ccSmb20PrepareSingleRequestByShare(&request, pShare, SMB2_CMD_IOCTL, 0))
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
		res = NQ_ERR_OUTOFMEMORY;
		goto Exit;
	}

	/* compose request - start with header*/
	cmSmb2HeaderWrite(&request.header, &request.writer);
	cmBufferWriteUint16(&request.writer, 0x39);							/* ioctl structure size*/

	/* ioctl header */
	cmBufferWriteUint16(&request.writer, 0x0);							/* reserved */
	cmBufferWriteUint32(&request.writer, SMB_IOCTL_VALIDATE_NEGOTIATE);	/* CtlCode: FSCTL_VALIDATE_NEGOTIATE_INFO */
	cmBufferWriteUint32(&request.writer, 0xFFFFFFFF);					/* set special file ID */
	cmBufferWriteUint32(&request.writer, 0xFFFFFFFF);					/* file ID */
	cmBufferWriteUint32(&request.writer, 0xFFFFFFFF);					/* file ID */
	cmBufferWriteUint32(&request.writer, 0xFFFFFFFF);					/* file ID */
	pInputOffset = cmBufferWriterGetPosition(&request.writer);
	cmBufferWriterSkip(&request.writer, sizeof(NQ_UINT32) * 3);			/* InputOffset/Count + MaxInputResponse */
	cmBufferWriteUint32(&request.writer, 0);							/* Output offset */
	cmBufferWriteUint32(&request.writer, 0);							/* Output count */
	cmBufferWriteUint32(&request.writer, 24);							/* Max Output Response */
	cmBufferWriteUint32(&request.writer, SMB2_0_IOCTL_IS_FSCTL);		/* flags: FSCTL */
	cmBufferWriteUint32(&request.writer, 0);							/* reserved */

	/* end of IOCTL header - start of IOCTL payload */
	offset = cmSmb2HeaderGetWriterOffset(&request.header, &request.writer);
#ifdef UD_NQ_INCLUDESMB3
    capabilities |= (SMB2_CAPABILITY_ENCRYPTION | SMB2_CAPABILITY_LARGE_MTU);
#endif /* UD_NQ_INCLUDESMB3 */
	cmBufferWriteUint32(&request.writer, capabilities);					/* client capabilities */
	cmBufferWriteUint32(&request.writer, pServer->clientGuidPartial);	/* client GUID */
	cmBufferWriteUint32(&request.writer, 0);							/* client GUID */
	cmBufferWriteUint32(&request.writer, 0);							/* client GUID */
	cmBufferWriteUint32(&request.writer, 0);							/* client GUID */
	cmBufferWriteUint16(&request.writer, nqGetMessageSigning()? 1: 0);	/* security mode */
	for (i = 0; i < sizeof(pServer->clientDialectRevision) / sizeof(pServer->clientDialectRevision[0]); i++)
	{
		if (pServer->clientDialectRevision[i] != CCCIFS_ILLEGALSMBREVISION)
			actualDialects++;
	}
	cmBufferWriteUint16(&request.writer, actualDialects);				/* number of dialects */

	for (i = 0; i < sizeof(pServer->clientDialectRevision) / sizeof(pServer->clientDialectRevision[0]); i++)
	{
		if (pServer->clientDialectRevision[i] != CCCIFS_ILLEGALSMBREVISION)
			cmBufferWriteUint16(&request.writer, pServer->clientDialectRevision[i]); 	/* write actual dialects */
	}

	/* set input fields in ioctl header  */
	pTemp = cmBufferWriterGetPosition(&request.writer);
	cmBufferWriterSetPosition(&request.writer, pInputOffset);
	cmBufferWriteUint32(&request.writer, offset);				/* Input Offset in bytes*/
	/* input count = 4 (capabilities) + 16 (client GUID) + 2 (security mode) + 2 (num dialects) + 2 * numDialects (dialects themselves) */
	cmBufferWriteUint32(&request.writer, (4 + 16 + 2 + 2 + (NQ_UINT32)(2 * actualDialects)));	/* InputCount */
	cmBufferWriteUint32(&request.writer, 0);					/* MaxInputResponse */
	cmBufferWriterSetPosition(&request.writer, pTemp);

	/* make sure this packet will be singed */
	{
		NQ_BOOL useSigning = pServer->useSigning;
		NQ_UINT32 capab = pServer->capabilities;
		cmListItemTake((CMItem *)pServer);
		pServer->useSigning = TRUE;
		pServer->capabilities &= CC_CAP_MESSAGESIGNING;

		res = pServer->smb->sendReceive(pServer, pUser, &request, &response);

		pServer->useSigning = useSigning;
		pServer->capabilities = capab;
		cmListItemGive((CMItem *)pServer);
	}

	if (res == SMB_STATUS_NOT_SUPPORTED || res == SMB_STATUS_INVALID_PARAMETER)
	{
		LOGERR(CM_TRC_LEVEL_FUNC_COMMON," validation returned status not supported/invalid parameter - skipping validation");
		result = TRUE;
		goto Exit;
	}

	if (NQ_SUCCESS != res)
	{
		LOGERR(CM_TRC_LEVEL_FUNC_COMMON," sendReceive() failed");
		goto Exit;
	}

	if (0 == (response.header.flags & SMB2_FLAG_SIGNED))
	{
		/* validate negotiate packet must be signed */
		LOGERR(CM_TRC_LEVEL_FUNC_COMMON," Validate negotiate response isn't signed. Validation failure.");
		goto Exit;
	}

	/* parse response */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT16));	/* reserved */
	cmBufferReadUint32(&response.reader, &temp32Uint);			/* CtlCode */
	if (temp32Uint != SMB_IOCTL_VALIDATE_NEGOTIATE)
	{
		LOGERR(CM_TRC_LEVEL_WARNING, "Bad CtlCode: %x in negotiate validation.", temp32Uint);
		goto Exit;
	}

	for (i = 4; i > 0; --i)
	{
		cmBufferReadUint32(&response.reader, &temp32Uint);				/* file ID */
		if (temp32Uint != 0xFFFFFFFF)
		{
			LOGERR(CM_TRC_LEVEL_WARNING, "Bad file ID value: %x in negotiate validation.", temp32Uint);
			goto Exit;
		}
	}

	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT32));	/* InputOffset */
	cmBufferReadUint32(&response.reader, &temp32Uint);			/* InputCount */
	if (temp32Uint != 0)
	{
		LOGERR(CM_TRC_LEVEL_WARNING, "Bad input count: %u in negotiate validation.", temp32Uint);
		goto Exit;
	}
	cmBufferReadUint32(&response.reader, &offset);				/* OutputOffset */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT32));	/* OutoutCount */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT32));	/* flags - currently no relevant response flags */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT32));	/* reserved */

	/* end of IOCTL header and start of IOCTL payload */
	cmSmb2HeaderSetReaderOffset(&response.header, &response.reader, (NQ_UINT16)offset);
	cmBufferReadUint32(&response.reader, &temp32Uint);				/* server capabilities*/
	if (temp32Uint != pServer->serverCapabilites)
	{
		LOGERR(CM_TRC_LEVEL_WARNING, "Capabilities mismatch, in negotiate validation.");
		goto Exit;
	}
	cmBufferReadBytes(&response.reader, serverGUID, 4 * sizeof(NQ_UINT32));	/* server GUID	 */
	if (0 != syMemcmp(serverGUID, pServer->serverGUID, sizeof(serverGUID)))
	{
		LOGERR(CM_TRC_LEVEL_WARNING, "Received server GUID doesn't match, in negotiate validation.");
		goto Exit;
	}
	cmBufferReadUint16(&response.reader, &temp16Uint);						/* security mode */
	if (temp16Uint != pServer->serverSecurityMode)
	{
		LOGERR(CM_TRC_LEVEL_WARNING, "Security mode mismatch, in negotiate validation.");
		goto Exit;
	}
	cmBufferReadUint16(&response.reader, &temp16Uint);						/* server selected Dialect Revision*/
	if (temp16Uint != pServer->serverDialectRevision)
	{
		LOGERR(CM_TRC_LEVEL_WARNING, "Dialect revision mismatch, in negotiate validation.");
		goto Exit;
	}
	result = TRUE;

Exit:
	cmBufManGive(request.buffer);
	cmBufManGive(response.buffer);
	if (NULL == _pShareIPC)
	{
	    cmListItemUnlock((CMItem *)pShare);
	}
Exit2:
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "validation result: %d send receive result:%d", result, res);
	return (result);

}


static NQ_BOOL checkMessageSignatureSMB3(CCUser *pUser, NQ_BYTE *pHeaderIn, NQ_COUNT headerDataLength, NQ_BYTE* buffer, NQ_COUNT bufLength)
{
	NQ_BYTE sigReceived[SMB2_SECURITY_SIGNATURE_SIZE];
	NQ_BYTE *sig = pHeaderIn + SMB2_SECURITY_SIGNATURE_OFFSET;
	NQ_BOOL result = TRUE;

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "pUser:%p pHeaderIn:%p headerDataLength:%d buffer:%p bufLength:%d", pUser, pHeaderIn, headerDataLength, buffer, bufLength);

	syMemcpy(sigReceived, sig, sizeof(sigReceived));
	LOGDUMP("Received Signature" , sigReceived , SMB2_SECURITY_SIGNATURE_SIZE);
	syMemset(sig, 0, SMB2_SECURITY_SIGNATURE_SIZE);

	cmSmb3CalculateMessageSignature(pUser->macSessionKey.data, pUser->macSessionKey.len, pHeaderIn, headerDataLength, buffer, bufLength, sig);

	result = syMemcmp(sigReceived, sig, SMB2_SECURITY_SIGNATURE_SIZE) == 0;

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "signatures %smatch", result ? "" : "don't ");
	return result;
}

#endif /* UD_NQ_INCLUDESMB3 */
#endif /* UD_NQ_INCLUDECIFSCLIENT */
