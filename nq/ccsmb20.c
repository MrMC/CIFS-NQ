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
#include "cctransport.h"
#include "ccserver.h"
#include "ccuser.h"
#include "ccshare.h"
#include "ccfile.h"
#include "ccutils.h"
#include "ccerrors.h"
#include "ccconfig.h"
#include "ccsearch.h"
#include "ccinfo.h"
#include "cmthread.h"
#include "cmfsutil.h"
#include "cmsmb2.h"
#include "cmbufman.h"
#include "cmcrypt.h"
#include "cmsdescr.h"

#ifdef UD_NQ_INCLUDECIFSCLIENT
#ifdef UD_NQ_INCLUDESMB2

/* -- Structures -- */

#define HEADERANDSTRUCT_SIZE (SMB2_HEADERSIZE + sizeof(NQ_UINT16))
#define MAXINFORESPONSE_SIZE 4096	 
#define REQUESTDURABLEFID_SIGNATURE "DHnQ"
#define RESTOREDURABLEFID_SIGNATURE "DHnC"
#define SEQNUMBEROFFSET 24 + 4

typedef struct 
{
	NQ_BYTE * buffer;		/* buffer pointer */
	CMBufferWriter writer;	/* writer to use */
	CMSmb2Header header;	/* header to use */
	CMBlob tail;			/* variable data (tail) */ 
	NQ_UINT16 command;		/* command code */
} 
Request;	/* SMB request descriptor */

typedef struct 
{
	NQ_BYTE * buffer;		/* buffer pointer */
	CMBufferReader reader;	/* reader to use */
	CMSmb2Header header;	/* pased header */
    NQ_COUNT tailLen;       /* payload length */
} 
Response;	/* SMB response descriptor */

typedef struct 
{
	CMItem item;			/* inherits from item */
	Response * response;	/* pointer to response structure */
	CCServer * server;		/* server pointer */
	NQ_UINT64 mid;			/* to match request and response */
	CMThreadCond * cond;	/* condition to raise */
	NQ_BYTE hdrBuf[HEADERANDSTRUCT_SIZE];	/* header + struct size for signing check */
}
Match;	/* Context between SMB and Transport with one instance per 
		   an outstanding request. Used to match request (expected response) 
		   with response. Is used as is for sync operations while async operations
		   inherit from it. */

typedef struct 
{
	Match match;					/* inherits from Match */
    NQ_TIME timeCreated;            /* time request is created*/
    NQ_TIME setTimeout;             /* timeout that was set when the request was created*/
	CCCifsWriteCallback callback; 	/* callback function to use */
	void * context;					/* context for this callback */
}
WriteMatch;	/* Context between SMB and Transport for Write. Used to match request (expected response) 
		   with response */

typedef struct 
{
	Match match;					/* inherits from Match */
    NQ_TIME timeCreated;            /* time request is created*/
    NQ_TIME setTimeout;             /* timeout that was set when the request was created*/
	CCCifsReadCallback callback; 	/* callback function to use */
	void * context;					/* context for this callback */
	NQ_BYTE * buffer;				/* buffer to read in */
	NQ_UINT32 count;				/* number of bytes to read */
}
ReadMatch;	/* Context between SMB and Transport for Read. Used to match request (expected response) 
		   with response */

typedef struct 
{
	NQ_UINT64 mid;		        /* sequence number of the last sent command */
	Match match;		        /* sync to receieve callback */
} 
Context;	/* SMB context */

typedef struct 
{
	NQ_UINT16 requestBufferSize;	/* required buffer size for request */
	NQ_UINT16 requestStructSize;	/* struct size for request */
	NQ_UINT16 responseStructSize;	/* expected struct size in response */
	void (* callback)(CCServer * pServer, Match * pContext);	/* on response callback - may be NULL */
    void (* notificationHandle)(CCServer *, Response *);     /* handle for a command initiated by server */

} Command;		/* SMB command descriptor */

typedef struct
{
	NQ_BYTE fid[16];	/* context file ID */
} 
SearchContext;	/* SMB2 search context */	

/* CCCifsSmb methods */
static void * allocateContext(CCServer * server);	
static void freeContext(void * context, void * server);	
static void setSolo(NQ_BOOL set);
static NQ_STATUS doNegotiate(CCServer * pServer, CMBlob * blob);
static NQ_STATUS doSessionSetup(CCUser * pUser, const CMBlob * pass1, const CMBlob * pass2);
static NQ_STATUS doSessionSetupExtended(CCUser * pUser, const CMBlob * outBlob, CMBlob * inBlob);
static NQ_STATUS doLogOff(CCUser * pUser);
static NQ_STATUS doTreeConnect(CCShare * pShare);
static NQ_STATUS doTreeDisconnect(CCShare * pShare);
static NQ_STATUS doCreate(CCFile * pFile);
static NQ_STATUS doRestoreHandle(CCFile * pFile);
static NQ_STATUS doClose(CCFile * pFile);
static NQ_STATUS doQueryDfsReferrals(CCShare * share, const NQ_WCHAR * path, CCCifsParseReferral parser, CMList * list);
static NQ_STATUS doFindOpen(CCSearch * pSearch);
static NQ_STATUS doFindMore(CCSearch * pSearch);
static NQ_STATUS doFindClose(CCSearch * pSearch);
static NQ_STATUS doWrite(CCFile * pFile, const NQ_BYTE * data, NQ_UINT bytesToWrite, CCCifsWriteCallback callback, void * context);
static NQ_STATUS doRead(CCFile * pFile, const NQ_BYTE * data, NQ_UINT bytesToRead, CCCifsReadCallback callback, void * context);
#ifdef UD_CC_INCLUDESECURITYDESCRIPTORS	
static NQ_STATUS doQuerySecurityDescriptor(CCFile * pFile, CMSdSecurityDescriptor * sd);
static NQ_STATUS doSetSecurityDescriptor(CCFile * pFile, const CMSdSecurityDescriptor * sd);
#endif /* UD_CC_INCLUDESECURITYDESCRIPTORS */
static NQ_STATUS doQueryFsInfo(CCShare * pShare, CCVolumeInfo * pInfo);
static NQ_STATUS doQueryFileInfoByName(CCShare * pShare, const NQ_WCHAR * fileName, CCCifsParseFileInfoCallback callback, void * context);
static NQ_STATUS doQueryFileInfoByHandle(CCFile * pFile, CCCifsParseFileInfoCallback callback, void * context);
static NQ_STATUS doSetFileAttributes(CCFile * pFile, NQ_UINT32 attributes);	
static NQ_STATUS doSetFileSize(CCFile * pFile, NQ_UINT64 size);	
static NQ_STATUS doSetFileTime(CCFile * pFile, NQ_UINT64 creationTime, NQ_UINT64 lastAccessTime, NQ_UINT64 lastWriteTime);	
static NQ_STATUS doSetFileDeleteOnClose(CCFile * pFile);	
static NQ_STATUS doRename(CCFile * pFile, const NQ_WCHAR * newName);	
static NQ_STATUS doFlush(CCFile * pFile);	
static NQ_STATUS doRapTransaction(void * pShare, const CMBlob * inData, CMBlob * outData);	
static NQ_STATUS doEcho(CCShare * pShare);

/* notification handles */
static void handleBreakNotification(CCServer * pServer, Response * pResponse);

/* special callbacks */
static void writeCallback(CCServer * pServer, Match * pContext);
static void readCallback(CCServer * pServer, Match * pContext);

/* -- Static data */

static const NQ_WCHAR rpcPrefix[] = { 0 };  /* value to prefix RPC pipe names */

static const CCCifsSmb dialect = 
{ 
		"SMB 2.002", 
		0x0202, 
		16,
		TRUE,
        rpcPrefix,
		(void * (*)(void *))allocateContext, 
		freeContext,  
        setSolo,
		(NQ_STATUS (*)(void *, CMBlob *))doNegotiate,
		(NQ_STATUS (*)(void *, const CMBlob *, const CMBlob *))doSessionSetup,
		(NQ_STATUS (*)(void *, const CMBlob *, CMBlob *))doSessionSetupExtended,
		(NQ_STATUS (*)(void *))doLogOff,
		(NQ_STATUS (*)(void *))doTreeConnect,
		(NQ_STATUS (*)(void *))doTreeDisconnect,
		(NQ_STATUS (*)(void *))doCreate,
		(NQ_STATUS (*)(void *))doRestoreHandle,
		(NQ_STATUS (*)(void *))doClose,
		(NQ_STATUS (*)(void *, const NQ_WCHAR *, CCCifsParseReferral, CMList *))doQueryDfsReferrals,
		(NQ_STATUS (*)(void *))doFindOpen,
		(NQ_STATUS (*)(void *))doFindMore,
		(NQ_STATUS (*)(void *))doFindClose,
		(NQ_STATUS (*)(void *, const NQ_BYTE *, NQ_UINT, CCCifsWriteCallback, void *))doWrite,
		(NQ_STATUS (*)(void *, const NQ_BYTE *, NQ_UINT, CCCifsReadCallback, void *))doRead,
#ifdef UD_CC_INCLUDESECURITYDESCRIPTORS	
		(NQ_STATUS (*)(void *, CMSdSecurityDescriptor *))doQuerySecurityDescriptor,
		(NQ_STATUS (*)(void *, const CMSdSecurityDescriptor *))doSetSecurityDescriptor,
#endif /* UD_CC_INCLUDESECURITYDESCRIPTORS */	
		(NQ_STATUS (*)(void *, void *))doQueryFsInfo, 
		(NQ_STATUS (*)(void *, const NQ_WCHAR *, CCCifsParseFileInfoCallback, void *))doQueryFileInfoByName, 
		(NQ_STATUS (*)(void *, CCCifsParseFileInfoCallback, void *))doQueryFileInfoByHandle,
		(NQ_STATUS (*)(void *, NQ_UINT32))doSetFileAttributes,
		(NQ_STATUS (*)(void *, NQ_UINT64))doSetFileSize,
		(NQ_STATUS (*)(void *, NQ_UINT64, NQ_UINT64, NQ_UINT64))doSetFileTime,

		(NQ_STATUS (*)(void *))doSetFileDeleteOnClose,
		(NQ_STATUS (*)(void *, const NQ_WCHAR *))doRename,
		(NQ_STATUS (*)(void * pFile))doFlush,
        (NQ_STATUS (*)(void *, const CMBlob *, CMBlob *))doRapTransaction,
        (NQ_STATUS (*)(void *))doEcho,
        FALSE,
        TRUE
};

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


/* -- API Functions */

NQ_BOOL ccSmb20Start()
{
	return TRUE;
}

NQ_BOOL ccSmb20Shutdown()
{
	return TRUE;
}

const CCCifsSmb * ccSmb20GetCifs(void)
{
	return &dialect;
}

/* -- Static functions -- */

static void * allocateContext(CCServer * server)
{
	Context * pContext;
	if (NULL == (pContext = (Context *)cmMemoryAllocate(sizeof(Context))))
	{
		return NULL;
	}
	cmU64Zero(&pContext->mid);
	return pContext;
}

static void freeContext(void * context, void * server)
{
	CCServer * pServer = (CCServer *)server;	/* casted pointer */
	Context * pContext = (Context *)context;
	
	ccTransportRemoveResponseCallback(&pServer->transport);
	if (NULL != pContext)
	{
		cmMemoryFree(context);
		pServer->smbContext = NULL;
	}
}

static void setSolo(NQ_BOOL set)
{
    /* do nothing */
}

static NQ_BOOL prepareSingleRequest(CCServer * pServer, CCUser * pUser, Request * pRequest, NQ_UINT16 command)
{
	NQ_BYTE * pBuffer;		/* allocated request buffer */ 
	NQ_COUNT bufferSize;	/* this buffer size */
	
	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	/* this call:
	 * - allocates request buffer
	 * - creates request header
	 */
	/* allocate buffer for request */
	bufferSize = (NQ_COUNT)(commandDescriptors[command].requestBufferSize + SMB2_HEADERSIZE + 4);
	pBuffer = cmBufManTake(bufferSize);
	if (NULL == pBuffer)
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return FALSE;
	}
	cmBufferWriterInit(&pRequest->writer, pBuffer, bufferSize);
	pRequest->buffer = pBuffer;
	pRequest->command = command;
	pRequest->tail.data = NULL;
	pRequest->tail.len = 0;
	cmBufferWriterSkip(&pRequest->writer, 4);	/* NBT header */
	cmSmb2HeaderInitForRequest(&pRequest->header, &pRequest->writer, command);
    if (NULL == pUser)
    {
        pRequest->header.sid.low = 0;
        pRequest->header.sid.high = 0;
    }
    else
        pRequest->header.sid = pUser->uid;
    pRequest->header.flags = (NQ_UINT16)(((command != SMB2_CMD_SESSIONSETUP) && (pServer && (ccServerUseSignatures(pServer)) && (pUser && !pUser->isAnonymous)) 
                                ? SMB2_FLAG_SIGNED : 0)
#ifdef UD_CC_INCLUDEDFS
                                | ((pServer->capabilities & CC_CAP_DFS) ? SMB2_FLAG_DFS_OPERATIONS : 0)
#endif /* UD_CC_INCLUDEDFS */                               
                                );


	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return TRUE;
}

static NQ_BOOL prepareSingleRequestByShare(Request * pRequest, const CCShare * pShare, NQ_UINT16 command)
{
	if (!prepareSingleRequest(pShare->user->server, pShare->user, pRequest, command))
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return FALSE;
	}
#ifdef UD_CC_INCLUDEDFS
    if (pShare->flags & CC_SHARE_IN_DFS)
        pRequest->header.flags |= SMB2_FLAG_DFS_OPERATIONS;
    else
        pRequest->header.flags =  (NQ_UINT32)(pRequest->header.flags & (NQ_UINT32)~SMB2_FLAG_DFS_OPERATIONS);
#endif /* UD_CC_INCLUDEDFS */
	pRequest->header.tid = pShare->tid;
	return TRUE;
}

static void writeHeader(Request * pRequest)
{
	cmSmb2HeaderWrite(&pRequest->header, &pRequest->writer);
	cmBufferWriteUint16(&pRequest->writer, commandDescriptors[pRequest->command].requestStructSize);
}

static NQ_STATUS sendRequest(CCServer * pServer, CCUser * pUser, Request * pRequest, Match * pMatch)
{
	NQ_UINT32 packetLen;		/* packet length of both in and out packets */
	CMBufferWriter writer;      /* to write down MID */
    Context * pContext;         /* server context */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	if (pServer->smbContext == NULL)
	{
		LOGERR(CM_TRC_LEVEL_ERROR, " smbContext in CCServer ibject is missing");
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NQ_ERR_NOTCONNECTED;
	}
	
    if (!ccServerWaitForCredits(pServer))
    {
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NQ_ERR_TIMEOUT;
    }

    packetLen = cmBufferWriterGetDataCount(&pRequest->writer) - 4;	/* NBT header */

    ccTransportLock(&pServer->transport);

    /* write down MID */
    pContext = (Context *)pServer->smbContext;
    cmU64Inc(&pContext->mid);
    pRequest->header.mid = pContext->mid;
    cmBufferWriterInit(&writer, pRequest->buffer + SEQNUMBEROFFSET, packetLen);
    cmBufferWriteUint64(&writer, &pContext->mid);
    pMatch->mid = pContext->mid;

	/* compose signature */
	if (ccServerUseSignatures(pServer) && ccUserUseSignatures(pUser) && pRequest->header.command != SMB2_CMD_SESSIONSETUP)
	{
		cmSmb2CalculateMessageSignature(
			pUser->macSessionKey.data, 
			pUser->macSessionKey.len, 
			pRequest->buffer + 4, 
			packetLen, 
			pRequest->tail.data,
			pRequest->tail.len, 
			pRequest->header._start + SMB2_SECURITY_SIGNATURE_OFFSET
			);
	}
	
	if (!ccTransportSend(
			&pServer->transport, 
			pRequest->buffer, 
			packetLen + pRequest->tail.len,
			packetLen
			)
		)
	{
        ccTransportUnlock(&pServer->transport);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return (NQ_STATUS)syGetLastError();
	}

	if (0 != pRequest->tail.len && 
		!ccTransportSendTail(&pServer->transport, pRequest->tail.data, pRequest->tail.len)
		)
	{
        ccTransportUnlock(&pServer->transport);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return (NQ_STATUS)syGetLastError();
	}
    ccTransportUnlock(&pServer->transport);

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return NQ_SUCCESS;
}

static NQ_STATUS sendReceive(CCServer * pServer, CCUser * pUser, Request * pRequest, Response * pResponse)
{
	NQ_STATUS res;				/* send result */
    CMThread * pThread;         /* current thread */
    Match * pMatch;             /* match structure pointer */
	
	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    pResponse->buffer = NULL;
    pThread = cmThreadGetCurrent();
    pMatch = (Match *)cmThreadGetContext(pThread, sizeof(Match));
    if (NULL == pMatch)
    {
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_OUTOFMEMORY;
    }
	pMatch->response = pResponse;
	pMatch->cond = &pThread->syncCond;
    pMatch->server = pServer; 
	cmListItemAdd(&pServer->expectedResponses, (CMItem *)pMatch, NULL);
	cmThreadCondClear(pMatch->cond); /* Cleaning up the condition socket before sending*/
	
	res = sendRequest(pServer, pUser, pRequest, pMatch);
	if (NQ_SUCCESS != res)
	{
	    cmListItemRemove((CMItem *)pMatch);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
	}
	
    if (!cmThreadCondWait(pMatch->cond, ccConfigGetTimeout()))
	{
	    (pServer->transport.cleanupCallback)(pServer->transport.cleanupContext);
		if ((!pServer->transport.connected || NULL == pResponse->buffer) 
            && pRequest->command != SMB2_CMD_NEGOTIATE && pRequest->command != SMB2_CMD_SESSIONSETUP
           )
        {
            if (!ccServerReconnect(pServer))
            {
                LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                return NQ_ERR_NOTCONNECTED;
            }
        }
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_TIMEOUT;
	}

	/* check connection */
    if (!pServer->transport.connected)
    {
	    (pServer->transport.cleanupCallback)(pServer->transport.cleanupContext);
        if (pRequest->command != SMB2_CMD_NEGOTIATE && pRequest->command != SMB2_CMD_SESSIONSETUP)
        {
            if (ccServerReconnect(pServer))
            {
		        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		        return NQ_ERR_TIMEOUT;              /* simulate timeout - causing retry */
            }
        }
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NQ_ERR_NOTCONNECTED;
    }

    /* check signatures */
    if (ccServerUseSignatures(pServer) && (pResponse->header.flags & SMB2_FLAG_SIGNED) && ccUserUseSignatures(pUser))
	{
		NQ_BYTE * pSignature = pMatch->hdrBuf + SMB2_SECURITY_SIGNATURE_OFFSET;
		
		cmSmb2CalculateMessageSignature(
			pUser->macSessionKey.data, 
			pUser->macSessionKey.len,
            pMatch->hdrBuf,
            HEADERANDSTRUCT_SIZE,
			pResponse->buffer, 
			pResponse->tailLen, 
			pSignature
			);
		if (0 != syMemcmp(pResponse->header.signature, pSignature, sizeof(pResponse->header.signature)))
		{
     		LOGERR(CM_TRC_LEVEL_ERROR, "bad incoming signature");
			LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
			return NQ_ERR_SIGNATUREFAIL;
		}
	}
	
	sySetLastError((NQ_UINT32)ccErrorsStatusToNq(pResponse->header.status, TRUE));

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return (NQ_STATUS)ccErrorsStatusToNq(pResponse->header.status, TRUE);
}

static NQ_STATUS exchangeEmptyCommand(CCShare * pShare, NQ_UINT16 command)
{
	Request request;		/* request dscriptor */
	Response response;		/* response descriptor */
	CCServer * pServer;		/* server object pointer */

	NQ_STATUS res;			/* exchange status */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	pServer = pShare->user->server;
	if (!prepareSingleRequestByShare(&request, pShare, command))
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_OUTOFMEMORY;
	}
	
	/* compose request */
	writeHeader(&request);
	cmBufferWriteUint16(&request.writer, 0);		/* reserved */
	request.tail.len = 0;
	request.tail.data = NULL;
	
	res = sendReceive(pServer, pShare->user, &request, &response);
	cmBufManGive(request.buffer);
	cmBufManGive(response.buffer);

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return res;
}

static void handleBreakNotification(CCServer * pServer, Response * notifyResponse)
{
	Request request;		    /* request descriptor */
	NQ_COUNT packetLen;		    /* packet length of both in and out packets */
    NQ_BYTE oplockLevel;        /* new oplock level */
    CCUser * pUser;             /* user pointer */
    CCShare * pShare;           /* share pointer */
    CCFile * pFile;             /* file pointer */
    Context * pContext;         /* SMB context */
    NQ_BYTE * pFid;             /* pointer to file ID in the notification */
    NQ_UINT64   negMid = {0xffffffff , 0xffffffff}; /* -1 mid */
	
	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	if (pServer->smbContext == NULL)
	{
		LOGERR(CM_TRC_LEVEL_ERROR, " smbContext in CCServer ibject is missing");
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return;
	}
	
    /* parse notification */
    cmBufferReadByte(&notifyResponse->reader, &oplockLevel);	/* oplock */
   	cmBufferReaderSkip(&notifyResponse->reader, 5);	            /* reserved + reserved 2 */
    pFid = cmBufferReaderGetPosition(&notifyResponse->reader);

    /* prepare objects */
    pFile = ccFileFindById(pServer, pFid);
    if (NULL == pFile)
	{
        LOGERR(CM_TRC_LEVEL_ERROR, "Unknown file ID");
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return;
	}
    if ((0 == oplockLevel && pFile->oplockLevel == 0x01)|| cmU64Cmp(&notifyResponse->header.mid ,&negMid )!= 0)
    {
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return;
    }
    pFile->oplockLevel = oplockLevel;
    pShare = pFile->share;
    pUser = pShare->user;

    /* compose ack */
	if (!prepareSingleRequestByShare(&request, pShare, SMB2_CMD_OPLOCKBREAK))
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return;
	}

	writeHeader(&request);
	cmBufferWriteByte(&request.writer, oplockLevel);        /* oplock */
	cmBufferWriteZeroes(&request.writer, 5);	            /* reserved + reserved 2 */
	cmBufferWriteBytes(&request.writer, pFile->fid, sizeof(pFile->fid));/* file id */
	packetLen = cmBufferWriterGetDataCount(&request.writer) - 4;	/* NBT header */

    /* write down MID */
    pContext = (Context *)pServer->smbContext;
    cmU64Inc(&pContext->mid);
    request.header.mid = pContext->mid;
    cmBufferWriterSetPosition(&request.writer, request.buffer + SEQNUMBEROFFSET);
    cmBufferWriteUint64(&request.writer, &pContext->mid);

	/* compose signature */
	if (ccServerUseSignatures(pServer) && ccUserUseSignatures(pUser))
	{
		cmSmb2CalculateMessageSignature(
			pUser->macSessionKey.data, 
			pUser->macSessionKey.len, 
			request.buffer + 4, 
			packetLen, 
			NULL,
			0, 
			request.header._start + SMB2_SECURITY_SIGNATURE_OFFSET
			);
	}

    /* send and receive. Since we running inside the receiving thread - this is done inlined */
    ccTransportLock(&pServer->transport);
	if (!ccTransportSendSync(
			&pServer->transport, 
			request.buffer, 
			packetLen,
			packetLen
			)
		)
	{
        ccTransportUnlock(&pServer->transport);
		cmBufManGive(request.buffer);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return;
	}
    ccTransportUnlock(&pServer->transport);
	cmBufManGive(request.buffer);
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return;	
}

static void anyResponseCallback(void * transport)
{
	CCTransport * pTransport = (CCTransport *)transport; 	/* casted to transport entry */
	CCServer * pServer;							/* casted pointer */
	CMIterator iterator;						/* iterates through expected responses */
	CMSmb2Header header;						/* response header */
	CMBufferReader reader;						/* to parse header */
	NQ_COUNT res;								/* bytes read */
	NQ_BYTE buffer[HEADERANDSTRUCT_SIZE];		/* header + struct size */
    const NQ_CHAR SIGNATURE[] = {(NQ_CHAR)0xfe, 'S', 'M', 'B' }; /* SMB2 signature */
	
	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
	
    pServer = (CCServer *)pTransport->context;
	
    if (!pTransport->connected) /* proceed disconnect */
    {
    	LOGERR(CM_TRC_LEVEL_ERROR, "Connection broken with %s", cmWDump(pServer->item.name));

        /* match with request */
    	cmListIteratorStart(&pServer->expectedResponses, &iterator);
	    while (cmListIteratorHasNext(&iterator))
	    {
		    Match * pMatch;
    		
		    pMatch = (Match *)cmListIteratorNext(&iterator);    
		    if (pMatch->server == pServer) 
		    {
                /* signal the first match */
			    cmListItemRemove((CMItem *)pMatch);
                if (pMatch->cond != NULL)
    		        cmThreadCondSignal(pMatch->cond);

                /* remove others */
	            while (cmListIteratorHasNext(&iterator))
	            {
		            pMatch = (Match *)cmListIteratorNext(&iterator);    
		            if (pMatch->server == pServer) 
		            {
        			    cmListItemRemove((CMItem *)pMatch);
                    }
                }
			    cmListIteratorTerminate(&iterator);
			    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
			    return;
		    }
	    }
	    cmListIteratorTerminate(&iterator);

    	LOGERR(CM_TRC_LEVEL_ERROR, "Response not matched. server: %s", cmWDump(pServer->item.name));
	    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	    return;
    }

    /* read & parse SMB header */
	res = ccTransportReceiveBytes(pTransport, buffer, sizeof(buffer));
	if (NQ_FAIL == res)
	{
        ccTransportReceiveEnd(pTransport);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return;
	}
    if (0 != syMemcmp(buffer, SIGNATURE, sizeof(SIGNATURE)))
    {
	    ccTransportReceiveEnd(&pServer->transport);
	    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	    return;
    }

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
			if (0 == header.status && length != commandDescriptors[header.command].responseStructSize)
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
				ccTransportReceiveEnd(pTransport);
				ccTransportDiscardReceive(pTransport);
			}
			else
			{
				cmListItemRemove((CMItem *)pMatch);
				if (pServer->useSigning && NULL != pMatch->hdrBuf)
					syMemcpy(pMatch->hdrBuf, buffer, HEADERANDSTRUCT_SIZE);
                if (NULL != commandDescriptors[header.command].callback)
				{
					commandDescriptors[header.command].callback(pServer, pMatch);
				}
				else
				{	
   	                if (pServer->transport.recv.remaining > 0)
	                {
                        Response * pResponse = pMatch->response;  /* associated response */
		                pResponse->tailLen = pServer->transport.recv.remaining;
		                pResponse->buffer = cmMemoryAllocate(pResponse->tailLen);
		                if (NULL != pResponse->buffer)
		                {
		                    if (pResponse->tailLen == ccTransportReceiveBytes(&pServer->transport, pResponse->buffer, pResponse->tailLen))
		                    {
		                        cmBufferReaderInit(&pResponse->reader, pResponse->buffer, pResponse->tailLen);
		                        pResponse->header._start = 	/* set virtual header start */
			                        pResponse->buffer - 
			                        HEADERANDSTRUCT_SIZE;	/* shift back on header size and more structure size */
                            }
                        }
                    }
	                ccTransportReceiveEnd(&pServer->transport);
					cmThreadCondSignal(pMatch->cond);
				}
			}
            if (header.credits > 0)
                ccServerPostCredits(pServer, header.credits);

			LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
			return;
		}
	}
	cmListIteratorTerminate(&iterator);
    if (NULL != commandDescriptors[header.command].notificationHandle)
    {
        if (pServer->transport.recv.remaining > 0)
        {
            Response response;
            
            response.tailLen = pServer->transport.recv.remaining;
            response.buffer = cmMemoryAllocate(response.tailLen);
            if (NULL != response.buffer)
            {
                if (response.tailLen == ccTransportReceiveBytes(&pServer->transport, response.buffer, response.tailLen))
                {
                    cmBufferReaderInit(&response.reader, response.buffer, response.tailLen);
                    response.header._start = 	/* set virtual header start */
                        response.buffer - 
                        HEADERANDSTRUCT_SIZE;	/* shift back on header size and more structure size */
                }
                response.header = header;
                commandDescriptors[header.command].notificationHandle(pServer, &response);
            }
            cmMemoryFree(response.buffer);
        }
   }
	ccTransportReceiveEnd(&pServer->transport);
	LOGERR(CM_TRC_LEVEL_ERROR, "Response not matched. Mid: %d:%d server: %s", header.mid.high, header.mid.low, cmWDump(pServer->item.name));
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
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
	if (!prepareSingleRequestByShare(pRequest, pFile->share, SMB2_CMD_QUERYINFO))
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_OUTOFMEMORY;
	}
	
	/* compose request */
	writeHeader(pRequest);
	cmBufferWriteByte(&pRequest->writer, infoType);		/* information type */
	cmBufferWriteByte(&pRequest->writer, infoClass);	/* information class */
	cmBufferWriteUint32(&pRequest->writer, maxResLen);	/* output buffer length */
	cmBufferWriteUint16(&pRequest->writer, 0);			/* input buffer offset  */
	cmBufferWriteUint16(&pRequest->writer, 0);			/* reserved */
	cmBufferWriteUint32(&pRequest->writer, 0);			/* input buffer length */
	cmBufferWriteUint32(&pRequest->writer, addInfo);		/* output buffer length */
	cmBufferWriteUint32(&pRequest->writer, 0);			/* flags */
	cmBufferWriteBytes(&pRequest->writer, pFile->fid, sizeof(pFile->fid));	/* file ID */
	return NQ_SUCCESS;
}

static NQ_STATUS writeSetInfoRequest(
		Request * pRequest,
		CCFile * pFile,
		NQ_BYTE infoType, 
		NQ_BYTE infoClass, 
		NQ_UINT32 addInfo,
		NQ_UINT32 dataLen
		)
{
	NQ_BYTE * pBufferOffset;		/* pointer to the buffer offset field */
	NQ_BYTE * pTemp;				/* temporary pointer */
	NQ_UINT16 bufferOffset;			/* buffer offset */
	
	if (!prepareSingleRequestByShare(pRequest, pFile->share, SMB2_CMD_SETINFO))
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_OUTOFMEMORY;
	}
	
	/* compose request */
	writeHeader(pRequest);
	cmBufferWriteByte(&pRequest->writer, infoType);		/* information type */
	cmBufferWriteByte(&pRequest->writer, infoClass);	/* information class */
	cmBufferWriteUint32(&pRequest->writer, dataLen);	/* buffer length */
	pBufferOffset = cmBufferWriterGetPosition(&pRequest->writer);
	cmBufferWriteUint16(&pRequest->writer, 0);			/* input buffer offset  */
	cmBufferWriteUint16(&pRequest->writer, 0);			/* reserved */
	cmBufferWriteUint32(&pRequest->writer, addInfo);		/* output buffer length */
	cmBufferWriteBytes(&pRequest->writer, pFile->fid, sizeof(pFile->fid));	/* file ID */
	bufferOffset = (NQ_UINT16)cmSmb2HeaderGetWriterOffset(&pRequest->header, &pRequest->writer);
	pTemp = cmBufferWriterGetPosition(&pRequest->writer);
	cmBufferWriterSetPosition(&pRequest->writer, pBufferOffset);	
	cmBufferWriteUint16(&pRequest->writer, bufferOffset);	/* input buffer offset  */
	cmBufferWriterSetPosition(&pRequest->writer, pTemp);	
	return NQ_SUCCESS;
}

static NQ_STATUS doNegotiate(CCServer * pServer, CMBlob * inBlob)
{
	Request request;		    /* request descriptor */
	Response response;		    /* response descriptor */
	const CCCifsSmb ** dialects;/* pointer to an array of supported dialects */
	NQ_UINT16 numDialects;	    /* number of dialects */
	NQ_COUNT packetLen;		    /* packet length of both in and out packets */
	NQ_STATUS res;				/* exchange status */
	NQ_UINT16 actualDialects;	/* number of dialects to negotiate */
	NQ_INT i;					/* just a counter */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	if (!pServer->useExtendedSecurity)
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "SMB2 requires extended security");
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_OUTOFMEMORY;
	}

	if (!prepareSingleRequest(NULL, NULL, &request, SMB2_CMD_NEGOTIATE))
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_OUTOFMEMORY;
	}
	
	numDialects = (NQ_UINT16)ccCifsGetDialects(&dialects);
	for (i = 0, actualDialects = 0; i < numDialects; i++)
	{
		const CCCifsSmb * pDialect = dialects[i];
		
		if (pDialect->revision != CCCIFS_ILLEGALSMBREVISION)
			actualDialects++;
	}
	/* compose request */
	writeHeader(&request);
	cmBufferWriteUint16(&request.writer, actualDialects);	/* num of dialects */
	cmBufferWriteUint16(&request.writer, nqGetMessageSigning()? 1: 0);	/* signing: enabled */
	cmBufferWriteUint16(&request.writer, 0);	/* reserved */
	cmBufferWriteUint32(&request.writer, 0);	/* capabilities */
	cmBufferWriteUint32(&request.writer, 0);	/* client GUID */
	cmBufferWriteUint32(&request.writer, 0);	/* client GUID */
	cmBufferWriteUint32(&request.writer, 0);	/* client GUID */
	cmBufferWriteUint32(&request.writer, 0);	/* client GUID */
	cmBufferWriteUint32(&request.writer, 0);	/* client start time */
	cmBufferWriteUint32(&request.writer, 0);	/* client start time */
	for (actualDialects = 0; numDialects > 0; numDialects--)
	{
		const CCCifsSmb * pDialect = *dialects++;
		
		if (pDialect->revision != CCCIFS_ILLEGALSMBREVISION)
			cmBufferWriteUint16(&request.writer, pDialect->revision);
	}
	
	/* send and receive. Since no context was established yet - this is done inlined */
	packetLen = cmBufferWriterGetDataCount(&request.writer) - 4;	/* NBT header */
    ccTransportLock(&pServer->transport);
	if (!ccTransportSendSync(
			&pServer->transport, 
			request.buffer, 
			packetLen,
			packetLen
			)
		)
	{
        ccTransportUnlock(&pServer->transport);
		cmBufManGive(request.buffer);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return (NQ_STATUS)syGetLastError();
	}
	cmBufManGive(request.buffer);
	response.buffer = ccTransportReceiveAll(&pServer->transport, &packetLen);
    ccTransportUnlock(&pServer->transport);
	if (NULL == response.buffer)
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_OUTOFMEMORY;
	}
	res = ccSmb20DoNegotiateResponse(pServer, response.buffer, packetLen, inBlob);
	cmBufManGive(response.buffer);

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return res;	
}

NQ_STATUS ccSmb20DoNegotiateResponse(CCServer * pServer, const NQ_BYTE * data, NQ_COUNT len, CMBlob * inBlob)
{
	CMBufferReader reader;	/* response reader */
	CMSmb2Header header;	/* response header */
	NQ_UINT16 tempUint16;	/* for parsing 2-byte values */
	NQ_UINT32 tempUint32;	/* for parsing 4-byte values */
	NQ_UINT16 blobOffset;	/* offset from header to the security buffer */
	NQ_UINT16 length;		/* structure length */
	NQ_STATUS res;			/* exchange status */
	CMBlob blob;			/* temporary blob */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	/* initialize correspondance with transports.
       we do it here since this response may come on an SMB1 request */
	ccTransportSetResponseCallback(&pServer->transport, anyResponseCallback, pServer);

    cmBufferReaderInit(&reader, data, len); /* starting from SMB header */
	cmSmb2HeaderRead(&header, &reader);
	pServer->credits += header.credits;
    if (0 == pServer->credits)
        pServer->credits = 1;
    
	res = (NQ_STATUS)header.status;
	sySetLastError((NQ_UINT32)ccErrorsStatusToNq((NQ_UINT32)res, TRUE));
	res = (NQ_STATUS)ccErrorsStatusToNq((NQ_UINT32)res, TRUE);
	if (NQ_SUCCESS != res)
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
	}
	cmBufferReadUint16(&reader, &length); /* structure size */
	if (length != commandDescriptors[0].responseStructSize)
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_BADFORMAT;
	}

	/* parse response */
	pServer->capabilities = 0;
	cmBufferReadUint16(&reader, &tempUint16);			/* security mode */
	if (tempUint16 & 0x001)
	{
		pServer->capabilities |= CC_CAP_MESSAGESIGNING;
	}
	cmBufferReadUint16(&reader, &tempUint16);			/* revision */
	/* TODO - analyse revision */
	cmBufferReaderSkip(&reader, sizeof(NQ_UINT16));	/* reserved */
	cmBufferReaderSkip(&reader, 4 * sizeof(NQ_UINT32));	/* server GUID	 */
	cmBufferReadUint32(&reader, &tempUint32);			/* capabilities */
	if (0x01 & tempUint32)
	{
		pServer->capabilities |= CC_CAP_DFS;
	}
	cmBufferReadUint32(&reader, &pServer->maxTrans);	
	cmBufferReadUint32(&reader, &pServer->maxRead);	
	cmBufferReadUint32(&reader, &pServer->maxWrite);	
	cmBufferReaderSkip(&reader, 4 * sizeof(NQ_UINT32));	/* system time + server start time */
	cmBufferReadUint16(&reader, &blobOffset);				/* offset to security buffer */	
	cmBufferReadUint16(&reader, &tempUint16);				/* length of security buffer */
	blob.len = tempUint16;
	cmSmb2HeaderSetReaderOffset(&header, &reader, blobOffset);
	blob.data = cmBufferReaderGetPosition(&reader);
	*inBlob = cmMemoryCloneBlob(&blob);
	pServer->smb = &dialect;
		
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return NQ_SUCCESS;	
}

static NQ_STATUS doSessionSetup(CCUser * pUser, const CMBlob * pass1, const CMBlob * pass2)
{
	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	/* not supported */
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return NQ_ERR_NOSUPPORT;
}

static NQ_STATUS doSessionSetupExtended(CCUser * pUser, const CMBlob * outBlob, CMBlob * inBlob)
{
	Request request;		/* request dscriptor */
	Response response;		/* response descriptor */
	CCServer * pServer;		/* server object pointer */
	NQ_BYTE * blobOffPtr;	/* pointer to blob (buffer) offset */
	NQ_BYTE * savedPtr;		/* for saving current position */
	NQ_UINT16 blobOffset;	/* offset from header to the security buffer */
	CMBlob blob;			/* original security blob */
	NQ_UINT16 tempUint16;	/* for parsing 2-byte values */
	NQ_STATUS res;			/* exchange result */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	inBlob->data = NULL;
	pServer = pUser->server;
	if (!prepareSingleRequest(pServer, pUser, &request, SMB2_CMD_SESSIONSETUP))
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_OUTOFMEMORY;
	}
	
	/* compose request */
	if (pServer->credits < 3)
	{
		request.header.credits = 40;	/* to have spare credits */
	}
    request.header.sid = pUser->uid;
	writeHeader(&request);
	cmBufferWriteByte(&request.writer, 0);		/* VCNumber */
	cmBufferWriteByte(&request.writer, 1);		/* security mode - message signing enabled */
	cmBufferWriteUint32(&request.writer, 0);	/* capabilities - none */
	cmBufferWriteUint32(&request.writer, 0);	/* channel */
	blobOffPtr = cmBufferWriterGetPosition(&request.writer);
	cmBufferWriterSkip(&request.writer, sizeof(NQ_UINT16));	/* skip buffer offset */
	cmBufferWriteUint16(&request.writer, (NQ_UINT16)outBlob->len);		/* buffer length */
	cmBufferWriteUint32(&request.writer, 0);	/* previous session ID */
	cmBufferWriteUint32(&request.writer, 0);	/* previous session ID */
	savedPtr = cmBufferWriterGetPosition(&request.writer);
	cmBufferWriterSetPosition(&request.writer, blobOffPtr);
	cmBufferWriteUint16(&request.writer, (NQ_UINT16)(savedPtr - cmBufferWriterGetStart(&request.writer) - 4));	/* buffer offset - NBT header */
	cmBufferWriterSetPosition(&request.writer, savedPtr);
	request.tail = *outBlob;

	res = sendReceive(pServer, pUser, &request, &response);
	cmBufManGive(request.buffer);
	if (NQ_SUCCESS != res && NQ_ERR_MOREDATA != res)
	{
	    cmU64Zero(&pUser->uid);
		cmBufManGive(response.buffer);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
	}

	/* parse response */
	pUser->uid = response.header.sid;	
    cmBufferReadUint16(&response.reader, &tempUint16);	/* session flags */
	pUser->isGuest = (tempUint16 & 0x1) ? TRUE : FALSE;
	cmBufferReadUint16(&response.reader, &blobOffset);				/* offset to security buffer */	
	cmBufferReadUint16(&response.reader, &tempUint16);				/* length of security buffer */
	blob.len = tempUint16;
	cmSmb2HeaderSetReaderOffset(&response.header, &response.reader, blobOffset);
	blob.data = cmBufferReaderGetPosition(&response.reader);
	if (0 != blob.len)
		*inBlob = cmMemoryCloneBlob(&blob);
	
	cmBufManGive(response.buffer);

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return res;
}

static NQ_STATUS doLogOff(CCUser * pUser)
{
	Request request;		/* request dscriptor */
	Response response;		/* response descriptor */
	CCServer * pServer;		/* server object pointer */
	NQ_STATUS res;			/* exchange result */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	pServer = pUser->server;
	if (!prepareSingleRequest(pServer, pUser, &request, SMB2_CMD_LOGOFF))
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_OUTOFMEMORY;
	}
	
	/* compose request */
	request.header.sid = pUser->uid;
	writeHeader(&request);
	cmBufferWriteUint16(&request.writer, 0);		/* reserved */

	res = sendReceive(pServer, pUser, &request, &response);
	cmBufManGive(request.buffer);
	if (NQ_SUCCESS != res)
	{
	    if (response.buffer != NULL)
            cmBufManGive(response.buffer);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
	}

	/* parse response - noting to parse */

	cmBufManGive(response.buffer);

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return NQ_SUCCESS;
}

static NQ_STATUS doTreeConnect(CCShare * pShare)
{
	Request request;		/* request dscriptor */
	Response response;		/* response descriptor */
	CCServer * pServer;		/* server object pointer */
	CCUser * pUser;			/* user object pointer */
    NQ_UINT16 tempUint16;	/* for parsing 2-byte values */
    NQ_UINT32 tempUint32;   /* for parsing 4-byte values */
	NQ_WCHAR * path;		/* full network path */
	NQ_STATUS res;			/* exchange result */
	
	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	pUser = pShare->user;
	pServer = pUser->server;
    if (!prepareSingleRequest(pServer, pUser, &request, SMB2_CMD_TREECONNECT))
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_OUTOFMEMORY;
	}
	
	/* compose request */
	writeHeader(&request);
	cmBufferWriteUint16(&request.writer, 0);	/* reserved */
	tempUint16 = (NQ_UINT16)cmSmb2HeaderGetWriterOffset(&request.header, &request.writer);
	tempUint16 = (NQ_UINT16)(tempUint16 +(2 * sizeof(NQ_UINT16)));
	cmBufferWriteUint16(&request.writer, tempUint16);	/* path offset */
    if (pServer->useName)
    {
	    path = ccUtilsComposeRemotePathToShare(pServer->item.name, pShare->item.name);
    }
    else
    {
        NQ_WCHAR  * ipW;
        NQ_CHAR   * ip;

        ip = (NQ_CHAR *)cmMemoryAllocate(CM_IPADDR_MAXLEN * sizeof(NQ_CHAR));
        ipW = (NQ_WCHAR *)cmMemoryAllocate(CM_IPADDR_MAXLEN * sizeof(NQ_WCHAR));
        
        cmIpToAscii(ip, &pServer->ips[0]);
        cmAnsiToUnicode(ipW, ip);
        path = ccUtilsComposeRemotePathToShare(ipW, pShare->item.name);
        cmMemoryFree(ip);
        cmMemoryFree(ipW);
    }
    
	if (NULL == path)
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return FALSE;
	}
	tempUint16 = (NQ_UINT16)(sizeof(NQ_WCHAR) * cmWStrlen(path));
	cmBufferWriteUint16(&request.writer, tempUint16);	/* path length */
	request.tail.data = (NQ_BYTE*)path;
	request.tail.len = (NQ_COUNT)tempUint16;
			
	res = sendReceive(pServer, pUser, &request, &response);
	cmMemoryFree(path);
	cmBufManGive(request.buffer);
	if (NQ_SUCCESS != res)
	{
		cmBufManGive(response.buffer);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
	}

	/* parse response */
	pShare->tid = response.header.tid;
	cmBufferReadByte(&response.reader, &pShare->type);		/* share type */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_BYTE));	/* reserved */
    pShare->flags = 0;
	cmBufferReadUint32(&response.reader, &tempUint32);      /* share flags */
    if (tempUint32 & SMB2_SHARE_FLAG_DFS)
        pShare->flags |= CC_SHARE_IN_DFS;
	cmBufferReadUint32(&response.reader, &tempUint32);	    /* capabilities */	
    if (tempUint32 & SMB2_SHARE_CAPS_DFS)
        pShare->flags |= CC_SHARE_IN_DFS;
	cmBufferReadUint32(&response.reader, &pShare->access);	/* maximal access */	
	cmBufManGive(response.buffer);

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return NQ_SUCCESS;
}

static NQ_STATUS doTreeDisconnect(CCShare * pShare)
{
	return exchangeEmptyCommand(pShare, SMB2_CMD_TREEDISCONNECT);
}

static NQ_STATUS create(CCFile * pFile, NQ_BOOL setDfsFlag)
{
	Request request;			/* request dscriptor */
	Response response;			/* response descriptor */
	CCServer * pServer;			/* server object pointer */
	CCShare * pShare;			/* share object pointer */
	NQ_WCHAR * pName;           /* pointer to name */
	NQ_BYTE * pNameOffset;		/* pointer to the name offset field */
	NQ_BYTE * pContextOffset;	/* pointer to the context offtset field */
	NQ_UINT32 contextOffset;	/* context offset */
	NQ_UINT32 contextLength;	/* context length */
	NQ_UINT16 nameOffset;		/* name offset */
	NQ_BYTE * pTemp;			/* temporary pointer in th writer */
	NQ_UINT16 nameLen;			/* name length in bytes (not including terminator) */
	NQ_STATUS res;				/* exchange result */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	pShare = pFile->share;
	pServer = pShare->user->server;
	if (!prepareSingleRequestByShare(&request, pShare, SMB2_CMD_CREATE))
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_OUTOFMEMORY;
	}
	pName = (pFile->item.name[0] == cmWChar('\\')) ? pFile->item.name + 1 : pFile->item.name;

	/* some operations like query fs info require smb2 dfs operations flag to be unset */
	if (!setDfsFlag)
	    request.header.flags = (NQ_UINT32)(request.header.flags & (NQ_UINT32)~SMB2_FLAG_DFS_OPERATIONS);

	/* compose request */
	writeHeader(&request);
	cmBufferWriteByte(&request.writer, 0);		                /* security flags */
    cmBufferWriteByte(&request.writer, SMB2_OPLOCK_BATCH);	    /* oplock */
	cmBufferWriteUint32(&request.writer, 2);	                /* impersonation */
	cmBufferWriteUint32(&request.writer, 0);	                /* SMB create flags */
	cmBufferWriteUint32(&request.writer, 0);	                /* SMB create flags */
	cmBufferWriteUint32(&request.writer, 0);	                /* reserved */
	cmBufferWriteUint32(&request.writer, 0);	                /* reserved */
	cmBufferWriteUint32(&request.writer, pFile->accessMask);	/* desired access */
	cmBufferWriteUint32(&request.writer, pFile->attributes);	/* file attributes */
	cmBufferWriteUint32(&request.writer, pFile->sharedAccess);	/* shared access */
	cmBufferWriteUint32(&request.writer, pFile->disposition);	/* create disposition */
	cmBufferWriteUint32(&request.writer, pFile->options);		/* create options */
	pNameOffset = cmBufferWriterGetPosition(&request.writer);
	cmBufferWriterSkip(&request.writer, sizeof(NQ_UINT16));		/* name offset */
	nameLen = (NQ_UINT16)(sizeof(NQ_WCHAR) * cmWStrlen(pName));
	cmBufferWriteUint16(&request.writer, nameLen);				/* name length */
	pContextOffset = cmBufferWriterGetPosition(&request.writer);
	cmBufferWriteUint32(&request.writer, 0);		/* context offset */
	cmBufferWriteUint32(&request.writer, 0);		/* context length */
	cmBufferWriterAlign(&request.writer, request.header._start, 8);
	
	pTemp = cmBufferWriterGetPosition(&request.writer);
 	nameOffset = (NQ_UINT16)cmSmb2HeaderGetWriterOffset(&request.header, &request.writer);
	cmBufferWriterSetPosition(&request.writer,pNameOffset);
	cmBufferWriteUint16(&request.writer, nameOffset);			/* name offset again */
	cmBufferWriterSetPosition(&request.writer, pTemp);
	cmBufferWriteBytes(&request.writer	,(NQ_BYTE *)pName,nameLen);

	cmBufferWriterAlign(&request.writer, request.header._start, 8);
	contextOffset = cmSmb2HeaderGetWriterOffset(&request.header, &request.writer);
	if (!pFile->share->isIpc)			
	{
		NQ_BYTE * pStart;			/* pointer to the element start */
		NQ_BYTE * pSignatureOffset;	/* pointer to name offset */
		NQ_BYTE * pDataOffset;		/* pointer to data offset */
		NQ_UINT16 offset;			/* name/data offset */
		
		pStart = cmBufferWriterGetPosition(&request.writer);
		cmBufferWriteUint32(&request.writer, 0);		/* chain offset - no more elements */
		pSignatureOffset = cmBufferWriterGetPosition(&request.writer);
		cmBufferWriteUint16(&request.writer, 0);		/* offset to element name */
		cmBufferWriteUint16(&request.writer, sizeof(REQUESTDURABLEFID_SIGNATURE) - 1);	/* element name length */
		cmBufferWriteUint16(&request.writer, 0);		/* reserved */
		pDataOffset = cmBufferWriterGetPosition(&request.writer);
		cmBufferWriteUint16(&request.writer, 0);		/* offset to element data */
		cmBufferWriteUint32(&request.writer, sizeof(pFile->fid));		/* element data length */
		pTemp = cmBufferWriterGetPosition(&request.writer);
		offset = (NQ_UINT16)(pTemp - pStart);
		cmBufferWriterSetPosition(&request.writer, pSignatureOffset);
		cmBufferWriteUint16(&request.writer, offset);	/* element name offset again */
		cmBufferWriterSetPosition(&request.writer, pTemp);
		cmBufferWriteBytes(&request.writer, (NQ_BYTE *)REQUESTDURABLEFID_SIGNATURE, sizeof(REQUESTDURABLEFID_SIGNATURE) - 1);	/* name */
		cmBufferWriterAlign(&request.writer, request.header._start, 8);
		pTemp = cmBufferWriterGetPosition(&request.writer);
		offset = (NQ_UINT16)(pTemp - pStart);
		cmBufferWriterSetPosition(&request.writer, pDataOffset);
		cmBufferWriteUint16(&request.writer, offset);	/* element name offset again */
		cmBufferWriterSetPosition(&request.writer, pTemp);
		cmBufferWriteZeroes(&request.writer, sizeof(pFile->fid));	/* data */
		pTemp = cmBufferWriterGetPosition(&request.writer);
		contextLength = cmSmb2HeaderGetWriterOffset(&request.header, &request.writer) - contextOffset;
		cmBufferWriterSetPosition(&request.writer, pContextOffset);
		cmBufferWriteUint32(&request.writer, contextOffset);	/* context offset again */
		cmBufferWriteUint32(&request.writer, contextLength );	/* context length again */
		cmBufferWriterSetPosition(&request.writer, pTemp);
	}
	
	res = sendReceive(pServer, pShare->user, &request, &response);
	cmBufManGive(request.buffer);
	if (NQ_SUCCESS != res)
	{
		cmBufManGive(response.buffer);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
	}

	/* parse response */

	cmBufferReadByte(&response.reader, &pFile->oplockLevel);		/* oplock level */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_BYTE));		/* reserved */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT32));	/* create action */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT64));	/* creation time */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT64));	/* last access time */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT64));	/* last write time */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT64));	/* change time */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT64));	/* allocation size */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT64));	/* end of file */
	cmBufferReadUint32(&response.reader, &pFile->attributes);	/* attributes */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT32));	/* reserved 2 */
	cmBufferReadBytes(&response.reader, pFile->fid, sizeof(pFile->fid));	/* file ID */

	cmBufManGive(response.buffer);

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return NQ_SUCCESS;
}

static NQ_STATUS doCreate(CCFile * pFile)
{
    return create(pFile, TRUE);
}

static NQ_STATUS doRestoreHandle(CCFile * pFile)
{
	Request request;			/* request dscriptor */
	Response response;			/* response descriptor */
	CCServer * pServer;			/* server object pointer */
	CCShare * pShare;			/* share object pointer */
	NQ_BYTE * pNameOffset;		/* pointer to the name offset field */
	NQ_BYTE * pContextOffset;	/* pointer to the context offtset field */
	NQ_UINT32 contextOffset;	/* context offset */
	NQ_UINT32 contextLength;	/* context length */
	NQ_UINT16 nameOffset;		/* name offset */
	NQ_BYTE * pTemp;			/* temporary pointer in th writer */
	NQ_UINT16 nameLen;			/* name length in bytes (not including terminator) */
	NQ_STATUS res;				/* exchange result */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	pShare = pFile->share;
	pServer = pShare->user->server;
	if (!prepareSingleRequestByShare(&request, pShare, SMB2_CMD_CREATE))
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_OUTOFMEMORY;
	}
	
	/* compose request */
	writeHeader(&request);
	cmBufferWriteByte(&request.writer, 0);		/* security flags */
	cmBufferWriteByte(&request.writer, 0);		/* no oplock */
	cmBufferWriteUint32(&request.writer, 0);	/* impersonation */
	cmBufferWriteUint32(&request.writer, 0);	/* SMB create flags */
	cmBufferWriteUint32(&request.writer, 0);	/* SMB create flags */
	cmBufferWriteUint32(&request.writer, 0);	/* reserved */
	cmBufferWriteUint32(&request.writer, 0);	/* reserved */
	cmBufferWriteUint32(&request.writer, 0);	/* desired access */
	cmBufferWriteUint32(&request.writer, 0);	/* file attributes */
	cmBufferWriteUint32(&request.writer, 0);	/* shared access */
	cmBufferWriteUint32(&request.writer, 0);	/* create disposition */
	cmBufferWriteUint32(&request.writer, 0);		/* create options */
	pNameOffset = cmBufferWriterGetPosition(&request.writer);
	cmBufferWriterSkip(&request.writer, sizeof(NQ_UINT16));		/* name offset */
	nameLen = (NQ_UINT16)(sizeof(NQ_WCHAR) * cmWStrlen(pFile->item.name)); 
	cmBufferWriteUint16(&request.writer, nameLen);				/* name length */
	pContextOffset = cmBufferWriterGetPosition(&request.writer);
	cmBufferWriteUint32(&request.writer, 0);		/* context offset */
	cmBufferWriteUint32(&request.writer, 0);		/* context length */
	cmBufferWriterAlign(&request.writer, request.header._start, 8);
	
	/* place context */
 	contextOffset = cmSmb2HeaderGetWriterOffset(&request.header, &request.writer);
	{
		NQ_BYTE * pStart;			/* pointer to the element start */
		NQ_BYTE * pSignatureOffset;	/* pointer to name offset */
		NQ_BYTE * pDataOffset;		/* pointer to data offset */
		NQ_UINT16 offset;			/* name/data offset */
		
		pStart = cmBufferWriterGetPosition(&request.writer);
		cmBufferWriteUint32(&request.writer, 0);		/* chain offset - no more elements */
		pSignatureOffset = cmBufferWriterGetPosition(&request.writer);
		cmBufferWriteUint16(&request.writer, 0);		/* offset to element name */
		cmBufferWriteUint16(&request.writer, sizeof(RESTOREDURABLEFID_SIGNATURE) - 1);	/* element name length */
		cmBufferWriteUint16(&request.writer, 0);		/* reserved */
		pDataOffset = cmBufferWriterGetPosition(&request.writer);
		cmBufferWriteUint16(&request.writer, 0);		/* offset to element data */
		cmBufferWriteUint32(&request.writer, sizeof(pFile->fid));		/* element data length */
		pTemp = cmBufferWriterGetPosition(&request.writer);
		offset = (NQ_UINT16)(pTemp - pStart);
		cmBufferWriterSetPosition(&request.writer, pSignatureOffset);
		cmBufferWriteUint16(&request.writer, offset);	/* element name offset again */
		cmBufferWriterSetPosition(&request.writer, pTemp);
		cmBufferWriteBytes(&request.writer, (NQ_BYTE *)RESTOREDURABLEFID_SIGNATURE, sizeof(RESTOREDURABLEFID_SIGNATURE) - 1);	/* name */
		cmBufferWriterAlign(&request.writer, request.header._start, 8);
		pTemp = cmBufferWriterGetPosition(&request.writer);
		offset = (NQ_UINT16)(pTemp - pStart);
		cmBufferWriterSetPosition(&request.writer, pDataOffset);
		cmBufferWriteUint16(&request.writer, offset);	/* element name offset again */
		cmBufferWriterSetPosition(&request.writer, pTemp);
		cmBufferWriteBytes(&request.writer, pFile->fid, sizeof(pFile->fid));	/* data */
		pTemp = cmBufferWriterGetPosition(&request.writer);
		contextLength = cmSmb2HeaderGetWriterOffset(&request.header, &request.writer) - contextOffset;
		cmBufferWriterSetPosition(&request.writer, pContextOffset);
		cmBufferWriteUint32(&request.writer, contextOffset);	/* context offset again */
		cmBufferWriteUint32(&request.writer, contextLength );	/* context length again */
		cmBufferWriterSetPosition(&request.writer, pTemp);
	}

	/* name offset */
	cmBufferWriterAlign(&request.writer, request.header._start, 8);
 	nameOffset = (NQ_UINT16)cmSmb2HeaderGetWriterOffset(&request.header, &request.writer);
	pTemp = cmBufferWriterGetPosition(&request.writer);
	cmBufferWriterSetPosition(&request.writer, pNameOffset);
	cmBufferWriteUint16(&request.writer, nameOffset);			/* name offset again */
	cmBufferWriterSetPosition(&request.writer, pTemp);
	request.tail.data = (NQ_BYTE*)pFile->item.name;
	request.tail.len = nameLen; 

	res = sendReceive(pServer, pShare->user, &request, &response);
	cmBufManGive(request.buffer);
	if (NQ_SUCCESS != res)
	{
		cmBufManGive(response.buffer);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
	}

	/* parse response */

	cmBufferReaderSkip(&response.reader, sizeof(NQ_BYTE));		/* oplock level */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_BYTE));		/* reserved */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT32));	/* create action */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT64));	/* creation time */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT64));	/* last access time */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT64));	/* last write time */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT64));	/* change time */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT64));	/* allocation size */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT64));	/* end of file */
	cmBufferReadUint32(&response.reader, &pFile->attributes);	/* attributes */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT32));	/* reserved 2 */
	cmBufferReadBytes(&response.reader, pFile->fid, sizeof(pFile->fid));	/* file ID */

	cmBufManGive(response.buffer);

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return NQ_SUCCESS;
}

static NQ_STATUS doClose(CCFile * pFile)
{
	Request request;		/* request dscriptor */
	Response response;		/* response descriptor */
	CCServer * pServer;		/* server object pointer */
	CCShare * pShare;		/* share object pointer */
	NQ_STATUS res;			/* exchange result */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	pShare = pFile->share;
	pServer = pShare->user->server;
	if (!prepareSingleRequestByShare(&request, pShare, SMB2_CMD_CLOSE))
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_OUTOFMEMORY;
	}
	
	/* compose request */
	writeHeader(&request);
	cmBufferWriteUint16(&request.writer, 0);		/* flags */
	cmBufferWriteUint32(&request.writer, 0);		/* reserved */
	cmBufferWriteBytes(&request.writer, pFile->fid, sizeof(pFile->fid));		/* file ID */

	res = sendReceive(pServer, pShare->user, &request, &response);
	cmBufManGive(request.buffer);
	if (NQ_SUCCESS != res)
	{
		cmBufManGive(response.buffer);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
	}

	/* parse response - we ingnore response parameters */

	cmBufManGive(response.buffer);

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return NQ_SUCCESS;
}

static NQ_STATUS doQueryDfsReferrals(CCShare * share, const NQ_WCHAR * path, CCCifsParseReferral parser, CMList * list)
{
	Request request;		/* request dscriptor */
	Response response;		/* response descriptor */
	CCServer * pServer;		/* server object pointer */
	NQ_STATUS res;			/* exchange result */
	NQ_BYTE * pOffset;		/* pointer to the input offset field in the request */
	NQ_UINT32 offset;		/* offset relative to the header */
	NQ_BYTE * pTemp;		/* pointer in the buffer */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	pServer = share->user->server;
	if (!prepareSingleRequestByShare(&request, share, SMB2_CMD_IOCTL))
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_OUTOFMEMORY;
	}
	
	/* compose request */
	request.header.flags |= SMB2_FLAG_DFS_OPERATIONS;
	writeHeader(&request);
	cmBufferWriterSkip(&request.writer, sizeof(NQ_UINT16));		/* reserved */
	cmBufferWriteUint32(&request.writer, 0x00060194);			/* CtlCode: FSCTL_DFS_GET_REFERRALS */
	cmBufferWriteUint32(&request.writer, 0xFFFFFFFF);			/* file ID */
	cmBufferWriteUint32(&request.writer, 0xFFFFFFFF);			/* file ID */
	cmBufferWriteUint32(&request.writer, 0xFFFFFFFF);			/* file ID */
	cmBufferWriteUint32(&request.writer, 0xFFFFFFFF);			/* file ID */
	pOffset = cmBufferWriterGetPosition(&request.writer);
	cmBufferWriterSkip(&request.writer, sizeof(NQ_UINT32) * 5);	/* InputOffset/Count + MaxInputResponse + OutputOffset/Count */
	cmBufferWriteUint32(&request.writer, 4096);					/* MaxOutputResponse */
	cmBufferWriteUint32(&request.writer, 1);					/* flags: FSCTL */
	cmBufferWriteUint32(&request.writer, 0);					/* reserved */
	
	/* end if IOCTL header - start of IOCTL payload */
	offset = cmSmb2HeaderGetWriterOffset(&request.header, &request.writer);
	cmBufferWriteUint16(&request.writer, 4);					/* MaxReferralLevel */
	request.tail.data = (NQ_BYTE*)path;
	request.tail.len = (NQ_COUNT)(sizeof(NQ_WCHAR) * (1 + cmWStrlen(path)));
	
	pTemp = cmBufferWriterGetPosition(&request.writer);
	cmBufferWriterSetPosition(&request.writer, pOffset);
	cmBufferWriteUint32(&request.writer, offset);				/* InputOffset */
	cmBufferWriteUint32(&request.writer, (NQ_UINT32)(request.tail.len + sizeof(NQ_UINT16)));	/* InputCount */
	cmBufferWriteUint32(&request.writer, 0);					/* MaxInputResponse */
	cmBufferWriteUint32(&request.writer, offset);				/* OutputOffset */
	cmBufferWriteUint32(&request.writer, 0);					/* Count */
	cmBufferWriterSetPosition(&request.writer, pTemp);

	res = sendReceive(pServer, share->user, &request, &response);
	cmBufManGive(request.buffer);
	if (NQ_SUCCESS != res)
	{
		cmBufManGive(response.buffer);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
	}

	/* parse response */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT16));	/* reserved */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT32));	/* CtlCode */
	cmBufferReaderSkip(&response.reader, 16);					/* FileId */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT32) * 2);/* InputOffset + ImputCount */
	cmBufferReadUint32(&response.reader, &offset);				/* OutputOffset */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT32));	/* OutoutCount */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT32) * 2);/* flags + reserved */

	/* end of IOCTL and start of IOCTL payload */
	parser(&response.reader, list);
	
	cmBufManGive(response.buffer);

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return NQ_SUCCESS;
}

static NQ_STATUS doFindOpen(CCSearch * pSearch)
{
	Request request;			/* request dscriptor */
	Response response;			/* response descriptor */
	NQ_STATUS res;				/* exchange result */
	SearchContext * pContext;	/* casted pointer */
	NQ_WCHAR * dirName;			/* parent diretcory name */
	NQ_BYTE * pNameOffset;	/* pointer to the name offset field */
	NQ_UINT16 nameOffset;	/* name offset */
	NQ_BYTE * pTemp;		/* temporary pointer in th writer */
	NQ_UINT16 nameLen;		/* name length in bytes (not including terminator) */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
	
	/* create context */
	pContext = cmMemoryAllocate(sizeof(SearchContext));
	if (NULL == pContext)
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_OUTOFMEMORY;
	}
	pSearch->context = pContext;
	if (ccUtilsFilePathHasWildcards(pSearch->item.name))
	{
		dirName = ccUtilsFilePathStripWildcards(pSearch->item.name);
	}
	else
	{
		dirName = ccUtilsDirectoryFromPath(pSearch->item.name);
	}
	if (NULL == dirName)
	{
		cmMemoryFree(pContext);
		pSearch->context = NULL;
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_OUTOFMEMORY;
	}
		
	if (!prepareSingleRequestByShare(&request, pSearch->share, SMB2_CMD_CREATE))
	{
	    cmMemoryFree(pContext);
		pSearch->context = NULL;
    	cmMemoryFree(dirName);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_OUTOFMEMORY;
	}
	
	/* compose request */
	writeHeader(&request);
	cmBufferWriteByte(&request.writer, 0);		/* security flags */
	cmBufferWriteByte(&request.writer, 0);		/* batch oplock */
	cmBufferWriteUint32(&request.writer, 2);	/* impersonation */
	cmBufferWriteUint32(&request.writer, 0);	/* SMB create flags */
	cmBufferWriteUint32(&request.writer, 0);	/* SMB create flags */
	cmBufferWriteUint32(&request.writer, 0);	/* reserved */
	cmBufferWriteUint32(&request.writer, 0);	/* reserved */
	cmBufferWriteUint32(&request.writer, 0x00100081);	/* desired access */
	cmBufferWriteUint32(&request.writer, 0);			/* file attributes */
	cmBufferWriteUint32(&request.writer, 0x00000007);	/* shared access */
	cmBufferWriteUint32(&request.writer, 1);			/* open existing */
	cmBufferWriteUint32(&request.writer, 0x20);			/* sync operations */
	pNameOffset = cmBufferWriterGetPosition(&request.writer);
	cmBufferWriterSkip(&request.writer, sizeof(NQ_UINT16));		/* name offset */
	nameLen = (NQ_UINT16)(sizeof(NQ_WCHAR) * cmWStrlen(dirName)); 
	cmBufferWriteUint16(&request.writer, nameLen);				/* name length */
	cmBufferWriteUint32(&request.writer, 0);		/* context offset */
	cmBufferWriteUint32(&request.writer, 0);		/* context length */
	cmBufferWriterAlign(&request.writer, request.header._start, 8);
	nameOffset = (NQ_UINT16)cmSmb2HeaderGetWriterOffset(&request.header, &request.writer);
	pTemp = cmBufferWriterGetPosition(&request.writer);
	cmBufferWriterSetPosition(&request.writer, pNameOffset);
	cmBufferWriteUint16(&request.writer, nameOffset);			/* name offset again */
	cmBufferWriterSetPosition(&request.writer, pTemp);
	if (nameLen == 0)
        cmBufferWriteUint16(&request.writer, 0);		
	request.tail.data = (NQ_BYTE *)dirName;
	request.tail.len = nameLen; 

	res = sendReceive(pSearch->server, pSearch->share->user, &request, &response);
	cmMemoryFree(dirName);
	cmBufManGive(request.buffer);
	if (NQ_SUCCESS != res)
	{
	    cmMemoryFree(pContext);
		pSearch->context = NULL;
		cmBufManGive(response.buffer);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
	}

	/* parse response */

	cmBufferReaderSkip(&response.reader, sizeof(NQ_BYTE));		/* oplock level */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_BYTE));		/* reserved */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT32));	/* create action */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT64));	/* creation time */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT64));	/* last access time */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT64));	/* last write time */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT64));	/* change time */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT64));	/* allocation size */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT64));	/* end of file */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT32));	/* attributes */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT32));	/* reserved 2 */
	cmBufferReadBytes(&response.reader, pContext->fid, sizeof(pContext->fid));	/* file ID */

	cmBufManGive(response.buffer);

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return NQ_SUCCESS;
}

static NQ_STATUS doFindMore(CCSearch * pSearch)
{
	Request request;			/* request dscriptor */
	Response response;			/* response descriptor */
	SearchContext * pContext;	/* casted pointer */
	NQ_WCHAR * pattern;			/* search pattern */
	NQ_BYTE * pNameOffset;	/* pointer to the name offset field */
	NQ_UINT16 nameOffset;	/* name offset */
	NQ_BYTE * pTemp;		/* temporary pointer in th writer */
	NQ_UINT16 nameLen;		/* name length in bytes (not including terminator) */
	NQ_UINT32 outputLen;	/* output buffer length */
	NQ_STATUS res;			/* exchange result */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	pContext = pSearch->context;
	if (NULL == pContext)
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "Search context does not exists");
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_BADFID;
	}
	if (ccUtilsFilePathHasWildcards(pSearch->item.name))
	{
		pattern = ccUtilsFilePathGetWildcards(pSearch->item.name);
	}
	else
	{
		pattern = ccUtilsFileFromPath(pSearch->item.name);
	}
	if (NULL == pattern)
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_OUTOFMEMORY;
	}
	
	if (!prepareSingleRequestByShare(&request, pSearch->share, SMB2_CMD_QUERYDIRECTORY))
	{
    	cmMemoryFree(pattern);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_OUTOFMEMORY;
	}
	
	/* compose request */
	writeHeader(&request);
	cmBufferWriteByte(&request.writer, SMB2_FILEINFO_BOTHDIRECTORY);	/* info class */
	cmBufferWriteByte(&request.writer, pSearch->isFirst? 1 : 0); 		/* flags - restart */
	cmBufferWriteUint32(&request.writer, 0);							/* file index */
	cmBufferWriteBytes(&request.writer, pContext->fid, sizeof(pContext->fid)); /* file ID */
	pNameOffset = cmBufferWriterGetPosition(&request.writer);
	cmBufferWriterSkip(&request.writer, sizeof(NQ_UINT16));		/* name offset */
	nameLen = (NQ_UINT16)(sizeof(NQ_WCHAR) * cmWStrlen(pattern)); 
	cmBufferWriteUint16(&request.writer, nameLen);				/* name length */
	cmBufferWriteUint32(&request.writer, 65536);				/* outout buffer length */
	if (0 == nameLen)
	{
		nameOffset = 0;
	}
	else
	{
		nameOffset = (NQ_UINT16)cmSmb2HeaderGetWriterOffset(&request.header, &request.writer);
	}
	pTemp = cmBufferWriterGetPosition(&request.writer);
	cmBufferWriterSetPosition(&request.writer, pNameOffset);
	cmBufferWriteUint16(&request.writer, nameOffset);			/* name offset */
	cmBufferWriterSetPosition(&request.writer, pTemp);
	request.tail.data = (NQ_BYTE *)pattern;
	request.tail.len = nameLen; 

	res = sendReceive(pSearch->server, pSearch->share->user, &request, &response);
	cmMemoryFree(pattern);
	cmBufManGive(request.buffer);
	if (NQ_SUCCESS != res)
	{
		cmBufManGive(response.buffer);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
	}

	/* parse response */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT16));	/* output buffer offset */
	cmBufferReadUint32(&response.reader, &outputLen);			/* output buffer length */
	cmBufferReaderInit(
		&pSearch->parser,
		cmBufferReaderGetPosition(&response.reader),
		outputLen
		);
	
	pSearch->buffer = response.buffer;		/* to be released later */

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return NQ_SUCCESS;
}

static NQ_STATUS doFindClose(CCSearch * pSearch)
{
	Request request;			/* request dscriptor */
	Response response;			/* response descriptor */
	SearchContext * pContext;	/* casted pointer */
	NQ_STATUS res;			/* exchange result */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	pContext = pSearch->context;
	if (NULL == pContext)
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "Search context does not exists");
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_BADFID;
	}

	if (!prepareSingleRequestByShare(&request, pSearch->share, SMB2_CMD_CLOSE))
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_OUTOFMEMORY;
	}
	
	/* compose request */
	writeHeader(&request);
	cmBufferWriteUint16(&request.writer, 0);		/* flags */
	cmBufferWriteUint32(&request.writer, 0);		/* reserved */
	cmBufferWriteBytes(&request.writer, pContext->fid, sizeof(pContext->fid));	/* file ID */

	res = sendReceive(pSearch->server, pSearch->share->user, &request, &response);
	cmBufManGive(request.buffer);
	if (NQ_SUCCESS != res)
	{
		cmBufManGive(response.buffer);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
	}

	/* parse response - we ingnore response parameters */

	cmBufManGive(response.buffer);

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return NQ_SUCCESS;
}

static void writeCallback(CCServer * pServer, Match * pContext)
{
	WriteMatch * pMatch = (WriteMatch *)pContext;	/* casted pointer */
	NQ_BYTE buffer[20];								/* buffer for structure */
	NQ_UINT tailLen = pServer->transport.recv.remaining;	/* bytes remaining */
	Response * pResponse = pContext->response;				/* response structure ptr */
	NQ_UINT32 count = 0;     								/* bytes written */
    NQ_TIME     currentTime;                    /* Current Time for checking timed-out responses*/

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	/* receive the rest of command */
	if (tailLen != ccTransportReceiveBytes(&pServer->transport, buffer, tailLen))
	{
    	ccTransportReceiveEnd(&pServer->transport);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return;
	}
    ccTransportReceiveEnd(&pServer->transport);
	cmBufferReaderInit(&pResponse->reader, buffer, tailLen);

	/* parse the response */
	if (NQ_SUCCESS == pResponse->header.status)
	{
		cmBufferReaderSkip(&pResponse->reader, sizeof(NQ_UINT16));	/* reserved */
		cmBufferReadUint32(&pResponse->reader, &count);	/* count */
	}
    currentTime = (NQ_TIME)syGetTime();

    /* call up */
	if ((pMatch->timeCreated + pMatch->setTimeout) > currentTime)
    {
	    pMatch->callback(pResponse->header.status == 0? 0 : (NQ_STATUS)ccErrorsStatusToNq(pResponse->header.status, TRUE), count, pMatch->context);
    }
	/* release context */
	cmMemoryFree(pMatch->match.response);
    cmListItemDispose((CMItem *)pMatch);

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

static NQ_STATUS doWrite(CCFile * pFile, const NQ_BYTE * data, NQ_UINT bytesToWrite, CCCifsWriteCallback callback, void * context)
{
	Request         request;			/* request descriptor */
	NQ_BYTE     *   pDataOffset;		/* pointer to the data offset field */
	NQ_UINT16       dataOffset;		    /* value in this field */
	NQ_STATUS       res;				/* exchange result */
	NQ_BYTE     *   pTemp;				/* temporary pointer in the writer */
	WriteMatch  *   pMatch;		        /* sync to response */
    CCServer    *   pServer;            /*pointer to server*/

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    if (!prepareSingleRequestByShare(&request, pFile->share, SMB2_CMD_WRITE))
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_OUTOFMEMORY;
	}

    pServer = pFile->share->user->server;
    
	/* compose request */
	writeHeader(&request);
	pDataOffset = cmBufferWriterGetPosition(&request.writer);
	cmBufferWriterSkip(&request.writer, sizeof(NQ_UINT16));		/* data offset */
	cmBufferWriteUint32(&request.writer, bytesToWrite);			/* length */
	cmBufferWriteUint64(&request.writer, &pFile->offset);		/* offset */
	cmBufferWriteBytes(&request.writer, pFile->fid, sizeof(pFile->fid));	/* file ID */
	cmBufferWriteUint32(&request.writer, 0);					/* channel */
	cmBufferWriteUint32(&request.writer, 0);					/* remaining bytes */
	cmBufferWriteUint16(&request.writer, 0);					/* write channel info offset */
	cmBufferWriteUint16(&request.writer, 0);					/* write channel info length */
	cmBufferWriteUint32(&request.writer, 0);					/* flags */
	dataOffset = (NQ_UINT16)cmSmb2HeaderGetWriterOffset(&request.header, &request.writer);
	pTemp = cmBufferWriterGetPosition(&request.writer);
	cmBufferWriterSetPosition(&request.writer, pDataOffset);
	cmBufferWriteUint16(&request.writer, dataOffset);			/* data offset */
	cmBufferWriterSetPosition(&request.writer, pTemp);
	request.tail.data = (NQ_BYTE *)data;
	request.tail.len = bytesToWrite;

	pMatch = (WriteMatch *)cmListItemCreate(sizeof(WriteMatch), NULL, FALSE);
	if (NULL == pMatch)
	{
	    cmBufManGive(request.buffer);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_OUTOFMEMORY;
	}
	pMatch->match.response = (Response *)cmMemoryAllocate(sizeof(Response));
	if (NULL == pMatch->match.response)
	{
    	cmBufManGive(request.buffer);
		cmMemoryFree(pMatch);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_OUTOFMEMORY;
	}
	pMatch->match.server = pFile->share->user->server;
    pMatch->timeCreated = (NQ_TIME)syGetTime();
    pMatch->setTimeout = ccConfigGetTimeout();
	pMatch->callback = callback;
	pMatch->context = context;
    pMatch->match.cond = NULL;
	cmListItemAdd(&pServer->expectedResponses, (CMItem *)pMatch, NULL);

	res = sendRequest(pFile->share->user->server, pFile->share->user, &request, &pMatch->match);
	cmBufManGive(request.buffer);
	if (NQ_SUCCESS != res)
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
	}
	
	/* responses are processed in the callback */

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return NQ_SUCCESS;
}

static void readCallback(CCServer * pServer, Match * pContext)
{
#define READSTRUCT_SIZE 14
	ReadMatch * pMatch = (ReadMatch *)pContext;		/* casted pointer */
	NQ_BYTE buffer[64];								/* buffer for structure and padding */
	Response * pResponse = pContext->response;		/* response structure ptr */
	NQ_UINT32 count = 0;							/* bytes read */
	NQ_BYTE offset;									/* data offset */
    NQ_TIME     currentTime;                    /* Current Time for checking timed-out responses*/

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	/* receive the structure but not the buffer (payload) */
	if (READSTRUCT_SIZE == ccTransportReceiveBytes(&pServer->transport, buffer, READSTRUCT_SIZE))
	{
		/* parse the response */
		cmBufferReaderInit(&pResponse->reader, buffer, sizeof(buffer));
		if (NQ_SUCCESS == pResponse->header.status)
		{
			cmBufferReadByte(&pResponse->reader, &offset);				/* data offset */
			cmBufferReaderSkip(&pResponse->reader, sizeof(NQ_BYTE));	/* reserved */
			cmBufferReadUint32(&pResponse->reader, &count);	/* data length */
		    offset = (NQ_BYTE)(offset - (SMB2_HEADERSIZE + 16));	/* bytes to skip */
		    if (offset > 0 )
		    {
			    ccTransportReceiveBytes(&pServer->transport, buffer, (NQ_COUNT)offset);	/* read padding */
		    }
		    ccTransportReceiveBytes(&pServer->transport, pMatch->buffer, count);	/* read into application buffer */
		}
	}
	else
	{
		count = 0;
	}
    ccTransportReceiveEnd(&pServer->transport);

	currentTime = (NQ_TIME)syGetTime();

    /* call up */
	if ((pMatch->timeCreated + pMatch->setTimeout) > currentTime)
    {
        pMatch->callback(pResponse->header.status == 0? 0 : (NQ_STATUS)ccErrorsStatusToNq(pResponse->header.status, TRUE), count, pMatch->context, count < pMatch->count);
    }
	/* release */
	cmMemoryFree(pMatch->match.response);
    cmListItemDispose((CMItem *)pMatch);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

static NQ_STATUS doRead(CCFile * pFile, const NQ_BYTE * buffer, NQ_UINT bytesToRead, CCCifsReadCallback callback, void * context)
{
	Request         request;			/* request descriptor */
	NQ_STATUS       res;				/* exchange result */
	ReadMatch   *   pMatch;		        /* sync to response */
    CCServer    *   pServer;            /* pointer to server*/

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	if (!prepareSingleRequestByShare(&request, pFile->share, SMB2_CMD_READ))
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_OUTOFMEMORY;
	}

    pServer = pFile->share->user->server;
     
	/* compose request */
	writeHeader(&request);
	cmBufferWriteByte(&request.writer, 0x50);					/* padding */
	cmBufferWriteByte(&request.writer, 0);						/* reserved */
	cmBufferWriteUint32(&request.writer, bytesToRead);			/* length */
	cmBufferWriteUint64(&request.writer, &pFile->offset);		/* offset */
	cmBufferWriteBytes(&request.writer, pFile->fid, sizeof(pFile->fid));	/* file ID */
	cmBufferWriteUint32(&request.writer, 0);					/* min count */
	cmBufferWriteUint32(&request.writer, 0);					/* channel */
	cmBufferWriteUint32(&request.writer, 0);					/* remaining bytes */
	cmBufferWriteUint16(&request.writer, 0);					/* write channel info offset */
	cmBufferWriteUint16(&request.writer, 0);					/* write channel info length */
	cmBufferWriteByte(&request.writer, 0);						/* buffer */

	pMatch = (ReadMatch *)cmListItemCreate(sizeof(ReadMatch), NULL , FALSE);
	if (NULL == pMatch)
	{
    	cmBufManGive(request.buffer);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_OUTOFMEMORY;
	}
	pMatch->match.response = (Response *)cmMemoryAllocate(sizeof(Response));
	if (NULL == pMatch->match.response)
	{
    	cmBufManGive(request.buffer);
		cmMemoryFree(pMatch);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_OUTOFMEMORY;
	}
	pMatch->match.server = pFile->share->user->server;
    pMatch->timeCreated = (NQ_TIME)syGetTime();
    pMatch->setTimeout = ccConfigGetTimeout();
	pMatch->callback = callback;
	pMatch->context = context;
	pMatch->count = bytesToRead;
	pMatch->buffer = (NQ_BYTE *)buffer;
    pMatch->match.cond = NULL;
	cmListItemAdd(&pServer->expectedResponses, (CMItem *)pMatch, NULL);

	res = sendRequest(pFile->share->user->server, pFile->share->user, &request, &pMatch->match);
	cmBufManGive(request.buffer);
	if (NQ_SUCCESS != res)
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
	}
	
	/* responses are processed in the callback */

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return NQ_SUCCESS;
}

#ifdef UD_CC_INCLUDESECURITYDESCRIPTORS	

static NQ_STATUS doQuerySecurityDescriptor(CCFile * pFile, CMSdSecurityDescriptor * sd)
{
	Request request;		/* request dscriptor */
	Response response;		/* response descriptor */
	CCServer * pServer;		/* server object pointer */
	NQ_STATUS res;			/* exchange result */
	NQ_UINT32 responseSize;	/* required response size */
	CMRpcPacketDescriptor in;	/* for parsing SD */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	pServer = pFile->share->user->server;
	
	/* query with zero buffer to get SD length */
	res = writeQueryInfoRequest(&request, pFile, SMB2_INFO_SECURITY, 0, 0, SMB2_SIF_OWNER | SMB2_SIF_GROUP | SMB2_SIF_DACL);
	if (NQ_SUCCESS != res)
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
	}
	request.tail.data = NULL;
	request.tail.len = 0;
	
	res = sendReceive(pServer, pFile->share->user, &request, &response);
	cmBufManGive(request.buffer);

	if (NQ_ERR_MOREDATA != res)
	{
		cmBufManGive(response.buffer);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
	}

	/* parse error response */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT16));	/* offset */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT32));	/* length - should be 4 */
	cmBufferReadUint32(&response.reader, &responseSize);		/* required buffer size */
	cmBufManGive(response.buffer);

	if (responseSize > UD_CS_SECURITYDESCRIPTORLENGTH)
	{
		LOGERR(CM_TRC_LEVEL_FUNC_COMMON," requested buffer size (%d) is larger then maximal SD buffer (%d)" , responseSize , UD_CS_SECURITYDESCRIPTORLENGTH);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
	}
	/* query with required buffer */
	res = writeQueryInfoRequest(&request, pFile, SMB2_INFO_SECURITY, 0, responseSize, SMB2_SIF_OWNER | SMB2_SIF_GROUP | SMB2_SIF_DACL);
	if (NQ_SUCCESS != res)
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
	}
	request.tail.data = NULL;
	request.tail.len = 0;
	
	res = sendReceive(pServer, pFile->share->user, &request, &response);
	cmBufManGive(request.buffer);
	
	if (NQ_SUCCESS != res)
	{
		cmBufManGive(response.buffer);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
	}

	/* parse response */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT16));	/* offset */
	cmBufferReadUint32(&response.reader, &sd->length);	/* length */
	cmRpcSetDescriptor(&in, cmBufferReaderGetPosition(&response.reader), FALSE);
	cmSdParseSecurityDescriptor(&in, sd);			/* security descriptor */
	cmBufManGive(response.buffer);
	

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return NQ_SUCCESS;
}

static NQ_STATUS doSetSecurityDescriptor(CCFile * pFile, const CMSdSecurityDescriptor * sd)
{
	Request request;		/* request dscriptor */
	Response response;		/* response descriptor */
	CCServer * pServer;		/* server object pointer */
	NQ_STATUS res;			/* exchange result */
	CMRpcPacketDescriptor out;	/* for packing SD */
	NQ_BYTE * sdBuffer;			/* buffer for packing SD - the same size as SD itself */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	pServer = pFile->share->user->server;
	sdBuffer = cmBufManTake(sd->length + 32);
	if (NULL == sdBuffer)
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_OUTOFMEMORY;
	}
	
	/* compose request */
	cmRpcSetDescriptor(&out, sdBuffer, FALSE);
	cmSdPackSecurityDescriptor(&out, sd);
	res = writeSetInfoRequest(
		&request, 
		pFile, 
		SMB2_INFO_SECURITY, 
		0, 
		SMB2_SIF_OWNER | SMB2_SIF_GROUP | SMB2_SIF_DACL, 
		(NQ_UINT32)(out.current - sdBuffer)
		);
	if (NQ_SUCCESS != res)
	{
		cmBufManGive(sdBuffer);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
	}
	
	request.tail.data = sdBuffer;
	request.tail.len = (NQ_COUNT)(out.current - sdBuffer);
	
	res = sendReceive(pServer, pFile->share->user, &request, &response);
	cmBufManGive(request.buffer);
	cmBufManGive(sdBuffer);

	if (NQ_SUCCESS != res)
	{
		cmBufManGive(response.buffer);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
	}

	/* parse response */

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return NQ_SUCCESS;
}

#endif /* UD_CC_INCLUDESECURITYDESCRIPTORS */

static NQ_STATUS doQueryFileInfoByHandle(CCFile * pFile, CCCifsParseFileInfoCallback callback, void * context)
{
	Request request;		/* request dscriptor */
	Response response;		/* response descriptor */
	CCServer * pServer;		/* server object pointer */
	NQ_STATUS res;			/* exchange result */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	pServer = pFile->share->user->server;

	/* compose request */
	res = writeQueryInfoRequest(
		&request, 
		pFile, 
		SMB2_INFO_FILE, 
		SMB2_FILEINFO_ALLINFORMATION, 
		MAXINFORESPONSE_SIZE, 
		0 /*cmBufferWriterGetRemaining(&request.writer)*/
		);
	if (NQ_SUCCESS != res)
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
	}
	
	request.tail.data = NULL;
	request.tail.len = 0;
	
	res = sendReceive(pServer, pFile->share->user, &request, &response);
	cmBufManGive(request.buffer);

	if (NQ_SUCCESS != res)
	{
		cmBufManGive(response.buffer);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
	}

	/* parse response */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT16) + sizeof(NQ_UINT32));
	(*callback)(&response.reader, context);

	cmBufManGive(response.buffer);

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return NQ_SUCCESS;
}

static NQ_STATUS doQueryFileInfoByName(CCShare * pShare, const NQ_WCHAR * fileName, CCCifsParseFileInfoCallback callback, void * context)
{
	NQ_STATUS res;			/* exchange result */
	CCFile file;			/* open file */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	file.accessMask = 0x100080;
	file.attributes = 0;
	file.disposition = 1;
	file.options = 0;
	file.share = pShare;
	file.sharedAccess = 0;
	file.item.name = cmMemoryCloneWString(fileName);
	if (NULL == file.item.name)
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_OUTOFMEMORY;
	}
	res = create(&file, TRUE);
	if (NQ_SUCCESS != res)
	{
		cmMemoryFree(file.item.name);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
	}
	
	doQueryFileInfoByHandle(&file, callback, context);
	
	doClose(&file);

	cmMemoryFree(file.item.name);

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return NQ_SUCCESS;
}

static NQ_STATUS doQueryFsInfo(CCShare * pShare, CCVolumeInfo * pInfo)
{
	Request request;		/* request dscriptor */
	Response response;		/* response descriptor */
	CCServer * pServer;		/* server object pointer */
	NQ_STATUS res;			/* exchange result */
	NQ_UINT64 temp64;		/* for parsing 64-bit values */
	NQ_UINT32 temp32;		/* for parsing 32-bit values */
	CCFile file;			/* open file */
	static NQ_WCHAR nullFile[] = { 0 };	/* empty file name */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	request.tail.data = NULL;
	request.tail.len = 0;

	pServer = pShare->user->server;

	file.accessMask = 0x1000a1;
	file.attributes = 0;
	file.disposition = 1;
	file.options = 0x21;
	file.share = pShare;
	file.sharedAccess = SMB2_SHAREACCESS_DELETE | SMB2_SHAREACCESS_READ | SMB2_SHAREACCESS_WRITE;
	file.item.name = nullFile;
	res = create(&file, FALSE);
	if (NQ_SUCCESS != res)
	{
		cmMemoryFree(file.item.name);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
	}
	
	/* compose FsSizeInformation request */
	res = writeQueryInfoRequest(
		&request, 
		&file, 
		SMB2_INFO_FILESYSTEM, 
		SMB2_FSINFO_SIZE, 
		MAXINFORESPONSE_SIZE, 
		0 /*cmBufferWriterGetRemaining(&request.writer)*/
		);
	if (NQ_SUCCESS != res)
	{
		doClose(&file);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
	}
	
	res = sendReceive(pServer, pShare->user, &request, &response);
	cmBufManGive(request.buffer);
	if (NQ_SUCCESS != res)
	{
		doClose(&file);
		cmBufManGive(response.buffer);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
	}

	/* parse response */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT16) + sizeof(NQ_UINT32));
	cmBufferReadUint64(&response.reader, &temp64);	/* total allocation units */
	pInfo->totalClusters = temp64.low;
	cmBufferReadUint64(&response.reader, &temp64);	/* available allocation units */
	pInfo->freeClusters = temp64.low;
	cmBufferReadUint32(&response.reader, &temp32);	/* sectors per allocation unit */
	pInfo->sectorsPerCluster = (NQ_UINT)temp32;
	cmBufferReadUint32(&response.reader, &temp32);	/* bytes per sectors */
	pInfo->bytesPerSector = (NQ_UINT)temp32;
	cmBufManGive(response.buffer);

	/* compose FsVolumeInformation request */
	res = writeQueryInfoRequest(
		&request, 
		&file, 
		SMB2_INFO_FILESYSTEM, 
		SMB2_FSINFO_VOLUME, 
		MAXINFORESPONSE_SIZE, 
		0/*cmBufferWriterGetRemaining(&request.writer)*/
		);
	if (NQ_SUCCESS != res)
	{
		doClose(&file);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
	}
	
	res = sendReceive(pServer, pShare->user, &request, &response);
	cmBufManGive(request.buffer);
	doClose(&file);
	if (NQ_SUCCESS != res)
	{
		cmBufManGive(response.buffer);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
	}

	/* parse response */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT16) + sizeof(NQ_UINT32));
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT64));	/* creation time */
	cmBufferReadUint32(&response.reader, &temp32);				/* volume serial number */
	pInfo->serialNumber = (NQ_UINT)temp32;
	cmBufManGive(response.buffer);

	pInfo->fsType = 0;	/* MS Servers always return 0 */
	
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return NQ_SUCCESS;
}

static NQ_STATUS doSetFileAttributes(CCFile * pFile, NQ_UINT32 attributes)
{
	Request request;		/* request dscriptor */
	Response response;		/* response descriptor */
	CCServer * pServer;		/* server object pointer */
	NQ_STATUS res;			/* exchange result */
	static const NQ_UINT64 doNotChange = 
	{ 0xFFFFFFFF, 0xFFFFFFFF };	/* the "do-not-change" value in the time fields */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	pServer = pFile->share->user->server;

	/* compose request */
	res = writeSetInfoRequest(
		&request, 
		pFile, 
		SMB2_INFO_FILE, 
		SMB2_FILEINFO_BASIC, 
		0, 
		40		/* basic info size */
		);
	if (NQ_SUCCESS != res)
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
	}
	
	cmBufferWriteUint64(&request.writer, &doNotChange);	/* creation time */
	cmBufferWriteUint64(&request.writer, &doNotChange);	/* last access time */
	cmBufferWriteUint64(&request.writer, &doNotChange);	/* last write time */
	cmBufferWriteUint64(&request.writer, &doNotChange);	/* change time */
	cmBufferWriteUint32(&request.writer, attributes);	/* file attributes */
	cmBufferWriteUint32(&request.writer, 0);			/* reserved */
	request.tail.data = NULL;
	request.tail.len = 0;
	
	res = sendReceive(pServer, pFile->share->user, &request, &response);
	cmBufManGive(request.buffer);

	if (NQ_SUCCESS != res)
	{
		cmBufManGive(response.buffer);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
	}

	/* parse response */
	cmBufManGive(response.buffer);

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return NQ_SUCCESS;
}

static NQ_STATUS doSetFileSize(CCFile * pFile, NQ_UINT64 size)
{
	Request request;		/* request dscriptor */
	Response response;		/* response descriptor */
	CCServer * pServer;		/* server object pointer */
	NQ_STATUS res;			/* exchange result */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	pServer = pFile->share->user->server;

	/* compose request */
	res = writeSetInfoRequest(
		&request, 
		pFile, 
		SMB2_INFO_FILE, 
		SMB2_FILEINFO_EOF, 
		0, 
		8		/* eof info size */
		);
	if (NQ_SUCCESS != res)
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
	}
	
	cmBufferWriteUint64(&request.writer, &size);	/* end of file */
	request.tail.data = NULL;
	request.tail.len = 0;
	
	res = sendReceive(pServer, pFile->share->user, &request, &response);
	cmBufManGive(request.buffer);

	if (NQ_SUCCESS != res)
	{
		cmBufManGive(response.buffer);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
	}

	/* parse response */
	cmBufManGive(response.buffer);

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return NQ_SUCCESS;
}

static NQ_STATUS doSetFileTime(CCFile * pFile, NQ_UINT64 creationTime, NQ_UINT64 lastAccessTime, NQ_UINT64 lastWriteTime)
{
	Request request;		/* request dscriptor */
	Response response;		/* response descriptor */
	CCServer * pServer;		/* server object pointer */
	NQ_STATUS res;			/* exchange result */
	static const NQ_UINT64 doNotChange = 
	{ 0xFFFFFFFF, 0xFFFFFFFF };	/* the "do-not-change" value in the time fields */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	pServer = pFile->share->user->server;

	/* compose request */
	res = writeSetInfoRequest(
		&request, 
		pFile, 
		SMB2_INFO_FILE, 
		SMB2_FILEINFO_BASIC, 
		0, 
		40		/* basic info size */
		);
	if (NQ_SUCCESS != res)
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
	}
	
	cmBufferWriteUint64(&request.writer, &creationTime);	/* creation time */
	cmBufferWriteUint64(&request.writer, &lastAccessTime);	/* last access time */
	cmBufferWriteUint64(&request.writer, &lastWriteTime);	/* last write time */
	cmBufferWriteUint64(&request.writer, &doNotChange);		/* change time */
	cmBufferWriteUint32(&request.writer, 0);				/* file attributes */
	cmBufferWriteUint32(&request.writer, 0);				/* reserved */
	request.tail.data = NULL;
	request.tail.len = 0;
	
	res = sendReceive(pServer, pFile->share->user, &request, &response);
	cmBufManGive(request.buffer);

	if (NQ_SUCCESS != res)
	{
		cmBufManGive(response.buffer);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
	}

	/* parse response */
	cmBufManGive(response.buffer);

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return NQ_SUCCESS;
}

static NQ_STATUS doSetFileDeleteOnClose(CCFile * pFile)
{
	Request request;		/* request dscriptor */
	Response response;		/* response descriptor */
	CCServer * pServer;		/* server object pointer */
	NQ_STATUS res;			/* exchange result */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	pServer = pFile->share->user->server;

	/* compose request */
	res = writeSetInfoRequest(
		&request, 
		pFile, 
		SMB2_INFO_FILE, 
		SMB2_FILEINFO_DISPOSITION, 
		0, 
		1		/* basic info size */
		);
	if (NQ_SUCCESS != res)
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
	}
	
	cmBufferWriteByte(&request.writer, 1);	/* delete pending */
	request.tail.data = NULL;
	request.tail.len = 0;
	
	res = sendReceive(pServer, pFile->share->user, &request, &response);
	cmBufManGive(request.buffer);

	if (NQ_SUCCESS != res)
	{
		cmBufManGive(response.buffer);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
	}

	/* parse response */
	cmBufManGive(response.buffer);

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return NQ_SUCCESS;
}

static NQ_STATUS doRename(CCFile * pFile, const NQ_WCHAR * newName)
{
	Request request;		/* request dscriptor */
	Response response;		/* response descriptor */
	CCServer * pServer;		/* server object pointer */
	NQ_STATUS res;			/* exchange result */
	NQ_UINT32 nameLen;		/* name length */
    NQ_UINT32    dataLen;

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	pServer = pFile->share->user->server;
    
    nameLen = (NQ_UINT32)(sizeof(NQ_WCHAR) * cmWStrlen(newName));
    dataLen = nameLen+20;
    
	/* compose request */
	res = writeSetInfoRequest(
		&request, 
		pFile, 
		SMB2_INFO_FILE, 
		SMB2_FILEINFO_RENAME, 
		0, 
		dataLen		/* info size */
		);
	if (NQ_SUCCESS != res)
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
	}
	
	cmBufferWriteByte(&request.writer, 0);		/* replace exists == false */
	cmBufferWriterSkip(&request.writer, 7);		/* reserved */
	cmBufferWriteZeroes(&request.writer, 8);	/* root directory */
	cmBufferWriteUint32(&request.writer, nameLen);	/* file name length */
	request.tail.data = (NQ_BYTE *)newName;
	request.tail.len = nameLen;
	
	res = sendReceive(pServer, pFile->share->user, &request, &response);
	cmBufManGive(request.buffer);

	if (NQ_SUCCESS != res)
	{
		cmBufManGive(response.buffer);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
	}

	/* parse response */
	cmBufManGive(response.buffer);

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return NQ_SUCCESS;
}

static NQ_STATUS doFlush(CCFile * pFile)
{
	Request request;		/* request dscriptor */
	Response response;		/* response descriptor */
	CCServer * pServer;		/* server object pointer */
	CCShare * pShare;		/* share object pointer */
	NQ_STATUS res;			/* exchange result */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	pShare = pFile->share;
	pServer = pShare->user->server;
	if (!prepareSingleRequestByShare(&request, pShare, SMB2_CMD_FLUSH))
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_OUTOFMEMORY;
	}
	
	/* compose request */
	writeHeader(&request);
	cmBufferWriteUint16(&request.writer, 0);		/* reserved1 */
	cmBufferWriteUint32(&request.writer, 0);		/* reserved2 */
	cmBufferWriteBytes(&request.writer, pFile->fid, sizeof(pFile->fid));		/* file ID */

	res = sendReceive(pServer, pFile->share->user, &request, &response);
	cmBufManGive(request.buffer);
	if (NQ_SUCCESS != res)
	{
		cmBufManGive(response.buffer);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
	}

	/* parse response - we ingnore response parameters */

	cmBufManGive(response.buffer);

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return NQ_SUCCESS;
}

static 	NQ_STATUS doRapTransaction(void * pShare, const CMBlob * inData, CMBlob * outData)
{
    return NQ_ERR_NOSUPPORT;
}


static NQ_STATUS  doEcho(CCShare * pShare)
{
    Request     request;
    Response    response;
    CCServer  * pServer;
    CCUser    * pUser;
    NQ_STATUS   res;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
    
    pUser = pShare->user;
    pServer = pUser->server;
    
    if (!prepareSingleRequestByShare(&request, pShare, SMB2_CMD_ECHO))
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_OUTOFMEMORY;
	}

    writeHeader(&request);
    cmBufferWriteUint16(&request.writer, 0);		/* reserved1 */

    res = sendReceive(pServer, pUser, &request, &response);
    cmBufManGive(request.buffer);
    if (NQ_SUCCESS != res)
	{
		cmBufManGive(response.buffer);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
	}
    
    cmBufManGive(response.buffer);
    
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return NQ_SUCCESS;
}

#endif /* UD_NQ_INCLUDESMB2 */
#endif /* UD_NQ_INCLUDECIFSCLIENT */

