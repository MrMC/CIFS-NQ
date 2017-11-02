/*********************************************************************
 *
 *           Copyright (c) 2005 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : DCERPC library for CIFS Client
 *--------------------------------------------------------------------
 * DEPENDENCIES  : None
 *--------------------------------------------------------------------
 * CREATION DATE : 3-Sep-2005
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "ccdcerpc.h"
#include "ccserver.h"
#include "ccshare.h"
#include "ccfile.h"
#include "cmbufman.h"
#include "cmrpcdef.h"

#ifdef UD_NQ_INCLUDECIFSCLIENT

/* --- Static definitions, functions & data --- */

#define NOPAYLOAD_BUFFERSIZE 1024	/* buffer size for messages with no call payload */ 
#define MAX_FRAGMENT 65448			/* max fragment size for calls */ 

static NQ_COUNT callId;     /* running number */

static const CMRpcDcerpcSyntaxId transferSyntax = {
    CM_RPC_TRANSFERSYNTAXSIGNATURE,
    CM_RPC_NDRVERSION
};

/* build fragment header in a buffer (no PDU yet) */

static NQ_BYTE * createFragmentHeader(CMBufferWriter * pWriter, NQ_BYTE type, NQ_UINT16 fragLength, NQ_BYTE fragType)
{
	NQ_BYTE * pFragLength;			/* pointer to the fragment length field */
	
	cmBufferWriteByte(pWriter, CM_RP_MAJORVERSION);	/* major vers */
	cmBufferWriteByte(pWriter, CM_RP_MINORVERSION);	/* minor vers */
	cmBufferWriteByte(pWriter, type);				/* packet type (e.g. - bind) */
	cmBufferWriteByte(pWriter, fragType);			/* flags */
	cmBufferWriteByte(pWriter, CM_RP_DREPLE);		/* data representation: LE byte order */
	cmBufferWriteByte(pWriter, 0);					/* data representation: float point */
	cmBufferWriteUint16(pWriter, 0);					/* data representation pad */
	pFragLength = cmBufferWriterGetPosition(pWriter);
	cmBufferWriteUint16(pWriter, fragLength);		/* fragment length */
	cmBufferWriteUint16(pWriter, 0);					/* auth length */
	cmBufferWriteUint32(pWriter, callId);			/* call ID */
    callId++;
    return pFragLength;
}

/* update fragment length in the header */

static void setFragmentLength(CMBufferWriter * pWriter, NQ_BYTE * pFragLength)
{
	NQ_BYTE * pTemp;			/* temporary pointer in the writer */
	NQ_UINT16 fragLength;		/* fragment length */
	
	fragLength = (NQ_UINT16)cmBufferWriterGetDataCount(pWriter);	
	pTemp = cmBufferWriterGetPosition(pWriter);
	cmBufferWriterSetPosition(pWriter, pFragLength);
	cmBufferWriteUint16(pWriter, fragLength);		/* fragment length */
	cmBufferWriterSetPosition(pWriter, pTemp);
}

/* parse response fragment header and fill PDU descriptor */
static NQ_INT parseFragmentHeader(const NQ_BYTE * data, CMRpcPacketDescriptor * pDesc, CMRpcDcerpcPacket * pPack)
{
	pPack->rpcVers = *data;						/* RPC version */ 
	pPack->rpcVersMinor = *(data + 1);			/* RPC minor version */
	pPack->packetType = *(data + 2);			/* packet type */
	pPack->pfcFlags = *(data + 3);				/* packet flags */
	pPack->drep.flags = *(data + 4);			/* data representation: flags - byte order */
	/* now we have byte order so that we can build descriptor */
	cmRpcSetDescriptor(pDesc, (NQ_BYTE *)data, 0 == (pPack->drep.flags & CM_RP_DREPLE));
	cmRpcParseSkip(pDesc, 5);					/* already parsed */
	cmRpcParseByte(pDesc, &pPack->drep.fp);		/* data representation: float point */
	cmRpcParseUint16(pDesc, (NQ_UINT16 *)&pPack->drep.pad);	/* data representation: padding */
	cmRpcParseUint16(pDesc, (NQ_UINT16 *)&pPack->fragLength);/* fragment length */
	cmRpcParseUint16(pDesc, (NQ_UINT16 *)&pPack->authLength);/* auth length */
	cmRpcParseUint32(pDesc, (NQ_UINT32 *)&pPack->callId);	/* call ID */
    return pPack->packetType;
}

NQ_HANDLE connectPipe(const NQ_WCHAR * hostName, const AMCredentialsW * pCredentials, const CCDcerpcPipeDescriptor * pipeDesc, NQ_BOOL doDfs)
{
    CCServer * pServer = NULL;  	    /* pointer to server */
    CCShare * pShare = NULL;		    /* pointer to IPC$ share */
	CCFile * pFile;		                /* file handle */
	CMRpcDcerpcPacket rpcHeader;   	    /* fragment header */
	CMRpcPacketDescriptor rpcDescr;	    /* incoming packet parser */
    CMBufferWriter writer;  		    /* writer for bind PDU */
    NQ_BYTE * pBuf;					    /* read and write buffer */
    NQ_COUNT dataLen;				    /* buffer length or data length into the buffer */
    NQ_BYTE * pFragLength;			    /* pointer to the fragment length field in the header */
    NQ_UINT16 maxLen;				    /* max fragment length (either xmit or recv) */
    NQ_INT type;					    /* packet type in response */
    NQ_BOOL security[] = {TRUE, FALSE}; /* whether to use extended security */
    NQ_INT i;                           /* just a counter */
    NQ_WCHAR * rpcNamePrefixed;         /* RPC pipe name with prefix */
#define RPC_OPENACCESS 0x2019f          /* access mask for opening an RPC pipe as a file */ 

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    /* open file */
    for (i = 0; i < sizeof(security)/sizeof(security[0]); i++)
    {
        const AMCredentialsW * oldCredentials = pCredentials;       /* saved credentials */ 
        const AMCredentialsW * newCredentials = oldCredentials;     /* try these credentials first */

    	pServer = ccServerFindOrCreate(hostName, security[i], NULL);
	    if (NULL != pServer)
        {
            pShare = ccShareConnectIpc(pServer, &newCredentials);
            if (newCredentials != oldCredentials)
            {
                /* new credentials were allocated */
                cmMemoryFree(newCredentials);
            }
	        if (NULL != pShare)
	        {   
	            cmListItemUnlock((CMItem *)pServer);
                break;
    	    }
            cmListItemUnlock((CMItem *)pServer);
        }
    }
    
    if (NULL == pShare)
    {
	    sySetLastError(NQ_ERR_SRVERROR);
	    LOGERR(CM_TRC_LEVEL_ERROR, "Unable to connect to server");
	    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	    return NULL;
    }

    rpcNamePrefixed = cmMemoryAllocate((NQ_UINT)((cmWStrlen (pipeDesc->name) + cmWStrlen(pServer->smb->rpcNamePrefix) + 1 ) * sizeof(NQ_WCHAR)));
    if (NULL == rpcNamePrefixed)
    {
	    sySetLastError(NQ_ERR_NOMEM);
	    LOGERR(CM_TRC_LEVEL_ERROR, "Unable to connect to server");
	    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	    return NULL;
    }
    syWStrcpy(rpcNamePrefixed, pServer->smb->rpcNamePrefix);
    syWStrcat(rpcNamePrefixed, pipeDesc->name);
    pFile = ccFileCreateOnServer(
				pShare, 
				rpcNamePrefixed, 
				FALSE,
				RPC_OPENACCESS, 
				FILE_SM_DENY_NONE,
				0,
				FALSE,
				0,
				FILE_CA_FAIL,
				FILE_OA_OPEN,
				TRUE
				);
    cmMemoryFree(rpcNamePrefixed);
	if (NULL == pFile)
	{
	    cmListItemUnlock((CMItem *)pShare);
		LOGERR(CM_TRC_LEVEL_ERROR, "Unable to connect to %s", cmWDump(pipeDesc->name));
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NULL;
	}
    cmListItemUnlock((CMItem *)pShare);
	/* allocate buffer of enough size for both request and response */
	pBuf = cmBufManTake(NOPAYLOAD_BUFFERSIZE);
	if (NULL == pBuf)
	{
		sySetLastError(NQ_ERR_OUTOFMEMORY);
		LOGERR(CM_TRC_LEVEL_ERROR, "Unable to allocate buffer");
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NULL;
	}
	
	/* compose Bind request */
	/*   header */ 
	dataLen = NOPAYLOAD_BUFFERSIZE;
    cmBufferWriterInit(&writer, pBuf, dataLen);
    pFragLength = createFragmentHeader(
					&writer, 
					CM_RP_PKT_BIND, 
					0,
					CM_RP_PFCFLAG_FIRST | CM_RP_PFCFLAG_LAST
	    );
    /*   build Bind PDU without context */
    cmBufferWriteUint16(&writer, (NQ_UINT16)MAX_FRAGMENT);  /* max xmit fragment */
    cmBufferWriteUint16(&writer, (NQ_UINT16)MAX_FRAGMENT); 	/* max recv fragment */
    cmBufferWriteUint32(&writer, 0);           				/* assocGroupId */
    cmBufferWriteByte(&writer, 1);             				/* num contexts */
    cmBufferWriterAlign(&writer, pBuf, 4);
    /*   buld context */
    cmBufferWriteUint16(&writer, 0);                   		/* context ID */
    cmBufferWriteByte(&writer, 1);                     		/* num transfer syntaxes */
    cmBufferWriterAlign(&writer, pBuf, 4);
    cmBufferWriteUuid(&writer, &pipeDesc->uuid);            /* pipe GUID */
    cmBufferWriteUint32(&writer, pipeDesc->version);    /* major/minor version */
    cmBufferWriteUuid(&writer, &transferSyntax.uuid);  		/* transfer syntax signature */
    cmBufferWriteUint32(&writer, transferSyntax.interfaceVersion);  /* transfer syntax version */
    /*   update fragment length */
    setFragmentLength(&writer, pFragLength);
    dataLen = cmBufferWriterGetDataCount(&writer);

    /* bind the pipe */
    if (!ccWriteFile(pFile, pBuf, dataLen, &dataLen))
    {
        cmBufManGive(pBuf);
		LOGERR(CM_TRC_LEVEL_ERROR, "Error sending Bind request");
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NULL;
    }
    
    /* analyse the response */
    if (!ccReadFile(pFile, pBuf, NOPAYLOAD_BUFFERSIZE, &dataLen))
    {
        cmBufManGive(pBuf);
		LOGERR(CM_TRC_LEVEL_ERROR, "Error receiving Bind response");
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NULL;
    }
    type = parseFragmentHeader(pBuf, &rpcDescr, &rpcHeader);
    if (type != CM_RP_PKT_BINDACK)
    {
        cmBufManGive(pBuf);
		LOGERR(CM_TRC_LEVEL_ERROR, "Unable to bind to the pipe");
        sySetLastError(NQ_ERR_BADACCESS);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NULL;
    }
    cmRpcParseUint16(&rpcDescr, &maxLen);		/* max xmit gragment length */
    pFile->maxRpcXmit = maxLen > MAX_FRAGMENT ? MAX_FRAGMENT : maxLen;
    cmRpcParseUint16(&rpcDescr, &maxLen);		/* max recv gragment length */
    pFile->maxRpcRecv = maxLen > MAX_FRAGMENT ? MAX_FRAGMENT : maxLen;
    
    cmBufManGive(pBuf);
    
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return (NQ_HANDLE)pFile;
}

/* -- API functions -- */

NQ_BOOL ccDcerpcStart(void)
{
	callId = 1;
	return TRUE;
}

void ccDcerpcShutdown(void)
{
	
}

NQ_HANDLE ccDcerpcConnect(const NQ_WCHAR * hostName, const AMCredentialsW * pCredentials, const CCDcerpcPipeDescriptor * pipeDesc, NQ_BOOL doDfs)
{
    NQ_HANDLE handle;           /* resulting handle */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
    handle = connectPipe(hostName, NULL != pCredentials ? pCredentials : ccUserGetAnonymousCredentials(), pipeDesc, doDfs);
    if (NULL == handle)
    {
        handle = connectPipe(hostName, NULL, pipeDesc, doDfs);
    }
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return handle;
}

NQ_BOOL ccDcerpcCall(NQ_HANDLE pipeHandle, CCDcerpcRequestCallback request, CCDcerpcResponseCallback response, void * callParams)
{
	CCFile * pFile;		        /* casted file handle */
    NQ_BOOL res = TRUE;         /* operation result */
    NQ_BOOL firstFrag = TRUE;   /* whether fragment is the first one */
	NQ_BYTE * pBuf;				/* read and write buffer */
    NQ_COUNT dataLen;			/* buffer length or data length into the buffer */
    NQ_BOOL moreData;			/* whether application has more data */
    NQ_STATUS status;			/* status of callback execution */
    NQ_COUNT pduLen;			/* PDU length applied by the caller (in callback) */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	/* allocate buffer of enough size for the request */
	pFile = (CCFile *)pipeHandle;
    dataLen = pFile->maxRpcXmit;
	pBuf = cmBufManTake(dataLen);
	if (NULL == pBuf)
	{
		sySetLastError(NQ_ERR_OUTOFMEMORY);
		LOGERR(CM_TRC_LEVEL_ERROR, "Unable to allocate buffer");
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return FALSE;
	}

    do 
    {
        CMBufferWriter writer;  		/* writer for bind PDU */
        NQ_BYTE fragType;				/* first and/or last flags */

        /* build header (just to skip it) and build Request PDU stub data */
    	cmBufferWriterInit(&writer, pBuf, dataLen);
        createFragmentHeader(&writer, CM_RP_PKT_REQUEST, 0, 0);
        cmBufferWriteUint32(&writer, 0);     /* alloc hint */
        cmBufferWriteUint16(&writer, 0);     /* context id */

        /* place stub data */
        moreData = FALSE;
        pduLen = (*request)(
					cmBufferWriterGetPosition(&writer), 
					dataLen - cmBufferWriterGetDataCount(&writer),
					callParams,
					&moreData
					);
        if (pduLen == 0)
        {
        	sySetLastError(NQ_ERR_OUTOFMEMORY);
        	res = FALSE;
        	break;
        }
        
        /* re-build header and set fragment length */
        fragType = 0;
        if (firstFrag)
        {
        	fragType |= CM_RP_PFCFLAG_FIRST;
        	firstFrag = FALSE;
        }
        if (!moreData)
        {
        	fragType |= CM_RP_PFCFLAG_LAST;
        }
        dataLen = cmBufferWriterGetDataCount(&writer) + pduLen;
        cmBufferWriterSetPosition(&writer, pBuf);
        createFragmentHeader(&writer, CM_RP_PKT_REQUEST, (NQ_UINT16)dataLen, fragType);
    	res = ccWriteFile(pipeHandle, pBuf, dataLen, &dataLen);
    } 
    while(res && moreData);

    cmBufManGive(pBuf);
    
    if (!res)
    {
    	LOGERR(CM_TRC_LEVEL_ERROR, "Error sending request");
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return FALSE;
    }

	/* allocate buffer of enough size for the response */
	pFile = (CCFile *)pipeHandle;
    dataLen = pFile->maxRpcRecv;
	pBuf = cmBufManTake(dataLen);
	if (NULL == pBuf)
	{
		sySetLastError(NQ_ERR_OUTOFMEMORY);
		LOGERR(CM_TRC_LEVEL_ERROR, "Unable to allocate buffer");
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return FALSE;
	}
	
	/* loop on sending Read(AndX) SMB */
    do
    {
    	CMRpcPacketDescriptor rpcDescr;	/* incoming packet parser */
    	CMRpcDcerpcPacket rpcHeader;   	/* fragment header */
    	NQ_BYTE cancelCount;			/* cancel count from PDU */
        NQ_INT type;					/* packet type in response */
    	           		   
        res = ccReadFile(pipeHandle, pBuf, pFile->maxRpcRecv, &dataLen);
        if (!res)
        {
        	break;
        }
        /* parse header and withdraw packet type */
        type = parseFragmentHeader(pBuf, &rpcDescr, &rpcHeader);
        if (type != CM_RP_PKT_RESPONSE)
        {
        	LOGERR(CM_TRC_LEVEL_ERROR, "Received packet is not Response");
            sySetLastError(NQ_ERR_BADPARAM);
            res = FALSE;
            break;
        }

        /* parse PDU */
        cmRpcParseSkip(&rpcDescr, 4 + 2);   /* alloc hint + context id */
        cmRpcParseByte(&rpcDescr, &cancelCount);
        if (0 != cancelCount)
        {
        	LOGERR(CM_TRC_LEVEL_ERROR, "Packet received with cancel count: %d", cancelCount);
            sySetLastError(NQ_ERR_BADPARAM);
            res = FALSE;
            break;
        }

        /* withdraw stub data */
        moreData = (0 == (rpcHeader.pfcFlags & CM_RP_PFCFLAG_LAST));
        cmRpcAllign(&rpcDescr, 2);
        status = (*response)(rpcDescr.current, (NQ_COUNT)(rpcHeader.fragLength) - (NQ_COUNT)(rpcDescr.current - rpcDescr.origin), callParams, moreData);
        if (NQ_SUCCESS != status)
        {
        	sySetLastError((NQ_UINT32)status);
        	res = FALSE;
        	break;
        }
    }
    while (moreData && res);

    cmBufManGive(pBuf);
    
    if (NQ_FAIL == dataLen)
    {
    	LOGERR(CM_TRC_LEVEL_ERROR, "Error receiving response");
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return FALSE;
    }

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return res;
}

NQ_STATUS ccDcerpcDisconnect(NQ_HANDLE pipeHandle)
{
    return ccCloseHandle(pipeHandle);
}

#endif /* UD_NQ_INCLUDECIFSCLIENT */
