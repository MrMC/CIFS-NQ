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
#include "cctrans.h"
#include "nqapi.h"

#ifdef UD_NQ_INCLUDECIFSCLIENT

/* -- Static data, functions and constants -- */

#define MAXREQUEST_SIZE	4096	/* maximum request packet size */
#define getByteParams(wp) \
    ((CMCifsByteBlock *) ((NQ_BYTE *) (wp) + \
    cmCifsSizeofWordParam((NQ_UINT)((wp)->count * 2))))

static const NQ_BYTE sDefaultHeader[] = {
    0xFF, 'S', 'M', 'B',                 /* Contains 0xFF,'SMB' */
    0xFF,                                /* Command code */
    0x00,                                /* Error class */
    0x00,                                /* Reserved for future use */
    0x00, 0x00,                          /* Error code */

    0x18,                                /* Flags */
    0x01, 0x00,                          /* More flags */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                         /* 12 bytes padding */
    0xFF, 0xFF,                          /* Tree identifier */
    0x00, 0x00,                          /* Caller's process id */
    0x00, 0x00,                          /* Unauthenticated user id */
    0x00, 0x00                           /* Multiplex id */
};

static CMCifsHeader * getPacket(CMCifsWordBlock ** cmdWordParams)
{
    CMCifsHeader * smbPacket;	/* pointer to request packet after NBT header */
    NQ_BYTE * packet;			/* pointer to NBT packet */
    
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    packet = cmMemoryAllocate(MAXREQUEST_SIZE);
    if (NULL == packet)
    {
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    	return NULL;
    }
    smbPacket = (CMCifsHeader *)nsSkipHeader(NULL, packet);
    syMemcpy(smbPacket, sDefaultHeader, sizeof(CMCifsHeader));
    *cmdWordParams = (CMCifsWordBlock *)(smbPacket + 1);

    cmPutSUint16(smbPacket->tid, 0);
    cmPutSUint16(smbPacket->pid, 0);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return smbPacket;
}

/* -- API functions -- */

CMCifsTransactionRequest * ccTransGetCmdPacket(NQ_BYTE ** parameters, NQ_BYTE setupCount)
{
    CMCifsWordBlock * wordParams;
    CMCifsByteBlock * byteParams;
    CMCifsTransactionRequest  * transCmd;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    /* Get the command packet */
    if (NULL == getPacket(&wordParams))
    {
    	return NULL;
    }

    wordParams->count = (NQ_BYTE)(SMB_TRANSACTION_REQUEST_WORDCOUNT + setupCount);
    byteParams = getByteParams(wordParams);
    *parameters = byteParams->data;
    transCmd = (CMCifsTransactionRequest *) wordParams;
    transCmd->setupCount = setupCount;

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return transCmd;
}

void ccTransPutCmdPacket(CMCifsTransactionRequest * packet)
{
	NQ_BYTE * head;			/* packet head */
	
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    head = ((NQ_BYTE *)packet - sizeof(CMCifsHeader)) - 4;
    
    cmMemoryFree(head);
    
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

#ifdef UD_NQ_USETRANSPORTNETBIOS

NQ_STATUS ccTransSendTo(
    NSSocketHandle socket,
    CMNetBiosNameInfo* dstName,
    CMCifsTransactionRequest *transCmd,
    NQ_UINT16 transOffset,
    NQ_UINT *paramCount,
    NQ_BYTE *cmdParameters,
    NQ_UINT *dataCount,
    NQ_BYTE *cmdData,
    NQ_UINT maxParamCount
)
{
    CMCifsHeader * cifsHeader;          /* pointer to SMB header */
    CMCifsWordBlock * wordParams;       /* pointer to the request words */
    CMCifsByteBlock * byteParams;       /* pointer to the request bytes */
    NQ_BYTE * dataEnd;                  /* end of the packet pointer */
    NQ_UINT16 byteCount;                /* number of packet bytes */
    NSSocketSet readList;               /* select subject */
    NQ_BYTE dummyBuf[2];                /* dummy buffer for reading extra responses */
    CMNetBiosNameInfo dummySrc;         /* source name for reading extra responses */
    NQ_BOOL exit = FALSE;               /* flag for exiting extra response cycle */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    /* Before transmitting a request datagram we need to cleanup the socket. 
       This is essential when one request (the previous one) gets multiple responses from 
       various hosts. 
     */

    nsClearSocketSet(&readList);
    nsAddSocketToSet(&readList, socket);

    while (!exit)
    {
        switch(nsSelect(&readList, 0))      /* will hit data only when it is already on the socket */
        {
            case 0:
                exit = TRUE;        /* no more */
                break;
            case NQ_FAIL:
                LOGERR(CM_TRC_LEVEL_ERROR, "Select error");
                LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                return syGetLastError();
            default:
                nsRecvFromName(socket, dummyBuf, sizeof(dummyBuf), &dummySrc);
        }
    }


    wordParams = (CMCifsWordBlock *) (transCmd);
    byteParams = (CMCifsByteBlock *) (cmdParameters - 2);
    cifsHeader = (CMCifsHeader *) ((NQ_BYTE *) wordParams - sizeof(CMCifsHeader));

    /* wordParams->wordCount += trans_cmd->SetupCount; */

    /* Fill the CIFS header */
    cifsHeader->command = SMB_COM_TRANSACTION;
    cmPutSUint16(cifsHeader->pid, 0);
    cmPutSUint16(cifsHeader->tid, 0);
    cmPutSUint16(cifsHeader->mid, 0);
    cmPutSUint16(cifsHeader->uid, 0);

    /* Encode transaction header fields */
    cmPutSUint16(transCmd->maxParameterCount, cmHtol16((NQ_UINT16) maxParamCount));
    cmPutSUint16(transCmd->maxDataCount, 0);

    cmPutSUint16(transCmd->parameterCount, cmHtol16((NQ_UINT16)(*paramCount - transOffset)));
    cmPutSUint16(transCmd->parameterOffset, cmHtol16((NQ_UINT16)((cmdParameters - (NQ_BYTE *)cifsHeader) + transOffset)));
    cmPutSUint16(transCmd->totalParameterCount, cmGetSUint16(transCmd->parameterCount));
    if (cmdData != NULL)
    {
        cmPutSUint16(transCmd->dataCount, cmHtol16((NQ_UINT16) *dataCount));
        cmPutSUint16(transCmd->dataOffset, cmHtol16((NQ_UINT16) (cmdData - (NQ_BYTE *) cifsHeader)));
        cmPutSUint16(transCmd->totalDataCount, cmGetSUint16(transCmd->dataCount));
    }

    byteCount = (NQ_UINT16)(*paramCount + ((cmdData != NULL) ? *dataCount : 0));
    cmPutSUint16(byteParams->count, cmHtol16(byteCount));
    dataEnd = byteParams->data + byteCount;
    transCmd->maxSetupCount = transCmd->setupCount;

    if (nsSendToName(socket, (const NQ_BYTE*)cifsHeader, (NQ_UINT)(dataEnd - (NQ_BYTE*)cifsHeader), dstName) == NQ_FAIL)
    {
        NQ_INT e = syGetLastError();
        nsClose(socket);
        LOGERR(CM_TRC_LEVEL_ERROR, "Error sending transaction frame");
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return e;
    }

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return NQ_ERR_OK;
}

NQ_STATUS ccTransReceiveFrom(
    NSSocketHandle socket,
    CMNetBiosNameInfo * srcName,
    NQ_UINT * paramCount,
    NQ_BYTE ** rspParameters,
    NQ_UINT * dataCount,
    NQ_BYTE ** rspData,
    NQ_BYTE ** buffer
    )
{
	NQ_BYTE * pBuffer;						/* buffer for response */
	CMCifsHeader * cifsHeader;				/* pointer to SMB header in the buffer */
    CMCifsWordBlock * wordParams;			/* pointer to word params in the buffer */
    CMCifsTransactionRequest * transRsp;	/* pointer to trunsaction response */
    NQ_UINT16 transDataCount;               /* data count */
    NQ_UINT16 transParamsCount;             /* parameter count */
    NQ_UINT16 transDataOffset;              /* data offset */
    NQ_UINT16 transParamsOffset;            /* parameter offset */
    NSSocketSet readList;                   /* select subject */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

#define MAXBUFFER_SIZE 64534
    *buffer = NULL;
    pBuffer = cmMemoryAllocate(MAXBUFFER_SIZE);
    if (NULL == pBuffer)
	{
		sySetLastError(NQ_ERR_NOMEM);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_NOMEM;
	}
	cifsHeader = (CMCifsHeader *)pBuffer;
    wordParams = (CMCifsWordBlock *) (pBuffer + sizeof(CMCifsHeader));

    nsClearSocketSet(&readList);
    nsAddSocketToSet(&readList, socket);

    switch(nsSelect(&readList, ccConfigGetTimeout()))
    {
        case 0:
            cmMemoryFree(pBuffer);
            LOGERR(CM_TRC_LEVEL_ERROR, "select() timeout");
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return NQ_ERR_TIMEOUT;
        case NQ_FAIL:
            cmMemoryFree(pBuffer);
            LOGERR(CM_TRC_LEVEL_ERROR, "Select error");
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return syGetLastError();
        default:
            break;
    }

    if (nsRecvFromName(socket, (NQ_BYTE*)cifsHeader, MAXBUFFER_SIZE, srcName) == NQ_FAIL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Error receiving transaction frame");
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return syGetLastError();
    }

    /* some servers answer on Transaction REquest format */
    transRsp = (CMCifsTransactionRequest *) wordParams;
    transDataCount =  cmLtoh16(cmGetSUint16(transRsp->dataCount));
    transDataOffset =  cmLtoh16(cmGetSUint16(transRsp->dataOffset));
    transParamsCount =  cmLtoh16(cmGetSUint16(transRsp->parameterCount));
    transParamsOffset =  cmLtoh16(cmGetSUint16(transRsp->parameterOffset));
    
    if (rspParameters != NULL)
    {
        *paramCount = transParamsCount;
        *rspParameters = (NQ_BYTE *) cifsHeader + transParamsOffset;
    }

    if (rspData != NULL)
    {
        *dataCount = transDataCount;
        *rspData = (NQ_BYTE *) cifsHeader + transDataOffset;
    }
    *buffer = pBuffer;

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return NQ_ERR_OK;
}

#endif /* UD_NQ_USETRANSPORTNETBIOS */

#endif
