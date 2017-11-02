/*********************************************************************
 *
 *           Copyright (c) 2005 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : SRVSVC functions for CIFS Client
 *--------------------------------------------------------------------
 * DEPENDENCIES  : None
 *--------------------------------------------------------------------
 * CREATION DATE : 22-Sep-2005
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "ccsrvsvc.h"
#include "ccdcerpc.h"

#ifdef UD_NQ_INCLUDECIFSCLIENT

/*
 * Static data and definitions
 */ 

#define NETRSHAREENUM_OPNUM 15                      /* NetrShareEnum */
#define NETRSHAREINFO_OPNUM 0x10                    /* NetGetShareInfo */
#define MAXSHARE_LEN 100                            /* max length of share name */
#define SHARESTRUCT_LEN   (3 * 4)   /* length of share struct */

/* parameters share enumeration for callbacks */

typedef struct
{
    const NQ_WCHAR * hostName;                  /* server name */
    NQ_UINT state;                              /* parse state (see below) */
    NQ_UINT32 numShares;                        /* number of shares in response */
    NQ_COUNT sharesParsed;                      /* number of shares already parsed */
    NQ_COUNT bytesToDo;                         /* number of bytes to skip or copy at the beginning of next portion */
    NQ_BOOL stuctParsed;                        /* TRUE when share structures were already parsed */
    NQ_UINT32 strDesc[3];                       /* current string descriptor */
    NQ_BYTE* pData;                             /* pointer to the currently parsed data in either strDesc or currentName */
    CCSrvsvcEnumerateCallback callBack;         /* callback function for placing one share name */
    void* params;                               /* parameters for this callback */
} NetrShareEnumParams;

/* parameters share for information callbacks */

typedef struct
{
    const NQ_WCHAR * serverName;                /* host name */
    const NQ_WCHAR * shareName;                 /* share name */
    NQ_UINT32 type;                             /* share type */
    NQ_BYTE *remark;                            /* share remark */
    NQ_INT maxRemarkSize;                       /* buffer size for the share remark */
    NQ_BOOL unicodeResult;                      /* if TRUE then the share remark is returned in UNICODE */
    NQ_BOOL result;                             /* TRUE if succeeded */
} NetShareInfoParams;

/* buffer for parsing share name and its protection */
static SYMutex guard;
static NQ_WCHAR currentName[MAXSHARE_LEN];

/* parse state values */
#define STATE_START     1   /* before parsing */
#define STATE_STRUCT    2   /* parsing structures */
#define STATE_NAMEDESC  3   /* parsing name desriptor */
#define STATE_NAME      4   /* parsing name */
#define STATE_COMMENTDESC  5   /* parsing comment desriptor */
#define STATE_COMMENT      6   /* parsing comment */

/* share enumeration request callback */

NQ_COUNT                /* count of outgoing data */
netShareEnumRequestCallback (
    NQ_BYTE* buffer,    /* ougoing data buffer */
    NQ_COUNT size,      /* room in the buffer */
    void* params,       /* abstract parameters */
    NQ_BOOL* moreData   /* put here TRUE when more outgoing data available */
    );

/* share enumeration response callback */

NQ_STATUS                   /* NQ_SUCCESS or error code */
netShareEnumResponseCallback (
    const NQ_BYTE* data,    /* data portion pointer */
    NQ_COUNT size,          /* data portion size */
    void* params,           /* abstract parameters */
    NQ_BOOL moreData        /* TRUE when more data available */
    );

/* share information request callback */

NQ_COUNT                /* count of outgoing data */
netShareInfoRequestCallback (
    NQ_BYTE* buffer,    /* ougoing data buffer */
    NQ_COUNT size,      /* room in the buffer */
    void* params,       /* abstract parameters */
    NQ_BOOL* moreData   /* put here TRUE when more outgoing data available */
    );

/* share information response callback */

NQ_STATUS                   /* NQ_SUCCESS or error code */
netShareInfoResponseCallback (
    const NQ_BYTE* data,    /* data portion pointer */
    NQ_COUNT size,          /* data portion size */
    void* params,           /* abstract parameters */
    NQ_BOOL moreData        /* TRUE when more data available */
    );

/* pipe descriptor */
static const NQ_WCHAR pipeName[] = { cmWChar('s'), cmWChar('r'), cmWChar('v'), cmWChar('s'), cmWChar('v'), cmWChar('c'), cmWChar(0) };
static const CCDcerpcPipeDescriptor pipeDescriptor =
{ pipeName,
  {cmPack32(0x4b324fc8),cmPack16(0x1670),cmPack16(0x01d3),{0x12,0x78},{0x5a,0x47,0xbf,0x6e,0xe1,0x88}},
  cmRpcVersion(3, 0)
};

/* -- API functions -- */

NQ_BOOL ccSrvsvcStart()
{
	syMutexCreate(&guard);
	return TRUE;
}

void ccSrvsvcShutdown()
{
	syMutexDelete(&guard);
}

void ccSrvsvcLock()
{
	syMutexTake(&guard);
}

void ccSrvsvcUnlock()
{
	syMutexGive(&guard);
}

/*====================================================================
 * PURPOSE: Return this pipe descriptor
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: Pipe descriptor
 *
 * NOTES:
 *====================================================================
 */

const CCDcerpcPipeDescriptor * ccSrvsvcGetPipe(
    void
    )
{
    return &pipeDescriptor;
}

/*====================================================================
 * PURPOSE: Start enumerating list of shares over a previously opened
 *          pipe
 *--------------------------------------------------------------------
 * PARAMS:  IN pipe handle
 *          IN server host name
 *          IN callback for getting next share name
 *          IN pointer to callback parameters
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:   Sends SRVSVC NetrShareEnum request with SHARE_INFO_1 leve;.
 *          Since we are interested in share names only, we skip all
 *          SHARE_INFO_1 structures in response until the first name.
 *          Then we parse share names, skipping comments. On each share
 *          name the callback function is called.
 *====================================================================
 */

NQ_STATUS
ccSrvsvcEnumerateShares(
    NQ_HANDLE pipeHandle,
    const NQ_WCHAR* hostName,
    CCSrvsvcEnumerateCallback callback,
    void* callParams
    )
{
    NQ_COUNT res;               /* response byte count */
    NetrShareEnumParams params; /* parameters for callbacks */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    /* setup parameters */
    params.hostName = hostName;
    params.callBack = callback;
    params.params = callParams;
    params.bytesToDo = 0;
    params.numShares = 0;
    params.sharesParsed = 0;
    params.stuctParsed = 0;
    params.state = STATE_START;

    res = (NQ_COUNT)ccDcerpcCall(pipeHandle, netShareEnumRequestCallback, netShareEnumResponseCallback, &params);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return res? NQ_SUCCESS : NQ_FAIL;
}

/*====================================================================
 * PURPOSE: DCERPC request callback function for share enumeration
 *--------------------------------------------------------------------
 * PARAMS:  OUT buffer for outgoing data
 *          IN buffer size
 *          IN/OUT params
 *          OUT set here TRUE when more data remains
 *
 * RETURNS: number of bytes placed into the buffer or
 *          zero on buffer overflow
 *
 * NOTES:   Composes request
 *====================================================================
 */

NQ_COUNT netShareEnumRequestCallback(NQ_BYTE* buffer, NQ_COUNT size, void * params, NQ_BOOL* moreData)
{
    CMRpcPacketDescriptor desc;         /* descriptor for SRVSVC request */
    NQ_UINT32 refId;                    /* running referent ID */
    NetrShareEnumParams* callParams;    /* casted parameters for callback */
    NQ_WCHAR * hostName;				/* hostname prefixed */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    callParams = (NetrShareEnumParams*)params;
    hostName = cmMemoryAllocate((NQ_UINT)(sizeof(NQ_WCHAR) * (cmWStrlen(callParams->hostName) + 4)));
    if (NULL == hostName)
    {
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    	return NQ_ERR_OUTOFMEMORY;
    }
    refId = 1;
    cmRpcSetDescriptor(&desc, buffer, FALSE);
    cmRpcPackUint16(&desc, NETRSHAREENUM_OPNUM);
    desc.origin = desc.current;     /* for alligment to 4 bytes */
    cmRpcPackUint32(&desc, refId);
    refId++;
    cmAnsiToUnicode(hostName, "\\\\");
    cmWStrcpy(hostName + 2, callParams->hostName);
    cmRpcPackUnicode(&desc, hostName, (CM_RP_SIZE32 | CM_RP_FRAGMENT32 | CM_RP_NULLTERM));
    cmRpcPackUint32(&desc, 1);   /* info level 1 */
    cmRpcPackUint32(&desc, 1);   /* info level 1 (once again) */
    cmRpcPackUint32(&desc, refId);
    refId++;
    cmRpcPackUint32(&desc, 0);   /* share count */
    cmRpcPackUint32(&desc, 0);   /* null referent */
    cmRpcPackUint32(&desc, (NQ_UINT32)-1);  /* max length - unlimited */
    cmRpcPackUint32(&desc, 0);   /* null enum handle */
    *moreData = FALSE;
    
    cmMemoryFree(hostName);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return (NQ_COUNT)((desc.current - desc.origin) + 2);
}


/*====================================================================
 * PURPOSE: DCERPC response callback function for share enumeration
 *--------------------------------------------------------------------
 * PARAMS:  IN data portion
 *          IN data length in the portion
 *          IN/OUT params
 *          IN TRUE when more data to come
 *
 * RETURNS: NQ_SUCCESS or error code
 *
 * NOTES:   Parses share names
 *====================================================================
 */

NQ_STATUS
netShareEnumResponseCallback(
    const NQ_BYTE* data,
    NQ_COUNT size,
    void* params,
    NQ_BOOL moreData
    )
{
    CMRpcPacketDescriptor desc;         /* descriptor for SRVSVC request */
    NetrShareEnumParams* callParams;    /* casted parameters for callback */
    NQ_UINT32 value;                    /* parsed long value */
    NQ_UINT32 len;                      /* name length in bytes including padding */
    NQ_BYTE* savedPtr;                  /* saved pointer of the descriptor */
    
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
   
    callParams = (NetrShareEnumParams*)params;
    cmRpcSetDescriptor(&desc, (NQ_BYTE*)data, FALSE);
    
    while (TRUE)
    {
        switch (callParams->state)
        {
            case STATE_START:
                if (size < 6 * 4)   /* portion too small */
                {
                    LOGERR(CM_TRC_LEVEL_ERROR, "The 1st portion of NetrShareEnum response is too small");
                    TRC1P("  size: %d", size);
                    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                    return NQ_ERR_GETDATA;
                }
                cmRpcParseUint32(&desc, &value); /* info level */
                if (1 != value)                  /* unexpected info level */
                {
                    LOGERR(CM_TRC_LEVEL_ERROR, "Unexpect info level");
                    TRC1P("  expected 1, value: %ld", value);
                    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                    return NQ_ERR_GETDATA;
                }
                cmRpcParseUint32(&desc, &value); /* info level (once again)*/
                if (1 != value)                  /* unexpected info level */
                {
                    LOGERR(CM_TRC_LEVEL_ERROR, "Unexpect info level");
                    TRC1P("  expected 1, value: %ld", value);
                    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                    return NQ_ERR_GETDATA;
                }
                cmRpcParseUint32(&desc, &value); /* ref id for response container */
                cmRpcParseUint32(&desc, &callParams->numShares); /* num entries */
                cmRpcParseUint32(&desc, &value); /* ref id for share array */
                cmRpcParseUint32(&desc, &value); /* max count */
                callParams->state = STATE_STRUCT;
                callParams->sharesParsed = 0;
                callParams->bytesToDo = 0;
                size -= (NQ_COUNT)(desc.current - desc.origin);
                
                /* continue to the next case */
            case STATE_STRUCT:
                if (callParams->bytesToDo > 0)
                {
                    cmRpcParseSkip(&desc, callParams->bytesToDo);
                    callParams->sharesParsed++;
                    size -= callParams->bytesToDo;
                    callParams->bytesToDo = 0;
                }
                else if (size < SHARESTRUCT_LEN) /* next share struct does not fit */
                {
                    callParams->bytesToDo = SHARESTRUCT_LEN - size;
                    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL,"Struct: end of fragment");
                    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                    return NQ_SUCCESS;
                }
                else
                {
                    cmRpcParseSkip(&desc, SHARESTRUCT_LEN);
                    callParams->sharesParsed++;
                    size -= SHARESTRUCT_LEN;
                }
                
                if (callParams->sharesParsed >= callParams->numShares)
                {
                    callParams->state = STATE_NAMEDESC;
                    callParams->sharesParsed = 0;
                }
                break;
            case STATE_NAMEDESC:
                if (callParams->bytesToDo > 0)
                {
                    cmRpcParseBytes(&desc, callParams->pData, callParams->bytesToDo);
                    size -= callParams->bytesToDo;
                    callParams->bytesToDo = 0;
                    callParams->state = STATE_NAME;
                }
                else if (size >= sizeof(callParams->strDesc))
                {
                    cmRpcParseBytes(&desc, (NQ_BYTE *)callParams->strDesc, sizeof(callParams->strDesc));
                    size -= (NQ_COUNT)sizeof(callParams->strDesc);  
                    callParams->state = STATE_NAME;
                }
                else
                {
                    cmRpcParseBytes(&desc, (NQ_BYTE *)callParams->strDesc, size);
                    callParams->bytesToDo = (NQ_COUNT)(sizeof(callParams->strDesc) - size);
                    callParams->pData = (NQ_BYTE*)callParams->strDesc + size;
                    
                    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL,"Name desc: end of fragment");
                    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                    return NQ_SUCCESS;
                }
                break;
            case STATE_NAME:
                len = cmLtoh32(callParams->strDesc[0]);
                len = (len + 1) & (NQ_UINT32)(~1);
                
                if (callParams->bytesToDo > 0)
                {
                    cmRpcParseBytes(&desc, callParams->pData, callParams->bytesToDo);
                    size -= callParams->bytesToDo;
                    callParams->bytesToDo = 0;
                    (*callParams->callBack)(currentName, callParams->params);   
                }
                else if (size >= sizeof(NQ_WCHAR) * len) 
                {
                    cmRpcParseBytes(&desc, (NQ_BYTE *)currentName, (NQ_UINT32)(sizeof(NQ_WCHAR) * len));  
                    size -= (NQ_COUNT)(sizeof(NQ_WCHAR) * len);
                    (*callParams->callBack)(currentName, callParams->params);
                }
                else
                {
                    cmRpcParseBytes(&desc, (NQ_BYTE *)currentName, size);  
                    callParams->bytesToDo = (NQ_COUNT)(sizeof(NQ_WCHAR) * (len - 1) - size); 
                    callParams->pData = (NQ_BYTE*)currentName + size;
                                  
                    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL,"Name text: end of fragment");
                    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                    return NQ_SUCCESS;
                }
                savedPtr = desc.current;
                cmRpcAllign(&desc, 4);
                size -=  (NQ_COUNT)(desc.current - savedPtr);  
                callParams->state = STATE_COMMENTDESC;
            case STATE_COMMENTDESC:
                if (callParams->bytesToDo > 0)
                {                   
                    cmRpcParseBytes(&desc, callParams->pData, callParams->bytesToDo);
                    size -= callParams->bytesToDo;
                    callParams->bytesToDo = 0;
                    callParams->state = STATE_COMMENT;
                }
                else if (size >= sizeof(callParams->strDesc))
                {
                    cmRpcParseBytes(&desc, (NQ_BYTE *)callParams->strDesc, sizeof(callParams->strDesc));
                    size -= (NQ_COUNT)(sizeof(callParams->strDesc)); 
                    callParams->state = STATE_COMMENT;
                }
                else
                {
                    cmRpcParseBytes(&desc, (NQ_BYTE *)callParams->strDesc, size);
                    callParams->bytesToDo = (NQ_COUNT)(sizeof(callParams->strDesc) - size);
                    callParams->pData = (NQ_BYTE*)callParams->strDesc + size;
                    
                    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL,"Comment desc: end of fragment");
                    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                    return NQ_SUCCESS;
                }
                break;
            case STATE_COMMENT:
                len = cmLtoh32(callParams->strDesc[0]);
                len = (len + 1) & (NQ_UINT32)(~1);
               
                if (callParams->bytesToDo > 0)
                {
                    cmRpcParseSkip(&desc, callParams->bytesToDo); 
                    size -= callParams->bytesToDo;   
                    callParams->bytesToDo = 0;
                }
                else if (size >= sizeof(NQ_WCHAR) * len) 
                {
                    cmRpcParseSkip(&desc, (NQ_UINT32)(sizeof(NQ_WCHAR) * len));
                    size -= (NQ_COUNT)(sizeof(NQ_WCHAR) * len);
                }
                else
                {
                    callParams->bytesToDo = (NQ_COUNT)(sizeof(NQ_WCHAR) * (len - 1) - size); 
                                        
                    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL,"Comment text: end of fragment");
                    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                    return NQ_SUCCESS;
                }
                
                savedPtr = desc.current;
                cmRpcAllign(&desc, 4);
                size -=  (NQ_COUNT)(desc.current - savedPtr);
                callParams->state = STATE_NAMEDESC;
                callParams->sharesParsed++;
                
                if ((int)size <= 0)
                {
                    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL,"End of fragment and end of comment share");
                    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                    return NQ_SUCCESS;
                }  
                if (callParams->sharesParsed >= callParams->numShares)
                {
                    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                    return NQ_SUCCESS;
                }
                break;
        }
    }
}

/*====================================================================
 * PURPOSE: Get share information
 *--------------------------------------------------------------------
 * PARAMS:  IN pipe handle
 *          IN server host name
 *          IN callback for getting next share name
 *          IN pointer to callback parameters
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:   Sends SRVSVC NetShareGetInfo request with SHARE_INFO_1 level.
 *====================================================================
 */

NQ_STATUS
ccSrvsvcGetShareInfo(
    NQ_HANDLE pipeHandle,
    const NQ_WCHAR* hostName,
    const NQ_WCHAR* share,
    NQ_UINT16 *type,
    NQ_BYTE *remark,
    NQ_INT maxRemarkSize,
    NQ_BOOL unicodeResult
    )
{
    NQ_COUNT res;                 /* response byte count */
    NetShareInfoParams params;    /* parameters for callbacks */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    params.serverName = hostName;
    params.shareName = share;
    params.remark = remark;
    params.maxRemarkSize = maxRemarkSize;
    params.unicodeResult = unicodeResult;

    res = (NQ_COUNT)ccDcerpcCall(pipeHandle, netShareInfoRequestCallback, netShareInfoResponseCallback, &params);
    *type = (NQ_UINT16)params.type;

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return res? (params.result? NQ_SUCCESS : NQ_FAIL): NQ_FAIL;
}

/*====================================================================
 * PURPOSE: DCERPC request callback function for share information
 *--------------------------------------------------------------------
 * PARAMS:  OUT buffer for outgoing data
 *          IN buffer size
 *          IN/OUT params
 *          OUT set here TRUE when more data remains
 *
 * RETURNS: number of bytes placed into the buffer or
 *          zero on buffer overflow
 *
 * NOTES:   Composes request
 *====================================================================
 */

NQ_COUNT                /* count of outgoing data */
netShareInfoRequestCallback (
    NQ_BYTE* buffer,    /* ougoing data buffer */
    NQ_COUNT size,      /* room in the buffer */
    void* params,       /* abstract parameters */
    NQ_BOOL* moreData   /* put here TRUE when more outgoing data available */
    )
{
    CMRpcPacketDescriptor desc;         /* descriptor for SRVSVC request */
    NQ_UINT32 refId = 1;                /* running referent ID */
    NetShareInfoParams* p = (NetShareInfoParams*)params;    /* casted parameters for callback */
    NQ_WCHAR * hostName;				/* hostname prefixed */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    hostName = cmMemoryAllocate((NQ_UINT)(sizeof(NQ_WCHAR) * (cmWStrlen(p->serverName) + 4)));
    if (NULL == hostName)
    {
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    	return NQ_ERR_OUTOFMEMORY;
    }

    *moreData = FALSE;
    cmAnsiToUnicode(hostName, "\\\\");
    cmWStrcpy(hostName + 2, p->serverName);
    cmWStrcpy(currentName, p->shareName);

    cmRpcSetDescriptor(&desc, buffer, FALSE);
    cmRpcPackUint16(&desc, NETRSHAREINFO_OPNUM);

    desc.origin = desc.current;     /* for alligment to 4 bytes */

    /* server name */
    cmRpcPackUint32(&desc, refId++);
    cmRpcPackUnicode(&desc, hostName, (CM_RP_SIZE32 | CM_RP_FRAGMENT32 | CM_RP_NULLTERM));
    /* share name */
    cmRpcPackUnicode(&desc, currentName, (CM_RP_SIZE32 | CM_RP_FRAGMENT32 | CM_RP_NULLTERM));
    /* info level 1 */
    cmRpcPackUint32(&desc, 1);
    
    cmMemoryFree(hostName);
    
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return (NQ_COUNT)((desc.current - desc.origin) + 2);
}

/*====================================================================
 * PURPOSE: DCERPC response callback function for share information
 *--------------------------------------------------------------------
 * PARAMS:  IN data portion
 *          IN data length in the portion
 *          IN/OUT params
 *          IN TRUE when more data to come
 *
 * RETURNS: NQ_SUCCESS or error code
 *
 * NOTES:   Parses share names
 *====================================================================
 */

NQ_STATUS                   /* NQ_SUCCESS or error code */
netShareInfoResponseCallback (
    const NQ_BYTE* data,    /* data portion pointer */
    NQ_COUNT size,          /* data portion size */
    void* params,           /* abstract parameters */
    NQ_BOOL moreData        /* TRUE when more data available */
    )
{
    CMRpcPacketDescriptor desc;                           /* descriptor for SRVSVC request */
    NetShareInfoParams* p = (NetShareInfoParams*)params;  /* casted parameters for callback */
    CMRpcUnicodeString remark;                            /* descriptor for share remark */
    NQ_UINT32 count;                                      /* text counter */

    cmRpcSetDescriptor(&desc, (NQ_BYTE*)data, FALSE);

    /* skip information level, SHARE_INFO_1 ref ID and share name ref ID */
    cmRpcParseSkip(&desc, 4);
    /* skip SHARE_INFO_1 ref ID */
    cmRpcParseUint32(&desc, &count);
    if (0 == count)     /* no share found */
    {
        p->result = FALSE;
        LOGERR(CM_TRC_LEVEL_ERROR, "No share found");
        return NQ_SUCCESS;
    }
    p->result = TRUE;
    /* skip share name ref ID */
    cmRpcParseSkip(&desc, 4);
    /* get share type */
    cmRpcParseUint32(&desc, &p->type);
    /* skip remark ref ID, share name max count and offset */
    cmRpcParseSkip(&desc, 3 * 4);
    /* get share name actual count and skip the name */
    cmRpcParseUint32(&desc, &count);
    cmRpcParseSkip(&desc, count * 2);
    cmRpcAllign(&desc, 4);

    cmRpcParseUnicode(&desc, &remark, CM_RP_SIZE32 | CM_RP_FRAGMENT32 | CM_RP_NULLTERM);

    if (p->maxRemarkSize < (NQ_INT)remark.size)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Insufficient buffer for share remark");
        sySetLastError(NQ_ERR_MOREDATA);
        return (NQ_STATUS)NQ_FAIL;
    }

    if (p->unicodeResult)
        cmWStrcpy((NQ_WCHAR *)p->remark, remark.text);
    else
        cmUnicodeToAnsi((NQ_CHAR *)p->remark, remark.text);

    return (NQ_STATUS)NQ_SUCCESS;
}


#endif /* UD_NQ_INCLUDECIFSCLIENT */

