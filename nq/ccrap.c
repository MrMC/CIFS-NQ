/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : RAP Client Implementation
 *--------------------------------------------------------------------
 * DEPENDENCIES  : None
 *--------------------------------------------------------------------
 * CREATION DATE : 18-Apr-2003
 * CREATED BY    : Alexey Yarovinsky
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "ccrap.h"
#include "ccshare.h"
#include "cmapi.h"
#include "nqapi.h"
#include "ccsrvsvc.h"

#ifdef UD_NQ_INCLUDECIFSCLIENT

/* Beginning of packed structures definition */

#include "sypackon.h"

typedef SY_PACK_PREFIX struct {
    NQ_SUINT16  function;
    NQ_SCHAR    pReq[6];
    NQ_SCHAR    pRsp[7];
    NQ_SUINT16  level;
    NQ_SUINT16  bufLen;
}
SY_PACK_ATTR NetShareEnum1Rsp;

typedef SY_PACK_PREFIX struct {
    NQ_SUINT16  status;
    NQ_SUINT16  converter;
    NQ_SUINT16  entries;
    NQ_SUINT16  total;
}
SY_PACK_ATTR NetShareEnumRsp;

typedef SY_PACK_PREFIX struct {
    NQ_SUINT16  function;
    NQ_SCHAR    pReq[6];
    NQ_SCHAR    pRsp[7];
}
SY_PACK_ATTR NetShareInfoReq;

typedef SY_PACK_PREFIX struct {
    NQ_SUINT16  status;
    NQ_SUINT16  converter;
    NQ_SUINT16  size;
    NQ_SUINT16  reserve;
}
SY_PACK_ATTR NetShareInfoRsp;

typedef SY_PACK_PREFIX struct {
    NQ_SCHAR    netName[13];
    NQ_SBYTE    pad;
    NQ_SUINT16  type;
    NQ_SUINT16  remark;
    NQ_SUINT16  pad2;
}
SY_PACK_ATTR RapShareInfo1;

typedef SY_PACK_PREFIX struct {
    NQ_SCHAR   srvName[16];
}
SY_PACK_ATTR RapServerInfo0;

typedef SY_PACK_PREFIX struct {
    NQ_SCHAR   srvName[16];
    NQ_SBYTE   versionMajor;
    NQ_SBYTE   versionMinor;
    NQ_SUINT32   type;
    NQ_SUINT16  comment;
    NQ_SUINT16  pad;
}
SY_PACK_ATTR RapServerInfo1;

typedef SY_PACK_PREFIX struct {
    NQ_SUINT16  function;
    NQ_SCHAR    pReq[8];
    NQ_SCHAR    pRsp[4];
    NQ_SUINT16  level;
    NQ_SUINT16  bufLen;
    NQ_SUINT32   type;
}
SY_PACK_ATTR NetServerEnum0Rsp;

typedef SY_PACK_PREFIX struct {
    NQ_SUINT16  function;
    NQ_SCHAR    pReq[8];
    NQ_SCHAR    pRsp[8];
    NQ_SUINT16  level;
    NQ_SUINT16  bufLen;
    NQ_SUINT32   type;
}
SY_PACK_ATTR NetServerEnum1Rsp;

typedef SY_PACK_PREFIX struct {
    NQ_SUINT16  status;
    NQ_SUINT16  converter;
    NQ_SUINT16  entries;
    NQ_SUINT16  total;
}
SY_PACK_ATTR NetServerEnumRsp;

#include "sypackof.h"

/* End of packed structures definition */

/* static functions */

static NQ_STATUS netShareEnumLevel1(NetShareEnumRsp * response, NQ_CHAR *data, CCRapEnumerateNamesCallback callback, void* params);
static NQ_STATUS netServerEnumLevel0(NetServerEnumRsp * response, NQ_CHAR *data, CCRapEnumerateNamesCallback callback, void* params);

/*
 *====================================================================
 * PURPOSE: enumerate shares on remote server
 *--------------------------------------------------------------------
 * PARAMS:  IN  server name
 *          IN  protocol level
 *          IN  pointer to data buffer to store share entries in
 *          IN  data buffer length
 *          OUT number of entries returned in the data buffer
 *          OUT total number of entries available
 *
 * RETURNS: NQ_ERR_OK if succeeded, appropriate error code otherwise
 *
 * NOTES:   only level 1 is available
 *====================================================================
 */

NQ_STATUS
ccRapNetShareEnum(
    const NQ_WCHAR *server,
    CCRapEnumerateNamesCallback callback,
    void* params
   )
{
    CCShare * pShare;                       /* pointer to IPC descriptor */
    CMBlob inData;                          /* request parameters */
	CMBlob outParams = {NULL, 0};           /* response parameters + data parameters */
	CMBlob outData = {NULL, 0};             /* response data parameters */
	NetShareEnum1Rsp request1;              /* request parameters structure */
    NQ_STATUS status = NQ_ERR_GENERAL;      /* operation status */
    NQ_COUNT i, j;                          /* just a counter */
    CCServer *pServer;                      /* pointer to server object */
    NQ_BOOL security[] = {TRUE, FALSE};     /* whether to use extended security */
    NQ_BOOL anon[] = {TRUE , FALSE};        /* whether to use Anonymous or not */

    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL, "server:%s callback:%p params:%p", cmWDump(server), callback, params);

    cmPutSUint16(request1.function, 0);
    syStrcpy(request1.pReq, "WrLeh");
    syStrcpy(request1.pRsp, "B13BWz");
    cmPutSUint16(request1.level, cmHtol16(1));
    cmPutSUint16(request1.bufLen, cmHtol16(CIFS_MAX_DATA_SIZE16));
    inData.data = (NQ_BYTE *)&request1;
    inData.len = sizeof(request1);

    for (i = 0; i < sizeof(security)/sizeof(security[0]); i++)
    {
        pServer = ccServerFindOrCreate(server, security[i], ccCifsGetDefaultSmb());
        if (pServer != NULL)
        {
            for (j = 0 ; j < sizeof(anon)/sizeof(anon[0]); j++)
            {
                const AMCredentialsW * pCredentials = anon[j] ? ccUserGetAnonymousCredentials() : NULL;       /* credentials */
                pShare = ccShareConnectIpc(pServer , &pCredentials);
                if (NULL == pShare)
                {
                    cmListItemUnlock((CMItem *)pServer);
                    LOGERR(CM_TRC_LEVEL_ERROR, "Can't establish connection to %s", cmWDump(server));
                    status = (NQ_STATUS)syGetLastError();
                    goto Exit;
                }

                status = pShare->user->server->smb->doRapTransaction(pShare, &inData, &outParams, &outData);
                cmListItemUnlock((CMItem *)pShare);       /* force disconnect when not used */

                if (status == NQ_SUCCESS || status == NQ_ERR_NOSUPPORT)
                {
                    break;
                }
            }
            cmListItemUnlock((CMItem *)pServer);
            if (status == NQ_SUCCESS || status == NQ_ERR_NOSUPPORT)
            {
                break;
            }
        }
        else
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Can't establish connection to %s", cmWDump(server));
            goto Exit;
        }
    }/* end of connecting "for" */

    if (NQ_SUCCESS != status)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "No valid NetShareEnum response");
        goto Exit;
    }

	status = netShareEnumLevel1((NetShareEnumRsp *)outParams.data, (NQ_CHAR *)outData.data, callback, params);

Exit:
	cmMemoryFreeBlob(&outParams);
	cmMemoryFreeBlob(&outData);
    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL, "result:%d", status);
    return status;
}

/*
 *====================================================================
 * PURPOSE: get share information
 *--------------------------------------------------------------------
 * PARAMS:  IN  server name
 *          IN  share name
 *          OUT share type (SMB_SHARETYPE_XXXXX)
 *          OUT share remark in the supplied buffer
 *          IN  remark buffer size
 *
 * RETURNS: NQ_ERR_OK if succeeded, appropriate error code otherwise
 *
 * NOTES:   only level 1 is available
 *====================================================================
 */

NQ_STATUS
ccRapNetShareInfo(
    const NQ_WCHAR * server,
    const NQ_WCHAR * share,
    NQ_UINT16 * type,
    NQ_WCHAR * remark,
    NQ_INT maxRemarkSize,
    NQ_BOOL unicodeResult
   )
{
    CCShare * pShare;                       /* pointer to IPC descriptor */
    CMBlob inData = {NULL, 0};              /* request parameters */
    CMBlob outParams = {NULL, 0};           /* response parameters + data parameters */
	CMBlob outData = {NULL, 0};             /* response data parameters */
    NetShareInfoReq * request;              /* pointer to request parameters */
    NetShareInfoRsp * response;             /* pointer to response parameters */
    RapShareInfo1 * info;                   /* pointer to share information data */
    NQ_BYTE * p;                            /* generic pointer */
    NQ_STATUS status = NQ_ERR_GENERAL;      /* operation status */
    NQ_COUNT i, j;                          /* just a counter */
    CCServer * pServer;                     /* pointer to server object */
    NQ_BOOL security[] = {TRUE, FALSE};     /* whether to use extended security */
    NQ_BOOL anon[] = {TRUE , FALSE};        /*whether to use Anonymous or not */

    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL, "server:%s share:%s type:%p remark:%p size:%d unicode:%s", cmWDump(server), cmWDump(share), type, remark, maxRemarkSize, unicodeResult ? "TRUE" : "FALSE");

    inData.len = (NQ_COUNT)(sizeof(NetShareInfoReq) + cmWStrlen(share) + 1 + (sizeof(NQ_UINT16) * 2));  /* more memory for multibyte characters */
    inData.data = (NQ_BYTE *)cmMemoryAllocate(inData.len);
    if (NULL == inData.data)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Memory overflow");
        status = NQ_ERR_NOMEM;
        goto Exit;
    }

    request = (NetShareInfoReq *)inData.data;
    cmPutSUint16(request->function, 1);
    syStrcpy(request->pReq, "zWrLh");
    syStrcpy(request->pRsp, "B13BWz");
    p = (NQ_BYTE *)(request + 1);
    cmUnicodeToAnsi((NQ_CHAR *)p, share);
    p += syStrlen((NQ_CHAR *)p) + 1;
    cmPutUint16(p, cmHtol16(1));
    p += 2;
    cmPutUint16(p, (NQ_UINT16)cmHtol16(maxRemarkSize));

    for (i = 0; i < sizeof(security)/sizeof(security[0]); i++)
    {
        pServer = ccServerFindOrCreate(server, security[i], ccCifsGetDefaultSmb());
        if (pServer != NULL)
        {
            for (j = 0 ; j < sizeof(anon)/sizeof(anon[0]); j++)
            {
                const AMCredentialsW * pCredentials = anon[j] ? ccUserGetAnonymousCredentials() : NULL;       /* credentials */
                pShare = ccShareConnectIpc(pServer , &pCredentials);
                if (NULL == pShare)
                {
                    cmListItemUnlock((CMItem *)pServer);
                    LOGERR(CM_TRC_LEVEL_ERROR, "Can't establish connection to %s", cmWDump(server));
                    status = (NQ_STATUS)syGetLastError();
                    goto Exit;
                }

				status = pShare->user->server->smb->doRapTransaction(pShare, &inData, &outParams, &outData);
                cmListItemUnlock((CMItem *)pShare);       /* force disconnect when not used */

                if (status == NQ_SUCCESS || status == NQ_ERR_NOSUPPORT)
                {
                    break;
                }
            }
            cmListItemUnlock((CMItem *)pServer);
            if (status == NQ_SUCCESS || status == NQ_ERR_NOSUPPORT)
            {
                break;
            }
        }
        else
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Can't establish connection to %s", cmWDump(server));
            status = (NQ_STATUS)syGetLastError();
            goto Exit;
        }
    }/* end of connecting "for" */

    if (NQ_SUCCESS != status)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "No valid NetShareInfo response");
        goto Exit;
    }

	response = (NetShareInfoRsp *)outParams.data;
	info = (RapShareInfo1 *)outData.data;
    if ((status = cmLtoh16(cmGetSUint16(response->status))) == NQ_ERR_OK)
    {
        *type = cmLtoh16(cmGetSUint16(info->type));
        if (unicodeResult)
            cmAnsiToUnicode((NQ_WCHAR *)remark, (NQ_CHAR *)info + (info->remark - response->converter));
        else
            syStrcpy((NQ_CHAR*)remark, (NQ_CHAR *)info + (info->remark - response->converter));
    }

Exit:
    cmMemoryFreeBlob(&inData);
	cmMemoryFreeBlob(&outParams);
	cmMemoryFreeBlob(&outData);
    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL, "result:%d", status);
    return status;
}

/*
 *====================================================================
 * PURPOSE: enumerate hosts in domain
 *--------------------------------------------------------------------
 * PARAMS:  IN  server name to send enumeration request to
 *          IN  callback for storing names
 *          IN/OUT parameters for the callback
 *          IN  server types include in enumeration
 *          IN  enumerated domain name
 *
 * RETURNS: NQ_ERR_OK if succeeded, appropriate error code otherwise
 *
 * NOTES:   levels 0 and 1 are supported
 *====================================================================
 */

NQ_STATUS
ccRapNetServerEnum(
    const NQ_WCHAR * server,
    CCRapEnumerateNamesCallback callback,
    void * params,
    NQ_UINT32 serverType,
    const NQ_WCHAR * domain
   )
{
    CCShare * pShare;                           /* pointer to IPC descriptor */
    CMBlob inData = {NULL, 0};                  /* request parameters */
	CMBlob outParams = {NULL, 0};               /* response parameters + data parameters */
	CMBlob outData = {NULL, 0};                 /* response data parameters */
	NetServerEnum0Rsp * request0;               /* request parameters structure */
    NQ_STATUS status = NQ_ERR_GENERAL;          /* operation status */
    NQ_COUNT i, j;                              /* just a counter */
    CCServer * pServer;                         /* pointer to server object */
    NQ_BOOL security[] = {TRUE, FALSE};         /* whether to use extended security */
    NQ_BOOL anon[] = {TRUE , FALSE};            /* whether to use Anonymous or not */
    NQ_BOOL emptyDomain = FALSE;                /* whether domain name is empty */
    NQ_COUNT len;                               /* string length */
    NQ_CHAR *domainA = NULL;                    /* domain in ASCII */

    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL, "server:%s callback:%p params:%p type:%u domain:%s", cmWDump(server), callback, params, serverType, cmWDump(domain));

    inData.len = sizeof(NetServerEnum0Rsp);
    if (NULL == domain)
    {
        emptyDomain = TRUE;
        len = 0;
    }
    else
    {
        NQ_CHAR *dot = NULL;

        /* check required space for domain */
        len = (NQ_COUNT)((cmWStrlen(domain) + 1) * sizeof(NQ_CHAR) * 2); /* add more space for multibyte character sets */
        domainA = (NQ_CHAR *)cmMemoryAllocate(len);
        if (NULL == domainA)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Memory overflow");
            status = NQ_ERR_NOMEM;
            goto Exit;
        }
        cmUnicodeToAnsi(domainA, domain);
        if (NULL != (dot = syStrchr(domainA, '.')))
            *dot = '\0';
        len = (NQ_COUNT)(syStrlen(domainA) + 1); /* check actual string length */
    }

    inData.len +=  len;
    inData.data = (NQ_BYTE *)cmMemoryAllocate(inData.len);
    if (NULL == inData.data)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Memory overflow");
        status = NQ_ERR_NOMEM;
        goto Exit;
    }

    request0 = (NetServerEnum0Rsp *)inData.data;
    cmPutSUint16(request0->function, cmHtol16(104));
    syStrcpy(request0->pReq, emptyDomain ? "WrLehDO" : "WrLehDz");
    syStrcpy(request0->pRsp, "B16");
    cmPutSUint16(request0->level, cmHtol16(0));      /* infoLevel always 0 */
    cmPutSUint16(request0->bufLen, cmHtol16(CIFS_MAX_DATA_SIZE16));
    cmPutSUint32(request0->type, cmHtol32(serverType));
    if (!emptyDomain)
        syStrcpy((NQ_CHAR *)(request0 + 1), domainA);

    for (i = 0; i < sizeof(security)/sizeof(security[0]); i++)
    {
        pServer = ccServerFindOrCreate(server, security[i], ccCifsGetDefaultSmb());
        if (pServer != NULL)
        {
            for (j = 0 ; j < sizeof(anon)/sizeof(anon[0]); j++)
            {
                const AMCredentialsW * pCredentials = anon[j] ? ccUserGetAnonymousCredentials() : NULL;       /* credentials */
                pShare = ccShareConnectIpc(pServer , &pCredentials);
                if (NULL == pShare)
                {
                    cmListItemUnlock((CMItem *)pServer);
                    LOGERR(CM_TRC_LEVEL_ERROR, "Can't establish connection to %s", cmWDump(server));
                    status = (NQ_STATUS)syGetLastError();
                    goto Exit;
                }
				status = pShare->user->server->smb->doRapTransaction(pShare, &inData, &outParams, &outData);
                cmListItemUnlock((CMItem *)pShare);       /* force disconnect when not used */

                if (status == NQ_SUCCESS || status == NQ_ERR_NOSUPPORT)
                {
                    break;
                }
            }
            cmListItemUnlock((CMItem *)pServer);
            if (status == NQ_SUCCESS || status == NQ_ERR_NOSUPPORT)
            {
                break;
            }
        }
        else
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Can't establish connection to %s", cmWDump(server));
            status = (NQ_STATUS)syGetLastError();
            goto Exit;
        }
    }/* end of connecting "for" */
    if (NQ_SUCCESS != status)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "No valid NetServerEnum response:%d", status);
        goto Exit;
    }

	status = netServerEnumLevel0((NetServerEnumRsp *)outParams.data, (NQ_CHAR *)outData.data, callback, params);

Exit:
    cmMemoryFreeBlob(&inData);
	cmMemoryFreeBlob(&outParams);
    cmMemoryFreeBlob(&outData);
    cmMemoryFree(domainA);
    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL, "result:%d", status);
    return status;
}

/*
 *====================================================================
 * PURPOSE: parse enumerate shares level 1 response
 *--------------------------------------------------------------------
 * PARAMS:  IN  pointer to net share enumeration response
 *          IN  pointer to received shares data to be parsed
 *          IN  pointer to callback function
 *          IN/OUT pointer to callback parameters
 *
 * RETURNS: NQ_ERR_OK if succeeded, NQ_ERR_MOREDATA if the output buffer
 *          is too small
 *
 * NOTES:
 *====================================================================
 */

static
NQ_STATUS
netShareEnumLevel1(
    NetShareEnumRsp *response,
    NQ_CHAR *data,
    CCRapEnumerateNamesCallback callback,
    void* params
   )
{
    ShareInfo1 * info = (ShareInfo1 *)data;
    ShareCallbackItem          pItem;
    NQ_UINT16 count = cmLtoh16(cmGetSUint16(response->entries));
    NQ_UINT16 i = 0;

    pItem.params = params;

    for (; i < count; i++, info++)
    {
        pItem.type = info->type;
        pItem.comment = NULL;
        (*callback)(info->netName, &pItem);
    }
    return NQ_ERR_OK;
}

/*
 *====================================================================
 * PURPOSE: parse enumerate servers level 0 response
 *--------------------------------------------------------------------
 * PARAMS:  IN  pointer to net server enumeration response
 *          IN  pointer to data buffer to store server entries in
 *          IN  callback for storing parameters
 *          IN/OUT  parameters for callback
 *
 * RETURNS: NQ_ERR_OK if succeeded, NQ_ERR_MOREDATA if the output buffer
 *          is too small
 *
 * NOTES:
 *====================================================================
 */

static
NQ_STATUS
netServerEnumLevel0(
    NetServerEnumRsp *response,
    NQ_CHAR *data,
    CCRapEnumerateNamesCallback callback,
    void* params
    )
{
    NQ_CHAR * pData = (NQ_CHAR*)cmAllignTwo(data);
    RapServerInfo0 * info = (RapServerInfo0 *)pData;
    NQ_UINT16 count = cmLtoh16(cmGetSUint16(response->entries));
    NQ_UINT16 i;
    NQ_STATUS result = NQ_ERR_SRVERROR;

    if (0 != cmLtoh16(cmGetSUint16(response->status)))
        goto Exit;

    for (i = 0; i < count; i++, info++)
        (*callback)(info->srvName, params);

    result = NQ_ERR_OK;

Exit:
    return result;
}

#endif
