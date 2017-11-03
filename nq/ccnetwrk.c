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

#include "ccnetwrk.h"
#include "cmlist.h"
#include "cmfinddc.h"
#include "ccdcerpc.h"
#include "ccnetlgn.h"
#include "ccsrvsvc.h"
#include "nsapi.h"
#include "cctrans.h"
#include "ccrap.h"
#include "cclsarpc.h"

#ifdef UD_NQ_INCLUDECIFSCLIENT

/* --- Definitions --- */

/* an item representing an abstract network entity: it may be a domain, a server or a share */
typedef struct
{
    CMItem item;                /* inherited CMItem */
    const NQ_CHAR * aName;      /* ASCII name. May be NULL when ASCII name was not requested yet */
    CCNetShareItem share;       /* share item for extended info */
}
NetItem;

/* cache ttl in seconds */
#define NET_ENUM_CACHE_TTL          5        

/* enumeration types*/
#define NET_ENUM_TYPE_DOMAINS       0x1
#define NET_ENUM_TYPE_SERVERS       0x2
#define NET_ENUM_TYPE_SHARES        0x3
#define NET_ENUM_TYPE_BACKUP        0x5

/* an active enumeration */
typedef struct
{
    CMItem item;              /* inherited CMItem, domain name for domains or servers enumeration, or server name for shares enumerations */
    CMList items;             /* enumeration items */
    NQ_UINT32 ttl;            /* ttl for cache */
    NQ_UINT16 type;           /* enumeration type */
    NetItem * next;           /* for iteration */
}
NetEnum;

/* Beginning of packed structures definition */

#include "sypackon.h"

typedef SY_PACK_PREFIX struct       /* BROWSER mail slot */
{
    NQ_SCHAR LANMAN[17];            /* name */
}
SY_PACK_ATTR BrowserMailSlot;

typedef SY_PACK_PREFIX struct       /* get backup list request */
{
    NQ_SBYTE opCode;                /* mail slot operation */
    NQ_SBYTE count;                 /* max number of responses */
    NQ_SUINT32 token;               /* request token */
}
SY_PACK_ATTR GetBackupListReq;

typedef SY_PACK_PREFIX struct       /* get backup list response */
{
    NQ_SBYTE opCode;                /* mail slot operation */
    NQ_SBYTE count;                 /* max number of responses */
    NQ_SUINT32 token;               /* request token */
}
SY_PACK_ATTR GetBackupListRsp;

#include "sypackof.h"

/* --- Static data --- */


typedef struct
{
    CMList enumerations;                            /* active enumerations */
    const NQ_WCHAR * theDomainW;                    /* NQ domain (NetBIOS name)*/
    const NQ_CHAR * theDomainA;                     /* NQ domain (NetBIOS name)*/
    SYMutex guard;                                  /* for critical sections */
#ifdef UD_NQ_USETRANSPORTNETBIOS
    NSSocketHandle requestSocket;                   /* shared socket for browse requests */
#endif /* UD_NQ_USETRANSPORTNETBIOS */
    NQ_BOOL cacheEnabled;                           /* cache state (enabled by default) */
    NQ_UINT32 cacheTimeout;                         /* cache item timeout */
}
StaticData;

#ifdef SY_FORCEALLOCATION
static StaticData* staticData = NULL;
#else  /* SY_FORCEALLOCATION */
static StaticData staticDataSrc;
static StaticData* staticData = &staticDataSrc;
#endif /* SY_FORCEALLOCATION */
static NQ_BOOL isInitDone = FALSE;

/* --- Static functions --- */

static void validateCache(NQ_UINT32 timeout)
{
    CMIterator iterator;
    NQ_UINT32 currentTime = (NQ_UINT32)syGetTimeInSec();

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "timeout:%d", timeout);

    cmListIteratorStart(&staticData->enumerations, &iterator);
    while (cmListIteratorHasNext(&iterator))
    {
        NetEnum * pEnum = (NetEnum *)cmListIteratorNext(&iterator);

        if (((timeout == 0) || (timeout != 0 && pEnum->ttl < currentTime)))
        {
            LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "removing %p (%s, type:0x%x) from cache", pEnum, cmWDump(((CMItem *)pEnum)->name), pEnum->type);
            if (pEnum->type == NET_ENUM_TYPE_BACKUP)
                cmListItemUnlock((CMItem *)pEnum);
            cmListItemUnlock((CMItem *)pEnum);
        }
    }
    cmListIteratorTerminate(&iterator);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

static NetEnum * findInCache(NQ_UINT16 type, const NQ_WCHAR * name)
{
    NetEnum * pEnumResult = NULL;    /* pointer to result */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "type:0x%x(%s) name:%s", type,
        type == NET_ENUM_TYPE_DOMAINS ? "domains" : (type == NET_ENUM_TYPE_SERVERS ? "servers" : (type == NET_ENUM_TYPE_SHARES ? "shares" : "backup servers")), cmWDump(name));
    
    if (staticData->cacheEnabled)
    {
        CMIterator iterator;

        validateCache(1);

        cmListIteratorStart(&staticData->enumerations, &iterator);
        while (cmListIteratorHasNext(&iterator))
        {
            NetEnum * pEnum = (NetEnum *)cmListIteratorNext(&iterator);

            if ((pEnum->type == type) && (pEnum->ttl > syGetTimeInSec()) && (cmWStricmp(((CMItem *)pEnum)->name, name) == 0))
            {
                if (pEnum->type != NET_ENUM_TYPE_BACKUP)
                    cmListItemLock((CMItem *)pEnum);
                pEnumResult = pEnum;
                break;
            }
        }
        cmListIteratorTerminate(&iterator);
    }
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "pEnum:%p", pEnumResult);
    return pEnumResult;
}

static NQ_BOOL disposeEnum(CMItem * pItem)
{
    NetEnum * pEnum = (NetEnum *)pItem;
    CMIterator iterator;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "pItem:%p", pItem);

    cmListIteratorStart(&pEnum->items, &iterator);
    while (cmListIteratorHasNext(&iterator))
    {
        CMItem * pItem;
        pItem = cmListIteratorNext(&iterator);
        cmListItemUnlock(pItem);
    }
    cmListIteratorTerminate(&iterator);
    cmListShutdown(&pEnum->items);
    cmListItemRemoveAndDispose((CMItem *)pEnum);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return TRUE;
}

static NQ_BOOL disposeItem(CMItem * pItem)
{
    NetItem * pNetItem = (NetItem *)pItem;
    cmMemoryFree(pNetItem->aName);
    cmMemoryFree(pNetItem->share.name);
    cmMemoryFree(pNetItem->share.comment);
    cmListItemRemoveAndDispose((CMItem *)pNetItem);
    return TRUE;
}

NQ_STATUS addShareNameCallback(const NQ_WCHAR * name, void * list)
{
    ShareCallbackItem *    params = (ShareCallbackItem *)list;
    CMList * pList;   			/* casted pointer */
    NetItem * pItem;            /* casted pointer */
    NQ_STATUS res = NQ_SUCCESS;

    pList = (CMList *)params->params;

    if (NULL == cmListItemFind(pList, name, TRUE, FALSE))
    {
        pItem = (NetItem *)cmListItemCreateAndAdd(pList, sizeof(NetItem), name, disposeItem , CM_LISTITEM_EXCLUSIVE | CM_LISTITEM_NOLOCK);
        if (NULL != pItem)
        {
            pItem->aName = NULL;
            pItem->share.comment = NULL;
            pItem->share.type = params->type;
#ifdef UD_CM_UNICODEAPPLICATION
            pItem->share.name = cmMemoryCloneWString((NQ_WCHAR *)name);
#else
            pItem->share.name = cmMemoryCloneWStringAsAscii((NQ_WCHAR *)name);
#endif
            if (params->comment != NULL)
#ifdef UD_CM_UNICODEAPPLICATION
                pItem->share.comment = cmMemoryCloneWString((NQ_WCHAR *)params->comment);
#else
                pItem->share.comment = cmMemoryCloneWStringAsAscii((NQ_WCHAR *)params->comment);
#endif
        }
        else
        {
        	LOGERR(CM_TRC_LEVEL_ERROR, "Not enough memory.");
        	res = NQ_ERR_NOMEM;
        	goto Exit;
        }
    }
Exit:
	return res;
}

static NetEnum * createEnumeration(NQ_UINT16 type, const NQ_WCHAR * name)
{
    NetEnum * pEnum;    /* pointer to the enumeration to create */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "type:0x%x(%s) name:%s", type,
        type == NET_ENUM_TYPE_DOMAINS ? "domains" : (type == NET_ENUM_TYPE_SERVERS ? "servers" : (type == NET_ENUM_TYPE_SHARES ? "shares" : "backup servers")), cmWDump(name));

    pEnum = (NetEnum *)cmListItemCreateAndAdd(&staticData->enumerations, sizeof(NetEnum), name, &disposeEnum, CM_LISTITEM_EXCLUSIVE | CM_LISTITEM_LOCK);
    if (NULL == pEnum)
    {
        sySetLastError(NQ_ERR_NOMEM);
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        goto Exit;
    }
    cmListStart(&pEnum->items);
    pEnum->ttl = (NQ_UINT32)((NQ_UINT32)syGetTimeInSec() + staticData->cacheTimeout);
    pEnum->type = type;
    if (staticData->cacheEnabled && pEnum->type != NET_ENUM_TYPE_BACKUP)
        cmListItemLock((CMItem *)pEnum);  /* locking twice for caching */

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "pEnum:%p", pEnum);
    return pEnum;
}

#ifdef UD_NQ_USETRANSPORTNETBIOS

/* This callback function is called from several result parsers when they encounter another item.
   This function creates an item and adds it to the respective list */
static void addNameCallback(const NQ_WCHAR * name, void * list)
{
    CMList * pList = (CMList *) list;   /* casted pointer */
    NetItem * pItem;                    /* casted pointer */

    if (NULL == cmListItemFind(pList, name, TRUE, FALSE))
    {
        pItem = (NetItem *)cmListItemCreateAndAdd(pList, sizeof(NetItem), name, disposeItem , CM_LISTITEM_EXCLUSIVE | CM_LISTITEM_NOLOCK);
        if (NULL != pItem)
        {
            pItem->aName = NULL;
            pItem->share.name = NULL;
            pItem->share.comment = NULL;
        }
    }
}

static void asciiAddNameCallback(const NQ_CHAR * name, void * params)
{
    const NQ_WCHAR * nameW; /* name in Unicode */

    nameW = cmMemoryCloneAString(name);
    if (NULL != nameW)
    {
        addNameCallback(nameW, params);
        cmMemoryFree(nameW);
    }
}

static NQ_UINT32 createToken(void)
{
    static NQ_UINT32 token = 1;
    NQ_UINT32 res;

    res = token++;
    return res;
}

static NQ_BOOL getBackupServerByDomain(const NQ_WCHAR * pDomain, CMList **pList)
{
    CMNetBiosNameInfo nbName;               /* NETBIOS source  and destination name */
    CMCifsTransactionRequest * transCmd = NULL; /* pointer to SMB Transaction words */
    NQ_UINT paramCount;                     /* number of parameter bytes */
    NQ_UINT dataCount;                      /* number of data bytes */
    static const BrowserMailSlot browser = { "\\MAILSLOT\\BROWSE" }; /* mail slot name */
    GetBackupListReq request;               /* BROWSER request */
    NQ_BYTE * data;                         /* Transaction data pointer */
    NQ_BYTE * parameters;                   /* Transaction parameters pointer */
    NQ_STATUS status;                       /* operation status */
    NQ_UINT32 token;                        /* next request token */
    const NQ_CHAR * pServer;                /* pointer to next server name */
    GetBackupListRsp * pResponse;           /* pointer to RAP structure in response */
    NQ_BYTE * rspData;                      /* pointer to data in response */
    NQ_UINT16 i;                            /* counter of entries in response */
    NQ_BYTE * pBuffer = NULL;               /* pointer to the response buffer to free later */
    NetEnum * pEnum;                        /* backup servers enumeration */
    NQ_BOOL result = FALSE;                 /* return value */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "domain:%s list:%p", cmWDump(pDomain), pList);

    pEnum = findInCache(NET_ENUM_TYPE_BACKUP, pDomain);
    if (NULL != pEnum)
    {
        *pList = &pEnum->items;
        result = TRUE;
        goto Exit;
    }

    pEnum = createEnumeration(NET_ENUM_TYPE_BACKUP, pDomain);
    if (NULL == pEnum)
    {
        goto Exit;
    }

    nbName.isGroup = TRUE;
    cmUnicodeToAnsi(nbName.name, pDomain);
    cmNetBiosNameFormat(nbName.name, *pDomain == 0x01 ? 0x01 : CM_NB_POSTFIX_MASTERBROWSER);

    syMutexTake(&staticData->guard);    /* protect socket and request buffer */

    /* Microsoft windows browser protocol */
    request.opCode = 9; /* Get backup list request  */
    request.count = 10;
    token = createToken();
    cmPutSUint32(request.token, cmHtol32(token));

    transCmd = ccTransGetCmdPacket(&parameters, 3);
    if (NULL == transCmd)
    {
        sySetLastError(NQ_ERR_NORESOURCE);
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to allocate Transaction packet");
        goto Error;
    }
    cmPutSUint32(transCmd->timeout, cmHtol32((NQ_UINT32)1000));

    data = (NQ_BYTE*)(transCmd + 1);

    cmPutUint16(data, cmHtol16(1));
    cmPutUint16(data + 2, cmHtol16(1));
    cmPutUint16(data + 2*2, cmHtol16(2));

    syMemcpy(parameters, &browser, sizeof(browser));
    paramCount = sizeof(browser);

    data = parameters + paramCount;
    syMemcpy(data, &request, sizeof(request));
    dataCount = 2 * 3;

    status = ccTransSendTo(
            staticData->requestSocket,
            &nbName,
            transCmd,
            sizeof(browser),
            &paramCount,
            parameters,
            &dataCount,
            data,
            0
            );
    if (NQ_SUCCESS != status)
    {
        sySetLastError(status);
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to send GetBackupList request");
        goto Error;
    }

    status = ccTransReceiveFrom(staticData->requestSocket, &nbName, NULL, NULL, &dataCount, &rspData, &pBuffer, ccConfigGetTimeout());
    syMutexGive(&staticData->guard);    /* free socket and request buffer */
    pResponse = (GetBackupListRsp *)rspData;
    if (NQ_SUCCESS != status || pResponse->opCode != 10 || pResponse->count == 0)
    {
        sySetLastError(status);
        LOGERR(CM_TRC_LEVEL_ERROR, "No valid GetBackupList response");
        goto Exit;
    }

    for (i = 0, pServer = (NQ_CHAR*)(pResponse + 1); i < pResponse->count; i++)
    {
        NQ_WCHAR *server = NULL;

        server = cmMemoryCloneAString(pServer);
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "backup server:%s", pServer);
        addNameCallback(server, &pEnum->items);
        cmMemoryFree(server);
        pServer += syStrlen(pServer) + 1;
    }

    *pList = &pEnum->items;
    result = TRUE;
    goto Exit;

Error:
    syMutexGive(&staticData->guard);

Exit:
    if (NULL != transCmd)
        ccTransPutCmdPacket(transCmd);
    if (NULL != pBuffer)
        cmMemoryFree(pBuffer);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result ? "TRUE" : "FALSE");
    return result;
}

/* get NetBIOS domain name for given FQDN, caller's responsibility to free the result pointer */
static NQ_WCHAR * getNetBIOSDomainName(const NQ_WCHAR *pDomain)
{
    NQ_WCHAR *dot;
    NQ_CHAR *pDomainA = NULL;
    NQ_WCHAR *dcW = NULL;
    NQ_CHAR dcA[CM_NQ_HOSTNAMESIZE + 1];
#if defined(UD_CC_INCLUDESECURITYDESCRIPTORS) || defined(UD_CC_INCLUDEDOMAINMEMBERSHIP) || defined(UD_CS_INCLUDEPASSTHROUGH)
    CCLsaPolicyInfoDomain domainInfo;
#endif
    NQ_WCHAR *pDomainResult = NULL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "pDomain:%s", cmWDump(pDomain));

    if (NULL == pDomain)
        goto Exit;

    dot = syWStrchr(pDomain, cmWChar('.'));
    if (NULL == dot)
    {
        pDomainResult = cmMemoryCloneWString(pDomain);
        goto Exit;
    }
 
    /* resolve DC name for domain */
    pDomainA = cmMemoryCloneWStringAsAscii(pDomain);
    if (NULL == pDomainA)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        goto Error;
    }    
    if (NQ_SUCCESS != cmGetDCNameByDomain(pDomainA, dcA))
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "failed to get dc for domain %s", pDomainA);
        sySetLastError((NQ_UINT32)syGetLastError());
        goto Error;
    }
    dcW = cmMemoryCloneAString(dcA);
    if (NULL == dcW)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        goto Error;
    }
#if defined(UD_CC_INCLUDESECURITYDESCRIPTORS) || defined(UD_CC_INCLUDEDOMAINMEMBERSHIP) || defined(UD_CS_INCLUDEPASSTHROUGH)
    /* use LSA pipe to get NetBIOS name for FQDN */
    if (NQ_SUCCESS == ccLsaDsRoleGetPrimaryDomainInformation(dcW, &domainInfo))
    {
        pDomainResult = cmMemoryCloneWString(domainInfo.name);
        goto Exit;
    }
#endif

Error:
    /* just cut off the name part after first dot */
    pDomainResult = (NQ_WCHAR *)cmMemoryAllocate((NQ_UINT)((syWStrlen(pDomain) - syWStrlen(dot) + 1) * sizeof(NQ_WCHAR)));
    if (NULL != pDomainResult)
    {
        syWStrncpy(pDomainResult, pDomain, syWStrlen(pDomain) - syWStrlen(dot));
        pDomainResult[syWStrlen(pDomain) - syWStrlen(dot)] = cmWChar('\0');
    }

Exit:
    if (NULL != pDomainA)
        cmMemoryFree(pDomainA);
    if (NULL != dcW)
        cmMemoryFree(dcW);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", pDomainResult ? cmWDump(pDomainResult) : "null");
    return pDomainResult;
}


/* this function returns TRUE on success */
static NQ_BOOL getBackupServer(const NQ_WCHAR * pDomain , NQ_BOOL findAny, CMList **pList)
{
    static const NQ_WCHAR msbrowser[] = { cmWChar(0x01),
                                        cmWChar(0x02),
                                        cmWChar('_'),
                                        cmWChar('_'),
                                        cmWChar('M'),
                                        cmWChar('S'),
                                        cmWChar('B'),
                                        cmWChar('R'),
                                        cmWChar('O'),
                                        cmWChar('W'),
                                        cmWChar('S'),
                                        cmWChar('E'),
                                        cmWChar('_'),
                                        cmWChar('_'),
                                        cmWChar(0x02),
                                        cmWChar('\0')};
    NQ_BOOL result = FALSE;
    const NQ_WCHAR *domainName = NULL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "domain:%s findAny:%s list:%p", cmWDump(pDomain), findAny ? "TRUE" : "FALSE", pList);
     
    domainName = (NULL == pDomain) ? cmMemoryCloneWString(msbrowser) : cmMemoryCloneWString(pDomain);
    if (NULL == domainName)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        goto Exit;
    }

    result = getBackupServerByDomain(domainName, pList);
    if (NULL != pDomain && FALSE == result && findAny)
        result = getBackupServerByDomain(msbrowser, pList);

    cmMemoryFree(domainName);

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result ? "TRUE" : "FALSE");
    return result;
}

static NQ_BOOL getGetDomainsNetBios(const NQ_WCHAR * pDomainW, CMList * pList)
{
    NQ_INT retryCount;              /* repeat count */
    NQ_STATUS status = NQ_FAIL;     /* operation result */
    CMList *backupServers;          /* backup servers list */
    CMIterator iterator;            /* backup servers list iterator */
    NQ_BOOL result = FALSE;         /* return value */
    NQ_WCHAR * pDomain = NULL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "domain:%s list:%p", cmWDump(pDomainW), pList);

    if (cmWStrlen(pDomainW) >= CM_DNS_NAMELEN)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Workgroup name is too long");
        sySetLastNqError(NQ_ERR_BADPARAM);
        goto Exit;
    }

    pDomain = getNetBIOSDomainName(pDomainW);
    if (FALSE == getBackupServer(pDomain, TRUE, &backupServers))
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Error retrieving domain backup list");
        goto Exit;
    }

    cmListIteratorStart(backupServers, &iterator);
    while (cmListIteratorHasNext(&iterator))
    {
        CMItem * pItem;

        pItem = cmListIteratorNext(&iterator);
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Querying server: %s", cmWDump(pItem->name));
        for (retryCount = CC_BROWSE_RETRYCOUNT; retryCount > 0; retryCount--)
        {
            status = ccRapNetServerEnum(pItem->name, asciiAddNameCallback, pList, SV_TYPE_DOMAIN_ENUM, NULL);
            if (NQ_SUCCESS != status)
            {
                LOGERR(CM_TRC_LEVEL_ERROR, "Error retrieving domains list");
                sySetLastNqError((NQ_UINT32)status);
                continue;
            }
            if (!cmListHasItems(pList))
            {
                LOGERR(CM_TRC_LEVEL_ERROR, "No domains found");
                sySetLastNqError(NQ_ERR_GETDATA);
                continue;
            }
            break;
        }
        if (cmListHasItems(pList))
            break;
    }
    cmListIteratorTerminate(&iterator);

    result = (status == NQ_SUCCESS);

Exit:
    if (NULL != pDomain)
        cmMemoryFree(pDomain);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result ? "TRUE" : "FALSE");
    return result;
}

static NQ_BOOL getTrustedDomains(const NQ_WCHAR * pDomain, CMList * pEnum)
{
    NQ_WCHAR * dc = NULL;       /* domain controller in Unicode */
    NQ_CHAR * dcA = NULL;       /* the same in ASCII */
    NQ_CHAR * domainA = NULL;   /* workgroup/domain copy in ASCII */
    NQ_HANDLE netlogon;         /* handle of NetLogon pipe */
    NQ_BOOL res = FALSE;        /* value to return */
    NQ_UINT32 status;           /* operation status */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "domain:%s enum:%p", cmWDump(pDomain), pEnum);

    /* allocate buffers and convert strings */
    domainA = cmMemoryCloneWStringAsAscii(pDomain);
    dcA = (NQ_CHAR *)cmMemoryAllocate(sizeof(NQ_BYTE) * CM_DNS_NAMELEN);
    if (NULL == domainA || NULL == dcA)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        sySetLastNqError(NQ_ERR_OUTOFMEMORY);
        goto Exit;
    }

    /* find domain controller by domain name */
    if ((status = (NQ_UINT32)cmGetDCNameByDomain(domainA, dcA)) != NQ_SUCCESS)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to get dc for domain %s", domainA);
        sySetLastError((NQ_UINT32)syGetLastError());
        goto Exit;
    }

    /* allocate more buffers and strings and free used */
    dc = cmMemoryCloneAString(dcA);

    /* try netlogon pipe to get trusted domains  */
    netlogon = ccDcerpcConnect(dc, NULL, ccNetlogonGetPipe(), TRUE);
    if (NULL != netlogon)
    {
        status = ccDsrEnumerateDomainTrusts(netlogon, dc, addNameCallback, pEnum);
        if (NQ_SUCCESS == status)
        {
            res = TRUE;
        }
        else
        {
            sySetLastNqError(status);
        }
        ccDcerpcDisconnect(netlogon);
    }
    else
    {
         LOGERR(CM_TRC_LEVEL_ERROR, "Failed to connect to netlogon pipe");
    }

Exit:
    cmMemoryFree(domainA);
    cmMemoryFree(dcA);
    cmMemoryFree(dc);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", res ? "TRUE" : "FALSE");
    return res;
}

#endif /* UD_NQ_USETRANSPORTNETBIOS */

static void asciiAddShareNameCallback(const NQ_CHAR * name, void * params)
{
    const NQ_WCHAR * nameW; /* name in Unicode */

    nameW = cmMemoryCloneAString(name);
    if (NULL != nameW)
    {
        addShareNameCallback(nameW, params);
        cmMemoryFree(nameW);
    }
}

static void arrangeEnumeration(NetEnum * pEnum)
{
    pEnum->next = (NetItem *)pEnum->items.first;
}

NQ_BOOL getShareInfo(const NQ_WCHAR * server, const NQ_WCHAR * share, NQ_UINT16 * type, NQ_BYTE * remarkBuffer, NQ_INT bufferSize, NQ_BOOL unicode)
{
    NQ_INT retryCount;
    NQ_STATUS status;
    AMCredentialsW *pCredentials = NULL;
    NQ_BOOL result = FALSE;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "server:%s share:%s type:%p remark:%p size:%d unicode:%s", cmWDump(server), cmWDump(share), type, remarkBuffer, bufferSize, unicode ? "TRUE" : "FALSE");

    pCredentials = (AMCredentialsW *)cmMemoryAllocate(sizeof(AMCredentialsW));
    if (NULL == pCredentials)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        sySetLastNqError(NQ_ERR_OUTOFMEMORY);
        goto Exit;
    }

    udGetCredentials(NULL, pCredentials->user,
                           pCredentials->password,
                           pCredentials->domain.name);

    for (retryCount = CC_BROWSE_RETRYCOUNT; retryCount > 0; retryCount--)
    {
        NQ_HANDLE pipe = ccDcerpcConnect(server, pCredentials, ccSrvsvcGetPipe(), TRUE);
        if (NULL == pipe)
        {
            if (syGetLastError() == NQ_ERR_LOGONFAILURE)
                retryCount = 0;

            status = ccRapNetShareInfo(server, share, type, (NQ_WCHAR*)remarkBuffer, bufferSize, unicode);
        }
        else
        {
            status = ccSrvsvcGetShareInfo(pipe, server, share, type, remarkBuffer, bufferSize, unicode);
            ccDcerpcDisconnect(pipe);
        }
        if (NQ_SUCCESS != status)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Error retrieving shares list");
            sySetLastNqError((NQ_UINT32)status);
            continue;
        }

        goto Exit;
    }

Exit:
    cmMemoryFree(pCredentials);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result ? "TRUE" : "FALSE");
    return result;
}

/* --- API functions --- */

void ccNetworkCacheSet(NQ_UINT32 timeout)
{
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "timeout:%d", timeout);

    if (NULL != staticData)
    {
        syMutexTake(&staticData->guard);
        if ((timeout == 0) && staticData->cacheEnabled)
        {
            /* empty cache */
            validateCache(0);
        }
        staticData->cacheEnabled = (timeout != 0);
        staticData->cacheTimeout = timeout;
        syMutexGive(&staticData->guard);
    }
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

NQ_BOOL ccNetworkStart(void)
{
    NQ_BOOL result = FALSE;
    NQ_WCHAR *fullDomainNameW = NULL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    /* allocate memory */
#ifdef SY_FORCEALLOCATION
    staticData = (StaticData *)cmMemoryAllocate(sizeof(*staticData));
    if (NULL == staticData)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to allocate ccnetwork data");
        sySetLastError(NQ_ERR_NOMEM);
        goto Exit;
    }
#endif /* SY_FORCEALLOCATION */
    syMemset(staticData, 0, sizeof(StaticData));

#ifdef UD_NQ_USETRANSPORTNETBIOS
    staticData->requestSocket = nsGetCommonDatagramSocket();
#endif /* UD_NQ_USETRANSPORTNETBIOS */
    
    /* save NetBIOS domain name */
    if (NULL == cmGetFullDomainName())
    {
        staticData->theDomainW = cmMemoryCloneAString(cmNetBiosGetDomain()->name);
    }
    else
#ifdef UD_NQ_USETRANSPORTNETBIOS
    {
        fullDomainNameW = cmMemoryCloneAString(cmGetFullDomainName());
        if (NULL == fullDomainNameW)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
            sySetLastError(NQ_ERR_NOMEM);
            goto Exit;
        }
        staticData->theDomainW = getNetBIOSDomainName(fullDomainNameW);
    }
#else
    {
    	staticData->theDomainW = cmMemoryCloneAString(cmGetFullDomainName());
    }
#endif /* UD_NQ_USETRANSPORTNETBIOS */

	if (NULL == staticData->theDomainW)
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
		sySetLastError(NQ_ERR_NOMEM);
		goto Exit;
	}
    /* make sure same name in both buffers */
	staticData->theDomainA = cmMemoryCloneWStringAsAscii(staticData->theDomainW);
	if (NULL == staticData->theDomainA)
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
		sySetLastError(NQ_ERR_NOMEM);
		goto Exit;
	}
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "domain:%s", staticData->theDomainA);

    syMutexCreate(&staticData->guard);

    /* start list of all enumerations (also cache) */
    cmListStart(&staticData->enumerations);

    /* set cache timeout */
    ccNetworkCacheSet(NET_ENUM_CACHE_TTL);

    result = TRUE;

Exit:
    if (!result)
    {
        if (NULL != staticData && NULL != staticData->theDomainW)
        {
            cmMemoryFree(staticData->theDomainW);
            staticData->theDomainW = NULL;
        }
    }
    else
    {
    	isInitDone = TRUE;
    }

    if (NULL != fullDomainNameW)
        cmMemoryFree(fullDomainNameW);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result ? "true" : "false");
    return result;
}

void ccNetworkShutdown(void)
{
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    if (FALSE == isInitDone)
    {
#ifdef SY_FORCEALLOCATION
		if (NULL != staticData)
			cmMemoryFree(staticData);
		staticData = NULL;
#endif /* SY_FORCEALLOCATION */
		return;
    }

#ifdef SY_FORCEALLOCATION
    if (NULL == staticData)
    	return;
#endif

    syMutexDelete(&staticData->guard);
    if (NULL != staticData->theDomainW)
    {
        cmMemoryFree(staticData->theDomainW);
        staticData->theDomainW = NULL;
    }
    if (NULL != staticData->theDomainA)
	{
        cmMemoryFree(staticData->theDomainA);
        staticData->theDomainA = NULL;
	}
     
    validateCache(0);
    
    cmListShutdown(&staticData->enumerations);

#ifdef SY_FORCEALLOCATION
    if (NULL != staticData)
        cmMemoryFree(staticData);
    staticData = NULL;
#endif /* SY_FORCEALLOCATION */
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

/* --- Public API Functions --- */

NQ_HANDLE ccNetworkEnumerateDomains(void)
{
    NetEnum * pEnum;        /* domain enumeration */
    NQ_BOOL res = FALSE;    /* operation result */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);    

    pEnum = findInCache(NET_ENUM_TYPE_DOMAINS, staticData->theDomainW);
    if (NULL != pEnum)
    {
        res = TRUE;
        goto Exit;
    }

    pEnum = createEnumeration(NET_ENUM_TYPE_DOMAINS, staticData->theDomainW);
    if (NULL == pEnum)
    {
    	goto Exit;
    }

#ifdef UD_NQ_USETRANSPORTNETBIOS
    res = getGetDomainsNetBios(staticData->theDomainW, &pEnum->items);

    res |= getTrustedDomains(staticData->theDomainW, &pEnum->items);
#endif /* UD_NQ_USETRANSPORTNETBIOS */

Exit:
    if (NULL != pEnum)
    {
        if (res)
        {
            arrangeEnumeration(pEnum);
        }
        else
        {
            cmListItemUnlock((CMItem *)pEnum);
            if (staticData->cacheEnabled)
                cmListItemUnlock((CMItem *)pEnum);  /* locked twice for caching */
        }
    }
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%p", res ? pEnum : NULL);
    return res ? pEnum : NULL;
}
#ifdef UD_NQ_USETRANSPORTNETBIOS

void ccNetworkSetDefaultDomainA(const NQ_CHAR * domain)
{    
    if (NULL != domain)
    {
        const NQ_WCHAR * domainW = cmMemoryCloneAString(domain);

        if (NULL != domainW)
        {
            ccNetworkSetDefaultDomainW(domainW);
            cmMemoryFree(domainW);
        }
    }
    else
        sySetLastError(NQ_ERR_BADPARAM);
}

void ccNetworkSetDefaultDomainW(const NQ_WCHAR * domain)
{
    if (NULL != domain && syWStrlen(domain) < CM_DNS_NAMELEN)
    {
        syMutexTake(&staticData->guard);
        if (NULL != staticData->theDomainW)
            cmMemoryFree(staticData->theDomainW);
        staticData->theDomainW = getNetBIOSDomainName(domain);

        if (NULL != staticData->theDomainA)
            cmMemoryFree(staticData->theDomainA);
        staticData->theDomainA = cmMemoryCloneWStringAsAscii(staticData->theDomainW);
        syMutexGive(&staticData->guard);
    }
    else
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Domain name too long, max length is %d.", (CM_DNS_NAMELEN - 1));
        sySetLastError(NQ_ERR_BADPARAM);
    }
}

const NQ_CHAR * ccNetworkGetDefaultDomainA()
{
    return staticData->theDomainA;
}

const NQ_WCHAR* ccNetworkGetDefaultDomainW()
{
    return staticData->theDomainW;
}
#endif /* UD_NQ_USETRANSPORTNETBIOS */

NQ_HANDLE ccNetworkEnumerateServersA(const NQ_CHAR * domain)
{
    const NQ_WCHAR * domainW = NULL;   /* a copy in ASCII */
    NQ_HANDLE res = NULL;              /* resulted value */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    if (NULL != domain)
    {
        domainW = cmMemoryCloneAString(domain);
        if (NULL == domainW)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
            sySetLastError(NQ_ERR_NOMEM);
            goto Exit;
        }
    }
    res = ccNetworkEnumerateServersW(domainW);
    if (NULL != domainW)    
        cmMemoryFree(domainW);

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%p", res);
    return res;
}

NQ_HANDLE ccNetworkEnumerateServersW(const NQ_WCHAR * pDomainW)
{
#ifdef UD_NQ_USETRANSPORTNETBIOS
    const NQ_WCHAR * pDomain = NULL;
    NetEnum * pEnum = NULL;                 /* enumeration pointer */
    NQ_INT retryCount;                      /* just a counter */
    NQ_STATUS status;                       /* operation result */
    CMList *backupServers;                  /* backup servers list */
    CMIterator iterator;                    /* backup servers list iterator */
#endif /* UD_NQ_USETRANSPORTNETBIOS */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "domain:%s", cmWDump(pDomainW));

#ifdef UD_NQ_USETRANSPORTNETBIOS

    pDomain = (NULL == pDomainW) ? cmMemoryCloneWString(ccNetworkGetDefaultDomainW()) : getNetBIOSDomainName(pDomainW);
    if (NULL == pDomain)
    {
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        goto Exit;
    }

    pEnum = findInCache(NET_ENUM_TYPE_SERVERS, pDomain);
    if (NULL != pEnum)
    {
        goto Exit;
    }

    if (FALSE == getBackupServer(pDomain, TRUE, &backupServers))
    {
        sySetLastError(syGetLastError());
        goto Exit;
    }

    pEnum = createEnumeration(NET_ENUM_TYPE_SERVERS, pDomain);
    if (NULL == pEnum)
    {
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        goto Exit;
    } 

    cmListIteratorStart(backupServers, &iterator);
    while (cmListIteratorHasNext(&iterator))
    {
        CMItem * pItem;

        pItem = cmListIteratorNext(&iterator);
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Querying server: %s", cmWDump(pItem->name));
        for (retryCount = CC_BROWSE_RETRYCOUNT; retryCount > 0; retryCount--)
        {
            status = ccRapNetServerEnum(pItem->name, asciiAddNameCallback, &pEnum->items, SV_TYPE_ALL, pDomain);
            if (NQ_SUCCESS != status)
            {
                LOGERR(CM_TRC_LEVEL_ERROR, "Error retrieving hosts list");
                sySetLastError((NQ_UINT32)status);
                continue;
            }
            break;
        }
        if (NQ_SUCCESS == status)
            break;
    }
    cmListIteratorTerminate(&iterator);

Exit:
    if (NULL != pEnum)
    {
        if (cmListHasItems(&pEnum->items))
        {
            arrangeEnumeration(pEnum);
        }
        else
        {
            cmListItemUnlock((CMItem *)pEnum);
            if (staticData->cacheEnabled)
                cmListItemUnlock((CMItem *)pEnum);  /* locked twice for caching */
            pEnum = NULL;
        }
    }

    if (NULL != pDomain)
        cmMemoryFree(pDomain);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%p", pEnum);
    return pEnum;
#else /* UD_NQ_USETRANSPORTNETBIOS */
    return NULL;
#endif /* UD_NQ_USETRANSPORTNETBIOS */
}

NQ_HANDLE ccNetworkEnumerateSharesA(const NQ_CHAR * server)
{
    const NQ_WCHAR * serverW = NULL;   /* a copy in ASCII */
    NQ_HANDLE res = NULL;              /* resulted value */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    serverW = cmMemoryCloneAString(server);
    if (NULL == serverW)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        sySetLastError(NQ_ERR_NOMEM);
        goto Exit;
    }
    res = ccNetworkEnumerateSharesW(serverW);

Exit:
    cmMemoryFree(serverW);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%p", res);
    return res;
}

NQ_HANDLE ccNetworkEnumerateSharesW(const NQ_WCHAR * server)
{
    NQ_INT retryCount;                      /* just a counter */
    NetEnum * pEnum;                        /* enumeration pointer */
    NQ_STATUS status;                       /* operation result */
    NQ_HANDLE resultHdl = NULL;             /* return value */
    AMCredentialsW *pCredentials = NULL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "server:%s", cmWDump(server));

    pEnum = findInCache(NET_ENUM_TYPE_SHARES, server);
    if (NULL != pEnum)
    {
        resultHdl = pEnum;
        goto Exit;
    }

    pEnum = createEnumeration(NET_ENUM_TYPE_SHARES, server);
    if (NULL == pEnum)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        sySetLastNqError(NQ_ERR_OUTOFMEMORY);
        goto Exit;
    }

    pCredentials = (AMCredentialsW *)cmMemoryAllocate(sizeof(AMCredentialsW));
    if (NULL == pCredentials)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        sySetLastNqError(NQ_ERR_OUTOFMEMORY);
        goto Exit;
    }
    udGetCredentials(NULL, pCredentials->user,
                           pCredentials->password,
                           pCredentials->domain.name);

    for (retryCount = CC_BROWSE_RETRYCOUNT; retryCount>0; retryCount--)
    {
        NQ_HANDLE pipe;                 /* pipe handle for SRVSVC */

        pipe = ccDcerpcConnect(server, pCredentials, ccSrvsvcGetPipe(), TRUE);
        if (NULL == pipe)
        {
            status = ccRapNetShareEnum(server, asciiAddShareNameCallback, &pEnum->items);
            if (NQ_SUCCESS != status)
            {
                LOGERR(CM_TRC_LEVEL_ERROR, "Error retrieving shares list");
                sySetLastNqError((NQ_UINT32)status);
                continue;
            }
            break;
        }
        else
        {
            status = ccSrvsvcEnumerateShares(pipe, server, addShareNameCallback, &pEnum->items);
            ccDcerpcDisconnect(pipe);
            if (NQ_SUCCESS != status)
            {
                LOGERR(CM_TRC_LEVEL_ERROR, "Error retrieving shares list");
                sySetLastNqError((NQ_UINT32)status);
                continue;
            }
            break;
        }
    }
Exit:
    if (NULL != pEnum)
    {
        if (cmListHasItems(&pEnum->items))
        {
            arrangeEnumeration(pEnum);
            resultHdl = pEnum;
        }
        else
        {
            cmListItemUnlock((CMItem *)pEnum);
            if (staticData->cacheEnabled)
                cmListItemUnlock((CMItem *)pEnum);  /* locked twice for caching */
        }
    }

    cmMemoryFree(pCredentials);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%p", resultHdl);
    return resultHdl;
}

const NQ_CHAR * ccNetworkGetNextItemNameA(NQ_HANDLE handle)
{
    NetEnum * pEnum = (NetEnum *)handle;    /* casted pointer */
    NetItem * pItem;                        /* next result */
    const NQ_CHAR * pResult = NULL;         /* return result */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    if (NULL == pEnum)
        goto Exit;

    pItem = pEnum->next;
    if (NULL == pItem)
        goto Exit;

    pEnum->next = (NetItem *)pItem->item.next;
    if (NULL == pItem->aName)
    {
        pItem->aName = cmMemoryCloneWStringAsAscii(pItem->item.name);
        if (NULL == pItem->aName)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
            sySetLastNqError(NQ_ERR_OUTOFMEMORY);
            goto Exit;
        }
    }
    pResult = pItem->aName;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return pResult;
}

const NQ_WCHAR * ccNetworkGetNextItemNameW(NQ_HANDLE handle)
{
    NetEnum * pEnum = (NetEnum *)handle;            /* casted pointer */
    NetItem * pItem = pEnum->next;                  /* next result */
    const NQ_WCHAR * pResult = NULL;                /* return result */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    if (NULL == pItem)
        goto Exit;
    pEnum->next = (NetItem *)pItem->item.next;

    pResult = pItem->item.name;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return pResult;
}

CCNetShareItem * ccNetworkGetNextShareItem(NQ_HANDLE handle)
{
    NetEnum * pEnum = (NetEnum *)handle;    /* casted pointer */
    NetItem * pItem = pEnum->next;          /* next result */
    CCNetShareItem * pResult = NULL;        /* return result */

    if (NULL == pItem)
        goto Exit;
    pEnum->next = (NetItem *)pItem->item.next;

    pResult = &pItem->share;

Exit:
    return pResult;
}

NQ_BOOL ccNetworkGetShareInfoA(const NQ_CHAR * server, const NQ_CHAR * share, NQ_UINT16 * type, NQ_CHAR * remarkBuffer, NQ_INT bufferSize)
{
    const NQ_WCHAR * serverW = NULL;       /* a Unicode copy */
    const NQ_WCHAR * shareW = NULL;        /* a Unicode copy */
    NQ_BOOL res = FALSE;                   /* value to return */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "server:%s share:%s type:%p remark:%p size:%d", server ? server : "", share ? share : "", type, remarkBuffer, bufferSize);

    serverW = cmMemoryCloneAString(server);
    shareW = cmMemoryCloneAString(share);
    if (NULL != serverW && NULL != shareW)
    {
        res = getShareInfo(serverW, shareW, type, (NQ_BYTE *)remarkBuffer, bufferSize , FALSE);
    }
    else
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        sySetLastError(NQ_ERR_NOMEM);
        goto Exit;
    }

Exit:
    cmMemoryFree(serverW);
    cmMemoryFree(shareW);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", res ? "TRUE" : "FALSE");
    return res;
}

NQ_BOOL ccNetworkGetShareInfoW(const NQ_WCHAR * server, const NQ_WCHAR * share, NQ_UINT16 * type, NQ_WCHAR * remarkBuffer, NQ_INT bufferSize)
{
    NQ_BOOL res;                    /* value to return */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "server:%s share:%s type:%p remark:%p size:%d", cmWDump(server), cmWDump(share), type, remarkBuffer, bufferSize);

    res = getShareInfo(server, share, type, (NQ_BYTE *)remarkBuffer, bufferSize, TRUE);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", res ? "TRUE" : "FALSE");
    return res;
}

NQ_BOOL ccNetworkCloseHandle(NQ_HANDLE handle)
{
    NetEnum * pEnum = (NetEnum *)handle;            /* casted pointer */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "handle:%p", handle);
     
    cmListItemUnlock((CMItem *)pEnum);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return TRUE;
}

NQ_BOOL ccNetworkResetHandle(NQ_HANDLE handle)
{
    NetEnum * pEnum = (NetEnum *)handle;            /* casted pointer */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "handle:%p", handle);

    pEnum->next = (NetItem *)pEnum->items.first;
    
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return TRUE;
}

#endif /* UD_NQ_INCLUDECIFSCLIENT */
