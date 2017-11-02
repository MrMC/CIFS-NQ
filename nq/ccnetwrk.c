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

#ifdef UD_NQ_INCLUDECIFSCLIENT

/* --- Definitions --- */

/* an item representing an abstract network entity: it may be a domain, a server or a share */
typedef struct 
{
    CMItem item;                /* inherited CMItem */
    const NQ_CHAR * aName;      /* ASCII name. May be NULL when ASCII name was not requested yet */
}
NetItem;

/* an active enumeration */
typedef struct 
{
    CMItem item;                /* inherited item */
    CMList items;               /* enumeration items */
    NetItem * next;             /* for iteration */
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

CMList enumerations;                        /* active enumerations */ 
static const NQ_WCHAR * theDomain;          /* NQ domain */
static SYMutex guard;                       /* for critical sections */
#ifdef UD_NQ_USETRANSPORTNETBIOS
static NSSocketHandle requestSocket = NULL; /* shared socket for browse requests */
#endif /* UD_NQ_USETRANSPORTNETBIOS */

/* --- Static functions --- */

static NQ_BOOL disposeEnum(CMItem * pItem)
{
    NetEnum * pEnum = (NetEnum *)pItem;
	
	cmListShutdown(&pEnum->items);
	cmListItemRemoveAndDispose((CMItem *)pEnum);
    return TRUE;
}

static NQ_BOOL disposeItem(CMItem * pItem)
{
    NetItem * pNetItem = (NetItem *)pItem;
    cmMemoryFree(pNetItem->aName);
	cmListItemRemoveAndDispose((CMItem *)pNetItem);
    return TRUE;
}

/* This callback function is called from several result parsers when they encounter another item.  
   This function creates an item and adds it to the respective list */ 
static void addNameCallback(const NQ_WCHAR * name, void * list)
{
    CMList * pList = (CMList *) list;   /* casted pointer */
    NetItem * pItem;                    /* casted pointer */

    if (NULL == cmListItemFind(pList, name, TRUE, FALSE))
    {
        pItem = (NetItem *)cmListItemCreateAndAdd(pList, sizeof(NetItem), name, disposeItem , FALSE);
        if (NULL != pItem)
            pItem->aName = NULL;
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

#ifdef UD_NQ_USETRANSPORTNETBIOS

static NQ_UINT32 createToken(void)
{
    static NQ_UINT32 token = 1;
    NQ_UINT32 res;

    res = token++;
    return res;
}

static const NQ_WCHAR * getBackupServerByDomain(const NQ_WCHAR * pDomain)
{
    CMNetBiosNameInfo nbName;               /* NETBIOS source  and destination name */
    CMCifsTransactionRequest * transCmd;    /* pointer to SMB Transaction words */ 
    NQ_UINT paramCount;                     /* number of parameter bytes */
    NQ_UINT dataCount;                      /* number of data bytes */
    static const BrowserMailSlot browser = { "\\MAILSLOT\\BROWSE" }; /* mailslot name */
    GetBackupListReq request;               /* BROWSER request */
    NQ_BYTE * data;                         /* Transaction data pointer */
    NQ_BYTE * parameters;                   /* Transaction parameters pointer */
    NQ_STATUS status;                       /* operation status */
    NQ_UINT32 token;                        /* next request token */
    const NQ_CHAR * pServer;			    /* pointer to next server name */
    GetBackupListRsp * pResponse;           /* pointer to RAP structure in response */
    NQ_BYTE * rspData;			            /* pointer to data in response */
    NQ_UINT16 i;		                    /* counter of entries in response */
    NQ_BYTE * pBuffer = NULL;               /* pointer to the response buffer to free later */
    const NQ_WCHAR * result;                /* the server name to return */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    nbName.isGroup = TRUE;
    cmUnicodeToAnsi(nbName.name, pDomain);
    cmNetBiosNameFormat(nbName.name, *pDomain == 0x01? 0x01 : CM_NB_POSTFIX_MASTERBROWSER);

    syMutexTake(&guard);    /* protect socket and request buffer */

    request.opCode = 9;
    request.count = 10;
    token = createToken();
    cmPutSUint32(request.token, cmHtol32(token));

    transCmd = ccTransGetCmdPacket(&parameters, 3);
    if (NULL == transCmd)
    {
        syMutexGive(&guard);
        sySetLastError(NQ_ERR_NORESOURCE);
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to allocate Transaction packet");
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NULL;
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
            requestSocket, 
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
        ccTransPutCmdPacket(transCmd);
        syMutexGive(&guard);
        sySetLastError(status);
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to send GetBackupList request");
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NULL;
    }

    ccTransPutCmdPacket(transCmd);

    status = ccTransReceiveFrom(requestSocket, &nbName, NULL, NULL, &dataCount, &rspData, &pBuffer);
    syMutexGive(&guard);    /* free socket and request buffer */
    pResponse = (GetBackupListRsp *)rspData;
    if (NQ_SUCCESS != status || pResponse->opCode != 10 || pResponse->count == 0)
    {
        if (NULL != pBuffer)
            cmMemoryFree(pBuffer);
        sySetLastError(status);
        LOGERR(CM_TRC_LEVEL_ERROR, "No valid GetBackupList response");
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NULL;
    }

    /* we behave as MS by taking the last one in the list */ 
    for (i = 0, pServer = (NQ_CHAR*)(pResponse + 1); i < (pResponse->count - 1); i++)
    {
        pServer += syStrlen(pServer) + 1;
    }
    result = cmMemoryCloneAString(pServer);

    cmMemoryFree(pBuffer);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return result;
}

/* this function returns an allocated result or NULL */
static const NQ_WCHAR * getBackupServer(const NQ_WCHAR * pDomain , NQ_BOOL findAny)
{
    static const NQ_WCHAR browser[] = { cmWChar(0x01), 
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
    const NQ_WCHAR  *   result;
    const NQ_WCHAR  *   domainToUse = NULL;
    NQ_WCHAR        *   domainToMod = NULL;
    NQ_WCHAR        *   point;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    point = syWStrchr(pDomain, cmWChar('.'));
	if (point != NULL)
	{
        domainToMod = (NQ_WCHAR *)cmMemoryAllocate((NQ_UINT)((syWStrlen(pDomain)-syWStrlen(point)+1) * sizeof(NQ_WCHAR)));
        if (NULL != domainToMod)
        {
            syWStrncpy(domainToMod , pDomain , syWStrlen(pDomain)-syWStrlen(point));
            domainToMod[syWStrlen(pDomain)-syWStrlen(point)] = cmWChar('\0');
            domainToUse = cmMemoryCloneWString(domainToMod);
        }
	}
	else
    {
		domainToUse = cmMemoryCloneWString(pDomain);
    }
    
    if (NULL == pDomain)
    {
        cmMemoryFree(domainToUse);
        domainToUse = cmMemoryCloneWString(browser);
    }
    
    result = getBackupServerByDomain(domainToUse);
    if (NULL != pDomain && NULL == result && findAny)
        result = getBackupServerByDomain(browser);

    cmMemoryFree(domainToUse);
    cmMemoryFree(domainToMod);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return result;
}

#ifdef UD_NQ_USETRANSPORTNETBIOS

static NQ_BOOL getGetDomainsNetBios(const NQ_WCHAR * pDomain, CMList * pList)
{
    NQ_INT retryCount;		        /* repeat three times */
    const NQ_WCHAR * pServerName;   /* backup server name */
    NQ_STATUS status;		        /* operation result */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    if (cmWStrlen(pDomain) >= CM_DNS_NAMELEN)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Workgroup name is too long");
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        sySetLastNqError(NQ_ERR_BADPARAM);
        return FALSE;
    }

    for (retryCount = CC_BROWSE_RETRYCOUNT; retryCount>0; retryCount--)
    {
        pServerName = getBackupServer(pDomain , TRUE);

        if (NULL == pServerName)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Error retrieving domain backup list");
            continue;
        }
        status = ccRapNetServerEnum(pServerName, asciiAddNameCallback, pList, SV_TYPE_DOMAIN_ENUM, NULL);
    	cmMemoryFree(pServerName);
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
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return status == NQ_SUCCESS;
    }

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return FALSE;
}

#endif /* UD_NQ_USETRANSPORTNETBIOS */

static NQ_BOOL getTrustedDomains(const NQ_WCHAR * pDomain, CMList * pEnum)
{
    NQ_WCHAR * dc;				/* domain controller in Unicode */
    NQ_CHAR * dcA;				/* the same in ASCII */
    NQ_CHAR * domainA;		    /* workgroup/domain copy in ASCII */
    NQ_HANDLE netlogon;         /* handle of NetLogon pipe */
    NQ_BOOL res = FALSE;        /* value to return */
    NQ_UINT32 status;           /* operation status */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);    
    
    /* allocate buffers and convert strings */
    domainA = cmMemoryCloneWStringAsAscii(pDomain);
    dcA = cmMemoryAllocate(sizeof(NQ_BYTE) * CM_DNS_NAMELEN);
	if (NULL == domainA || NULL == dcA)
	{
    	cmMemoryFree(domainA);   /* NULL ignored */
    	cmMemoryFree(dcA);          /* NULL ignored */
		sySetLastNqError(NQ_ERR_OUTOFMEMORY);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return FALSE;
	}
    
    /* find domain controller by domain name */
    if (cmGetDCNameByDomain(domainA, dcA) != NQ_SUCCESS)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to get dc for domain %s", domainA);
    	cmMemoryFree(domainA);
    	cmMemoryFree(dcA);
        sySetLastNqError(NQ_ERR_BADPARAM);
        LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
        return FALSE;        
    }
    
    /* allocate more buffers and strings and free used */
    dc = cmMemoryCloneAString(dcA);
	cmMemoryFree(domainA);
	cmMemoryFree(dcA);

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
    cmMemoryFree(dc);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return res;
}

#endif /* UD_NQ_USETRANSPORTNETBIOS */

static NetEnum * createEnumeration(void)
{
    NetEnum * pEnum;    /* pointer to the enumeration to create */

    pEnum = (NetEnum *)cmListItemCreateAndAdd(&enumerations, sizeof(NetEnum), NULL, &disposeEnum , FALSE);
    if (NULL == pEnum)
    {
        sySetLastError(NQ_ERR_NOMEM);
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        return NULL;
    }
    cmListStart(&pEnum->items);
    return pEnum;
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
#ifndef UD_CM_UNICODEAPPLICATION
    AMCredentialsA *pCredentialsA = NULL;
#endif

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    pCredentials = cmMemoryAllocate(sizeof(AMCredentialsW));
    if (NULL == pCredentials)
	{
		sySetLastNqError(NQ_ERR_OUTOFMEMORY);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return FALSE;
	}
#ifdef UD_CM_UNICODEAPPLICATION
    udGetCredentials(NULL, pCredentials->user,
                           pCredentials->password,
                           pCredentials->domain.name);
#else
    pCredentialsA = cmMemoryAllocate(sizeof(AMCredentialsA));
    if (NULL == pCredentialsA)
	{
    	cmMemoryFree(pCredentials);
		sySetLastNqError(NQ_ERR_OUTOFMEMORY);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return FALSE;
	}
    udGetCredentials(NULL, pCredentialsA->user,
                           pCredentialsA->password,
                           pCredentialsA->domain.name);
    amCredentialsAsciiiToW(pCredentials, pCredentialsA);
    cmMemoryFree(pCredentialsA);
#endif

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

        cmMemoryFree(pCredentials);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return TRUE;
    }

    cmMemoryFree(pCredentials);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return FALSE;
}

/* --- API functions --- */

NQ_BOOL ccNetworkStart(void)
{
#ifdef UD_NQ_USETRANSPORTNETBIOS
    requestSocket = nsGetCommonDatagramSocket();
#endif /* UD_NQ_USETRANSPORTNETBIOS */
    cmListStart(&enumerations);
    /* save domain */
    theDomain = cmMemoryCloneAString(cmNetBiosGetDomain()->name);
    if (NULL == theDomain)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        return FALSE;
    }
    syMutexCreate(&guard);
    return TRUE;
}

void ccNetworkShutdown(void)
{
    syMutexDelete(&guard);
    cmMemoryFree(theDomain);
    cmListShutdown(&enumerations);
}

/* --- Public API Functions --- */

#ifdef UD_NQ_USETRANSPORTNETBIOS

NQ_HANDLE ccNetworkEnumerateDomains(void)
{   
    NetEnum * pEnum;        /* domain enumeration */
    NQ_BOOL res = FALSE;        /* operation result */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    pEnum = createEnumeration();
    if (NULL != pEnum)
    {
#ifdef UD_NQ_USETRANSPORTNETBIOS
        res = getGetDomainsNetBios(theDomain, &pEnum->items);
#endif /* UD_NQ_USETRANSPORTNETBIOS */
        res |= getTrustedDomains(theDomain, &pEnum->items);
    }
    if (NULL != pEnum)
        arrangeEnumeration(pEnum);
	if (!res)
		cmListItemUnlock((CMItem *)pEnum);
	
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return res? pEnum : NULL;
}

#endif /* UD_NQ_USETRANSPORTNETBIOS */

NQ_HANDLE ccNetworkEnumerateServersA(const NQ_CHAR * domain)
{
    const NQ_WCHAR * domainW;   /* a copy in ASCII */
    NQ_HANDLE res;              /* resulted value */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    domainW = cmMemoryCloneAString(domain);
    if (NULL == domainW)
    {
        sySetLastError(NQ_ERR_NOMEM);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NULL;
    }

    res = ccNetworkEnumerateServersW(domainW);
    cmMemoryFree(domainW);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return res;
}

NQ_HANDLE ccNetworkEnumerateServersW(const NQ_WCHAR * pDomain)
{
#ifdef UD_NQ_USETRANSPORTNETBIOS
    NetEnum * pEnum = NULL;                 /* enumeration pointer */
    NQ_INT retryCount;                      /* just a counter */
    const NQ_WCHAR * backupServer;          /* backup server name */
    NQ_STATUS status;                       /* operation result */
#endif /* UD_NQ_USETRANSPORTNETBIOS */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

#ifdef UD_NQ_USETRANSPORTNETBIOS
    backupServer = getBackupServer(pDomain , FALSE);
    if (NULL == backupServer)
    {
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NULL;
    }

    pEnum = createEnumeration();
    if (NULL == pEnum)
    {
    	cmMemoryFree(backupServer);
        return NULL;
    }

	for (retryCount = CC_BROWSE_RETRYCOUNT; retryCount>0; retryCount--)
    {
        status = ccRapNetServerEnum(
            backupServer, 
            asciiAddNameCallback, 
            &pEnum->items,
            0xffffffff /*SV_TYPE_WORKSTATION | SV_TYPE_SERVER*/, 
            pDomain
            );
        if (NQ_SUCCESS != status)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Error retrieving hosts list");
            sySetLastNqError((NQ_UINT32)status);
            continue;
        }
        break;
    }
	cmMemoryFree(backupServer);

    if (NULL != pEnum && cmListHasItems(&pEnum->items))
    {
        arrangeEnumeration(pEnum);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return pEnum;
    }
    if (NULL != pEnum)
		cmListItemUnlock((CMItem *)pEnum);
#endif /* UD_NQ_USETRANSPORTNETBIOS */

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return NULL;
}

NQ_HANDLE ccNetworkEnumerateSharesA(const NQ_CHAR * server)
{
    const NQ_WCHAR * serverW;   /* a copy in ASCII */
    NQ_HANDLE res;              /* resulted value */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    serverW = cmMemoryCloneAString(server);
    if (NULL == serverW)
    {
        sySetLastError(NQ_ERR_NOMEM);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NULL;
    }

    res = ccNetworkEnumerateSharesW(serverW);
    cmMemoryFree(serverW);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return res;
}

NQ_HANDLE ccNetworkEnumerateSharesW(const NQ_WCHAR * server)
{
    NQ_INT retryCount;                      /* just a counter */
    NetEnum * pEnum = NULL;                 /* enumeration pointer */
    NQ_STATUS status;                       /* operation result */
    AMCredentialsW *pCredentials = NULL;
#ifndef UD_CM_UNICODEAPPLICATION
    AMCredentialsA *pCredentialsA = NULL;
#endif

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    pEnum = createEnumeration();
    if (NULL == pEnum)
        return NULL;

    pCredentials = cmMemoryAllocate(sizeof(AMCredentialsW));
    if (NULL == pCredentials)
	{
		sySetLastNqError(NQ_ERR_OUTOFMEMORY);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NULL;
	}
#ifdef UD_CM_UNICODEAPPLICATION
    udGetCredentials(NULL, pCredentials->user,
                           pCredentials->password,
                           pCredentials->domain.name);
#else
    pCredentialsA = cmMemoryAllocate(sizeof(AMCredentialsA));
    if (NULL == pCredentialsA)
	{
    	cmMemoryFree(pCredentials);
		sySetLastNqError(NQ_ERR_OUTOFMEMORY);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NULL;
	}
    udGetCredentials(NULL, pCredentialsA->user,
                           pCredentialsA->password,
                           pCredentialsA->domain.name);
    amCredentialsAsciiiToW(pCredentials, pCredentialsA);
    cmMemoryFree(pCredentialsA);
#endif

    for (retryCount = CC_BROWSE_RETRYCOUNT; retryCount>0; retryCount--)
    {
        NQ_HANDLE pipe;                 /* pipe handle for SRVSVC */

        pipe = ccDcerpcConnect(server, pCredentials, ccSrvsvcGetPipe(), TRUE);
        if (NULL == pipe)
        {
            status = ccRapNetShareEnum(server, asciiAddNameCallback, &pEnum->items);
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
            status = ccSrvsvcEnumerateShares(pipe, server, addNameCallback, &pEnum->items);
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

    cmMemoryFree(pCredentials);

    if (NULL != pEnum && cmListHasItems(&pEnum->items))
    {
        arrangeEnumeration(pEnum);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return pEnum;
    }

    if (NULL != pEnum)
		cmListItemUnlock((CMItem *)pEnum);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return NULL;
}

const NQ_CHAR * ccNetworkGetNextItemNameA(NQ_HANDLE handle)
{
    NetEnum * pEnum = (NetEnum *)handle;            /* casted pointer */
    NetItem * pItem = pEnum->next;                  /* next result */

    if (NULL == pItem)
        return NULL;
    pEnum->next = (NetItem *)pItem->item.next;
    if (NULL == pItem->aName)
    {
        pItem->aName = cmMemoryCloneWStringAsAscii(pItem->item.name);
    }
    return pItem->aName;
}

const NQ_WCHAR * ccNetworkGetNextItemNameW(NQ_HANDLE handle)
{
    NetEnum * pEnum = (NetEnum *)handle;            /* casted pointer */
    NetItem * pItem = pEnum->next;                  /* next result */

    if (NULL == pItem)
        return NULL;
    pEnum->next = (NetItem *)pItem->item.next;
    return pItem->item.name;
}

NQ_BOOL ccNetworkGetShareInfoA(const NQ_CHAR * server, const NQ_CHAR * share, NQ_UINT16 * type, NQ_CHAR * remarkBuffer, NQ_INT bufferSize)
{
    const NQ_WCHAR * serverW;       /* a Unicode copy */
    const NQ_WCHAR * shareW;        /* a Unicode copy */
    NQ_BOOL res = FALSE;            /* value to return */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    serverW = cmMemoryCloneAString(server);
    shareW = cmMemoryCloneAString(share);
    if (NULL != serverW && NULL != shareW)
    {
        res = getShareInfo(serverW, shareW, type, (NQ_BYTE *)remarkBuffer, bufferSize , FALSE);
    }
    else
    {
        sySetLastError(NQ_ERR_NOMEM);
    }

    cmMemoryFree(serverW);
    cmMemoryFree(shareW);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return res;
}

NQ_BOOL ccNetworkGetShareInfoW(const NQ_WCHAR * server, const NQ_WCHAR * share, NQ_UINT16 * type, NQ_WCHAR * remarkBuffer, NQ_INT bufferSize)
{
    NQ_BOOL res;                    /* value to return */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    res = getShareInfo(server, share, type, (NQ_BYTE *)remarkBuffer, bufferSize, TRUE);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return res;
}

NQ_BOOL ccNetworkCloseHandle(NQ_HANDLE handle)
{
    NetEnum * pEnum = (NetEnum *)handle;            /* casted pointer */
    cmListItemUnlock((CMItem *)pEnum);
    return TRUE;
}

NQ_BOOL ccNetworkResetHandle(NQ_HANDLE handle)
{
    NetEnum * pEnum = (NetEnum *)handle;            /* casted pointer */

    pEnum->next = (NetItem *)pEnum->items.first;
    return TRUE;
}

#endif /* UD_NQ_INCLUDECIFSCLIENT */
