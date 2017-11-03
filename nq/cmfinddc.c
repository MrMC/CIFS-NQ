/*********************************************************************
 *
 *           Copyright (c) 2001 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Domain controller discovery library
 *--------------------------------------------------------------------
 * DEPENDENCIES  : None
 *--------------------------------------------------------------------
 * CREATION DATE : 20-Jan-2005
 * CREATED BY    : Igor Gokhman
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "cmapi.h"
#include "cmcrypt.h"
#include "nsapi.h"
#include "nqapi.h"

#include "cmfinddc.h"
#ifdef UD_NQ_INCLUDESMB2
#include "cmsmb2.h"
#endif /* UD_NQ_INCLUDESMB2 */
#ifdef UD_CS_INCLUDEEXTENDEDSECURITY
#include "cmgssapi.h"
#endif /* UD_CS_INCLUDEEXTENDEDSECURITY */

/*
    defines
*/

#define OPCODE_NETLOGONQUERY    ((NQ_BYTE)7)
#define OPCODE_NETLOGONRESPONSE ((NQ_BYTE)12)
#define MS_REQ_NETLOGONQUERY    "\\MAILSLOT\\NET\\NETLOGON"     /* NETLOGON_QUERY request mailslot name */
#define MS_RSP_NETLOGONQUERY    "\\MAILSLOT\\TEMP\\NETLOGON"    /* NETLOGON_QUERY response mailslot name */
#define LM20TOKEN               ((NQ_UINT16)0xFFFF)

#define PASSTHROUGH_TIMEOUT     10
#define TRANSACTION_TIMEOUT     ((NQ_UINT32)1000)
#define PDC_QUERY_TIMEOUT       5
#define TRANSACTION_SETUP_COUNT 3

#define EXISTING_PDC_TTL 60          /* timeout for cache entry in seconds */
#define NONEXISTING_PDC_TTL 10       /* the same when no PDC was found */

typedef struct
{
    CMItem item;                                /* inherited object */
    NQ_UINT32 time;                               /* time when this entry was cached */
    NQ_UINT32 ttl;                                /* time to live */
    NQ_BOOL doesExist;                          /* TRUE if the PDC exists, FALSE otherwise */
    NQ_CHAR pdcName[CM_NQ_HOSTNAMESIZE + 1];    /* PDC name */
    NQ_BOOL isDefaultDomain;                    /* TRUE when entry is for default domain, never expires */
}
CacheEntry;          /* an association between domain name and host name */

/* 
    static data 
*/

typedef struct
{
    NQ_BOOL pdcDiscovered;                      /* whether PDC was found already */
    NQ_CHAR pdcName[CM_NQ_HOSTNAMESIZE + 1];    /* PDC name                      */
    const NQ_CHAR *domainName;                  /* domain name                   */ 
    CMList cache;                               /* cached domains                */
}
StaticData;

#ifdef SY_FORCEALLOCATION
static StaticData* staticData = NULL;
#else  /* SY_FORCEALLOCATION */
static StaticData staticDataSrc;
static StaticData* staticData = &staticDataSrc;
#endif /* SY_FORCEALLOCATION */

/* 
   functions 
*/

/*
 *====================================================================
 * PURPOSE: Initialize find DC resources
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:   
 *====================================================================
 */

NQ_STATUS
cmFindDCInit(
    void
    )
{
    NQ_STATUS result = NQ_FAIL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    /* allocate memory */
#ifdef SY_FORCEALLOCATION
    staticData = (StaticData *)cmMemoryAllocate(sizeof(*staticData));
    if (NULL == staticData)
    {
       sySetLastError(NQ_ERR_NOMEM);
       goto Exit;
    }
#endif /* SY_FORCEALLOCATION */
    staticData->pdcDiscovered = FALSE;  
    staticData->domainName = NULL;
    cmListStart(&staticData->cache);
    result = NQ_SUCCESS;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
}

/*
 *====================================================================
 * PURPOSE: Release find DC resources
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: NONE
 *
 * NOTES:   
 *====================================================================
 */

void
cmFindDCExit(
    void
    )
{
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
    
    cmListShutdown(&staticData->cache);

    /* release memory */
#ifdef SY_FORCEALLOCATION
    if (NULL != staticData)
        cmMemoryFree(staticData);
    staticData = NULL;
#endif /* SY_FORCEALLOCATION */

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

static void validateCache()
{
    CMIterator iterator;            /* for iterating cache items */
    NQ_UINT32 curTime;                /* current time in seconds */

    curTime  = (NQ_UINT32)syGetTimeInSec();
    cmListIteratorStart(&staticData->cache, &iterator);
    while (cmListIteratorHasNext(&iterator))
    {
        const CacheEntry * pEntry;   /* next cache entry */
        
        pEntry = (const CacheEntry *)cmListIteratorNext(&iterator);
        if (!pEntry->isDefaultDomain && pEntry->ttl < (curTime - pEntry->time))
        {
            cmListItemRemoveAndDispose((CMItem *)pEntry);
        }
    }
    cmListIteratorTerminate(&iterator);
}

static const CacheEntry * lookupNameInCache(const NQ_CHAR * name)
{
    NQ_WCHAR * nameW;                       /* name in Unicode */
    const CacheEntry * result = NULL;       /* lookup result */   

    nameW = cmMemoryCloneAString(name);
    if (NULL != nameW)
    {
        validateCache();
        result = (const CacheEntry *)cmListItemFind(&staticData->cache, nameW, TRUE , FALSE);
        cmMemoryFree(nameW);
    }
    else
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
    }
    return result;
}

static void addToCache(const NQ_CHAR * domain, const NQ_CHAR * pdc, NQ_BOOL doesExist, NQ_BOOL isDefaultDomain)
{
    NQ_WCHAR * nameW = NULL;        /* name in Unicode */
    CacheEntry * pEntry = NULL;     /* new entry */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "domain:%s pcd:%s exists:%s isDefault:%s", domain ? domain : "", pdc ? pdc : "", doesExist ? "TRUE" : "FALSE", isDefaultDomain ? "TRUE" : "FALSE");
    /*LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "domain: %s, pdc: %s, exists: %d", domain, pdc, doesExist);*/

    nameW = cmMemoryCloneAString(domain);
    if (NULL == nameW)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        goto Exit;
    }
    pEntry = (CacheEntry *)cmListItemCreateAndAdd(&staticData->cache, sizeof(CacheEntry), nameW, NULL, CM_LISTITEM_NOLOCK);
    if (NULL == pEntry)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        goto Exit;
    }
    pEntry->doesExist = doesExist;
    pEntry->time = (NQ_UINT32)syGetTimeInSec();
    pEntry->ttl = doesExist ? EXISTING_PDC_TTL : NONEXISTING_PDC_TTL;
    syStrncpy(pEntry->pdcName, pdc, sizeof(pEntry->pdcName) - 2);
    pEntry->isDefaultDomain = isDefaultDomain;

Exit:
    cmMemoryFree(nameW);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

/*
 *====================================================================
 * PURPOSE: query given domain for its PDC name and return this name upon success
 *--------------------------------------------------------------------
 * PARAMS:  IN  domain name
 *          OUT PDC name
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:
 *====================================================================
 */

NQ_STATUS cmGetDCNameByDomain(const NQ_CHAR* domain, NQ_CHAR *pdc)
{
    const CacheEntry *pEntry;
    const NQ_WCHAR *dcW = NULL, *domainW = NULL, *dcListW = NULL;
    NQ_INT numDCs, i;
    NQ_STATUS result = NQ_FAIL;
    const NQ_IPADDRESS * ips = NULL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "domain:%s pdc:%p", domain ? domain : "", pdc);

    /* check in cache first */
    pEntry = lookupNameInCache(domain);
    if (NULL != pEntry)
    {
        if (pEntry->doesExist)
        {
            syStrcpy(pdc, pEntry->pdcName);
        }
        else
        {
            sySetLastError(NQ_ERR_BADPATH);
        }
        result = pEntry->doesExist ? NQ_SUCCESS : NQ_FAIL;
        goto Exit;
    }
  
    /* resolve */
    domainW = cmMemoryCloneAString(domain);
    if (NULL == domainW)
    {
        sySetLastError(NQ_ERR_NOMEM);
        goto Exit;
    }
    dcListW = cmResolverGetDCName(domainW, &numDCs);
    if (NULL != dcListW)
    {
        for (dcW = dcListW, i = 0; i < numDCs; i++, dcW += cmWStrlen(dcW) + 1)
        {
	        NQ_INT numIps;
            LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "DC: %s", cmWDump(dcW));

            ips = cmResolverGetHostIps(dcW, &numIps);
            if (NULL != ips)
            {
                cmUnicodeToAnsi(pdc, dcW);
                addToCache(domain, pdc, TRUE, FALSE);
                LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "PDC = %s, Domain = %s", pdc, domain);
                result = NQ_SUCCESS;
                goto Exit;
            }
        }
    }

    pdc[0] = '\0';
    addToCache(domain, pdc, FALSE, FALSE);
    sySetLastError(NQ_ERR_BADPATH);

Exit:
    cmMemoryFree(ips);
    cmMemoryFree(dcListW);
    cmMemoryFree(domainW);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d pdc:%s", result, pdc);
    return result;
}

/*
 *====================================================================
 * PURPOSE: query DEFAULT domain for its PDC name and return this name upon success
 *--------------------------------------------------------------------
 * PARAMS:  OUT PDC name
 *          OUT domain name (IN may be NULL)
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:
 *====================================================================
 */

NQ_STATUS cmGetDCName(NQ_CHAR* pdc, const NQ_CHAR** domainBuffer)
{
    NQ_STATUS result = NQ_FAIL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "pdc:%p domain:%p", pdc, domainBuffer);

    if (!staticData->pdcDiscovered)
    {
        staticData->domainName = cmGetFullDomainName() ? cmGetFullDomainName() : cmNetBiosGetDomain()->name;
 
        if (NQ_SUCCESS != cmGetDCNameByDomain(staticData->domainName, pdc))
        {
            sySetLastError(NQ_ERR_BADPATH);
            goto Exit;
        }
        staticData->pdcDiscovered = TRUE;        
        syStrcpy(staticData->pdcName, pdc);

        addToCache(staticData->domainName, pdc, TRUE, TRUE);
        /* add to cache NetBIOS form of domain name */
        addToCache(cmNetBiosGetDomainAuth()->name, pdc, TRUE, TRUE);
    }

    syStrcpy(pdc, staticData->pdcName);
    if (NULL != domainBuffer)
        syStrcpy((NQ_CHAR *)*domainBuffer, staticData->domainName);

    result = NQ_SUCCESS;

    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "PDC = %s, Domain = %s", staticData->pdcName, staticData->domainName);

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
}
