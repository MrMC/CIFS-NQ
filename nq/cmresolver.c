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

#include "cmapi.h"
#include "cmresolver.h"
#include "cmlist.h"
#include "cmcommon.h"

/* -- Definitions -- */

#define CACHEITEM_TIMEOUT 10    /* in seconds */

typedef struct 
{
    CMItem item;                        /* inherited object */
    SYSocketHandle socket;              /* socket to use with this method */
    void * context;                     /* method-specific context */
    NQ_STATUS status;                   /* method status as:
                                            NQ_ERR_MOREDATA - use this method (method was initially scheduled or it requires more iterations)
                                            NQ_SUCCESS - do not use this method (either succeded or requests in progress)
                                            NQ_ERR_<*> - method failed - do not use 
                                        */
    NQ_IPADDRESS serverIp;              /* server IP address */
    CMResolverMethodDescriptor method;  /* method descriptor */
    NQ_BOOL enabled;                    /* TRUE when this method is enabled */
    NQ_COUNT numRequests;               /* number of pending requests */
} 
Method;                                 /* resolution method */

typedef struct
{
    CMItem item;                        /* inherited object */
    NQ_TIME time;                       /* time when this entry was cached */
    NQ_COUNT numIps;                    /* number of IPs */
    const NQ_IPADDRESS * ips;           /* IP addresses */
}
CacheEntry;                             /* an association between host name and IP(s) */

/* -- Static data -- */

typedef struct
{
    SYMutex guard;                  /* critical section guard */
    CMList methods;                 /* list of registered methods */
    CMList cache;                   /* cached associations */
    CMResolverNameToIpA nameToIpA;  /* name-to-ip external method (ASCII) */
    CMResolverIpToNameA ipToNameA;  /* ip-to-name external method (ASCII) */
    CMResolverNameToIpW nameToIpW;  /* name-to-ip external method (UNICODE) */
    CMResolverIpToNameW ipToNameW;  /* ip-to-name external method (UNICODE) */
}
StaticData;

#ifdef SY_FORCEALLOCATION
static StaticData* staticData = NULL;
#else  /* SY_FORCEALLOCATION */
static StaticData staticDataSrc;
static StaticData* staticData = &staticDataSrc;
#endif /* SY_FORCEALLOCATION */

/* -- Static functions -- */

static NQ_BOOL methodUnlockCallback(CMItem * pItem)
{
    Method * pMethod = (Method *)pItem; /* casted pointer */

    syCloseSocket(pMethod->socket);
    cmListItemRemoveAndDispose(pItem);
    return TRUE;
}

static void prepareMethods()
{
    CMIterator iterator;        /* method iterator */

    /* prepare methods */
    for (cmListIteratorStart(&staticData->methods, &iterator); cmListIteratorHasNext(&iterator); )
    {
        SYSocketSet set;                                                /* socket set for select */
        Method * pMethod = (Method *)cmListIteratorNext(&iterator);     /* casted pointer */
        NQ_BOOL exit = FALSE;                                           /* clean socket indicator */
        NQ_BYTE dummyBuf[2];                                            /* dummy buffer */
        NQ_IPADDRESS dummySrc;                                          /* dummy source address */
        NQ_PORT dummyPort;                                              /* dummy source port */

        pMethod->status = NQ_ERR_MOREDATA;      /* initial status */
        pMethod->context = NULL;
        pMethod->numRequests = 0;

        /* cleanup sockets since they may have pending datagrams from previous requests */
        syClearSocketSet(&set);
        syAddSocketToSet(pMethod->socket, &set);

        while (!exit)
        {
            switch(sySelectSocket(&set, 0))      /* will hit data only when it is already on the socket */
            {
                case 0:
                    exit = TRUE;        /* no more */
                    break;
                case NQ_FAIL:
                    LOGERR(CM_TRC_LEVEL_ERROR, "Select error");
                    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                    exit = TRUE;        /* no more */
                    break;
                default:
                    syRecvFromSocket(pMethod->socket, dummyBuf, sizeof(dummyBuf), &dummySrc, &dummyPort);
                    break;
            }
        }
    }
    cmListIteratorTerminate(&iterator);
}

static NQ_BOOL mergeIpAddresses(const NQ_IPADDRESS ** pTo, NQ_INT * pNumTo, NQ_IPADDRESS * from, NQ_INT numFrom)
{
    if (NULL == *pTo)
    {
        *pNumTo = numFrom;
        *pTo = cmMemoryAllocate((NQ_UINT)(sizeof(NQ_IPADDRESS) * (NQ_UINT)numFrom));
        if (NULL == *pTo)
        {
        	cmMemoryFree(from);
            return FALSE;
        }
        syMemcpy(*pTo, from, sizeof(NQ_IPADDRESS) * (NQ_UINT)numFrom);
        cmMemoryFree(from);
    }
    else
    {   
        NQ_IPADDRESS * newArray;                        /* new array of IPs */
        NQ_INT iTo;                                     /* just a counter */
        NQ_INT iFrom;                                   /* just a counter */
        const NQ_IPADDRESS zeroIp = CM_IPADDR_ZERO;     /* non-existent IP */
        NQ_INT numToAdd = numFrom;                      /* num of addresses to add after resolving duplicates */    


        /* check duplicate addresses */
        for (iFrom = 0; iFrom < numFrom; iFrom++)
        {
            for (iTo = 0; iTo < *pNumTo; iTo++)
            {
                if (CM_IPADDR_EQUAL((*pTo)[iTo], from[iFrom]))
                {
                    from[iFrom] = zeroIp;
                    numToAdd--;
                    break;
                }
            }
        }

        newArray = cmMemoryAllocate((NQ_UINT)(sizeof(NQ_IPADDRESS) * (NQ_UINT)(*pNumTo + numToAdd)));
        if (NULL == newArray)
        {
            cmMemoryFree(from);
            return FALSE;
        }
        syMemcpy(newArray, *pTo, sizeof(NQ_IPADDRESS) * (NQ_UINT)(*pNumTo));
        iTo = *pNumTo;
        for (iFrom = 0; iFrom < numFrom; iFrom++)
        {
            if (!CM_IPADDR_EQUAL(zeroIp, from[iFrom]))
            {
                newArray[iTo++] = from[iFrom];
            }
        }
        *pNumTo += numToAdd;
        cmMemoryFree(from);
        cmMemoryFree(*pTo);
        *pTo = newArray;
    }
    return TRUE;
}

static const NQ_IPADDRESS * externalNameToIp(const NQ_WCHAR * name, NQ_INT * numIps)
{
    NQ_IPADDRESS nextIp;                /* next IP in the result */
    NQ_IPADDRESS * pNext;               /* pointer to a copy of next IP */
    NQ_COUNT index;                     /* IP index */
    const NQ_IPADDRESS * ips = NULL;    /* resulted array of IPs */
#ifdef UD_NQ_USETRANSPORTIPV4
    NQ_IPADDRESS4 *ip;                  /* pointer to IP */
#endif /* UD_NQ_USETRANSPORTIPV4 */
    NQ_INT type;                        /* next IP type */
    NQ_BYTE buffer[16];                 /* buffer for IP */

    if (NULL != staticData->nameToIpW)
    {
        for (index = 0; ; index++)
        {
            type = staticData->nameToIpW(name, buffer, index);
            switch(type)
            {
#ifdef UD_NQ_USETRANSPORTIPV4
            case NQ_RESOLVER_IPV4:
                ip = (NQ_IPADDRESS4 *)buffer;
                CM_IPADDR_ASSIGN4(nextIp, (*ip));
                break;
#endif /* UD_NQ_USETRANSPORTIPV4 */
#ifdef UD_NQ_USETRANSPORTIPV6
            case NQ_RESOLVER_IPV6:
                CM_IPADDR_ASSIGN6(nextIp, (buffer));
                break;
#endif /* UD_NQ_USETRANSPORTIPV6 */
            default:
                type = NQ_RESOLVER_NONE;
            }
            if (NQ_RESOLVER_NONE == type)
                break;
            {
                pNext = cmMemoryAllocate(sizeof(NQ_IPADDRESS));
                if (NULL != pNext)
                {
                    *pNext = nextIp;
                    mergeIpAddresses(&ips, numIps, pNext, 1);   /* will release pNext */
                }
            }
        }
    }
    else if (NULL != staticData->nameToIpA)
    {
        const NQ_CHAR * nameA;      /* ASCII name */
    
        nameA = cmMemoryCloneWStringAsAscii(name);
        if (NULL != nameA)
        {
            for (index = 0; ; index++)
            {
                type = staticData->nameToIpA(nameA, buffer, index);
                switch(type)
                {
#ifdef UD_NQ_USETRANSPORTIPV4
                case NQ_RESOLVER_IPV4:
                    ip = (NQ_IPADDRESS4 *)buffer;
                    CM_IPADDR_ASSIGN4(nextIp, (*ip));
                    break;
#endif /* UD_NQ_USETRANSPORTIPV4 */
#ifdef UD_NQ_USETRANSPORTIPV6
                case NQ_RESOLVER_IPV6:
                    CM_IPADDR_ASSIGN6(nextIp, (buffer));
                    break;
#endif /* UD_NQ_USETRANSPORTIPV6 */
                default:
                    type = NQ_RESOLVER_NONE;
                }
                if (NQ_RESOLVER_NONE == type)
                    break;
                pNext = cmMemoryAllocate(sizeof(NQ_IPADDRESS));
                if (NULL != pNext)
                {
                    *pNext = nextIp;
                    mergeIpAddresses(&ips, numIps, pNext, 1);   /* will release pNext */
                }
            }
        }
        cmMemoryFree(nameA);
    }

    return ips;
}

static const NQ_WCHAR * externalIpToName(const NQ_IPADDRESS * ip)
{
    NQ_WCHAR * name;            /* resulted name */
    NQ_BOOL result = FALSE;     /* resolution result */
    NQ_INT version;             /* IP version */

    name = cmMemoryAllocate(CM_DNS_NAMELEN);
    if (NULL == name)
        return NULL;
    version = CM_IPADDR_VERSION(*ip);
    if (NULL != staticData->ipToNameW)
    {
        switch(version)
        {
#ifdef UD_NQ_USETRANSPORTIPV4
        case CM_IPADDR_IPV4:
            result = staticData->ipToNameW(name, &(CM_IPADDR_GET4(*ip)), NQ_RESOLVER_IPV4);
            break;
#endif /* UD_NQ_USETRANSPORTIPV4 */
#ifdef UD_NQ_USETRANSPORTIPV6
        case CM_IPADDR_IPV6:
            result = staticData->ipToNameW(name, CM_IPADDR_GET6(*ip), NQ_RESOLVER_IPV6);
            break;
#endif /* UD_NQ_USETRANSPORTIPV6 */
        default:
            break;
        }
    }
    else if (NULL != staticData->ipToNameA)
    {
        NQ_CHAR * nameA;    /* pointer to ASCII name */

        switch(version)
        {
#ifdef UD_NQ_USETRANSPORTIPV4
        case CM_IPADDR_IPV4:
            result = staticData->ipToNameW(name, &(CM_IPADDR_GET4(*ip)), NQ_RESOLVER_IPV4);
            break;
#endif /* UD_NQ_USETRANSPORTIPV4 */
#ifdef UD_NQ_USETRANSPORTIPV6
        case CM_IPADDR_IPV6:
            result = staticData->ipToNameA((NQ_CHAR *)name, &(CM_IPADDR_GET4(*ip)), NQ_RESOLVER_IPV4);
            break;
#endif /* UD_NQ_USETRANSPORTIPV6 */
        default:
            break;
        }
        if (result)
        {
            nameA = (NQ_CHAR *)name;
            name = cmMemoryCloneAString(nameA); /* NULL is OK */
            cmMemoryFree(nameA);
        }
    }
    if (!result)
    {
        cmMemoryFree(name);
        name = NULL;
    }
    return name;
}

static void validateCache()
{
    CMIterator iterator;            /* for iterating cache items */
    NQ_TIME curTime;                /* current time in seconds */

    curTime  = (NQ_TIME)syGetTime();
    cmListIteratorStart(&staticData->cache, &iterator);
    while (cmListIteratorHasNext(&iterator))
    {
        const CacheEntry * pEntry;   /* next cache entry */
        
        pEntry = (const CacheEntry *)cmListIteratorNext(&iterator);
        if (CACHEITEM_TIMEOUT < (curTime - pEntry->time))
        {
            cmListItemCheck((CMItem *)pEntry);
            cmListItemRemoveAndDispose((CMItem *)pEntry);
        }
    }
    cmListIteratorTerminate(&iterator);
}

static const CacheEntry * lookupNameInCache(const NQ_WCHAR * name)
{
    validateCache();
    return (const CacheEntry *)cmListItemFind(&staticData->cache, name, TRUE , FALSE);
}

static const CacheEntry * lookupIpInCache(const NQ_IPADDRESS * ip)
{
    CMIterator iterator;            /* for iterating cache items */

    validateCache();
    cmListIteratorStart(&staticData->cache, &iterator);
    while (cmListIteratorHasNext(&iterator))
    {
        const CacheEntry * pEntry;   /* next cache entry */
        NQ_COUNT i;                 /* index in IPs */

        pEntry = (const CacheEntry *)cmListIteratorNext(&iterator);
        for (i = 0; i < pEntry->numIps; i++)
        {
            if (CM_IPADDR_EQUAL(*ip, pEntry->ips[i]))
            {
                cmListIteratorTerminate(&iterator);
                return pEntry;
            }
        }
    }
    cmListIteratorTerminate(&iterator);
    return NULL;
}

/*
 * Callback for cache entry unlock and disposal:
 * 	- disconnects from the server
 *  - disposes private data  
 */
static NQ_BOOL cacheEntryUnlockCallback(CMItem * pItem)
{
    const CacheEntry * pEntry = (const CacheEntry *)pItem;  /* casted pointer */
    if (NULL != pEntry->ips)
    {
        cmMemoryFree(pEntry->ips);
    }
    return FALSE;
}

static void addToCache(const NQ_WCHAR * name, const NQ_IPADDRESS * ips, NQ_COUNT numIps)
{
    CacheEntry * pEntry;        /* new cache entry */

    pEntry = (CacheEntry *)cmListItemCreateAndAdd(&staticData->cache, sizeof(CacheEntry), name, cacheEntryUnlockCallback , FALSE);
    if (NULL == pEntry)
    {
        return;
    }
    pEntry->ips = cmMemoryAllocate((NQ_UINT)(numIps * sizeof(NQ_IPADDRESS)));
    if (NULL == pEntry->ips)
    {
        cmListItemRemoveAndDispose((CMItem *)pEntry);
        return;
    }
    syMemcpy(pEntry->ips, ips, numIps * sizeof(NQ_IPADDRESS));
    pEntry->numIps = numIps;
    pEntry->time = (NQ_TIME)syGetTime();
}

/* -- API Functions */

NQ_BOOL cmResolverStart(void)
{
    /* allocate memory */
#ifdef SY_FORCEALLOCATION
    staticData = (StaticData *)syCalloc(1, sizeof(*staticData));
    if (NULL == staticData)
    {
        TRCERR("Unable to allocate resolver data");
        return NQ_FAIL;
    }
#endif /* SY_FORCEALLOCATION */

    staticData->ipToNameA = NULL;
    staticData->ipToNameW = NULL;
    staticData->nameToIpA = NULL;
    staticData->nameToIpW = NULL;
    syMutexCreate(&staticData->guard);
    cmListStart(&staticData->methods);
    cmListStart(&staticData->cache);

    return TRUE;
}

void cmResolverShutdown(void)
{
    CMIterator  cacheItr;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    cmListIteratorStart(&staticData->cache, &cacheItr);
    while (cmListIteratorHasNext(&cacheItr))
    {
        CacheEntry * pEntry;
        pEntry = (CacheEntry *)cmListIteratorNext(&cacheItr);
        cmListItemCheck((CMItem *)pEntry);
    }
    cmListIteratorTerminate(&cacheItr);
    cmListIteratorStart(&staticData->methods, &cacheItr);
    while (cmListIteratorHasNext(&cacheItr))
    {
        CMItem * pItem;
        
        pItem = cmListIteratorNext(&cacheItr);
        cmListItemCheck(pItem);
    }
    cmListShutdown(&staticData->methods);
    cmListShutdown(&staticData->cache);
    syMutexDelete(&staticData->guard);

#ifdef SY_FORCEALLOCATION
    if (NULL != staticData)
        syFree(staticData);
    staticData = NULL;
#endif /* SY_FORCEALLOCATION */
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

NQ_BOOL cmResolverRegisterMethod(const CMResolverMethodDescriptor * descriptor, const NQ_IPADDRESS * serverIp)
{
    Method * pMethod;                                                                   /* method pointer */
    NQ_UINT family = NULL == serverIp? CM_IPADDR_IPV4 : (NQ_UINT)CM_IPADDR_VERSION(*serverIp);   /* IP family */
#ifdef UD_NQ_USETRANSPORTIPV4
    NQ_IPADDRESS anyIp4 = CM_IPADDR_ANY4;                                               /* for binding */
#endif /* UD_NQ_USETRANSPORTIPV4 */                                                                                 
#ifdef UD_NQ_USETRANSPORTIPV6
    NQ_IPADDRESS anyIp6 = CM_IPADDR_ANY6;                                               /* for binding */
#endif /* UD_NQ_USETRANSPORTIPV6 */                                                                                 
    NQ_STATUS res = TRUE;                                                               /* operation result */
    
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    pMethod = (Method *)cmListItemCreateAndAdd(&staticData->methods, sizeof(Method), NULL, methodUnlockCallback, FALSE);
    if (NULL == pMethod)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return FALSE;
    }

    pMethod->socket = syCreateSocket(FALSE, family);
    if (!syIsValidSocket(pMethod->socket))
    {
        cmListItemRemoveAndDispose((CMItem *)pMethod);
        LOGERR(CM_TRC_LEVEL_ERROR, "Error creating Resolver socket for method %d", (CMItem *)pMethod->item.name);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return FALSE;
    }
    pMethod->enabled = TRUE;

#if defined(UD_NQ_USETRANSPORTIPV4) && defined(UD_NQ_USETRANSPORTIPV6) 
    if (family == CM_IPADDR_IPV4)
    {
        res = syBindSocket(pMethod->socket, &anyIp4, 0);
    }
    else
    {
        res = syBindSocket(pMethod->socket, &anyIp6, 0);
    }
#else /* defined(UD_NQ_USETRANSPORTIPV4) && defined(UD_NQ_USETRANSPORTIPV6) */
#ifdef UD_NQ_USETRANSPORTIPV4
    res = syBindSocket(pMethod->socket, &anyIp4, 0);
#endif /* UD_NQ_USETRANSPORTIPV4 */                                                                                 
#ifdef UD_NQ_USETRANSPORTIPV6
    res = syBindSocket(pMethod->socket, &anyIp6, 0);
#endif /* UD_NQ_USETRANSPORTIPV6 */                                                                                 
#endif /* defined(UD_NQ_USETRANSPORTIPV4) && defined(UD_NQ_USETRANSPORTIPV6) */
    if (res == NQ_FAIL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Error binding DNS socket");
        syCloseSocket(pMethod->socket);
        cmListItemRemoveAndDispose((CMItem *)pMethod);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return FALSE;
    }
    /*LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "CreatedResolver socket for method %s", cmWDump((const NQ_WCHAR*)((CMItem *)pMethod->item.name)));*/

    pMethod->method = *descriptor;
    pMethod->context = NULL;
    if (NULL != serverIp)
    {
        pMethod->serverIp = *serverIp;
    }
    else
    {
        CM_IPADDR_ASSIGN4(pMethod->serverIp, 0L);
    }
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return TRUE;
}

void cmResolverRemoveMethod(const CMResolverMethodDescriptor * descriptor, const NQ_IPADDRESS * serverIp)
{
    CMIterator iterator;            /* method iterator */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    syMutexTake(&staticData->guard);

    for (cmListIteratorStart(&staticData->methods, &iterator); cmListIteratorHasNext(&iterator); )
    {
        Method * pMethod = (Method *)cmListIteratorNext(&iterator);

        if (pMethod->method.type == descriptor->type && CM_IPADDR_EQUAL(pMethod->serverIp, *serverIp) && pMethod->method.isMulticast == descriptor->isMulticast)
        {
            cmListItemCheck((CMItem *)pMethod);
            break;
        }
    }
    cmListIteratorTerminate(&iterator);
    syMutexGive(&staticData->guard);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

const NQ_WCHAR * cmResolverGetHostName(const NQ_IPADDRESS * ip)
{
    NQ_TIME elapsedTime = 0;        /* seconds elapsed on timeouts */
    NQ_TIME selectTimeStamp;        /* time when the current select started */
    NQ_TIME currentTimeout;         /* timeout of the current select */
    CMIterator iterator;            /* method iterator */
    const NQ_WCHAR * pName = NULL;  /* pointer to the resulted name */
    NQ_BOOL useMulticasts = FALSE;  /* TRUE when NQ switches to multicasts */
    const CacheEntry * pEntry;      /* entry in the cache */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    syMutexTake(&staticData->guard);

    /* look in cache */
    pEntry = lookupIpInCache(ip);
    if (NULL != pEntry)
    {
        pName = cmMemoryCloneWString(pEntry->item.name);
        syMutexGive(&staticData->guard);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return pName;
    }

    prepareMethods();    

    /* loop by the smallest timeout until either all timeouts expire or there is at least one answer */
    for (; ;)
    {
        SYSocketSet set;                /* socket set for select */
        NQ_BOOL hasMethods = FALSE;     /* valid method flag */     

        syClearSocketSet(&set);
        currentTimeout = 0;
        for (cmListIteratorStart(&staticData->methods, &iterator); cmListIteratorHasNext(&iterator); )
        {
            Method * pMethod = (Method *)cmListIteratorNext(&iterator);
            if (!pMethod->enabled)
                continue;
            if (NQ_ERR_MOREDATA == pMethod->status)
            {
                if (useMulticasts == pMethod->method.isMulticast)
                {
                    pMethod->status = (*pMethod->method.requestByIp)(pMethod->socket, ip, pMethod->context, &pMethod->serverIp);
                    if (NQ_SUCCESS == pMethod->status)
                    {
                        if (pMethod->method.timeout > elapsedTime)
                        {
                            elapsedTime = pMethod->method.timeout;
                            currentTimeout = elapsedTime;
                        }
                        syAddSocketToSet(pMethod->socket, &set);  
                        hasMethods = TRUE;
                    }
                }
            }
        }
        cmListIteratorTerminate(&iterator);
        if (!hasMethods)
        {
            if (!useMulticasts)             /* switch to multicasts */
            {
                useMulticasts = TRUE;
                currentTimeout = 0;
                continue;
            }
            syMutexGive(&staticData->guard);
            LOGERR(CM_TRC_LEVEL_ERROR, "All methods failed");
            pName = pName == NULL ? externalIpToName(ip) : pName;
            if (NULL != pName)
                addToCache(pName, ip, 1);
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return pName;
        }

        selectTimeStamp = (NQ_TIME)syGetTime();
        switch(sySelectSocket(&set, currentTimeout))
        {
        case 0:  /* timeout */          
            LOGERR(CM_TRC_LEVEL_ERROR, "Select timeout - no response");
            syMutexGive(&staticData->guard);
            pName = pName == NULL ? externalIpToName(ip) : pName;
            if (NULL != pName)
                addToCache(pName, ip, 1);
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return pName;

        case NQ_FAIL: /* error the select failed  */
            syMutexGive(&staticData->guard);
            LOGERR(CM_TRC_LEVEL_ERROR, "Select failed");
            pName = pName == NULL ? externalIpToName(ip) : pName;
            if (NULL != pName)
                addToCache(pName, ip, 1);
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return pName;

        default: /* datagram ready for reading */
            for (cmListIteratorStart(&staticData->methods, &iterator); cmListIteratorHasNext(&iterator); )
            {
                Method * pMethod = (Method *)cmListIteratorNext(&iterator);
                if (!pMethod->enabled)
                    continue;
                if (syIsSocketSet(pMethod->socket, &set))
                {
                    pMethod->status = (*pMethod->method.responseByIp)(pMethod->socket, &pName, &pMethod->context);
                    switch (pMethod->status)
                    {
                    case NQ_SUCCESS:
                        cmMemoryFree(pMethod->context); /* will handle NULL */
                        cmListIteratorTerminate(&iterator);
                        syMutexGive(&staticData->guard);
                        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                        if (NULL != pName)
                        {
                            addToCache(pName, ip, 1);
                        }
                        return pName;
                    case NQ_ERR_MOREDATA:
                    case NQ_FAIL:
                        cmMemoryFree(pMethod->context); /* will handle NULL */
                        pMethod->numRequests--;
                        break;    
                    default:    /* error */
                        break;
                    }
                }
            }
            cmListIteratorTerminate(&iterator);
        }
        /* recalculate timeout */
	    elapsedTime = (NQ_TIME)syGetTime() - selectTimeStamp;
        currentTimeout -= (elapsedTime == 0 ? 1 : elapsedTime);
    }
    syMutexGive(&staticData->guard);
    pName = pName == NULL ? externalIpToName(ip) : pName;
    if (NULL != pName)
        addToCache(pName, ip, 1);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return pName;
}

const NQ_IPADDRESS * cmResolverGetHostIps(const NQ_WCHAR * host, NQ_INT * numIps)
{
    NQ_TIME elapsedTime = 0;                    /* seconds elapsed on timeouts */
    NQ_TIME selectTimeStamp;                    /* time when the current select started */
    NQ_TIME currentTimeout;                     /* timeout of the current select */
    CMIterator iterator;                        /* method iterator */
    NQ_BOOL useMulticasts = FALSE;              /* TRUE when NQ switches to multicasts */
    const NQ_IPADDRESS * result = NULL;         /* resulted array of IPs */
    NQ_IPADDRESS * methodResult = NULL;         /* one method result */
    NQ_INT methodNumIps;                        /* number of IPs returned by one method */
    const CacheEntry * pEntry;                      /* entry in the cache */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    syMutexTake(&staticData->guard);

    /* look in cache */
    pEntry = lookupNameInCache(host);
    if (NULL != pEntry)
    {
        result = cmMemoryAllocate((NQ_UINT)(sizeof(NQ_IPADDRESS) * pEntry->numIps));
        if (NULL != result)
        {
            syMemcpy(result, pEntry->ips, sizeof(NQ_IPADDRESS) * pEntry->numIps);
            *numIps = (NQ_INT)pEntry->numIps;
        }
        syMutexGive(&staticData->guard);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return result;
    }

    prepareMethods();  

    *numIps = 0;
    currentTimeout = 0;

    /* loop by the smallest timeout until either all timeouts expire */
    for (; ;)
    {
        SYSocketSet set;                /* socket set for select */
        NQ_BOOL hasMethods = FALSE;     /* valid method flag */     
        NQ_BOOL wasResponse = FALSE;    /* there was at least one response */

        syClearSocketSet(&set);
        for (cmListIteratorStart(&staticData->methods, &iterator); cmListIteratorHasNext(&iterator); )
        {
            Method * pMethod = (Method *)cmListIteratorNext(&iterator);
            if (!pMethod->enabled)
                continue;
            switch(pMethod->status)
            {
            case NQ_SUCCESS:
                if (pMethod->numRequests > 0) 
                {
                    syAddSocketToSet(pMethod->socket, &set);  
                    hasMethods = TRUE;
                }
                break;
            case NQ_ERR_MOREDATA:
                if (useMulticasts == pMethod->method.isMulticast)
                {
                    pMethod->status = (*pMethod->method.requestByName)(pMethod->socket, host, pMethod->context, &pMethod->serverIp);
                    if (pMethod->status >= 0)
                    {
                        pMethod->numRequests = NQ_SUCCESS == pMethod->status? 1 : pMethod->status;
                        pMethod->status = NQ_SUCCESS;
                        if (pMethod->method.timeout > elapsedTime)
                        {
                            elapsedTime = pMethod->method.timeout;
                            currentTimeout = elapsedTime;
                        }
                        syAddSocketToSet(pMethod->socket, &set);  
                        hasMethods = TRUE;
                    }
                }
                break;
            default:
                break;
            }
        }
        cmListIteratorTerminate(&iterator);
        if (!hasMethods)
        {
            if (NULL == result && !useMulticasts)             /* switch to multicasts */
            {
                useMulticasts = TRUE;
                currentTimeout = 0;
                continue;
            }
            LOGERR(CM_TRC_LEVEL_ERROR, "All methods failed");
            syMutexGive(&staticData->guard);
            result = result == NULL? externalNameToIp(host, numIps) : result;
            if (NULL != result)
                addToCache(host, result, (NQ_COUNT)*numIps);
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return result;
        }

        selectTimeStamp = (NQ_TIME)syGetTime();
        if (0 == currentTimeout)
            break;
        switch(sySelectSocket(&set, currentTimeout))
        {
        case 0:  /* timeout */
            LOGERR(CM_TRC_LEVEL_ERROR, "Select timeout - no response");
            /* if multicasts have not been sent yet, just break */
            if (NULL == result && !useMulticasts)
            {
                useMulticasts = TRUE;
                elapsedTime = 0;
                break;
            }
            syMutexGive(&staticData->guard);
            result = result == NULL? externalNameToIp(host, numIps) : result;
            if (NULL != result)
                addToCache(host, result, (NQ_COUNT)*numIps);
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return result;

        case NQ_FAIL: /* error the select failed  */
            LOGERR(CM_TRC_LEVEL_ERROR, "Select failed");
            syMutexGive(&staticData->guard);
            result = result == NULL? externalNameToIp(host, numIps) : result;
            if (NULL != result)
                addToCache(host, result, (NQ_COUNT)*numIps);
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return result;

        default: /* datagram ready for reading */
            for (cmListIteratorStart(&staticData->methods, &iterator); cmListIteratorHasNext(&iterator); )
            {
                Method * pMethod = (Method *)cmListIteratorNext(&iterator);
                if (!pMethod->enabled)
                    continue;
                if (syIsSocketSet(pMethod->socket, &set))
                {
                    pMethod->status = (*pMethod->method.responseByName)(pMethod->socket, &methodResult, &methodNumIps, &pMethod->context);
                    wasResponse = TRUE;
                    pMethod->numRequests--;
                    switch (pMethod->status)
                    {
                    case NQ_SUCCESS:
                        cmMemoryFree(pMethod->context); /* will handle NULL */
                        mergeIpAddresses(&result, numIps, methodResult, methodNumIps);
                        break;
                    case NQ_ERR_MOREDATA:
                    case NQ_FAIL:
                        cmMemoryFree(pMethod->context); /* will handle NULL */
                        if (pMethod->numRequests > 0)
                            pMethod->status = NQ_SUCCESS;
                        break;
                    default:    /* error */
                        break;
                    }
                }
            }
            cmListIteratorTerminate(&iterator);
        }
        /* check pending requests */
        if (wasResponse)
        {
            for (cmListIteratorStart(&staticData->methods, &iterator); cmListIteratorHasNext(&iterator); )
            {
                Method * pMethod = (Method *)cmListIteratorNext(&iterator);
                if (useMulticasts == pMethod->method.isMulticast)
                {
                    if (NQ_ERR_MOREDATA == pMethod->status && pMethod->method.waitAnyway)
                    {
                        wasResponse = FALSE;
                        break;
                    }
                    if (pMethod->numRequests > 0)
                    {
                        wasResponse = FALSE;
                        break;
                    }
                }
            }
            cmListIteratorTerminate(&iterator);
            if (wasResponse && useMulticasts)
            {
                syMutexGive(&staticData->guard);
                result = result == NULL? externalNameToIp(host, numIps) : result;
                if (NULL != result)
                    addToCache(host, result, (NQ_COUNT)*numIps);
                LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                return result;
            }
        }
        /* recalculate timeout */
        elapsedTime = (NQ_TIME)syGetTime() - selectTimeStamp;
        if (currentTimeout >= elapsedTime)
            currentTimeout -= elapsedTime;
        else
            currentTimeout = 0;
    }
    syMutexGive(&staticData->guard);
    result = result == NULL? externalNameToIp(host, numIps) : result;
    if (NULL != result)
        addToCache(host, result, (NQ_COUNT)*numIps);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return result;
}

/* --- API functions --- */

void cmResolverSetExternalA(CMResolverNameToIpA nameToIp, CMResolverIpToNameA ipToName)
{
    staticData->nameToIpA = nameToIp;
    staticData->ipToNameA = ipToName;
}

void cmResolverSetExternalW(CMResolverNameToIpW nameToIp, CMResolverIpToNameW ipToName)
{
    staticData->nameToIpW = nameToIp;
    staticData->ipToNameW = ipToName;
}

void cmResolverEnableMethod(NQ_INT type, NQ_BOOL unicast, NQ_BOOL multicast)
{
    CMIterator iterator;                        /* method iterator */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    syMutexTake(&staticData->guard);

    for (cmListIteratorStart(&staticData->methods, &iterator); cmListIteratorHasNext(&iterator); )
    {
        Method * pMethod = (Method *)cmListIteratorNext(&iterator);

        if (type == pMethod->method.type)
        {
            if (pMethod->method.isMulticast)
                pMethod->enabled = multicast;
            else
                pMethod->enabled = unicast;
        }
    }
    cmListIteratorTerminate(&iterator);
    syMutexGive(&staticData->guard);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}
