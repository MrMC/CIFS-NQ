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
                                            NQ_SUCCESS - do not use this method (either succeeded or requests in progress)
                                            NQ_ERR_<*> - method failed - do not use 
                                        */
    NQ_IPADDRESS serverIp;              /* server IP address */
    CMResolverMethodDescriptor method;  /* method descriptor */
    NQ_BOOL enabled;                    /* TRUE when this method is enabled */
} 
Method;                                 /* resolution method */

typedef struct
{
    CMItem item;                        /* inherited object */
    NQ_UINT32 time;                       /* time when this entry was cached */
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
    NQ_BOOL cacheEnabled;           /* cache state (enabled by default) */
    NQ_UINT32 cacheTimeout;           /* cache item timeout */
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
#ifndef UD_NQ_CLOSESOCKETS
    Method * pMethod = (Method *)pItem; /* casted pointer */

    syCloseSocket(pMethod->socket);
#endif

    cmListItemRemoveAndDispose(pItem);
    return TRUE;
}

#ifdef UD_NQ_CLOSESOCKETS
static NQ_BOOL bindClientSocket(Method *pMethod)
{
    NQ_STATUS res = NQ_FAIL;                   /* operation result */
#ifdef UD_NQ_USETRANSPORTIPV4
    NQ_IPADDRESS anyIp4 = CM_IPADDR_ANY4;      /* for binding */
#endif /* UD_NQ_USETRANSPORTIPV4 */
#ifdef UD_NQ_USETRANSPORTIPV6
    NQ_IPADDRESS anyIp6 = CM_IPADDR_ANY6;      /* for binding */
#endif
    SYSocketHandle socket = syInvalidSocket();
    NQ_UINT family = (NQ_UINT)CM_IPADDR_VERSION(pMethod->serverIp);   /* IP family */


    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
    pMethod->socket = syInvalidSocket();
    socket = syCreateSocket(FALSE, family);
    if (!syIsValidSocket(socket))
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Error creating socket for method %d", (CMItem *)pMethod->item.name);
        goto Exit;
    }

#if defined(UD_NQ_USETRANSPORTIPV4) && defined(UD_NQ_USETRANSPORTIPV6)
    if (family == CM_IPADDR_IPV4)
    {
        res = syBindSocket(socket, &anyIp4, 0);
    }
    else
    {
        res = syBindSocket(socket, &anyIp6, 0);
    }
#else /* defined(UD_NQ_USETRANSPORTIPV4) && defined(UD_NQ_USETRANSPORTIPV6) */
#ifdef UD_NQ_USETRANSPORTIPV4
    res = syBindSocket(socket, &anyIp4, 0);
#endif /* UD_NQ_USETRANSPORTIPV4 */
#ifdef UD_NQ_USETRANSPORTIPV6
    res = syBindSocket(socket, &anyIp6, 0);
#endif /* UD_NQ_USETRANSPORTIPV6 */
#endif /* defined(UD_NQ_USETRANSPORTIPV4) && defined(UD_NQ_USETRANSPORTIPV6) */
    if (res == NQ_FAIL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Error binding DNS socket");
        syCloseSocket(socket);
        goto Exit;
    }

    pMethod->socket = socket;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);

    return (res == NQ_FAIL)? FALSE : TRUE;
}
#endif /* UD_NQ_CLOSESOCKETS */

static void prepareMethods()
{
    CMIterator iterator;        /* method iterator */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    /* prepare methods */
    for (cmListIteratorStart(&staticData->methods, &iterator); cmListIteratorHasNext(&iterator);  )
    {
        Method * pMethod = (Method *)cmListIteratorNext(&iterator);     /* casted pointer */
#ifndef UD_NQ_CLOSESOCKETS
    	SYSocketSet set;                                                /* socket set for select */
        NQ_BOOL exit = FALSE;                                           /* clean socket indicator */
        NQ_BYTE dummyBuf[2];                                            /* dummy buffer */
        NQ_IPADDRESS dummySrc;                                          /* dummy source address */
        NQ_PORT dummyPort;                                              /* dummy source port */
#endif /* UD_NQ_CLOSESOCKETS */
        pMethod->status = NQ_ERR_MOREDATA;      /* initial status */
        pMethod->context = NULL;

#ifdef UD_NQ_CLOSESOCKETS
        bindClientSocket(pMethod);
#else
        /* cleanup sockets since they may have pending datagrams from previous requests */
        syClearSocketSet(&set);
        syAddSocketToSet(pMethod->socket, &set);

        while (!exit)
        {
            switch (sySelectSocket(&set, 0))      /* will hit data only when it is already on the socket */
            {
            case 0:
                exit = TRUE;        /* no more */
                break;
            case NQ_FAIL:
                LOGERR(CM_TRC_LEVEL_ERROR, "Select error");
                exit = TRUE;        /* no more */
                break;
            default:
                syRecvFromSocket(pMethod->socket, dummyBuf, sizeof(dummyBuf), &dummySrc, &dummyPort);
                break;
            }
        }
#endif /* UD_NQ_CLOSESOCKETS */
	}
	cmListIteratorTerminate(&iterator);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

#ifdef UD_NQ_CLOSESOCKETS
static void closeSockets()
{
    CMIterator iterator;        /* method iterator */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    /* close method sockets */
    for (cmListIteratorStart(&staticData->methods, &iterator); cmListIteratorHasNext(&iterator); )
    {
        Method * pMethod = (Method *)cmListIteratorNext(&iterator);     /* casted pointer */
        if(syIsValidSocket(pMethod->socket))
        {
            syCloseSocket(pMethod->socket);
            pMethod->socket = syInvalidSocket();
        }
    }
    cmListIteratorTerminate(&iterator);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}
#endif /* UD_NQ_CLOSESOCKETS */

static NQ_BOOL mergeIpAddresses(const NQ_IPADDRESS ** pTo, NQ_INT * pNumTo, NQ_IPADDRESS ** from, NQ_INT numFrom)
{
    NQ_BOOL result = FALSE;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "num IPs: %d, num new IPs: %d", *pNumTo, numFrom);

    if (NULL == *pTo)
    {
        *pNumTo = numFrom;
        *pTo = (const NQ_IPADDRESS *)cmMemoryAllocate((NQ_UINT)(sizeof(NQ_IPADDRESS) * (NQ_UINT)numFrom));
        if (NULL == *pTo)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
            goto Exit;
        }
        syMemcpy(*pTo, *from, sizeof(NQ_IPADDRESS) * (NQ_UINT)numFrom);
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
                if (CM_IPADDR_EQUAL((*pTo)[iTo], (*from)[iFrom]))
                {
                    (*from)[iFrom] = zeroIp;
                    numToAdd--;
                    break;
                }
            }
        }

        newArray = (NQ_IPADDRESS *)cmMemoryAllocate((NQ_UINT)(sizeof(NQ_IPADDRESS) * (NQ_UINT)(*pNumTo + numToAdd)));
        if (NULL == newArray)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
            goto Exit;
        }
        syMemcpy(newArray, *pTo, sizeof(NQ_IPADDRESS) * (NQ_UINT)(*pNumTo));
        iTo = *pNumTo;
        for (iFrom = 0; iFrom < numFrom; iFrom++)
        {
            if (!CM_IPADDR_EQUAL(zeroIp, (*from)[iFrom]))
            {
                newArray[iTo++] = (*from)[iFrom];
            }
        }
        *pNumTo += numToAdd;
        cmMemoryFree(*pTo);
        *pTo = newArray;
    }
    result = TRUE;

Exit:
    cmMemoryFree(*from);
    *from = NULL;
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "num non recurring IPs: %d", *pNumTo);
    return result;
}

static const NQ_IPADDRESS * externalNameToIp(const NQ_WCHAR * name, NQ_INT * numIps)
{
    NQ_IPADDRESS nextIp = CM_IPADDR_ZERO;                /* next IP in the result */
    NQ_IPADDRESS * pNext = NULL;               /* pointer to a copy of next IP */
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
                pNext = (NQ_IPADDRESS *)cmMemoryAllocate(sizeof(NQ_IPADDRESS));
                if (NULL != pNext)
                {
                    *pNext = nextIp;
                    mergeIpAddresses(&ips, numIps, &pNext, 1);   /* will release pNext */
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
                pNext = (NQ_IPADDRESS *)cmMemoryAllocate(sizeof(NQ_IPADDRESS));
                if (NULL != pNext)
                {
                    *pNext = nextIp;
                    mergeIpAddresses(&ips, numIps, &pNext, 1);   /* will release pNext */
                }
            }
        }
        cmMemoryFree(nameA);
    }

    return ips;
}

static const NQ_WCHAR * externalIpToName(const NQ_IPADDRESS * ip)
{
    NQ_WCHAR * name = NULL;     /* resulted name */
    NQ_BOOL result = FALSE;     /* resolution result */
    NQ_INT version;             /* IP version */

    name = (NQ_WCHAR *)cmMemoryAllocate(CM_DNS_NAMELEN);
    if (NULL == name)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        goto Exit;
    }

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
            result = staticData->ipToNameW(name, &CM_IPADDR_GET6(*ip), NQ_RESOLVER_IPV6);
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
           	result = staticData->ipToNameA((NQ_CHAR *)name, &(CM_IPADDR_GET4(*ip)), NQ_RESOLVER_IPV4);
            break;
#endif /* UD_NQ_USETRANSPORTIPV4 */
#ifdef UD_NQ_USETRANSPORTIPV6
        case CM_IPADDR_IPV6:
            result = staticData->ipToNameA((NQ_CHAR *)name, &(CM_IPADDR_GET6(*ip)), NQ_RESOLVER_IPV6);
            break;
#endif /* UD_NQ_USETRANSPORTIPV6 */
        default:
            break;
        }
        if (result)
        {
            nameA = (NQ_CHAR *)name;
            name = cmMemoryCloneAString(nameA); /* NULL is OK */
            if (NULL == name)
            {
                LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
                goto Exit;
            }
            cmMemoryFree(nameA);
        }
    }
    if (!result)
    {
        cmMemoryFree(name);
        name = NULL;
    }

Exit:
    return name;
}

static void validateCache(NQ_UINT32 timeout)
{
    CMIterator iterator;            /* for iterating cache items */
    NQ_UINT32 curTime;                /* current time in seconds */

    curTime  = (NQ_UINT32)syGetTimeInSec();
    cmListIteratorStart(&staticData->cache, &iterator);
    while (cmListIteratorHasNext(&iterator))
    {
        const CacheEntry * pEntry;   /* next cache entry */
        
        pEntry = (const CacheEntry *)cmListIteratorNext(&iterator);
	    if ((timeout == 0) || (timeout < (curTime - pEntry->time)))
        {
            cmListItemCheck((CMItem *)pEntry);
            cmListItemRemoveAndDispose((CMItem *)pEntry);
        }
    }
    cmListIteratorTerminate(&iterator);
}

static const CacheEntry * lookupNameInCache(const NQ_WCHAR * name)
{
    validateCache(staticData->cacheTimeout);
    return staticData->cacheEnabled ? (const CacheEntry *)cmListItemFind(&staticData->cache, name, TRUE, FALSE) : NULL;
}

static const CacheEntry * lookupIpInCache(const NQ_IPADDRESS * ip)
{
    CMIterator iterator;               /* for iterating cache items */
    const CacheEntry * pEntry = NULL;  /* next cache entry */

    validateCache(staticData->cacheTimeout);
    if (!staticData->cacheEnabled)
        goto Exit1;
    cmListIteratorStart(&staticData->cache, &iterator);
    while (cmListIteratorHasNext(&iterator))
    {
        NQ_COUNT i;                 /* index in IPs */

        pEntry = (const CacheEntry *)cmListIteratorNext(&iterator);
        for (i = 0; i < pEntry->numIps; i++)
        {
            if (CM_IPADDR_EQUAL(*ip, pEntry->ips[i]))
            {
                goto Exit;
            }
        }
    }
    pEntry = NULL;

Exit:
    cmListIteratorTerminate(&iterator);
Exit1:
    return pEntry;
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

    if (NULL == name || NULL == ips || !staticData->cacheEnabled)
    {
        goto Exit;
    }

    pEntry = (CacheEntry *)cmListItemCreateAndAdd(&staticData->cache, sizeof(CacheEntry), name, cacheEntryUnlockCallback, CM_LISTITEM_NOLOCK);
    if (NULL == pEntry)
    {
        goto Exit;
    }
    pEntry->ips = (const NQ_IPADDRESS *)cmMemoryAllocate((NQ_UINT)(numIps * sizeof(NQ_IPADDRESS)));
    if (NULL == pEntry->ips)
    {
        cmListItemRemoveAndDispose((CMItem *)pEntry);
        goto Exit;
    }
    syMemcpy(pEntry->ips, ips, numIps * sizeof(NQ_IPADDRESS));
    pEntry->numIps = numIps;
    pEntry->time = (NQ_UINT32)syGetTimeInSec();

Exit:
    return;
}

/* -- API Functions */

NQ_BOOL cmResolverStart(void)
{
    NQ_BOOL result = NQ_FAIL;
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    /* allocate memory */
#ifdef SY_FORCEALLOCATION
    staticData = (StaticData *)cmMemoryAllocate(sizeof(*staticData));
    if (NULL == staticData)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to allocate resolver data");
        sySetLastError(NQ_ERR_NOMEM);
        goto Exit;
    }
#endif /* SY_FORCEALLOCATION */

    staticData->ipToNameA = NULL;
    staticData->ipToNameW = NULL;
    staticData->nameToIpA = NULL;
    staticData->nameToIpW = NULL;
    syMutexCreate(&staticData->guard);
    staticData->cacheEnabled = TRUE;
    staticData->cacheTimeout = CACHEITEM_TIMEOUT;
    cmListStart(&staticData->methods);
    cmListStart(&staticData->cache);
    result = TRUE;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return result;
}

void cmResolverShutdown(void)
{
    CMIterator  itr;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    cmListIteratorStart(&staticData->cache, &itr);
    while (cmListIteratorHasNext(&itr))
    {
        CacheEntry * pEntry;

        pEntry = (CacheEntry *)cmListIteratorNext(&itr);
        cmListItemCheck((CMItem *)pEntry);
    }
    cmListIteratorTerminate(&itr);

    cmListIteratorStart(&staticData->methods, &itr);
    while (cmListIteratorHasNext(&itr))
    {
        CMItem * pItem;
        
        pItem = cmListIteratorNext(&itr);
        cmListItemCheck(pItem);
    }
    cmListIteratorTerminate(&itr);

    cmListShutdown(&staticData->methods);
    cmListShutdown(&staticData->cache);
    syMutexDelete(&staticData->guard);

#ifdef SY_FORCEALLOCATION
    if (NULL != staticData)
        cmMemoryFree(staticData);
    staticData = NULL;
#endif /* SY_FORCEALLOCATION */
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

void cmResolverCacheSet(NQ_UINT32 timeout)
{
    if (NULL == staticData)
        return;

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

NQ_BOOL cmResolverRegisterExternalMethod(const CMResolverRegisteredMethodDescription * pMethod)
{
	NQ_BOOL res = FALSE;
	CMResolverMethodDescriptor methodDescriptor;
	/* validations */
	/**************/

	if (NULL == pMethod->serverIP)
	{
		LOGERR(CM_TRC_LEVEL_WARNING, "A registered method must add a server IP which the queries will be sent to.");
		goto Exit;
	}
	if (NULL == pMethod->requestByName && NULL == pMethod->requestByIp)
	{
		LOGERR(CM_TRC_LEVEL_WARNING, "A registered method must support at least on query type. Query by name or query by IP.");
		goto Exit;
	}

	if (NULL != pMethod->requestByIp && NULL == pMethod->responseByIp)
	{
		LOGERR(CM_TRC_LEVEL_WARNING, "Each registered query method must have a corresponding response method. Add a method that will handle your query results.");
		goto Exit;
	}
	if (NULL != pMethod->requestByName && NULL == pMethod->responseByName)
	{
		LOGERR(CM_TRC_LEVEL_WARNING, "Each registered query method must have a corresponding response method. Add a method that will handle your query results.");
		goto Exit;
	}

	/* register method */
	/*******************/
	methodDescriptor.type = NQ_RESOLVER_EXTERNAL_METHOD;
	methodDescriptor.isMulticast = FALSE;

	switch (pMethod->activationPriority)
	{
		case 1:
			methodDescriptor.activationPriority = 1;
			break;
		case 2:
			methodDescriptor.activationPriority = 3;
			break;
		default:
			methodDescriptor.activationPriority = 5;
			break;
	}

	methodDescriptor.timeout = cmTimeConvertSecToMSec(pMethod->timeout);
	methodDescriptor.waitAnyway = FALSE;

	methodDescriptor.requestByIp = pMethod->requestByIp;
	methodDescriptor.requestByName = pMethod->requestByName;
	methodDescriptor.responseByIp = pMethod->responseByIp;
	methodDescriptor.responseByName = pMethod->responseByName;

	res = TRUE;

	cmResolverRegisterMethod(&methodDescriptor, pMethod->serverIP);

Exit:
	return res;
}
NQ_BOOL cmResolverRegisterMethod(const CMResolverMethodDescriptor * descriptor, const NQ_IPADDRESS * serverIp)
{
    Method * pMethod;                                                                   /* method pointer */
#ifndef UD_NQ_CLOSESOCKETS
    NQ_UINT family = NULL == serverIp? CM_IPADDR_IPV4 : (NQ_UINT)CM_IPADDR_VERSION(*serverIp);   /* IP family */
#endif
    NQ_BOOL result = FALSE;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "descriptor:%p serverIP:%p", descriptor, serverIp);

    pMethod = (Method *)cmListItemCreateAndAdd(&staticData->methods, sizeof(Method), NULL, methodUnlockCallback, CM_LISTITEM_NOLOCK);
    if (NULL == pMethod)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        goto Exit;
    }

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
#ifndef UD_NQ_CLOSESOCKETS
    pMethod->socket = syCreateSocket(FALSE, family);
    if (!syIsValidSocket(pMethod->socket))
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Error creating Resolver socket for method %d", (CMItem *)pMethod->item.name);
        goto Error1;
    }

    /*LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "CreatedResolver socket for method %s", cmWDump((const NQ_WCHAR*)((CMItem *)pMethod->item.name)));*/

#else
    /* in this case we test socket and close it.
     * to later be opened on prepare methods per resolver call */
    /* test to ensure local socket bind succeeds */
	if(bindClientSocket(pMethod) == FALSE)
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "Error binding DNS socket");
		goto Error1;
	}

	/* Close socket until needed */
	syCloseSocket(pMethod->socket);
	pMethod->socket = syInvalidSocket();
#endif

	/* socket is usable */
	pMethod->enabled = TRUE;

	result = TRUE;
	goto Exit;


Error1:
    cmListItemRemoveAndDispose((CMItem *)pMethod);

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result ? "TRUE" : "FALSE");
    return result;
}

void cmResolverRemoveMethod(const CMResolverMethodDescriptor * descriptor, const NQ_IPADDRESS * serverIp)
{
    CMIterator iterator;            /* method iterator */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "descriptor:%p serverIP:%p", descriptor, serverIp);

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
    NQ_TIME selectTimeStamp, timeDiff;  /* time when the current select started */
    NQ_TIME currentTimeout;             /* timeout of the current select */
    NQ_TIME zero = {0, 0}, tmpTime;
    CMIterator iterator;            	/* method iterator */
    const NQ_WCHAR * pName = NULL;  	/* pointer to the resulted name */
    const CacheEntry * pEntry;      	/* entry in the cache */
    NQ_COUNT numPendingMethods;			/* number of methods that sent request */
    NQ_UINT priorityToActivate = 1;		/* each resolver method has activation priority. we start from 1 which is highest*/

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "ip:%p", ip);

    syMutexTake(&staticData->guard);

    /* look in cache */
    pEntry = lookupIpInCache(ip);
    if (NULL != pEntry)
    {
        pName = cmMemoryCloneWString(pEntry->item.name);
        if (NULL == pName)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        }
        goto Exit1;
    }

    prepareMethods();    

    /* loop by the smallest timeout until either all timeouts expire or there is at least one answer */
    for (; ;)
    {
        SYSocketSet set;                /* socket set for select */
        NQ_BOOL breakWhile = FALSE;
        numPendingMethods = 0;

        syClearSocketSet(&set);
        cmU64Zero(&currentTimeout);

        for (cmListIteratorStart(&staticData->methods, &iterator); cmListIteratorHasNext(&iterator); )
        {
            Method * pMethod = (Method *)cmListIteratorNext(&iterator);
            if (!pMethod->enabled || pMethod->method.type == NQ_RESOLVER_DNS_DC || pMethod->method.type == NQ_RESOLVER_NETBIOS_DC)
                continue;
            if ((NQ_ERR_MOREDATA == pMethod->status) && (priorityToActivate == pMethod->method.activationPriority))
			{
				pMethod->status = (*pMethod->method.requestByIp)(pMethod->socket, ip, pMethod->context, &pMethod->serverIp);
				if (pMethod->status >= NQ_SUCCESS)
				{
                    if (cmU64Cmp(&pMethod->method.timeout, &currentTimeout) > 0)
                    {
                    	/* set to max timeout value */
                    	cmU64AssignU64(&currentTimeout, &pMethod->method.timeout);
                    }
					syAddSocketToSet(pMethod->socket, &set);
					if (pMethod->status > 1)
					{
						numPendingMethods += (NQ_COUNT)pMethod->status;
						pMethod->status = NQ_SUCCESS;
					}
					else
					{
						++numPendingMethods;
					}
				}
			}
        }
        cmListIteratorTerminate(&iterator);

        selectTimeStamp = syGetTimeInMsec();
        while (numPendingMethods > 0)
        {
        	NQ_UINT32 curTo = cmTimeConvertMSecToSec(&currentTimeout);

        	if (cmU64Cmp(&currentTimeout, &zero) <= 0)
			{
				LOGERR(CM_TRC_LEVEL_ERROR, "Timeout - no response, method priority: %d.", priorityToActivate);
				break;
			}

			switch (sySelectSocket(&set, curTo))
			{
			case 0:  /* timeout */
				LOGERR(CM_TRC_LEVEL_ERROR, "Select timeout - no response, method priority: %d.", priorityToActivate);
				breakWhile = TRUE;
				break;

			case NQ_FAIL: /* error the select failed  */
				LOGERR(CM_TRC_LEVEL_ERROR, "Select failed");
				goto Error;

			default: /* datagram ready for reading */
				for (cmListIteratorStart(&staticData->methods, &iterator); cmListIteratorHasNext(&iterator); )
				{
					Method * pMethod = (Method *)cmListIteratorNext(&iterator);
					if (!pMethod->enabled || pMethod->method.type == NQ_RESOLVER_DNS_DC || pMethod->method.type == NQ_RESOLVER_NETBIOS_DC)
						continue;
					if (syIsSocketSet(pMethod->socket, &set))
					{
						--numPendingMethods;
						pMethod->status = (*pMethod->method.responseByIp)(pMethod->socket, &pName, &pMethod->context);
						switch (pMethod->status)
						{
						case NQ_SUCCESS:
							cmMemoryFree(pMethod->context); /* will handle NULL */
							cmListIteratorTerminate(&iterator);
							goto Exit2;
						case NQ_ERR_MOREDATA:
						case NQ_FAIL:
							cmMemoryFree(pMethod->context); /* will handle NULL */
							break;
						default:    /* error */
							break;
						}
					}
				}
				syClearSocketSet(&set);
				cmListIteratorTerminate(&iterator);
			}

			if (breakWhile)
				break;

			/* recalculate timeout */
			tmpTime = syGetTimeInMsec();
			cmU64SubU64U64(&timeDiff, &tmpTime, &selectTimeStamp);
			if (cmU64Cmp(&timeDiff, &zero) > 0)
			{
				if (cmU64Cmp(&timeDiff, &currentTimeout) > 0)
					currentTimeout = zero;
				else
				{
					NQ_TIME tmp = currentTimeout;

					cmU64SubU64U64(&currentTimeout, &tmp, &timeDiff);
				}

				cmU64AddU64(&selectTimeStamp, &timeDiff);
			}
    	}

        /* activate next priority methods */
		if (priorityToActivate < RESOLVER_MAX_ACTIVATION_PRIORITY)
		{
			++priorityToActivate;
			continue;
		}
		LOGERR(CM_TRC_LEVEL_ERROR, "All methods failed");
		goto Error;
    }


Error:
    pName = pName == NULL ? externalIpToName(ip) : pName;
Exit2:
    addToCache(pName, ip, 1);

Exit1:
#ifdef UD_NQ_CLOSESOCKETS
    closeSockets();
#endif
    syMutexGive(&staticData->guard);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", cmWDump(pName));
    return pName;
}

static const NQ_BOOL orderIPAddreses(const NQ_IPADDRESS ** resolvedIPs, NQ_COUNT numIPs)
{
	const CMSelfIp 	* pAdapter;
	NQ_IPADDRESS *orderedIPs, *newArray; /* Same IP list. the IPs that are on same subnet as local addresses, will appear first */
	NQ_COUNT iOrdered = 0; 	/* counter for new list of ordered IPS*/
	NQ_BOOL res = FALSE;
	NQ_COUNT iResolved; 	/* counter for list of resolved IPs before ordering */
	const NQ_IPADDRESS zeroIp = CM_IPADDR_ZERO;     /* non-existent IP */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "numIps: %d", numIPs);

	orderedIPs = (NQ_IPADDRESS *) cmMemoryAllocate((NQ_UINT)(sizeof (NQ_IPADDRESS) * numIPs));
	newArray = (NQ_IPADDRESS *) cmMemoryAllocate((NQ_UINT)(sizeof (NQ_IPADDRESS) * numIPs));

	if (NULL == orderedIPs || NULL == newArray)
	{
		if (orderedIPs)
		{
			cmMemoryFree(orderedIPs);
			orderedIPs = NULL;
		}
		goto Exit;
	}

	syMemcpy(newArray, *resolvedIPs, sizeof(NQ_IPADDRESS) * (NQ_UINT)numIPs);

	for (cmSelfipIterate(); NULL != (pAdapter = cmSelfipNext()); )
	{
		if (CM_IPADDR_VERSION(pAdapter->ip) == CM_IPADDR_IPV4)
		{
			for (iResolved = 0; iResolved < numIPs; ++iResolved)
			{
				if (!CM_IPADDR_EQUAL(zeroIp, newArray[iResolved]) &&
						((CM_IPADDR_GET4(newArray[iResolved]) & pAdapter->bcast) == CM_IPADDR_GET4(newArray[iResolved])))
				{
					/* this IP is in same subnet as this adapter */
					orderedIPs[iOrdered++] = newArray[iResolved];
					newArray[iResolved] = zeroIp;
				}
			}
		}
	}
	cmSelfipTerminate();

	LOGMSG(CM_TRC_LEVEL_MESS_SOME, "Number of received IPs: %d, num in same subnets: %d", numIPs, iOrdered);

	iResolved = 0;
	while ((iOrdered < numIPs) && (iResolved < numIPs))
	{
		if (!CM_IPADDR_EQUAL(zeroIp, newArray[iResolved]))
			orderedIPs[iOrdered ++] = newArray[iResolved];

		++iResolved;
	}

	res = TRUE;

Exit:
	cmMemoryFree(newArray);
	cmMemoryFree(*resolvedIPs);
	*resolvedIPs = orderedIPs;
	return res;
}

const NQ_IPADDRESS * cmResolverGetHostIps(const NQ_WCHAR * host, NQ_INT * numIps)
{
    NQ_TIME selectTimeStamp, timeDiff;          /* time when the current select started */
    NQ_TIME currentTimeout;                     /* timeout of the current select */
    NQ_TIME zero = {0, 0}, tmpTime;
    CMIterator iterator;                        /* method iterator */
    const NQ_IPADDRESS * result = NULL;         /* resulted array of IPs */
    NQ_IPADDRESS * methodIPArray = NULL;        /* one method result */
    NQ_INT methodNumIps;                        /* number of IPs returned by one method */
    const CacheEntry * pEntry;					/* entry in the cache */
    NQ_UINT priorityToActivate = 1;				/* each resolver method has activation priority. we start from 1 which is highest*/
    NQ_COUNT numPendingMethods = 0;				/* valid method flag */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "host:%s numIps:%p", cmWDump(host), numIps);

    syMutexTake(&staticData->guard);

    /* look in cache */
    pEntry = lookupNameInCache(host);
    if (NULL != pEntry)
    {
        result = (const NQ_IPADDRESS *)cmMemoryAllocate((NQ_UINT)(sizeof(NQ_IPADDRESS) * pEntry->numIps));
        if (NULL != result)
        {
            syMemcpy(result, pEntry->ips, sizeof(NQ_IPADDRESS) * pEntry->numIps);
            *numIps = (NQ_INT)pEntry->numIps;
        }
        goto Exit1;
    }

    prepareMethods();  

    *numIps = 0;

    /* loop by the smallest timeout until either all timeouts expire */
    for (; ;)
    {
        SYSocketSet set;                /* socket set for select */
        NQ_BOOL wasResponse = FALSE;    /* there was at least one response */
        NQ_BOOL breakWhile = FALSE;
        cmU64Zero(&currentTimeout);

        syClearSocketSet(&set);
        for (cmListIteratorStart(&staticData->methods, &iterator); cmListIteratorHasNext(&iterator); )
        {
        	Method * pMethod = (Method *)cmListIteratorNext(&iterator);
            if (!pMethod->enabled || pMethod->method.type == NQ_RESOLVER_DNS_DC || pMethod->method.type == NQ_RESOLVER_NETBIOS_DC)
                continue;
            switch(pMethod->status)
            {
            case NQ_SUCCESS:
                break;
            case NQ_ERR_MOREDATA:
            	if (priorityToActivate == pMethod->method.activationPriority)
                {
                    pMethod->status = (*pMethod->method.requestByName)(pMethod->socket, host, pMethod->context, &pMethod->serverIp);
                    if (pMethod->status >= 0)
                    {
                    	if (pMethod->status > 1)
							numPendingMethods += (NQ_COUNT)pMethod->status;
						else
							++numPendingMethods;
                        pMethod->status = NQ_SUCCESS;
                        if (cmU64Cmp(&pMethod->method.timeout, &currentTimeout) > 0)
                        {
                        	/* set to max timeout value */
                        	cmU64AssignU64(&currentTimeout, &pMethod->method.timeout);
                        }
                        syAddSocketToSet(pMethod->socket, &set);
                    }
                }
                break;
            default:
                break;
            }
        }
        cmListIteratorTerminate(&iterator);

        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Select on socket set - host IPs, priority: %d, pending: %d, timeout: %d",
                priorityToActivate, numPendingMethods, cmTimeConvertMSecToSec(&currentTimeout));

        selectTimeStamp = syGetTimeInMsec();
        while (numPendingMethods > 0)
        {
        	NQ_UINT32 curTo = cmTimeConvertMSecToSec(&currentTimeout);

			if (cmU64Cmp(&currentTimeout, &zero) <= 0)
			{
				LOGERR(CM_TRC_LEVEL_ERROR, "Resolve IPs Select timeout, method priority: %d.", priorityToActivate);
				break;
			}

			switch (sySelectSocket(&set, curTo))
			{
			case 0:  /* timeout */
				LOGERR(CM_TRC_LEVEL_ERROR, "Select timeout, method priority: %d.", priorityToActivate);
				breakWhile = TRUE;
				break;

			case NQ_FAIL: /* error the select failed  */
				LOGERR(CM_TRC_LEVEL_ERROR, "Select failed");
				goto Exit2;
				break;

			default: /* datagram ready for reading */
				for (cmListIteratorStart(&staticData->methods, &iterator); cmListIteratorHasNext(&iterator); )
				{
					Method * pMethod = (Method *)cmListIteratorNext(&iterator);
					if (!pMethod->enabled || pMethod->method.type == NQ_RESOLVER_DNS_DC || pMethod->method.type == NQ_RESOLVER_NETBIOS_DC)
						continue;
					if (syIsSocketSet(pMethod->socket, &set))
					{
						syClearSocketFromSet(pMethod->socket, &set);
						syAddSocketToSet(pMethod->socket, &set);
						--numPendingMethods;
						pMethod->status = (*pMethod->method.responseByName)(pMethod->socket, &methodIPArray, &methodNumIps, &pMethod->context);
						switch (pMethod->status)
						{
						case NQ_SUCCESS:
							cmMemoryFree(pMethod->context); /* will handle NULL */
							pMethod->context = NULL;
							mergeIpAddresses(&result, numIps, &methodIPArray, methodNumIps);
							wasResponse = TRUE;
							break;
						case NQ_ERR_MOREDATA:
						case NQ_FAIL:
							cmMemoryFree(pMethod->context); /* will handle NULL */
							pMethod->context = NULL;
							cmMemoryFree(methodIPArray);
							methodIPArray = NULL;
							break;
						default:    /* error */
							break;
						}
					}
				}
				cmListIteratorTerminate(&iterator);
			}

			if (breakWhile)
				break;

			/* check pending requests */
			if (wasResponse)
			{
				for (cmListIteratorStart(&staticData->methods, &iterator); cmListIteratorHasNext(&iterator); )
				{
					Method * pMethod = (Method *)cmListIteratorNext(&iterator);

					if (NQ_ERR_MOREDATA == pMethod->status && pMethod->method.waitAnyway)
					{
						wasResponse = FALSE;
						break;
					}
				}
				cmListIteratorTerminate(&iterator);
				if (wasResponse && 0 == numPendingMethods)
				{
					goto Exit2;
				}
			}

			/* recalculate timeout */
			tmpTime = syGetTimeInMsec();
			cmU64SubU64U64(&timeDiff, &tmpTime, &selectTimeStamp);
			if (cmU64Cmp(&timeDiff, &zero) > 0)
			{
				if (cmU64Cmp(&timeDiff, &currentTimeout) > 0)
					currentTimeout = zero;
				else
				{
					NQ_TIME tmp = currentTimeout;

					cmU64SubU64U64(&currentTimeout, &tmp, &timeDiff);
				}

				cmU64AddU64(&selectTimeStamp, &timeDiff);
			}
		} /*while (numPendingMethods > 0)*/

        /* advance activation priority or abort */
        if (NULL == result)
        {
        	if (priorityToActivate < RESOLVER_MAX_ACTIVATION_PRIORITY)
        	{
        		++priorityToActivate;
        		continue;
        	}
        	else
        	{
        		LOGERR(CM_TRC_LEVEL_ERROR, "All methods failed");
        	}
		}

		goto Exit2;
    }
Exit2:
	if (NULL == result)
	{
		result = externalNameToIp(host, numIps);
	}

	if (*numIps > 1)
	{
		orderIPAddreses(&result, (NQ_COUNT)*numIps);
	}

	/* add to cache an ordered list */
    addToCache(host, result, (NQ_COUNT)*numIps);

Exit1:
#ifdef UD_NQ_CLOSESOCKETS
    closeSockets();
#endif
    syMutexGive(&staticData->guard);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%p", result);
    return result;
}

NQ_BOOL cmResolverUpdateExternalMethodsPriority(NQ_INT requiredPriority)
{
	CMIterator iterator;                        /* method iterator */

	for (cmListIteratorStart(&staticData->methods, &iterator); cmListIteratorHasNext(&iterator); )
	{
		Method * pMethod = (Method *)cmListIteratorNext(&iterator);

		if (NQ_RESOLVER_EXTERNAL_METHOD == pMethod->method.type)
		{
			switch (requiredPriority)
			{
				case 1:
					pMethod->method.activationPriority = 1;
					break;
				case 2:
					pMethod->method.activationPriority = 3;
					break;
				default:
					pMethod->method.activationPriority = 5;
					break;
			}
		}
	}
	cmListIteratorTerminate(&iterator);

	return TRUE;
}

const NQ_WCHAR * cmResolverGetDCName(const NQ_WCHAR * domain, NQ_INT * numDCs)
{
    NQ_TIME selectTimeStamp, timeDiff;          /* time when the current select started */
    NQ_TIME currentTimeout;                     /* timeout of the current select */
    NQ_TIME zero = {0, 0}, tmpTime;
    CMIterator iterator;                        /* method iterator */
    NQ_UINT priorityToActivate = 1;             /* each resolver method has activation priority. we start from 1 which is highest*/
    const NQ_WCHAR *pDCName = NULL;             /* resolved domain DC name */
    const NQ_WCHAR *pResult = NULL;             /* return value */
    NQ_COUNT numPendingMethods = 0;     		/* valid method flag */
    NQ_IPADDRESS * methodIPArray = NULL;        /* one method result */
    NQ_INT methodNumIps;                        /* number of IPs returned by one method *//* one method result */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "domain:%s numDCs:%p", cmWDump(domain), numDCs);

    syMutexTake(&staticData->guard);

    prepareMethods();

    /* loop by the smallest timeout until either all timeouts expire or there is at least one answer */
    for (; ;)
    {
        SYSocketSet set;                /* socket set for select */
        NQ_BOOL breakWhile = FALSE;
        NQ_BOOL IPReceivedForNbns = FALSE;

        syClearSocketSet(&set);
        cmU64Zero(&currentTimeout);

        for (cmListIteratorStart(&staticData->methods, &iterator); cmListIteratorHasNext(&iterator); )
        {
            Method * pMethod = (Method *)cmListIteratorNext(&iterator);
            
            if (!pMethod->enabled || (pMethod->method.type != NQ_RESOLVER_DNS_DC && pMethod->method.type != NQ_RESOLVER_NETBIOS_DC))
                continue;
            if ((NQ_ERR_MOREDATA == pMethod->status) && (priorityToActivate == pMethod->method.activationPriority))
            {
				pMethod->status = (*pMethod->method.requestByName)(pMethod->socket, domain, pMethod->context, &pMethod->serverIp);
				if (pMethod->status >= 0)
				{
					pMethod->status = NQ_SUCCESS;
                    if (cmU64Cmp(&pMethod->method.timeout, &currentTimeout) > 0)
                    {
                    	/* set to max timeout value */
                    	cmU64AssignU64(&currentTimeout, &pMethod->method.timeout);
                    }
					syAddSocketToSet(pMethod->socket, &set);
					++numPendingMethods;
				}
			}
        }
        cmListIteratorTerminate(&iterator);


        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Select on socket set for DC response, priority: %d , pending: %d, timeout: %d",
        		priorityToActivate , numPendingMethods, cmTimeConvertMSecToSec(&currentTimeout));

        selectTimeStamp = syGetTimeInMsec();
        while (numPendingMethods > 0)
        {
        	NQ_UINT32 curTo = cmTimeConvertMSecToSec(&currentTimeout);

        	if (cmU64Cmp(&currentTimeout, &zero) <= 0)
        	{
        		LOGERR(CM_TRC_LEVEL_ERROR, "Get DC Select timeout, methods priority: %d.", priorityToActivate);
        		break;
        	}

			switch (sySelectSocket(&set, curTo))
			{
			case 0:  /* timeout */
				LOGERR(CM_TRC_LEVEL_ERROR, "Select timeout - no response, priority: %d ", priorityToActivate);
				breakWhile = TRUE;
				break;
			case NQ_FAIL: /* error the select failed  */
				LOGERR(CM_TRC_LEVEL_ERROR, "Select failed");
				goto Exit;

			default: /* datagram ready for reading */
				for (cmListIteratorStart(&staticData->methods, &iterator); cmListIteratorHasNext(&iterator); )
				{
					Method * pMethod = (Method *)cmListIteratorNext(&iterator);

					if (!pMethod->enabled || (pMethod->method.type != NQ_RESOLVER_DNS_DC && pMethod->method.type != NQ_RESOLVER_NETBIOS_DC))
						continue;
					if (syIsSocketSet(pMethod->socket, &set))
					{
						--numPendingMethods;
						syClearSocketFromSet(pMethod->socket, &set); /* remove this socket from set */
						if (!IPReceivedForNbns && pMethod->method.type == NQ_RESOLVER_NETBIOS_DC)
						{
							/* for NETBIOS we first receive IP responses - take IPs and query names*/
							NQ_COUNT IPNum;
							IPReceivedForNbns = TRUE;

							pMethod->status = (*pMethod->method.responseByName)(pMethod->socket, &methodIPArray, &methodNumIps, &pMethod->context);
							/* Received IP responses. iterate IPs and request host names.*/
							if (NQ_SUCCESS == pMethod->status)
							{
								for (IPNum = 0; methodNumIps > 0; --methodNumIps, ++IPNum)
								{
									pMethod->status = (*pMethod->method.requestByIp)(pMethod->socket, &methodIPArray[IPNum], pMethod->context, &pMethod->serverIp);
									if (NQ_SUCCESS == pMethod->status)
									{
				                        if (cmU64Cmp(&pMethod->method.timeout, &currentTimeout) > 0)
				                        {
				                        	/* set to max timeout value */
				                        	cmU64AssignU64(&currentTimeout, &pMethod->method.timeout);
				                        	selectTimeStamp = syGetTimeInMsec();
				                        }
										cmU64Inc(&currentTimeout);
										++numPendingMethods;
									}
								}
								syAddSocketToSet(pMethod->socket, &set);
							}
							cmMemoryFree(methodIPArray);
							methodIPArray = NULL;
							continue;
						}

						/* add removed socket back to set */
						syAddSocketToSet(pMethod->socket, &set);

						/* Above we query by name. but for DNS in this type we need response by IP */
						pMethod->status = (*pMethod->method.responseByIp)(pMethod->socket, &pDCName, &pMethod->context);
						switch (pMethod->status)
						{
						case NQ_SUCCESS:
							*numDCs = *((NQ_INT *)pMethod->context);
							cmMemoryFree(pMethod->context); /* will handle NULL */
							pMethod->context = NULL;
							cmListIteratorTerminate(&iterator);
							pResult = pDCName;
							goto Exit;
						case NQ_ERR_MOREDATA:
						case NQ_FAIL:
							cmMemoryFree(pMethod->context); /* will handle NULL */
							pMethod->context = NULL;
							break;
						default:    /* error */
							break;
						}
					}
				}
				cmListIteratorTerminate(&iterator);
			}

			if (breakWhile)
				break;

			/* recalculate timeout */
			tmpTime = syGetTimeInMsec();
			cmU64SubU64U64(&timeDiff, &tmpTime, &selectTimeStamp);
			if (cmU64Cmp(&timeDiff, &zero) > 0)
			{
				if (cmU64Cmp(&timeDiff, &currentTimeout) > 0)
					currentTimeout = zero;
				else
				{
					NQ_TIME tmp = currentTimeout;

					cmU64SubU64U64(&currentTimeout, &tmp, &timeDiff);
				}

				cmU64AddU64(&selectTimeStamp, &timeDiff);
			}
        }

        /* modify activation priority */
		if (priorityToActivate < RESOLVER_MAX_ACTIVATION_PRIORITY)
		{
			++priorityToActivate;
			continue;
		}
		LOGERR(CM_TRC_LEVEL_ERROR, "All methods failed");
		goto Exit;
    }

Exit:
    syMutexGive(&staticData->guard);
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%p, numDCs:%d", pResult, *numDCs);
    return pResult;
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

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "type:%d unicast:%s multicast:%s", unicast, unicast ? "TRUE" : "FALSE", multicast ? "TRUE" : "FALSE");

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

