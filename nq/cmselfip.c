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

#include "cmselfip.h"

/* Definitions: */
typedef struct 
{
    CMItem item;        /* inheritance */
    CMSelfIp selfIp;    /* IP address and broadcast address */
}
SelfIp;

typedef struct
{
    CMList ips;                     /* list of self IPs */
    CMIterator iterator;            /* IP iterator */ 
}
StaticData;

#ifdef SY_FORCEALLOCATION
static StaticData* staticData = NULL;
#else  /* SY_FORCEALLOCATION */
static StaticData staticDataSrc;
static StaticData* staticData = &staticDataSrc;
#endif /* SY_FORCEALLOCATION */

/* API functions */

NQ_BOOL cmSelfipStart(void)
{
    NQ_BOOL result = FALSE;

    /* allocate memory */
#ifdef SY_FORCEALLOCATION
    staticData = (StaticData *)cmMemoryAllocate(sizeof(*staticData));
    if (NULL == staticData)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to allocate SelfIp data");
        sySetLastError(NQ_ERR_NOMEM);
        goto Exit;
    }
#endif /* SY_FORCEALLOCATION */

    cmListStart(&staticData->ips);
    result = TRUE;

Exit:
    return result;
}

void cmSelfipShutdown(void)
{
    cmListShutdown(&staticData->ips);
#ifdef SY_FORCEALLOCATION
    if (NULL != staticData)
        cmMemoryFree(staticData);
    staticData = NULL;
#endif /* SY_FORCEALLOCATION */
}

void cmSelfipIterate(void)
{
    NQ_BOOL result = FALSE;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    syMutexTake(&staticData->ips.guard);

    /* load IPs from system */
    {
    	NQ_IPADDRESS4 ip;          	/* next IP address */
        NQ_IPADDRESS6 ip6;         	/* next IPv6 address */
        NQ_IPADDRESS4 subnet;       /* next subnet mask */
        NQ_IPADDRESS4 bcast;        /* next bcast address */
        NQ_IPADDRESS4 wins;        	/* next WINS IP address */
        NQ_INDEX idx;              	/* index in the list of adapters */
        NQ_INDEX osIdx = 0;			/* index in the OS */
#ifdef CM_NQ_STORAGE
        NQ_BOOL isRdma = FALSE;    	/* TRUE for an RDMA-capable adapter */
#endif /* CM_NQ_STORAGE */

        /* empty the list */
        cmListRemoveAndDisposeAll(&staticData->ips);

#ifdef UD_NQ_USETRANSPORTIPV6
        syMemset(ip6, 0, sizeof(ip6));
#endif /* UD_NQ_USETRANSPORTIPV6 */
#ifdef CM_NQ_STORAGE
        for (idx = 0; syGetAdapter(idx,	&osIdx, &isRdma, &ip, &ip6, &subnet, &bcast, &wins) == NQ_SUCCESS && idx < UD_NS_MAXADAPTERS; idx++)
#else
        for (idx = 0; syGetAdapter(idx, &osIdx, &ip, &ip6, &subnet, &bcast, &wins) == NQ_SUCCESS && idx < UD_NS_MAXADAPTERS; idx++)
#endif /* CM_NQ_STORAGE */
        {
            SelfIp * pSelf = NULL; /* pointer to next IP entry */

            LOGMSG(CM_TRC_LEVEL_FUNC_COMMON, "Adapter found, ip=0x%08lx subnet=0x%08lx bcast=0x%08lx wins=0x%08lx", ip, subnet, bcast, wins);

            if (ip != CM_IPADDR_ZERO4)
            {
            	pSelf = (SelfIp *)cmListItemCreateAndAdd(&staticData->ips, sizeof(SelfIp), NULL, NULL, CM_LISTITEM_NOLOCK);
                if (NULL == pSelf)
                {
                    LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
                    goto Exit;
                }
                CM_IPADDR_ASSIGN4(pSelf->selfIp.ip, ip);
                pSelf->selfIp.bcast = bcast;
                pSelf->selfIp.subnet = subnet;
#ifdef CM_NQ_STORAGE
                pSelf->selfIp.osIndex = osIdx;
                pSelf->selfIp.rdmaCapable = isRdma;
#endif /* CM_NQ_STORAGE */
            }
#ifdef UD_NQ_USETRANSPORTIPV6
            if (ip6[0] != 0)
            {
                pSelf = (SelfIp *)cmListItemCreateAndAdd(&staticData->ips, sizeof(SelfIp), NULL, NULL, CM_LISTITEM_NOLOCK);
                if (NULL == pSelf)
                {
                    LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
                    goto Exit;
                }
                CM_IPADDR_ASSIGN6(pSelf->selfIp.ip, ip6);
                pSelf->selfIp.bcast = 0L;
                pSelf->selfIp.subnet = subnet;
#ifdef CM_NQ_STORAGE
                pSelf->selfIp.osIndex = osIdx;
                pSelf->selfIp.rdmaCapable = FALSE;
#endif /* CM_NQ_STORAGE */
            }
            syMemset(ip6, 0, sizeof(ip6));
#endif /* UD_NQ_USETRANSPORTIPV6 */
        }
    }
    result = TRUE;

Exit:
    syMutexGive(&staticData->ips.guard);
    if (TRUE == result)
        cmListIteratorStart(&staticData->ips, &staticData->iterator);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

const CMSelfIp * cmSelfipNext(void)
{
    const CMSelfIp * pResult = NULL;

    if (cmListIteratorHasNext(&staticData->iterator))
    {
        const SelfIp * selfIp = (const SelfIp *)cmListIteratorNext(&staticData->iterator);
        pResult = &selfIp->selfIp;
    }
    return pResult;
}

void cmSelfipTerminate(void)
{
    cmListIteratorTerminate(&staticData->iterator);  
}
