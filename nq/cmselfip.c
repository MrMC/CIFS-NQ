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
    /* allocate memory */
#ifdef SY_FORCEALLOCATION
    staticData = (StaticData *)syCalloc(1, sizeof(*staticData));
    if (NULL == staticData)
    {
        TRCERR("Unable to allocate SelfIp data");
        return NQ_FAIL;
    }
#endif /* SY_FORCEALLOCATION */

    cmListStart(&staticData->ips);
    return TRUE;
}

void cmSelfipShutdown(void)
{
    cmListShutdown(&staticData->ips);
#ifdef SY_FORCEALLOCATION
    if (NULL != staticData)
        syFree(staticData);
    staticData = NULL;
#endif /* SY_FORCEALLOCATION */
}

void cmSelfipIterate(void)
{
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
    
    syMutexTake(&staticData->ips.guard);

    /* load IPs from system */
    {
        NQ_UINT32 ip;              /* next IP address */
        NQ_IPADDRESS6 ip6;         /* next IPv6 address */
        NQ_UINT32 subnet;          /* next subnet mask */
        NQ_UINT32 wins;            /* next WINS IP address */
        NQ_INDEX idx;              /* index in the list of adapters */

        /* empty the list */
        cmListRemoveAndDisposeAll(&staticData->ips);

#ifdef UD_NQ_USETRANSPORTIPV6
        syMemset(ip6, 0, sizeof(ip6));
#endif /* UD_NQ_USETRANSPORTIPV6 */
        for (idx = 0; syGetAdapter(idx, &ip, &ip6, &subnet, &wins) == NQ_SUCCESS && idx < UD_NS_MAXADAPTERS; idx++)
        {
            SelfIp * pSelf;                     /* pointer to next IP entry */

            LOGMSG(CM_TRC_LEVEL_FUNC_COMMON, "Adapter found, ip=0x%08lx subnet=0x%08lx wins=0x%08lx", ip, subnet, wins);

            if (ip != CM_IPADDR_ZERO4)
            {
                pSelf = (SelfIp *)cmListItemCreateAndAdd(&staticData->ips, sizeof(SelfIp), NULL, NULL, FALSE);
                if (NULL == pSelf)
                {
                    syMutexGive(&staticData->ips.guard);
                    LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
                    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                    return;
                }
                CM_IPADDR_ASSIGN4(pSelf->selfIp.ip, ip);
                pSelf->selfIp.bcast = (ip & subnet) | (0xFFFFFFFF & ~subnet);
                pSelf->selfIp.subnet = subnet;
            }
#ifdef UD_NQ_USETRANSPORTIPV6
            if (ip6[0] != 0)
            {
                pSelf = (SelfIp *)cmListItemCreateAndAdd(&staticData->ips, sizeof(SelfIp), NULL, NULL , FALSE);
                if (NULL == pSelf)
                {
                    syMutexGive(&staticData->ips.guard);
                    LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
                    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                    return;
                }
                CM_IPADDR_ASSIGN6(pSelf->selfIp.ip, ip6);
                pSelf->selfIp.bcast = 0L;
            }
            syMemset(ip6, 0, sizeof(ip6));
#endif /* UD_NQ_USETRANSPORTIPV6 */
        }
    }
    syMutexGive(&staticData->ips.guard);
    cmListIteratorStart(&staticData->ips, &staticData->iterator);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

const CMSelfIp * cmSelfipNext(void)
{
    if (cmListIteratorHasNext(&staticData->iterator))
    {
        const SelfIp * selfIp = (const SelfIp *)cmListIteratorNext(&staticData->iterator);
        return &selfIp->selfIp;
    }
    return NULL;
}

void cmSelfipTerminate(void)
{
  cmListIteratorTerminate(&staticData->iterator);  
}
