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

#include "ccsecure.h"
#include "ccserver.h"
#include "ccshare.h"
#include "cmfinddc.h"
#include "amspnego.h"

#ifdef UD_NQ_INCLUDECIFSCLIENT

/* -- Static data -- */

static SYMutex guard;					/* critical section guard */
static NQ_BOOL signingPolicy;

/* -- API functions -- */

NQ_BOOL ccSecureStart(void)
{
	syMutexCreate(&guard);
	signingPolicy = TRUE;
	return TRUE;
}

void ccSecureShutdown(void)
{
	syMutexDelete(&guard);
}

void nqSetSecurityParams(NQ_INT authenticationLevel, NQ_BOOL messageSigning)
{
	syMutexTake(&guard);
	amSpnegoClientSetAuthLevel(authenticationLevel);
	syMutexGive(&guard);
}

NQ_INT nqGetAuthenticationLevel(void)
{
    NQ_INT level;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
	level = amSpnegoClientGetAuthLevel();
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "level:%d", level);
    return level;
}

NQ_BOOL nqGetMessageSigning(void)
{
	return signingPolicy;
}

void ccSetSigningPolicy(NQ_BOOL enable)
{
	syMutexTake(&guard);
	signingPolicy = enable;
	syMutexGive(&guard);
}

NQ_BOOL nqCheckClientUserCredentialsA(NQ_CHAR * server)
{
	NQ_WCHAR * wServer;   /* server name in Unicode */
	NQ_BOOL res = FALSE;  /* return value */
	
	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	wServer = cmMemoryCloneAString(server);
	if (NULL == wServer)
	{
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
		sySetLastError(NQ_ERR_OUTOFMEMORY);
		goto Exit;
	}
	res = nqCheckClientUserCredentialsW(wServer);
	cmMemoryFree(wServer);

Exit:
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", res ? "TRUE" : "FALSE");
	return res;
}

NQ_BOOL nqCheckClientUserCredentialsW(NQ_WCHAR * server)
{
	NQ_CHAR * dcA = NULL;         /* DC name in ASCII */
	NQ_WCHAR *  dcW = NULL;       /* DC name in Unicode */
	NQ_STATUS   status;           /* operation status */
	CCServer *  pServer = NULL;   /* server object pointer */
    CCShare *   pShare = NULL;
    NQ_BOOL     security[] = {TRUE, FALSE}; /* whether to use extended security */
    NQ_COUNT    i;                /* just a counter */
    NQ_BOOL     result = FALSE;   /* return value */
    const AMCredentialsW * pCredentials = NULL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "server:%s", cmWDump(server));

    if (NULL == server || 0 == *server)
    {
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "No server name supplied, trying to discover PDC name...");

    	dcA = (NQ_CHAR *)cmMemoryAllocate(CM_BUFFERLENGTH(NQ_CHAR, CM_DNS_NAMELEN));
        if (NULL == dcA)
    	{
            LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
    		sySetLastError(NQ_ERR_OUTOFMEMORY);
    		goto Exit;
    	}
    	if ((status = cmGetDCName(dcA, NULL)) != NQ_ERR_OK)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Domain controller discovery failure");
            sySetLastError((NQ_UINT32)status);
    		goto Exit;
        }

        dcW = cmMemoryCloneAString(dcA);
        if (NULL == dcW)
    	{
            LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
    		sySetLastError(NQ_ERR_OUTOFMEMORY);
    		goto Exit;
    	}
        server = dcW;
    }

    for (i = 0; i < sizeof(security)/sizeof(security[0]); i++)
    {
        pServer = ccServerFindOrCreate(server, security[i], NULL);
        if (NULL != pServer)
        {
            pShare = ccShareConnectIpc(pServer, &pCredentials);
            if (NULL != pShare)
            {
                cmListItemUnlock((CMItem *)pShare);
                cmListItemUnlock((CMItem *)pServer);
                result = TRUE;
                goto Exit;
            }
            cmListItemUnlock((CMItem *)pServer);
            cmMemoryFree(pCredentials);
            pCredentials = NULL;
        }
    }

Exit:
    cmMemoryFree(dcA);
    cmMemoryFree(dcW);
    cmMemoryFree(pCredentials);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result ? "TRUE" : "FALSE");
	return result;
}

#endif /* UD_NQ_INCLUDECIFSCLIENT */
