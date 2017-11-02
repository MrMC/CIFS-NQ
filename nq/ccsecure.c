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

#ifdef UD_NQ_INCLUDECIFSCLIENT

/* -- Static data -- */

static SYMutex guard;					/* critical section guard */
static NQ_INT curAuthenticationLevel;	/* for the next connection */ 
static NQ_BOOL curMessageSigning;		/* for the next connection */ 

/* -- API functions -- */

NQ_BOOL ccSecureStart(void)
{
	syMutexCreate(&guard);
	return TRUE;
}

void ccSecureShutdown(void)
{
	syMutexDelete(&guard);
}

void nqSetSecurityParams(NQ_INT authenticationLevel, NQ_BOOL messageSigning)
{
	syMutexTake(&guard);
	curAuthenticationLevel = authenticationLevel;
	curMessageSigning = messageSigning;
	syMutexGive(&guard);
}

NQ_INT nqGetAuthenticationLevel(void)
{
	return curAuthenticationLevel;
}

NQ_BOOL nqGetMessageSigning(void)
{
	return curMessageSigning;
}

NQ_BOOL nqCheckClientUserCredentialsA(NQ_CHAR * server)
{
	NQ_WCHAR * wServer;			/* server name in Unicode */
	NQ_INT res;					/* Unicode operation result */
	
	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
	
	wServer = cmMemoryCloneAString(server);
	if (NULL == wServer)
	{
		sySetLastError(NQ_ERR_OUTOFMEMORY);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_FAIL;
	}
	res = nqCheckClientUserCredentialsW(wServer);
	cmMemoryFree(wServer);

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return res;
}

NQ_BOOL nqCheckClientUserCredentialsW(NQ_WCHAR * server)
{
	NQ_WCHAR *  dcW = NULL;		/* DC name in Unicode */
	NQ_STATUS   status;			/* operation status */
	CCServer *  pServer = NULL;	/* server obejct pointer */
    CCShare *   pShare = NULL;
    NQ_BOOL     security[] = {TRUE, FALSE}; /* whether to use extended security */
    NQ_INT      i;                   /* just a counter */
	
	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
	
    if (server == NULL || *server == 0)
    {
    	NQ_CHAR * dcA;				/* DC name in ASCII */

    	LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "No server name supplied, trying to discover PDC name...");

    	dcA = cmMemoryAllocate(CM_BUFFERLENGTH(NQ_CHAR, CM_DNS_NAMELEN));
        if (NULL == dcA)
    	{
    		sySetLastError(NQ_ERR_OUTOFMEMORY);
    		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    		return NQ_FAIL;
    	}
    	if ((status = cmGetDCName(dcA, NULL)) != NQ_ERR_OK)
        {
    		cmMemoryFree(dcA);
            LOGERR(CM_TRC_LEVEL_ERROR, "Domain controller discovery failure");
            sySetLastError((NQ_UINT32)status);
    		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return FALSE;
        }

        dcW = cmMemoryCloneAString(dcA);
		cmMemoryFree(dcA);
        if (NULL == dcW)
    	{
    		sySetLastError(NQ_ERR_OUTOFMEMORY);
    		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    		return NQ_FAIL;
    	}
        server = dcW;
    }

    for (i = 0; i < sizeof(security)/sizeof(security[0]); i++)
    {
        const AMCredentialsW * pCredentials = NULL;
        pServer = ccServerFindOrCreate(server, security[i], NULL);
        if (NULL != pServer)
        {
            pShare = ccShareConnectIpc(pServer, &pCredentials);
            if (NULL != pShare)
            {
        	    cmMemoryFree(dcW);			/* will ignore NULL */
                cmMemoryFree(pCredentials);
                cmListItemUnlock((CMItem *)pShare);
                cmListItemUnlock((CMItem *)pServer);
		        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                return TRUE;
            }
            cmListItemUnlock((CMItem *)pServer);
            cmMemoryFree(pCredentials);
        }
    }

    cmMemoryFree(dcW);			/* will ignore NULL */
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return FALSE;
}

#endif /* UD_NQ_INCLUDECIFSCLIENT */
