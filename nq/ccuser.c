
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

#include "ccuser.h"
#include "ccshare.h"
#include "amspnego.h"

#ifdef UD_NQ_INCLUDECIFSCLIENT

/* -- Static data -- */

typedef struct
{
    SYMutex guard;                  /* critical section guard */
    AMCredentialsW admin;           /* pointer to administrative credentials */
    NQ_BOOL useAdmin;               /* whether to use admin. credentials */ 
}
StaticData;

#ifdef SY_FORCEALLOCATION
static StaticData* staticData = NULL;
#else  /* SY_FORCEALLOCATION */
static StaticData staticDataSrc;
static StaticData* staticData = &staticDataSrc;
#endif /* SY_FORCEALLOCATION */

static const AMCredentialsW anonymous = {{{0}, {0}}, {0}, {0}};

/* -- Static functions --- */

#if SY_DEBUGMODE
/*
 * Print user-specific information 
 */
static void dumpOne(CMItem * pItem)
{
	CCUser * pUser = (CCUser *)pItem;
	LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "  User:: UID: %d:%d%s", pUser->uid.low, pUser->uid.high, pUser->isAnonymous ? " anonymous" : "");
	LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "  Shares: ");
	cmListDump(&pUser->shares);
}
#endif /* SY_DEBUGMODE */

#ifdef UD_CC_INCLUDEEXTENDEDSECURITY

/* wrapper for SMB's doSessionSetup  - used as AM callback. it converts NQ_ERR_MOREDATA into NQ_SUCCESS  */
static NQ_STATUS doSessionSetup(void * pUser, const CMBlob * outBlob, CMBlob * inBlob)
{
    NQ_STATUS status;           /* operation status */
    CMBlob outBlobFragment;     /* current fragment of the outgoing blob */
    NQ_COUNT remainingLen;      /* remaing data length in the outgoing blob */
    NQ_COUNT maxFragmentLen;    /* available length of an outgoing blob gragment */ 

    outBlobFragment = *outBlob;
    remainingLen = outBlob->len;
    maxFragmentLen = ((CCUser *)pUser)->server->maxTrans - 120; /* leave enough room for headers */ 
    
    for (;;)
    {
        inBlob->data = NULL;    /* to check that server responds with an empty blob */
        outBlobFragment.len = remainingLen > maxFragmentLen? maxFragmentLen : remainingLen; 
        status = ((CCUser *)pUser)->server->smb->doSessionSetupExtended(pUser, &outBlobFragment, inBlob);
        if (status != NQ_SUCCESS && status != NQ_ERR_MOREDATA)
            return status;
        if (remainingLen == outBlobFragment.len)
            break;
        remainingLen -= maxFragmentLen;
        outBlobFragment.data += maxFragmentLen;
    }
    return NQ_SUCCESS;
}
#endif /* UD_CC_INCLUDEEXTENDEDSECURITY */

/*
 * Explicitely dispose and disconnect server:
 * 	- disconnects from the share
 *  - disposes private data  
 */
static void disposeUser(CCUser * pUser)
{
    CCServer * pServer = pUser->server;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "About to dispose user %s", cmWDump(pUser->item.name));

    if (pServer->masterUser != (CMItem *)pUser)
    {
   	    ccUserLogoff(pUser);
        cmListShutdown(&pUser->shares);
        if (NULL != pUser->credentials)
            cmMemoryFree(pUser->credentials);
	    cmListItemRemoveAndDispose((CMItem *)pUser);
    }
    else
    {
        cmListItemRemoveReference((CMItem *)pUser, (CMItem *)pServer);
    }

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

/*
 * Callback for share unlock and disposal:
 * 	- disconnects from the share
 *  - disposes private data  
 */
static NQ_BOOL unlockCallback(CMItem * pItem)
{
	disposeUser((CCUser *)pItem);
    return TRUE;
}

/* query user credentials from application */
static AMCredentialsW * queryCredentials(const NQ_WCHAR * path)
{
	AMCredentialsW * pCredentials = NULL;	/* credentials allocated */
	
	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	pCredentials = (AMCredentialsW *)cmMemoryAllocate(sizeof(AMCredentialsW));
	if (NULL == pCredentials)
	{
		sySetLastNqError(NQ_ERR_OUTOFMEMORY);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NULL;
	}
	/* query credentials */
    if (staticData->useAdmin)
    {
         syMemcpy(pCredentials, &staticData->admin, sizeof(AMCredentialsW));
    }
    else
    {
	    AMCredentials * pCredentialsT;	/* credentials allocated */
	    pCredentialsT = (AMCredentials *)cmMemoryAllocate(sizeof(AMCredentials));
	    if (NULL == pCredentialsT)
	    {
            cmMemoryFree(pCredentials);
            sySetLastNqError(NQ_ERR_OUTOFMEMORY);
		    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		    return NULL;
	    }
        syMutexTake(&staticData->guard);
	    if (!udGetCredentials(path, pCredentialsT->user, pCredentialsT->password, pCredentialsT->domain.name))
	    {
            syMutexGive(&staticData->guard);
		    cmMemoryFree(pCredentials);
		    cmMemoryFree(pCredentialsT);
		    LOGERR(CM_TRC_LEVEL_ERROR, "udGetCredentials canceled");
		    sySetLastNqError(NQ_ERR_BADPARAM);
		    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		    return NULL;
	    }
        syMutexGive(&staticData->guard);
        amCredentialsTcharToW(pCredentials, pCredentialsT);
        cmMemoryFree(pCredentialsT);
    }
	LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Domain: %s", cmWDump(pCredentials->domain.name));
	LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "User: %s", cmWDump(pCredentials->user));
	LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Password: %s", cmWDump(pCredentials->password));

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return pCredentials;
}

static CCUser * createUser(CCServer * pServer, const AMCredentialsW * pCredentials)
{
	CCUser * pUser;					/* user pointer */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	/* create a user and logon to it */
	pUser = (CCUser *)cmListItemCreateAndAdd(&pServer->users, sizeof(CCUser), pCredentials->user, unlockCallback , TRUE);
	if (NULL == pUser)
	{
		sySetLastNqError(NQ_ERR_OUTOFMEMORY);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NULL;
	}

	pUser->server = pServer;
	pUser->logged = FALSE;
	cmListStart(&pUser->shares);
    pUser->credentials = cmMemoryAllocate(sizeof(AMCredentialsW));
	if (NULL == pUser->credentials)
	{
	    cmListItemCheck((CMItem *)pUser);
		sySetLastNqError(NQ_ERR_OUTOFMEMORY);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NULL;
	}
    syMemcpy(pUser->credentials, pCredentials, sizeof(AMCredentialsW));
    cmListItemAddReference((CMItem *)pUser, (CMItem *)pServer);
    pUser->isAnonymous = cmWStrlen(pUser->credentials->user) == 0;
   	cmU64Zero(&pUser->uid);
	pUser->macSessionKey.data = NULL;
    pUser->sessionKey.data = NULL;
   	pUser->isGuest = FALSE;
#if SY_DEBUGMODE
	pUser->item.dump = dumpOne; 
#endif /* SY_DEBUGMODE */

	if (!ccUserLogon(pUser))
	{
        cmListItemUnlock((CMItem *)pUser);
		pUser = NULL;
	}

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return pUser;
}

static CCUser * findUser(CCServer * pServer, const AMCredentialsW * pCredentials)
{
    CMIterator iterator;    /* user iterator */

    cmListIteratorStart(&pServer->users, &iterator);
    while (cmListIteratorHasNext(&iterator))
    {
        CCUser * pUser = (CCUser *)cmListIteratorNext(&iterator);
        if (NULL != pUser->credentials &&
            0 == cmWStrcmp(pCredentials->user, pUser->credentials->user) && 
            0 == cmWStrcmp(pCredentials->domain.name, pUser->credentials->domain.name) && 
            0 == cmWStrcmp(pCredentials->password, pUser->credentials->password) 
            )
        {
            cmListItemLock((CMItem *)pUser);
            cmListIteratorTerminate(&iterator);
            return pUser;
        }
    }
    cmListIteratorTerminate(&iterator);
    return NULL;
}

/* -- API Functions */

NQ_BOOL ccUserStart(void)
{
    /* allocate memory */
#ifdef SY_FORCEALLOCATION
    staticData = (StaticData *)syCalloc(1, sizeof(*staticData));
    if (NULL == staticData)
    {
        TRCERR("Unable to allocate user data");
        return NQ_FAIL;
    }
#endif /* SY_FORCEALLOCATION */

    syMutexCreate(&staticData->guard);
    staticData->useAdmin = FALSE;
	return TRUE;
}

void ccUserShutdown(void)
{
    syMutexDelete(&staticData->guard);

#ifdef SY_FORCEALLOCATION
    if (NULL != staticData)
        syFree(staticData);
    staticData = NULL;
#endif /* SY_FORCEALLOCATION */
}

const AMCredentialsW * ccUserGetAnonymousCredentials(void)
{
    return &anonymous;
}

NQ_BOOL ccUserIsAnonymousCredentials(const AMCredentialsW *pCredentials)
{
	return (0 == cmWStrcmp(pCredentials->user, anonymous.user) &&
			0 == cmWStrcmp(pCredentials->domain.name, anonymous.domain.name) &&
			0 == cmWStrcmp(pCredentials->password, anonymous.password));
}

CCUser * ccUserFindById(CCServer * pServer, NQ_UINT64 uid)
{
    CMIterator iterator;    /* user iterator */

    ccServerIterateUsers(pServer, &iterator);
    while (cmListIteratorHasNext(&iterator))
    {
        CCUser * pNextUser;     /* next user pointer */

        pNextUser = (CCUser *)cmListIteratorNext(&iterator);
        if (0 == cmU64Cmp(&uid, &pNextUser->uid))
        {
            return pNextUser;
        }
    }
    cmListIteratorTerminate(&iterator);
    return NULL;
}

void ccUserIterateShares(CCUser * pUser, CMIterator * iterator)
{
    cmListIteratorStart(&pUser->shares, iterator);
}

NQ_BOOL ccUserUseSignatures(CCUser * pUser)
{
    return !pUser->isAnonymous && (pUser->uid.high != 0 || pUser->uid.low != 0) && NULL != pUser->macSessionKey.data && !pUser->isGuest;
}

void ccUserSetAdministratorCredentials(const AMCredentialsW * credentials)
{
    if (NULL != credentials)
    {
        staticData->admin = *credentials;
    }
    staticData->useAdmin = NULL != credentials;
}

const AMCredentialsW * ccUserGetAdministratorCredentials(void)
{
    return staticData->useAdmin ? &staticData->admin : NULL;
}


CCUser * ccUserGet(CCServer * pServer, const NQ_WCHAR * path, const AMCredentialsW ** pCredentials)
{
	CCUser * pUser = NULL;				                    /* user pointer */
    const AMCredentialsW * credentials = * pCredentials;    /* credentials to use */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    cmListItemTake((CMItem *)pServer);
#ifdef UD_CC_CACHECREDENTIALS
    /* find existing: this is only possible when credentials are supplied */
	if (NULL != credentials)
	{
	    pUser = findUser(pServer, credentials);
    }
	if (NULL != pUser)
    {
        if (!pUser->logged && !ccUserLogon(pUser))
        {
            cmListItemGive((CMItem *)pServer);
            cmListItemUnlock((CMItem *)pUser);
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	        return NULL;
        }
        cmListItemGive((CMItem *)pServer);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	    return pUser;
    }
    if (NULL != credentials)
    {
        pUser = createUser(pServer, credentials);
        if (NULL != pUser)
        {
            cmListItemGive((CMItem *)pServer);
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	        return pUser;
        }
    }
#endif /* UD_CC_CACHECREDENTIALS */

    credentials = queryCredentials(path);
    if (NULL == credentials)
    {
        cmListItemGive((CMItem *)pServer);
        sySetLastNqError(NQ_ERR_OUTOFMEMORY);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NULL;
    }

    pUser = findUser(pServer, credentials);
    if (NULL == pUser || (NULL != pUser && !pUser->logged))
    {
        pUser = createUser(pServer, credentials);
    }

    if (*pCredentials != NULL && !ccUserIsAnonymousCredentials(*pCredentials))
    {
    	syMemcpy(*pCredentials, credentials, sizeof(AMCredentialsW));
    }
	cmMemoryFree(credentials);

    cmListItemGive((CMItem *)pServer);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return pUser;
}

void ccUserLogoff(CCUser * pUser)
{
	CMIterator iterator;		/* to enumerate users */
	CCServer * pServer;			/* server pointer */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    if (!pUser->logged)
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    	return;
	}
	cmListIteratorStart(&pUser->shares, &iterator);
	while (cmListIteratorHasNext(&iterator))
	{
		CCShare * pShare;			/* next share pointer */
		
		pShare = (CCShare *)cmListIteratorNext(&iterator);
		ccShareDisconnect(pShare);
	}
	cmListIteratorTerminate(&iterator);

	pServer = pUser->server;
	if (NULL!= pServer->smb && pUser->logged)
    {
		pServer->smb->doLogOff(pUser);
        pUser->logged = FALSE;
    }
    amSpnegoFreeKey(&pUser->sessionKey);
	amSpnegoFreeKey(&pUser->macSessionKey);

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

NQ_BOOL ccUserLogon(CCUser * pUser)
{
	NQ_STATUS status;	        /* SPNEGO status */
	CCServer * pServer;	        /* server pointer */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    amSpnegoFreeKey(&pUser->sessionKey);       /* in case of reconnect, otherwise - will be NULL */
	amSpnegoFreeKey(&pUser->macSessionKey);

    cmListItemTake((CMItem *)pUser);
    if (pUser->logged)
    {
        cmListItemGive((CMItem *)pUser);
        LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "Logon: user already logged in");
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return TRUE;
    }

    pServer = pUser->server;

#ifdef UD_CC_INCLUDEEXTENDEDSECURITY
    if (pServer->useExtendedSecurity)
    {
    	NQ_BOOL restrictCrypters;	/* whether to allow all crypters or not */
    
        restrictCrypters = (pServer->capabilities & CC_CAP_MESSAGESIGNING) && pServer->smb->restrictCrypters;
        status = amSpnegoClientLogon(
            pUser, 
            pServer->item.name, 
            pUser->credentials, 
            restrictCrypters, 
            &pServer->firstSecurityBlob, 
            &pUser->sessionKey,
            &pUser->macSessionKey,
            doSessionSetup
            );
        if (AM_SPNEGO_SUCCESS == status)
        {
			pServer->useSigning = TRUE;
			if (!pServer->isLoggedIn && !pUser->isAnonymous)
			{
			    pServer->isLoggedIn = TRUE;
			}
			pUser->logged = TRUE;
        }
        cmListItemGive((CMItem *)pUser);
        if (AM_SPNEGO_SUCCESS == status && NULL != pUser->macSessionKey.data && pUser->macSessionKey.len > pServer->smb->maxSigningKeyLen)
            pUser->macSessionKey.len = pServer->smb->maxSigningKeyLen;  /* restrict bigger keys */
        LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "Logon: %s", AM_SPNEGO_SUCCESS == status ? "ok" : "failed");
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return AM_SPNEGO_SUCCESS == status; 
	}
	else
#endif /* UD_CC_INCLUDEEXTENDEDSECURITY */
	{
        NQ_INT level;           /* encryption level */

	    for (level = AM_MAXSECURITYLEVEL; level >= 0; level--)
	    {
		    CMBlob pass1;	/* first password blob */
		    CMBlob pass2;	/* second password blob */

            if (NULL == pServer->firstSecurityBlob.data)
            {
                cmListItemGive((CMItem *)pUser);
                sySetLastError(NQ_ERR_BADPARAM);
                LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                return FALSE;
            }
            pUser->sessionKey = cmMemoryCloneBlob(&pServer->firstSecurityBlob);
            
            if (pUser->isAnonymous || !pServer->userSecurity)
            {
                pass1.data = NULL;
                pass1.len = 0;
                pass2.data = NULL;
                pass2.len = 0;

                
                status = pServer->smb->doSessionSetup(pUser, &pass1, &pass2);
       
                if (NQ_SUCCESS == status)
			    {
        			pServer->useSigning = TRUE;
                    pUser->logged = TRUE;
        			if (!pServer->isLoggedIn && !pUser->isAnonymous)
        			{
        			    pServer->isLoggedIn = TRUE;
        			}
                    cmListItemGive((CMItem *)pUser);
				    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
				    return TRUE;
			    }
                amSpnegoFreeKey(&pUser->sessionKey);
			    sySetLastNqError((NQ_UINT32)status);
                continue;
                
            }
            if (AM_SPNEGO_SUCCESS == amSpnegoGeneratePasswordBlobs(pUser->credentials, level, &pass1, &pass2, &pUser->sessionKey, &pUser->macSessionKey))
		    {
			    status = pServer->smb->doSessionSetup(pUser, &pass1, &pass2);
                cmMemoryFreeBlob(&pass1);
			    cmMemoryFreeBlob(&pass2);
                
                if (NQ_SUCCESS == status)
			    {
        			pServer->useSigning = TRUE;
                    pUser->logged = TRUE;
        			if (!pServer->isLoggedIn && !pUser->isAnonymous)
        			{
        			    pServer->isLoggedIn = TRUE;
        			}
                    if (NULL != pUser->macSessionKey.data && pUser->macSessionKey.len > 16)
                        pUser->macSessionKey.len = 16;  /* restict bigger keys */
                    cmListItemGive((CMItem *)pUser);
				    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
				    return TRUE;
			    }
                amSpnegoFreeKey(&pUser->sessionKey);
                amSpnegoFreeKey(&pUser->macSessionKey);
			    sySetLastNqError((NQ_UINT32)status);
		    }
            else
            {
                cmMemoryFreeBlob(&pUser->sessionKey);
            }

        }
    }
    cmListItemGive((CMItem *)pUser);   
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return FALSE;
}

NQ_BOOL ccUserReconnectShares(CCUser * pUser)
{
	CMIterator iterator;		/* to enumerate users */
	
	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
	
	cmListIteratorStart(&pUser->shares, &iterator);
	while (cmListIteratorHasNext(&iterator))
	{
		CCShare * pShare;			/* next share pointer */
		
		pShare = (CCShare *)cmListIteratorNext(&iterator);
		ccShareConnectExisting(pShare, TRUE);
		ccShareReopenFiles(pShare);
	}
	cmListIteratorTerminate(&iterator);

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return TRUE;
}

#endif /* UD_NQ_INCLUDECIFSCLIENT */
