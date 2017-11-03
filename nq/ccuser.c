
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
#include "cmsmb2.h"

#ifdef UD_NQ_INCLUDECIFSCLIENT

/* -- Static data -- */

static NQ_BOOL isInit = FALSE;
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
    NQ_STATUS status; /* operation status */
    CMBlob outBlobFragment;     /* current fragment of the outgoing blob */
    NQ_COUNT remainingLen;      /* remaining data length in the outgoing blob */
    NQ_COUNT maxFragmentLen;    /* available length of an outgoing blob fragment */

    outBlobFragment = *outBlob;
    remainingLen = outBlob->len;
    maxFragmentLen = (NQ_COUNT)(((CCUser *)pUser)->server->maxTrans - 120); /* leave enough room for headers */
    
    for (;;)
    {
        inBlob->data = NULL;    /* to check that server responds with an empty blob */
        outBlobFragment.len = remainingLen > maxFragmentLen? maxFragmentLen : remainingLen; 
        status = ((CCUser *)pUser)->server->smb->doSessionSetupExtended(pUser, &outBlobFragment, inBlob);
        if (status != NQ_SUCCESS && status != NQ_ERR_MOREDATA)
            goto Exit;
        if (remainingLen == outBlobFragment.len)
            break;
        remainingLen -= maxFragmentLen;
        outBlobFragment.data += maxFragmentLen;
    }
    status = NQ_SUCCESS;

Exit:
    return status;
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

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "user:%p", pUser);
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "About to dispose user %s", cmWDump(pUser->item.name));

    if (pServer->masterUser != (CMItem *)pUser)
    {
   	    ccUserLogoff(pUser);
        cmListShutdown(&pUser->shares);
        if (NULL != pUser->credentials)
        {
            cmMemoryFree(pUser->credentials);
            pUser->credentials = NULL;
        }
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
    AMCredentialsW * pCredentials = NULL;  /* credentials allocated */
	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "path:%s", cmWDump(path));

	pCredentials = (AMCredentialsW *)cmMemoryAllocate(sizeof(AMCredentialsW));
	if (NULL == pCredentials)
	{
		sySetLastNqError(NQ_ERR_OUTOFMEMORY);
		goto Exit;
	}
	/* query credentials */
    if (staticData->useAdmin)
    {
         syMemcpy(pCredentials, &staticData->admin, sizeof(AMCredentialsW));
    }
    else
    {
	    pCredentials->domain.realm[0] = 0;
        syMutexTake(&staticData->guard);
	    if (!udGetCredentials(path, pCredentials->user, pCredentials->password, pCredentials->domain.name))
	    {
            syMutexGive(&staticData->guard);
		    LOGERR(CM_TRC_LEVEL_ERROR, "udGetCredentials canceled");
		    sySetLastNqError(NQ_ERR_BADPARAM);
			goto Error;
	    }
        syMutexGive(&staticData->guard);
    }

    cmWStrupr(pCredentials->domain.name);

	LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Domain: %s", cmWDump(pCredentials->domain.name));
	LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "User: %s", cmWDump(pCredentials->user));
	LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Password: xxx");
    goto Exit;

Error:
    cmMemoryFree(pCredentials);
    pCredentials = NULL;

Exit:
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%p", pCredentials);
	return pCredentials;
}

static CCUser * createUser(CCServer * pServer, const AMCredentialsW * pCredentials)
{
	CCUser * pUser;					/* user pointer */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "server:%p credentials:%p", pServer, pCredentials);

	/* create a user and logon to it */
	pUser = (CCUser *)cmListItemCreateAndAdd(&pServer->users, sizeof(CCUser), pCredentials->user, unlockCallback , CM_LISTITEM_LOCK);

	if (NULL == pUser)
	{
		sySetLastNqError(NQ_ERR_OUTOFMEMORY);
		goto Exit;
	}

	pUser->server = pServer;
	pUser->logged = FALSE;
	cmListStart(&pUser->shares);
    pUser->credentials = (AMCredentialsW *)cmMemoryAllocate(sizeof(AMCredentialsW));
	if (NULL == pUser->credentials)
	{
	    cmListItemCheck((CMItem *)pUser);
		sySetLastNqError(NQ_ERR_OUTOFMEMORY);
		pUser = NULL;
		goto Exit;
	}
    syMemcpy(pUser->credentials, pCredentials, sizeof(AMCredentialsW));
    cmListItemAddReference((CMItem *)pUser, (CMItem *)pServer);
    pUser->isAnonymous = cmWStrlen(pUser->credentials->user) == 0;
   	cmU64Zero(&pUser->uid);
	pUser->macSessionKey.data = NULL;
    pUser->sessionKey.data = NULL;
    pUser->isEncrypted = FALSE;
    pUser->isLogginOff = FALSE;
#ifdef UD_NQ_INCLUDESMB3
    pUser->encryptionKey.data = NULL;
    pUser->decryptionKey.data = NULL;
    pUser->applicationKey.data = NULL;
#ifdef UD_NQ_INCLUDESMB311
    pUser->isPreauthIntegOn = FALSE;
#endif /* UD_NQ_INCLUDESMB311 */
#endif /* UD_NQ_INCLUDESMB3 */
   	pUser->isGuest = FALSE;
#if SY_DEBUGMODE
	pUser->item.dump = dumpOne; 
#endif /* SY_DEBUGMODE */

	if (!ccUserLogon(pUser))
	{
        cmListItemUnlock((CMItem *)pUser);
		pUser = NULL;
	}

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%p", pUser);
	return pUser;
}

CCUser * findUser(CCServer * pServer, const AMCredentialsW * pCredentials)
{
    CMIterator iterator;    /* user iterator */
    CCUser * pUser;

    cmListIteratorStart(&pServer->users, &iterator);
    while (cmListIteratorHasNext(&iterator))
    {
        pUser = (CCUser *)cmListIteratorNext(&iterator);
        if (pUser->item.findable &&
        	NULL != pUser->credentials &&
            0 == cmWStrcmp(pCredentials->user, pUser->credentials->user) && 
            0 == cmWStrcmp(pCredentials->domain.name, pUser->credentials->domain.name) && 
            0 == cmWStrcmp(pCredentials->password, pUser->credentials->password) 
            )
        {
            cmListItemLock((CMItem *)pUser);
            goto Exit;
        }
    }
    pUser = NULL;

Exit:
    cmListIteratorTerminate(&iterator);
    return pUser;
}

/* -- API Functions */

NQ_BOOL ccUserStart(void)
{
    NQ_BOOL result = FALSE;

    /* allocate memory */
#ifdef SY_FORCEALLOCATION
    staticData = (StaticData *)cmMemoryAllocate(sizeof(*staticData));
    if (NULL == staticData)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to allocate user data");
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        goto Exit;
    }
#endif /* SY_FORCEALLOCATION */

    syMutexCreate(&staticData->guard);
    staticData->useAdmin = FALSE;
    isInit = TRUE;
	result = TRUE;

Exit:
    return result;
}

void ccUserShutdown(void)
{
	if (TRUE == isInit)
	{
		syMutexDelete(&staticData->guard);
	}

#ifdef SY_FORCEALLOCATION
    if (NULL != staticData)
        cmMemoryFree(staticData);
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
    CCUser * pNextUser;     /* next user pointer */

    ccServerIterateUsers(pServer, &iterator);
    while (cmListIteratorHasNext(&iterator))
    {
        pNextUser = (CCUser *)cmListIteratorNext(&iterator);
        if (0 == cmU64Cmp(&uid, &pNextUser->uid))
        {
        	if (FALSE == pNextUser->item.findable)
        	{
        		pNextUser = NULL;
        	}
            goto Exit;
        }
    }
    pNextUser = NULL;

Exit:
    cmListIteratorTerminate(&iterator);
    return pNextUser;
}

void ccUserIterateShares(CCUser * pUser, CMIterator * iterator)
{
    cmListIteratorStart(&pUser->shares, iterator);
}

NQ_BOOL ccUserUseSignatures(CCUser * pUser)
{
    return !pUser->isAnonymous && !pUser->isGuest;
}

void ccUserSetAdministratorCredentials(const AMCredentialsW * credentials)
{
    if (NULL != credentials)
    {
        staticData->admin = *credentials;
    }
    staticData->useAdmin = NULL != credentials;
}

const AMCredentialsW * ccUserGetAdministratorCredentials()
{
    return staticData->useAdmin ? &staticData->admin : NULL;
}


CCUser * ccUserGet(CCServer * pServer, const NQ_WCHAR * path, const AMCredentialsW ** pCredentials)
{
	CCUser * pUser = NULL;				                    /* user pointer */
    const AMCredentialsW * credentials = * pCredentials;    /* credentials to use */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "server:%p path:%s credentials:%p", pServer, cmWDump(path), pCredentials);

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
            cmListItemUnlock((CMItem *)pUser);
            pUser = NULL;
            goto Exit;
        }
        goto Exit;
    }
    if (NULL != credentials)
    {
        pUser = createUser(pServer, credentials);
        if (NULL != pUser)
        {
            goto Exit;
        }
    }
#endif /* UD_CC_CACHECREDENTIALS */

    credentials = queryCredentials(path);
    if (NULL == credentials)
    {
        sySetLastNqError(NQ_ERR_OUTOFMEMORY);
        pUser = NULL;
        goto Exit;
    }

    pUser = findUser(pServer, credentials);
    if (NULL == pUser || (NULL != pUser && !pUser->logged))
    {
    	if (pUser != NULL)
    		cmListItemUnlock((CMItem *)pUser); /* remove the lock from findUser */
        pUser = createUser(pServer, credentials);
    }

    if (*pCredentials != NULL && !ccUserIsAnonymousCredentials(*pCredentials))
    {
    	syMemcpy(*pCredentials, credentials, sizeof(AMCredentialsW));
    }
	cmMemoryFree(credentials);

Exit:
    cmListItemGive((CMItem *)pServer);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%p", pUser);
	return pUser;
}

void ccUserLogoff(CCUser * pUser)
{
	CMIterator iterator;		/* to enumerate users */
	CCServer * pServer;			/* server pointer */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "user:%p", pUser);

	pServer = pUser->server;

	cmListItemTake(&pServer->item);
	cmListItemTake(&pUser->item);

	if (!pUser->logged || pUser->isLogginOff)
	{
		cmListItemGive(&pUser->item);
		cmListItemGive(&pServer->item);
		goto Exit;
	}
	pUser->isLogginOff = TRUE;

	cmListItemGive(&pUser->item);
	cmListItemGive(&pServer->item);

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
		pUser->isLogginOff = TRUE;
		pServer->smb->doLogOff(pUser);
		pUser->isLogginOff = FALSE;
        pUser->logged = FALSE;
    }
    amSpnegoFreeKey(&pUser->sessionKey);
	amSpnegoFreeKey(&pUser->macSessionKey);
#ifdef UD_NQ_INCLUDESMB3
	cmMemoryFreeBlob(&pUser->encryptionKey);
	cmMemoryFreeBlob(&pUser->decryptionKey);
	cmMemoryFreeBlob(&pUser->applicationKey);
#endif /* UD_NQ_INCLUDESMB3 */

Exit:
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

NQ_BOOL ccUserLogon(CCUser * pUser)
{
	NQ_STATUS status;	        /* SPNEGO status */
	CCServer * pServer;	        /* server pointer */
    NQ_BOOL result = FALSE;     /* return value */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "user:%p", pUser);

    cmListItemTake((CMItem *)pUser);
    if (pUser->logged)
    {
        LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "Logon: user already logged in");
        result = TRUE;
        goto Exit;
    }

	pServer = pUser->server;
#ifdef UD_NQ_INCLUDESMB311
    syMemcpy(pUser->preauthIntegHashVal , pServer->preauthIntegHashVal , SMB3_PREAUTH_INTEG_HASH_LENGTH);
    pUser->isPreauthIntegOn = TRUE; /* hashing process starting. turn on hash flag */
#endif /* UD_NQ_INCLUDESMB311 */
	
    amSpnegoFreeKey(&pUser->sessionKey);       /* in case of reconnect, otherwise - will be NULL */
   	amSpnegoFreeKey(&pUser->macSessionKey);
#ifdef UD_NQ_INCLUDESMB3
	cmMemoryFreeBlob(&pUser->encryptionKey);
	cmMemoryFreeBlob(&pUser->decryptionKey);
	cmMemoryFreeBlob(&pUser->applicationKey);
#endif /* UD_NQ_INCLUDESMB3 */

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
        	pUser->logged = TRUE;
        	if (!pUser->isAnonymous && pServer->firstSecurityBlob.len == 0 && !pUser->isGuest)
        	{
        		result = FALSE;
				goto Exit;
        	}
        	if (pServer->capabilities & CC_CAP_MESSAGESIGNING && nqGetMessageSigning())
        		pServer->useSigning = TRUE;

        }
        if (AM_SPNEGO_SUCCESS == status && NULL != pUser->macSessionKey.data && pUser->macSessionKey.len > pServer->smb->maxSigningKeyLen)
            pUser->macSessionKey.len = pServer->smb->maxSigningKeyLen;  /* restrict bigger keys */

#ifdef UD_NQ_INCLUDESMB311
        if (pServer->smb->revision < SMB3_1_1_DIALECTREVISION)
        /* for revision 3.1.1 key derivation done earlier since we need to verify session setup success packet signature */
#endif
        	pUser->server->smb->keyDerivation(pUser);

#ifdef UD_NQ_INCLUDESMB3
        if (AM_SPNEGO_SUCCESS != status)
        {
            cmMemoryFreeBlob(&pUser->encryptionKey);
            cmMemoryFreeBlob(&pUser->decryptionKey);
            cmMemoryFreeBlob(&pUser->applicationKey);
        }
#endif /* UD_NQ_INCLUDESMB3 */

        LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "Logon: %s", AM_SPNEGO_SUCCESS == status ? "ok" : "failed");
        result = (AM_SPNEGO_SUCCESS == status);
        goto Exit;
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
                sySetLastError(NQ_ERR_BADPARAM);
                goto Exit;
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
				    result = TRUE;
				    goto Exit;
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
                    if (NULL != pUser->macSessionKey.data && pUser->macSessionKey.len > 16)
                        pUser->macSessionKey.len = 16;  /* restict bigger keys */
				    result = TRUE;
				    goto Exit;
			    }
                amSpnegoFreeKey(&pUser->sessionKey);
                amSpnegoFreeKey(&pUser->macSessionKey);
#ifdef UD_NQ_INCLUDESMB3
                cmMemoryFreeBlob(&pUser->encryptionKey);
                cmMemoryFreeBlob(&pUser->decryptionKey);
                cmMemoryFreeBlob(&pUser->applicationKey);
#endif /* UD_NQ_INCLUDESMB3 */

			    sySetLastNqError((NQ_UINT32)status);
		    }
            else
            {
                cmMemoryFreeBlob(&pUser->sessionKey);
                sySetLastNqError(NQ_ERR_LOGONFAILURE);
            }

        }
    }
Exit:
    cmListItemGive((CMItem *)pUser);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result ? "TRUE" : "FALSE");
	return result;
}

NQ_BOOL ccUserReconnectShares(CCUser * pUser)
{
	CMIterator 	iterator;		/* to enumerate users */
	NQ_BOOL		res = FALSE;
	
	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "user:%p", pUser);
	
	cmListIteratorStart(&pUser->shares, &iterator);
	while (cmListIteratorHasNext(&iterator))
	{
		CCShare * pShare;			/* next share pointer */
		
		pShare = (CCShare *)cmListIteratorNext(&iterator);
		res = ccShareConnectExisting(pShare, NULL, TRUE);
		if (res)
		{
			/* if a single file failed to restorer we still return true so other files will continue previous activity */
			ccShareReopenFiles(pShare);
		}
	}
	cmListIteratorTerminate(&iterator);

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", res ? "TRUE" : "FALSE");
	return res;
}

#endif /* UD_NQ_INCLUDECIFSCLIENT */
