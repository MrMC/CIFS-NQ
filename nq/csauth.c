/*********************************************************************
 *
 *           Copyright (c) 2001 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : CIFS pass-through and local authentication
 *--------------------------------------------------------------------
 * DEPENDENCIES  : None
 *--------------------------------------------------------------------
 * CREATION DATE : 24-Aug-2004
 * CREATED BY    : Igor Gokhman
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "cmapi.h"
#include "cmcrypt.h"
#include "cmlist.h"
#include "nsapi.h"
#include "nqapi.h"
#include "cmfinddc.h"
#include "csauth.h"
#include "amspnego.h"
#include "amntlmss.h"
#include "cmlist.h"
#ifdef UD_CS_INCLUDEPASSTHROUGH
#include "ccapi.h"
#include "ccserver.h"
#include "ccuser.h"
#include "ccdomain.h"
#include "ccdcerpc.h"
#include "cclsarpc.h"
#include "ccsamrpc.h"
#endif /*UD_CS_INCLUDEPASSTHROUGH*/

#ifdef UD_NQ_INCLUDECIFSSERVER

/*
    PDC data structure
*/

typedef struct {
    NQ_CHAR name[CM_NQ_HOSTNAMESIZE+1]; /* PDC name for the server domain */
#ifdef UD_CS_INCLUDEPASSTHROUGH
    CCServer * server;                  /* used for communicating CIFS with PDC */
    CCUser user;                        /* dummy user - used only as an UID store */
#endif
    NQ_BOOL connected;                  /* connection flag */
}
Pdc;

/*
    static data declarations
*/

typedef struct
{
    NQ_BYTE buffer[CM_NB_DATAGRAMBUFFERSIZE];
    Pdc pdc;
}
StaticData;

#ifdef SY_FORCEALLOCATION
static StaticData* staticData = NULL;
#else  /* SY_FORCEALLOCATION */
static StaticData staticDataSrc;
static StaticData* staticData = &staticDataSrc;
#endif /* SY_FORCEALLOCATION */

/* This flag enables LM encryption method. */
#define CS_AUTH_ENCRYPTION_LM        1
/* This flag enables NTLM encryption method. */
#define CS_AUTH_ENCRYPTION_NTLM      2
/* This flag enables LMv2 encryption method. */
#define CS_AUTH_ENCRYPTION_LMV2      4
/* This flag enables NTLMv2 encryption method. */
#define CS_AUTH_ENCRYPTION_NTLMV2    8

static NQ_UINT encryptLevel = 	CS_AUTH_ENCRYPTION_LM |
								CS_AUTH_ENCRYPTION_NTLM|
								CS_AUTH_ENCRYPTION_LMV2|
								CS_AUTH_ENCRYPTION_NTLMV2;

typedef struct 
{
    NQ_BOOL hashed;               /* 1 - password is hashed, 0 - plain text */
    NQ_WCHAR unicode[64+1];       /* plain text UNICODE password */
    NQ_BYTE lm[16];               /* hashed LM password */
    NQ_BYTE ntlm[16];             /* hashed NTLM password */
} LocalPassword;

/* key type definition is applied to session key */
#define KEY_LM 1
#define KEY_NTLM 2
#define KEY_NTLMV2 3

/*
    Static functions
    ----------------
 */
#if defined (UD_CS_INCLUDELOCALUSERMANAGEMENT) || defined(UD_CS_MESSAGESIGNINGPOLICY)
/* Generate session key */
static void
generateSessionKey(
    const LocalPassword* in,
    NQ_BYTE* out,
    NQ_INT keyType
    );
#endif

#ifdef UD_CS_MESSAGESIGNINGPOLICY
static void                         /* create context for signing calculation */
createSigningContextSmb(
    CSUser *pUser,                       /* user pointer */
    AMNtlmDescriptor *pDescr             /* NTLM blob descriptor */  
    );
#endif

static NQ_BOOL                      /* check NTLM password */
encryptNTLMv2(
    const NQ_BYTE* key,             /* session key */
    const NQ_BYTE* v2hash,          /* v2 hash */
    const NQ_BYTE* ntlm,            /* NTLM password data in request */
    NQ_INT ntlmlen,                 /* data size */
    CSUser* pUser                   /* user structure */
    );

static NQ_BOOL                      /* check NTLM password */
encryptLMv2(
    const NQ_BYTE* key,             /* session key */
    const NQ_BYTE* v2hash,          /* v2 hash */
    const NQ_BYTE* lm,              /* LM password data in request */
    CSUser* pUser                   /* user structure */
    );
   
static NQ_UINT32                                    /* local status */
authenticateNtlm(
    const CMCifsSessionSetupAndXRequest* pRequest,  /* request pointer */
    NQ_BOOL unicodeRequired,                        /* TRUE when client sends UNICODE strings */
    AMNtlmDescriptor* descr,                        /* NTLM blob descriptor */
    NQ_WCHAR* userName,                             /* buffer for user name */
    const NQ_BYTE** pDomain,                        /* buffer for pointer to the domain name */
    const NQ_BYTE** osName                          /* buffer for pointer to the 1st byte of non-parsed data */
    );


#ifdef UD_CS_INCLUDEEXTENDEDSECURITY
static NQ_UINT32                                    /* local status */
authenticateSpnego(
    const CMCifsSessionSetupAndXRequest * pRequest, /* request pointer */
    CSSession * session,                            /* session structure */ 
    AMNtlmDescriptor * descr,                       /* NTLM blob descriptor */
    NQ_WCHAR * userName,                            /* buffer for user name */
    const NQ_BYTE** pDomain,                        /* buffer for pointer to the domain name */
    const NQ_BYTE ** pSessionKey,                   /* buffer for session key pointer or NULL if none */
    NQ_BYTE* resBlob,                               /* buffer for response blob */
    NQ_COUNT* resBlobLen,                           /* buffer for blob length */                            
    const NQ_BYTE ** osName,                        /* buffer for pointer to the 1st byte of non-parsed data */
    const NQ_BYTE ** inBlob,                        /* buffer for pointer to incoming blob */
    NQ_UINT16* inBlobLength                         /* pointer to incoming blob length */
    );
#endif /* UD_CS_INCLUDEEXTENDEDSECURITY */

static NQ_BOOL                  /* returns TRUE is there is a local user */
isLocalUserOk(
    CSUser* pUser,              /* user structure pointer */
    const NQ_WCHAR* domain,     /* domain name */
    const NQ_WCHAR* user,       /* user name */
    const NQ_BYTE* key,         /* session key */
    AMNtlmDescriptor * pBlob /* incoming blob descriptor */
#ifdef UD_CS_INCLUDEEXTENDEDSECURITY
    ,
    NQ_BOOL  isExtendedSecurity
#endif /* UD_CS_INCLUDEEXTENDEDSECURITY */ 
#ifdef UD_CS_INCLUDESECURITYDESCRIPTORS
    ,
    CMSdRid* userRid            /* buffer for user RID */
#endif /* UD_CS_INCLUDESECURITYDESCRIPTORS */
    );


/*
    actual pass-through authentication implementation
*/

NQ_UINT getCurrentSessionKey(NQ_BYTE ** key, NQ_BYTE **nonce)
{
    CSSession* session = csGetSessionBySocket();     /* session structure */
    if (NULL == session)                             /* malformed command or there was no Negotiate yet */
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unknown session by socket");
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return AM_STATUS_GENERIC;
    }

    *key = session->encryptionKey;
    *nonce = session->sessionNonce;
    return sizeof(session->encryptionKey);
}

/*
 *====================================================================
 * PURPOSE: initialize the pass-through authentication module
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: TRUE if succeeded, FALSE otherwise
 *
 * NOTES:
 *====================================================================
 */
NQ_BOOL
csAuthInit(
    void
    )
{
    TRCB();

    /* allocate memory */
#ifdef SY_FORCEALLOCATION
    staticData = (StaticData *)syMalloc(sizeof(*staticData));
    if (NULL == staticData)
    {
       TRCE();
       return NQ_FAIL;
    }
#endif /* SY_FORCEALLOCATION */

    staticData->pdc.name[0] = '\0';
    staticData->pdc.connected = FALSE;

#ifdef UD_CS_INCLUDEEXTENDEDSECURITY
    amSpnegoServerSetSessionKeyCallback(getCurrentSessionKey);
#endif /* UD_CS_INCLUDEEXTENDEDSECURITY */

    TRC("Initialized with name: %s, %s", cmNetBiosGetDomainAuth()->name, (cmNetBiosGetDomainAuth()->isGroup ? "workgroup" : "domain"));
    TRCE();
    return TRUE;
}

/*
 *====================================================================
 * PURPOSE: shut down the pass-through authentication module
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: NONE
 *
 * NOTES:
 *====================================================================
 */

void
csAuthShutdown(void)
{
    TRCB();

    /* release memory */
#ifdef SY_FORCEALLOCATION
    if (NULL != staticData)
        syFree(staticData);
    staticData = NULL;
#endif /* SY_FORCEALLOCATION */
    TRCE();
}

/*
 *====================================================================
 * PURPOSE: get PDC name
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: pointer to PDC name or NULL
 *
 * NOTES:
 *====================================================================
 */

const NQ_CHAR*
csAuthGetPDCName(
    void
    )
{
    const NQ_CHAR* pResult = NULL;

    if (staticData->pdc.name[0] != '\0' ||
        cmGetDCName(staticData->pdc.name, NULL) == NQ_SUCCESS)
    {
        pResult = staticData->pdc.name;
    }

    return pResult;
}

/*
 *====================================================================
 * PURPOSE: Perform user authentication
 *--------------------------------------------------------------------
 * PARAMS:  IN pointer to the command in the message
 *          IN pointer to the session descriptor
 *          OUT pointer to the blob buffer
 *          OUT pointer to the blob length
 *          IN TRUE when client sends UNICODE strings
 *          OUT place for pointer to user descriptor
 *          OUT place for pointer to domain name in Unicode or ASCII
 *          OUT place for the pointer to OS name
 *
 * RETURNS: error code or NQ_SUCCESS
 *
 * NOTES:   none
 *====================================================================
 */
NQ_UINT32
csAuthenticateUser(
    const NQ_BYTE* pReq,
    CSSession* pSession,
#ifdef UD_CS_INCLUDEEXTENDEDSECURITY
    NQ_BYTE* pBlob,                                 /* place to generate response blob */
    NQ_COUNT* blobLength,                           /* pointer to blob length */
#endif /* UD_CS_INCLUDEEXTENDEDSECURITY */
    NQ_BOOL unicodeRequired,
    CSUser** pUser,
    const NQ_BYTE** pOsName
    )
{
    NQ_STATIC NQ_WCHAR userName[CM_BUFFERLENGTH(NQ_WCHAR, CM_USERNAMELENGTH)];
                                    /* user name converted to TCHAR */
    NQ_STATIC NQ_BYTE passwords[CM_CRYPT_MAX_NTLMV2NTLMSSPRESPONSESIZE];   
                                    /* saved passwords */                                
    AMNtlmDescriptor descr;         /* descriptor of LM/NTLM blobs */
    NQ_INT credentialsLen;          /* lengths of the credentials to save */
#ifdef UD_CS_INCLUDESECURITYDESCRIPTORS
    CMSdRid userRid;                /* RID for user */
#endif /* UD_CS_INCLUDESECURITYDESCRIPTORS */
#if defined(UD_CS_INCLUDESECURITYDESCRIPTORS) && defined(UD_CS_INCLUDEEXTENDEDSECURITY) && defined(UD_CS_INCLUDEPASSTHROUGH)
	CMSdRid groupRid;               /* RID for user group */
#endif /* defined(UD_CS_INCLUDESECURITYDESCRIPTORS) && defined(UD_CS_INCLUDEEXTENDEDSECURITY) && defined(UD_CS_INCLUDEPASSTHROUGH) */
#ifdef UD_CS_INCLUDEEXTENDEDSECURITY
#ifdef UD_CS_INCLUDEPASSTHROUGH                                    
    NQ_STATIC NQ_CHAR domainA[CM_BUFFERLENGTH(NQ_CHAR, CM_NQ_HOSTNAMESIZE)];
    /* buffer for domain name in CHAR */
#endif  
    const NQ_BYTE* pSessionKey = NULL;  /* pointer to session key in session setup auth message */
    const NQ_BYTE* inBlob = NULL;       /* pointer to incoming blob */
    NQ_UINT16 inBlobLength = 0;         /* its length */
#endif /* UD_CS_INCLUDEEXTENDEDSECURITY */
    NQ_STATIC NQ_WCHAR domain[CM_BUFFERLENGTH(NQ_WCHAR, CM_NQ_HOSTNAMESIZE)]; /* buffer for domain name in WCHAR */
    const NQ_BYTE * pDomain = NULL;     /* pointer to domain name in response */
    NQ_UINT32 res = AM_STATUS_GENERIC;  /* local response */
    const CMCifsSessionSetupAndXRequest* pRequest = (const CMCifsSessionSetupAndXRequest*)pReq;

    TRCB();

#if defined(UD_NQ_INCLUDESMB3) && !defined(UD_CS_ALLOW_NONENCRYPTED_ACCESS_TO_ENCRYPTED_SHARE)
    if (csIsServerEncrypted() && pSession->dialect < CS_DIALECT_SMB30)
    {
        /* reject session for SMB1 and SMB2 clients */
        TRCERR("Session rejected because of global encryption");
        TRCE();
        return csErrorReturn(SMB_STATUS_ACCESS_DENIED, DOS_ERRnoaccess);
    }
#endif /* defined(UD_NQ_INCLUDESMB3) && !defined(UD_CS_ALLOW_NONENCRYPTED_ACCESS_TO_ENCRYPTED_SHARE) */

    syMemset(&descr, 0, sizeof(descr));
 
    switch (pSession->dialect)
    {
    case CS_DIALECT_SMB1:
#ifdef UD_CS_INCLUDEEXTENDEDSECURITY
        if (pRequest->wordCount == SMB_SESSIONSETUPANDX_REQUEST_WORDCOUNT)  /* NTLM logon */
        {
#endif /* UD_CS_INCLUDEEXTENDEDSECURITY */
            res = authenticateNtlm(
                    pRequest,
                    unicodeRequired,
                    &descr, 
                    userName,
                    &pDomain, 
                    pOsName
                    ); 
            break;            
#ifdef UD_CS_INCLUDEEXTENDEDSECURITY
        }
#endif /* UD_CS_INCLUDEEXTENDEDSECURITY */
        /* fall through  - if word count is different, SMB1 will use SPNego */
    case CS_DIALECT_SMB2:
    case CS_DIALECT_SMB210:
    case CS_DIALECT_SMB30:
    case CS_DIALECT_SMB311:
    default:
#ifdef UD_CS_INCLUDEEXTENDEDSECURITY    
        res = authenticateSpnego(
                pRequest, 
                pSession,
                &descr, 
                userName,
                &pDomain,
                &pSessionKey,
                pBlob,
                blobLength, 
                pOsName,
                &inBlob,
                &inBlobLength
                ); 
#endif /* UD_CS_INCLUDEEXTENDEDSECURITY */
        break;
    }

   	/* allocate user if not yet */
	if (*pUser == NULL)
	{
		/* find an empty record in the session table */
		*pUser = csGetNewUser(pSession);
		if (*pUser == NULL)
		{
			TRCERR("User table overflow");
			TRCE();
			return csErrorReturn(SMB_STATUS_NO_MEMORY, DOS_ERRnomem);
		}
	}

	if(CM_CRYPT_MAX_NTLMV2NTLMSSPRESPONSESIZE < descr.lmLen + descr.ntlmLen)
	{
		/* we later copy these parameters to passwords[CM_CRYPT_MAX_NTLMV2NTLMSSPRESPONSESIZE]. size has to fit */
		TRCERR("password sizes too long for passwords array. NTLM length: %d, lm length: %d", descr.ntlmLen, descr.lmLen);
		res = AM_STATUS_BAD_FORMAT;
	}

    switch (res)
    {
        case AM_STATUS_AUTHENTICATED:
            TRCE();
            return NQ_SUCCESS;    
        case AM_STATUS_NOT_AUTHENTICATED:         /* NTLM login or ntlmssp auth message (final) */
            res = NQ_SUCCESS;
			break;
#ifdef UD_CS_INCLUDEEXTENDEDSECURITY
        case AM_STATUS_MORE_PROCESSING_REQUIRED:  /* ntlmssp negot */
#endif  /* UD_CS_INCLUDEEXTENDEDSECURITY */ 
            TRCE();
            return csErrorReturn(SMB_STATUS_MORE_PROCESSING_REQUIRED, NQ_ERR_MOREDATA);
        case AM_STATUS_BAD_FORMAT:
        	if (*pUser != NULL)
        		csReleaseUser((*pUser)->uid, FALSE);
            TRCE();
            return csErrorReturn(SMB_STATUS_INVALID_PARAMETER, DOS_ERRbadformat);
        case AM_STATUS_INSUFFICIENT_RESOURCES:
        	if (*pUser != NULL)
        		csReleaseUser((*pUser)->uid, FALSE);
            TRCE();
            return csErrorReturn(SMB_STATUS_INSUFFICIENT_RESOURCES, DOS_ERRnomem);
        case AM_STATUS_GENERIC:
        default:
        	if (*pUser != NULL)
        		csReleaseUser((*pUser)->uid, FALSE);
            TRCE();    
            return csErrorReturn(SMB_STATUS_UNSUCCESSFUL, SRV_ERRerror);
    }

    if (unicodeRequired)
    {
    	syWStrcpy(domain, (NQ_WCHAR*)pDomain);
    }
    else
    {
    	syAnsiToUnicode(domain, (const NQ_CHAR *)pDomain);
    }
   
    TRC("Username: %s", cmWDump(userName));
    TRC("Domain: %s", cmWDump(domain));
    TRC("Own host name: %s", (NQ_CHAR *)cmNetBiosGetHostNameZeroed());

    /* anonymous connection */
    if ((descr.lmLen == 0 || descr.lmLen == 1) && (descr.ntlmLen == 0 || descr.ntlmLen == 1) && 
       ((pSession->dialect > CS_DIALECT_SMB1) ? TRUE : (pRequest->wordCount == SMB_SESSIONSETUPANDXSSP_REQUEST_WORDCOUNT ? TRUE : *(NQ_BYTE*)(pRequest + 1) == 0)))
    {
#ifdef UD_CS_AUTHENTICATEANONYMOUS
    	NQ_INT res;
    	NQ_UINT32 fakeRid;
    	NQ_BOOL fakePassHashed;
    	NQ_CHAR fakePass;
#endif	/* UD_CS_AUTHENTICATEANONYMOUS */
    	CSUser *pAnononymous;

        TRC("anonymous connection");
        
        /* set user */
        syAnsiToUnicode(userName, "ANONYMOUS LOGON");

#ifdef UD_CS_AUTHENTICATEANONYMOUS
        res = udGetPassword(userName, &fakePass, &fakePassHashed, &fakeRid);
        if (res == NQ_CS_PWDNOUSER)
        {
            csReleaseUser((*pUser)->uid, TRUE);
            TRCERR("anonymous connection isn't allowed");
            TRCE();
            return csErrorReturn(SMB_STATUS_LOGON_FAILURE, DOS_ERRnoaccess);
        }
#endif	/* UD_CS_AUTHENTICATEANONYMOUS */

        pAnononymous = csGetUserByNameAndCredentials(userName, NULL, 0);

        if (NULL != pAnononymous && pAnononymous->authenticated)  /* user already authenticated in previous steps */
        {
        	csReleaseUser((*pUser)->uid, TRUE);
         	*pUser = pAnononymous;
            if (pSession->dialect == CS_DIALECT_SMB1)
                pDomain = (NQ_BYTE*)(pRequest + 1) + 1;
            TRCE();
            return NQ_SUCCESS;
        }

        syAnsiToUnicode((*pUser)->name, "anonymous");
        (*pUser)->isAnonymous = TRUE;
        (*pUser)->token.isAnon = TRUE;
#ifdef UD_CS_INCLUDESECURITYDESCRIPTORS
	    (*pUser)->token.rids[0] = CM_SD_RIDALIASGUEST; /* CM_SD_RIDGUEST */
	    (*pUser)->token.numRids = 1;
	    syMemcpy(&(*pUser)->token.domain, cmSdGetComputerSid(), sizeof((*pUser)->token.domain));
#endif /* UD_CS_INCLUDESECURITYDESCRIPTORS */
#ifdef UD_CS_AUTHENTICATEANONYMOUS
        (*pUser)->rid = fakeRid;
#endif	/* UD_CS_AUTHENTICATEANONYMOUS */

#ifdef UD_CS_INCLUDEEXTENDEDSECURITY
        /* for anonymous session key is 0*/
        syMemset((*pUser)->sessionKey, 0, sizeof((*pUser)->sessionKey));
        TRC("Performing local authentication for anonymous");
        if (pSessionKey)  /* client supplied session key */
        {
        	if (descr.flags & NTLMSSP_NEGOTIATE_KEY_EXCH) /* session key should be decrypted*/
        	{
        		TRC("Client supplied encrypted session key");
        		TRCDUMP("encrypted session key (sess setup auth mess)", pSessionKey, 16);
        		cmArcfourCrypt((NQ_BYTE*)pSessionKey, 16, (*pUser)->sessionKey, sizeof((*pUser)->sessionKey));
        	}
        	syMemcpy((*pUser)->sessionKey, pSessionKey, sizeof((*pUser)->sessionKey));
        	TRC("Created session key from local key 0x00 and client session key");
        	TRCDUMP("Final session key for anonymous", (*pUser)->sessionKey, 16);
        }
#endif /* UD_CS_INCLUDEEXTENDEDSECURITY */
#ifdef UD_CS_MESSAGESIGNINGPOLICY
        createSigningContextSmb(*pUser, &descr);
#endif /* UD_CS_MESSAGESIGNINGPOLICY */
        TRCE();
        return NQ_SUCCESS;
	}

	/* save user name, credentials, session key */
    syWStrcpy((*pUser)->name, userName);
	syMemcpy(passwords, descr.pLm, descr.lmLen);
	syMemcpy(passwords + descr.lmLen, descr.pNtlm, descr.ntlmLen);
	credentialsLen = descr.lmLen + descr.ntlmLen;
	if (credentialsLen > (NQ_INT)sizeof((*pUser)->credentials))
	{
	    credentialsLen = sizeof((*pUser)->credentials);
	}
	syMemcpy((*pUser)->credentials, passwords, credentialsLen);
#ifdef UD_CS_INCLUDEEXTENDEDSECURITY
	if (NULL != pSessionKey)
	{
	    syMemcpy((*pUser)->sessionKey, pSessionKey, sizeof((*pUser)->sessionKey));
	}
#endif /* UD_CS_INCLUDEEXTENDEDSECURITY */

	/* find an existing user (SMB1 only) */
	if (pSession->dialect == CS_DIALECT_SMB1)
	{
	    CSUser *pPreviousUser = csGetUserByNameAndCredentials(userName, passwords, credentialsLen);
	    if (NULL != pPreviousUser && pPreviousUser->authenticated)  /* user already authenticated by previous setups */
	    {
	        csReleaseUser((*pUser)->uid, TRUE);
	        *pUser = pPreviousUser;
	        TRC("user already authenticated by previous setups");
	        TRCE();
	        return NQ_SUCCESS;
	    }
	}

	/* try pass through authentication */
#if defined(UD_CS_INCLUDEEXTENDEDSECURITY) && defined(UD_CS_INCLUDEPASSTHROUGH)
	if (unicodeRequired)
	{
	    cmUnicodeToAnsi(domainA, (NQ_WCHAR*)pDomain);   
	}
	else
	{
	    syStrcpy(domainA, (const NQ_CHAR *)pDomain);
	}

	/* get session key from DC if client's domain differs from own host and own host is in domain */
	if (!cmNetBiosGetDomainAuth()->isGroup
	    && (cmAStricmp(cmNetBiosGetHostNameZeroed(), domainA) != 0 && cmAStricmp(cmGetFullHostName(), domainA) != 0)
	    && pSession->usePassthrough)
	{
	    (*pUser)->isDomainUser = TRUE;

            TRC("Passthrough authentication is required");

        if (!udGetComputerSecret(NULL))
        {
            TRCERR("Secret not available (passthrough NetLogon)");
            /* try local authentication */
        }
        else
        {
            NQ_STATIC NQ_WCHAR hostName[CM_BUFFERLENGTH(NQ_WCHAR, CM_NQ_HOSTNAMESIZE)];
            NQ_BYTE *secret;
#ifndef UD_CS_INCLUDESECURITYDESCRIPTORS
            CMSdRid userRid;                /* RID for user */
            CMSdRid groupRid;               /* RID for user group */
#endif /* UD_CS_INCLUDESECURITYDESCRIPTORS */
            NQ_BOOL isExtendedSecurity = pSession->dialect > CS_DIALECT_SMB1;

            udGetComputerSecret(&secret);
            syAnsiToUnicode(hostName, (NQ_CHAR *)cmNetBiosGetHostNameZeroed());

			if (pSession->dialect == CS_DIALECT_SMB1 && pRequest->wordCount == SMB_SESSIONSETUPANDXSSP_REQUEST_WORDCOUNT)
				isExtendedSecurity = TRUE;
					
            TRC("Getting session key from DC (passthrough NetLogon)");
            TRCDUMP("server challenge (encryptionKey)", pSession->encryptionKey, 8);
            TRCDUMP("secret", secret, 16);
            TRC("lmLen %d, ntlmLen %d", descr.lmLen, descr.ntlmLen);

            if (ccNetLogonW(domain,
                            userName,
                            hostName,
                            pSession->encryptionKey, 
                            descr.pLm, 
                            descr.lmLen, 
                            descr.pNtlm, 
                            descr.ntlmLen, 
                            NULL,
                            secret,
                            isExtendedSecurity,
                            (*pUser)->sessionKey,
							&userRid,
							&groupRid) == TRUE)

            {
                TRC("Passthrough (NetLogon) authentication succeeded");
                TRCDUMP("Session key:", (*pUser)->sessionKey, 16);

                if (0 != (descr.flags & NTLMSSP_NEGOTIATE_EXTENDED_SECURITY) && descr.lmLen == 24 && descr.ntlmLen == 24) 
                {
                    TRC("Generating extended security (ntlmv2) session key");
                    cmGenerateExtSecuritySessionKey((*pUser)->sessionKey, pSession->sessionNonce, (*pUser)->sessionKey);                        
                }

                if (pSessionKey)  /* client supplied session key */
                {
                    if (descr.flags & NTLMSSP_NEGOTIATE_KEY_EXCH) /* session key should be decrypted*/
                    {
                        TRC("Client supplied encrypted session key");
                        TRCDUMP("encrypted session key (sess setup auth mess)", pSessionKey, 16);
                        cmArcfourCrypt((NQ_BYTE*)pSessionKey, 16, (*pUser)->sessionKey, sizeof((*pUser)->sessionKey));
                    }
                    syMemcpy((*pUser)->sessionKey, pSessionKey, sizeof((*pUser)->sessionKey));
                }
                TRCDUMP("Session key (final)", (*pUser)->sessionKey, 16);
                (*pUser)->isExtendSecAuth = isExtendedSecurity;
                (*pUser)->authBySamlogon = TRUE;
                descr.isNtlmAuthenticated = TRUE;
#ifdef UD_CS_INCLUDESECURITYDESCRIPTORS
				TRC("userRid:%d, groupRid:%d", userRid, groupRid);
				(*pUser)->token.rids[0] = userRid;
				(*pUser)->token.rids[1] = groupRid;
				(*pUser)->token.numRids = 2;
#endif /* UD_CS_INCLUDESECURITYDESCRIPTORS */
#ifdef UD_CS_MESSAGESIGNINGPOLICY
                createSigningContextSmb(*pUser, &descr);
#endif /* UD_CS_MESSAGESIGNINGPOLICY */
                TRCE();
                return NQ_SUCCESS;
            }
            else
            {
                TRCERR("Passthrough (NetLogon) authentication failed");
                /* try local authentication */
            }
        }
    }
#endif /* defined(UD_CS_INCLUDEEXTENDEDSECURITY) && defined(UD_CS_INCLUDEPASSTHROUGH) */
   
    TRC("Performing local authentication");

#ifdef UD_CS_INCLUDESECURITYDESCRIPTORS
    /* if user will be locally authenticated this value will be > 0 */
    (*pUser)->token.numRids = 0;
#endif /* UD_CS_INCLUDESECURITYDESCRIPTORS */
    (*pUser)->isDomainUser = FALSE;

    if (isLocalUserOk(
            *pUser,
            domain,
            userName,
            pSession->encryptionKey,
            &descr
#ifdef UD_CS_INCLUDEEXTENDEDSECURITY
            ,
            pRequest->wordCount == SMB_SESSIONSETUPANDXSSP_REQUEST_WORDCOUNT
#endif /* UD_CS_INCLUDEEXTENDEDSECURITY */           
#ifdef UD_CS_INCLUDESECURITYDESCRIPTORS
            ,
            &userRid
#endif /* UD_CS_INCLUDESECURITYDESCRIPTORS */
            )
        )
    {
        if ((*pUser)->isGuest)
        {
            TRCE();
            return NQ_SUCCESS;
        }

#ifdef UD_CS_INCLUDEEXTENDEDSECURITY
        if (NULL != pSessionKey)
        {
            if (descr.flags & NTLMSSP_NEGOTIATE_KEY_EXCH) /* client supplied encrypted session key */
            {
                cmArcfourCrypt((NQ_BYTE*)pSessionKey, 16, (*pUser)->sessionKey, sizeof((*pUser)->sessionKey));
            }
            syMemcpy((*pUser)->sessionKey, pSessionKey, sizeof((*pUser)->sessionKey));
        }     
#endif /* UD_CS_INCLUDEEXTENDEDSECURITY */
#ifdef UD_CS_MESSAGESIGNINGPOLICY
        createSigningContextSmb(*pUser, &descr);
#endif /* UD_CS_MESSAGESIGNINGPOLICY */
    }
    else
    {
#ifdef UD_NQ_INCLUDEEVENTLOG
    	UDUserAccessEvent	eventInfo;
#endif /* UD_NQ_INCLUDEEVENTLOG */
        TRCERR("Local authentication failed");
#ifdef UD_NQ_INCLUDEEVENTLOG
    	eventInfo.rid = csGetUserRid((*pUser));
		udEventLog(UD_LOG_MODULE_CS,
				   UD_LOG_CLASS_USER,
				   UD_LOG_USER_LOGON,
				   (*pUser)->name,
				   (*pUser)->ip,
				   csErrorReturn(SMB_STATUS_LOGON_FAILURE, DOS_ERRnoaccess),
				   (const NQ_BYTE *)&eventInfo);
#endif /* UD_NQ_INCLUDEEVENTLOG */
		csReleaseUser((*pUser)->uid, TRUE);
        TRCE();
        return csErrorReturn(SMB_STATUS_LOGON_FAILURE, DOS_ERRnoaccess);
    }

#ifdef UD_CS_INCLUDESECURITYDESCRIPTORS
    (*pUser)->token.numRids = 2;
    (*pUser)->token.rids[0] = userRid;
    (*pUser)->token.rids[1] = CM_SD_RIDALIASUSER;

    if (cmSdIsAdmin(userRid))         /* administrator */
    {
        (*pUser)->token.numRids = 4;
        (*pUser)->token.rids[2] = CM_SD_RIDGROUPADMINS;
        (*pUser)->token.rids[3] = CM_SD_RIDALIASADMIN;
    }
	syMemcpy(&(*pUser)->token.domain, cmSdGetComputerSid(), sizeof((*pUser)->token.domain));
#endif /* UD_CS_INCLUDESECURITYDESCRIPTORS */

#ifdef UD_NQ_INCLUDESMB3
    (*pUser)->isEncrypted = csIsServerEncrypted();
#endif /* UD_NQ_INCLUDESMB3 */

    TRCE();
    return NQ_SUCCESS;
}

/*
 *====================================================================
 * PURPOSE: Perform local user authentication
 *--------------------------------------------------------------------
 * PARAMS:  IN pointer to the domain name
 *          IN pointer to the user name
 *          IN pointer to the encryption key
 *          IN pointer to the LM password
 *          IN pointer to the incoming blob
 *          IN TRUE for extended security 
 *          OUT buffer for user RID
 *
 * RETURNS: TRUE if authenticated, FALSE otherwise
 *
 * NOTES:   If there is no user list or it has no records - we treat
 *          this as automatic authentication and allow any access by
 *          any user
 *====================================================================
 */

static
NQ_BOOL
isLocalUserOk(
    CSUser* pUser,
    const NQ_WCHAR* domain,
    const NQ_WCHAR* user,
    const NQ_BYTE* key,
    AMNtlmDescriptor * pBlob
#ifdef UD_CS_INCLUDEEXTENDEDSECURITY
    ,
    NQ_BOOL  isExtendedSecurity
#endif /* UD_CS_INCLUDEEXTENDEDSECURITY */    
#ifdef UD_CS_INCLUDESECURITYDESCRIPTORS
    ,
    CMSdRid* userRid
#endif /* UD_CS_INCLUDESECURITYDESCRIPTORS */
    )
{
    NQ_STATIC LocalPassword password;
    NQ_STATIC NQ_BYTE encrypted[24];
    NQ_STATIC NQ_BYTE v2hash[16];
    NQ_STATIC NQ_CHAR buffer[64+1];
#ifndef UD_CS_INCLUDESECURITYDESCRIPTORS
    NQ_UINT32 userRid[1];                   /* dummy for user RID */
#endif /* UD_CS_INCLUDESECURITYDESCRIPTORS */
    const NQ_WCHAR zeroWStr[] = {0,0};
    NQ_UINT16 enclen = 0;
#if (defined(UD_CS_INCLUDELOCALUSERMANAGEMENT) || defined(UD_CS_MESSAGESIGNINGPOLICY)) && defined(UD_CS_INCLUDEEXTENDEDSECURITY)
    CSSession* session;                     /* session structure */      
#endif

    TRCB();

#ifdef UD_CS_INCLUDEEXTENDEDSECURITY
    pUser->isExtendSecAuth = isExtendedSecurity;
#endif
        
    switch (udGetPassword(user, buffer, &password.hashed, userRid))
    {
        case NQ_CS_PWDNOAUTH:
            pUser->isGuest = TRUE;
            pUser->rid = *userRid;
	        TRC("No authentication required");
            TRCE();
            return TRUE;        /* automatic authentication when there is no user list */

        case NQ_CS_PWDNOUSER:
            TRCERR("Unknown user");
            pUser->rid = CS_ILLEGALID;
            TRC1P("  user name: %s", cmWDump(user));
            break;

        case NQ_CS_PWDANY:
        {
            /* both LM and NTML passwords present */
           	pUser->rid = *userRid;
            if (password.hashed)
            {
                syMemcpy(password.lm, buffer, 16);
                syMemcpy(password.ntlm, buffer + 16, 16);
            }
            else
            {
                cmHashPassword((NQ_BYTE *)buffer, password.lm);
                cmAnsiToUnicode(password.unicode, buffer);
                cmMD4(password.ntlm, (NQ_BYTE*)password.unicode, (NQ_UINT)(cmWStrlen(password.unicode) * sizeof(NQ_WCHAR)));
            }

            if (pBlob->ntlmLen > 0)
            {
            	if (encryptLevel & CS_AUTH_ENCRYPTION_NTLMV2 || encryptLevel & CS_AUTH_ENCRYPTION_NTLM )
                {
            		TRC("trying NTLM");

            		/* check NTLM password */
            		cmEncryptNTLMPassword(key, password.ntlm, encrypted, &enclen);
                }
                if (encryptLevel & CS_AUTH_ENCRYPTION_NTLM)
                {
					if (pBlob->ntlmLen == enclen && syMemcmp(pBlob->pNtlm, encrypted, enclen) == 0)
					{
#if defined (UD_CS_INCLUDELOCALUSERMANAGEMENT) || defined(UD_CS_MESSAGESIGNINGPOLICY)                
						generateSessionKey(&password, pUser->sessionKey, KEY_NTLM);
#ifdef UD_CS_INCLUDEEXTENDEDSECURITY
						if ((session = csGetSessionBySocket()) == NULL)
						{
							TRCERR("Unknown session by socket");
							TRCE();
							return FALSE;
						}
						if ((isExtendedSecurity && (pBlob->flags & NTLMSSP_NEGOTIATE_EXTENDED_SECURITY)) || session->dialect != CS_DIALECT_SMB1)
						{
							cmGenerateExtSecuritySessionKey(pUser->sessionKey, session->sessionNonce, pUser->sessionKey);
						}
#endif /* UD_CS_INCLUDEEXTENDEDSECURITY */    
#endif /* defined (UD_CS_INCLUDELOCALUSERMANAGEMENT) || defined(UD_CS_MESSAGESIGNINGPOLICY) */
						pBlob->isNtlmAuthenticated = TRUE;
						TRC("NTLM passwords match");
						TRCE();
						return TRUE;
                    }
                }

                if (encryptLevel & CS_AUTH_ENCRYPTION_NTLMV2)
                {
					TRC("trying NTLMv2 (csd)");

					/* check NTLMv2 passwords */
					cmCreateV2Hash(domain, TRUE, user, password.ntlm, sizeof(password.ntlm), v2hash);
					if (encryptNTLMv2(key, v2hash, pBlob->pNtlm, pBlob->ntlmLen, pUser))
					{
						pBlob->isNtlmAuthenticated = TRUE;
						TRC(" NTLMv2 (csd) passwords match");
						TRCE();
						return TRUE;
					}

					TRC("trying NTLMv2");

					/* check NTLMv2 passwords */
					cmCreateV2Hash(domain, FALSE, user, password.ntlm, sizeof(password.ntlm), v2hash);
					if (encryptNTLMv2(key, v2hash, pBlob->pNtlm, pBlob->ntlmLen, pUser))
					{
						pBlob->isNtlmAuthenticated = TRUE;
						TRC(" NTLMv2 passwords match");
						TRCE();
						return TRUE;
					}

					TRC("trying NTLMv2 - null domain");

					/* check NTLMv2 passwords */
					cmCreateV2Hash(zeroWStr, FALSE, user, password.ntlm, sizeof(password.ntlm), v2hash);
					if (encryptNTLMv2(key, v2hash, pBlob->pNtlm, pBlob->ntlmLen, pUser))
					{
						pBlob->isNtlmAuthenticated = TRUE;
						TRC(" NTLMv2 null domain passwords match");
						TRCE();
						return TRUE;
                    }
                }
            }
            if (pBlob->lmLen > 0)
            {
            	if (encryptLevel & CS_AUTH_ENCRYPTION_LMV2)
            	{
					TRC("trying LMv2 (csd)");

					/* check LMv2 passwords with case sensitive domain */
					cmCreateV2Hash(domain, TRUE, user, password.ntlm, sizeof(password.ntlm), v2hash);
					if (encryptLMv2(key, v2hash, pBlob->pLm, pUser))
					{
						pBlob->isLmAuthenticated = TRUE;
						TRC(" LMv2 (csd) passwords match");
						TRCE();
						return TRUE;
					}

					TRC("trying LMv2");

					/* check LMv2 passwords */
					cmCreateV2Hash(domain, FALSE, user, password.ntlm, sizeof(password.ntlm), v2hash);
					if (encryptLMv2(key, v2hash, pBlob->pLm, pUser))
					{
						pBlob->isLmAuthenticated = TRUE;
						TRC(" LMv2 passwords match");
						TRCE();
						return TRUE;
					}

					TRC("trying LMv2 - null domain");

					/* check LMv2 passwords */
					cmCreateV2Hash(zeroWStr, FALSE, user, password.ntlm, sizeof(password.ntlm), v2hash);
					if (encryptLMv2(key, v2hash, pBlob->pLm, pUser))
					{
						pBlob->isLmAuthenticated = TRUE;
						TRC(" LMv2 null domain passwords match");
						TRCE();
						return TRUE;
                    }
            	}
            }
        }
        /* continue to the next case */
        case NQ_CS_PWDLMHASH: /* only LM password presents */
        default:
        	pUser->rid = *userRid;
            if (pBlob->lmLen > 0)
            {
                if (password.hashed)
                    syMemcpy(password.lm, buffer, 16);
                else
                    cmHashPassword((NQ_BYTE *)buffer, password.lm);

                TRC("trying LM");
                if (encryptLevel & CS_AUTH_ENCRYPTION_LM)
                {
					cmEncryptLMPassword(key, password.lm, encrypted, &enclen);

					if(pBlob->lmLen == enclen && syMemcmp(pBlob->pLm, encrypted, enclen) == 0)
					{
#if defined (UD_CS_INCLUDELOCALUSERMANAGEMENT) || defined(UD_CS_MESSAGESIGNINGPOLICY)               
						generateSessionKey(&password, pUser->sessionKey, KEY_LM);
#endif /* defined (UD_CS_INCLUDELOCALUSERMANAGEMENT) || defined(UD_CS_MESSAGESIGNINGPOLICY) */                  
						pBlob->isLmAuthenticated = TRUE;
						TRC("LM passwords match");
						TRCE();
						return TRUE;
					}
                }
            }
    }

    TRCE();
    return FALSE;
}

#if defined (UD_CS_INCLUDELOCALUSERMANAGEMENT) || defined(UD_CS_MESSAGESIGNINGPOLICY)

/*
 *====================================================================
 * PURPOSE: Generate session key
 *--------------------------------------------------------------------
 * PARAMS:  IN 16 byte hash
 *          OUT buffer for session key
 *          IN key type as LM or NTLM
 *
 * RETURNS: None
 *
 * NOTES:
 *====================================================================
 */

static void
generateSessionKey(
    const LocalPassword* in,
    NQ_BYTE* out,
    NQ_INT keyType
    )
{
    TRCB();
    switch (keyType)
    {
        case KEY_LM:
            TRC("Generated LM session key");
            syMemset(out, 0, SMB_SESSIONKEY_LENGTH);
            syMemcpy(out, in->lm, 8);
            break;
        case KEY_NTLM:
        default:
            TRC("Generated NTLM session key");
            cmMD4(out, (NQ_BYTE*)in->ntlm, SMB_SESSIONKEY_LENGTH);
            break;
    }
    TRCE();
}

#endif

/*
 *====================================================================
 * PURPOSE: check NTLM password
 *--------------------------------------------------------------------
 * PARAMS:  IN session key
 *          IN generated v2 hash
 *          IN NTLM password data in the request
 *          IN data size
 *          IN pointer to user structure
 *
 * RETURNS: TRUE if match, FALSE if not
 *
 * NOTES:
 *====================================================================
 */

static NQ_BOOL
encryptNTLMv2(
    const NQ_BYTE* key,
    const NQ_BYTE* v2hash,
    const NQ_BYTE* ntlm,
    NQ_INT ntlmlen,
    CSUser* pUser
    )
{
    NQ_STATIC NQ_BYTE encrypted[24];
    NQ_UINT16 enclen = 0;

    cmEncryptNTLMv2Password(key, v2hash, ntlm + CM_CRYPT_ENCLMv2HMACSIZE, (NQ_UINT16)(ntlmlen - CM_CRYPT_ENCLMv2HMACSIZE), encrypted, &enclen);
    if (syMemcmp(ntlm, encrypted, enclen) == 0)
    {
#if defined(UD_CS_INCLUDELOCALUSERMANAGEMENT) || defined(UD_CS_MESSAGESIGNINGPOLICY)
        cmGenerateExtSecuritySessionKey(v2hash, encrypted, pUser->sessionKey);
#endif /* defined(UD_CS_INCLUDELOCALUSERMANAGEMENT) || defined(UD_CS_MESSAGESIGNINGPOLICY) */
        return TRUE;
    }
    return FALSE;
}

/*
 *====================================================================
 * PURPOSE: check NTLM password
 *--------------------------------------------------------------------
 * PARAMS:  IN session key
 *          IN generated v2 hash
 *          IN LM password data in the request
 *          IN pointer to user structure
 *
 * RETURNS: TRUE if match, FALSE if not
 *
 * NOTES:
 *====================================================================
 */

static NQ_BOOL
encryptLMv2(
    const NQ_BYTE* key,
    const NQ_BYTE* v2hash,
    const NQ_BYTE* lm,
    CSUser* pUser
    )
{
    NQ_STATIC NQ_BYTE encrypted[24];
    NQ_UINT16 enclen = 0;

    cmEncryptNTLMv2Password(key, v2hash, lm + CM_CRYPT_ENCLMv2HMACSIZE, 8, encrypted, &enclen);
    if (syMemcmp(lm, encrypted, enclen) == 0)
    {
#if defined(UD_CS_INCLUDELOCALUSERMANAGEMENT) || defined(UD_CS_MESSAGESIGNINGPOLICY)
        cmGenerateExtSecuritySessionKey(v2hash, encrypted, pUser->sessionKey);
#endif /* defined(UD_CS_INCLUDELOCALUSERMANAGEMENT) || defined(UD_CS_MESSAGESIGNINGPOLICY) */
        return TRUE;
    }
    return FALSE;
}


/*
 *====================================================================
 * PURPOSE: Parse SPNEGO Session Setup request
 *--------------------------------------------------------------------
 * PARAMS:  IN pointer to the request
 *          IN TRUE when Unicode desired
 *          OUT populate this structure with blob pointers and sizes  
 *          OUT buffer for user name
 *          OUT buffer for domain name pointer
 *          OUT buffer for pointer to the 1st byte after parsed data
 *
 * RETURNS: status, including:
 *      AM_STATUS_NOT_AUTHENTICATED         - was parsed but not authenticated yet
 *      <any other>                         - parse error
 *
 * NOTES:   
 *====================================================================
 */
static NQ_UINT32 authenticateNtlm(
    const CMCifsSessionSetupAndXRequest * pRequest,  
    NQ_BOOL unicodeRequired,                
    AMNtlmDescriptor * descr,
    NQ_WCHAR * userName,
    const NQ_BYTE ** pDomain,   
    const NQ_BYTE ** pOsName                              
    )
{
    NQ_CHAR * pName;             /* pointer to the account name in the message */

    TRCB();
    
    descr->lmLen = cmLtoh16(cmGetSUint16(pRequest->caseInsensitivePasswordLength));
    descr->ntlmLen = cmLtoh16(cmGetSUint16(pRequest->caseSensitivePasswordLength));
    descr->pLm = (NQ_BYTE*)pRequest + sizeof(*pRequest);
    descr->pNtlm = descr->pLm + descr->lmLen;

    pName = (NQ_CHAR*)(descr->pNtlm + descr->ntlmLen);
    if (unicodeRequired)
    {
        /* UNICODE string padding (skip 1 byte) */
        pName = (NQ_CHAR*)cmAllignTwo(pName);
        syWStrcpy(userName, (NQ_WCHAR*)pName);
        *pDomain = (NQ_BYTE*)(pName + (cmWStrlen((NQ_WCHAR*)pName) + 1)*sizeof(NQ_WCHAR));
        *pOsName = (NQ_BYTE*)(*pDomain + (cmWStrlen((NQ_WCHAR*)*pDomain) + 1)*sizeof(NQ_WCHAR));
    }
    else
    {
    	syAnsiToUnicode(userName, pName);
        /* the next works only if the user name is always in UNICODE */
        *pDomain = (NQ_BYTE*)(pName + (syWStrlen(userName) + 1)*sizeof(NQ_CHAR));
        *pOsName = (NQ_BYTE*)(*pDomain + (syStrlen((NQ_CHAR*)*pDomain) + 1)*sizeof(NQ_CHAR));
    }

    TRCE();
    return AM_STATUS_NOT_AUTHENTICATED;
}

#ifdef UD_CS_INCLUDEEXTENDEDSECURITY

/*
 *====================================================================
 * PURPOSE: Parse SPNEGO Session Setup request
 *--------------------------------------------------------------------
 * PARAMS:  IN pointer to the request
 *          IN/OUT session structure
 *          OUT populate this structure with blob pointers and sizes
 *          OUT buffer for user name
 *          OUT buffer for domain name pointer
 *          OUT buffer for pointer to session key or NULL if none
 *          OUT buffer for response blob
 *          OUT buffer for response blob length
 *          OUT buffer for pointer to the 1st byte after parsed data
 *
 * RETURNS: status, including:
 *      AM_STATUS_AUTHENTICATED            - was authenticated
 *      AM_STATUS_NOT_AUTHENTICATED        - was parsed but not authenticated yet
 *      AM_STATUS_MORE_PROCESSING_REQUIRED - was recognized but requires more exchange
 *      <any other>                        - parse error
 *
 * NOTES:   
 *====================================================================
 */

static NQ_UINT32                                   
authenticateSpnego(
    const CMCifsSessionSetupAndXRequest * pRequest, 
    CSSession * session,                           
    AMNtlmDescriptor * descr,
    NQ_WCHAR * userName,
    const NQ_BYTE** pDomain,                       
    const NQ_BYTE ** pSessionKey,
    NQ_BYTE * resBlob,                              
    NQ_COUNT * resBlobLen,                            
    const NQ_BYTE ** pOsName,
    const NQ_BYTE ** inBlob,
    NQ_UINT16 * inBlobLength
    )
{
    const CMCifsSessionSetupAndXSSPRequest* pSpnego;
    NQ_UINT32 result;
    CMBlob spnegoIn;
    CMBlob spnegoOut;
    NQ_STATIC NQ_WCHAR domainName[CM_BUFFERLENGTH(NQ_WCHAR, CM_USERNAMELENGTH)];

    TRCB();

    if (session->dialect != CS_DIALECT_SMB1)
    {
        *inBlob = (const NQ_BYTE*)pRequest;
        *inBlobLength = cmLtoh16(cmGetSUint16(*((NQ_SUINT16 *)(*inBlob - 10))));
    }
    else
    {
        pSpnego = (const CMCifsSessionSetupAndXSSPRequest*)pRequest;
        *pOsName = (NQ_BYTE*)(pSpnego + 1) + cmLtoh16(cmGetSUint16(pSpnego->blobLength));
        *pOsName = cmAllignTwo(*pOsName);
        *inBlob = (const NQ_BYTE*)(pSpnego + 1);
        *inBlobLength = cmLtoh16(cmGetSUint16(pSpnego->blobLength));
    }

    TRC("blob length = %d", *inBlobLength);
    spnegoIn.data = (NQ_BYTE *)*inBlob;
    spnegoIn.len = *inBlobLength;
    spnegoOut.data = resBlob;
        
    result = amSpnegoServerAcceptBlobW(
        &session->securityMech,
        &spnegoIn,
        &spnegoOut, 
        userName,
        (const NQ_WCHAR **)pDomain,
        pSessionKey,
        descr
        );
    if (NULL != *pDomain)
    {
        cmWStrcpy(domainName, (const NQ_WCHAR *)(*pDomain));
        cmMemoryFree(*pDomain);
        *pDomain = (const NQ_BYTE *)domainName;
    }
	*resBlobLen = spnegoOut.len;

    TRCE();    
    return result;    
}

#endif /* UD_CS_INCLUDEEXTENDEDSECURITY */

#ifdef UD_CS_INCLUDESECURITYDESCRIPTORS
/*
*====================================================================
* PURPOSE: Perform local user authentication
*--------------------------------------------------------------------
* PARAMS:  IN/OUT pointer to the user structure
*          IN pointer to the domain name
*          IN TRUE if client sent information in UNICODE
*
* RETURNS: TRUE if authenticated, FALSE otherwise
*
* NOTES:   If there is no user list or it has no records - we treat
*          this as automatic authentication and allow any access by
*          any user
*====================================================================
*/

NQ_BOOL                         /* TRUE if succeeded */
csFillUserToken(
CSUser* pUser,              /* pointer to the user structure */
NQ_BOOL unicodeRequired     /* TRUE when client sends UNICODE strings */
)
{
#ifdef UD_CS_INCLUDEPASSTHROUGH
	const NQ_CHAR* hostDomain;                /* pointer to the current domain */
	NQ_STATIC NQ_WCHAR domainW[CM_BUFFERLENGTH(NQ_WCHAR, CM_NQ_HOSTNAMESIZE)];
	/* buffer for client domain name in TCHAR */
	NQ_STATIC NQ_WCHAR pdcNameW[CM_BUFFERLENGTH(NQ_WCHAR, CM_NQ_HOSTNAMESIZE)];
	/* buffer for PDC name in TCHAR */
	const NQ_CHAR* pdcName;             /* pointer to PDC name in CHAR */
	NQ_HANDLE lsa;                      /* pipe handle for LSA */
	NQ_HANDLE sam;                      /* pipe handle for SAMR */
	NQ_STATUS status;                   /* operation status */
#endif /* UD_CS_INCLUDEPASSTHROUGH */

	TRCB();

	if (pUser->isAnonymous)
	{
		pUser->token.numRids = 1;
		pUser->token.rids[0] = CM_SD_RIDALIASGUEST;  /* will match everyone */
	}
	if (pUser->token.numRids > 0)   /* locally authenticated or anonymous */
	{
		syMemcpy(&pUser->token.domain, cmSdGetComputerSid(), sizeof(pUser->token.domain));
		TRCE();
		return TRUE;
	}

#ifdef UD_CS_INCLUDEPASSTHROUGH
		pdcName = csAuthGetPDCName();
		if (NULL == pdcName)
		{
			TRCERR("Pass through authentication is not initialized yet");
			TRCE();
			return FALSE;
		}
		cmAnsiToUnicode(pdcNameW, pdcName);



	hostDomain = cmGetFullDomainName();
	if (hostDomain == NULL)
		hostDomain = cmNetBiosGetDomainAuth()->name;
	cmAnsiToUnicode(domainW, hostDomain);
	lsa = ccDcerpcConnect(pdcNameW, NULL, ccLsaGetPipe(), FALSE);
	if (NULL == lsa)
	{
		TRCERR("Unable to open LSA on PDC");
		TRCE();
		return FALSE;
	}
	status = ccLsaGetUserToken(lsa, pUser->name, domainW, &pUser->token);
	ccDcerpcDisconnect(lsa);
	sam = ccDcerpcConnect(pdcNameW, NULL, ccSamGetPipe(), FALSE);
	if (NULL == sam)
	{
		TRCERR("Unable to open SAMR on PDC");
		TRCE();
		return FALSE;
	}
	status = ccSamGetUserGroups(sam, pUser->name, domainW, &pUser->token);
	ccDcerpcDisconnect(sam);

	/* add appropriate "well known" rids for this user. This section is a
	* matter for further modifications */
	if (pUser->token.numRids < sizeof(pUser->token.rids) / sizeof(pUser->token.rids[0]))
	{
		pUser->token.rids[pUser->token.numRids] = CM_SD_RIDALIASUSER;
		pUser->token.numRids++;
	}

	TRCE();
	return NQ_SUCCESS == status;
#else /* UD_CS_INCLUDEPASSTHROUGH */
	return FALSE;
#endif /* UD_CS_INCLUDEPASSTHROUGH */
}
#endif /*  UD_CS_INCLUDESECURITYDESCRIPTORS */


#ifdef UD_CS_MESSAGESIGNINGPOLICY
/*
 *====================================================================
 * PURPOSE: Create context for message signing
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT pointer user structure
 *          IN     pointer NTLM blob descriptor
 *
 * RETURNS: none
 *
 * NOTES:   none
 *====================================================================
 */

static 
void
createSigningContextSmb(
    CSUser *pUser,    
    AMNtlmDescriptor * pDescr     
    )
{    
    CSSession *pSession;
    NQ_BYTE *password;
    NQ_COUNT passwordLen;

    TRCB();
    
    if (pUser != NULL && (pSession = csGetSessionById(pUser->session)) != NULL  && pSession->signingOn && pSession->dialect == CS_DIALECT_SMB1)
    {
#ifdef UD_CS_INCLUDEEXTENDEDSECURITY
        if (pUser->isExtendSecAuth)
        {
            password = NULL;
            passwordLen = 0;
            TRC("extended security authentication");
        }
        else
#endif  /* UD_CS_INCLUDEEXTENDEDSECURITY */            
        {
            password = (NQ_BYTE *)(pDescr->isLmAuthenticated ? pDescr->pLm : (pDescr->isNtlmAuthenticated ? pDescr->pNtlm : NULL));
            passwordLen = (NQ_COUNT)(pDescr->isLmAuthenticated ? pDescr->lmLen : (pDescr->isNtlmAuthenticated ? pDescr->ntlmLen : 0));
            TRC("authenticated by %s", pDescr->isLmAuthenticated ? "LM" : "NTLM");
        }           
        
        /* on first "real" logged in user save session key for signing throughout the whole session */
        if (pSession->isBsrspyl)
        {
            pSession->isBsrspyl = FALSE;
            syMemcpy(pSession->sessionKey, pUser->sessionKey, sizeof(pUser->sessionKey));
            TRCDUMP("session key", pSession->sessionKey, sizeof(pUser->sessionKey));
        }
        
		if (password != NULL)
		{
			pUser->password.data = (NQ_BYTE *)cmMemoryAllocate(passwordLen);
			pUser->password.len = passwordLen;
			syMemcpy(pUser->password.data , password , passwordLen);
		}
    }

    TRCE();
}
#endif /* UD_CS_MESSAGESIGNINGPOLICY */

NQ_BOOL
csChangeEncryptionLevel(
		NQ_UINT mask
		)
{
	encryptLevel = mask;
	return TRUE;
}

#endif /* UD_NQ_INCLUDECIFSSERVER */

