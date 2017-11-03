/*********************************************************************
 *
 *           Copyright (c) 2009 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : CIFS Client domain related operations
 *--------------------------------------------------------------------
 * MODULE        : CC
 * DEPENDENCIES  : None
 *--------------------------------------------------------------------
 * CREATION DATE : 14-Jul-2009
 ********************************************************************/

#include "nqapi.h"
#include "ccdomain.h"

#include "cmsdescr.h"
#include "cmfinddc.h"

#include "ccparams.h"
#include "cclsarpc.h"
#include "ccsamrpc.h"
#include "ccnetlgn.h"
#include "ccuser.h"
#include "ccerrors.h"
#include "cmcrypt.h"
#include "cmbuf.h"

#ifdef UD_CC_INCLUDEDOMAINMEMBERSHIP

#define MAX_USER_NAME_LENGTH            DOMAIN_LENGTH
#define MAX_DOMAIN_NAME_LENGTH          DOMAIN_LENGTH
#define MAX_PLAIN_PASSWORD_LENGTH       PASSWORD_LENGTH
#define LM_HASH_SIZE                    HASHED_PASSWORD_SIZE
#define NTLM_HASH_SIZE                  HASHED_PASSWORD_SIZE
#define COMP_ACCOUNT_PASSWORD_LENGTH    14


/* 0xe00500b0 */
#define SAMR_CREATE_USER_DEFAULT_ACCESS     (SAMR_AM_GENERICREAD | SAMR_AM_GENERICWRITE | SAMR_AM_GENERICEXECUTE | \
                                            SAMR_AM_WRITEDAC | SAMR_AM_DELETE | \
                                            SAMR_AM_USERSETPASSWORD | SAMR_AM_USERGETATTRIBUTES | SAMR_AM_USERSETATTRIBUTES)

/* -- Static prototypes --- */

static NQ_UINT32 createComputerAccount(const NQ_WCHAR *server, const CMSdDomainSid *domain, const NQ_WCHAR *computer, NQ_BYTE secret[16]);
static NQ_UINT32 removeComputerAccount(const NQ_WCHAR *server, const CMSdDomainSid *domain, const NQ_WCHAR *computer);
static void generateNetlogonCredentials(CCNetlogonCredential *credential, NQ_BYTE secret[16]);
static NQ_BOOL domainLogon(const NQ_WCHAR *domain, const NQ_WCHAR *computer, const AMCredentialsW *admin, NQ_BYTE secret[16]);
static NQ_BOOL domainJoin(const NQ_WCHAR *domain, const NQ_WCHAR *computer, const AMCredentialsW *admin, NQ_BYTE secret[16]);
static NQ_BOOL domainLeave(const NQ_WCHAR *domain, const NQ_WCHAR *computer, const AMCredentialsW *admin);
static NQ_HANDLE getNetlogonHandle(const NQ_WCHAR *dc);

typedef struct
{
	NQ_HANDLE netlogonHandle;
	SYMutex netlogonGuard;
}
StaticData;

#ifdef SY_FORCEALLOCATION
static StaticData* staticData = NULL;
#else  /* SY_FORCEALLOCATION */
static StaticData staticDataSrc;
static StaticData* staticData = &staticDataSrc;
#endif /* SY_FORCEALLOCATION */

NQ_BOOL ccDomainStart()
{
	NQ_BOOL result = TRUE;

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	/* allocate memory */
#ifdef SY_FORCEALLOCATION
	staticData = (StaticData *)cmMemoryAllocate(sizeof(*staticData));
	if (NULL == staticData)
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        sySetLastError(NQ_ERR_OUTOFMEMORY);
		goto Exit;
	}
#endif /* SY_FORCEALLOCATION */

	staticData->netlogonHandle = NULL;
	syMutexCreate(&staticData->netlogonGuard);

Exit:
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result ? "TRUE" : "FALSE");
	return result;
}

void ccDomainShutdown()
{
	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

#ifdef SY_FORCEALLOCATION
	if (NULL == staticData)
		goto Exit;
#endif

	if (NULL != staticData->netlogonHandle)
		ccDcerpcDisconnect(staticData->netlogonHandle);
	syMutexDelete(&staticData->netlogonGuard);

	/* release memory */
#ifdef SY_FORCEALLOCATION
	if (NULL != staticData)
		cmMemoryFree(staticData);
	staticData = NULL;
#endif /* SY_FORCEALLOCATION */

Exit:
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}



/* --- Static functions --- */

static NQ_HANDLE getNetlogonHandle(const NQ_WCHAR *dc)
{
	if (NULL == staticData->netlogonHandle)
	{
		staticData->netlogonHandle = ccDcerpcConnect(dc, ccUserGetAdministratorCredentials(), ccNetlogonGetPipe(), FALSE);
	}
	return staticData->netlogonHandle;
}

static NQ_UINT32 createComputerAccount(
    const NQ_WCHAR * server,
    const CMSdDomainSid * domain,
    const NQ_WCHAR * computer,
    NQ_BYTE secret[16]
    )
{
    NQ_BYTE password[COMP_ACCOUNT_PASSWORD_LENGTH + 1]; /* random computer account password */
    NQ_WCHAR * name = NULL;                             /* computer name with $ postfix */
    const NQ_WCHAR dollarSign[] = {cmWChar('$'), cmWChar('\0')};  /* computer name postfix */
    NQ_WCHAR * passwordW = NULL;                        /* Unicode password */
    NQ_HANDLE samr;                                     /* SAMR file handle */
    NQ_UINT32 status = NQ_ERR_GENERAL;                  /* generic result */
    NQ_UINT16 len;                                      /* RPC length */
    NQ_UINT32 type;                                     /* RPC value */
    NQ_UINT32 access;                                   /* rpc value */
    CMRpcPolicyHandle c, d, u;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "server:%s domain:%p computer:%s secret:%p", cmWDump(server), domain, cmWDump(computer), &secret);

    /* connect to SAMR */
    if ((samr = ccDcerpcConnect(server, ccUserGetAdministratorCredentials(), ccSamGetPipe(), FALSE)) != NULL)
    {
        NQ_UINT32 rid;

        /* SAMR::Connect2 */
        if ((status = ccSamrConnect5(samr, 0, &c)) == NQ_SUCCESS)
        {
            /* SAMR::OpenDomain */
            if ((status = ccSamrOpenDomain(samr, &c, domain, SAMR_AM_MAXIMUMALLOWED, &d)) == NQ_SUCCESS)
            {
                /* append '$' to computer name */
                name = (NQ_WCHAR *)cmMemoryAllocate((NQ_UINT)(sizeof(NQ_WCHAR) * (cmWStrlen(computer) + 2)));
                if (NULL == name)
                {
                    status = NQ_ERR_NOMEM;
                    LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
                    sySetLastError(status);
                    goto Error1;
                }
                cmWStrcpy(name, computer);
                cmWStrcat(name, dollarSign);

                /* SAMR::CreateUser2 */
                access = SAMR_CREATE_USER_DEFAULT_ACCESS;
                if ((status = ccSamrCreateUser2(samr, &d, name, SAMR_ACB_WSTRUST, access, &u, &rid, &access)) == NQ_SUCCESS)
                {
                    /* SAMR::Close(user) */
                    ccSamrClose(samr, &u);

                    /* lookup newly created user */
                    /* SAMR::LookupNames */
                    if ((status = ccSamrLookupNames(samr, &d, name, &rid, &type)) == NQ_SUCCESS)
                    {
                        /* set password */
                        /* SAMR::OpenUser */
                        if ((status = ccSamrOpenUser(samr, &d, &rid, SAMR_AM_MAXIMUMALLOWED, &u)) == NQ_SUCCESS)
                        {
                            /* create random computer account password */
                            cmCreateRandomByteSequence(password, COMP_ACCOUNT_PASSWORD_LENGTH);
                            password[COMP_ACCOUNT_PASSWORD_LENGTH] = '\0';

                            /* create hashed computer account password  - secret used in domain logons */
                            passwordW = cmMemoryCloneAString((const NQ_CHAR *)password);
                            if (NULL == passwordW)
                            {
                                LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
                                status = NQ_ERR_NOMEM;
                                sySetLastError(NQ_ERR_OUTOFMEMORY);
                                goto Error2;
                            }
                            len = (NQ_UINT16)(cmWStrlen(passwordW) * sizeof(NQ_WCHAR));
                            cmMD4(secret, (NQ_BYTE*)passwordW, len);
                            LOGDUMP("secret", secret, 16);

                            /* SAMR::SetUserInfo2 */
                            if ((status = ccSamrSetUserPassword(samr, &u, password, COMP_ACCOUNT_PASSWORD_LENGTH)) == NQ_SUCCESS)
                            {
                                ParamsSamrUserSetInfo2Level16 params;

                                /* set flags */
                                /* SAMR::SetUserInfo */
                                params.flags = SAMR_ACB_WSTRUST;
                                ccSamrSetUserInfo2(samr, &u, 16, (NQ_BYTE *)&params);
                            }

                            /* SAMR::Close(user) */
                            ccSamrClose(samr, &u);
                        }
                    }
                }

                /* SAMR::Close(domain) */
                ccSamrClose(samr, &d);
            }

            /* SAMR::Close(connection) */
            ccSamrClose(samr, &c);
        }

        /* close SAMR */
        ccDcerpcDisconnect(samr);
    }
    else
        status = (NQ_UINT32)syGetLastError();

Exit:
    cmMemoryFree(name);
    cmMemoryFree(passwordW);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%u", status);
    return status;

Error2:
    ccSamrClose(samr, &u);

Error1:
    ccSamrClose(samr, &d);
    ccSamrClose(samr, &c);
    ccDcerpcDisconnect(samr);
    goto Exit;
}

static NQ_UINT32 removeComputerAccount(
    const NQ_WCHAR *server,
    const CMSdDomainSid *domain,
    const NQ_WCHAR *computer
    )
{
    NQ_WCHAR * compName = NULL;                                     /* computer name with a postfix */
    const NQ_WCHAR dollarSign[] = {cmWChar('$'), cmWChar('\0')};    /* postfix */
    NQ_HANDLE samr;                                                 /* SAMR file handle */
    NQ_UINT32 status = NQ_ERR_GENERAL;                              /* generic result */
    CMRpcPolicyHandle c, d, u;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "server:%s domain:%p computer:%s", cmWDump(server), domain, cmWDump(computer));

    /* connect to SAMR */
    if ((samr = ccDcerpcConnect(server, ccUserGetAdministratorCredentials(), ccSamGetPipe(), FALSE)) != NULL)
    {
        NQ_UINT32 rid, type;

        /* SAMR::Connect2 */
        if ((status = ccSamrConnect5(samr, 0, &c)) == NQ_SUCCESS)
        {
            /* SAMR::OpenDomain */
            if ((status = ccSamrOpenDomain(samr, &c, domain, SAMR_AM_MAXIMUMALLOWED, &d)) == NQ_SUCCESS)
            {
                compName = (NQ_WCHAR *)cmMemoryAllocate((NQ_UINT)(sizeof(NQ_WCHAR) * (cmWStrlen(computer) + 2)));
                if (NULL == compName)
                {
                    LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
                    status = NQ_ERR_NOMEM;
                    sySetLastError(status);
                    goto Error;
                }
                cmWStrcpy(compName, computer);
                cmWStrcat(compName, dollarSign);

                /* SAMR::LookupNames */
                if ((status = ccSamrLookupNames(samr, &d, compName, &rid, &type)) == NQ_SUCCESS)
                {
                    /* SAMR::OpenUser */
                    if ((status = ccSamrOpenUser(samr, &d, &rid, SAMR_AM_MAXIMUMALLOWED, &u)) == NQ_SUCCESS)
                    {
                        /* SAMR::DeleteUser */
                        status = ccSamrDeleteUser(samr, &u);
                    }
                }
                /* SAMR::Close(domain) */
                ccSamrClose(samr, &d);
            }

            /* SAMR::Close(connection) */
            ccSamrClose(samr, &c);
        }

        /* close SAMR */
        ccDcerpcDisconnect(samr);
    }
    else
        status = (NQ_UINT32)syGetLastError();

    goto Exit;

Error:
    ccSamrClose(samr, &d);
    ccSamrClose(samr, &c);
    ccDcerpcDisconnect(samr);

Exit:
    cmMemoryFree(compName);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%u", status);
    return status;

}

static void generateNetlogonCredentials(
    CCNetlogonCredential *credential,
    NQ_BYTE secret[16]
    )
{
    CCNetlogonCredential tmp = {{0}};
    NQ_BYTE sessKey[16];

    cmGenerateNetlogonCredentials((const NQ_BYTE*)credential->client, (const NQ_BYTE*)credential->server, secret, tmp.client, tmp.server, sessKey);
    syMemcpy(credential, &tmp, sizeof(CCNetlogonCredential));
}

static NQ_BOOL domainLogon(
    const NQ_WCHAR * domain,
    const NQ_WCHAR * computer,
    const AMCredentialsW * admin,
    NQ_BYTE secret[16]
    )
{
    const NQ_WCHAR * dc = NULL;             /* DC name in Unicode */
    NQ_CHAR * dcA = NULL;                   /* DC name in ASCII */
    const NQ_CHAR * domainA = NULL;         /* domain name in ASCII */
    NQ_UINT32 status = NQ_SUCCESS;          /* generic result */
    NQ_BOOL result = FALSE;                 /* return value */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "domain:%s computer:%s admin:%p, secret:%p", cmWDump(domain), cmWDump(computer), admin, &secret);

    if (secret == NULL)
    {
        sySetLastError((NQ_UINT32)NQ_ERR_BADPARAM);
        LOGERR(CM_TRC_LEVEL_ERROR, "null secret");
        goto Exit;
    }

    if (cmWStrlen(computer) > 15)
    {
        sySetLastError((NQ_UINT32)NQ_ERR_BADPARAM);
        LOGERR(CM_TRC_LEVEL_ERROR, "computer name exceeds 15 characters");
        goto Exit;
    }

    /* find domain controller by domain name */
    domainA = cmMemoryCloneWStringAsAscii(domain);
    dcA = (NQ_CHAR *)cmMemoryAllocate(sizeof(NQ_BYTE) * CM_DNS_NAMELEN);
    if (NULL == domainA || NULL == dcA)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        sySetLastError(NQ_ERR_NOMEM);
        goto Exit;
    }
    if ((status = (NQ_UINT32)cmGetDCNameByDomain(domainA, dcA)) != NQ_SUCCESS)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "failed to get dc for domain %s", domainA);
        sySetLastError((NQ_UINT32)syGetLastError());
        goto Exit;
    }
    dc = cmMemoryCloneAString(dcA);
    if (NULL == dc)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        sySetLastError(NQ_ERR_NOMEM);
        goto Exit;
    }

    /* replace default credentials with domain administrator ones */
    cmWStrupr((NQ_WCHAR *)admin->domain.name); /* capitalize credentials domain name */
    ccUserSetAdministratorCredentials(admin);

    /* connect to NETLOGON */	
    {
        CCNetlogonCredential credentials;

		syMutexTake(&staticData->netlogonGuard);

        /* generate client random challenge */
        cmCreateRandomByteSequence(credentials.client, sizeof(credentials.client));

        /* send client challenge and get server random challenge */
        if ((status = ccNetrServerReqChallenge(getNetlogonHandle(dc), dc, computer, &credentials)) == NQ_SUCCESS)
        {
            /* calculate new client challenge and new server challenge */
            generateNetlogonCredentials(&credentials, secret);

            /* send new client challenge */
			status = ccNetrServerAuthenticate2(getNetlogonHandle(dc), dc, computer, &credentials, NULL);
        }
		syMutexGive(&staticData->netlogonGuard);
    }


    LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "status = 0x%x", status);

    /* restore previous user credentials */
    ccUserSetAdministratorCredentials(NULL);

    sySetLastError((NQ_UINT32)status);
    result = (status == NQ_SUCCESS);

Exit:
    cmMemoryFree(domainA);
    cmMemoryFree(dcA);
    cmMemoryFree(dc);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result ? "TRUE" : "FALSE");
    return result;
}

/*
 *====================================================================
 * PURPOSE: join domain
 *--------------------------------------------------------------------
 * PARAMS:  IN  target domain
 *          IN  computer name
 *          IN  domain administrator credentials
 *          IN/OUT domain secret
 *
 * RETURNS: TRUE if succeeded, FAIL otherwise
 *
 * NOTES:
 *====================================================================
 */
static NQ_BOOL domainJoin(
    const NQ_WCHAR * domain,
    const NQ_WCHAR * computer,
    const AMCredentialsW * admin,
    NQ_BYTE secret[16]
    )
{
    NQ_UINT32 status;                       /* generic result */
    const NQ_CHAR * domainA = NULL;         /* domain name in ASCII */
    NQ_CHAR * dcA = NULL;                   /* DC name in ASCII */
    const NQ_WCHAR * dc = NULL;             /* DC name in Unicode */
    CCLsaPolicyInfoDomain info;             /* domain info */
    NQ_BOOL result = FALSE;                 /* return value */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "domain:%s computer:%s admin:%p, secret:%p", cmWDump(domain), cmWDump(computer), admin, &secret);

    if (secret == NULL)
    {
        sySetLastError((NQ_UINT32)NQ_ERR_BADPARAM);
        LOGERR(CM_TRC_LEVEL_ERROR, "null secret");
        goto Exit;
    }

    if (cmWStrlen(computer) > 15)
    {
        sySetLastError((NQ_UINT32)NQ_ERR_BADPARAM);
        LOGERR(CM_TRC_LEVEL_ERROR, "computer name exceeds 15 characters: %s", cmWDump(computer));
        goto Exit;
    }

    /* find domain controller by domain name */
    domainA = cmMemoryCloneWStringAsAscii(domain);
    dcA = (NQ_CHAR *)cmMemoryAllocate(CM_BUFFERLENGTH(NQ_CHAR, CM_DNS_NAMELEN) * sizeof(NQ_CHAR));
    if (NULL == domainA || NULL == dcA)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        sySetLastError(NQ_ERR_NOMEM);
        goto Exit;
    }
    if ((status = (NQ_UINT32)cmGetDCNameByDomain(domainA, dcA)) != NQ_SUCCESS)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "failed to get dc for domain %s", domainA);
        sySetLastError((NQ_UINT32)syGetLastError());
        goto Exit;
    }
    dc = cmMemoryCloneAString(dcA);
    if (NULL == dc)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        sySetLastError(NQ_ERR_NOMEM);
        goto Exit;
    }

    /* replace default credentials with domain administrator ones */
    cmWStrupr((NQ_WCHAR *)admin->domain.name); /* capitalize credentials domain name */
    ccUserSetAdministratorCredentials(admin);

    /* get domain SID */
    if ((status = ccLsaPolicyQueryInfoDomain(dc, &info)) == NQ_SUCCESS)
    {
        /* create computer account in this domain */
        status = createComputerAccount(dc, &info.sid, computer, secret);
        LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "status = 0x%x", status);
    }

    /* restore previous user credentials */
    ccUserSetAdministratorCredentials(NULL);

    sySetLastError((NQ_UINT32)status);
    result = (status == NQ_SUCCESS);

Exit:
    cmMemoryFree(domainA);
    cmMemoryFree(dcA);
    cmMemoryFree(dc);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result ? "TRUE" : "FALSE");
    return result;
}

typedef struct
{
    NQ_WCHAR * domain;
    NQ_WCHAR * server;
    NQ_WCHAR * username;
    NQ_WCHAR * workstation;
    const NQ_BYTE  * serverChallenge;
    const NQ_BYTE  * lmPasswd;
    NQ_UINT16 lmPasswdLen;
    const NQ_BYTE  * ntlmPasswd;
    NQ_UINT16 ntlmPasswdLen;
    const CCNetlogonCredential *credential;
    NQ_BYTE *userSessionKey;
    NQ_BOOL extendedSecurity;
	NQ_UINT32 * userRid;
	NQ_UINT32 * groupRid;
    NQ_UINT32 status;
}
ParamsNetrLogonSamLogon;

static NQ_COUNT
composeNetrLogonSamLogon (
    NQ_BYTE* buffer,
    NQ_COUNT size,
    void* params,
    NQ_BOOL* moreData
    )
{
    CMBufferWriter w;           /* for composing request */
    ParamsNetrLogonSamLogon *p = (ParamsNetrLogonSamLogon *)params;
    NQ_UINT32 ref = 0;          /* ref id */
    NQ_UINT32 sz;               /* rpc string size */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "buff:%p size:%d params:%p more:%p", buffer, size, params, moreData);

    cmBufferWriterInit(&w, buffer, size);
    cmBufferWriteUint16(&w, 2);                    /* opcode: NetrLogonSamLogon*/

    /* server name prefixed by double back slash */
    sz = 3 + (NQ_UINT32)cmWStrlen(p->server);
    cmBufferWriteUint32(&w, ++ref);                /* ref ID */
    cmBufferWriteUint32(&w, sz);                   /* max count */
    cmBufferWriteUint32(&w, 0);                    /* offset */
    cmBufferWriteUint32(&w, sz);                   /* actual count */
    cmBufferWriteAsciiAsUnicodeN(&w, "\\\\", 2, CM_BSF_NOFLAGS);
    cmWStrupr(p->server); /* capitalize server name */
    cmBufferWriteUnicode(&w, p->server);

    /* workstation name */
    cmBufferWriterAlign(&w, buffer + 2, 4);        /* 4 byte alignment */
    sz = 1 + (NQ_UINT32)cmWStrlen(p->workstation);
    cmBufferWriteUint32(&w, ++ref);                /* ref ID */
    cmBufferWriteUint32(&w, sz);                   /* max count */
    cmBufferWriteUint32(&w, 0);                    /* offset */
    cmBufferWriteUint32(&w, sz);                   /* actual count */
    cmWStrupr(p->workstation); /* capitalize workstation name */
    cmBufferWriteUnicode(&w, p->workstation);

    /* Authenticator */
    cmBufferWriterAlign(&w, buffer + 2, 4);        /* 4 byte alignment */
    cmBufferWriteUint32(&w, ++ref);                /* ref ID */
    cmBufferWriteBytes(&w, p->credential->client, sizeof(p->credential->client));
    cmBufferWriteUint32(&w, p->credential->sequence/*syGetTimeInSec()*/);

    /* Return authenticator */
    cmBufferWriteUint32(&w, ++ref);                /* ref ID */
    /*cmBufferWriteBytes(&w, p->credential->server, sizeof(p->credential->server));*/
    cmBufferWriteZeroes(&w, 8);
    cmBufferWriteUint32(&w, 0/*syGetTimeInSec()*/);

    cmBufferWriteUint16(&w, 2);                    /* logon level */
    cmBufferWriteUint16(&w, 2);                    /* logon level */
    cmBufferWriteUint32(&w, ++ref);                /* ref ID */

    /* Logon information */
    cmBufferWriterAlign(&w, buffer + 2, 4);        /* 4 byte alignment */

    /* domain */
    sz = 2 * (NQ_UINT32)cmWStrlen(p->domain);
    cmBufferWriteUint16(&w, (NQ_UINT16)sz);        /* max count */
    cmBufferWriteUint16(&w, (NQ_UINT16)sz);        /* actual count */
    cmBufferWriteUint32(&w, ++ref);                /* ref ID */

    /* parameter control */
    if (p->lmPasswdLen == 24 && p->ntlmPasswdLen == 24 && !p->extendedSecurity)
        cmBufferWriteUint32(&w, 0x00000a42);
    else
        cmBufferWriteUint32(&w, 0x00000820);
    /* cmBufferWriteUint32(&w, 0x00000AE0);  */        /* parameter control */
    /* cmBufferWriteUint32(&w, 0x00002a42);  */        /* parameter control */
    /* cmBufferWriteUint32(&w, 0x00010000);  */        /* parameter control */
    cmBufferWriteUint32(&w, 0);                    /* logon id low */
    cmBufferWriteUint32(&w, 0);                    /* logon id high */

    /* username */
    sz = 2 * (NQ_UINT32)cmWStrlen(p->username);
    cmBufferWriteUint16(&w, (NQ_UINT16)sz);        /* max count */
    cmBufferWriteUint16(&w, (NQ_UINT16)sz);        /* actual count */
    cmBufferWriteUint32(&w, ++ref);                /* ref ID */

    /* workstation - client's workstation name*/
    sz = 2 * (NQ_UINT32)cmWStrlen(p->workstation);
    cmBufferWriteUint16(&w, (NQ_UINT16)sz);        /* max count */
    cmBufferWriteUint16(&w, (NQ_UINT16)sz);        /* actual count */
    cmBufferWriteUint32(&w, ++ref);                /* ref ID */

    /* serverChallenge */
    cmBufferWriteBytes(&w, p->serverChallenge, 8);

    /* ntlmPasswd */
    sz = p->ntlmPasswdLen;
    cmBufferWriteUint16(&w, (NQ_UINT16)sz);        /* max count */
    cmBufferWriteUint16(&w, (NQ_UINT16)sz);        /* actual count */
    cmBufferWriteUint32(&w, ++ref);                /* ref ID */

    /* lmPasswd */
    sz = p->lmPasswdLen;
    cmBufferWriteUint16(&w, (NQ_UINT16)sz);        /* max count */
    cmBufferWriteUint16(&w, (NQ_UINT16)sz);        /* actual count */
    cmBufferWriteUint32(&w, ++ref);                /* ref ID */

    /* domain */
    cmBufferWriterAlign(&w, buffer + 2, 4);        /* 4 byte alignment */
    sz = (NQ_UINT32)cmWStrlen(p->domain);
    cmBufferWriteUint32(&w, sz);                    /* max count */
    cmBufferWriteUint32(&w, 0);                     /* offset */
    cmBufferWriteUint32(&w, sz);                    /* actual count */
    cmBufferWriteUnicodeNoNull(&w, p->domain);

    /* username */
    cmBufferWriterAlign(&w, buffer + 2, 4);        /* 4 byte alignment */
    sz = (NQ_UINT32)cmWStrlen(p->username);
    cmBufferWriteUint32(&w, sz);                   /* max count */
    cmBufferWriteUint32(&w, 0);                    /* offset */
    cmBufferWriteUint32(&w, sz);                   /* actual count */
    cmBufferWriteUnicodeNoNull(&w, p->username);

    /* workstation - client's workstation name*/
    cmBufferWriterAlign(&w, buffer + 2, 4);        /* 4 byte alignment */
    sz = (NQ_UINT32)cmWStrlen(p->workstation);
    cmBufferWriteUint32(&w, sz);                   /* max count */
    cmBufferWriteUint32(&w, 0);                    /* offset */
    cmBufferWriteUint32(&w, sz);                   /* actual count */
    cmBufferWriteUnicodeNoNull(&w, p->workstation);

    /* ntlmPasswd */
    cmBufferWriterAlign(&w, buffer + 2, 4);        /* 4 byte alignment */
    sz = p->ntlmPasswdLen;
    cmBufferWriteUint32(&w, sz);                   /* max count */
    cmBufferWriteUint32(&w, 0);                    /* offset */
    cmBufferWriteUint32(&w, sz);                   /* actual count */
    cmBufferWriteBytes(&w, p->ntlmPasswd, (NQ_COUNT)sz);

    /* lmPasswd */
    cmBufferWriterAlign(&w, buffer + 2, 4);        /* 4 byte alignment */
    sz = (NQ_UINT32)p->lmPasswdLen;
    cmBufferWriteUint32(&w, sz);                   /* max count */
    cmBufferWriteUint32(&w, 0);                    /* offset */
    cmBufferWriteUint32(&w, sz);                   /* actual count */
    cmBufferWriteBytes(&w, p->lmPasswd, (NQ_COUNT)sz);

    cmBufferWriteUint16(&w, 3/*6*/);               /* validation level */
    /* cmBufferWriteUint16(&w, 0); */
    /* cmBufferWriteUint32(&w, 0); */              /* flags */

    *moreData = FALSE;

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return cmBufferWriterGetDataCount(&w);
}

static NQ_STATUS
processNetrLogonSamLogon (
    const NQ_BYTE * data,
    NQ_COUNT size,
    void * params,
    NQ_BOOL moreData
    )
{
    CMBufferReader r;
    ParamsNetrLogonSamLogon *p = (ParamsNetrLogonSamLogon *)params;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "data:p size:%d params:%p more:%s", data, size, params, moreData ? "TRUE" : "FALSE");

    cmBufferReaderInit(&r, data, size);
    cmBufferReaderSetOffset(&r, size - 4);
    cmBufferReadUint32(&r, &p->status);
    if (p->status == 0)
    {
        cmBufferReaderSetPosition(&r, cmBufferReaderGetStart(&r));
		cmBufferReaderSkip(&r, 124);
		cmBufferReadUint32(&r, p->userRid);
		cmBufferReadUint32(&r, p->groupRid);
        cmBufferReaderSkip(&r, 12);
        cmBufferReadBytes(&r, p->userSessionKey, 16);
    }

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", p->status);
    return (NQ_STATUS)p->status;
}

static
NQ_UINT32
ccNetrLogonSamLogon(
    NQ_HANDLE netlogon,
    NQ_WCHAR * domain,
    NQ_WCHAR * server,
    NQ_WCHAR * username,
    NQ_WCHAR * workstation,
    const NQ_BYTE serverChallenge[8],
    const NQ_BYTE * lmPasswd,
    NQ_UINT16 lmPasswdLen,
    const NQ_BYTE * ntlmPasswd,
    NQ_UINT16 ntlmPasswdLen,
    const CCNetlogonCredential *    credential,
    NQ_BOOL isExtendedSecurity,
    NQ_BYTE userSessionKey[16],
	NQ_UINT32 * userRid,
	NQ_UINT32 * groupRid
    )
{
    ParamsNetrLogonSamLogon p;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "hetlogon:%p domain:%s server:%s user:%s workstation:%s", netlogon, cmWDump(domain), cmWDump(server), cmWDump(username), cmWDump(workstation));

    p.domain = domain;
    p.server = server;
    p.username = username;
    p.workstation = workstation;
    p.serverChallenge = serverChallenge;
    p.lmPasswdLen = lmPasswdLen;
    p.lmPasswd = lmPasswd;
    p.ntlmPasswdLen = ntlmPasswdLen;
    p.ntlmPasswd = ntlmPasswd;
    p.credential = credential;
    p.userSessionKey = userSessionKey;
    p.extendedSecurity = isExtendedSecurity;
	p.userRid = userRid;
	p.groupRid = groupRid;

    /* call NETLOGON::NetrLogonSamLogon */
    if (ccDcerpcCall(netlogon, composeNetrLogonSamLogon, processNetrLogonSamLogon, &p) == 0)
    {
        p.status = (p.status == 0) ? (NQ_UINT32)syGetLastError() : (NQ_UINT32)ccErrorsStatusToNq(p.status, TRUE);
        LOGERR(CM_TRC_LEVEL_ERROR, "NETLOGON::NetrLogonSamLogon");
    }

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:0x%x", p.status);
    return p.status;
}

static
void
initNetlogonCredentials(
    CCNetlogonCredential* creds,
    const NQ_BYTE secret[16]
    )
{
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "creds:%p, secret:%p", creds, &secret);

    creds->sequence = (NQ_UINT32)syGetTimeInSec();
    cmGenerateNetlogonCredentials((const NQ_BYTE*)creds->client, (const NQ_BYTE*)creds->server, secret, creds->client, creds->server, creds->sessionKey);
    syMemcpy(creds->seed, creds->client, sizeof(creds->seed));

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

static
void
nextNetlogonCredentials(
    CCNetlogonCredential* creds
    )
{
    NQ_BYTE data[8];
    NQ_UINT32 *p;
    NQ_UINT32 temp;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "creds:%p", creds);

    creds->sequence += 2;
    syMemcpy(data, creds->seed, sizeof(data));

    p = (NQ_UINT32*)data;
    temp = cmLtoh32(*p);
    *p = cmHtol32(temp + creds->sequence);

    cmDES112(creds->client, data, creds->sessionKey);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

/*
 *====================================================================
 * PURPOSE: logon to domain
 *--------------------------------------------------------------------
 * PARAMS:  IN  target domain
 *          IN  user name
 *          IN  computer name
 *          IN  server challenge
 *          IN  lm password
 *          IN  lm password length
 *          IN  ntlm password
 *          IN  ntlm password length
 *          IN  domain administrator credentials
 *          IN  domain secret
 *          IN  whether extended security is used
 *          OUT user session key
 *          OUT user rid
 *          OUT group rid
 *
 * RETURNS: TRUE if succeeded, FAIL otherwise
 *
 * NOTES:
 *====================================================================
 */
static
NQ_BOOL
netLogon(
    NQ_WCHAR * domain,
    NQ_WCHAR * username,
    NQ_WCHAR * workstation,
    const NQ_BYTE serverChallenge[8],
    const NQ_BYTE * lmPasswd,
    NQ_UINT16 lmPasswdLen,
    const NQ_BYTE * ntlmPasswd,
    NQ_UINT16 ntlmPasswdLen,
    const AMCredentialsW * admin,
    const NQ_BYTE secret[16],
    NQ_BOOL isExtendedSecurity,
    NQ_BYTE userSessionKey[16],
	NQ_UINT32 * userRid,
	NQ_UINT32 * groupRid
    )
{
    NQ_WCHAR * dc = NULL;               /* DC name in Unicode */
    NQ_CHAR * dcA = NULL;               /* DC name in ASCII */
    const NQ_CHAR * domainA = NULL;     /* Domain name in ASCII */
    NQ_UINT32 status = NQ_SUCCESS;      /* generic result */
    NQ_BOOL result = FALSE;             /* return value */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "domain:%s user:%s workstation:%s", cmWDump(domain), cmWDump(username), cmWDump(workstation));

    if (secret == NULL)
    {
        sySetLastError((NQ_UINT32)NQ_ERR_BADPARAM);
        LOGERR(CM_TRC_LEVEL_ERROR, "null secret");
        goto Exit;
    }

    if (cmWStrlen(workstation) > 15)
    {
        sySetLastError((NQ_UINT32)NQ_ERR_BADPARAM);
        LOGERR(CM_TRC_LEVEL_ERROR, "workstation name exceeds 15 characters");
        goto Exit;
    }

    /* find domain controller by domain name */
    domainA = cmMemoryCloneWStringAsAscii(domain);
    dcA = (NQ_CHAR *)cmMemoryAllocate(sizeof(NQ_BYTE) * CM_DNS_NAMELEN);
    if (NULL == domainA || NULL == dcA)
    {
        sySetLastError(NQ_ERR_NOMEM);
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        goto Exit;
    }
    if ((status = (NQ_UINT32)cmGetDCNameByDomain(domainA, dcA)) != NQ_SUCCESS)
    {
        sySetLastError((NQ_UINT32)syGetLastError());
        LOGERR(CM_TRC_LEVEL_ERROR, "failed to get dc for domain %s", domainA);
        goto Exit;
    }

    if (NULL == cmAStrchr(dcA, '.') && syStrlen(dcA) > 15)
    {
        dcA[15] = '\0';
    }

    dc = cmMemoryCloneAString(dcA);
    if (NULL == dc)
    {
        sySetLastError(NQ_ERR_NOMEM);
        goto Exit;
    }

    /* replace default credentials with domain administrator ones */
    ccUserSetAdministratorCredentials(admin);

    /* connect to NETLOGON (as admin) */
    {
        CCNetlogonCredential credentials;

		syMutexTake(&staticData->netlogonGuard);

        /* generate client random challenge */
        cmCreateRandomByteSequence(credentials.client, sizeof(credentials.client));

        /* send client challenge and get server random challenge */
        if ((status = ccNetrServerReqChallenge(getNetlogonHandle(dc), dc, workstation, &credentials)) == NQ_SUCCESS)
        {
            NQ_UINT32 flags;

            /* init and generate next netlogon credentials */
            initNetlogonCredentials(&credentials, secret);

            /* send new client challenge, get server's challenge */
			if ((status = ccNetrServerAuthenticate2(getNetlogonHandle(dc), dc, workstation, &credentials, &flags)) == NQ_SUCCESS)
            {
                nextNetlogonCredentials(&credentials);

                /* send new client challenge */
                status = ccNetrLogonSamLogon(
					                        getNetlogonHandle(dc),
                                            domain,
                                            dc,
                                            username,
                                            workstation,
                                            serverChallenge,
                                            lmPasswd,
                                            lmPasswdLen,
                                            ntlmPasswd,
                                            ntlmPasswdLen,
                                            &credentials,
                                            isExtendedSecurity,
                                            userSessionKey,
											userRid,
											groupRid
											);
                if (status == NQ_SUCCESS)
                {
                    LOGDUMP("userSessionKey", userSessionKey, 16);
                    /* decrypt user session key (RC4) */
                    if (flags & 0x00000004)
                    {
                        cmArcfourCrypt(userSessionKey, 16, credentials.sessionKey, 16);
                        LOGDUMP("userSessionKey (after rc4)", userSessionKey, 16);
                    }
                }
            }
        }

		syMutexGive(&staticData->netlogonGuard);
	}

    LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "status = 0x%x", status);

    /* restore previous user credentials */
    if (admin)
        ccUserSetAdministratorCredentials(NULL);

    sySetLastError((NQ_UINT32)status);
    result = (status == NQ_SUCCESS);

Exit:
    cmMemoryFree(domainA);
    cmMemoryFree(dcA);
    cmMemoryFree(dc);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result ? "TRUE" : "FALSE");
    return result;
}

/*
 *====================================================================
 * PURPOSE: leave domain
 *--------------------------------------------------------------------
 * PARAMS:  IN  target domain
 *          IN  computer name
 *          IN  domain administrator credentials
 *
 * RETURNS: TRUE if succeded, FAIL otherwise
 *
 * NOTES:
 *====================================================================
 */
static
NQ_BOOL
domainLeave(
    const NQ_WCHAR * domain,
    const NQ_WCHAR * computer,
    const AMCredentialsW *admin
    )
{
    NQ_UINT32 status;               /* generic result */
    NQ_WCHAR * dc = NULL;           /* DC name in Unicode */
    NQ_CHAR * dcA = NULL;           /* DC name in ASCII */
    NQ_CHAR * domainA = NULL;       /* domain name in ASCII */
    CCLsaPolicyInfoDomain info;
    NQ_BOOL result = FALSE;         /* return value */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "domain:%s computer:%s admin:%p", cmWDump(domain), cmWDump(computer), admin);

    if (cmWStrlen(computer) > 15)
    {
        sySetLastError((NQ_UINT32)NQ_ERR_BADPARAM);
        LOGERR(CM_TRC_LEVEL_ERROR, "workstation name exceeds 15 characters");
        goto Exit;
    }

    /* find domain controller by domain name */
    domainA = cmMemoryCloneWStringAsAscii(domain);
    dcA = (NQ_CHAR *)cmMemoryAllocate(sizeof(NQ_BYTE) * CM_DNS_NAMELEN);
    if (NULL == domainA || NULL == dcA)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        sySetLastError(NQ_ERR_NOMEM);
        goto Exit;
    }
    if ((status = (NQ_UINT32)cmGetDCNameByDomain(domainA, dcA)) != NQ_SUCCESS)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "failed to get dc for domain %s", domainA);
        sySetLastError((NQ_UINT32)syGetLastError());
        goto Exit;
    }
    dc = cmMemoryCloneAString(dcA);
    if (NULL == dc)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        sySetLastError(NQ_ERR_NOMEM);
        goto Exit;
    }

    /* replace default credentials with domain administrator ones */
    cmWStrupr((NQ_WCHAR *)admin->domain.name); /* capitalize credentials domain name */
    ccUserSetAdministratorCredentials(admin);

    /* get domain SID */
    if ((status = ccLsaPolicyQueryInfoDomain(dc, &info)) == NQ_SUCCESS)
    {
        /* remove computer account in this domain */
        status = removeComputerAccount(dc, &info.sid, computer);
        LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "status = 0x%x", status);
    }

    /* restore previous user credentials */
    ccUserSetAdministratorCredentials(NULL);

    sySetLastError((NQ_UINT32)status);
    result = (status == NQ_SUCCESS);

Exit:
    cmMemoryFree(domainA);
    cmMemoryFree(dcA);
    cmMemoryFree(dc);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result ? "TRUE" : "FALSE");
    return result;
}

/*
 *====================================================================
 * PURPOSE: join domain (ASCII version)
 *--------------------------------------------------------------------
 * PARAMS:  IN  target domain
 *          IN  computer name
 *          IN  domain administrator credentials
 *          IN/OUT domain secret
 *
 * RETURNS: TRUE if succeeded, FAIL otherwise
 *
 * NOTES:
 *====================================================================
 */
NQ_BOOL
ccDomainJoinA(
    const NQ_CHAR * domain,
    const NQ_CHAR * computer,
    const AMCredentialsA * admin,
    NQ_BYTE secret[16]
    )
{
    NQ_WCHAR * domainW;     /* domain name in Unicode */
    NQ_WCHAR * computerW;   /* computer name in Unicode */
    NQ_BOOL result;         /* operation result */

    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL, "domain:%s computer:%s admin:%p secret:%p", domain ? domain : "", computer ? computer : "" , admin, &secret);

    domainW = cmMemoryCloneAString(domain);
    computerW = cmMemoryCloneAString(computer);
    if (NULL != domainW && NULL != computerW)
    {
        AMCredentialsW adminW;  /* Unicode credentials */

        amCredentialsAsciiiToW(&adminW, admin);
        cmWStrupr(computerW);           /* capitalize computer name */
        result = domainJoin(domainW, computerW, &adminW, secret);
    }
    else
    {
        sySetLastError(NQ_ERR_NOMEM);
        result = FALSE;
    }

    cmMemoryFree(domainW);
    cmMemoryFree(computerW);

    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL, "result:%s", result ? "TRUE" : "FALSE");
    return result;
}

/*
 *====================================================================
 * PURPOSE: join domain (UNICODE version)
 *--------------------------------------------------------------------
 * PARAMS:  IN  target domain
 *          IN  computer name
 *          IN  domain administrator credentials
 *          IN/OUT domain secret
 *
 * RETURNS: TRUE if succeeded, FAIL otherwise
 *
 * NOTES:
 *====================================================================
 */
NQ_BOOL
ccDomainJoinW(
    const NQ_WCHAR * domain,
    const NQ_WCHAR * computer,
    const AMCredentialsW * admin,
    NQ_BYTE secret[16]
    )
{
    NQ_WCHAR * computerW;   /* computer name in Unicode */
    NQ_BOOL result;         /* operation result */

    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL, "domain:%s computer:%s admin:%p secret:%p", cmWDump(domain), cmWDump(computer), admin, &secret);

    computerW = cmMemoryCloneWString(computer);
    if (NULL != computerW)
    {
        cmWStrupr(computerW); /* capitalize computer name */
        result = domainJoin(domain, computerW, admin, secret);
    }
    else
    {
        sySetLastError(NQ_ERR_NOMEM);
        result = FALSE;
    }

    cmMemoryFree(computerW);

    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL, "result:%s", result ? "TRUE" : "FALSE");
    return result;
}

/*
 *====================================================================
 * PURPOSE: leave domain (ASCII version)
 *--------------------------------------------------------------------
 * PARAMS:  IN  target domain
 *          IN  computer name
 *          IN  domain administrator credentials
 *
 * RETURNS: TRUE if succeeded, FAIL otherwise
 *
 * NOTES:
 *====================================================================
 */
NQ_BOOL ccDomainLeaveA(
    const NQ_CHAR * domain,
    const NQ_CHAR * computer,
    const AMCredentialsA * admin
    )
{
    NQ_WCHAR * domainW;     /* domain name in Unicode */
    NQ_WCHAR * computerW;   /* computer name in Unicode */
    NQ_BOOL result;         /* operation result */

    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL, "domain:%s computer:%s admin:%p", domain ? domain : "", computer ? computer : "" , admin);

    domainW = cmMemoryCloneAString(domain);
    computerW = cmMemoryCloneAString(computer);
    if (NULL != domainW && NULL != computerW)
    {
        AMCredentialsW adminW;  /* Unicode credentials */

        cmWStrupr(computerW); /* capitalize computer name */
        amCredentialsAsciiiToW(&adminW, admin);
        result = domainLeave(domainW, computerW, &adminW);
    }
    else
    {
        sySetLastError(NQ_ERR_NOMEM);
        result = FALSE;
    }

    cmMemoryFree(domainW);
    cmMemoryFree(computerW);

    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL, "result:%s", result ? "TRUE" : "FALSE");
    return result;
}

/*
 *====================================================================
 * PURPOSE: leave domain (UNICODE version)
 *--------------------------------------------------------------------
 * PARAMS:  IN  target domain
 *          IN  computer name
 *          IN  domain administrator credentials
 *
 * RETURNS: TRUE if succeeded, FAIL otherwise
 *
 * NOTES:
 *====================================================================
 */
NQ_BOOL ccDomainLeaveW(
    const NQ_WCHAR * domain,
    const NQ_WCHAR * computer,
    const AMCredentialsW  *admin
    )
{
    NQ_WCHAR * computerW;   /* computer name in Unicode */
    NQ_BOOL result;         /* operation result */

    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL, "domain:%s computer:%s admin:%p", cmWDump(domain), cmWDump(computer), admin);

    computerW = cmMemoryCloneWString(computer);
    if (NULL != computerW)
    {
        cmWStrupr(computerW); /* capitalize computer name */
        result = domainLeave(domain, computerW, admin);
    }
    else
    {
        sySetLastError(NQ_ERR_NOMEM);
        result = FALSE;
    }

    cmMemoryFree(computerW);

    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL, "result:%s", result ? "TRUE" : "FALSE");
    return result;
}

/*
 *====================================================================
 * PURPOSE: logon to a domain (ASCII version)
 *--------------------------------------------------------------------
 * PARAMS:  IN  target domain
 *          IN  domain administrator credentials
 *          IN  computer name
 *          IN  domain secret
 *
 * RETURNS: TRUE if succeeded, FAIL otherwise
 *
 * NOTES:
 *====================================================================
 */
NQ_BOOL ccDomainLogonA(
    const NQ_CHAR * domain,
    const NQ_CHAR * computer,
    const AMCredentialsA * admin,
    NQ_BYTE secret[16]
    )
{
    NQ_WCHAR * domainW;     /* domain name in Unicode */
    NQ_WCHAR * computerW;   /* computer name in Unicode */
    NQ_BOOL result;         /* operation result */

    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL, "domain:%s computer:%s admin:%p secret:%p", domain ? domain : "", computer ? computer : "" , admin, &secret);

    domainW = cmMemoryCloneAString(domain);
    computerW = cmMemoryCloneAString(computer);
    if (NULL != domainW && NULL != computerW)
    {
        AMCredentialsW adminW;  /* Unicode credentials */

        cmWStrupr(computerW); /* capitalize computer name */
        amCredentialsAsciiiToW(&adminW, admin);
        result = domainLogon(domainW, computerW, &adminW, secret);
    }
    else
    {
        sySetLastError(NQ_ERR_NOMEM);
        result = FALSE;
    }

    cmMemoryFree(domainW);
    cmMemoryFree(computerW);

    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL, "result:%s", result ? "TRUE" : "FALSE");
    return result;
}


/*
 *====================================================================
 * PURPOSE: logon to a domain (UNICODE version)
 *--------------------------------------------------------------------
 * PARAMS:  IN  target domain
 *          IN  domain administrator credentials
 *          IN  computer name
 *          IN  domain secret
 *
 * RETURNS: TRUE if succeeded, FAIL otherwise
 *
 * NOTES:
 *====================================================================
 */
NQ_BOOL ccDomainLogonW(
    const NQ_WCHAR * domain,
    const NQ_WCHAR * computer,
    const AMCredentialsW * admin,
    NQ_BYTE secret[16]
    )
{
    NQ_WCHAR * computerW;   /* computer name in Unicode */
    NQ_BOOL result;         /* operation result */

    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL, "domain:%s computer:%s admin:%p secret:%p", cmWDump(domain), cmWDump(computer), admin, &secret);

    computerW = cmMemoryCloneWString(computer);
    if (NULL != computerW)
    {
        cmWStrupr(computerW); /* capitalize computer name */
        result = domainLogon(domain, computerW, admin, secret);
    }
    else
    {
        sySetLastError(NQ_ERR_NOMEM);
        result = FALSE;
    }

    cmMemoryFree(computerW);

    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL, "result:%s", result ? "TRUE" : "FALSE");
    return result;
}

/*
 *====================================================================
 * PURPOSE: logon to a domain (ASCII version)
 *--------------------------------------------------------------------
 * PARAMS:  IN  target domain
 *          IN  user name
 *          IN  computer name
 *          IN  server challenge
 *          IN  lm password
 *          IN  lm password length
 *          IN  ntlm password
 *          IN  ntlm password length
 *          IN  domain administrator credentials
 *          IN  domain secret
 *          IN  whether extended security is used
 *          OUT user session key
 *          OUT user rid
 *          OUT group rid
 *
 * RETURNS: TRUE if succeeded, FAIL otherwise
 *
 * NOTES:
 *====================================================================
 */
NQ_BOOL ccNetLogonA(
    const NQ_CHAR * domain,
    const NQ_CHAR * username,
    const NQ_CHAR * workstation,
    const NQ_BYTE serverChallenge[8],
    const NQ_BYTE * lmPasswd,
    NQ_UINT16 lmPasswdLen,
    const NQ_BYTE * ntlmPasswd,
    NQ_UINT16 ntlmPasswdLen,
    const AMCredentialsA * admin,
    const NQ_BYTE secret[16],
    NQ_BOOL isExtendedSecurity,
    NQ_BYTE userSessionKey[16],
	NQ_UINT32 * userRid,
	NQ_UINT32 * groupRid
    )
{
    NQ_WCHAR * domainW;         /* domain name in Unicode */
    NQ_WCHAR * userW;           /* user name in Unicode */
    NQ_WCHAR * workstationW;    /* computer name in Unicode */
    NQ_BOOL result;

    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL, "domain:%s user:%s workstation:%s", domain ? domain : "", username ? username : "", workstation ? workstation : "");

    domainW = cmMemoryCloneAString(domain);
    userW = cmMemoryCloneAString(username);
    workstationW = cmMemoryCloneAString(workstation);
    if (NULL != domainW && NULL != userW && NULL != workstationW)
    {
        AMCredentialsW adminW;  /* Unicode credentials */

        if (NULL != admin)
        {
            amCredentialsAsciiiToW(&adminW, admin);
            cmWStrupr(adminW.domain.name); /* capitalize credentials domain name */
        }
        result = netLogon(
                        domainW,
                        userW,
                        workstationW,
                        serverChallenge,
                        lmPasswd,
                        lmPasswdLen,
                        ntlmPasswd,
                        ntlmPasswdLen,
                        admin ? &adminW : NULL,
                        secret,
                        isExtendedSecurity,
                        userSessionKey,
						userRid,
						groupRid);
    }
    else
    {
        sySetLastError(NQ_ERR_NOMEM);
        result = FALSE;
    }

    cmMemoryFree(domainW);
    cmMemoryFree(userW);
    cmMemoryFree(workstationW);

    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL, "result:%s", result ? "TRUE" : "FALSE");
    return result;
}


/*
 *====================================================================
 * PURPOSE: logon to a domain (UNICODE version)
 *--------------------------------------------------------------------
 * PARAMS:  IN  target domain
 *          IN  user name
 *          IN  computer name
 *          IN  server challenge
 *          IN  lm password
 *          IN  lm password length
 *          IN  ntlm password
 *          IN  ntlm password length
 *          IN  domain administrator credentials
 *          IN  domain secret
 *          IN  whether extended security is used
 *          OUT user session key
 *          OUT user rid
 *          OUT group rid
 *
 * RETURNS: TRUE if succeeded, FAIL otherwise
 *
 * NOTES:
 *====================================================================
 */
NQ_BOOL ccNetLogonW(
    const NQ_WCHAR * domain,
    const NQ_WCHAR * username,
    const NQ_WCHAR * workstation,
    const NQ_BYTE serverChallenge[8],
    const NQ_BYTE * lmPasswd,
    NQ_UINT16 lmPasswdLen,
    const NQ_BYTE * ntlmPasswd,
    NQ_UINT16 ntlmPasswdLen,
    const AMCredentialsW * admin,
    const NQ_BYTE secret[16],
    NQ_BOOL isExtendedSecurity,
    NQ_BYTE userSessionKey[16],
	NQ_UINT32 * userRid,
	NQ_UINT32 * groupRid
    )
{
    NQ_BOOL result;

    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL, "domain:%s user:%s workstation:%s", cmWDump(domain), cmWDump(username), cmWDump(workstation));

    result = netLogon(
        (NQ_WCHAR *)domain,
        (NQ_WCHAR *)username,
        (NQ_WCHAR *)workstation,
        serverChallenge,
        lmPasswd,
        lmPasswdLen,
        ntlmPasswd,
        ntlmPasswdLen,
        admin,
        secret,
        isExtendedSecurity,
        userSessionKey,
		userRid,
		groupRid);

    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL, "result:%s", result ? "TRUE" : "FALSE");
    return result;
}

#endif /* UD_CC_INCLUDEDOMAINMEMBERSHIP */
