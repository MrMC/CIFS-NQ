/*********************************************************************
 *
 *           Copyright (c) 2005 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : LSA RPC client
 *--------------------------------------------------------------------
 * DEPENDENCIES  : None
 *--------------------------------------------------------------------
 * CREATION DATE : 14-Oct-2005
 * CREATED BY    : Igor Lerner
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "cclsarpc.h"
#include "ccfile.h"
#include "cmrpcdef.h"
#include "cmsdescr.h"

#include "nqapi.h"

#if defined(UD_CC_INCLUDESECURITYDESCRIPTORS) || defined(UD_CC_INCLUDEDOMAINMEMBERSHIP) || defined(UD_CS_INCLUDEPASSTHROUGH)

/*
 * Static data, functions and definitions
 * -------------------------------------
 */

#define OPENPOLICY_OPNUM    44  /* currently - OpenPolicy2 */
#define LOOKUPNAMES_OPNUM   58  /* currently - LookupNames2 */
#define LOOKUPSIDS_OPNUM    57  /* currently - LookupSids2 */
#define CLOSE_OPNUM         0   /* */

/* LSA::OpenPolicy access masks */
#define OPA_LOOKUPNAMES     0x00000800
#define OPA_QUERYINFODOMAIN 0x02000000

/* parameters for callbacks */
typedef struct
{
    const NQ_WCHAR * host;  /* host name */
    const NQ_WCHAR * user;  /* user name */
    const NQ_WCHAR * domain; /* domain name */
    NQ_UINT32 access;       /* access mask for open policy RPC call */
    CMRpcUuid uuid;         /* result uuid */
    NQ_UINT32 id;           /* result policy ID */
    CMSdAccessToken* token; /* token buffer */
    NQ_BYTE* callParams;    /* parameters for external callbacks */
    CCLsaLookupSidsRequestCallback sidProvider;    /* callback for providing SIDs */
    CCLsaLookupSidsDomainsCallback domainConsumer; /* callback for getting trusted domains */
    CCLsaLookupSidsNamesCallback nameConsumer;     /* callback for getting translated names */
    NQ_UINT32 numSids;      /* number of SIDs */
    NQ_BOOL success;        /* TRUE when name was found */
    CCLsaPolicyInfoDomain *info;
    NQ_UINT32 status;       /* RPC operation status */
}
CallbackParams;

/* pipe descriptor for standard LSA operations */
static const NQ_WCHAR pipeName[] = { cmWChar('l'), cmWChar('s'), cmWChar('a'), cmWChar('r'), cmWChar('p'), cmWChar('c'), cmWChar(0) };
static const CCDcerpcPipeDescriptor pipeDescriptor =
{ pipeName,
  {cmPack32(0x12345778), cmPack16(0x1234), cmPack16(0xabcd), {0xef, 0x00},{0x01,0x23,0x45,0x67,0x89,0xab}},
  cmRpcVersion(0, 0)
};

/* pipe descriptor for DSSETUP LSA operations */
static const NQ_WCHAR pipeNameDs[] = { cmWChar('l'), cmWChar('s'), cmWChar('a'), cmWChar('r'), cmWChar('p'), cmWChar('c'), cmWChar(0) };
static const CCDcerpcPipeDescriptor pipeDescriptorDs =
{ pipeNameDs,
  {cmPack32(0x3919286a), cmPack16(0xb10c), cmPack16(0x11d0), {0x9b, 0xa8},{0x00,0xc0,0x4f,0xd9,0x2e,0xf5}},
  cmRpcVersion(0, 0)
};


/* OpenPolicy2 request callback */

static NQ_COUNT          /* count of outgoing data */
openPolicyRequestCallback (
    NQ_BYTE* buffer,    /* outgoing data buffer */
    NQ_COUNT size,      /* room in the buffer */
    void* params,       /* abstract parameters */
    NQ_BOOL* moreData   /* put here TRUE when more outgoing data available */
    );

/* OpenPolicy2 response callback */

static NQ_STATUS            		/* NQ_SUCCESS or error code */
openPolicyResponseCallback (
    const NQ_BYTE* data,    /* data portion pointer */
    NQ_COUNT size,          /* data portion size */
    void* params,           /* abstract parameters */
    NQ_BOOL moreData        /* TRUE when more data avaiable */
    );

/* LookupNames2 request callback */

static NQ_COUNT                	/* count of outgoing data */
lookupNamesRequestCallback (
    NQ_BYTE* buffer,    /* outgoing data buffer */
    NQ_COUNT size,      /* room in the buffer */
    void* params,       /* abstract parameters */
    NQ_BOOL* moreData   /* put here TRUE when more outgoing data available */
    );

/* LookupNames2 response callback */

static NQ_STATUS                   	/* NQ_SUCCESS or error code */
lookupNamesResponseCallback (
    const NQ_BYTE* data,    /* data portion pointer */
    NQ_COUNT size,          /* data portion size */
    void* params,           /* abstract parameters */
    NQ_BOOL moreData        /* TRUE when more data available */
    );

/* LookupSids2 request callback */

static NQ_COUNT 	             	/* count of outgoing data */
lookupSidsRequestCallback (
    NQ_BYTE* buffer,    /* outgoing data buffer */
    NQ_COUNT size,      /* room in the buffer */
    void* params,       /* abstract parameters */
    NQ_BOOL* moreData   /* put here TRUE when more outgoing data available */
    );

/* LookupSids2 response callback */

static NQ_STATUS                  	/* NQ_SUCCESS or error code */
lookupSidsResponseCallback (
    const NQ_BYTE* data,    /* data portion pointer */
    NQ_COUNT size,          /* data portion size */
    void* params,           /* abstract parameters */
    NQ_BOOL moreData        /* TRUE when more data available */
    );

/* Close request callback */

static NQ_COUNT               		/* count of outgoing data */
closeRequestCallback (
    NQ_BYTE* buffer,    /* outgoing data buffer */
    NQ_COUNT size,      /* room in the buffer */
    void* params,       /* abstract parameters */
    NQ_BOOL* moreData   /* put here TRUE when more outgoing data available */
    );

/* Close response callback */

static NQ_STATUS                   	/* NQ_SUCCESS or error code */
closeResponseCallback (
    const NQ_BYTE* data,    /* data portion pointer */
    NQ_COUNT size,          /* data portion size */
    void* params,           /* abstract parameters */
    NQ_BOOL moreData        /* TRUE when more data available */
    );

static const CCDcerpcPipeDescriptor * ccLsaDsGetPipe(void)
{
    return &pipeDescriptorDs;
}

/*====================================================================
 * PURPOSE: Return this pipe descriptor
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: Pipe descriptor
 *
 * NOTES:
 *====================================================================
 */

const CCDcerpcPipeDescriptor * ccLsaGetPipe(void)
{
    return &pipeDescriptor;
}

/*
 *====================================================================
 * PURPOSE: get name by its SID
 *--------------------------------------------------------------------
 * PARAMS:  IN pipe handle
 *          IN callback function for providing SIDS
 *          IN callback function for saving resolved names
 *          IN number of SIDs to map
 *          IN/OUT abstract parameters for callbacks
 *
 * RETURNS: NQ_SUCCESS always
 *
 * NOTES:
 *====================================================================
 */

NQ_STATUS ccLsaLookupSids(
    NQ_HANDLE pipeHandle,
    CCLsaLookupSidsRequestCallback request,
    CCLsaLookupSidsDomainsCallback domainsPacker,
    CCLsaLookupSidsNamesCallback namesPacker,
    NQ_UINT32 numSids,
    NQ_BYTE * callParams
    )
{
    CallbackParams params;  /* parameters for OpenPolciy2/Close */
    NQ_BOOL res;           /* operation result */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    /* pass parameters */
    params.host = ((CCFile *)pipeHandle)->share->user->server->item.name;
    params.callParams = callParams;
    params.sidProvider = request;
    params.domainConsumer = domainsPacker;
    params.nameConsumer = namesPacker;
    params.numSids = numSids;
    params.access = OPA_LOOKUPNAMES;

    /* open policy handle */
    res  = ccDcerpcCall(pipeHandle, openPolicyRequestCallback, openPolicyResponseCallback, &params);
    if (!res)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Error in processing OpenPolicy2");
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NQ_FAIL;
    }

    /* lookup sids */
    res  = ccDcerpcCall(pipeHandle, lookupSidsRequestCallback, lookupSidsResponseCallback, &params);
    if (!res)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Error in processing LookupSids2");
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NQ_FAIL;
    }

    /* close policy handle - policy params are already inside the param structure */
    res  = ccDcerpcCall(pipeHandle, closeRequestCallback, closeResponseCallback, &params);
    if (!res)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Error in processing Close");
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NQ_FAIL;
    }

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return NQ_SUCCESS;
}

/*
 *====================================================================
 * PURPOSE: get user token by acount name
 *--------------------------------------------------------------------
 * PARAMS:  IN pipe handle
 *          IN user name
 *          IN domain name
 *          OUT buffer for token
 *
 * RETURNS: NQ_SUCCESS or error code
 *
 * NOTES:
 *====================================================================
 */

NQ_STATUS ccLsaGetUserToken(
    NQ_HANDLE pipeHandle,
    const NQ_WCHAR * name,
    const NQ_WCHAR * domain,
    CMSdAccessToken * token
    )
{
    CallbackParams params;  /* parameters for OpenPolicy2/Close */
    NQ_BOOL res;           /* operation result */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    /* pass parameters */
    params.user = name;
    params.domain = domain;
    params.token = token;
    params.host = ((CCFile *)pipeHandle)->share->user->server->item.name;
    params.access = OPA_LOOKUPNAMES;
    params.success = FALSE;

    /* open policy handle */
    res  = ccDcerpcCall(pipeHandle, openPolicyRequestCallback, openPolicyResponseCallback, &params);
    if (!res)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Error in processing OpenPolicy2");
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NQ_FAIL;
    }

    /* lookup names */
    res  = ccDcerpcCall(pipeHandle, lookupNamesRequestCallback, lookupNamesResponseCallback, &params);
    if (!res)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Error in processing LookupNames2");
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NQ_FAIL;
    }

    /* close policy handle - policy params are already inside the param structure */
    res  = ccDcerpcCall(pipeHandle, closeRequestCallback, closeResponseCallback, &params);
    if (!res)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Error in processing Close");
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NQ_FAIL;
    }

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return params.success? NQ_SUCCESS : NQ_FAIL;
}

static NQ_COUNT policyQueryInfoRequestCallback (
    NQ_BYTE* buffer,
    NQ_COUNT size,
    void* params,
    NQ_BOOL* moreData
    )
{
    CMRpcPacketDescriptor d;
    CallbackParams* cp = (CallbackParams *)params;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    cmRpcSetDescriptor(&d, buffer, FALSE);
    cmRpcPackUint16(&d, 7);                 /* query info opcode */

    d.origin = d.current;                   /* for aligment to 4 bytes */

    cmRpcPackUint32(&d, cp->id);            /* policy ID */
    cmRpcPackUuid(&d, &cp->uuid);           /* policy UUID */
    cmRpcPackUint16(&d, 5);                 /* level: domain info (5) */

    *moreData = FALSE;

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return (NQ_COUNT)((d.current - d.origin) + 2);
}

static NQ_STATUS policyQueryInfoResponseCallback (
    const NQ_BYTE* data,
    NQ_COUNT size,
    void* params,
    NQ_BOOL moreData
    )
{
    CMRpcPacketDescriptor d;
    CallbackParams *cp = (CallbackParams*)params;
    CMRpcUnicodeString s;
    NQ_UINT32 ptr;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    cmRpcSetDescriptor(&d, (NQ_BYTE*)data, FALSE);

    cmRpcParseUint32(&d, &ptr);  /* ref ID of info pointer */

    /* only if info pointer not NULL */
    if (ptr != 0)
    {
        cmRpcParseSkip(&d, 2);     /* level (this function supports level 5 only) */
        cmRpcAllign(&d, 4);
        /* ptr to domain name */
        cmRpcParseSkip(&d, 2);     /* length */
        cmRpcParseSkip(&d, 2);     /* size */
        cmRpcParseSkip(&d, 4);     /* ref ID */
        /* ptr to domain SID */
        cmRpcParseSkip(&d, 4);     /* ref ID */
        /* read domain name */    
        cmRpcParseUnicode(&d, &s, CM_RP_SIZE32 | CM_RP_FRAGMENT32);
        cmUnicodeToTcharN(cp->info->name, s.text, sizeof(cp->info->name));
        /* read domain SID */
        cmRpcParseSkip(&d, 4);   /* count */
        cmSdParseSid(&d, &cp->info->sid);
    }

    /* RPC status */
    cmRpcParseUint32(&d, &cp->status);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return (NQ_STATUS)cp->status;
}

static NQ_COUNT dsRoleGetPrimaryDomainInformationRequestCallback (
    NQ_BYTE* buffer,
    NQ_COUNT size,
    void* params,
    NQ_BOOL* moreData
    )
{
    CMRpcPacketDescriptor d;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    cmRpcSetDescriptor(&d, buffer, FALSE);
    cmRpcPackUint16(&d, 0);                 /* opcode */
    cmRpcPackUint16(&d, 1);                 /* level */

    *moreData = FALSE;

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return (NQ_COUNT)((d.current - d.origin));
}

static NQ_STATUS dsRoleGetPrimaryDomainInformationResponseCallback(
    const NQ_BYTE* data,
    NQ_COUNT size,
    void* params,
    NQ_BOOL moreData
    )
{
    CMRpcPacketDescriptor d;
    CallbackParams *cp = (CallbackParams*)params;
    NQ_UINT32 refId;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    cmRpcSetDescriptor(&d, (NQ_BYTE*)data, FALSE);

    cmRpcParseUint32(&d, &refId);  /* ref ID of info pointer */
    if (refId != 0)
    {
        cmRpcParseSkip(&d, 2);     /* level (this function supports level 5 only) */
        cmRpcAllign(&d, 4);
        cmRpcParseSkip(&d, 2);     /* skip role */
        cmRpcAllign(&d, 4);
        cmRpcParseSkip(&d, 4);     /* skip flags */

        cmRpcParseUint32(&d, &refId);
        if (refId != 0)
        {
        	cmRpcParseSkip(&d, 2 * 4); /* skip rest strings refId */
        	cmRpcParseSkip(&d, 16);    /* skip guid */
        	cmRpcParseSkip(&d, 3 * 4); /* skip length + offset + size */
            cmUnicodeToTchar(cp->info->name, (NQ_WCHAR *)d.current);
        }
        cp->status = NQ_SUCCESS;
    }
    else
    	cmRpcParseUint32(&d, &cp->status);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return (NQ_STATUS)cp->status;
}

NQ_UINT32 ccLsaDsRoleGetPrimaryDomainInformation(
	const NQ_WCHAR *server,
	CCLsaPolicyInfoDomain *info
	)
{
    NQ_UINT32 status;
    NQ_HANDLE lsads;

    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL);

    /* connect to LSA DSSETUP */
    if ((lsads = ccDcerpcConnect(server, ccUserGetAdministratorCredentials(), ccLsaDsGetPipe(), TRUE)) != NULL)
    {
        CallbackParams cp;

        cp.info = info;

        /* call LSA::DsRoleGetPrimaryDomainInformation */
        if (ccDcerpcCall(lsads, dsRoleGetPrimaryDomainInformationRequestCallback, dsRoleGetPrimaryDomainInformationResponseCallback, &cp))
        {
            /* store the operation status */
            status = cp.status;
        }
        else
            status = (NQ_UINT32)NQ_ERR_BADPARAM;

        /* close LSA */
        ccCloseHandle(lsads);
    }
    else
        status = (NQ_UINT32)NQ_ERR_NOACCESS;

    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
    return status;
}


NQ_UINT32 ccLsaPolicyQueryInfoDomain(
    const NQ_WCHAR *server,
    CCLsaPolicyInfoDomain *info
    )
{
    NQ_UINT32 status;
    NQ_HANDLE lsa;

    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL);

    /* connect to LSA */
    if ((lsa = ccDcerpcConnect(server, ccUserGetAdministratorCredentials(), ccLsaGetPipe(), TRUE)) != NULL)
    {
        CallbackParams cp;

        /* LSA::OpenPolicy - required parameters: host name, access mask */
        cp.host = ((CCFile *)lsa)->share->user->server->item.name;
        cp.access = OPA_QUERYINFODOMAIN;
        /* call LSA::OpenPolicy */
        if (ccDcerpcCall(lsa, openPolicyRequestCallback, openPolicyResponseCallback, &cp))
        {
            /* LSA::QueryInfoPolicy - required parameters: info structure */
            cp.info = info;
            /* call LSA::QueryInfoPolicy */
            ccDcerpcCall(lsa, policyQueryInfoRequestCallback, policyQueryInfoResponseCallback, &cp);
            /* store the operation status */
            status = cp.status;
            /* call LSA::ClosePolicy */
            ccDcerpcCall(lsa, closeRequestCallback, closeResponseCallback, &cp);
        }
        else
            status = (NQ_UINT32)NQ_ERR_BADPARAM;

        /* close LSA */
        ccCloseHandle(lsa);
    }
    else
        status = (NQ_UINT32)NQ_ERR_NOACCESS;

    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
    return status;
}

/*====================================================================
 * PURPOSE: DCERPC request callback function
 *--------------------------------------------------------------------
 * PARAMS:  OUT buffer for outgoing data
 *          IN buffer size
 *          IN/OUT params
 *          OUT set here TRUE when more data remains
 *
 * RETURNS: number of bytes placed into the buffer or
 *          zero on buffer overflow
 *
 * NOTES:   Composes request
 *====================================================================
 */

static NQ_COUNT openPolicyRequestCallback (
    NQ_BYTE* buffer,
    NQ_COUNT size,
    void* params,
    NQ_BOOL* moreData
    )
{
    CMRpcPacketDescriptor desc;         /* descriptor for SRVSVC request */
    NQ_UINT32 refId;                    /* running referent ID */
    CallbackParams* callParams;         /* casted parameters for callback */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    refId = 1;
    callParams = (CallbackParams*)params;
    cmRpcSetDescriptor(&desc, buffer, FALSE);
    cmRpcPackUint16(&desc, OPENPOLICY_OPNUM);
    desc.origin = desc.current;     /* for alligment to 4 bytes */
    cmRpcPackUint32(&desc, refId);  /* object attributes */
    refId++;
    cmRpcPackUnicode(&desc, callParams->host, (CM_RP_SIZE32 | CM_RP_FRAGMENT32 | CM_RP_NULLTERM));
    cmRpcAllign(&desc, 4);
    cmRpcPackUint32(&desc, 24);     /* length */
    cmRpcPackUint32(&desc, 0);      /* LSPTR pointer */
    cmRpcPackUint32(&desc, 0);      /* NAME pointer */
    cmRpcPackUint32(&desc, 0);      /* attributes */
    cmRpcPackUint32(&desc, 0);      /* LSA SECURITY DESCRIPTOR pointer */
    cmRpcPackUint32(&desc, refId);  /* Quality Of Service object */
    refId++;
    cmRpcPackUint32(&desc, 12);     /* length */
    cmRpcPackUint16(&desc, 2);      /* impersonation level */
    cmRpcPackByte(&desc, 1);        /* context tracking */
    cmRpcPackByte(&desc, 0);        /* effective only */
    cmRpcPackUint32(&desc, callParams->access);     /* access mask */
    *moreData = FALSE;

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return (NQ_COUNT)((desc.current - desc.origin) + 2);
}


/*====================================================================
 * PURPOSE: DCERPC response callback function
 *--------------------------------------------------------------------
 * PARAMS:  IN data portion
 *          IN data length in the portion
 *          IN/OUT params
 *          IN TRUE when more data to come
 *
 * RETURNS: NQ_SUCCESS or error code
 *
 * NOTES:   Parses share names
 *====================================================================
 */

static NQ_STATUS openPolicyResponseCallback (
    const NQ_BYTE* data,
    NQ_COUNT size,
    void* params,
    NQ_BOOL moreData
    )
{
    CMRpcPacketDescriptor desc;         /* descriptor for SRVSVC request */
    CallbackParams* callParams;         /* casted parameters for callback */
    NQ_UINT32 value;                    /* parsed long value */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    if (size < (sizeof(CMRpcUuid) + 4 + 4))
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "response too short, size: %d", size);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return (NQ_STATUS)NQ_FAIL;
    }
    callParams = (CallbackParams*)params;
    cmRpcSetDescriptor(&desc, (NQ_BYTE*)data, FALSE);
    cmRpcParseUint32(&desc, &callParams->id);   /* policy ID */
    cmRpcParseUuid(&desc, &callParams->uuid);   /* policy uuid */
    cmRpcParseUint32(&desc, &value);            /* status */
    if (0 != value)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "unexpected status in response, status: %ld", value);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return (NQ_STATUS)NQ_FAIL;
    }
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return NQ_SUCCESS;
}

/*====================================================================
 * PURPOSE: DCERPC request callback function
 *--------------------------------------------------------------------
 * PARAMS:  OUT buffer for outgoing data
 *          IN buffer size
 *          IN/OUT params
 *          OUT set here TRUE when more data remains
 *
 * RETURNS: number of bytes placed into the buffer or
 *          zero on buffer overflow
 *
 * NOTES:   Composes request
 *====================================================================
 */

static NQ_COUNT closeRequestCallback (
    NQ_BYTE* buffer,
    NQ_COUNT size,
    void* params,
    NQ_BOOL* moreData
    )
{
    CMRpcPacketDescriptor desc;         /* descriptor for SRVSVC request */
    CallbackParams* callParams;         /* casted parameters for callback */

    callParams = (CallbackParams*)params;
    cmRpcSetDescriptor(&desc, buffer, FALSE);
    cmRpcPackUint16(&desc, CLOSE_OPNUM);
    desc.origin = desc.current;     /* for alligment to 4 bytes */
    cmRpcPackUint32(&desc, callParams->id);     /* policy ID */
    cmRpcPackUuid(&desc, &callParams->uuid);     /* policy UUID */
    *moreData = FALSE;

    return (NQ_COUNT)((desc.current - desc.origin) + 2);
}


/*====================================================================
 * PURPOSE: DCERPC response callback function
 *--------------------------------------------------------------------
 * PARAMS:  IN data portion
 *          IN data length in the portion
 *          IN/OUT params
 *          IN TRUE when more data to come
 *
 * RETURNS: NQ_SUCCESS or error code
 *
 * NOTES:   Parses share names
 *====================================================================
 */

static NQ_STATUS closeResponseCallback (
    const NQ_BYTE* data,
    NQ_COUNT size,
    void* params,
    NQ_BOOL moreData
    )
{
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    /* do nothing */

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return NQ_SUCCESS;
}

/*====================================================================
 * PURPOSE: DCERPC request callback function
 *--------------------------------------------------------------------
 * PARAMS:  OUT buffer for outgoing data
 *          IN buffer size
 *          IN/OUT params
 *          OUT set here TRUE when more data remains
 *
 * RETURNS: number of bytes placed into the buffer or
 *          zero on buffer overflow
 *
 * NOTES:   Composes request
 *====================================================================
 */

static NQ_COUNT lookupNamesRequestCallback (
    NQ_BYTE* buffer,
    NQ_COUNT size,
    void* params,
    NQ_BOOL* moreData
    )
{
    CMRpcPacketDescriptor desc;         /* descriptor for SRVSVC request */
    CallbackParams * callParams;         /* casted parameters for callback */
    NQ_UINT32 refId;                    /* running referent ID */
    NQ_WCHAR * accountName;				 /* buffer for qualified account name */
    static const NQ_WCHAR delimiter[] = { cmWChar('@'), cmWChar(0) };
    static const NQ_WCHAR empty[] = { cmWChar(0) };

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    callParams = (CallbackParams*)params;
    if (NULL == callParams->domain)
        callParams->domain = empty;
    accountName = (NQ_WCHAR *)cmMemoryAllocate((NQ_UINT)(sizeof(NQ_WCHAR) *  
        (cmWStrlen(callParams->user) + cmWStrlen(callParams->domain) + 3)));
    if (NULL == accountName)
    {
    	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    	return NQ_ERR_OUTOFMEMORY;
    }
    cmWStrcpy(accountName, callParams->user);
    if (cmWStrchr(accountName, cmWChar('@')) == NULL && cmWStrcmp(callParams->domain, empty) != 0)
    {
        cmWStrcat(accountName, delimiter);
        cmWStrcat(accountName, callParams->domain);
    }
    
    cmRpcSetDescriptor(&desc, buffer, FALSE);
    refId = 1;
    cmRpcPackUint16(&desc, LOOKUPNAMES_OPNUM);
    desc.origin = desc.current;     /* for alligment to 4 bytes */
    cmRpcPackUint32(&desc, callParams->id);     /* policy ID */
    cmRpcPackUuid(&desc, &callParams->uuid);    /* policy UUID */
    cmRpcPackUint32(&desc, 1);                  /* num names */
    cmRpcPackUint32(&desc, 1);                  /* max count */
    cmRpcPackUint16(&desc, (NQ_UINT16)(cmWStrlen(accountName) * sizeof(NQ_WCHAR)));  /* length */
    cmRpcPackUint16(&desc, (NQ_UINT16)(cmWStrlen(accountName) * sizeof(NQ_WCHAR)));  /* maxlen */
    cmRpcPackUint32(&desc, refId);              /* ref id */
    refId++;
    cmRpcPackUnicode(&desc, accountName, (CM_RP_SIZE32 | CM_RP_FRAGMENT32));
    cmRpcPackUint32(&desc, 1);         /* referenced domains count */
    cmRpcPackUint32(&desc, 0);         /* referenced domains ptr */
    cmRpcPackUint32(&desc, 1);         /* level */
    cmRpcPackUint32(&desc, 0);         /* count */
    cmRpcPackUint32(&desc, 0);         /* undocumented */
    cmRpcPackUint32(&desc, 2);         /* undocumented */
    *moreData = FALSE;
    
    cmMemoryFree(accountName);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return (NQ_COUNT)((desc.current - desc.origin) + 2);
}


/*====================================================================
 * PURPOSE: DCERPC response callback function
 *--------------------------------------------------------------------
 * PARAMS:  IN data portion
 *          IN data length in the portion
 *          IN/OUT params
 *          IN TRUE when more data to come
 *
 * RETURNS: NQ_SUCCESS or error code
 *
 * NOTES:   This function discards group RIDs and sets user RID as the 1st one
 *====================================================================
 */

static NQ_STATUS lookupNamesResponseCallback(
	const NQ_BYTE* data,
    NQ_COUNT size,
    void* params,
    NQ_BOOL moreData
    )
{
    CMRpcPacketDescriptor desc;         /* descriptor for SRVSVC request */
    CallbackParams* callParams;         /* casted parameters for callback */
    NQ_UINT32 v32;                      /* parsed long value */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    callParams = (CallbackParams*)params;
    cmRpcSetDescriptor(&desc, (NQ_BYTE*)data, FALSE);

    cmRpcParseSkip(&desc, 4);   /* domain list - ref id */
    cmRpcParseUint32(&desc, &v32);              /* domain list - count */
    if (1 != v32)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "unexpected number of domains in response");
        TRC1P(" num: %ld, should be 1", v32);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return (NQ_STATUS)NQ_FAIL;
    }
    cmRpcParseSkip(&desc, 4);   /* trust info array - ref id */
    cmRpcParseSkip(&desc, 4);   /* trust info array - max count*/
    cmRpcParseUint32(&desc, &v32);              /* trust info array - count*/
    if (1 != v32)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "unexpected number of domains in response");
        TRC1P(" num: %ld, should be 1", v32);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return (NQ_STATUS)NQ_FAIL;
    }
    cmRpcParseSkip(&desc, 2);   /* domain name - LSA name length */
    cmRpcParseSkip(&desc, 2);   /* domain name - LSA max name length */
    cmRpcParseSkip(&desc, 4);   /* domain name - ref id */
    cmRpcParseSkip(&desc, 4);   /* domain sid - ref id */
    cmRpcParseUint32(&desc, &v32);              /* name - max count */
    cmRpcParseSkip(&desc, 4);           /* name - offset */
    cmRpcParseUint32(&desc, &v32);                      /* name - actual count */
    cmRpcParseSkip(&desc, (NQ_UINT32)(v32 * sizeof(NQ_WCHAR)));      /* name - chars */
    cmRpcAllign(&desc, 4);              /* allign */
    cmRpcParseSkip(&desc, 4);           /* sid - count */
    cmSdParseSid(&desc, &callParams->token->domain);    /* sid - value */
    cmRpcParseUint32(&desc, &v32);              /* rids - count */
    if (1 != v32)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "unexpected number of RIDs in response");
        TRC1P(" num: %ld, should be 1", v32);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return (NQ_STATUS)NQ_FAIL;
    }
    cmRpcParseSkip(&desc, 4);   /* rids - ref id */
    cmRpcParseUint32(&desc, &v32);              /* rids - max count */
    if (1 != v32)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "unexpected number of RIDs in response");
        TRC1P(" num: %ld, should be 1", v32);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return (NQ_STATUS)NQ_FAIL;
    }
    cmRpcParseSkip(&desc, 2);               /* rids - SID type */
    cmRpcAllign(&desc, 4);                  /* */
    cmRpcParseUint32(&desc, &callParams->token->rids[0]);       /* rid */
    callParams->token->numRids = 1;                             /* meanwhile */
    callParams->success = TRUE;

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return NQ_SUCCESS;
}


/*====================================================================
 * PURPOSE: DCERPC request callback function
 *--------------------------------------------------------------------
 * PARAMS:  OUT buffer for outgoing data
 *          IN buffer size
 *          IN/OUT params
 *          OUT set here TRUE when more data remains
 *
 * RETURNS: number of bytes placed into the buffer or
 *          zero on buffer overflow
 *
 * NOTES:   Composes request
 *====================================================================
 */

static NQ_COUNT lookupSidsRequestCallback (
    NQ_BYTE* buffer,
    NQ_COUNT size,
    void* params,
    NQ_BOOL* moreData
    )
{
    CMRpcPacketDescriptor desc;         /* descriptor for LSA request */
    CallbackParams* callParams;         /* casted parameters for callback */
    NQ_UINT32 refId;                    /* running referent ID */
    NQ_COUNT i;                         /* generic number */
    CMSdDomainSid sidBuffer;            /* buffer for getting SID */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    callParams = (CallbackParams*)params;
    cmRpcSetDescriptor(&desc, buffer, FALSE);
    refId = 1;
    cmRpcPackUint16(&desc, LOOKUPSIDS_OPNUM);
    desc.origin = desc.current;     /* for alligment to 4 bytes */
    cmRpcPackUint32(&desc, callParams->id);         /* policy ID */
    cmRpcPackUuid(&desc, &callParams->uuid);        /* policy UUID */
    cmRpcPackUint32(&desc, callParams->numSids);    /* num SIDS */
    cmRpcPackUint32(&desc, refId);                  /* ref id for PSID array */
    refId++;
    cmRpcPackUint32(&desc, callParams->numSids);    /* max count */
    for (i = 0; i < callParams->numSids; i++)
    {
        cmRpcPackUint32(&desc, refId);              /* ref id for a SID */
        refId++;
    }
    while ((*callParams->sidProvider)(&sidBuffer, callParams->callParams))
    {
        cmRpcPackUint32(&desc, sidBuffer.numAuths);     /* count */
        cmSdPackSid(&desc, &sidBuffer);
    }
    cmRpcPackUint32(&desc, 0);     /* names pointer count */
    cmRpcPackUint32(&desc, 0);     /* names pointer ref id */
    cmRpcPackUint32(&desc, 1);     /* level */
    cmRpcPackUint32(&desc, 0);     /* num mapped */
    cmRpcPackUint32(&desc, 0);     /* undocumented */
    cmRpcPackUint32(&desc, 2);     /* undocumented */
    *moreData = FALSE;

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return (NQ_COUNT)((desc.current - desc.origin) + 2);
}


/*====================================================================
 * PURPOSE: DCERPC response callback function
 *--------------------------------------------------------------------
 * PARAMS:  IN data portion
 *          IN data length in the portion
 *          IN/OUT params
 *          IN TRUE when more data to come
 *
 * RETURNS: NQ_SUCCESS or error code
 *
 * NOTES:   This function discards group RIDs and sets user RID as the 1st one
 *====================================================================
 */

static NQ_STATUS
lookupSidsResponseCallback (
    const NQ_BYTE* data,
    NQ_COUNT size,
    void* params,
    NQ_BOOL moreData
    )
{
    CMRpcPacketDescriptor desc;         /* descriptor for LSA request */
    CMRpcPacketDescriptor strDesc;      /* descriptor for parsing strings */
    CallbackParams* callParams;         /* casted parameters for callback */
    NQ_UINT32 count;                    /* parsed long value */
    CMSdDomainSid sidBuffer;            /* for parsing SIDs */
    NQ_UINT32 nameId;                   /* read ref id */
    NQ_UINT32 sidId;                    /* read ref id */
    NQ_COUNT i;                         /* just a counter */
    CMRpcUnicodeString unicodeName;     /* Unicode name descriptor */
    static NQ_TCHAR nameT[CM_BUFFERLENGTH(NQ_TCHAR, CM_USERNAMELENGTH)]; /* buffer for name */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    callParams = (CallbackParams*)params;
    cmRpcSetDescriptor(&desc, (NQ_BYTE*)data, FALSE);

    /* parse REFERENCED DOMAIN LIST by just skipping it */
    cmRpcParseUint32(&desc, &nameId);   /* referenced domain list - ref id */
    if (0 != nameId)
    {
        NQ_UINT32 maxCount;     /* available number of domains */

        cmRpcParseUint32(&desc, &count);   /* count */
        cmRpcParseSkip(&desc, 4);   /* trust information array - ref id */
        cmRpcParseSkip(&desc, 4);   /* max count */
        cmRpcParseUint32(&desc, &maxCount);            /* trust information array - max count */
        cmRpcCloneDescriptor(&desc, &strDesc);
        strDesc.current += count * (2 * 2 + 4 * 2);
        for (i = 0; i < count; i++)
        {
            CMRpcUnicodeString nameDescr;               /* domain name descriptor */

            cmRpcParseSkip(&desc, 2);   /* length */
            cmRpcParseSkip(&desc, 2);   /* size */
            cmRpcParseUint32(&desc, &nameId);           /* name - ref id */
            cmRpcParseUint32(&desc, &sidId);            /* sid - ref id */
            if (0 != nameId)
            {
                cmRpcParseUnicode(&strDesc, &nameDescr, CM_RP_SIZE32 | CM_RP_FRAGMENT32);       /* name */
                cmUnicodeToTcharN(nameT, nameDescr.text, nameDescr.length);
                nameT[nameDescr.length] = 0;
            }
            if (0 != sidId)
            {
                cmRpcParseSkip(&strDesc, 4);   /* sid - count */
                cmSdParseSid(&strDesc, &sidBuffer);            /* sid - value */
            }
            (*callParams->domainConsumer)(
                (0 == nameId ? NULL : nameT),
                (0 == sidId ? NULL : &sidBuffer),
                count,
                maxCount,
                callParams->callParams
                );
        }
        desc.current = strDesc.current;
    }
    else
    {
        (*callParams->domainConsumer)(NULL, NULL, 0, 0, callParams->callParams);
    }

    /* parse TRANSLATED NAMES EX */

    cmRpcParseUint32(&desc, &count);            /* count */
    cmRpcParseSkip(&desc, 4);   /* ref id */
    cmRpcParseSkip(&desc, 4);   /* max count */
    cmRpcCloneDescriptor(&desc, &strDesc);
    strDesc.current += count * (2 * 4 + 4 * 3);
    for (i = 0; i < count; i++)
    {
        NQ_UINT16 type;     /* SID type */
        NQ_UINT32 index;    /* SID index */
        NQ_UINT32 reserved; /* undocumented field */

        cmRpcParseUint16(&desc, &type);             /* type */
        cmRpcAllign(&desc, 4);      /* */
        cmRpcParseSkip(&desc, 2);   /* name - length */
        cmRpcParseSkip(&desc, 2);   /* name - size */
        cmRpcParseUint32(&desc, &nameId);             /* name - ref id */
        cmRpcParseUint32(&desc, &index);              /* name - index */
        cmRpcParseUint32(&desc, &reserved);           /* name - unknown */

        if (0 != nameId)
        {
            cmRpcParseUnicode(&strDesc, &unicodeName, (CM_RP_SIZE32 | CM_RP_FRAGMENT32 | CM_RP_NULLTERM));
            cmUnicodeToTcharN(nameT, unicodeName.text, unicodeName.length);
            (*callParams->nameConsumer)(nameT, type, index, reserved, count, callParams->callParams);
        }
        else
        {
            (*callParams->nameConsumer)(NULL, type, index, reserved, count, callParams->callParams);
        }
    }

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return NQ_SUCCESS;
}

#endif /* defined(UD_CC_INCLUDESECURITYDESCRIPTORS) || defined(UD_CC_INCLUDEDOMAINMEMBERSHIP) || defined(UD_CS_INCLUDEPASSTHROUGH) */
