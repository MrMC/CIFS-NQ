/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : SRVSVC pipe
 *--------------------------------------------------------------------
 * MODULE        : CS - CIFS Server
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 23-October-2004
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "csdataba.h"
#include "csauth.h"
#include "cslsarpc.h"
#ifdef UD_CS_INCLUDEPASSTHROUGH
#include "ccapi.h"
#include "ccdcerpc.h"
#include "cclsarpc.h"
#endif /*UD_CS_INCLUDEPASSTHROUGH*/

#ifdef UD_NQ_INCLUDECIFSSERVER

#ifdef UD_CS_INCLUDERPC_LSARPC

#ifndef UD_CS_INCLUDERPC
#error illegal combination of parameters UD_CS_INCLUDERPC_LSARPC (defined) and UD_CS_INCLUDERPC (not defined)
#endif

/*
    Static data and definitions
    ---------------------------
 */

/* Callback parameters for Get name by SID */
#ifdef UD_CS_INCLUDESECURITYDESCRIPTORS
typedef struct {
    const CMSdDomainSid* sid;
    NQ_UINT16 type;
    NQ_COUNT requestCount;
} LookupSids2Params;
#endif /* UD_CS_INCLUDESECURITYDESCRIPTORS */

/* packet sizes - maximum packet sizes not including strings */
#define QUERYINFO_ENTRYSIZE     40
#define LOOKUPNAMES3_ENTRYSIZE    12
#define MAX_NAMESTRANSLATED 20    /* max number of RIDS in a lookup request */
#define MAX_SIDSTRANSLATED 10    /* max number of RIDS in a lookup request */

/* Policy handles */
#define HOSTNAME_HANDLE     1
#define DOMAINNAME_HANDLE   2

/* buffers */
#ifdef UD_CS_INCLUDESECURITYDESCRIPTORS
typedef struct     /* translated names */
{
    NQ_UINT32 index;    /* refrerenced domain index */
    CMSdRid rid;        /* translated rid */
} TranslatedName;
#endif /* UD_CS_INCLUDESECURITYDESCRIPTORS */

typedef struct
{
    NQ_UINT32 fakePolicyHandle;  /* to have different handles for subseq. openings */
    NQ_WCHAR nameW[CM_BUFFERLENGTH(NQ_WCHAR, CM_USERNAMELENGTH)];
    NQ_TCHAR txtBufferT[CM_BUFFERLENGTH(NQ_TCHAR, 256)];
#ifdef UD_CS_INCLUDESECURITYDESCRIPTORS
    NQ_TCHAR fullNameT[CM_BUFFERLENGTH(NQ_TCHAR, 256)];
    TranslatedName translatedNames[MAX_NAMESTRANSLATED];    /* requested/returned RIDS */
    CMSdDomainSid lookupSids[MAX_SIDSTRANSLATED];        /* requested SIDS */
#endif /* UD_CS_INCLUDESECURITYDESCRIPTORS */
}
StaticData;

#ifdef SY_FORCEALLOCATION
static StaticData* staticData = NULL;
#else  /* SY_FORCEALLOCATION */
static StaticData staticDataSrc;
static StaticData* staticData = &staticDataSrc;
#endif /* SY_FORCEALLOCATION */

/* LSA pipe function prototypes */

static NQ_UINT32 lsaClose(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
/* static NQ_UINT32 lsaDelete(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 lsaEnumPrivs(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 lsaQuerySecObj(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 lsaSetSecObj(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 lsaChangePassword(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
static NQ_UINT32 lsaOpenPolicy(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
static NQ_UINT32 lsaOpenPolicy2(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
static NQ_UINT32 lsaQueryInfoPolicy(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
/* static NQ_UINT32 lsaSetInfoPolicy (CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 lsaClearAuditLog(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 lsaCreateAccount(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 lsaEnumAccounts(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 lsaCreateTrustedDomain(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 lsaEnumTrustDom(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 lsaLookupNames(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
#ifdef UD_CS_INCLUDELOCALUSERMANAGEMENT
static NQ_UINT32 lsaLookupNames2(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
#endif /* UD_CS_INCLUDELOCALUSERMANAGEMENT */
/* static NQ_UINT32 lsaLookupSids(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
#ifdef UD_CS_INCLUDESECURITYDESCRIPTORS
static NQ_UINT32 lsaLookupSids2(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
#endif /* UD_CS_INCLUDESECURITYDESCRIPTORS */
/* static NQ_UINT32 lsaCreateSecret(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 lsaOpenAccount(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 lsaEnumPrivsAccount(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 lsaAddPrivilegesToAccount(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 lsaRemovePrivilegesFromAccount(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 lsaGetQuotasForAccount(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 lsaSetQuotasForAccount(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 lsaGetSystemAccessAccount(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 lsaSetSystemAccessAccount(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 lsaOpenTrustedDomain(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 lsaQueryInfoTrustedDomain(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 lsaSetInformationTrustedDomain(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 lsaOpenSecret(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 lsaSetSecret(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 lsaQuerySecret(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 lsaLookupPrivValue(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 lsaLookupPrivName(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 lsaLookupPrivDisplayName(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 lsaDeleteObject(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 lsaEnumAccountsWithUserRight(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 lsaEnumAccountRights(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 lsaAddAccountRights(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 lsaRemoveAccountRights(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 lsaQueryTrustDomainInfo(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 lsaSetTrustDomainInfo(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 lsaDeleteTrustDomain(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 lsaStorePrivateData(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 lsaRetrievePrivateData(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 lsaOpenPolicy2(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 lsaGetUserName(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 lsaQueryInfoPolicy2(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 lsaSetInfoPolicy2(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 lsaQueryTrustedDomainInfoByName(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 lsaSetTrustedDomainInfoByName(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 lsaEnumTrustedDomainsEx(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 lsaCreateTrustedDomainEx(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 lsaCloseTrustedDomainEx(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 lsaQueryDomainInformationPolicy(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 lsaSetDomInfoPolicy(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 lsaOpenTrustedDomainByName(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 lsaTestCal(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 lsaCreateTrustedDomainEx2(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
#ifdef UD_CS_INCLUDELOCALUSERMANAGEMENT
static NQ_UINT32 lsaLookupNames3(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
#endif /* UD_CS_INCLUDELOCALUSERMANAGEMENT */

/* LSA pipe function table */

static const CSRpcFunctionDescriptor lsafuncs[] =
{
    { lsaClose                                                      /* 0x00 */ },
    { NULL /* lsaDelete */                                          /* 0x01 */ },
    { NULL /* lsaEnumPrivs */                                       /* 0x02 */ },
    { NULL /* lsaQuerySecObj */                                     /* 0x03 */ },
    { NULL /* lsaSetSecObj */                                       /* 0x04 */ },
    { NULL /* lsaChangePassword */                                  /* 0x05 */ },
    { lsaOpenPolicy                                                 /* 0x06 */ },
    { lsaQueryInfoPolicy                                            /* 0x07 */ },
    { NULL /* lsaSetInfoPolicy  */                                  /* 0x08 */ },
    { NULL /* lsaClearAuditLog */                                   /* 0x09 */ },
    { NULL /* lsaCreateAccount */                                   /* 0x0a */ },
    { NULL /* lsaEnumAccounts */                                    /* 0x0b */ },
    { NULL /* lsaCreateTrustedDomain */                             /* 0x0c */ },
    { NULL /* lsaEnumTrustDom */                                    /* 0x0d */ },
    { NULL /* lsaLookupNames */                                     /* 0x0e */ },
    { NULL /* lsaLookupSids */                                      /* 0x0f */ },
    { NULL /* lsaCreateSecret */                                    /* 0x10 */ },
    { NULL /* lsaOpenAccount */                                     /* 0x11 */ },
    { NULL /* lsaEnumPrivsAccount */                                /* 0x12 */ },
    { NULL /* lsaAddPrivilegesToAccount */                          /* 0x13 */ },
    { NULL /* lsaRemovePrivilegesFromAccount */                     /* 0x14 */ },
    { NULL /* lsaGetQuotasForAccount */                             /* 0x15 */ },
    { NULL /* lsaSetQuotasForAccount */                             /* 0x16 */ },
    { NULL /* lsaGetSystemAccessAccount */                          /* 0x17 */ },
    { NULL /* lsaSetSystemAccessAccount */                          /* 0x18 */ },
    { NULL /* lsaOpenTrustedDomain */                               /* 0x19 */ },
    { NULL /* lsaQueryInfoTrustedDomain */                          /* 0x1a */ },
    { NULL /* lsaSetInformationTrustedDomain */                     /* 0x1b */ },
    { NULL /* lsaOpenSecret */                                      /* 0x1c */ },
    { NULL /* lsaSetSecret */                                       /* 0x1d */ },
    { NULL /* lsaQuerySecret */                                     /* 0x1e */ },
    { NULL /* lsaLookupPrivValue */                                 /* 0x1f */ },
    { NULL /* lsaLookupPrivName */                                  /* 0x20 */ },
    { NULL /* lsaLookupPrivDisplayName */                           /* 0x21 */ },
    { NULL /* lsaDeleteObject */                                    /* 0x22 */ },
    { NULL /* lsaEnumAccountsWithUserRight */                       /* 0x23 */ },
    { NULL /* lsaEnumAccountRights */                               /* 0x24 */ },
    { NULL /* lsaAddAccountRights */                                /* 0x25 */ },
    { NULL /* lsaRemoveAccountRights */                             /* 0x26 */ },
    { NULL /* lsaQueryTrustDomainInfo */                            /* 0x27 */ },
    { NULL /* lsaSetTrustDomainInfo */                              /* 0x28 */ },
    { NULL /* lsaDeleteTrustDomain */                               /* 0x29 */ },
    { NULL /* lsaStorePrivateData */                                /* 0x2a */ },
    { NULL /* lsaRetrievePrivateData */                             /* 0x2b */ },
    { lsaOpenPolicy2                                                /* 0x2c */ },
    { NULL /* lsaGetUserName */                                     /* 0x2d */ },
    { NULL /* lsaQueryInfoPolicy2 */                                /* 0x2e */ },
    { NULL /* lsaSetInfoPolicy2 */                                  /* 0x2f */ },
    { NULL /* lsaQueryTrustedDomainInfoByName */                    /* 0x30 */ },
    { NULL /* lsaSetTrustedDomainInfoByName */                      /* 0x31 */ },
    { NULL /* lsaEnumTrustedDomainsEx */                            /* 0x32 */ },
    { NULL /* lsaCreateTrustedDomainEx */                           /* 0x33 */ },
    { NULL /* lsaCloseTrustedDomainEx */                            /* 0x34 */ },
    { NULL /* lsaQueryDomainInformationPolicy */                    /* 0x35 */ },
    { NULL /* lsaSetDomInfoPolicy */                                /* 0x36 */ },
    { NULL /* lsaOpenTrustedDomainByName */                         /* 0x37 */ },
    { NULL /* lsaTestCal */                                         /* 0x38 */ },
#ifdef UD_CS_INCLUDESECURITYDESCRIPTORS
    { lsaLookupSids2                                                /* 0x39 */ },
#else /* UD_CS_INCLUDESECURITYDESCRIPTORS */
    { NULL /* lsaLookupSids2 */                                     /* 0x39 */ },
#endif /* UD_CS_INCLUDESECURITYDESCRIPTORS */
#if defined(UD_CS_INCLUDESECURITYDESCRIPTORS) && defined(UD_CS_INCLUDELOCALUSERMANAGEMENT)
    { lsaLookupNames2                                                /* 0x3a */ },
#else /* defined(UD_CS_INCLUDESECURITYDESCRIPTORS) && defined(UD_CS_INCLUDELOCALUSERMANAGEMENT) */
    { NULL /* lsaLookupNames2 */                                    /* 0x3a */ },
#endif /* defined(UD_CS_INCLUDESECURITYDESCRIPTORS) && defined(UD_CS_INCLUDELOCALUSERMANAGEMENT) */
    { NULL /* lsaCreateTrustedDomainEx2 */                          /* 0x3b */ },
    { NULL /* unknown */                                              /* 0x3c */ },
    { NULL /* unknown */                                              /* 0x3d */ },
    { NULL /* unknown */                                              /* 0x3e */ },
    { NULL /* unknown */                                              /* 0x3f */ },
    { NULL /* unknown */                                              /* 0x40 */ },
    { NULL /* unknown */                                              /* 0x41 */ },
    { NULL /* unknown */                                              /* 0x42 */ },
    { NULL /* unknown */                                              /* 0x43 */ },
#if defined(UD_CS_INCLUDESECURITYDESCRIPTORS) && defined(UD_CS_INCLUDELOCALUSERMANAGEMENT)
    { lsaLookupNames3                                                   /* 0x44 */ },
#else /* defined(UD_CS_INCLUDESECURITYDESCRIPTORS) && defined(UD_CS_INCLUDELOCALUSERMANAGEMENT) */
    { NULL /* lsaLookupNames3 */                                    /* 0x39 */ },
#endif /* defined(UD_CS_INCLUDESECURITYDESCRIPTORS) && defined(UD_CS_INCLUDELOCALUSERMANAGEMENT) */
};

static NQ_STATUS    /* initialialization of the open entry table */
initData(
    void
    );

static void            /* release open entry table */
stopData(
    void
    );

static void             /* create UUID by host/domain name */
generatePolicyHandle(
    const NQ_WCHAR* name,           /* host/domain name */
    CMRpcPacketDescriptor *out      /* packet to write to */
    );

static NQ_BOOL          /* analyse policy handle */
isDomainPolicyHandle(
    CMRpcPacketDescriptor *in       /* incoming packet */
    );

#ifdef UD_CS_INCLUDESECURITYDESCRIPTORS
static NQ_UINT16    /* resolve one SID */
resolveSid(
    CMSdDomainSid* sid
    );

#endif /* UD_CS_INCLUDESECURITYDESCRIPTORS */

/* LSA pipe descriptor */

static const CSRpcPipeDescriptor lsa =
{
    initData,
    stopData,
    NULL,
    "lsarpc",
    {cmPack32(0x12345778),cmPack16(0x1234),cmPack16(0xabcd),{0xef,0x00},{0x01,0x23,0x45,0x67,0x89,0xab}},
    cmRpcVersion(0, 0),
    (sizeof(lsafuncs) / sizeof(lsafuncs[0])),
    lsafuncs,
    NULL
};

/* LSA_DS pipe function prototypes */

static NQ_UINT32 lsadsRoleGetDomInfo(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);

/* LSA pipe function table */

static const CSRpcFunctionDescriptor lsadsfuncs[] =
{
    { lsadsRoleGetDomInfo                              /* 0x00 */ }
};

/* LSA_DS pipe descriptor */

static const CSRpcPipeDescriptor lsa_ds =
{
    NULL,
    NULL,
    NULL,
    "lsarpc",
    {cmPack32(0x3919286a),cmPack16(0xb10c),cmPack16(0x11d0),{0x9b,0xa8},{0x00,0xc0,0x4f,0xd9,0x2e,0xf5}},
    cmRpcVersion(0, 0),
    (sizeof(lsadsfuncs) / sizeof(lsadsfuncs[0])),
    lsadsfuncs
};

/* Request callback for LookupSids2 */

/* check domain SID */

#ifdef UD_CS_INCLUDELOCALUSERMANAGEMENT

static const NQ_CHAR*    /* domain name or NULL */
sidHasLocalDomain(
    CMSdDomainSid* pSid    /* full SID including user RID */
    );

#endif /* UD_CS_INCLUDELOCALUSERMANAGEMENT */

#ifdef UD_CS_INCLUDEPASSTHROUGH
#ifdef UD_CS_INCLUDESECURITYDESCRIPTORS

static NQ_BOOL          /* TRUE when next SID was parsed */
lookupSids2RequestCallback(
    CMSdDomainSid* out, /* buffer for SID */
    NQ_BYTE* params     /* pointer to callback parameters */
    );

/* Domain packing callback for LookupSids2 */

static NQ_BOOL
lookupSids2DomainsCallback(
    const NQ_TCHAR* name,       /* next domain name */
    const CMSdDomainSid* sid,   /* trusted domain SID */
    NQ_UINT32 count,            /* total number of names */
    NQ_UINT32 maxCount,         /* total number of names */
    NQ_BYTE* params             /* pointer to parameters */
    );

/* Name packing callback for LookupSids2 */

static NQ_BOOL
lookupSids2NamesCallback(
    const NQ_TCHAR* name,       /* next resolved name */
    NQ_UINT16 type,             /* name type */
    NQ_UINT32 index,            /* name index */
    NQ_UINT32 reserved,         /* unknown value */
    NQ_UINT32 count,            /* total number of names */
    NQ_BYTE* params             /* pointer to callback parameters */
    );

#endif /* UD_CS_INCLUDESECURITYDESCRIPTORS */
#endif /* UD_CS_INCLUDEPASSTHROUGH */

/*====================================================================
 * PURPOSE: Get pipe descriptor
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: pipe descriptor for this pipe
 *
 * NOTES:
 *====================================================================
 */

const CSRpcPipeDescriptor*
csRpcLsa(
    )
{
    return &lsa;
}

/*====================================================================
 * PURPOSE: Get pipe descriptor
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: pipe descriptor for this pipe
 *
 * NOTES:
 *====================================================================
 */

const CSRpcPipeDescriptor*
csRpcLsads(
    )
{
    return &lsa_ds;
}

/*
    Pipe lsafuncs
    --------------

    All pipe lsafuncs have the same signature:

 *====================================================================
 * PURPOSE: A pipe function
 *--------------------------------------------------------------------
 * PARAMS:  IN incoming packet descriptor
 *          OUT outgoing packet descriptor
 *
 * RETURNS: zero on success or error code
 *
 * NOTES:   a pipe function parses incoming packet and packs outgoing
 *          packet
 *====================================================================
 */

/* Open policy */

static NQ_UINT32
lsaOpenPolicy(
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    CMRpcUuid uuid;                 /* returned handle */

    TRCB();

    /* generate fake handle */

    cmRpcPackUint32(out, 1);    /* a referral */
    cmRpcPackUint32(out, staticData->fakePolicyHandle++);
    syMemset((NQ_BYTE*)&uuid, 0, sizeof(uuid));
    cmRpcPackBytes(out, (NQ_BYTE*)&uuid, sizeof(uuid) - sizeof(staticData->fakePolicyHandle));

    TRCE();
    return 0;
}

/* Open policy 2 */

static NQ_UINT32
lsaOpenPolicy2(
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    CMRpcUnicodeString server;      /* requested server name */
    NQ_UINT32 length, access;

    TRCB();

    /* read server name (referent id and unicode string) */
    cmRpcParseSkip(in, 4);
    cmRpcParseUnicode(in, &server, CM_RP_SIZE32 | CM_RP_FRAGMENT32 | CM_RP_NULLTERM);
    /* read object attributes */
    cmRpcParseUint32(in, &length);
    cmRpcParseSkip(in, length);
    /* read access mask */
    cmRpcParseUint32(in, &access);
    generatePolicyHandle(server.text, out);

    TRCE();
    return 0;
}

/* Close policy  */

static NQ_UINT32
lsaClose(
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    CMRpcUuid uuid;                 /* returned handle */

    TRCB();

    cmRpcParseSkip(in, 4);
    cmRpcParseBytes(in, (NQ_BYTE*)&uuid, sizeof(uuid));

    /* pack the result header */

    cmRpcPackUint32(out, 0);                /* referral */
    syMemset(&uuid, 0, sizeof(uuid));
    cmRpcPackBytes(out, (NQ_BYTE*)&uuid, sizeof(uuid));

    TRCE();
    return 0;
}

/* Get policy information by handle */

static NQ_UINT32
lsaQueryInfoPolicy(
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    NQ_UINT16 infoClass;            /* information class */
    NQ_UINT32 referentId;           /* runing number */
    NQ_BOOL isDomain;               /* TRUE for domain policy handle */
#ifdef UD_CS_INCLUDESECURITYDESCRIPTORS
    const CMSdDomainSid* pSid;      /* SID to report */
#endif /* UD_CS_INCLUDESECURITYDESCRIPTORS */
    const NQ_CHAR* name;            /* name to report */

    TRCB();

    /* parse input parameters */

    isDomain = isDomainPolicyHandle(in);
    cmRpcParseUint16(in, &infoClass);

    TRC2P("info class: %d, domain: %s", infoClass, isDomain? "true":"false");

    /* prepare results */

    referentId = 2;                         /* an arbitrary value */

    /* switch by info class */

    switch (infoClass)
    {
    case 3:
    case 5:
        cmRpcPackUint32(out, referentId++);     /* info ref id */
        cmRpcPackUint16(out, infoClass);
        cmRpcPackUint16(out, 0);                /* pad */

        name = isDomain? cmNetBiosGetDomain()->name : cmNetBiosGetHostNameZeroed();
        cmRpcPackUint16(out, (NQ_UINT16)(syStrlen(name)*sizeof(NQ_WCHAR)));
        cmRpcPackUint16(out, (NQ_UINT16)((syStrlen(name) + 1) *sizeof(NQ_WCHAR)));
        cmRpcPackUint32(out, referentId++);     
#ifdef UD_CS_INCLUDESECURITYDESCRIPTORS
        cmRpcPackUint32(out, referentId++);     /* domain SID reference */
#else
        cmRpcPackUint32(out, 0);                /* no SD */
#endif        
        cmRpcPackAsciiAsUnicode(out, name, CM_RP_SIZE32 | CM_RP_FRAGMENT32 | CM_RP_INCMAXCOUNT); /* domain name */
#ifdef UD_CS_INCLUDESECURITYDESCRIPTORS
        pSid = isDomain? cmSdGetDomainSid() : cmSdGetComputerSid();
        cmRpcPackUint32(out, pSid->numAuths);   /* SID auth size */
        cmSdPackSid(out, pSid);                 /* SID */
#endif
        break;
    default:
        cmRpcPackUint32(out, 0);                /* info ref id */
        TRCERR("Unsupported information class");
        TRC1P("  value: %d", infoClass);

        TRCE();
        return CM_RP_FAULTUSERDEFINED;
    }

    TRCE();
    return 0;
}

#ifdef UD_CS_INCLUDESECURITYDESCRIPTORS

static NQ_UINT32
lsaLookupSids2(
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    NQ_UINT32 refId = 20;               /* running ref id */
    CMRpcPacketDescriptor outTemp;      /* temporary descriptor */
    NQ_UINT i;                          /* just a counter */
    NQ_UINT16 infoLevel;                /* info level */
    NQ_UINT32 mappedCount;              /* number of mapped SIDs */
    NQ_UINT32 originalCount;            /* number of required SIDs */
    NQ_UINT16 nameLen;                  /* LSA name length/size */
    NQ_UINT16 type;                     /* sid type */
    NQ_UINT32 domainIndex;              /* trusted domain index */

    TRCB();

    /* skip policy handle */
    cmRpcParseSkip(in, sizeof(CMRpcUuid) + 4);

    /* skip array */
    cmRpcParseUint32(in, &originalCount);   /* get number of SIDs in the request */
    cmRpcParseSkip(in, 4 * 2); /* array ref id + max count */
    cmRpcParseSkip(in, 4 * originalCount); /* skip all SIDs ref ids */

    /* cycle by SIDs and save SIDs */
    mappedCount = 0;
    for (i = 0; i < originalCount; i++)
    {
        cmRpcParseSkip(in, 4); /* count */
        cmSdParseSid(in, &staticData->lookupSids[i]);
    }
    cmRpcParseSkip(in, 4 * 2);  /* name array */
    cmRpcParseUint16(in, &infoLevel);           /* info level */

    switch (infoLevel)
    {
    case 1:
        /* try to resolve SIDs (first pass) and count mapped count */
        /* place referent domain list */
        cmRpcPackUint32(out, refId++);          /* ref id */
        cmRpcCloneDescriptor(out, &outTemp);
        cmRpcPackUint32(out, 0);                /* count */
        cmRpcPackUint32(out, refId++);          /* ref id */
        cmRpcPackUint32(out, 32);                /* max count */
        cmRpcPackUint32(out, 0);                /* max count */
        /* place ref ids for domains */
        for (i = 0; i < originalCount; i++)
        {
            type = resolveSid(&staticData->lookupSids[i]);
            if (CM_SD_RIDTYPE_UNKNOWN != type)
            {
                mappedCount++;
                nameLen = (NQ_UINT16)cmTStrlen(staticData->txtBufferT);
                cmRpcPackUint16(out, (NQ_UINT16)(nameLen * sizeof(NQ_WCHAR)));   /* length */
                cmRpcPackUint16(out, (NQ_UINT16)(nameLen * sizeof(NQ_WCHAR)));   /* size */
                cmRpcPackUint32(out, refId++);                      /* name ref id */
                cmRpcPackUint32(out, refId++);                      /* SID ref id */
            }
        }

        /* place names and SIDs for domains */
        for (i = 0; i < originalCount; i++)
        {
            type = resolveSid(&staticData->lookupSids[i]);
            if (CM_SD_RIDTYPE_UNKNOWN != type)
            {
                cmRpcPackTcharAsUnicode(out, staticData->txtBufferT, CM_RP_SIZE32 | CM_RP_FRAGMENT32);
                staticData->lookupSids[i].numAuths--;
                cmRpcPackUint32(out, staticData->lookupSids[i].numAuths);   /* sid count */
                cmSdPackSid(out, &staticData->lookupSids[i]);               /* domain sid */
                staticData->lookupSids[i].numAuths++;
            }
        }

        /* update counts */
        cmRpcPackUint32(&outTemp, mappedCount);         /* count */
        cmRpcPackSkip(&outTemp, 4);     /* ref id */
        cmRpcPackUint32(&outTemp, 32);                  /* max count */
        cmRpcPackUint32(&outTemp, mappedCount);         /* max count */

        /* place translated names */
        cmRpcPackUint32(out, originalCount);            /* count */
        cmRpcPackUint32(out, refId++);                  /* ref id */
        cmRpcPackUint32(out, originalCount);            /* max count */

        /* place scalars */
        domainIndex = 0;
        for (i = 0; i < originalCount; i++)
        {
            type = resolveSid(&staticData->lookupSids[i]);
            cmRpcPackUint16(out, type);
            cmRpcAllign(out, 4);
            if (type == CM_SD_RIDTYPE_UNKNOWN || type == CM_SD_RIDTYPE_DOMAIN)
            {
                cmRpcPackUint16(out, 0);   /* length */
                cmRpcPackUint16(out, 0);   /* size */
                cmRpcPackUint32(out, 0);   /* name ref id */
            }
            else
            {
                nameLen = (NQ_UINT16)cmWStrlen(staticData->nameW);
                cmRpcPackUint16(out, (NQ_UINT16)(nameLen * sizeof(NQ_WCHAR)));   /* length */
                cmRpcPackUint16(out, (NQ_UINT16)(nameLen * sizeof(NQ_WCHAR)));   /* size */
                cmRpcPackUint32(out, refId++);                      /* name ref id */
            }
            cmRpcPackUint32(out, domainIndex);                  /* index */
            cmRpcPackUint32(out, 0);                            /* undocumented */
            if (CM_SD_RIDTYPE_UNKNOWN != type)
            {
                domainIndex++;
            }
        }

        /* place names */
        for (i = 0; i < originalCount; i++)
        {
            type = resolveSid(&staticData->lookupSids[i]);
            if (CM_SD_RIDTYPE_UNKNOWN != type && CM_SD_RIDTYPE_DOMAIN != type)
            {
                cmRpcPackUnicode(out, staticData->nameW, CM_RP_SIZE32 | CM_RP_FRAGMENT32);
            }
        }
        break;
    default:
        cmRpcPackUint32(out, 0);        /* NULL pointer */
        cmRpcPackUint32(out, 0);        /* NULL pointer */
        cmRpcPackUint32(out, 0);        /* NULL pointer */
        cmRpcPackUint32(out, 0);        /* num mapped */
        TRCE();
        return CM_RP_FAULTUNSUPPORTED;
    }

    /* the rest */
    cmRpcPackUint32(out, mappedCount);

    TRCE();
    return mappedCount == originalCount ? 0 : (mappedCount == 0 ? CM_RP_FAULTNONEMAPPED : CM_RP_FAULTSOMENOTMAPPED);
}

#ifdef UD_CS_INCLUDELOCALUSERMANAGEMENT

static NQ_UINT32
lsaLookupNames2(
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
/* lookup local names only */
    NQ_UINT32 refId = 20;        /* running ref id */
    NQ_UINT32 numNames;            /* number of requested names */
    NQ_UINT32 numMapped;        /* number of found names */
    CMRpcUnicodeString nameDesc;/* requested name descriptor */
    NQ_UINT i;                        /* just a counter */
    NQ_UINT16 nameLen;                /* LSA name length */
    NQ_BOOL isNoDomain = FALSE;            /* TRUE when name with no domain prefix requested */
    NQ_BOOL isComputerDomain = FALSE;    /* TRUE when name with host name prefix requested */
    NQ_UINT32 numDomains;                /* number of referenced domains */

    TRCB();

    /* parse input parameters */
    cmRpcParseSkip(in, sizeof(CMRpcUuid) + 4);    /* skip policy handle */
    cmRpcParseUint32(in, &numNames);               /* get number of SIDs in the request */
    cmRpcParseSkip(in, 4);         /* max count */

    /* parse names */
    if (numNames > sizeof(staticData->translatedNames)/sizeof(staticData->translatedNames[0]))
    {
        numNames = sizeof(staticData->translatedNames)/sizeof(staticData->translatedNames[0]);
    }
    for (i = 0; i < numNames; i++)
    {
        cmRpcParseSkip(in, 2 * 2);     /* name size and length */
        cmRpcParseSkip(in, 4);         /* name ptr */
    }
    numMapped = 0;
    for (i = 0; i < numNames; i++)
    {
        NQ_TCHAR* pName;    /* pointer to requested name */

        cmRpcParseUnicode(in, &nameDesc, CM_RP_SIZE32 | CM_RP_FRAGMENT32 | CM_RP_NULLTERM);
        cmUnicodeToTchar(staticData->txtBufferT, nameDesc.text);
        staticData->txtBufferT[nameDesc.length] = 0;
        pName = cmTStrchr(staticData->txtBufferT, cmTChar('\\'));
        if (pName == NULL)
        {
            isNoDomain = TRUE;
            pName = staticData->txtBufferT;
        }
        else
        {
            NQ_UINT16 nameLen;                                /* host name length */

            isNoDomain = FALSE;
            nameLen = (NQ_UINT16)(pName - staticData->txtBufferT);
            cmAnsiToTchar(staticData->fullNameT, cmNetBiosGetHostNameZeroed());
            if (0 != cmTStrncmp(staticData->fullNameT, staticData->txtBufferT, nameLen))
            {
                cmAnsiToTchar(staticData->fullNameT, cmGetFullHostName());

                if (0 != cmTStrncmp(staticData->fullNameT, staticData->txtBufferT, nameLen))
                {
                    continue;        /* domain not matched */
                }
            }
            pName++;
        }
        if (cmSdLookupName(pName, &staticData->translatedNames[numMapped].rid))
        {
            staticData->translatedNames[numMapped].index = isNoDomain? 0 : 1;
            numMapped++;
        }
    }
    numDomains = 0;
    if (isNoDomain && numMapped > 0) numDomains++;
    if (isComputerDomain && numMapped > 0) numDomains++;

    /* packed header */
    cmRpcPackUint32(out, refId++);      /* response ptr */
    cmRpcPackUint32(out, numDomains);   /* num entries */
    cmRpcPackUint32(out, refId++);      /* ref domain ptr */
    cmRpcPackUint32(out, 32);           /* max entries */
    cmRpcPackUint32(out, numDomains);   /* max count */

    /* packed referenced default domain alias */
    if (isNoDomain && numMapped > 0)
    {
        nameLen = (NQ_UINT16)syStrlen(cmNetBiosGetHostNameZeroed());
        cmRpcPackUint16(out, (NQ_UINT16)(nameLen * sizeof(NQ_WCHAR)));        /* length */
        cmRpcPackUint16(out, (NQ_UINT16)((NQ_UINT16)(nameLen + 1) * sizeof(NQ_WCHAR)));    /* size */
        cmRpcPackUint32(out, refId++);    /* ref domain name ptr */
        cmRpcPackUint32(out, refId++);    /* ref domain sid ptr */
        cmRpcPackAsciiAsUnicode(out, cmNetBiosGetHostNameZeroed(), (CM_RP_SIZE32 | CM_RP_FRAGMENT32 | CM_RP_INCMAXCOUNT));
        cmRpcPackUint32(out, cmSdGetLocalDomainAlias()->numAuths);    /* ref domain SID */
        cmSdPackSid(out, cmSdGetLocalDomainAlias());                /* ref domain SID */
    }

    /* packed referenced computer domain */
    if (isComputerDomain && numMapped > 0)
    {
        nameLen = (NQ_UINT16)syStrlen(cmNetBiosGetHostNameZeroed());
        cmRpcPackUint16(out, (NQ_UINT16)(nameLen * sizeof(NQ_WCHAR)));        /* length */
        cmRpcPackUint16(out, (NQ_UINT16)((NQ_UINT16)(nameLen + 1) * sizeof(NQ_WCHAR)));    /* size */
        cmRpcPackUint32(out, refId++);    /* ref domain name ptr */
        cmRpcPackUint32(out, refId++);    /* ref domain sid ptr */
        cmRpcPackAsciiAsUnicode(out, cmNetBiosGetHostNameZeroed(), (CM_RP_SIZE32 | CM_RP_FRAGMENT32 | CM_RP_INCMAXCOUNT));
        cmRpcPackUint32(out, cmSdGetDomainSid()->numAuths);        /* ref domain SID */
        cmSdPackSid(out, cmSdGetDomainSid());                    /* ref domain SID */
    }

    /* translated SIDS header */
    cmRpcPackUint32(out, numMapped);        /* count */
    if (numMapped == 0)
    {
        cmRpcPackUint32(out, 0);            /* num entries */
        cmRpcPackUint32(out, 0);            /* num mapped */
        TRCE();
        return CM_RP_FAULTNONEMAPPED;
    }
    cmRpcPackUint32(out, refId++);        /* translated names ptr */
    cmRpcPackUint32(out, numMapped);    /* max count */

    /* cycle by entries */
    for (i = 0; i < numMapped; i++)
    {
        cmRpcPackByte(out, (NQ_BYTE)cmSdGetRidType(staticData->translatedNames[i].rid));    /* SID type */
        cmRpcAllign(out, 4);
        cmRpcPackUint32(out, staticData->translatedNames[i].rid);                                /* RID */
        cmRpcPackUint32(out, staticData->translatedNames[i].index);                /* referenced domain index */
        cmRpcPackUint32(out, 0);                                                /* undocumented */
    }
    cmRpcPackUint32(out, numMapped);    /* num entries */

    TRCE();
    return numMapped == numNames? 0 : CM_RP_FAULTSOMENOTMAPPED;
}

static NQ_UINT32
lsaLookupNames3(
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
/* lookup local names only */
    NQ_UINT32 refId = 20;        /* running ref id */
    NQ_UINT32 numNames;            /* number of requested names */
    NQ_UINT32 numMapped;        /* number of found names */
    CMRpcUnicodeString nameDesc;/* requested name descriptor */
    NQ_UINT i;                        /* just a counter */
    NQ_UINT16 nameLen;                /* LSA name length */
    CMSdDomainSid sid;                /* temporary sid */
    NQ_BOOL isNoDomain = FALSE;            /* TRUE when name with no domain prefix requested */
    NQ_BOOL isComputerDomain = FALSE;    /* TRUE when name with host name prefix requested */
    NQ_UINT32 numDomains;                /* number of referenced domains */

    TRCB();

    /* parse input parameters */
    cmRpcParseSkip(in, sizeof(CMRpcUuid) + 4);    /* skip policy handle */
    cmRpcParseUint32(in, &numNames);               /* get number of SIDs in the request */
    cmRpcParseSkip(in, 4);         /* max count */

    /* parse names */
    if (numNames > sizeof(staticData->translatedNames)/sizeof(staticData->translatedNames[0]))
    {
        numNames = sizeof(staticData->translatedNames)/sizeof(staticData->translatedNames[0]);
    }
    for (i = 0; i < numNames; i++)
    {
        cmRpcParseSkip(in, 2 * 2);     /* name size and length */
        cmRpcParseSkip(in, 4);         /* name ptr */
    }
    numMapped = 0;
    for (i = 0; i < numNames; i++)
    {
        NQ_TCHAR* pName;    /* pointer to requested name */

        cmRpcParseUnicode(in, &nameDesc, CM_RP_SIZE32 | CM_RP_FRAGMENT32);
        cmUnicodeToTcharN(staticData->txtBufferT, nameDesc.text, nameDesc.length);
        staticData->txtBufferT[nameDesc.length] = 0;
        pName = cmTStrchr(staticData->txtBufferT, cmTChar('\\'));
        if (pName == NULL)
        {
            isNoDomain = TRUE;
            pName = staticData->txtBufferT;
        }
        else
        {
            NQ_UINT16 nameLen;                                /* host name length */

            isNoDomain = FALSE;
            nameLen = (NQ_UINT16)(pName - staticData->txtBufferT);
            cmAnsiToTchar(staticData->fullNameT, cmNetBiosGetHostNameZeroed());
            if (0 != cmTStrncmp(staticData->fullNameT, staticData->txtBufferT, nameLen))
            {
                cmAnsiToTchar(staticData->fullNameT, cmGetFullHostName());

                if (0 != cmTStrncmp(staticData->fullNameT, staticData->txtBufferT, nameLen))
                {
                    continue;        /* domain not matched */
                }
            }
            else
            {
                isComputerDomain = TRUE;
            }
            pName++;
        }
        if (cmSdLookupName(pName, &staticData->translatedNames[numMapped].rid))
        {
            staticData->translatedNames[numMapped].index = isNoDomain? 0 : 1;
            numMapped++;
        }
    }
    numDomains = 0;
    if (isNoDomain && numMapped > 0) numDomains++;
    if (isComputerDomain && numMapped > 0) numDomains++;

    /* packed header */
    cmRpcPackUint32(out, refId++);        /* response ptr */
    cmRpcPackUint32(out, numDomains);    /* num entries */
    cmRpcPackUint32(out, refId++);        /* ref domain ptr */
    cmRpcPackUint32(out, 32);            /* max entries */
    cmRpcPackUint32(out, numDomains);    /* count ref domains */

    /* packed referenced default domain alias */
    if (isNoDomain && numMapped > 0)
    {
        nameLen = (NQ_UINT16)syStrlen(cmNetBiosGetHostNameZeroed());
        cmRpcPackUint16(out, (NQ_UINT16)(nameLen * sizeof(NQ_WCHAR)));        /* length */
        cmRpcPackUint16(out, (NQ_UINT16)((NQ_UINT16)(nameLen + 1) * sizeof(NQ_WCHAR)));    /* size */
        cmRpcPackUint32(out, refId++);    /* ref domain name ptr */
        cmRpcPackUint32(out, refId++);    /* ref domain sid ptr */
        cmRpcPackAsciiAsUnicode(out, cmNetBiosGetHostNameZeroed(), (CM_RP_SIZE32 | CM_RP_FRAGMENT32 | CM_RP_INCMAXCOUNT));
        cmRpcPackUint32(out, cmSdGetLocalDomainAlias()->numAuths);    /* ref domain SID */
        cmSdPackSid(out, cmSdGetLocalDomainAlias());                /* ref domain SID */
    }

    /* packed referenced computer domain */
    if (isComputerDomain && numMapped > 0)
    {
        nameLen = (NQ_UINT16)syStrlen(cmNetBiosGetHostNameZeroed());
        cmRpcPackUint16(out, (NQ_UINT16)(nameLen * sizeof(NQ_WCHAR)));        /* length */
        cmRpcPackUint16(out, (NQ_UINT16)((NQ_UINT16)(nameLen + 1) * sizeof(NQ_WCHAR)));    /* size */
        cmRpcPackUint32(out, refId++);    /* ref domain name ptr */
        cmRpcPackUint32(out, refId++);    /* ref domain sid ptr */
        cmRpcPackAsciiAsUnicode(out, cmNetBiosGetHostNameZeroed(), (CM_RP_SIZE32 | CM_RP_FRAGMENT32 | CM_RP_INCMAXCOUNT));
        cmRpcPackUint32(out, cmSdGetDomainSid()->numAuths);        /* ref domain SID */
        cmSdPackSid(out, cmSdGetDomainSid());                    /* ref domain SID */
    }

    /* translated names header */
    cmRpcPackUint32(out, numMapped);        /* num entries */
    if (numMapped == 0)
    {
        cmRpcPackUint32(out, 0);            /* num entries */
        cmRpcPackUint32(out, 0);            /* num mapped */        
        TRCE();
        return CM_RP_FAULTNONEMAPPED;
    }
    cmRpcPackUint32(out, refId++);        /* translated names ptr */
    cmRpcPackUint32(out, numMapped);    /* count entries */

    /* cycle by entries */
    for (i = 0; i < numMapped; i++)
    {
        cmRpcPackByte(out, (NQ_BYTE)cmSdGetRidType(staticData->translatedNames[i].rid));    /* SID type */
        cmRpcAllign(out, 4);
        cmRpcPackUint32(out, refId++);                                /* SID ptr */
        cmRpcPackUint32(out, staticData->translatedNames[i].index);                /* referenced domain index */
        cmRpcPackUint32(out, 0);                                    /* undocumented */
    }
    /* cycle by SIDs */
    syMemcpy(&sid, cmSdGetLocalDomainAlias(), sizeof(sid));
    sid.numAuths++;
    for (i = 0; i < numMapped; i++)
    {
        sid.subs[1] = staticData->translatedNames[i].rid;
        cmRpcPackUint32(out, sid.numAuths);
        cmSdPackSid(out, &sid);
    }
    cmRpcPackUint32(out, numMapped);    /* num entries */

    TRCE();
    return numMapped == numNames? 0 : CM_RP_FAULTSOMENOTMAPPED;
}

#endif /* UD_CS_INCLUDELOCALUSERMANAGEMENT */
#endif /* UD_CS_INCLUDESECURITYDESCRIPTORS */

/* machine roles */
#define LSADS_MR_STANDALONEWORKSTATION           0  /* The computer is a workstation that is not a member of a domain. */
#define LSADS_MR_MEMBERWORKSTATION               1  /* The computer is a workstation that is a member of a domain. */
#define LSADS_MR_STANDALONESERVER                2  /* The computer is a server that is not a member of a domain. */
#define LSADS_MR_MEMBERSERVER                    3  /* The computer is a server that is a member of a domain. */
#define LSADS_MR_BACKUPDOMAINCONTROLLER          4  /* The computer is a backup domain controller. */
#define LSADS_MR_PRIMARYDOMAINCONTROLLER         5  /* The computer is a primary domain controller. */

/* lsadsRoleGetDomInfo flags */
#define LSADS_FLAGS_PRIMARY_DOMAIN_GUID_PRESENT  0  /* The DomainGuid member contains a valid domain GUID. */
#define LSADS_FLAGS_PRIMARY_DS_MIXED_MODE        0  /* The directory service is running in mixed mode. This flag is valid only if the LSADS_FLAGS_PRIMARY_DS_RUNNING flag is set. */
#define LSADS_FLAGS_PRIMARY_DS_RUNNING           0  /* The directory service is running on this computer. */
#define LSADS_FLAGS_UPGRADE_IN_PROGRESS          0  /* The computer is being upgraded from a previous version of Windows NT/Windows 2000. */

/* LSA_DS functions */

static NQ_UINT32
lsadsRoleGetDomInfo(
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    NQ_UINT16 level;      /* information level */
    NQ_UINT32 refid = 1;
    const CMNetBiosNameInfo* domain;
    const NQ_CHAR* dnsDomain;
    NQ_BOOL hasDnsDomain;
    NQ_UINT16 i;

    TRCB();

    /* domain names */
    domain = cmNetBiosGetDomain();
    dnsDomain = cmGetFullDomainName();
    hasDnsDomain = NULL != dnsDomain && '\0' != *dnsDomain && '<' != *dnsDomain;

    /* get the information level */
    cmRpcParseUint16(in, &level);

    switch (level)
    {
       case 1:
           cmRpcPackUint32(out, refid++);  /* DOMAIN_INFO referent id */
           cmRpcPackUint16(out, level);    /* write back the information level */
           cmRpcAllign(out, 4);   /* pad */
           /* machine role depends on the configured domain info */
           cmRpcPackUint16(out, domain->isGroup? LSADS_MR_STANDALONESERVER : LSADS_MR_MEMBERSERVER);
           cmRpcAllign(out, 4);   /* pad */
           cmRpcPackUint32(out, 0);        /* no flags (domain UUID does not present) */
           cmRpcPackUint32(out, refid++);  /* NetBios domain name pointer */
           cmRpcPackUint32(out, hasDnsDomain? refid++ : 0);  /* DNS domain pointer */
           cmRpcPackUint32(out, hasDnsDomain? refid++ : 0);  /* DNS forest name pointer */
           /* zero domain uuid */
           for (i = 0; i < 4; i++)
               cmRpcPackUint32(out, 0);
           /* the actual strings (NB name, DNS name, DNS forest name) */
           cmRpcPackAsciiAsUnicode(out, domain->name, CM_RP_SIZE32 | CM_RP_FRAGMENT32 | CM_RP_NULLTERM);
           if (hasDnsDomain)
           {
               cmRpcPackAsciiAsUnicode(out, dnsDomain, CM_RP_SIZE32 | CM_RP_FRAGMENT32 | CM_RP_NULLTERM);
               cmRpcPackAsciiAsUnicode(out, dnsDomain, CM_RP_SIZE32 | CM_RP_FRAGMENT32 | CM_RP_NULLTERM);
           }
           break;
    default:
        TRCERR("Unsupported level");
        TRCE();
        return CM_RP_FAULTNOLEVEL;
    }

    TRCE();
    return 0;
}

/*====================================================================
 * PURPOSE: LSA LookupSids request callback function
 *--------------------------------------------------------------------
 * PARAMS:  OUT buffer for next SID
 *          IN/OUT pointer to callback parameters
 *
 * RETURNS: TRUE when next SID was parsed
 *
 * NOTES:
 *====================================================================
 */

#ifdef UD_CS_INCLUDEPASSTHROUGH

#ifdef UD_CS_INCLUDESECURITYDESCRIPTORS

static NQ_BOOL
    lookupSids2RequestCallback(
    CMSdDomainSid* out,
    NQ_BYTE* abstractParams
    )
{
    LookupSids2Params *params = (LookupSids2Params *)abstractParams;

    if (params->requestCount == 0)
        return FALSE;
    syMemcpy(out, params->sid, sizeof(*out));
    params->type = CM_SD_RIDTYPE_UNKNOWN;
    params->requestCount--;
    return TRUE;
}

/*====================================================================
 * PURPOSE: LSA LookupSids domain packing callback function
 *--------------------------------------------------------------------
 * PARAMS:  IN next domain name
 *          IN next domain SID
 *          IN total domain number
 *          IN max domain number
 *          IN/OUT pointer to callback parameters
 *
 * RETURNS: TRUE always
 *
 * NOTES:   Packs the TRUSTED DOMAINS LIST component of the response
 *====================================================================
 */

static NQ_BOOL
lookupSids2DomainsCallback(
    const NQ_TCHAR* name,
    const CMSdDomainSid* sid,
    NQ_UINT32 count,
    NQ_UINT32 maxCount,
    NQ_BYTE* abstractParams
    )
{
    cmTStrcpy(staticData->txtBufferT, name);
    return TRUE;
}

/*====================================================================
 * PURPOSE: LSA LookupSids name packing callback function
 *--------------------------------------------------------------------
 * PARAMS:  IN next name
 *          IN name type
 *          IN name index
 *          IN unknown parameter
 *          IN total number of names
 *          IN/OUT pointer to callback parameters
 *
 * RETURNS: always
 *
 * NOTES:
 *====================================================================
 */

static NQ_BOOL
lookupSids2NamesCallback(
    const NQ_TCHAR* name,
    NQ_UINT16 type,
    NQ_UINT32 index,
    NQ_UINT32 reserved,
    NQ_UINT32 count,
    NQ_BYTE* abstractParams
    )
{
    LookupSids2Params *params = (LookupSids2Params *)abstractParams;

    if (type != CM_SD_RIDTYPE_UNKNOWN && type != CM_SD_RIDTYPE_DOMAIN)
        cmTcharToUnicode(staticData->nameW, name);
    params->type = type;
    params->requestCount++;
    return TRUE;
}

#endif /* UD_CS_INCLUDESECURITYDESCRIPTORS */
#endif /* UD_CS_INCLUDEPASSTHROUGH */

#ifdef UD_CS_INCLUDELOCALUSERMANAGEMENT

static const NQ_CHAR*
sidHasLocalDomain(
    CMSdDomainSid* pSid
    )
{
    const NQ_CHAR* res = NULL;        /* result pointer */

    pSid->numAuths--;
    if (cmSdIsAnySid(pSid))
        res = cmNetBiosGetHostNameZeroed();
    else if (cmSdIsComputerSid(pSid))
        res = cmNetBiosGetHostNameZeroed();
    pSid->numAuths++;
    return res;
}

#endif /* UD_CS_INCLUDELOCALUSERMANAGEMENT */

/*====================================================================
 * PURPOSE: initialize entry table
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:
 *====================================================================
 */

static NQ_STATUS
initData(
    void
    )
{
    TRCB();

    /* allocate memory */
#ifdef SY_FORCEALLOCATION
    staticData = syCalloc(1, sizeof(*staticData));
    if (NULL == staticData)
    {
        TRCERR("Unable to allocate SPOOLSS table");
        TRCE();
        return NQ_FAIL;
    }
#endif /* SY_FORCEALLOCATION */

    staticData->fakePolicyHandle = 1;
    TRCE();
    return NQ_SUCCESS;
}

/*====================================================================
 * PURPOSE: release entry table
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: None
 *
 * NOTES:
 *====================================================================
 */

static void
stopData(
    void
    )
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

/*====================================================================
 * PURPOSE: create policy handle by host/domain name
 *--------------------------------------------------------------------
 * PARAMS:  IN host/domain name
 *          OUT packet descriptor pointer
 *
 * RETURNS: None
 *
 * NOTES:   20 bytes
 *====================================================================
 */

static void
generatePolicyHandle(
    const NQ_WCHAR* name,
    CMRpcPacketDescriptor *out
    )
{
    NQ_STATIC NQ_CHAR temp[17]; /* string conversion buffer */
    NQ_CHAR* pTemp = temp;      /* pointer in this string */
    CMRpcUuid uuid;             /* uuid */

    cmRpcPackUint32(out, 0);
    cmUnicodeToAnsiN(temp, name, sizeof(temp) - 1);
    if (   temp[0] == '\\' && temp[1] == '\\')
        pTemp += 2;
    if (0 == syStrcmp(cmNetBiosGetHostNameZeroed(), pTemp))
    {
        cmPutSUint16(uuid.timeMid, HOSTNAME_HANDLE);
    }
    else
    {
        cmPutSUint16(uuid.timeMid, DOMAINNAME_HANDLE);
    }
    cmRpcPackUuid(out, &uuid);
}

/*====================================================================
 * PURPOSE: analyse policy handle type
 *--------------------------------------------------------------------
 * PARAMS:  IN packet descriptor pointer
 *
 * RETURNS: TRUE if a domain handle, false if a host handle
 *
 * NOTES:   20 bytes
 *====================================================================
 */

static NQ_BOOL
isDomainPolicyHandle(
    CMRpcPacketDescriptor *in
    )
{
    CMRpcUuid uuid;             /* uuid */
    NQ_UINT16 flag;             /* domain flag */

    cmRpcParseSkip(in, 4);
    cmRpcParseUuid(in, &uuid);
    flag = cmGetSUint16(uuid.timeMid);
    return flag == DOMAINNAME_HANDLE;
}

#ifdef UD_CS_INCLUDESECURITYDESCRIPTORS

/*====================================================================
 * PURPOSE: resolve one SID
 *--------------------------------------------------------------------
 * PARAMS:  IN SID to resolve
 *
 * RETURNS: RID type
 *
 * NOTES:
 *====================================================================
 */

static NQ_UINT16
resolveSid(
    CMSdDomainSid* sid
    )
{
    NQ_UINT16 type;     /* the result */

#ifdef UD_CS_INCLUDELOCALUSERMANAGEMENT
    if (NULL != sidHasLocalDomain(sid))
    {
        const NQ_CHAR* domainName;  /* domain name */
        CMSdRid rid = sid->subs[sid->numAuths - 1]; /* user rid */

        /* local SIDs */
        domainName = sidHasLocalDomain(sid);
        type = (NQ_UINT16)cmSdGetRidType(rid);
        if (!cmSdLookupRid(rid, staticData->txtBufferT, staticData->fullNameT))
            return CM_SD_RIDTYPE_UNKNOWN;
        cmTcharToUnicode(staticData->nameW, staticData->txtBufferT);
        cmAnsiToTchar(staticData->txtBufferT, domainName);
    }
    else
    {
#endif /* UD_CS_INCLUDELOCALUSERMANAGEMENT */
#ifdef UD_CS_INCLUDEPASSTHROUGH
        if (cmNetBiosGetDomain()->isGroup)      /* workgroup - standalone server */
        {
#endif /* UD_CS_INCLUDEPASSTHROUGH */
            return CM_SD_RIDTYPE_UNKNOWN;
#ifdef UD_CS_INCLUDEPASSTHROUGH
        }
        else
        {
            const NQ_CHAR *dc;                  /* DC name */
            NQ_WCHAR * dcW;                     /* DC NQ_WCHAR name*/
            NQ_HANDLE lsa;                      /* LSA open handle */
            LookupSids2Params params;           /* callback parameters for domain SIDs */

            dc = csAuthGetPDCName();
            if (dc == NULL)
            {
                TRCERR("Could not obtain PDC name");
                TRCE();
                return FALSE;
            }
            cmAnsiToTchar(staticData->txtBufferT, dc);
            dcW = cmMemoryAllocate(sizeof(NQ_WCHAR) * (cmTStrlen(staticData->txtBufferT) + 1));
            if (NULL == dcW)
            {
                TRCERR("Out of memory");
                TRCE();
                return 1;
            }
            cmTcharToUnicode(dcW, staticData->txtBufferT);

            lsa = ccDcerpcConnect(dcW, NULL, ccLsaGetPipe(), FALSE);
            cmMemoryFree(dcW);
            if (lsa == NULL)
            {
                TRCERR("Unable to open LSA on PDC");
                TRCE();
                return 1;
            }
            /* prepare parameters */
			params.sid = sid;
			params.requestCount = 1;
            ccLsaLookupSids(
                lsa,
                lookupSids2RequestCallback,
                lookupSids2DomainsCallback,
                lookupSids2NamesCallback,
                1,
                (NQ_BYTE *)&params
                );
            ccDcerpcDisconnect(lsa);
            type = (NQ_UINT16)(params.requestCount == 1? params.type : CM_SD_RIDTYPE_UNKNOWN);
        }
#endif /* UD_CS_INCLUDEPASSTHROUGH */
#ifdef UD_CS_INCLUDELOCALUSERMANAGEMENT
    }
#endif /* UD_CS_INCLUDELOCALUSERMANAGEMENT */
    return type;
}

#endif /* UD_CS_INCLUDESECURITYDESCRIPTORS */

#endif /* UD_CS_INCLUDERPC_LSARPC */

#endif /* UD_NQ_INCLUDECIFSSERVER */

