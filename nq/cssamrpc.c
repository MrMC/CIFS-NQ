/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : SAMR pipe
 *--------------------------------------------------------------------
 * MODULE        : CS - CIFS Server
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 23-October-2004
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "cssamrpc.h"

#include "csdataba.h"
#include "cmsdescr.h"
#include "cmcrypt.h"

#ifdef UD_CS_INCLUDERPC_SAMRPC

#ifndef UD_CS_INCLUDERPC
#error illegal combination of parametsrs UD_CS_INCLUDERPC_SAMRPC (defined) and UD_CS_INCLUDERPC (not defined)
#endif
#ifndef UD_CS_INCLUDESECURITYDESCRIPTORS
#error illegal combination of parametsrs UD_CS_INCLUDERPC_SAMRPC (defined) and UD_CS_INCLUDESECURITYDESCRIPTORS (not defined)
#endif

/*
    Static data and definitions
    ---------------------------
 */

#define CONNECTSERVER_RIGHTS 0x30L   /* supported access rights for Connect:
                                        - Open domain
                                        - Enum domains */
#define OPENDOMAIN_RIGHTS 0xFFFFFFFF/*0x385L*/    /* supported access rights for OpenDoman:
                                        - Open account
                                        - Enum accounts
                                        - Lookup alias
                                        - Lookup info 2
                                        - Loopup info 1 */
#define OPENUSER_RIGHTS 0x70fffL     /* supported access rights for OpenUser:
                                        - Write DAC
                                        - Delete
                                        - Get group membership
                                        - Get groups
                                        - Get attributes
                                        - Get logon info
                                        - Get locale
                                        - Get name, etc. */
#define OPENALIAS_RIGHTS 0x02000fL   /* supported access rights for OpenAlias:
                                        - Read control
                                        - Lookup info
                                        - Get members
                                        - Remove member
                                        - Add member
                                        */
#define CREATEUSER_RIGHTS 0xffffffffL/* supported access rights for CreateUser2 */
#define OPENGROUP_RIGHTS 0x3L        /* supported access rights for OpenDoman:
                                        - Get info
                                        - Lookup info */
#define GROUPACCOUNT_ATTRIBS 7       /* no paasword, disabled, homedir */
#define USERACCOUNT_ATTRIBS    0x210 /* password not expire, normal user */
#define HANDLE_SIGNATURE 0xa5a5      /* unique signature for a "singleton" handle */
#define PSEUDO_DOMAIN "Builtin"
#define USERACCOUNT_DESCRIPTION "Local user"
#define ADMINSGROUP_DESCRIPTION "Local administrators"
#define USERSGROUP_DESCRIPTION "Local users"
#define LOGONHOURS_COUNT 21          /* number of bytes in logon hours bitmask */
#define MAXRIDS_INREQUEST 20         /* max number of RIDS in a lookup request */

/* buffers */

typedef struct
{
    NQ_TCHAR txtBufferT[CM_BUFFERLENGTH(NQ_TCHAR, 256)];
    NQ_TCHAR fullNameT[CM_BUFFERLENGTH(NQ_TCHAR, 256)];
    NQ_TCHAR descriptionT[CM_BUFFERLENGTH(NQ_TCHAR, 256)];
    CMSdSecurityDescriptor sd;           /* temporary security descriptor */
    NQ_UINT32 rids[MAXRIDS_INREQUEST];   /* requested/returned RIDS */
    CMNetBiosNameInfo netbiosName;
    CMSdDomainSid sid;                   /* any sid */
}
StaticData;

#ifdef SY_FORCEALLOCATION
static StaticData* staticData = NULL;
#else  /* SY_FORCEALLOCATION */
static StaticData staticDataSrc;
static StaticData* staticData = &staticDataSrc;
#endif /* SY_FORCEALLOCATION */

/* Account definition structure */

typedef struct
{
    const NQ_CHAR* name;    /* account name */
    CMSdRid rid;            /* account RID */
    NQ_UINT32 acctCtrl;     /* account mask */
}
AccountDef;

#define PWDNOTEXPIRES_ACCOUNT   0x200
#define SERVERTRUCT_ACCOUNT     0x100
#define NORMALUSER_ACCOUNT      0x010

/* supported aliases */

static const AccountDef serverAliases[] = {
    {"Administrators", CM_SD_RIDALIASADMIN, SERVERTRUCT_ACCOUNT},
    {"Users", CM_SD_RIDALIASUSER, SERVERTRUCT_ACCOUNT},
};

/* pipe function prototypes */

/* static NQ_UINT32 samrConnect(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
static NQ_UINT32 samrClose(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
static NQ_UINT32 samrSetSecurity(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
static NQ_UINT32 samrQuerySecurity(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
/* static NQ_UINT32 samrShutdown(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
static NQ_UINT32 samrLookupDomain(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
static NQ_UINT32 samrEnumDomains(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
static NQ_UINT32 samrOpenDomain(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
static NQ_UINT32 samrQueryDomainInfo(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
/* static NQ_UINT32 samrSetDomainInfo(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 samrCreateDomainGroup(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 samrEnumDomainGroups(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 samrCreateUser(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 samrEnumDomainUsers(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 samrCreateDomAlias(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
static NQ_UINT32 samrEnumDomainAliases(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
static NQ_UINT32 samrGetAliasMembership(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
static NQ_UINT32 samrLookupNames(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
static NQ_UINT32 samrLookupRids(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
static NQ_UINT32 samrOpenGroup(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
static NQ_UINT32 samrQueryGroupInfo(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
/* static NQ_UINT32 samrSetGroupInfo(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 samrAddGroupMember(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 samrDeleteDomainGroup(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 samrDeleteGroupMember(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 samrQueryGroupMember(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 samrSetMemberAttributesOfGroup(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
static NQ_UINT32 samrOpenAlias(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
static NQ_UINT32 samrQueryAliasInfo(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
/* static NQ_UINT32 samrSetAliasInfo(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 samrDeleteDomAlias(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
static NQ_UINT32 samrAddAliasMember(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
static NQ_UINT32 samrDeleteAliasMember(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
static NQ_UINT32 samrGetMembersInAlias(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
static NQ_UINT32 samrOpenUser(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
static NQ_UINT32 samrDeleteUser(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
static NQ_UINT32 samrQueryUserInfo(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
static NQ_UINT32 samrSetUserInfo(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
/* static NQ_UINT32 samrChangePasswordUser(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
static NQ_UINT32 samrGetGroupsForUser(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
static NQ_UINT32 samrQueryDisplayInfo(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
/* static NQ_UINT32 samrGetDisplayEnumerationIndex(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 samrTestPrivateFunctionsDomain(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 samrTestPrivateFunctionsUser(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
static NQ_UINT32 samrGetUserPwInfo(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
static NQ_UINT32 samrRemoveMemberFromForeignDomain(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
/* static NQ_UINT32 samrQueryDomainInfo2(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 samrQueryUserInfo2(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
static NQ_UINT32 samrQueryDisplayInfo2(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
/* static NQ_UINT32 samrGetDisplayEnumerationIndex2(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
static NQ_UINT32 samrCreateUser2(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
/* static NQ_UINT32 samrQueryDisplayInfo3(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 samrAddMultipleMembersToAlias(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 samrRemoveMultipleMembersFromAlias(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 samrOemChangePasswordUser2(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 samrChangePasswordUser2(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 samrGetDomPwInfo(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 samrConnect2(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
static NQ_UINT32 samrSetUserInfo2(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
/* static NQ_UINT32 samrSetBootKeyInformation(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 samrGetBootKeyInformation(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 samrConnect3(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
static NQ_UINT32 samrConnect4(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
/* static NQ_UINT32 samrChangePasswordUser3(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
static NQ_UINT32 samrConnect5(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
/* static NQ_UINT32 samrRidToSid(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 samrSetDsrmPassword(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 samrValidatePassword(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */

static const CSRpcFunctionDescriptor functions[] =
{
    { NULL, /* samrConnect */                       /* 0x00 */ },
    { samrClose                                     /* 0x01 */ },
    { samrSetSecurity                               /* 0x02 */ },
    { samrQuerySecurity                             /* 0x03 */ },
    { NULL, /* samrShutdown */                      /* 0x04 */ },
    { samrLookupDomain                              /* 0x05 */ },
    { samrEnumDomains                               /* 0x06 */ },
    { samrOpenDomain                                /* 0x07 */ },
    { samrQueryDomainInfo                           /* 0x08 */ },
    { NULL, /* samrSetDomainInfo */                 /* 0x09 */ },
    { NULL, /* samrCreateDomainGroup */             /* 0x0a */ },
    { NULL, /* samrEnumDomainGroups */              /* 0x0b */ },
    { NULL, /* samrCreateUser */                    /* 0x0c */ },
    { NULL, /* samrEnumDomainUsers */               /* 0x0d */ },
    { NULL, /* samrCreateDomAlias */                /* 0x0e */ },
    { samrEnumDomainAliases                         /* 0x0f */ },
    { samrGetAliasMembership                        /* 0x10 */ },
    { samrLookupNames                               /* 0x11 */ },
    { samrLookupRids                                /* 0x12 */ },
    { samrOpenGroup                                 /* 0x13 */ },
    { samrQueryGroupInfo                            /* 0x14 */ },
    { NULL, /* samrSetGroupInfo */                  /* 0x15 */ },
    { NULL, /* samrAddGroupMember */                /* 0x16 */ },
    { NULL, /* samrDeleteDomainGroup */             /* 0x17 */ },
    { NULL, /* samrDeleteGroupMember */             /* 0x18 */ },
    { NULL, /* samrQueryGroupMember */              /* 0x19 */ },
    { NULL, /* samrSetMemberAttributesOfGroup */    /* 0x1a */ },
    { samrOpenAlias                                 /* 0x1b */ },
    { samrQueryAliasInfo                            /* 0x1c */ },
    { NULL, /* samrSetAliasInfo */                  /* 0x1d */ },
    { NULL, /* samrDeleteDomAlias */                /* 0x1e */ },
    { samrAddAliasMember                            /* 0x1f */ },
    { samrDeleteAliasMember                         /* 0x20 */ },
    { samrGetMembersInAlias                         /* 0x21 */ },
    { samrOpenUser                                  /* 0x22 */ },
    { samrDeleteUser                                /* 0x23 */ },
    { samrQueryUserInfo                             /* 0x24 */ },
    { samrSetUserInfo                               /* 0x25 */ },
    { NULL, /* samrChangePasswordUser */            /* 0x26 */ },
    { samrGetGroupsForUser                          /* 0x27 */ },
    { samrQueryDisplayInfo                          /* 0x28 */ },
    { NULL, /* samrGetDisplayEnumerationIndex */    /* 0x29 */ },
    { NULL, /* samrTestPrivateFunctionsDomain */    /* 0x2a */ },
    { NULL, /* samrTestPrivateFunctionsUser */      /* 0x2b */ },
    { samrGetUserPwInfo                             /* 0x2c */ },
    { samrRemoveMemberFromForeignDomain             /* 0x2d */ },
    { NULL, /* samrQueryDomainInfo2 */              /* 0x2e */ },
    { NULL, /* samrQueryUserInfo2 */                /* 0x2f */ },
    { samrQueryDisplayInfo2                         /* 0x30 */ },
    { NULL, /* samrGetDisplayEnumerationIndex2 */   /* 0x31 */ },
    { samrCreateUser2                               /* 0x32 */ },
    { NULL, /* samrQueryDisplayInfo3 */             /* 0x33 */ },
    { NULL, /* samrAddMultipleMembersToAlias */     /* 0x34 */ },
    { NULL, /* samrRemoveMultipleMembersFromAlias *//* 0x35 */ },
    { NULL, /* samrOemChangePasswordUser2 */        /* 0x36 */ },
    { NULL, /* samrChangePasswordUser2 */           /* 0x37 */ },
    { NULL, /* samrGetDomPwInfo */                  /* 0x38 */ },
    { NULL, /* samrConnect2 */                      /* 0x39 */ },
    { samrSetUserInfo2                              /* 0x3a */ },
    { NULL, /* samrSetBootKeyInformation */         /* 0x3b */ },
    { NULL, /* samrGetBootKeyInformation */         /* 0x3c */ },
    { NULL, /* samrConnect3 */                      /* 0x3d */ },
    { samrConnect4                                  /* 0x3e */ },
    { NULL, /* samrChangePasswordUser3 */           /* 0x3f */ },
    { samrConnect5                                  /* 0x40 */ },
    { NULL, /* samrRidToSid */                      /* 0x41 */ },
    { NULL, /* samrSetDsrmPassword */               /* 0x42 */ },
    { NULL, /* samrValidatePassword */              /* 0x43 */ },
};

static NQ_STATUS    /* initialialization of the open entry table */
initData(
    void
    );

static void         /* release open entry table */
stopData(
    void
    );

static const CSRpcPipeDescriptor pipeDescriptor =
{
  initData,
  stopData,
  NULL,
  "samr",
  {cmPack32(0x12345778),cmPack16(0x1234),cmPack16(0xabcd),{0xef,0x00},{0x01,0x23,0x45,0x67,0x89,0xac}},
  cmRpcVersion(1, 0),
  (sizeof(functions) / sizeof(functions[0])),
  functions,
  NULL
};

/* pack group information */

static NQ_BOOL        /* FALSE if not found */
packGroupInfo(
    CMRpcPacketDescriptor* out, /* outgoing packet descriptor */
    CMSdRid rid,                /* group ID */
    NQ_UINT32 index             /* group index */
    );

/* parse handle with predefined value */

static NQ_UINT32        /* 0 on success, error code on error */
parseSingletonHandle(
    CMRpcPacketDescriptor* in       /* incoming packet descriptor */
    );

/* pack one account entry */

static NQ_UINT32        /* 0 on success, error code on error */
packAccountEntry(
    CMRpcPacketDescriptor* out,     /* outgoing packet descriptor */
    const AccountDef* account,      /* account descriptor */
    NQ_UINT32 infoLevel,            /* info level */
    NQ_UINT32 refId                 /* reference id to use */
    );

/* check that the current user can manage local users */

static NQ_BOOL
canManageUsers(
    const CMRpcPacketDescriptor* in    /* incoming packet descriptor */
    );

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
csRpcSamr(
    )
{
    return &pipeDescriptor;
}

/*
    Pipe functions
    --------------

    All pipe functions have the same signature:

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

/* Connect (4) */

static NQ_UINT32
samrConnect4(
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    CMRpcUnicodeString serverName;              /* requested server name */
    CMRpcUuid uuid;                             /* returned handle */
    NQ_UINT32 accessMask;                       /* required rights */

    TRCB();

    /* parse input parameters */
    cmRpcParseSkip(in, 4);      /* referent ID */
    cmRpcParseUnicode(in, &serverName, CM_RP_SIZE32 | CM_RP_FRAGMENT32 | CM_RP_NULLTERM);
    if (cmHtol16((NQ_WCHAR)('\\')) == *serverName.text)
        cmUnicodeToAnsiN(staticData->netbiosName.name, serverName.text + 2, (NQ_UINT)((serverName.length - 3)* sizeof(NQ_WCHAR)));
    else
        cmUnicodeToAnsiN(staticData->netbiosName.name, serverName.text, (NQ_UINT)((serverName.length - 1) * sizeof(NQ_WCHAR)));
    cmRpcParseSkip(in, 4);
    cmRpcParseUint32(in, &accessMask);
    if (accessMask != (CONNECTSERVER_RIGHTS & accessMask))
    {
        cmRpcPackUint32(out, 0);    /* NULL ref id */
        syMemset(&uuid, 0, sizeof(uuid));
        cmRpcPackUuid(out, &uuid);

        TRCERR("Request for non-existing server");
        TRCE();
        return CM_RP_FAULTLOGONFAILURE;
    }

    /* pack response */

    cmRpcPackUint32(out, 1);    /* uuid ref id */
    cmPutSUint32(uuid.timeLow, HANDLE_SIGNATURE);
    cmPutSUint16(uuid.timeMid, HANDLE_SIGNATURE);
    cmRpcPackUuid(out, &uuid);
    TRCE();
    return 0;
}

/* Connect (5) */

static NQ_UINT32
samrConnect5(
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    CMRpcUnicodeString serverName;              /* requested server name */
    CMRpcUuid uuid;                             /* returned handle */
    NQ_UINT32 accessMask;                       /* required rights */

    TRCB();

    /* parse input parameters */

    cmRpcParseSkip(in, 4);  /* referent ID */
    cmRpcParseUnicode(in, &serverName, CM_RP_SIZE32 | CM_RP_FRAGMENT32 | CM_RP_NULLTERM);
    if (cmHtol16((NQ_WCHAR)('\\')) == *serverName.text)
        cmUnicodeToAnsiN(staticData->netbiosName.name, serverName.text + 2, (NQ_UINT)((serverName.length - 3)* sizeof(NQ_WCHAR)));
    else
        cmUnicodeToAnsiN(staticData->netbiosName.name, serverName.text, (NQ_UINT)((serverName.length - 1) * sizeof(NQ_WCHAR)));
    cmRpcParseUint32(in, &accessMask);
    if (accessMask != (CONNECTSERVER_RIGHTS & accessMask))
    {
        cmRpcPackUint32(out, 1);    /* undocumented */
        cmRpcPackUint32(out, 1);    /* undocumented */
        cmRpcPackUint32(out, 3);    /* undocumented */
        cmRpcPackUint32(out, 0);    /* undocumented */
        cmRpcPackUint32(out, 0);    /* NULL ref id */
        syMemset(&uuid, 0, sizeof(uuid));
        cmRpcPackUuid(out, &uuid);

        TRCERR("Request for non-existing server");
        TRCE();
        return CM_RP_FAULTLOGONFAILURE;
    }

    /* pack response */

    cmRpcPackUint32(out, 1);    /* undocumented */
    cmRpcPackUint32(out, 1);    /* undocumented */
    cmRpcPackUint32(out, 3);    /* undocumented */
    cmRpcPackUint32(out, 0);    /* undocumented */

    cmRpcPackUint32(out, 1);    /* uuid ref id */
    cmPutSUint32(uuid.timeLow, HANDLE_SIGNATURE);
    cmPutSUint16(uuid.timeMid, HANDLE_SIGNATURE);
    cmRpcPackUuid(out, &uuid);
    TRCE();
    return 0;
}

/* Close */

static NQ_UINT32
samrClose(
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    CMRpcUuid uuid;                 /* returned handle */
    NQ_UINT32 retCode;              /* return code */

    TRCB();

    retCode = parseSingletonHandle(in);

    /* NULL handle */

    cmRpcPackUint32(out, 0);    /* NULL ref id */
    syMemset(&uuid, 0, sizeof(uuid));
    cmRpcPackUuid(out, &uuid);

    /* parse input parameters */

    TRCE();
    return retCode;
}

/* OpenDomain */

static NQ_UINT32
samrOpenDomain(
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    CMRpcUuid uuid;                     /* returned handle */
    CMRpcPacketDescriptor outTemp;      /* saved out descriptor */
    NQ_UINT32 accessMask;               /* required rights */
    NQ_UINT32 retCode;                  /* return code */
    CMSdDomainSid domainSid;            /* required domain */
    NQ_BOOL isAny;                      /* TRUE for S-1-5-32 */

    TRCB();

    /* Parse parameters */

    retCode = parseSingletonHandle(in);
    cmRpcParseUint32(in, &accessMask);
    cmRpcParseSkip(in, 4);       /* count */
    cmSdParseSid(in, &domainSid);                /* SID */

    /* NULL handle for error return */

    cmRpcCloneDescriptor(out, &outTemp);
    cmRpcPackUint32(out, 0);    /* NULL ref id */
    syMemset(&uuid, 0, sizeof(uuid));
    cmRpcPackUuid(out, &uuid);

    if (0 != retCode)
    {
        TRCE();
        return retCode;
    }
    if (accessMask != (OPENDOMAIN_RIGHTS & accessMask))
    {
        TRCERR("Unsupported access");
        TRCE();
        return CM_RP_FAULTLOGONFAILURE;
    }
    isAny = cmSdIsAnySid(&domainSid);
    if (!isAny && !cmSdIsComputerSid(&domainSid))
    {
        TRCERR("Unexpected domain");
        TRCE();
        return CM_RP_FAULTLOGONFAILURE;
    }

    /* pack response */

    out->current = outTemp.current;
    cmRpcPackUint32(out, 1);    /* uuid ref id */
    cmPutSUint32(uuid.timeLow, HANDLE_SIGNATURE);
    cmPutSUint16(uuid.timeMid, HANDLE_SIGNATURE);
    cmPutSUint16(uuid.timeHiVersion, (NQ_UINT16)isAny);
    cmRpcPackUuid(out, &uuid);

    TRCE();
    return 0;
}

/* OpenUser */

static NQ_UINT32
samrOpenUser(
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    CMRpcUuid uuid;                     /* returned handle */
    CMRpcPacketDescriptor outTemp;      /* saved out descriptor */
    NQ_UINT32 accessMask;               /* required rights */
    NQ_UINT32 rid;                      /* rid */
    NQ_UINT32 retCode;                  /* return code */

    TRCB();

    /* Parse parameters */

    retCode = parseSingletonHandle(in);
    cmRpcParseUint32(in, &accessMask);
    cmRpcParseUint32(in, &rid);

    /* NULL handle for error return */

    cmRpcCloneDescriptor(out, &outTemp);
    cmRpcPackUint32(out, 0);    /* NULL ref id */
    syMemset(&uuid, 0, sizeof(uuid));
    cmRpcPackUuid(out, &uuid);

    if (0 != retCode)
    {
        TRCE();
        return retCode;
    }
    if (accessMask != (OPENUSER_RIGHTS & accessMask))
    {
        TRCERR("Unsupported access to user account");
        TRC2P(" required: %lx, supported: %lx", accessMask, OPENUSER_RIGHTS);
        TRCE();
        return CM_RP_FAULTLOGONFAILURE;
    }
    if (!udGetUserNameByRid(rid, staticData->txtBufferT, staticData->fullNameT))
    {
        TRCERR("No such user");
        TRC1P(" Rid: %ld", rid);
        TRCE();
        return CM_RP_FAULTLOGONFAILURE;
    }

    /* pack response:
     *    field 'timeLow' in user handle contains RID
     */

    out->current = outTemp.current;
    cmRpcPackUint32(out, 1);    /* uuid ref id */
    cmPutSUint32(uuid.timeLow, rid);
    cmPutSUint16(uuid.timeMid, HANDLE_SIGNATURE);
    cmRpcPackUuid(out, &uuid);

    TRCE();
    return 0;
}

/* OpenAlias */

static NQ_UINT32
samrOpenAlias(
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    CMRpcUuid uuid;                     /* returned handle */
    CMRpcPacketDescriptor outTemp;      /* saved out descriptor */
    NQ_UINT32 accessMask;               /* required rights */
    NQ_UINT32 rid;                      /* rid */
    NQ_UINT32 retCode;                  /* return code */

    TRCB();

    /* Parse parameters */

    cmRpcParseSkip(in, 4);
    cmRpcParseUuid(in, &uuid);
    cmRpcParseUint32(in, &accessMask);
    cmRpcParseUint32(in, &rid);

    /* check parameters */

    retCode = 0;
    if (cmGetSUint16(uuid.timeMid) != HANDLE_SIGNATURE)
    {
        TRCERR("Unexpected handle");
        TRCE();
        retCode = CM_RP_FAULTLOGONFAILURE;
    }
    else if (!(NQ_BOOL)cmGetSUint16(uuid.timeHiVersion))
    {
        TRCERR("Unexpected domain");
        TRCE();
        retCode = CM_RP_FAULTLOGONFAILURE;
    }

    /* NULL handle for error return */

    cmRpcCloneDescriptor(out, &outTemp);
    cmRpcPackUint32(out, 0);    /* NULL ref id */
    syMemset(&uuid, 0, sizeof(uuid));
    cmRpcPackUuid(out, &uuid);

    if (0 != retCode)
    {
        TRCE();
        return retCode;
    }
    if (accessMask != (OPENALIAS_RIGHTS & accessMask))
    {
        TRCERR("Unsupported access to alias");
        TRC2P(" required: %lx, supported: %lx", accessMask, OPENUSER_RIGHTS);
        TRCE();
        return CM_RP_FAULTLOGONFAILURE;
    }

    /* pack response:
     *    field 'timeLow' in user handle contains RID
     */

    out->current = outTemp.current;
    cmRpcPackUint32(out, 1);    /* uuid ref id */
    cmPutSUint32(uuid.timeLow, rid);
    cmPutSUint16(uuid.timeMid, HANDLE_SIGNATURE);
    cmRpcPackUuid(out, &uuid);

    TRCE();
    return 0;
}

/* CreateUser2 */

static NQ_UINT32
samrCreateUser2(
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    CMRpcUuid uuid;                     /* returned handle */
    CMRpcPacketDescriptor outTemp;      /* saved out descriptor */
    NQ_UINT32 acctCtrl;                 /* account attributes */
    NQ_UINT32 accessMask;               /* required rights */
    CMRpcUnicodeString nameDescr;       /* account name descriptor */
    NQ_UINT32 retCode;                  /* return code */
    CMSdRid    rid;                     /* user RID */

    TRCB();

    /* Parse parameters */
    retCode = parseSingletonHandle(in);                               /* handle */
    cmRpcParseSkip(in, 2 * 2 + 4);    /* size + length + name ptr */
    cmRpcParseUnicode(in, &nameDescr, CM_RP_SIZE32 | CM_RP_FRAGMENT32);
    cmUnicodeToTcharN(staticData->txtBufferT, nameDescr.text, (NQ_UINT)(nameDescr.length*sizeof(NQ_WCHAR)));
    staticData->txtBufferT[nameDescr.length] = 0;
    cmRpcAllign(in, 4);
    cmRpcParseUint32(in, &acctCtrl);
    cmRpcParseUint32(in, &accessMask);

    /* NULL handle for error return */

    cmRpcCloneDescriptor(out, &outTemp);
    cmRpcPackUint32(out, 0);    /* NULL ref id */
    syMemset(&uuid, 0, sizeof(uuid));
    cmRpcPackUuid(out, &uuid);
    cmRpcPackUint32(out, 0);    /* right granted */
    cmRpcPackUint32(out, 0);    /* rid */

    if (!canManageUsers(in))
    {
        TRCERR("User is not allowed to modify local users");
        TRCE();
        return CM_RP_FAULTLOGONFAILURE;
    }

    if (0 != retCode)
    {
        TRCE();
        return retCode;
    }
    if (accessMask != (CREATEUSER_RIGHTS & accessMask))
    {
        TRCERR("Unsupported access for creating user account");
        TRC2P(" required: %lx, supported: %lx", accessMask, CREATEUSER_RIGHTS);
        TRCE();
        return CM_RP_FAULTLOGONFAILURE;
    }

    /* create user */

    if (udGetUserRidByName(staticData->txtBufferT, &rid))
    {
        TRCERR("User already exists. Cannot be created");
        TRC1P(" required name: %s", cmTDump(staticData->txtBufferT));
        TRCE();
        return CM_RP_FAULTLOGONFAILURE;
    }
    cmAnsiToTchar(staticData->fullNameT, "");

    if (!udCreateUser(staticData->txtBufferT, staticData->fullNameT, staticData->fullNameT))
    {
        TRCERR("Unable to add user");
        TRC1P(" required name: %s", cmTDump(staticData->txtBufferT));
        TRCE();
        return CM_RP_FAULTLOGONFAILURE;
    }
    if (!udGetUserRidByName(staticData->txtBufferT, &rid))
    {
        TRCERR("User was not added");
        TRC1P(" required name: %s", cmTDump(staticData->txtBufferT));
        TRCE();
        return CM_RP_FAULTLOGONFAILURE;
    }

    /* pack response:
     *    field 'timeLow' in user handle contains RID
     */

    out->current = outTemp.current;
    cmRpcPackUint32(out, 1);    /* uuid ref id */
    cmPutSUint32(uuid.timeLow, rid);
    cmPutSUint16(uuid.timeMid, HANDLE_SIGNATURE);
    cmRpcPackUuid(out, &uuid);           /* policy handle */
    cmRpcPackUint32(out, accessMask);    /* access granted */
    cmRpcPackUint32(out, rid);           /* rid */

    TRCE();
    return 0;
}

/* OpenGroup */

static NQ_UINT32
samrOpenGroup(
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    CMRpcUuid uuid;                     /* returned handle */
    CMRpcPacketDescriptor outTemp;      /* saved out descriptor */
    NQ_UINT32 accessMask;               /* required rights */
    NQ_UINT32 rid;                      /* rid */
    NQ_UINT32 retCode;                  /* return code */

    TRCB();

    /* Parse parameters */

    retCode = parseSingletonHandle(in);
    cmRpcParseUint32(in, &accessMask);
    cmRpcParseUint32(in, &rid);

    /* NULL handle for error return */

    cmRpcCloneDescriptor(out, &outTemp);
    cmRpcPackUint32(out, 0);    /* NULL ref id */
    syMemset(&uuid, 0, sizeof(uuid));
    cmRpcPackUuid(out, &uuid);

    if (0 != retCode)
    {
        TRCE();
        return retCode;
    }
    if (accessMask != (OPENGROUP_RIGHTS & accessMask))
    {
        TRCERR("Unsupported access to user account");
        TRC2P(" required: %lx, supported: %lx", accessMask, OPENUSER_RIGHTS);
        TRCE();
        return CM_RP_FAULTLOGONFAILURE;
    }
    if (!cmSdLookupRid(rid, staticData->txtBufferT, staticData->fullNameT))
    {
        TRCERR("No such user");
        TRC1P(" Rid: %ld", rid);
        TRCE();
        return CM_RP_FAULTLOGONFAILURE;
    }

    /* pack response:
     *    field 'timeLow' in user handle contains RID
     */

    out->current = outTemp.current;
    cmRpcPackUint32(out, 1);    /* uuid ref id */
    cmPutSUint32(uuid.timeLow, rid);
    cmPutSUint16(uuid.timeMid, HANDLE_SIGNATURE);
    cmRpcPackUuid(out, &uuid);

    TRCE();
    return 0;
}

/* EnumDomains */

static NQ_UINT32
samrEnumDomains(
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    CMRpcPacketDescriptor outTemp;      /* saved out descriptor */
    NQ_UINT32 maxSize;                  /* buffer size */
    NQ_UINT32 retCode;                  /* return code */
    NQ_UINT32 refId;                    /* next referent ID */
    NQ_UINT16 nameLen;                  /* host name length */

    TRCB();

    /* Parse parameters */

    retCode = parseSingletonHandle(in);
    cmRpcParseSkip(in, 4);
    cmRpcParseUint32(in, &maxSize);

    /* for error return */

    cmRpcCloneDescriptor(out, &outTemp);
    cmRpcPackUint32(out, 0);    /* NULL resume handle */
    cmRpcPackUint32(out, 0);    /* NULL array */
    cmRpcPackUint32(out, 0);    /* no entries */

    if (0 != retCode)
    {
        TRCE();
        return retCode;
    }

    /* pack response */

    out->current = outTemp.current;
    refId = 1;
    cmRpcPackUint32(out, 2);            /* resume handle */
    cmRpcPackUint32(out, refId++);      /* array */
    cmRpcPackUint32(out, 2);            /* count */
    cmRpcPackUint32(out, refId++);      /* entries */
    cmRpcPackUint32(out, 2);            /* max count */

    cmRpcPackUint32(out, 0);            /* index 1 */
    nameLen = (NQ_UINT16)syStrlen(cmNetBiosGetHostNameZeroed());
    cmRpcPackUint16(out, (NQ_UINT16)(nameLen * sizeof(NQ_WCHAR)));            /* name len 1 */
    cmRpcPackUint16(out, (NQ_UINT16)((NQ_UINT16)(nameLen + 1) * sizeof(NQ_WCHAR)));      /* name size 1 */
    cmRpcPackUint32(out, refId++);      /* name 1 */

    cmRpcPackUint32(out, 0);            /* index 2 */
    nameLen = (NQ_UINT16)syStrlen(PSEUDO_DOMAIN);
    cmRpcPackUint16(out, (NQ_UINT16)(nameLen * sizeof(NQ_WCHAR)));            /* name len 1 */
    cmRpcPackUint16(out, (NQ_UINT16)((NQ_UINT16)(nameLen + 1) * sizeof(NQ_WCHAR)));      /* name size 1 */
    cmRpcPackUint32(out, refId++);      /* name 2 */

    cmRpcPackAsciiAsUnicode(out, cmNetBiosGetHostNameZeroed(), CM_RP_SIZE32 | CM_RP_FRAGMENT32 | CM_RP_INCMAXCOUNT);
    cmRpcAllignZero(out, 4);
    cmRpcPackAsciiAsUnicode(out, PSEUDO_DOMAIN, CM_RP_SIZE32 | CM_RP_FRAGMENT32 | CM_RP_INCMAXCOUNT);
    cmRpcAllignZero(out, 4);
    cmRpcPackUint32(out, 2);            /* num entries */

    TRCE();
    return 0;
}

/* LookupDomain */

static NQ_UINT32
samrLookupDomain(
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    CMRpcPacketDescriptor outTemp;          /* saved out descriptor */
    NQ_UINT32 retCode;                      /* return code */
    CMRpcUnicodeString domainName;          /* requested domain name */

    TRCB();

    /* Parse parameters */

    retCode = parseSingletonHandle(in);
    cmRpcParseSkip(in, 2);    /* length */
    cmRpcParseSkip(in, 2);    /* size */
    cmRpcParseSkip(in, 4);    /* ref id */
    cmRpcParseUnicode(in, &domainName, CM_RP_SIZE32 | CM_RP_FRAGMENT32 | CM_RP_NULLTERM);
    cmUnicodeToAnsiN(staticData->netbiosName.name, domainName.text, (NQ_UINT)(domainName.length * sizeof(NQ_WCHAR)));

    /* for error return */

    cmRpcCloneDescriptor(out, &outTemp);
    cmRpcPackUint32(out, 0);    /* NULL SID */

    if (0 != retCode)
    {
        TRCE();
        return retCode;
    }
    if (0 != syStrcmp(staticData->netbiosName.name, cmNetBiosGetHostNameZeroed()))
    {
        TRCERR("Unsupported access");
        TRCE();
        return CM_RP_FAULTLOGONFAILURE;
    }

    /* pack response */

    out->current = outTemp.current;
    cmRpcPackUint32(out, 1);                /* SID ref id */
    cmRpcPackUint32(out, 4);                /* count */
    cmSdPackSid(out, cmSdGetComputerSid()); /* sid */

    TRCE();
    return 0;
}

/* QueryDisplayInfo */

static NQ_UINT32
samrQueryDisplayInfo(
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    NQ_UINT16 infoLevel;                    /* information level */
    NQ_UINT32 refId;                        /* next referent ID */
    CMRpcPacketDescriptor outTemp;          /* saved out descriptor */
    NQ_UINT16 nameLen;                      /* host name length */
    NQ_BYTE* savedPtr;                      /* saved pointer in packet */
    NQ_UINT32 returnedSize;                 /* size of returned info */
    NQ_UINT32 startIdx;                     /* index to start from */
    NQ_UINT32 nextIdx;                      /* current index */
    NQ_UINT32 numUsers;                     /* number of users */
    NQ_UINT32 maxEntries;                   /* maximum number of users */
    NQ_UINT32 rid;                          /* user RID */

    TRCB();

    /* Parse parameters */

    parseSingletonHandle(in);
    cmRpcParseUint16(in, &infoLevel);   /* level */
    cmRpcAllign(out, 4);
    cmRpcParseUint32(in, &startIdx);    /* startIdx */
    cmRpcParseUint32(in, &maxEntries);  /* max entries */

    /* pack response */

    refId = 1;
    cmRpcCloneDescriptor(out, &outTemp);
    cmRpcPackUint32(out, 0);                /* total size */
    cmRpcPackUint32(out, 0);                /* returned size */
    cmRpcPackUint16(out, infoLevel);        /* level */
    cmRpcAllign(out, 4);
    savedPtr = out->current;

    switch(infoLevel)
    {
    case 1:        /* WELL-KNOWN USERS */
        cmRpcPackUint32(out, 0);                /* count */
        cmRpcPackUint32(out, refId++);          /* array */
        cmRpcPackUint32(out, 0);                /* max count */
        for (nextIdx = startIdx, numUsers = 0;
             numUsers < maxEntries;
             nextIdx++, numUsers++
            )
        {
            if (!udGetUserInfo(nextIdx, &rid, staticData->txtBufferT, staticData->fullNameT, staticData->descriptionT))
            {
                break;
            }
            if (cmRpcSpace(out) < (48 + sizeof(NQ_WCHAR) *
                                        (cmTStrlen(staticData->txtBufferT) +
                                         cmTStrlen(staticData->fullNameT) +
                                         cmTStrlen(staticData->descriptionT)
                                        )
                                   )
               )
            {
                break;
            }
            cmRpcPackUint32(out, nextIdx + 1);            /* next index */
            cmRpcPackUint32(out, rid);                    /* rid */
            cmRpcPackUint32(out, USERACCOUNT_ATTRIBS);    /* account attrib */
            nameLen = (NQ_UINT16)(sizeof(NQ_WCHAR) * cmTStrlen(staticData->txtBufferT));
            cmRpcPackUint16(out, nameLen);                /* length */
            cmRpcPackUint16(out, nameLen);                /* size */
            cmRpcPackUint32(out, refId++);                /* account name */
            nameLen = (NQ_UINT16)(sizeof(NQ_WCHAR) * cmTStrlen(staticData->descriptionT));
            cmRpcPackUint16(out, nameLen);                /* length */
            cmRpcPackUint16(out, nameLen);                /* size */
            cmRpcPackUint32(out, refId++);                /* description */
            nameLen = (NQ_UINT16)(sizeof(NQ_WCHAR) * cmTStrlen(staticData->fullNameT));
            cmRpcPackUint16(out, nameLen);                /* length */
            cmRpcPackUint16(out, nameLen);                /* size */
            cmRpcPackUint32(out, refId++);                /* full name */
        }
        if (numUsers > 0)
        {
            for (nextIdx = startIdx;
                 nextIdx < startIdx + numUsers;
                 nextIdx++
                )
            {
                udGetUserInfo(nextIdx, &rid, staticData->txtBufferT, staticData->fullNameT, staticData->descriptionT);
                cmRpcPackTcharAsUnicode(out, staticData->txtBufferT, CM_RP_SIZE32 | CM_RP_FRAGMENT32);
                cmRpcPackTcharAsUnicode(out, staticData->descriptionT, CM_RP_SIZE32 | CM_RP_FRAGMENT32);
                cmRpcPackTcharAsUnicode(out, staticData->fullNameT, CM_RP_SIZE32 | CM_RP_FRAGMENT32);
            }
            returnedSize = (NQ_UINT32)(out->current - savedPtr);
            cmRpcPackUint32(&outTemp, returnedSize);    /* total size */
            cmRpcPackUint32(&outTemp, returnedSize);    /* returned size */
            cmRpcPackUint16(&outTemp, infoLevel);       /* level */
            cmRpcAllign(&outTemp, 4);
            cmRpcPackUint32(&outTemp, numUsers);    /* count */
            cmRpcPackUint32(&outTemp, refId++);     /* array */
            cmRpcPackUint32(&outTemp, numUsers);    /* max count */
        }
        else
        {
            out->current = outTemp.current;
            cmRpcPackUint32(out, 0);                /* count */
            cmRpcPackUint32(out, 0);                /* returned size */
            cmRpcPackUint32(out, refId++);          /* array */
            cmRpcPackUint32(out, 0);                /* max count */
            cmRpcPackUint32(out, 0);                /* count */
            cmRpcPackUint32(out, 0);                /* NULL array */
        }
        break;
    case 3:        /* GROUPS */
        switch(startIdx)
        {
        case 0:
            if (packGroupInfo(out, CM_SD_RIDGROUPUSERS, startIdx))
            {
                returnedSize = 64; /* undocumented */
            }
            else
            {
                returnedSize = 0;
            }
            cmRpcPackUint32(&outTemp, returnedSize);    /* total size */
            cmRpcPackUint32(&outTemp, returnedSize);    /* returned size */
            break;
        case 1:
            if (packGroupInfo(out, CM_SD_RIDGROUPADMINS, startIdx))
            {
                returnedSize = 64; /* undocumented */
            }
            else
            {
                returnedSize = 0;
            }
            returnedSize = 64; /* undocumented */
            cmRpcPackUint32(&outTemp, returnedSize);    /* total size */
            cmRpcPackUint32(&outTemp, returnedSize);    /* returned size */
            break;
        default:
            cmRpcPackUint32(out, 0);                /* count */
            cmRpcPackUint32(out, 0);                /* ref id */
            return CM_RP_FAULTNOLEVEL;
        }
    }

    TRCE();
    return 0;
}

/* QueryDisplayInfo2 */

static NQ_UINT32
samrQueryDisplayInfo2(
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    return samrQueryDisplayInfo(in, out);
}

/* QueryDomainInfo */

static NQ_UINT32
samrQueryDomainInfo(
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    CMRpcUuid uuid;                         /* domain handle */
    NQ_UINT16 infoLevel;                    /* information level */
    NQ_UINT16 nameLen;                      /* length for various names */
    NQ_UINT32 refId;                        /* next referent ID */
    NQ_BOOL isAny;                          /* TRUE for ANY domain */
    CMRpcPacketDescriptor outTemp;          /* saved out descriptor */

    TRCB();

    /* Parse parameters */

    cmRpcParseSkip(in, 4);
    cmRpcParseUuid(in, &uuid);
    cmRpcParseUint16(in, &infoLevel);    /* level */

    if (cmGetSUint16(uuid.timeMid) != HANDLE_SIGNATURE)
    {
        cmRpcPackUint32(out, 0);    /* NULL pointer */
        TRCERR("Unexpected handle");
        TRCE();
        return CM_RP_FAULTLOGONFAILURE;
    }

    isAny = cmGetSUint16(uuid.timeHiVersion);

    /* for error return */

    cmRpcCloneDescriptor(out, &outTemp);
    cmRpcPackUint32(out, 0);    /* NULL pointer */

    /* pack response */

    out->current = outTemp.current;
    /* pack response */

    refId = 1;
    cmRpcPackUint32(out, refId++);           /* DOMAIN_INFO pointer */
    cmRpcPackUint16(out, infoLevel);         /* level */
    cmRpcAllign(out, 4);
    switch (infoLevel)
    {
       case 2:
           /* relative time */
        cmRpcPackUint16(out, 0);
        cmRpcPackUint16(out, 0);
        cmRpcPackUint16(out, 0);
        cmRpcPackUint16(out, 0x8000);
        /* Undocumented (empty) string */
        cmRpcPackUint16(out, 0);            /* length */
        cmRpcPackUint16(out, 0);            /* size */
        cmRpcPackUint32(out, refId++);      /* string array */
        /* Domain */
        nameLen = (NQ_UINT16)syStrlen(PSEUDO_DOMAIN);
        cmRpcPackUint16(out, (NQ_UINT16)(nameLen * sizeof(NQ_WCHAR)));            /* name len 1 */
        cmRpcPackUint16(out, (NQ_UINT16)((NQ_UINT16)(nameLen + 1) * sizeof(NQ_WCHAR)));      /* name size 1 */
        cmRpcPackUint32(out, refId++);      /* domain string array */
        /* DC */
        cmRpcPackUint16(out, 0);            /* length */
        cmRpcPackUint16(out, 0);            /* size */
        cmRpcPackUint32(out, refId++);      /* string array */
           /* undocumented time */
        cmRpcPackUint16(out, 0xb);
        cmRpcPackUint16(out, 0);
        cmRpcPackUint16(out, 0);
        cmRpcPackUint16(out, 8);
        /* undocumented */
        cmRpcPackUint32(out, 1);
        cmRpcPackUint32(out, 3);
        cmRpcPackByte(out, 1);
        /* accounts */
        cmRpcAllign(out, 4);
        cmRpcPackUint32(out, isAny? 0 : udGetUserCount());  /* num users */
        cmRpcPackUint32(out, isAny? 0 : 1);                 /* num groups */
        cmRpcPackUint32(out, isAny? 0 : sizeof(serverAliases)/sizeof(serverAliases[0]));    /* num aliases */
        /* strings */
        cmRpcPackUint32(out, 0);            /* undocumented string array */
        cmRpcPackUint32(out, 0);            /* undocumented string array */
        cmRpcPackUint32(out, 0);            /* undocumented string array */
        cmRpcPackAsciiAsUnicode(out, PSEUDO_DOMAIN, CM_RP_SIZE32 | CM_RP_FRAGMENT32 | CM_RP_NULLTERM | CM_RP_DECACTCOUNT);
        cmRpcPackUint32(out, 0);            /* DC */
        cmRpcPackUint32(out, 0);            /* DC */
        cmRpcPackUint32(out, 0);            /* DC */
        break;
       default:
        out->current = outTemp.current;
        cmRpcPackUint32(out, 0);        /* NULL pointer */
        TRCERR("Unsupported level");
        TRCE();
        return CM_RP_FAULTNOLEVEL;
       }

    TRCE();
    return 0;
}

/* EnumDomainAliases */

static NQ_UINT32
samrEnumDomainAliases(
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    CMRpcUuid uuid;                         /* domain handle */
    NQ_UINT16 numAliases;                   /* number of aliases to pack */
    NQ_UINT32 retCode;                      /* return code */
    NQ_UINT32 refId;                        /* next referent ID */
    NQ_UINT32 resumeHandle;                 /* alias index to start from */
    NQ_UINT32 acctCtrl;                     /* account property mask */
    CMRpcPacketDescriptor outTemp;          /* saved out descriptor */
    NQ_INT i;                               /* just a counter */
    NQ_BOOL isAny;                          /* TRUE for ANY domain */

    TRCB();

    /* Parse parameters */

    cmRpcParseSkip(in, 4);
    cmRpcParseUuid(in, &uuid);

    if (cmGetSUint16(uuid.timeMid) != HANDLE_SIGNATURE)
    {
        cmRpcPackUint32(out, 0);    /* NULL pointer */
        TRCERR("Unexpected handle");
        TRCE();
        return CM_RP_FAULTLOGONFAILURE;
    }

    isAny = cmGetSUint16(uuid.timeHiVersion);
    cmRpcParseUint32(in, &resumeHandle);    /* resume handle */
    cmRpcParseUint32(in, &acctCtrl);        /* Acct Ctrl */

    /* for error return */

    cmRpcCloneDescriptor(out, &outTemp);
    cmRpcPackUint32(out, 0);    /* resume handle */
    cmRpcPackUint32(out, 0);    /* NULL pointer */
    cmRpcPackUint32(out, 0);    /* entries */

    /* pack response */

    out->current = outTemp.current;
    refId = 1;
    numAliases = isAny? sizeof(serverAliases)/sizeof(serverAliases[0]) : 0;
    cmRpcPackUint32(out, numAliases);                   /* resume handle */
    cmRpcPackUint32(out, refId++);                      /* array pointer */
    cmRpcPackUint32(out, numAliases - resumeHandle);    /* count */
    cmRpcPackUint32(out, refId++);                      /* IDX_AND_NAME pointer */
    cmRpcPackUint32(out, numAliases);                   /* max count */
    for (i = 0; i < numAliases; i++)
    {
        if (acctCtrl & serverAliases[i].acctCtrl)
        {
            retCode = packAccountEntry(out, &serverAliases[i], 0, refId++);
            if (0 != retCode)
            {
                out->current = outTemp.current;
                cmRpcPackUint32(out, 0);    /* resume handle */
                cmRpcPackUint32(out, 0);    /* NULL pointer */
                cmRpcPackUint32(out, 0);    /* entries */
                TRCE();
                return retCode;
            }
        }
    }
    for (i = 0; i < numAliases; i++)
    {
        if (acctCtrl & serverAliases[i].acctCtrl)
        {
            cmRpcPackAsciiAsUnicode(out, serverAliases[i].name, CM_RP_SIZE32 | CM_RP_FRAGMENT32);
        }
    }
    cmRpcPackUint32(out, numAliases);        /* entries */

    TRCE();
    return 0;
}

/* LookupNames */

static NQ_UINT32
samrLookupNames(
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    CMRpcUuid uuid;                         /* parsed handle */
    NQ_UINT32 numNames;                     /* number of names to look for */
    NQ_UINT32 maxCount;                     /* maximum number of entries */
    NQ_UINT32 retCode;                      /* return code */
    NQ_UINT32 numMapped;                    /* number of names mapped */
    NQ_UINT32 refId;                        /* next referent ID */
    NQ_UINT32 nextRid;                      /* next user RID */
    CMRpcPacketDescriptor outTemp;          /* saved out descriptor */
    NQ_UINT i;                              /* just a counter */
    CMRpcUnicodeString nameDescr;           /* Unicode name descriptor */
    NQ_BOOL isAny;                          /* TRUE for ANY domain */

    TRCB();

    /* Parse parameters */
    cmRpcParseSkip(in, 4);
    cmRpcParseUuid(in, &uuid);
    retCode = cmGetSUint16(uuid.timeMid) == HANDLE_SIGNATURE? 0 : CM_RP_FAULTLOGONFAILURE;
    isAny = cmGetSUint16(uuid.timeHiVersion);
    cmRpcParseUint32(in, &numNames);        /* count */
    cmRpcParseUint32(in, &maxCount);        /* max count */
    cmRpcParseSkip(in, 4);  /* offset */
    cmRpcParseSkip(in, 4);  /* actual count */

    /* for error return */

    cmRpcCloneDescriptor(out, &outTemp);
    cmRpcPackUint32(out, 0);    /* rid count */
    cmRpcPackUint32(out, 0);    /* ref id */
    cmRpcPackUint32(out, 0);    /* type count  */
    cmRpcPackUint32(out, 0);    /* ref id */

    if (0 != retCode)
    {
        TRCE();
        return retCode;
    }

    /* cycle by names to look for */

    out->current = outTemp.current;
    refId = 1;
    cmRpcPackUint32(out, 0);            /* rid count */
    cmRpcPackUint32(out, 0);            /* ref id */
    cmRpcPackUint32(out, 0);            /* max count or type count on error */
    if (maxCount < numNames)
        numNames = maxCount;
    if (MAXRIDS_INREQUEST < numNames)
        numNames = MAXRIDS_INREQUEST;
    numMapped = 0;
    for (i = 0; i < numNames; i++)
    {
        /* parse next name */
        cmRpcParseSkip(in, 2);    /* length */
        cmRpcParseSkip(in, 2);    /* size */
        cmRpcParseSkip(in, 4);    /* ref id */
        cmRpcParseUnicode(in, &nameDescr, CM_RP_SIZE32 | CM_RP_FRAGMENT32 | CM_RP_NULLTERM);
        cmUnicodeToTchar(staticData->txtBufferT, nameDescr.text);

        /* pack response */
        if (    cmSdLookupName(staticData->txtBufferT, &nextRid)
            && (isAny || (nextRid != CM_SD_RIDALIASADMIN && nextRid != CM_SD_RIDALIASUSER))
           )
        {
            cmRpcPackUint32(out, nextRid);      /* rid */
            numMapped++;
            staticData->rids[i] = nextRid;
        }
        else
        {
            cmRpcPackUint32(out, 0);            /* NULL rid */
            staticData->rids[i] = 0;
        }
    }
    if (0 == numMapped)
    {
        out->current = outTemp.current;
        cmRpcPackUint32(out, 0);    /* rid count */
        cmRpcPackUint32(out, 0);    /* ref id */
        cmRpcPackUint32(out, 0);    /* type count  */
        cmRpcPackUint32(out, 0);    /* ref id */

        TRCE();
        return CM_RP_FAULTNONEMAPPED;
    }

    /* types */
    cmRpcPackUint32(out, numNames);            /* type count */
    cmRpcPackUint32(out, refId + 2);           /* type ref id */
    cmRpcPackUint32(out, numNames);            /* max count */
    for (i = 0; i < numNames; i++)
    {
        cmRpcPackUint32(out, cmSdGetRidType(staticData->rids[i]));
    }
    cmRpcPackUint32(&outTemp, numNames);    /* rid count - now real */
    cmRpcPackUint32(&outTemp, refId + 1);   /* rid ref id - now real */
    cmRpcPackUint32(&outTemp, numNames);    /* rid max count - now real */

    TRCE();
    return numMapped == numNames? 0 : CM_RP_FAULTSOMENOTMAPPED;
}

/* LookupRids */

static NQ_UINT32
samrLookupRids(
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    NQ_UINT32 numRids;                      /* number of RIDs to look for */
    NQ_UINT32 maxCount;                     /* maximum number of entries */
    NQ_UINT32 retCode;                      /* return code */
    NQ_UINT32 numMapped;                    /* number of names mapped */
    NQ_UINT32 refId;                        /* next referent ID */
    CMRpcPacketDescriptor outTemp;          /* saved out descriptor */
    NQ_UINT i;                              /* just a counter */
    NQ_UINT16 nameLen;                      /* length for various names */

    TRCB();

    /* Parse parameters */

    retCode = parseSingletonHandle(in);
    cmRpcParseUint32(in, &numRids);         /* count */
    cmRpcParseUint32(in, &maxCount);        /* max count */
    cmRpcParseSkip(in, 4);  /* offset */
    cmRpcParseSkip(in, 4);  /* actual count */
    if (MAXRIDS_INREQUEST < numRids)
        numRids = MAXRIDS_INREQUEST;
    for (i = 0; i < numRids; i++)
    {
        cmRpcParseUint32(in, &staticData->rids[i]);        /* next rid */
    }

    /* for error return */

    cmRpcCloneDescriptor(out, &outTemp);
    cmRpcPackUint32(out, 0);    /* rid count */
    cmRpcPackUint32(out, 0);    /* ref id */
    cmRpcPackUint32(out, 0);    /* type count  */
    cmRpcPackUint32(out, 0);    /* ref id */

    if (0 != retCode)
    {
        TRCE();
        return retCode;
    }

    /* cycle by RIDS to look for */

    out->current = outTemp.current;
    refId = 1;
    cmRpcPackUint32(out, 0);            /* rid count */
    cmRpcPackUint32(out, 0);            /* ref id */
    cmRpcPackUint32(out, 0);            /* max count or type count on error */
    if (maxCount < numRids)
        numRids = maxCount;
    numMapped = 0;

    /* place name array */
    for (i = 0; i < numRids; i++)
    {
        if (cmSdLookupRid(staticData->rids[i], staticData->txtBufferT, staticData->fullNameT))
        {
            numMapped++;
            nameLen = (NQ_UINT16)cmTStrlen(staticData->txtBufferT);
            cmRpcPackUint16(out, (NQ_UINT16)(nameLen * sizeof(NQ_WCHAR)));    /* name len 1 */
            cmRpcPackUint16(out, (NQ_UINT16)(nameLen * sizeof(NQ_WCHAR)));    /* name size 1 */
            cmRpcPackUint32(out, refId++);                       /* name string */
        }
    }
    if (0 == numMapped)
    {
        out->current = outTemp.current;
        cmRpcPackUint32(out, 0);    /* rid count */
        cmRpcPackUint32(out, 0);    /* ref id */
        cmRpcPackUint32(out, 0);    /* type count  */
        cmRpcPackUint32(out, 0);    /* ref id */

        TRCE();
        return CM_RP_FAULTNONEMAPPED;
    }

    /* place strings */
    for (i = 0; i < numRids; i++)
    {
        if (cmSdLookupRid(staticData->rids[i], staticData->txtBufferT, staticData->fullNameT))
        {
            cmRpcPackTcharAsUnicode(out, staticData->txtBufferT, CM_RP_SIZE32 | CM_RP_FRAGMENT32);
        }
    }

    /* place types */
    cmRpcPackUint32(out, numMapped);    /* count */
    cmRpcPackUint32(out, refId++);      /* ref id */
    cmRpcPackUint32(out, numMapped);    /* max count */
    for (i = 0; i < numRids; i++)
    {
        if (cmSdLookupRid(staticData->rids[i], staticData->txtBufferT, staticData->fullNameT))
        {
            cmRpcPackUint32(out, cmSdGetRidType(staticData->rids[i]));
        }
    }

    cmRpcPackUint32(&outTemp, numMapped);    /* rid count - now real */
    cmRpcPackUint32(&outTemp, refId++);      /* rid ref id - now real */
    cmRpcPackUint32(&outTemp, numMapped);    /* rid max count - now real */

    TRCE();
    return numMapped == numRids? 0 : CM_RP_FAULTSOMENOTMAPPED;
}

/* QueryAliasInfo */

static NQ_UINT32
samrQueryAliasInfo(
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    NQ_UINT32 alias;                    /* RID for required alias */
    NQ_UINT16 infoLevel;                /* information level */
    NQ_UINT32 refId;                    /* next referent ID */
    CMRpcUuid uuid;                     /* parsed user handle */
    NQ_UINT16 nameLen;                  /* name length */
    NQ_UINT nextIdx;                    /* user index */
    NQ_UINT32 numUsers;                 /* member count */

    TRCB();

    /* Parse parameters */
    cmRpcParseSkip(in, 4);
    cmRpcParseUuid(in, &uuid);
    if (cmGetSUint16(uuid.timeMid) != HANDLE_SIGNATURE)
    {
        cmRpcPackUint32(out, 0);    /* ref id */
        TRCERR("Unexpected handle");
        TRCE();
        return CM_RP_FAULTLOGONFAILURE;
    }
    alias = cmGetSUint32(uuid.timeLow);
    for (nextIdx = 0, numUsers = 0;
         numUsers < 100000;
         nextIdx++
        )
    {
        CMSdRid rid;        /* next rid */
        if (!udGetUserInfo(nextIdx, &rid, staticData->txtBufferT, staticData->fullNameT, staticData->descriptionT))
        {
            break;
        }
        if (alias == CM_SD_RIDALIASADMIN)
        {
            if (cmSdIsAdmin(rid))
                numUsers++;
        }
        else
            numUsers++;
    }
    if (!cmSdLookupRid(alias, staticData->txtBufferT, staticData->fullNameT))
    {
        cmRpcPackUint32(out, 0);    /* ref id */
        TRCERR("No such alias");
        TRC1P(" Rid: %ld", alias);
        TRCE();
        return CM_RP_FAULTLOGONFAILURE;
    }
    cmRpcParseUint16(in, &infoLevel);        /* level */

    /* pack the response */

    refId = 1;
    switch (infoLevel)
    {
    case 1:
        cmRpcPackUint32(out, refId++);          /* ref id */
        cmRpcPackUint16(out, infoLevel);        /* level */
        cmRpcAllign(out, 4);
        nameLen = (NQ_UINT16)cmTStrlen(staticData->txtBufferT);
        cmRpcPackUint16(out, (NQ_UINT16)(nameLen * sizeof(NQ_WCHAR)));   /* account name len */
        cmRpcPackUint16(out, (NQ_UINT16)(nameLen * sizeof(NQ_WCHAR)));   /* account name size */
        cmRpcPackUint32(out, refId++);            /* account name ref id */
        nameLen = (NQ_UINT16)cmTStrlen(staticData->fullNameT);
        cmRpcPackUint32(out, numUsers);
        cmRpcPackUint16(out, (NQ_UINT16)(nameLen * sizeof(NQ_WCHAR)));   /* full name len */
        cmRpcPackUint16(out, (NQ_UINT16)(nameLen * sizeof(NQ_WCHAR)));   /* full name size */
        cmRpcPackUint32(out, refId++);            /* full name ref id */
        cmRpcPackTcharAsUnicode(out, staticData->txtBufferT, CM_RP_SIZE32 | CM_RP_FRAGMENT32);    /* account name */
        cmRpcAllign(out, 4);
        cmRpcPackTcharAsUnicode(out, staticData->fullNameT, CM_RP_SIZE32 | CM_RP_FRAGMENT32);    /* full name */
        break;
	case 3:
        cmRpcPackUint32(out, refId++);          /* ref id */
        cmRpcPackUint16(out, infoLevel);        /* level */
        cmRpcAllign(out, 4);
        nameLen = (NQ_UINT16)syStrlen(USERACCOUNT_DESCRIPTION);
        cmRpcPackUint16(out, (NQ_UINT16)(nameLen * sizeof(NQ_WCHAR)));    /* account description len */
        cmRpcPackUint16(out, (NQ_UINT16)(nameLen * sizeof(NQ_WCHAR)));    /* account description size */
        cmRpcPackUint32(out, refId++);          /* account descripton ref id */
		cmRpcPackAsciiAsUnicode(out, USERACCOUNT_DESCRIPTION, CM_RP_SIZE32 | CM_RP_FRAGMENT32);    /* account description */
		cmRpcAllign(out, 4);
		break;
    default:
        cmRpcPackUint32(out, 0);    /* ref id */
        TRCERR("Information level not supported");
        TRC1P(" level: %d", infoLevel);
        TRCE();
        return CM_RP_FAULTNOLEVEL;
    }

    TRCE();
    return 0;
}

/* QueryUserInfo */

static NQ_UINT32
samrQueryUserInfo(
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    NQ_UINT32 rid;                      /* RID for queried user */
    NQ_UINT16 infoLevel;                /* information level */
    NQ_UINT32 refId;                    /* next referent ID */
    CMRpcUuid uuid;                     /* parsed user handle */
    NQ_UINT16 nameLen;                  /* name length */
    NQ_UINT i;                          /* just a counter */

    TRCB();

    /* Parse parameters */
    cmRpcParseSkip(in, 4);
    cmRpcParseUuid(in, &uuid);
    if (cmGetSUint16(uuid.timeMid) != HANDLE_SIGNATURE)
    {
        cmRpcPackUint32(out, 0);    /* ref id */
        TRCERR("Unexpected handle");
        TRCE();
        return CM_RP_FAULTLOGONFAILURE;
    }
    rid = cmGetSUint32(uuid.timeLow);
    if (!udGetUserNameByRid(rid, staticData->txtBufferT, staticData->fullNameT))
    {
        cmRpcPackUint32(out, 0);    /* ref id */
        TRCERR("No such user");
        TRC1P(" Rid: %ld", rid);
        TRCE();
        return CM_RP_FAULTLOGONFAILURE;
    }
    cmRpcParseUint16(in, &infoLevel);        /* level */

    /* pack the response */

    refId = 1;
    switch (infoLevel)
    {
    case 16:
        cmRpcPackUint32(out, refId++);          /* ref id */
        cmRpcPackUint16(out, infoLevel);        /* level */
        cmRpcAllign(out, 4);
        cmRpcPackUint32(out, 0x10);             /* account controls */
        break;
    case 21:
        cmRpcPackUint32(out, refId++);          /* ref id */
        cmRpcPackUint16(out, infoLevel);        /* level */
        cmRpcAllign(out, 4);
        cmRpcPackUint64(out, 0, 0);             /* logon time */
        cmRpcPackUint64(out, 0, 0);             /* logoff time */
        cmRpcPackTimeAsUTC(out, (NQ_TIME)syGetTime());   /* password last set */
        cmRpcPackUint64(out, 0, 0);             /* password expires */
        cmRpcPackTimeAsUTC(out, (NQ_TIME)syGetTime());   /* password can change */
        cmRpcPackUint64(out, 0xFFFFFFFF, 0x7FFFFFFF); /* password must change */
        nameLen = (NQ_UINT16)cmTStrlen(staticData->txtBufferT);
        cmRpcPackUint16(out, (NQ_UINT16)(nameLen * sizeof(NQ_WCHAR)));   /* account name len */
        cmRpcPackUint16(out, (NQ_UINT16)(nameLen * sizeof(NQ_WCHAR)));   /* account name size */
        cmRpcPackUint32(out, refId++);          /* account name ref id */
        nameLen = (NQ_UINT16)cmTStrlen(staticData->fullNameT);
        cmRpcPackUint16(out, (NQ_UINT16)(nameLen * sizeof(NQ_WCHAR)));   /* full name len */
        cmRpcPackUint16(out, (NQ_UINT16)(nameLen * sizeof(NQ_WCHAR)));   /* full name size */
        cmRpcPackUint32(out, refId++);          /* full name ref id */
        cmRpcPackUint16(out, 0);                /* home len */
        cmRpcPackUint16(out, 0);                /* home size */
        cmRpcPackUint32(out, refId++);          /* home ref id */
        cmRpcPackUint16(out, 0);                /* home drive len */
        cmRpcPackUint16(out, 0);                /* home drive size */
        cmRpcPackUint32(out, refId++);          /* home drive ref id */
        cmRpcPackUint16(out, 0);                /* script len */
        cmRpcPackUint16(out, 0);                /* script size */
        cmRpcPackUint32(out, refId++);          /* script ref id */
        cmRpcPackUint16(out, 0);                /* profile len */
        cmRpcPackUint16(out, 0);                /* profile size */
        cmRpcPackUint32(out, refId++);          /* profile ref id */
        nameLen = (NQ_UINT16)syStrlen(USERACCOUNT_DESCRIPTION);
        cmRpcPackUint16(out, (NQ_UINT16)(nameLen * sizeof(NQ_WCHAR)));    /* account description len */
        cmRpcPackUint16(out, (NQ_UINT16)(nameLen * sizeof(NQ_WCHAR)));    /* account description size */
        cmRpcPackUint32(out, refId++);          /* account descripton ref id */
        cmRpcPackUint16(out, 0);                /* workstations len */
        cmRpcPackUint16(out, 0);                /* workstations size */
        cmRpcPackUint32(out, refId++);          /* workstations ref id */
        cmRpcPackUint16(out, 0);                /* account comments len */
        cmRpcPackUint16(out, 0);                /* account comments size */
        cmRpcPackUint32(out, refId++);          /* account comments ref id */
        cmRpcPackUint16(out, 0);                /* callback len */
        cmRpcPackUint16(out, 0);                /* callback size */
        cmRpcPackUint32(out, refId++);          /* callback ref id */
        cmRpcPackUint16(out, 0);                /* unknown string len */
        cmRpcPackUint16(out, 0);                /* unknown string size */
        cmRpcPackUint32(out, 0);                /* unknown string (NULL) ref id */
        cmRpcPackUint16(out, 0);                /* unknown string len */
        cmRpcPackUint16(out, 0);                /* unknown string size */
        cmRpcPackUint32(out, 0);                /* unknown string (NULL) ref id */
        cmRpcPackUint16(out, 0);                /* unknown string len */
        cmRpcPackUint16(out, 0);                /* unknown string size */
        cmRpcPackUint32(out, 0);                /* unknown string (NULL) ref id */
        cmRpcPackUint32(out, 0);                /* buffer - count */
        cmRpcPackUint32(out, 0);                /* buffer - (NULL) ref id */
        cmRpcPackUint32(out, rid);              /* rid */
        cmRpcPackUint32(out, cmSdIsAdmin(rid)? CM_SD_RIDGROUPADMINS : CM_SD_RIDGROUPUSERS); /* primary group rid */
        cmRpcPackUint32(out, PWDNOTEXPIRES_ACCOUNT | NORMALUSER_ACCOUNT);    /* account control */
        cmRpcPackUint32(out, 0x00ffffff);       /* fields present */
        cmRpcPackUint16(out, 168);              /* logon hours - divisions */
        cmRpcAllignZero(out, 4);
        cmRpcPackUint32(out, refId++);          /* logon hours - ref id */
        cmRpcPackUint16(out, 0);                /* bad password count */
        cmRpcPackUint16(out, 0);                /* logon count */
        cmRpcPackUint16(out, 0);                /* country (default) */
        cmRpcPackUint16(out, 0);                /* codepage (default) */
        cmRpcPackByte(out, 0);                  /* NT password set */
        cmRpcPackByte(out, 0);                  /* LM password set */
        cmRpcPackByte(out, 0);                  /* expired flag */
        cmRpcPackByte(out, 0);                  /* undocumented */
        cmRpcPackTcharAsUnicode(out, staticData->txtBufferT, CM_RP_SIZE32 | CM_RP_FRAGMENT32);   /* account name */
        cmRpcPackTcharAsUnicode(out, staticData->fullNameT, CM_RP_SIZE32 | CM_RP_FRAGMENT32);    /* full name */
        cmRpcPackAsciiAsUnicode(out, "", CM_RP_SIZE32 | CM_RP_FRAGMENT32);            /* home */
        cmRpcPackAsciiAsUnicode(out, "", CM_RP_SIZE32 | CM_RP_FRAGMENT32);            /* home drive */
        cmRpcPackAsciiAsUnicode(out, "", CM_RP_SIZE32 | CM_RP_FRAGMENT32);            /* script */
        cmRpcPackAsciiAsUnicode(out, "", CM_RP_SIZE32 | CM_RP_FRAGMENT32);            /* profile */
        cmRpcPackAsciiAsUnicode(out, USERACCOUNT_DESCRIPTION, CM_RP_SIZE32 | CM_RP_FRAGMENT32);    /* account description */
        cmRpcPackAsciiAsUnicode(out, "", CM_RP_SIZE32 | CM_RP_FRAGMENT32);            /* workstations */
        cmRpcPackAsciiAsUnicode(out, "", CM_RP_SIZE32 | CM_RP_FRAGMENT32);            /* account comment */
        cmRpcPackAsciiAsUnicode(out, "", CM_RP_SIZE32 | CM_RP_FRAGMENT32);            /* callback */
        /* logon hours are placed as a bitmask of 3 bytes per hour */
        cmRpcPackUint32(out, 1260);             /* logon hours: max count */
        cmRpcPackUint32(out, 0);                /* logon hours: offset */
        cmRpcPackUint32(out, LOGONHOURS_COUNT); /* logon hours: count */
        for (i = 0; i < LOGONHOURS_COUNT; i++)
            cmRpcPackByte(out, 0xff);           /* logon hours: mask */
        cmRpcAllign(out, 4);
        break;
    default:
        cmRpcPackUint32(out, 0);    /* ref id */
        TRCERR("Information level not supported");
        TRC1P(" level: %d", infoLevel);
        TRCE();
        return CM_RP_FAULTNOLEVEL;
    }

    TRCE();
    return 0;
}

/* DeleteAliasMember */

static NQ_UINT32
samrDeleteAliasMember(
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    NQ_UINT32 rid;                  /* RID for added user */
    NQ_UINT32 alias;                /* RID for alias */
    CMRpcUuid uuid;                 /* parsed user handle */

    TRCB();

    if (!canManageUsers(in))
    {
        TRCERR("User is not allowed to modify local users");
        TRCE();
        return CM_RP_FAULTLOGONFAILURE;
    }

    /* Parse parameters */
    cmRpcParseSkip(in, 4);
    cmRpcParseUuid(in, &uuid);

    /* continue parsing */
    if (cmGetSUint16(uuid.timeMid) != HANDLE_SIGNATURE)
    {
        TRCERR("Unexpected handle");
        TRCE();
        return CM_RP_FAULTLOGONFAILURE;
    }
    alias = cmGetSUint32(uuid.timeLow);
    cmRpcParseSkip(in, 4);        /* count */
    cmSdParseSid(in, &staticData->sid);
    rid = staticData->sid.subs[staticData->sid.numAuths - 1];
    staticData->sid.numAuths--;
    if (!cmSdIsComputerSid(&staticData->sid) && !cmSdIsAnySid(&staticData->sid))
    {
        TRCERR("Nor a computer SID neither any SID as expected");
        TRCE();
        return CM_RP_FAULTLOGONFAILURE;
    }

    if (!udGetUserNameByRid(rid, staticData->txtBufferT, staticData->fullNameT))
    {
        TRCERR("Cannot find user");
        TRC1P(" Rid: %ld", rid);
        TRCE();
        return CM_RP_FAULTLOGONFAILURE;
    }

    /* do not remove from Users */

    switch(alias)
    {
    case CM_SD_RIDALIASADMIN:
        udSetUserAsAdministrator(rid, FALSE);
        break;
    default:
        return CM_RP_FAULTLOGONFAILURE;
    }

    TRCE();
    return 0;
}

/* AddAliasMember */

static NQ_UINT32
samrAddAliasMember(
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    NQ_UINT32 rid;                  /* RID for added user */
    NQ_UINT32 alias;                /* RID for alias */
    CMRpcUuid uuid;                 /* parsed user handle */

    TRCB();

    if (!canManageUsers(in))
    {
        TRCERR("User is not allowed to modify local users");
        TRCE();
        return CM_RP_FAULTLOGONFAILURE;
    }

    /* Parse parameters */
    cmRpcParseSkip(in, 4);
    cmRpcParseUuid(in, &uuid);

    /* continue parsing */
    if (cmGetSUint16(uuid.timeMid) != HANDLE_SIGNATURE)
    {
        TRCERR("Unexpected handle");
        TRCE();
        return CM_RP_FAULTLOGONFAILURE;
    }
    alias = cmGetSUint32(uuid.timeLow);
    cmRpcParseSkip(in, 4);        /* count */
    cmSdParseSid(in, &staticData->sid);
    rid = staticData->sid.subs[staticData->sid.numAuths - 1];
    staticData->sid.numAuths--;
    if (!cmSdIsComputerSid(&staticData->sid) && !cmSdIsAnySid(&staticData->sid))
    {
        TRCERR("Nor a computer SID neither any SID as expected");
        TRCE();
        return CM_RP_FAULTLOGONFAILURE;
    }

    if (!udGetUserNameByRid(rid, staticData->txtBufferT, staticData->fullNameT))
    {
        TRCERR("Cannot find user");
        TRC1P(" Rid: %ld", rid);
        TRCE();
        return CM_RP_FAULTLOGONFAILURE;
    }

    /* do not add to Users, just skip */

    if (alias == CM_SD_RIDALIASADMIN)
    {
        udSetUserAsAdministrator(rid, TRUE);
    }

    TRCE();
    return 0;
}

/* RemoveMemberFromForeignDomain */

static NQ_UINT32
samrRemoveMemberFromForeignDomain(
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    NQ_UINT32 rid;                  /* RID for queried user */
    CMRpcUuid uuid;                 /* parsed user handle */

    TRCB();

    if (!canManageUsers(in))
    {
        TRCERR("User is not allowed to modify local users");
        TRCE();
        return CM_RP_FAULTLOGONFAILURE;
    }

    /* Parse parameters */
    cmRpcParseSkip(in, 4);
    cmRpcParseUuid(in, &uuid);

    /* continue parsing */
    if (cmGetSUint16(uuid.timeMid) != HANDLE_SIGNATURE)
    {
        TRCERR("Unexpected handle");
        TRCE();
        return CM_RP_FAULTLOGONFAILURE;
    }
    cmRpcParseSkip(in, 4);        /* count */
    cmSdParseSid(in, &staticData->sid);
    rid = staticData->sid.subs[staticData->sid.numAuths - 1];
    staticData->sid.numAuths--;
    if (!cmSdIsComputerSid(&staticData->sid))
    {
        TRCERR("Not a computer SID as expected");
        TRCE();
        return CM_RP_FAULTLOGONFAILURE;
    }

    if (!udGetUserNameByRid(rid, staticData->txtBufferT, staticData->fullNameT))
    {
        TRCERR("Cannot find user");
        TRC1P(" Rid: %ld", rid);
        TRCE();
        return CM_RP_FAULTLOGONFAILURE;
    }

    TRCE();
    return 0;
}

/* DeleteUser */

static NQ_UINT32
samrDeleteUser(
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    NQ_UINT32 rid;                  /* RID for queried user */
    CMRpcUuid uuid;                 /* parsed user handle */

    TRCB();

    if (!canManageUsers(in))
    {
        TRCERR("User is not allowed to modify local users");
        TRCE();
        return CM_RP_FAULTLOGONFAILURE;
    }

    /* parse parameters */
    cmRpcParseSkip(in, 4);
    cmRpcParseUuid(in, &uuid);
    
    /* pack uuid */
    cmRpcPackUuid(out, &uuid);

    /* continue parsing */
    if (cmGetSUint16(uuid.timeMid) != HANDLE_SIGNATURE)
    {
        TRCERR("Unexpected handle");
        TRCE();
        return CM_RP_FAULTLOGONFAILURE;
    }
    rid = cmGetSUint32(uuid.timeLow);
    cmRpcPackUint32(out, rid);
    if (!udDeleteUserByRid(rid))
    {
        TRCERR("Cannot delete user");
        TRC1P(" Rid: %ld", rid);
        TRCE();
        return CM_RP_FAULTLOGONFAILURE;
    }

    TRCE();
    return 0;
}

/* SetUserInfo2 */

static NQ_UINT32
samrSetUserInfo2(
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    return samrSetUserInfo(in, out);
}

/* SetUserInfo */

static NQ_UINT32
samrSetUserInfo(
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    NQ_UINT32 rid;                  /* RID for queried user */
    NQ_UINT16 infoLevel;            /* information level */
    CMRpcUuid uuid;                 /* parsed user handle */
    NQ_UINT16 nameLen;              /* name length */
    NQ_BOOL isAccountName;          /* TRUE when account name presents */
    NQ_BOOL isFullName;             /* TRUE when full account name presents */
    NQ_BOOL isDescription;          /* TRUE when full account name presents */
    CMRpcUnicodeString strDescr;    /* Unicode string descriptor */
    NQ_UINT32 temp;                 /* arbitrary value */
    NQ_BYTE* pPassword;             /* pointer to the password */
    NQ_UINT32 passLen;              /* password length */

    TRCB();

    if (!canManageUsers(in))
    {
        TRCERR("User is not allowed to modify local users");
        TRCE();
        return CM_RP_FAULTLOGONFAILURE;
    }

    /* Parse parameters */
    cmRpcParseSkip(in, 4);
    cmRpcParseUuid(in, &uuid);

    /* continue parsing */
    if (cmGetSUint16(uuid.timeMid) != HANDLE_SIGNATURE)
    {
        TRCERR("Unexpected handle");
        TRCE();
        return CM_RP_FAULTLOGONFAILURE;
    }
    rid = cmGetSUint32(uuid.timeLow);
    if (!udGetUserNameByRid(rid, staticData->txtBufferT, staticData->fullNameT))
    {
        cmRpcPackUint32(out, 0);    /* ref id */
        TRCERR("No such user");
        TRC1P(" Rid: %ld", rid);
        TRCE();
        return CM_RP_FAULTLOGONFAILURE;
    }
    cmRpcParseUint16(in, &infoLevel);        /* level */
    cmRpcParseUint16(in, &infoLevel);        /* the same */

    /* switch by info level */

    switch (infoLevel)
    {
    case 21:
    case 25:
        cmRpcParseSkip(in, 6 * 2 * 4);  /* all times */
        cmRpcParseUint16(in, &nameLen);                 /* SAM account length */
        cmRpcParseUint16(in, &nameLen);                 /* SAM account length (again) */
        isAccountName = nameLen > 0;                    /* parse name later */
        cmRpcParseSkip(in, 4);          /* account name ptr */
        cmRpcParseUint16(in, &nameLen);                 /* SAM full name length */
        cmRpcParseUint16(in, &nameLen);                 /* SAM full name length (again) */
        isFullName = nameLen > 0;                       /* parse full name later */
        cmRpcParseSkip(in, 4);          /* full name ptr */
        cmRpcParseSkip(in, 2 * 2 + 4);    /* skip home */
        cmRpcParseSkip(in, 2 * 2 + 4);    /* skip home drive */
        cmRpcParseSkip(in, 2 * 2 + 4);    /* skip home script */
        cmRpcParseSkip(in, 2 * 2 + 4);    /* skip home profile */
        cmRpcParseUint16(in, &nameLen);                 /* SAM description length */
        cmRpcParseUint16(in, &nameLen);                 /* SAM description length (again) */
        isDescription = nameLen > 0;                    /* parse description later */
        cmRpcParseSkip(in, 4);          /* description ptr */
        cmRpcParseSkip(in, 2 * 2 + 4);    /* skip workstations */
        cmRpcParseSkip(in, 2 * 2 + 4);    /* skip account comment */
        cmRpcParseSkip(in, 2 * 2 + 4);    /* skip callback */
        cmRpcParseSkip(in, 2 * 2 + 4);    /* skip unknown string */
        cmRpcParseSkip(in, 2 * 2 + 4);    /* skip unknown string */
        cmRpcParseSkip(in, 2 * 2 + 4);    /* skip unknown string */
        cmRpcParseUint32(in, &temp);                    /* buffer count */
        cmRpcParseSkip(in, 4 + temp);   /* buffer ptr + data */
        cmRpcParseSkip(in, 4);          /* RID */
        cmRpcParseUint32(in, &temp);                    /* primary group */
        cmRpcParseSkip(in, 4);          /* account control */
        cmRpcParseSkip(in, 4);          /* undocumented */
        cmRpcParseSkip(in, 2);          /* logon hours: divisions */
        cmRpcAllign(in, 4);
        cmRpcParseSkip(in, 4);          /* logon hours: ptr */
        cmRpcParseSkip(in, 4 * 2);      /* until codepage */
        cmRpcParseSkip(in, 4 * sizeof(NQ_BYTE));        /* passwords + flags */
        cmRpcAllign(in, 4);
        if (infoLevel == 25)
        {
            CMRpcPacketDescriptor tempDesc;

            pPassword = in->current;
            cmDecryptPassword(
                ((CSUser*)in->user)->sessionKey,
                pPassword,
                TRUE
                );
            pPassword += 512;
            cmRpcSetDescriptor(&tempDesc, pPassword, in->nbo);
            cmRpcParseUint32(&tempDesc, &passLen);
            if ((NQ_UINT32)passLen >= 512)
            {
                TRCERR("Illegal password length");
                TRC1P(" passLen: %ld", passLen);
                TRCE();
                return CM_RP_FAULTLOGONFAILURE;
            }
            *pPassword = 0;
            *(pPassword + 1) = 0;
            pPassword -= passLen;
            cmRpcParseSkip(in, 532);
        }
        else
        {
            pPassword = NULL;
        }
        if (isAccountName)
        {
            CMSdRid otherRid; /* RID to check if new neme belongs to another user */

            cmRpcParseUnicode(in, &strDescr, CM_RP_SIZE32 | CM_RP_FRAGMENT32);
            cmUnicodeToTchar(staticData->txtBufferT, strDescr.text);
            if (   udGetUserRidByName(staticData->txtBufferT, &otherRid)
                && otherRid != rid
               )
            {
                TRCERR("user with this name already exists");
                TRC3P(" Rid: %ld, name: %s, other rid: %ld", rid, cmTDump(staticData->txtBufferT), otherRid);
                TRCE();
                return CM_RP_FAULTLOGONFAILURE;
            }
        }
        else
        {
            if (!udGetUserNameByRid(rid, staticData->txtBufferT, staticData->fullNameT))
            {
                TRCERR("No such user");
                TRC1P(" Rid: %ld", rid);
                TRCE();
                return CM_RP_FAULTLOGONFAILURE;
            }
        }
        if (isFullName)
        {
            cmRpcParseUnicode(in, &strDescr, CM_RP_SIZE32 | CM_RP_FRAGMENT32);
            cmUnicodeToTchar(staticData->fullNameT, strDescr.text);
        }
        if (isDescription)
        {
            cmRpcParseUnicode(in, &strDescr, CM_RP_SIZE32 | CM_RP_FRAGMENT32);
            cmUnicodeToTchar(staticData->fullNameT, strDescr.text);
        }
        if (!udSetUserInfo(
                rid,
                staticData->txtBufferT,
                isFullName? staticData->fullNameT : NULL,
                isDescription? staticData->descriptionT : NULL,
                (NQ_WCHAR*)pPassword
                )
           )
        {
            TRCERR("Unable to set user info");
            TRC1P(" Rid: %ld", rid);
            TRCE();
            return CM_RP_FAULTLOGONFAILURE;
        }
        break;
    case 23:
    {
        pPassword = in->current + 196;    /* undocumented */
        cmDecryptPassword(
            ((CSUser*)in->user)->sessionKey,
            pPassword,
            FALSE
            );
        pPassword += 512;
        passLen = cmGetSUint32(*((NQ_SUINT32*)pPassword));
        passLen = in->nbo? syNtoh32(passLen): cmLtoh32(passLen);
        if ((NQ_UINT32)passLen >= 512)
        {
            TRCERR("Illegal password length");
            TRC1P(" passLen: %ld", passLen);
            TRCE();
            return CM_RP_FAULTLOGONFAILURE;
        }
        *pPassword = 0;
        *(pPassword + 1) = 0;
        pPassword -= passLen;
        if (!udSetUserInfo(
                rid,
                staticData->txtBufferT,
                NULL,
                NULL,
                (NQ_WCHAR*)pPassword
                )
           )
        {
            TRCERR("Unable to set user info");
            TRC1P(" Rid: %ld", rid);
            TRCE();
            return CM_RP_FAULTLOGONFAILURE;
        }
        break;
    }
    default:
        TRCERR("Information level not supported");
        TRC1P(" level: %d", infoLevel);
        TRCE();
        return CM_RP_FAULTNOLEVEL;
    }

    TRCE();
    return 0;
}

/* QueryGroupInfo */

static NQ_UINT32
samrQueryGroupInfo(
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    NQ_UINT32 rid;                      /* RID for queried user */
    NQ_UINT16 infoLevel;                /* information level */
    NQ_UINT32 refId;                    /* next referent ID */
    CMRpcUuid uuid;                     /* parsed user handle */
    NQ_UINT16 nameLen;                  /* name length */

    TRCB();

    /* Parse parameters */
    cmRpcParseSkip(in, 4);
    cmRpcParseUuid(in, &uuid);
    if (cmGetSUint16(uuid.timeMid) != HANDLE_SIGNATURE)
    {
        cmRpcPackUint32(out, 0);    /* ref id */
        TRCERR("Unexpected handle");
        TRCE();
        return CM_RP_FAULTLOGONFAILURE;
    }
    rid = cmGetSUint32(uuid.timeLow);
    if (!cmSdLookupRid(rid, staticData->txtBufferT, staticData->fullNameT))
    {
        cmRpcPackUint32(out, 0);    /* ref id */
        TRCERR("No such group");
        TRC1P(" Rid: %ld", rid);
        TRCE();
        return CM_RP_FAULTLOGONFAILURE;
    }
    cmRpcParseUint16(in, &infoLevel);        /* level */

    /* pack the response */

    refId = 1;
    switch (infoLevel)
    {
    case 5:
        cmRpcPackUint32(out, refId++);          /* ref id */
        cmRpcPackUint16(out, infoLevel);        /* level */
        cmRpcAllign(out, 4);
        nameLen = (NQ_UINT16)cmTStrlen(staticData->txtBufferT);
        cmRpcPackUint16(out, (NQ_UINT16)(nameLen * sizeof(NQ_WCHAR)));   /* group name len */
        cmRpcPackUint16(out, (NQ_UINT16)(nameLen * sizeof(NQ_WCHAR)));   /* group name size */
        cmRpcPackUint32(out, refId++);          /* group name ref id */
        cmRpcPackUint32(out, 7);                /* undocumented */
        cmRpcPackUint32(out, 0);                /* undocumented */
        nameLen = (NQ_UINT16)cmTStrlen(staticData->fullNameT);
        cmRpcPackUint16(out, (NQ_UINT16)(nameLen * sizeof(NQ_WCHAR)));   /* full name len */
        cmRpcPackUint16(out, (NQ_UINT16)(nameLen * sizeof(NQ_WCHAR)));   /* full name size */
        cmRpcPackUint32(out, refId++);          /* full name ref id */
        cmRpcPackTcharAsUnicode(out, staticData->txtBufferT, CM_RP_SIZE32 | CM_RP_FRAGMENT32);   /* account name */
        cmRpcPackTcharAsUnicode(out, staticData->fullNameT, CM_RP_SIZE32 | CM_RP_FRAGMENT32);    /* full name */
        break;
    default:
        cmRpcPackUint32(out, 0);    /* ref id */
        TRCERR("Information level not supported");
        TRC1P(" level: %d", infoLevel);
        TRCE();
        return CM_RP_FAULTNOLEVEL;
    }

    TRCE();
    return 0;
}

/* samrGetUserPwInfo */

static NQ_UINT32
samrGetUserPwInfo(
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    TRCB();

    /* pack the response */
    cmRpcPackUint16(out, 0);        /* password length */
    cmRpcAllign(out, 4);
    cmRpcPackUint32(out, 0);        /* password properties: complex */

    TRCE();
    return 0;
}

/* QuerySecurity */

static NQ_UINT32
samrQuerySecurity(
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    NQ_UINT32 rid;                      /* RID for queried user */
    NQ_UINT16 infoLevel;                /* information level */
    NQ_UINT32 refId;                    /* next referent ID */
    CMRpcUuid uuid;                     /* parsed user handle */

    TRCB();

    /* Parse parameters */
    cmRpcParseSkip(in, 4);
    cmRpcParseUuid(in, &uuid);
    if (cmGetSUint16(uuid.timeMid) != HANDLE_SIGNATURE)
    {
        cmRpcPackUint32(out, 0);    /* ref id */
        TRCERR("Unexpected handle");
        TRCE();
        return CM_RP_FAULTLOGONFAILURE;
    }
    rid = cmGetSUint32(uuid.timeLow);
    if (!udGetUserNameByRid(rid, staticData->txtBufferT, staticData->fullNameT))
    {
        cmRpcPackUint32(out, 0);    /* ref id */
        TRCERR("No such user");
        TRC1P(" Rid: %ld", rid);
        TRCE();
        return CM_RP_FAULTLOGONFAILURE;
    }
    cmRpcParseUint16(in, &infoLevel);        /* info type */

    /* pack the response */

    refId = 1;
    switch (infoLevel)
    {
    case 4:
        if (!cmSdGetLocalSecurityDescriptorForUser(rid, &staticData->sd))
        {
            cmRpcPackUint32(out, 0);    /* ref id */
            TRCERR("Unable to obtain security descriptor for user");
            TRCE();
            return CM_RP_FAULTUNSUPPORTED;
        }
        cmRpcPackUint32(out, refId++);    /* ref id */
        cmRpcPackUint32(out, staticData->sd.length);  /* size */
        cmRpcPackUint32(out, refId++);    /* ref id */
        cmRpcPackUint32(out, staticData->sd.length);  /* size */
        cmSdPackSecurityDescriptor(out, &staticData->sd);
        break;
    default:
        cmRpcPackUint32(out, 0);    /* ref id */
        TRCERR("Information level not supported");
        TRC1P(" level: %d", infoLevel);
        TRCE();
        return CM_RP_FAULTNOLEVEL;
    }

    TRCE();
    return 0;
}

/* SetSecurity */

static NQ_UINT32
samrSetSecurity(
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    NQ_UINT32 rid;                      /* RID for queried user */
    NQ_UINT16 infoLevel;                /* information level */
    CMRpcUuid uuid;                     /* parsed user handle */

    TRCB();

    if (!canManageUsers(in))
    {
        TRCERR("User is not allowed to modify local users");
        TRCE();
        return CM_RP_FAULTLOGONFAILURE;
    }

    /* Parse parameters */
    cmRpcParseSkip(in, 4);
    cmRpcParseUuid(in, &uuid);
    if (cmGetSUint16(uuid.timeMid) != HANDLE_SIGNATURE)
    {
        cmRpcPackUint32(out, 0);    /* ref id */
        TRCERR("Unexpected handle");
        TRCE();
        return CM_RP_FAULTLOGONFAILURE;
    }
    rid = cmGetSUint32(uuid.timeLow);
    if (!udGetUserNameByRid(rid, staticData->txtBufferT, staticData->fullNameT))
    {
        cmRpcPackUint32(out, 0);    /* ref id */
        TRCERR("No such user");
        TRC1P(" Rid: %ld", rid);
        TRCE();
        return CM_RP_FAULTLOGONFAILURE;
    }
    cmRpcParseUint16(in, &infoLevel);        /* info type */

    /* pack the response */

    switch (infoLevel)
    {
    case 4:
        break;
    default:
        cmRpcPackUint32(out, 0);    /* ref id */
        TRCERR("Information level not supported");
        TRC1P(" level: %d", infoLevel);
        TRCE();
        return CM_RP_FAULTNOLEVEL;
    }

    TRCE();
    return 0;
}

/* GetGroupsForUser */

static NQ_UINT32
samrGetGroupsForUser(
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    NQ_UINT32 rid;                      /* RID for queried user */
    NQ_UINT32 refId;                    /* next referent ID */
    CMRpcUuid uuid;                     /* parsed user handle */
    NQ_BOOL isAny;                      /* TRUE for ANY domain */

    TRCB();

    /* Parse parameters */
    cmRpcParseSkip(in, 4);
    cmRpcParseUuid(in, &uuid);
    if (cmGetSUint16(uuid.timeMid) != HANDLE_SIGNATURE)
    {
        cmRpcPackUint32(out, 0);    /* ref id */
        TRCERR("Unexpected handle");
        TRCE();
        return CM_RP_FAULTLOGONFAILURE;
    }
    isAny = cmGetSUint16(uuid.timeHiVersion);
    rid = cmGetSUint32(uuid.timeLow);
    if (!udGetUserNameByRid(rid, staticData->txtBufferT, staticData->fullNameT))
    {
        cmRpcPackUint32(out, 0);    /* ref id */
        TRCERR("No such user");
        TRC1P(" Rid: %ld", rid);
        TRCE();
        return CM_RP_FAULTLOGONFAILURE;
    }

    /* pack the response */

    refId = 1;
    cmRpcPackUint32(out, refId++);                /* container */
    cmRpcPackUint32(out, isAny? (cmSdIsAdmin(rid)? 2:1):0);    /* count */
    cmRpcPackUint32(out, refId++);        /* group array */
    cmRpcPackUint32(out, isAny? (cmSdIsAdmin(rid)? 2:1):0);    /* max count */
    if (isAny)
    {
        if (cmSdIsAdmin(rid))
        {
            cmRpcPackUint32(out, CM_SD_RIDGROUPADMINS); /* rid */
            cmRpcPackUint32(out, GROUPACCOUNT_ATTRIBS); /* rid attrib */
            cmRpcPackUint32(out, CM_SD_RIDGROUPUSERS);  /* rid */
            cmRpcPackUint32(out, GROUPACCOUNT_ATTRIBS); /* rid attrib */
        }
        else
        {
            cmRpcPackUint32(out, CM_SD_RIDGROUPUSERS);  /* rid */
            cmRpcPackUint32(out, GROUPACCOUNT_ATTRIBS); /* rid attrib */
        }
    }
    TRCE();
    return 0;
}

/* GetAliasMembership */

static NQ_UINT32
samrGetAliasMembership(
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    CMRpcUuid uuid;                     /* parsed user handle */
    CMRpcPacketDescriptor outTemp;      /* saved out descriptor */
    CMSdDomainSid sid;                  /* sid to find alias for */
    NQ_UINT32 numSids;                  /* number of sids */
    NQ_UINT32 numAliases;               /* number of mapped aliases */
    NQ_UINT i;                          /* just a counter */
    CMSdRid rid;                        /* next alias */
    NQ_BOOL isAdmins = FALSE;           /* TRUE when Administrators was reported */
    NQ_BOOL isUsers = FALSE;            /* TRUE when Users was reported */

    TRCB();

    /* Parse parameters */
    cmRpcParseSkip(in, 4);
    cmRpcParseUuid(in, &uuid);
    if (cmGetSUint16(uuid.timeMid) != HANDLE_SIGNATURE)
    {
        cmRpcPackUint32(out, 0);    /* ref id */
        TRCERR("Unexpected handle");
        TRCE();
        return CM_RP_FAULTLOGONFAILURE;
    }
    if (!(NQ_BOOL)cmGetSUint16(uuid.timeHiVersion))
    {
        cmRpcPackUint32(out, 0);                /* count */
        cmRpcPackUint32(out, 1);                /* array pointer */
        cmRpcPackUint32(out, 0);                /* num aliases */
        TRCE();
        return 0;
    }
    cmRpcParseUint32(in, &numSids);        /* count */
    cmRpcParseSkip(in, 4 + 4);    /* array + max count */
    for (i = 0; i < numSids; i++)
    {
        cmRpcParseSkip(in, 4);    /* pointer */
    }

    /* pack empty header */

    cmRpcCloneDescriptor(out, &outTemp);
    cmRpcPackUint32(out, 0);                /* count */
    cmRpcPackUint32(out, 1);                /* array */
    cmRpcPackUint32(out, 0);                /* max count */

    /* cycle by sids */

    numAliases = 0;
    for (i = 0; i < numSids; i++)
    {
        cmRpcParseSkip(in, 4);    /* count */
        cmSdParseSid(in, &sid);
        if (cmSdCheckAlias(&sid, &rid))
        {
            if (   (!isUsers && CM_SD_RIDALIASUSER == rid)
                || (CM_SD_RIDALIASUSER != rid && CM_SD_RIDALIASADMIN != rid)
                || (!isAdmins && CM_SD_RIDALIASADMIN == rid)
               )
            {
                cmRpcPackUint32(out, rid);
                numAliases++;
                if (CM_SD_RIDALIASUSER == rid)
                    isUsers = TRUE;
                if (CM_SD_RIDALIASADMIN == rid)
                    isAdmins = TRUE;
            }
        }
        rid = sid.subs[sid.numAuths - 1];
        if (cmSdIsAdmin(rid) && !isAdmins)
        {
            cmRpcPackUint32(out, CM_SD_RIDALIASADMIN);
            numAliases++;
            isAdmins = TRUE;
        }
    }

    if (0 == numAliases)
    {
        TRCE();
        return CM_RP_FAULTOBJECTNOTFOUND;
    }

    /* update counters */

    cmRpcPackUint32(&outTemp, numAliases);   /* count */
    cmRpcPackUint32(&outTemp, 1);            /* array */
    cmRpcPackUint32(&outTemp, numAliases);   /* max count */

    TRCE();
    return 0;
}

/* GetMembersInAlias */

static NQ_UINT32
samrGetMembersInAlias(
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    CMRpcUuid uuid;                     /* parsed user handle */
    CMRpcPacketDescriptor outTemp;      /* saved out descriptor */
    NQ_UINT32 numMembers;               /* number of alias members */
    NQ_UINT32 refId;                    /* running reference ID */
    NQ_COUNT numUsers;                  /* number of users */
    NQ_UINT i;                          /* just a counter */
    CMSdRid alias;                      /* alias */
    CMSdRid rid;                        /* next member rid */
    CMSdDomainSid sid;                  /* next user SID */

    TRCB();

    /* Parse parameters */
    cmRpcParseSkip(in, 4);
    cmRpcParseUuid(in, &uuid);
    if (cmGetSUint16(uuid.timeMid) != HANDLE_SIGNATURE)
    {
        cmRpcPackUint32(out, 0);    /* ref id */
        TRCERR("Unexpected handle");
        TRCE();
        return CM_RP_FAULTLOGONFAILURE;
    }
    alias = cmGetSUint32(uuid.timeLow);

    /* pack empty header */

    cmRpcCloneDescriptor(out, &outTemp);
    cmRpcPackUint32(out, 0);                /* count */
    cmRpcPackUint32(out, 1);                /* array */
    cmRpcPackUint32(out, 0);                /* max count */

    /* cycle by users 1) */

    refId = 1;
    numMembers = 0;
    numUsers = udGetUserCount();
    for (i = 0; i < numUsers; i++)
    {
        if (!udGetUserInfo(
                i,
                &rid,
                staticData->txtBufferT,
                staticData->fullNameT,
                staticData->descriptionT
                )
           )
        {
            TRCERR("unable to get user information");
            TRC1P("...at index %d", i);
            TRCE();
            return CM_RP_FAULTOBJECTNOTFOUND;
        }
        if (   alias == CM_SD_RIDALIASUSER
            || (alias == CM_SD_RIDALIASADMIN && cmSdIsAdmin(rid))
           )
        {
            cmRpcPackUint32(out, refId++);
            numMembers++;
        }
    }

    /* cycle by users 2) */

    syMemcpy(&sid, cmSdGetComputerSid(), sizeof(sid));
    sid.numAuths++;        /* for user RID */
    for (i = 0; i < numUsers; i++)
    {
        if (!udGetUserInfo(
                i,
                &rid,
                staticData->txtBufferT,
                staticData->fullNameT,
                staticData->descriptionT
                )
           )
        {
            TRCERR("unable to get user information");
            TRC1P("...at index %d", i);
            TRCE();
            return CM_RP_FAULTOBJECTNOTFOUND;
        }
        if (   alias == CM_SD_RIDALIASUSER
            || (alias == CM_SD_RIDALIASADMIN && cmSdIsAdmin(rid))
           )
        {
            sid.subs[sid.numAuths - 1] = rid;
            cmRpcPackUint32(out, sid.numAuths);
            cmSdPackSid(out, &sid);
        }
    }

    if (0 == numMembers)
    {
        TRCE();
        return CM_RP_FAULTOBJECTNOTFOUND;
    }

    /* update counters */

    cmRpcPackUint32(&outTemp, numMembers);   /* count */
    cmRpcPackUint32(&outTemp, 1);            /* array */
    cmRpcPackUint32(&outTemp, numMembers);   /* max count */

    TRCE();
    return 0;
}

/*====================================================================
 * PURPOSE: parse expected "singlton" handle
 *--------------------------------------------------------------------
 * PARAMS:  IN incoming packet descriptor
 *
 * RETURNS: zero on success or error code
 *
 * NOTES:
 *====================================================================
 */

static NQ_UINT32
parseSingletonHandle(
    CMRpcPacketDescriptor* in
    )
{
    CMRpcUuid uuid;                 /* returned handle */

    /* Parse parameters */
    cmRpcParseSkip(in, 4);
    cmRpcParseUuid(in, &uuid);
    if (cmGetSUint16(uuid.timeMid) != HANDLE_SIGNATURE)
    {
        TRCERR("Unexpected handle");
        return CM_RP_FAULTLOGONFAILURE;
    }
    return 0;
}

/*====================================================================
 * PURPOSE: pack one account entry
 *--------------------------------------------------------------------
 * PARAMS:  OUT outgoing packet descriptor
 *          IN account descriptor
 *          IN info level (0 - only RID and name)
 *          IN ref id to use
 *
 * RETURNS: zero on success or error code
 *
 * NOTES:   names are not packed yet
 *====================================================================
 */

static NQ_UINT32
packAccountEntry(
    CMRpcPacketDescriptor* out,
    const AccountDef* account,
    NQ_UINT32 infoLevel,
    NQ_UINT32 refId
    )
{
    NQ_UINT16 nameLen;                         /* length for names */

    switch(infoLevel)
    {
    case 0:
        CS_RP_CHECK(out, 4 + 2 * 2 + 3 * 4 + sizeof(NQ_WCHAR) * syStrlen(account->name));
        cmRpcPackUint32(out, account->rid);                     /* index */
        nameLen = (NQ_UINT16)syStrlen(account->name);
        cmRpcPackUint16(out, (NQ_UINT16)(nameLen * sizeof(NQ_WCHAR)));       /* name len 1 */
        cmRpcPackUint16(out, (NQ_UINT16)(nameLen * sizeof(NQ_WCHAR)));       /* name size 1 */
        cmRpcPackUint32(out, refId);                            /* ref id */
        break;
    default:
        TRCERR("Unsupported level");
        TRCE();
        return CM_RP_FAULTNOLEVEL;
    }
    return 0;
}

/*====================================================================
 * PURPOSE: pack group information
 *--------------------------------------------------------------------
 * PARAMS:  OUT outgoing packet descriptor
 *          IN group ID
 *          IN group index
 *
 * RETURNS: None
 *
 * NOTES:   FALSE if group was not found
 *====================================================================
 */

static NQ_BOOL
packGroupInfo(
    CMRpcPacketDescriptor* out,
    CMSdRid rid,
    NQ_UINT32 index
    )
{
    NQ_UINT16 nameLen;                      /* host name length */

    if (!cmSdLookupRid(CM_SD_RIDGROUPUSERS, staticData->txtBufferT, staticData->fullNameT))
        return FALSE;
    cmRpcPackUint32(out, 1);                    /* count */
    cmRpcPackUint32(out, 2);                    /* array ptr */
    cmRpcPackUint32(out, 1);                    /* max count */
    cmRpcPackUint32(out, index + 1);            /* next index */
    cmRpcPackUint32(out, rid);                  /* rid */
    cmRpcPackUint32(out, GROUPACCOUNT_ATTRIBS); /* rid attributes */
    nameLen = (NQ_UINT16)(sizeof(NQ_WCHAR) * cmTStrlen(staticData->txtBufferT));
    cmRpcPackUint16(out, nameLen);              /* length */
    cmRpcPackUint16(out, nameLen);              /* size */
    cmRpcPackUint32(out, 3);                    /* account name ptr */
    nameLen = (NQ_UINT16)(sizeof(NQ_WCHAR) * cmTStrlen(staticData->fullNameT));
    cmRpcPackUint16(out, nameLen);              /* length */
    cmRpcPackUint16(out, nameLen);              /* size */
    cmRpcPackUint32(out, 4);                    /* account description ptr */
    /* strings */
    cmRpcPackTcharAsUnicode(out, staticData->txtBufferT, CM_RP_SIZE32 | CM_RP_FRAGMENT32);
    cmRpcPackTcharAsUnicode(out, staticData->fullNameT, CM_RP_SIZE32 | CM_RP_FRAGMENT32);
    return TRUE;
}

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
 * PURPOSE: check that the current user is allowed to manage local users
 *--------------------------------------------------------------------
 * PARAMS:  IN in comiming packet descriptor
 *
 * RETURNS: None
 *
 * NOTES:   should be administrator
 *====================================================================
 */

static NQ_BOOL
canManageUsers(
    const CMRpcPacketDescriptor* in
    )
{
    CMSdAccessToken* pToken = (CMSdAccessToken*)in->token;    /* user token */

    return (cmSdIsAnySid(&pToken->domain) || cmSdIsComputerSid(&pToken->domain))
            && cmSdIsAdmin(pToken->rids[0]
           );
}

#endif /* UD_CS_INCLUDERPC_SAMRPC */
