/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : NT Security Descriptors
 *--------------------------------------------------------------------
 * MODULE        : CM - Common Libraries
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 18-October-2004
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _CMSDESCR_H_
#define _CMSDESCR_H_

#include "cmapi.h"

/* security descriptor */

typedef struct
{
    NQ_UINT32   length;
    NQ_BYTE     data[UD_CS_SECURITYDESCRIPTORLENGTH];
}
CMSdSecurityDescriptor;


#if defined(UD_CS_INCLUDESECURITYDESCRIPTORS) || defined(UD_CC_INCLUDESECURITYDESCRIPTORS) || defined (UD_CC_INCLUDEDOMAINMEMBERSHIP) || defined(UD_CS_INCLUDEPASSTHROUGH)

/* relative ID */

typedef NQ_UINT32 CMSdRid;
#define cmSdIsAdmin(rid)    ((NQ_INT)rid < 0)
/* defintion of an "empty" domain sid */

#define cmSdClearDomainSid(_pSid)   (_pSid)->revision = -1
#define cmSdIsEmptyDomainSid(_pSid) (_pSid)->revision == -1

#include "sypackon.h"

/*  Domain SID (security ID). Sub-authorities follow this structure. Each sub-authority is
    a 32-bit value. Number of values is defined by numAuth field. */

typedef SY_PACK_PREFIX struct
{
    NQ_BYTE revision;               /* SID revision number */
    NQ_BYTE numAuths;               /* number of sub-authorities */
    NQ_BYTE idAuth[6];              /* identifier authority */
    NQ_UINT32 subs[6];              /* subauthorities */
}
SY_PACK_ATTR CMSdDomainSid;

typedef SY_PACK_PREFIX struct
{
    NQ_BYTE type;       /* ace type - e.g allowed / denied etc */
    NQ_BYTE flags;      /* see below */
    NQ_UINT16 size;
    NQ_UINT32 accessMask;
    CMSdDomainSid trustee;
}
SY_PACK_ATTR CMSdAce;

/* type values */
#define CM_SD_ALLOW 0
#define CM_SD_DENY  1

/* Flag bits in SACE */
#define CM_SD_AUDITFAILEDACCESS      0x40
#define CM_SD_AUDITNQ_SUCCESSFULLACCESS 0x20
#define CM_SD_INHERITEDACE           0x10
#define CM_SD_INHERITONLY            0x08
#define CM_SD_NONPROPAGATEINHERIT    0x04
#define CM_SD_CONTAINERINHERIT       0x02
#define CM_SD_OBJECTINHERIT          0x01

/* access mask bits and masks */
#define CM_SD_SPECIFICRIGHTSMASK    0x0000ffff
#define CM_SD_STANDARDRIGHTSMASK    0x001f0000
#define CM_SD_GENERCIRIGHTSMASK     0xf0000000

/*  An array of CMCifsSecurityAce structures follows this structure. The number of
    following CMCifsSecurityAce values is defined by the numAces field. */
typedef SY_PACK_PREFIX struct
{
    NQ_UINT16 revision;
    NQ_UINT16 size;
    NQ_UINT32 numAces;
}
SY_PACK_ATTR CMSdAcl;

/* default revision for new ACLs */
#define CM_SD_REVISION                    1

/* Finally - security descriptor */
typedef SY_PACK_PREFIX struct
{
    NQ_UINT16 revision;             /* format version */
    NQ_UINT16 type;                 /* see flags below */
    NQ_UINT32 ownerSid;             /* offset to owner SID */
    NQ_UINT32 groupSid;             /* offset to main group SID */
    NQ_UINT32 sacl;                 /* offset to system ACL */
    NQ_UINT32 dacl;                 /* offset to DACL */
}
SY_PACK_ATTR CMSdSecurityDescriptorHeader;

/* type bits for security descriptor */
#define CM_SD_OWNERDEFAULTED        0x0001
#define CM_SD_GROUPDEFAULTED        0x0002
#define CM_SD_DACLPRESENT           0x0004
#define CM_SD_DACLDEFAULTED         0x0008
#define CM_SD_SACLPRESENT           0x0010
#define CM_SD_SACLDEFAULTED         0x0020
#define CM_SD_DACLTRUSTED           0x0040
#define CM_SD_SERVER_SECURITY       0x0080
#define CM_SD_DACLAUTOINHERITREQ    0x0100
#define CM_SD_SACLAUTOINHERITREQ    0x0200
#define CM_SD_DACLAUTOINHERITED     0x0400
#define CM_SD_SACLAUTOINHERITED     0x0800
#define CM_SD_DACLPROTECTED         0x1000
#define CM_SD_SACLPROTECTED         0x2000
#define CM_SD_RM_CONTROLVALID       0x4000
#define CM_SD_SELF_RELATIVE         0x8000

/* "Well known RIDs for groups and aliases */

#define CM_SD_RIDADMINISTRATOR  500     /* local administrator */
#define CM_SD_RIDGUEST          501     /* guest user */
#define CM_SD_RIDGROUPADMINS    512     /* administrators group */
#define CM_SD_RIDGROUPUSERS     513     /* users group */
#define CM_SD_RIDGROUPGUESTS    514     /* guests group */
#define CM_SD_RIDALIASADMIN     544     /* any administrators */
#define CM_SD_RIDALIASUSER      545     /* any users */
#define CM_SD_RIDALIASGUEST     546     /* any guests */
#define CM_SD_RIDALIASACCOUNTOP 548     /* account operators */

/* RID/name types */

#define CM_SD_RIDTYPE_USENONE    0  /* NOTUSED */
#define CM_SD_RIDTYPE_USER       1  /* user */
#define CM_SD_RIDTYPE_DOMGRP     2  /* domain group */
#define CM_SD_RIDTYPE_DOMAIN     3  /* domain name */
#define CM_SD_RIDTYPE_ALIAS      4  /* local group */
#define CM_SD_RIDTYPE_WKNGRP     5  /* well-known group */
#define CM_SD_RIDTYPE_DELETED    6  /* deleted account: needed for c2 rating */
#define CM_SD_RIDTYPE_INVALID    7  /* invalid account */
#define CM_SD_RIDTYPE_UNKNOWN    8  /* */

#include "sypackof.h"

/* user identification structure (access token) contains all information for
 * querying particular access of user to an object protected by an ACL */

typedef struct
{
    CMSdDomainSid domain;                  /* domain SID */
    NQ_UINT16 numRids;                     /* actual number of rids */
    CMSdRid rids[UD_CS_MAXUSERGROUPS + 1]; /* user and group RIDs */
    NQ_BOOL isAnon;							/* is user anonymous */
}
CMSdAccessToken;

#endif /* defined(UD_CS_INCLUDESECURITYDESCRIPTORS) || defined(UD_CC_INCLUDESECURITYDESCRIPTORS) */

/* desired access */

typedef  NQ_UINT32 CMSdAccessFlags;

#if defined(UD_CS_INCLUDESECURITYDESCRIPTORS) || defined(UD_CC_INCLUDESECURITYDESCRIPTORS) || defined (UD_CC_INCLUDEDOMAINMEMBERSHIP) || defined(UD_CS_INCLUDEPASSTHROUGH)

/* initialize this module */
NQ_STATUS        /* NQ_SUCCESS or NQ_FAIL */
cmSdInit(
    void
    );

/* release this module */
void
cmSdExit(
    void
    );

/* check security descriptor */
NQ_BOOL                                 /* TRUE when valid */
cmSdIsValid(
    const CMSdSecurityDescriptor* pSd   /* decriptor to check */
    );

/* determine user�s access by ACL */
NQ_BOOL                     /* TRUE when allowed */
cmSdHasAccess(
    const CMSdAccessToken* token,      /* user access token (may be NULL) */
    const NQ_BYTE* sd,                 /* security descriptor data */
    CMSdAccessFlags access             /* desired access flags */
    );

/* determine if this user has administrative access */
NQ_BOOL                     /* TRUE when allowed */
cmSdIsAdministrator(
    const CMSdAccessToken* token       /* user access token */
    );

/* get default SD with no owner */
NQ_BOOL                                 /* TRUE on success */
cmSdGetDefaultSecurityDescriptor(
    CMSdSecurityDescriptor* pSd         /* buffer for descriptor */
    );

/* get default SD for a share */
NQ_BOOL                                 /* TRUE on success */
cmSdGetShareSecurityDescriptor(
    CMSdSecurityDescriptor* pSd         /* buffer for descriptor */
    );

/* get empty SD for a share */
NQ_BOOL                                 /* TRUE on success */
cmSdGetEmptyShareSecurityDescriptor(
    CMSdSecurityDescriptor* pSd         /* buffer for descriptor */
    );
    
/* get "non-supported" SD */
NQ_BOOL                                 /* TRUE on success */
cmSdGetNoneSecurityDescriptor(
    CMSdSecurityDescriptor* pSd         /* buffer for descriptor */
    );
    
/* get readonly SD for a share */
NQ_BOOL                                 /* TRUE on success */
cmSdGetReadonlyShareSecurityDescriptor(
    CMSdSecurityDescriptor* pSd         /* buffer for descriptor */
    );

/* get adminonly SD for a share */
NQ_BOOL                                 /* TRUE on success */
cmSdGetAdminonlyShareSecurityDescriptor(
    CMSdSecurityDescriptor* pSd         /* buffer for descriptor */
    );
    
/* get default ACE for group Everyone */
const NQ_BYTE*
cmSdGetEveryoneGroupACE(
    void
    );

/* get default ACE for group Administrators */
const NQ_BYTE*
cmSdGetAdministratorsGroupACE(
    void
    );

/* get default ACE for group Users */
const NQ_BYTE*
cmSdGetUsersGroupACE(
    void
    );

/* get default SD by token */
NQ_BOOL                                 /* TRUE on success */
cmSdGetDefaultSecurityDescriptorByToken(
    const CMSdAccessToken* token,       /* pointer to owner's handle */
    CMSdSecurityDescriptor* pSd         /* buffer for descriptor */
    );

/* get default SD for user */
NQ_BOOL                                 /* TRUE on success */
cmSdGetLocalSecurityDescriptorForUser(
    CMSdRid rid,                        /* owner's RID */
    CMSdSecurityDescriptor* pSd         /* buffer for descriptor */
    );

/* set host domain's SID */
void
cmSdSetDomainSid(
    const CMSdDomainSid* sid        /* sid to set */
    );

/* Get host domain's SID */
const CMSdDomainSid*                /* domain SID */
cmSdGetDomainSid(
    void
    );

/* Get local domain sid alias */
const CMSdDomainSid*                /* domain SID */
cmSdGetLocalDomainAlias(
    void
    );

/* Get computer SID */
const CMSdDomainSid*                /* computer SID */
cmSdGetComputerSid(
    void
    );

/* checks if domain SID was set */
NQ_BOOL                             /* TRUE if already set */
cmSdIsDomainSidSet(
    void
    );

/* parse domain SID */
void
cmSdParseSid(
    CMRpcPacketDescriptor* in,      /* incoming packet descriptor */
    CMSdDomainSid* sid              /* buffer for SID */
    );

/* pack domain SID */
void
cmSdPackSid(
    CMRpcPacketDescriptor* out,     /* outgoing packet descriptor */
    const CMSdDomainSid* sid        /* SID to pack */
    );

/* pack full SID including domain SID and user RID */
void
cmSdPackSidRid(
    CMRpcPacketDescriptor* out,
    const CMSdDomainSid* sid,
    NQ_UINT32 rid
    );

/* parse Security Descriptor */
void
cmSdParseSecurityDescriptor(
    CMRpcPacketDescriptor* in,      /* incoming packet descriptor */
    CMSdSecurityDescriptor* pSd     /* buffer for SD */
    );

/* pack Security Descriptor */
void
cmSdPackSecurityDescriptor(
    CMRpcPacketDescriptor* out,         /* outgoing packet descriptor */
    const CMSdSecurityDescriptor* pSd   /* SD to pack */
    );

/* parse Access Control List */
void
cmSdParseAcl(
    CMRpcPacketDescriptor* in,      /* incoming packet descriptor */
    CMSdAcl* pAcl,                  /* buffer for ACL */
    const NQ_BYTE* limit            /* the highest address to use */
    );

/* pack Access Control List */
void
cmSdPackAcl(
    CMRpcPacketDescriptor* out,         /* outgoing packet descriptor */
    const CMSdAcl* pAcl                 /* ACL to pack */
    );

/* parse Access Control Entry */
void
cmSdParseAce(
    CMRpcPacketDescriptor* in,      /* incoming packet descriptor */
    CMSdAce* pAce                   /* buffer for ACE */
    );

/* pack Access Control Entry */
void
cmSdPackAce(
    CMRpcPacketDescriptor* out,         /* outgoing packet descriptor */
    const CMSdAce* pAce                 /* ACE to pack */
    );

/* checks if the required SID is "Any" domain sid */

NQ_BOOL                         /* TRUE on match */
cmSdIsAnySid(
    const CMSdDomainSid* sid    /* SID to match */
    );

/* checks if the required SID is computer sid */

NQ_BOOL                         /* TRUE on match */
cmSdIsComputerSid(
    const CMSdDomainSid* sid    /* SID to match */
    );

/* check an alias */

NQ_BOOL                         /* TRUE when we support this alias */
cmSdCheckAlias(
    const CMSdDomainSid* sid,   /* SID + alias RID */
    CMSdRid* alias              /* buffer for alias RID */
    );

#ifdef UD_CS_INCLUDELOCALUSERMANAGEMENT

/* find local name by RID */

NQ_BOOL                         /* TRUE when found */
cmSdLookupRid(
    CMSdRid rid,                /* rid */
    NQ_TCHAR* nameBuffer,       /* name buffer */
    NQ_TCHAR* fullNameBuffer    /* name buffer */
    );

/* find RID by local name */

NQ_BOOL                         /* TRUE when found */
cmSdLookupName(
    const NQ_TCHAR* name,       /* name */
    CMSdRid* rid                /* rid buffer */
    );

/* get RID type */

NQ_UINT32                       /* RID type */
cmSdGetRidType(
    CMSdRid rid                 /* rid */
    );

#endif /* UD_CS_INCLUDELOCALUSERMANAGEMENT */

/* create SD with exclusive rights for a given user */

NQ_BOOL                         /* TRUE on success, FALSE on failure */
cmSdCreateExclusiveSecurityDescriptor(
    const CMSdAccessToken* token,    /* user token */
    CMSdSecurityDescriptor* sd       /* buffer for the result */
    );

/* check if the given SD has exclusive rights for a given user */

NQ_BOOL                         /* TRUE when exclusive */
cmSdIsExclusiveSecurityDescriptor(
    const CMSdAccessToken* token,       /* user token */
    const CMSdSecurityDescriptor* sd    /* descriptor to check */
    );

#if SY_DEBUGMODE
void cmSdDumpSecurityDescriptor(NQ_TCHAR *shareName, const CMSdSecurityDescriptor *sd);
void cmSdDumpAccessToken(CMSdAccessToken *token);
#endif

#else /* defined(UD_CS_INCLUDESECURITYDESCRIPTORS) || defined(UD_CC_INCLUDESECURITYDESCRIPTORS) || defined (UD_CC_INCLUDEDOMAINMEMBERSHIP)|| defined(UD_CS_INCLUDEPASSTHROUGH)*/

/* a placeholder for user identification structure (access token) */

typedef struct
{
    NQ_UINT32 dummy;
    NQ_BOOL isAnon; /* is user anonymous*/
}
CMSdAccessToken;

/* determine user�s access by ACL */
NQ_BOOL                     /* TRUE when allowed */
cmSdHasAccess(
    const CMSdAccessToken* token,      /* user access token (may be NULL) */
    const NQ_BYTE* sd,                 /* security descriptor data */
    CMSdAccessFlags access             /* desired access flags */
    );

#endif /* defined(UD_CS_INCLUDESECURITYDESCRIPTORS) || defined(UD_CC_INCLUDESECURITYDESCRIPTORS) || defined (UD_CC_INCLUDEDOMAINMEMBERSHIP) || defined(UD_CS_INCLUDEPASSTHROUGH)*/

#endif  /* _CMSDESCR_H_ */
