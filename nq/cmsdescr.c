/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : API for user-defined features
 *--------------------------------------------------------------------
 * MODULE        : CM - Common Library
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 28-Sep-2005
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "cmsdescr.h"

/*
 * Local definitions, functions, data
 * ----------------------------------
 */

#if defined(UD_CS_INCLUDESECURITYDESCRIPTORS) || defined(UD_CC_INCLUDESECURITYDESCRIPTORS) || defined (UD_CC_INCLUDEDOMAINMEMBERSHIP) || defined(UD_CS_INCLUDEPASSTHROUGH)

/* local domain alias SId */

typedef struct
{
        /* singletones */
#ifdef UD_NQ_INCLUDECIFSSERVER
    NQ_BOOL domainAliasSidSet;
    NQ_BOOL domainSidSet;
    NQ_BOOL computerSidSet;
        /* SID for the computer of the server */
    CMSdDomainSid computerSid;
        /* SID for the domain alias */
    CMSdDomainSid domainAliasSid;
        /* SID for the domain of the server */
    CMSdDomainSid domainSid;
#endif /* UD_NQ_INCLUDECIFSSERVER */
    NQ_CHAR tempName[256];    /* name in ASCII */
}
StaticData;

#ifdef SY_FORCEALLOCATION
static StaticData* staticData = NULL;
#else  /* SY_FORCEALLOCATION */
static StaticData staticDataSrc;
static StaticData* staticData = &staticDataSrc;
#endif /* SY_FORCEALLOCATION */

static const CMSdDomainSid constDomainSid =
    {0x01,0x01,{0,0,0,0,0,0x05},{32,0,0,0,0,0}};
#ifdef UD_NQ_INCLUDECIFSSERVER
static const CMSdDomainSid constComputerSid =
    {0x01,0x04,{0,0,0,0,0,0x05},{21,0,0,0,0,0}};
#endif /* UD_NQ_INCLUDECIFSSERVER */

/* local alias/group table */

typedef struct
{
    CMSdRid rid;            /* RID */
    NQ_UINT32 type;         /* RID type */
    const NQ_CHAR* name;    /* name */
    const NQ_CHAR* fullName;/* description */
} AliasEntry;

#ifdef UD_CS_INCLUDELOCALUSERMANAGEMENT

static const AliasEntry localAliases[] = {
    {CM_SD_RIDALIASADMIN,         CM_SD_RIDTYPE_ALIAS,     "Administrators", "Administrators have complete and unrestricted access to the computer/domain"},
    {CM_SD_RIDALIASUSER,         CM_SD_RIDTYPE_ALIAS,     "Users", "Ordinary users"},
    {CM_SD_RIDALIASGUEST,        CM_SD_RIDTYPE_ALIAS,     "Guests", "Local or domain guests"},
    {CM_SD_RIDGROUPADMINS,        CM_SD_RIDTYPE_DOMGRP,     "Administrators", "Local or domain administrators"},
    {CM_SD_RIDGROUPUSERS,        CM_SD_RIDTYPE_DOMGRP,     "None", "Local or domain users"},
    {CM_SD_RIDGROUPGUESTS,        CM_SD_RIDTYPE_DOMGRP,     "Guests", "Local or domain guests"},
/*    {CM_SD_RIDADMINISTRATOR,    CM_SD_RIDTYPE_USER,     "Administrator", "Local Administrator"},
    {CM_SD_RIDGUEST,            CM_SD_RIDTYPE_USER,     "Guest", "Guest account"},
*/
};

#endif /* UD_CS_INCLUDELOCALUSERMANAGEMENT */

/* "Current" SID for the domain of the server */
static const CMSdDomainSid anyDomainSid = {0x01,0x01,{0,0,0,0,0,0x05},{32,0,0,0,0,0} };

/* Different default security descriptors are defined in Little Endian
 * byte order
 */

/* default SD for files, printers */
static const NQ_BYTE defaultSecurityDescriptor[] =
{       /* SD */
    0x01, 0,        /* revision*/
    0x04,0x84,      /* type */
    0,0,0,0,        /* owner sid */
    0,0,0,0,        /* group sid */
    0,0,0,0,        /* sacl */
    0x14,0,0,0,     /* dacl */
        /* DACL */
    2,0,            /* revision */
    96,0,           /* size */
    4,0,0,0,        /* num ACEs */
        /* ACE: S-1-5-32-544 */
    0x00,0x03,0x18,0x00,0xff,0x01,0x1f,0x00,0x01,0x02,0,0,0,0,0,0x05,0x20,0,0,0,0x20,0x02,0,0,
        /* ACE: S-1-1-0 */
    0x00,0x0b,0x14,0x00,0xff,0x01,0x1f,0x00,0x01,0x01,0,0,0,0,0,0x01,0,0,0,0,
        /* ACE: S-1-5-18 */
    0x00,0x03,0x14,0x00,0xff,0x01,0x1f,0x00,0x01,0x01,0,0,0,0,0,0x05,0x12,0,0,0,
        /* ACE: S-1-5-32-545 */
    0x00,0x03,0x18,0x00,0xa9,0x00,0x12,0x00,0x01,0x02,0,0,0,0,0,0x05,0x20,0,0,0,0x21,0x02,0,0
};

/* default SD for printers jobs */
static const NQ_BYTE defaultJobSecurityDescriptor[] =
{       /* SD */
    0x01, 0,        /* revision*/
    0x04,0x84,      /* type */
    0,0,0,0,        /* owner sid */
    0,0,0,0,        /* group sid */
    0,0,0,0,        /* sacl */
    0x14,0,0,0,     /* dacl */
        /* DACL */
    2,0,            /* revision */
    96,0,           /* size */
    4,0,0,0,        /* num ACEs */
        /* ACE: S-1-5-32-544 */
    0x00,0x03,0x18,0x00,0xff,0x01,0x1f,0x00,0x01,0x02,0,0,0,0,0,0x05,0x20,0,0,0,0x20,0x02,0,0,
        /* ACE: S-1-1-0 */
    0x00,0x0b,0x14,0x00,0x04,0x00,0x12,0x00,0x01,0x01,0,0,0,0,0,0x01,0,0,0,0,
        /* ACE: S-1-5-18 */
    0x00,0x03,0x14,0x00,0xff,0x01,0x1f,0x00,0x01,0x01,0,0,0,0,0,0x05,0x12,0,0,0,
        /* ACE: S-1-5-32-545 */
    0x00,0x03,0x18,0x00,0xa9,0x00,0x12,0x00,0x01,0x02,0,0,0,0,0,0x05,0x20,0,0,0,0x21,0x02,0,0
};

/* default SD for shares */
static const NQ_BYTE shareSecurityDescriptor[] =
{       /* SD */
    0x01, 0,        /* revision*/
    0x04,0x80,      /* type */
    0,0,0,0,        /* owner sid */
    0,0,0,0,        /* group sid */
    0,0,0,0,        /* sacl */
    0x14,0,0,0,     /* dacl */
        /* DACL */
    2,0,            /* revision */
    76,0,           /* size */
    3,0,0,0,        /* num ACEs */
        /* ACE: S-1-1-0 */
    0x00,0x00,0x14,0x00,0xbf,0x01,0x13,0x00,0x01,0x01,0,0,0,0,0,0x01,0,0,0,0,
/*    0x00,0x00,0x14,0x00,0xff,0x01,0x1f,0x00,0x01,0x01,0,0,0,0,0,0x01,0,0,0,0,*/
        /* ACE: S-1-5-32-544 */
    0x00,0x03,0x18,0x00,0xff,0x01,0x1f,0x00,0x01,0x02,0,0,0,0,0,0x05,0x20,0,0,0,0x20,0x02,0,0,
        /* ACE: S-1-5-32-545 */
    0x00,0x03,0x18,0x00,0xbf,0x01,0x13,0x00,0x01,0x02,0,0,0,0,0,0x05,0x20,0,0,0,0x21,0x02,0,0,
        /* ACE: S-1-5-32-512 */
/*    0x00,0x03,0x18,0x00,0xff,0x01,0x1f,0x00,0x01,0x02,0,0,0,0,0,0x05,0x20,0,0,0,0,0x02,0,0*/
};

/* special groups default ACEs */
/* Everyone: ACE: S-1-1-0 */
static const NQ_BYTE EveryoneSID[] = {0x01,0x01,0,0,0,0,0,0x01,0,0,0,0};
/* Administrators: ACE: S-1-5-32-544 */
static const NQ_BYTE AdminsSID[] = {0x01,0x02,0,0,0,0,0,0x05,0x20,0,0,0,0x20,0x02,0,0};
/* Users: ACE: S-1-5-32-545 */
static const NQ_BYTE UsersSID[] = {0x01,0x02,0,0,0,0,0,0x05,0x20,0,0,0,0x21,0x02,0,0};

/* default empty SD for shares */
static const NQ_BYTE shareEmptySecurityDescriptor[] =
{       /* SD */
    0x01, 0,        /* revision*/
    0x04,0x80,      /* type */
    0,0,0,0,        /* owner sid */
    0,0,0,0,        /* group sid */
    0,0,0,0,        /* sacl */
    0x14,0,0,0,     /* dacl */
        /* DACL */
    2,0,            /* revision */
    8,0,            /* size */
    0,0,0,0,        /* num ACEs */
};

/* "non-supported" SD */
static const NQ_BYTE noneSecurityDescriptor[] =
{       /* SD */
    0x01, 0,        /* revision*/
    0x04,0x80,      /* type */
    0x14,0,0,0,     /* owner sid */
    0x20,0,0,0,     /* group sid */
    0,0,0,0,        /* sacl */
    0,0,0,0,     /* dacl */
        /* owner S-1-1-0 */
    0x01,0x01,0,0,0,0,0,0x01,0,0,0,0,
		/* group S-1-1-0 */
    0x01,0x01,0,0,0,0,0,0x01,0,0,0,0,
};

/* default SD for readonly shares */
static const NQ_BYTE readonlyShareSecurityDescriptor[] =
{       /* SD */
    0x01, 0,        /* revision*/
    0x04,0x80,      /* type */
    0,0,0,0,        /* owner sid */
    0,0,0,0,        /* group sid */
    0,0,0,0,        /* sacl */
    0x14,0,0,0,     /* dacl */
        /* DACL */
    2,0,            /* revision */
    28,0,           /* size */
    1,0,0,0,        /* num ACEs */
        /* ACE: S-1-1-0 */
    0x00,0x00,0x14,0x00,0xa9,0x00,0x12,0x00,0x01,0x01,0,0,0,0,0,0x01,0,0,0,0,
        /* ACE: S-1-5-32-544 */
/*    0x00,0x03,0x18,0x00,0xff,0x01,0x1f,0x00,0x01,0x02,0,0,0,0,0,0x05,0x20,0,0,0,0x20,0x02,0,0*/
};

/* default SD for shares with administrative access only */
static const NQ_BYTE adminonlyShareSecurityDescriptor[] =
{       /* SD */
    0x01, 0,        /* revision*/
    0x04,0x81,      /* type */
    0,0,0,0,        /* owner sid */
    0,0,0,0,        /* group sid */
    0,0,0,0,        /* sacl */
    0x14,0,0,0,     /* dacl */
        /* DACL */
    2,0,            /* revision */
    32,0,           /* size */
    1,0,0,0,        /* num ACEs */
        /* ACE: S-1-5-32-544 */
    0x00,0x03,0x18,0x00,0xff,0x01,0x1f,0x00,0x01,0x02,0,0,0,0,0,0x05,0x20,0,0,0,0x20,0x02,0,0
};

#ifdef UD_CS_INCLUDESECURITYDESCRIPTORS
#ifdef UD_NQ_INCLUDECIFSSERVER
/* check whether given SID matches user's domain and rid pair */
static NQ_BOOL                          /* TRUE when match */
matchSid(
    const CMSdDomainSid* domain1,       /* SID in ACE */
    const CMSdDomainSid* domain2,       /* user's domain SID */
    CMSdRid rid1,                       /* RID in ACE */
    CMSdRid rid2                        /* user's RID */
    );
#endif /* UD_NQ_INCLUDECIFSSERVER */

#if SY_DEBUGMODE
static void dumpSid(const NQ_CHAR *title, NQ_BYTE *buffer, NQ_INT length, NQ_INT offset);
static NQ_BYTE *dumpDomainSid(const CMSdDomainSid *sid);
static void dumpAcl(const NQ_CHAR *title, NQ_BYTE *buffer, NQ_INT length, NQ_INT offset);
static CMSdAce *dumpAce(const CMSdAce *ace);
#endif

#endif

/*
 *====================================================================
 * PURPOSE: Initialize this module
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *====================================================================
 */

NQ_STATUS
cmSdInit(
    void
    )
{
    /* allocate memory */
#ifdef SY_FORCEALLOCATION
    staticData = (StaticData*)syCalloc(1, sizeof(*staticData));
    if (NULL == staticData)
    {
        TRCERR("Unable to allocate SD data");
        TRCE();
        return NQ_FAIL;
    }
#endif /* SY_FORCEALLOCATION */

#ifdef UD_NQ_INCLUDECIFSSERVER
    staticData->domainAliasSidSet = FALSE;
    staticData->domainSidSet = FALSE;
    syMemcpy(
        &staticData->domainSid,
        &constDomainSid,
        sizeof(staticData->domainSid)
        );
    syMemcpy(
            &staticData->computerSid,
            &constComputerSid,
            sizeof(staticData->computerSid)
            );
    staticData->computerSidSet = FALSE;
    cmSdGetComputerSid();
#endif /* UD_NQ_INCLUDECIFSSERVER */
     return NQ_SUCCESS;
}

/*
 *====================================================================
 * PURPOSE: Release data
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: NONE
 *====================================================================
 */

void
cmSdExit(
    void
    )
{
    /* release memory */
#ifdef SY_FORCEALLOCATION
    if (NULL != staticData)
        syFree(staticData);
    staticData = NULL;
#endif /* SY_FORCEALLOCATION */
}

/*
 *====================================================================
 * PURPOSE: check security descriptor
 *--------------------------------------------------------------------
 * PARAMS:  IN descriptor to check
 *
 * RETURNS: TRUE when descriptor is valid
 *
 * NOTES:
 *====================================================================
 */

NQ_BOOL
cmSdIsValid(
    const CMSdSecurityDescriptor* pSd
    )
{
    const CMSdSecurityDescriptorHeader* pHdr;     /* casted pointer to SD header */
    const CMSdAcl* pAcl;                          /* ACL pointer */
    const CMSdAce* pAce;                          /* running ACE pointer */
    NQ_COUNT aceIdx;                              /* ACE index in ACL */
    const NQ_BYTE* limit;                         /* the highest address ACL can contain */

    TRCB();

    limit = (const NQ_BYTE*)(pSd + 1);
    if (pSd->length > sizeof(pSd->data))
    {
        TRCERR("SD too long");
        TRC1P("  length: %ld", pSd->length);
        TRCE();
        return FALSE;
    }

    pHdr = (CMSdSecurityDescriptorHeader*)pSd->data;
    if (0 == pHdr->dacl ||
        pHdr->dacl > UD_CS_SECURITYDESCRIPTORLENGTH - sizeof(CMSdAcl) - sizeof(CMSdAce))
    {
        TRCERR("Security descriptor has no or invalid DACL offset");
        TRC1P("DACL: %ld", pHdr->dacl);
        TRCE();
        return FALSE;
    }

    pAcl = (const CMSdAcl*)(pSd->data + pHdr->dacl);

    for (aceIdx = 0,     \
           pAce = (const CMSdAce*)(pAcl + 1);
         aceIdx < pAcl->numAces;
         aceIdx++,
           pAce = (const CMSdAce*)((NQ_BYTE*)pAce + pAce->size)
         )
    {
        if ((NQ_BYTE*)pAce > limit)
        {
            TRCERR("Security descriptor too long, probably corrupted");
            TRCE();
            return FALSE;
        }
        if (pAce->size > sizeof(*pAce))
        {
            TRCERR("ACE too long in descriptor, probably corrupted");
            TRC1P(" index: %d", aceIdx);
            TRCE();
            return FALSE;
        }
    }

    TRCE();
    return TRUE;
}

/*
 *====================================================================
 * PURPOSE: determine if this user has administrative access
 *--------------------------------------------------------------------
 * PARAMS:  IN user access token
 *
 * RETURNS: TRUE when access is allowed
 *
 * NOTES:
 *====================================================================
 */

NQ_BOOL
cmSdIsAdministrator(
    const CMSdAccessToken* token
    )
{
    NQ_INT i;       /* just a counter */

    if (cmSdIsAdmin(token->rids[0]))
        return TRUE;            /* local administrator */

    for (i = 1; i < token->numRids; i++)
    {
        if (   token->rids[i] == CM_SD_RIDADMINISTRATOR
            || token->rids[i] == CM_SD_RIDGROUPADMINS
            || token->rids[i] == CM_SD_RIDALIASADMIN
           )
            return TRUE;        /* domain administrator or alias */
    }
    return FALSE;
}

#endif /* defined(UD_CS_INCLUDESECURITYDESCRIPTORS) || defined(UD_CC_INCLUDESECURITYDESCRIPTORS) || defined (UD_CC_INCLUDEDOMAINMEMBERSHIP)*/

#ifdef UD_NQ_INCLUDECIFSSERVER

/*
 *====================================================================
 * PURPOSE: determine user's access by ACL
 *--------------------------------------------------------------------
 * PARAMS:  IN user access token
 *          IN security descriptor data
 *          IN desired access mask
 *
 * RETURNS: TRUE when access is allowed
 *
 * NOTES:   We consider DACL only by comparing each ACE until either
 *          all are parsed or the first match both access bits and
 *          the SID
 *====================================================================
 */

NQ_BOOL
cmSdHasAccess(
    const CMSdAccessToken* token,
    const NQ_BYTE* sd,
    CMSdAccessFlags access
    )
{
#ifdef UD_CS_INCLUDESECURITYDESCRIPTORS
    const CMSdSecurityDescriptorHeader* pHdr;     /* casted pointer to SD header */
    const CMSdAcl* pAcl;                          /* ACL pointer */
    const CMSdAce* pAce;                          /* running ACE pointer */
    NQ_COUNT aceIdx;                              /* ACE index in ACL */
    NQ_COUNT ridIdx;                              /* RID index in token */
    const NQ_BYTE* limit;                         /* the highest address ACL can contain */
    NQ_BOOL result = FALSE;                       /* return value */
    static const CMSdDomainSid defDomain = {      /* ACE: S-1-5-32 + one unknown sub-authority */
      0x01,0x02,{0,0,0,0,0,0x05},
      {0x20,0,0,0,0,0}
    };
    static const CMSdDomainSid everyone = {       /* ACE: S-1-1-0 */
      0x01,0x01,{0,0,0,0,0,0x01},
      {0,0,0,0,0,0}
    };

    #define ANYDACLACCESS ( SMB_DESIREDACCESS_WRITEDAC | \
                            SMB_DESIREDACCESS_WRITEOWNER | \
                            SMB_DESIREDACCESS_SYNCHRONISE | \
                            SMB_DESIREDACCESS_WRITEOWNER \
                          )

    TRCB();
    
    /* allow any DACL access for local administrators */

    if ((access & ANYDACLACCESS) > 0)
    {
        for (ridIdx = 0; ridIdx < token->numRids; ridIdx++
             )
        {
            if (CM_SD_RIDALIASADMIN == token->rids[ridIdx])
                return TRUE;
        }
    }

    /* validate SD */
    limit = sd + UD_CS_SECURITYDESCRIPTORLENGTH;
    pHdr = (CMSdSecurityDescriptorHeader*)sd;
    if (0 == pHdr->dacl ||
        pHdr->dacl > UD_CS_SECURITYDESCRIPTORLENGTH - sizeof(CMSdAcl) - sizeof(CMSdAce))
    {
        TRCERR("Security descriptor has no or invalid DACL offset");
        TRC1P("DACL: %ld", pHdr->dacl);
        TRCE();
        return FALSE;
    }
    pAcl = (const CMSdAcl*)(sd + pHdr->dacl);

    for (aceIdx = 0,
           pAce = (const CMSdAce*)(pAcl + 1);
         aceIdx < pAcl->numAces;
         aceIdx++,
           pAce = (const CMSdAce*)((NQ_BYTE*)pAce + pAce->size)
         )
    {
        if ((NQ_BYTE*)pAce > limit)
        {
            TRCERR("Security descriptor too long, probably corrupted");
            TRCE();
            return FALSE;
        }
        if (syMemcmp(
                &pAce->trustee,
                &everyone,
                (NQ_UINT)sizeof(everyone) - (NQ_UINT)(6 - everyone.numAuths) * (NQ_UINT)sizeof(CMSdRid)
            ) == 0)
        {
            if ((access & pAce->accessMask) == access)
            {
                if (pAce->type == CM_SD_DENY)
                    return FALSE;
                result = TRUE;
            }
            continue;
        }
        if (NULL == token)
        {
            continue;
        }
        for (ridIdx = 0; ridIdx < token->numRids; ridIdx++
             )
        {
            if ((syMemcmp(
                        &pAce->trustee,
                        &defDomain,
                        (NQ_UINT)sizeof(defDomain) - (NQ_UINT)(6 - defDomain.numAuths + 1) * (NQ_UINT)sizeof(CMSdRid)
                        ) == 0 &&
                   matchSid(
                        &staticData->computerSid,
                        &token->domain,
                        pAce->trustee.subs[pAce->trustee.numAuths - 1],
                        token->rids[ridIdx]
                        )
                ) ||
                matchSid(
                    &pAce->trustee,
                    &token->domain,
                    pAce->trustee.subs[pAce->trustee.numAuths - 1],
                    token->rids[ridIdx]
                    )
               )
            {
                if ((access & pAce->accessMask) == access)
                {
                    if (pAce->type == CM_SD_DENY)
                        return FALSE;
                    result = TRUE;
                }
            }
        }
    }

    TRCE();
    return result;
#else  /* UD_CS_INCLUDESECURITYDESCRIPTORS */
    if (token->isAnon)
    {
    	if( (access & (SMB_DESIREDACCESS_WRITEDATA |
    			SMB_DESIREDACCESS_APPENDDATA |
    			SMB_DESIREDACCESS_WRITEEA |
    			SMB_DESIREDACCESS_DELETECHILD |
    			SMB_DESIREDACCESS_WRITEATTRIBUTES |
    			SMB_DESIREDACCESS_DELETE |
    			SMB_DESIREDACCESS_GENWRITE |
    			SMB_DESIREDACCESS_GENALL |
    			SMB_DESIREDACCESS_WRITEOWNER |
    			SMB_DESIREDACCESS_WRITEDAC
    			)))
    	{
    		return FALSE;
    	}
    	else
    		return TRUE;
    }
    else
    	return TRUE;
#endif /* UD_CS_INCLUDESECURITYDESCRIPTORS */
}

#endif /* UD_NQ_INCLUDECIFSSERVER */

#if defined(UD_CS_INCLUDESECURITYDESCRIPTORS) || defined(UD_CC_INCLUDESECURITYDESCRIPTORS)|| defined (UD_CC_INCLUDEDOMAINMEMBERSHIP) || defined(UD_CS_INCLUDEPASSTHROUGH)

/*
 *====================================================================
 * PURPOSE: get default SD with no owner
 *--------------------------------------------------------------------
 * PARAMS:  OUT buffer for resulting descriptor size
 *
 * RETURNS: TRUE on success
 *
 * NOTES:
 *====================================================================
 */

NQ_BOOL
cmSdGetDefaultSecurityDescriptor(
    CMSdSecurityDescriptor* pSd
    )
{
    CMRpcPacketDescriptor descr;    /* packet descriptor for parsing Littel Endian SD */

    cmRpcSetDescriptor(&descr, (NQ_BYTE*)defaultSecurityDescriptor, FALSE);
    cmSdParseSecurityDescriptor(&descr, pSd);
    return TRUE;
}

/*
 *====================================================================
 * PURPOSE: get default SD for a share
 *--------------------------------------------------------------------
 * PARAMS:  OUT buffer for resulting descriptor
 *
 * RETURNS: TRUE on success
 *
 * NOTES:
 *====================================================================
 */

NQ_BOOL
cmSdGetShareSecurityDescriptor(
    CMSdSecurityDescriptor* pSd
    )
{
    CMRpcPacketDescriptor descr;    /* packet descriptor for parsing Little Endian SD */

    cmRpcSetDescriptor(&descr, (NQ_BYTE*)shareSecurityDescriptor, FALSE);
    cmSdParseSecurityDescriptor(&descr, pSd);
    return TRUE;
}

/*
 *====================================================================
 * PURPOSE: get empty SD for a share
 *--------------------------------------------------------------------
 * PARAMS:  OUT buffer for resulting descriptor
 *
 * RETURNS: TRUE on success
 *
 * NOTES:
 *====================================================================
 */

NQ_BOOL
cmSdGetEmptyShareSecurityDescriptor(
    CMSdSecurityDescriptor* pSd
    )
{
    CMRpcPacketDescriptor descr;    /* packet descriptor for parsing Little Endian SD */

    cmRpcSetDescriptor(&descr, (NQ_BYTE*)shareEmptySecurityDescriptor, FALSE);
    cmSdParseSecurityDescriptor(&descr, pSd);
    return TRUE;
}

/*
 *====================================================================
 * PURPOSE: get "non-supported" SD 
 *--------------------------------------------------------------------
 * PARAMS:  OUT buffer for resulting descriptor
 *
 * RETURNS: TRUE on success
 *
 * NOTES:   This descriptor has "WorldSid" for owner and NULL for others
 *====================================================================
 */

NQ_BOOL
cmSdGetNoneSecurityDescriptor(
    CMSdSecurityDescriptor* pSd
    )
{
    CMRpcPacketDescriptor descr;    /* packet descriptor for parsing Little Endian SD */

    cmRpcSetDescriptor(&descr, (NQ_BYTE*)noneSecurityDescriptor, FALSE);
    cmSdParseSecurityDescriptor(&descr, pSd);
    return TRUE;
}

/*
 *====================================================================
 * PURPOSE: get read-only SD for a share
 *--------------------------------------------------------------------
 * PARAMS:  OUT buffer for resulting descriptor
 *
 * RETURNS: TREU on success
 *
 * NOTES:
 *====================================================================
 */

NQ_BOOL
cmSdGetReadonlyShareSecurityDescriptor(
    CMSdSecurityDescriptor* pSd
    )
{
    CMRpcPacketDescriptor descr;    /* packet descriptor for parsing Little Endian SD */

    cmRpcSetDescriptor(&descr, (NQ_BYTE*)readonlyShareSecurityDescriptor, FALSE);
    cmSdParseSecurityDescriptor(&descr, pSd);
    return TRUE;
}

/*
 *====================================================================
 * PURPOSE: get admin-only SD for a share
 *--------------------------------------------------------------------
 * PARAMS:  OUT buffer for resulting descriptor
 *
 * RETURNS: TREU on success
 *
 * NOTES:
 *====================================================================
 */

NQ_BOOL
cmSdGetAdminonlyShareSecurityDescriptor(
    CMSdSecurityDescriptor* pSd
    )
{
    CMRpcPacketDescriptor descr;    /* packet descriptor for parsing Little Endian SD */

    cmRpcSetDescriptor(&descr, (NQ_BYTE*)adminonlyShareSecurityDescriptor, FALSE);
    cmSdParseSecurityDescriptor(&descr, pSd);
    return TRUE;
}


const NQ_BYTE*
cmSdGetEveryoneGroupACE(
    void
    )
{
    return EveryoneSID;
}

const NQ_BYTE*
cmSdGetAdministratorsGroupACE(
    void
    )
{
    return AdminsSID;
}

const NQ_BYTE*
cmSdGetUsersGroupACE(
    void
    )
{
    return UsersSID;
}

/*
 *====================================================================
 * PURPOSE: get default SD by token
 *--------------------------------------------------------------------
 * PARAMS:  IN user access token to be the owner
 *          OUT buffer for resulting descriptor
 *
 * RETURNS: TRUE on success
 *
 * NOTES:
 *====================================================================
 */

NQ_BOOL
cmSdGetDefaultSecurityDescriptorByToken(
    const CMSdAccessToken* token,
    CMSdSecurityDescriptor* pSd
    )
{
    CMRpcPacketDescriptor descr;        /* packet descriptor for parsing Little Endian SD */
    CMSdSecurityDescriptorHeader* pHdr; /* casted pointer to the header */
    CMSdAcl* pAcl;                      /* casted pointer to DACL */
    CMSdAce* pAce;                      /* casted pointer to DACL */

    cmRpcSetDescriptor(&descr, (NQ_BYTE*)defaultJobSecurityDescriptor, FALSE);
    cmSdParseSecurityDescriptor(&descr, pSd);
    pHdr = (CMSdSecurityDescriptorHeader*) pSd->data;
    pAcl = (CMSdAcl*) (pSd->data + pHdr->dacl);
    pAcl->numAces++;
    pAce = (CMSdAce*)(pSd->data + pSd->length);
    pAce->type = CM_SD_ALLOW;
    pAce->flags = CM_SD_CONTAINERINHERIT | CM_SD_OBJECTINHERIT;
    pAce->accessMask = 0x001f01ff;
    syMemcpy(&pAce->trustee, &token->domain, sizeof(token->domain));
    pAce->trustee.subs[pAce->trustee.numAuths++] = token->rids[0];
    pAce->size = (NQ_UINT16)(((NQ_UINT16)sizeof(*pAce) - (6 - pAce->trustee.numAuths) * (NQ_UINT16)sizeof (CMSdRid)));
    pSd->length += pAce->size;

    return TRUE;
}

#ifdef UD_NQ_INCLUDECIFSSERVER

/*
 *====================================================================
 * PURPOSE: get default SD for user
 *--------------------------------------------------------------------
 * PARAMS:  IN owner's RID
 *          OUT buffer for resulting descriptor
 *
 * RETURNS: TRUE on success
 *
 * NOTES:
 *====================================================================
 */

NQ_BOOL
cmSdGetLocalSecurityDescriptorForUser(
    CMSdRid rid,
    CMSdSecurityDescriptor* pSd
    )
{
    CMSdSecurityDescriptorHeader* pHdr; /* casted pointer to the header */
    CMSdAcl* pAcl;                      /* casted pointer to DACL */
    CMSdAce* pAce;                      /* casted pointer to ACE */

    pHdr = (CMSdSecurityDescriptorHeader*) pSd->data;
    pHdr->revision =  1;
    pHdr->type = CM_SD_DACLPRESENT | CM_SD_SELF_RELATIVE;
    pHdr->groupSid = 0;
    pHdr->ownerSid = 0;
    pHdr->dacl = 20;
    pAcl = (CMSdAcl*) (pSd->data + pHdr->dacl);
    pAcl->revision = 2;
    pAcl->numAces = 4;
    pAcl->size = 112;
    pAce = (CMSdAce*)((NQ_BYTE*)pAcl + sizeof(*pAcl));
    /* Everyone */
    pAce->type = CM_SD_ALLOW;
    pAce->flags = 0;
    pAce->accessMask = 0x0002035b;    /* Windows server sends 0x2035b. However,
     * from us Win client expects 0x20075, otherwise it tries to update the
     * value */
    pAce->size = 20;
    pAce->trustee.revision = 1;
    pAce->trustee.numAuths = 1;
    pAce->trustee.idAuth[0] = 0;
    pAce->trustee.idAuth[1] = 0;
    pAce->trustee.idAuth[2] = 0;
    pAce->trustee.idAuth[3] = 0;
    pAce->trustee.idAuth[4] = 0;
    pAce->trustee.idAuth[5] = 1;
    pAce->trustee.subs[0] = 0;
    pAce = (CMSdAce*)((NQ_BYTE*)pAce + pAce->size);
    /* Administrator */
    pAce->type = CM_SD_ALLOW;
    pAce->flags = 0;
    pAce->accessMask = 0x000f07ff;
    pAce->size = 24;
    pAce->trustee.revision = 1;
    pAce->trustee.numAuths = 2;
    pAce->trustee.idAuth[0] = 0;
    pAce->trustee.idAuth[1] = 0;
    pAce->trustee.idAuth[2] = 0;
    pAce->trustee.idAuth[3] = 0;
    pAce->trustee.idAuth[4] = 0;
    pAce->trustee.idAuth[5] = 5;
    pAce->trustee.subs[0] = 32;
    pAce->trustee.subs[1] = CM_SD_RIDALIASADMIN;
    pAce = (CMSdAce*)((NQ_BYTE*)pAce + pAce->size);
    /* Account operator */
    pAce->type = CM_SD_ALLOW;
    pAce->flags = 0;
    pAce->accessMask = 0x000f07ff;
    pAce->size = 24;
    pAce->trustee.revision = 1;
    pAce->trustee.numAuths = 2;
    pAce->trustee.idAuth[0] = 0;
    pAce->trustee.idAuth[1] = 0;
    pAce->trustee.idAuth[2] = 0;
    pAce->trustee.idAuth[3] = 0;
    pAce->trustee.idAuth[4] = 0;
    pAce->trustee.idAuth[5] = 5;
    pAce->trustee.subs[0] = 32;
    pAce->trustee.subs[1] = CM_SD_RIDALIASACCOUNTOP;
    pAce = (CMSdAce*)((NQ_BYTE*)pAce + pAce->size);
    /* Computer SID + user RID */
    pAce->type = CM_SD_ALLOW;
    pAce->flags = 0;
    pAce->accessMask = 0x00020044;
    pAce->size = 36;
    syMemcpy(&pAce->trustee, cmSdGetComputerSid(), sizeof(CMSdDomainSid));
    pAce->trustee.subs[4] = rid;
    pAce->trustee.numAuths++;
    pAce = (CMSdAce*)((NQ_BYTE*)pAce + pAce->size);

    pSd->length = (NQ_UINT32)((NQ_BYTE*)pAce - pSd->data);

    return TRUE;
}

/*
 *====================================================================
 * PURPOSE: set host domain's SID
 *--------------------------------------------------------------------
 * PARAMS:  IN pointer to SID to set
 *
 * RETURNS: None
 *
 * NOTES:
 *====================================================================
 */

void
cmSdSetDomainSid(
    const CMSdDomainSid* sid
    )
{
    if (TRUE == staticData->domainSidSet) return;
    syMemcpy(&staticData->domainSid, sid, sizeof(staticData->domainSid));
    staticData->domainSidSet = TRUE;
}

/*
 *====================================================================
 * PURPOSE: get host domain's SID
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: pointer to domain SID
 *
 * NOTES:   if domain SID was not set yet computer SID is used instead
 *====================================================================
 */

const CMSdDomainSid*
cmSdGetDomainSid(
    void
    )
{
    if (!staticData->domainSidSet)
    {
        return cmSdGetComputerSid();
    }
    return &staticData->domainSid;
}

/*
 *====================================================================
 * PURPOSE: get local domain SID alias
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: pointer to domain SID
 *
 * NOTES:   returns S-1-1-5-32
 *====================================================================
 */

const CMSdDomainSid*
cmSdGetLocalDomainAlias(
    void
    )
{
    if (!staticData->domainAliasSidSet)
    {
        staticData->domainAliasSid.revision = 1;
        staticData->domainAliasSid.numAuths = 1;
        staticData->domainAliasSid.idAuth[0] = 0;
        staticData->domainAliasSid.idAuth[1] = 0;
        staticData->domainAliasSid.idAuth[2] = 0;
        staticData->domainAliasSid.idAuth[3] = 0;
        staticData->domainAliasSid.idAuth[4] = 0;
        staticData->domainAliasSid.idAuth[5] = 5;
        staticData->domainAliasSid.subs[0] =  32;
        staticData->domainAliasSidSet = TRUE;
    }
    return &staticData->domainAliasSid;
}

/*
 *====================================================================
 * PURPOSE: get host computer SID
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: pointer to computer SID
 *
 * NOTES:
 *====================================================================
 */

const CMSdDomainSid*
cmSdGetComputerSid(
    void
    )
{
    if (!staticData->computerSidSet)
    {
        udGetComputerId((NQ_BYTE*)&staticData->computerSid.subs[1]);
        staticData->computerSidSet = TRUE;
    }

    return &staticData->computerSid;
}

/*
 *====================================================================
 * PURPOSE: checks if domain SID was set
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: TRUE if already set
 *
 * NOTES:
 *====================================================================
 */

NQ_BOOL
cmSdIsDomainSidSet(
    void
    )
{
    return staticData->domainSidSet;
}

#endif /* UD_NQ_INCLUDECIFSSERVER */

/*
 *====================================================================
 * PURPOSE: parse domain SID
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT incoming packet descriptor
 *          OUT buffer for SID
 *
 * RETURNS: None
 *
 * NOTES:
 *====================================================================
 */

void cmSdParseSid(
    CMRpcPacketDescriptor* in,
    CMSdDomainSid* sid
    )
{
    NQ_INT i;   /* just a counter */

    cmRpcParseByte(in, &sid->revision);
    cmRpcParseByte(in, &sid->numAuths);
    if (sid->numAuths > sizeof(sid->subs)/sizeof(sid->subs[0]))
    {
        sid->numAuths = sizeof(sid->subs)/sizeof(sid->subs[0]);
    }
    cmRpcParseBytes(in, sid->idAuth, 6);
    for (i = 0; i < sid->numAuths; i++)
    {
        NQ_UINT32 t;
        cmRpcParseUint32(in, &t);
        sid->subs[i] = t;
    }
}

/*
 *====================================================================
 * PURPOSE: compare domain SID with "Any" SID
 *--------------------------------------------------------------------
 * PARAMS:  IN SID to compare
 *
 * RETURNS: TRUE on match
 *
 * NOTES:
 *====================================================================
 */

NQ_BOOL
cmSdIsAnySid(
    const CMSdDomainSid* sid
    )
{
    return sid->numAuths == anyDomainSid.numAuths
        && 0 == syMemcmp(sid->subs, anyDomainSid.subs, sid->numAuths * sizeof(sid->subs[0]));
}

#ifdef UD_NQ_INCLUDECIFSSERVER

/*
 *====================================================================
 * PURPOSE: checks if our server knows an alias
 *--------------------------------------------------------------------
 * PARAMS:  IN SID with domain SID + alias RID
 *          OUT buffer for alias RID
 *
 * RETURNS: TRUE when we suppor this alias
 *
 * NOTES:   The domain portion of the SID should match computer SID
 *          The last authority should be RID for a well known user, group
 *          or alias.
 *====================================================================
 */

NQ_BOOL
cmSdCheckAlias(
    const CMSdDomainSid* sid,
    CMSdRid* alias
    )
{
    const CMSdDomainSid* compSid;        /* computer SID */

    compSid = cmSdGetComputerSid();
    if (   sid->numAuths != compSid->numAuths + 1
        || 0 != syMemcmp(sid->subs, compSid->subs, compSid->numAuths * sizeof(compSid->subs[0]))
       )
    {
        return FALSE;
    }
    switch (sid->subs[sid->numAuths - 1])
    {
    case CM_SD_RIDADMINISTRATOR:
    case CM_SD_RIDGUEST:
        *alias = CM_SD_RIDALIASGUEST;
        break;
    case CM_SD_RIDGROUPADMINS:
        *alias = CM_SD_RIDALIASADMIN;
        break;
    case CM_SD_RIDGROUPUSERS:
        *alias = CM_SD_RIDALIASUSER;
        break;
    case CM_SD_RIDGROUPGUESTS:
        *alias = CM_SD_RIDALIASGUEST;
        break;
    case CM_SD_RIDALIASADMIN:
        *alias = CM_SD_RIDALIASADMIN;
        break;
    case CM_SD_RIDALIASUSER:
        *alias = CM_SD_RIDALIASUSER;
        break;
    case CM_SD_RIDALIASGUEST:
        *alias = CM_SD_RIDALIASGUEST;
        break;
    default:
        *alias = CM_SD_RIDALIASUSER;
        return TRUE;
    }
    return TRUE;
}

/*
 *====================================================================
 * PURPOSE: compare domain SID with computer SID
 *--------------------------------------------------------------------
 * PARAMS:  IN SID to compare
 *
 * RETURNS: TRUE on match
 *
 * NOTES:
 *====================================================================
 */

NQ_BOOL
cmSdIsComputerSid(
    const CMSdDomainSid* sid
    )
{
    const CMSdDomainSid* compSid;        /* computer SID */

    compSid = cmSdGetComputerSid();
    return sid->numAuths == compSid->numAuths
        && 0 == syMemcmp(sid->subs, compSid->subs, sid->numAuths * sizeof(sid->subs[0]));
}

#endif /* UD_NQ_INCLUDECIFSSERVER */

/*
 *====================================================================
 * PURPOSE: pack domain SID
 *--------------------------------------------------------------------
 * PARAMS:  OUT outgoing packet descriptor
 *          IN SID to pack
 *
 * RETURNS: None
 *
 * NOTES:
 *====================================================================
 */

void cmSdPackSid(
    CMRpcPacketDescriptor* out,
    const CMSdDomainSid* sid
    )
{
    NQ_INT i;   /* just a counter */

    cmRpcPackByte(out, sid->revision);
    cmRpcPackByte(out, sid->numAuths);
    cmRpcPackBytes(out, sid->idAuth, 6);
    for (i = 0; i < sid->numAuths; i++)
        cmRpcPackUint32(out, sid->subs[i]);
}

/*
 *====================================================================
 * PURPOSE: pack full user SID
 *--------------------------------------------------------------------
 * PARAMS:  OUT outgoing packet descriptor
 *          IN SID to pack
 *          IN RID to pack
 *
 * RETURNS: None
 *
 * NOTES:
 *====================================================================
 */

void cmSdPackSidRid(
    CMRpcPacketDescriptor* out,
    const CMSdDomainSid* sid,
    NQ_UINT32 rid
    )
{
    NQ_INT i;   /* just a counter */

    cmRpcPackByte(out, sid->revision);
    /* number of sub authorities should include an additional RID */
    cmRpcPackByte(out, (NQ_BYTE)(sid->numAuths + 1));
    cmRpcPackBytes(out, sid->idAuth, 6);

    for (i = 0; i < sid->numAuths; i++)
        cmRpcPackUint32(out, sid->subs[i]);

    cmRpcPackUint32(out, rid);
}

/*
 *====================================================================
 * PURPOSE: parse Security Descriptor
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT incoiming packet descriptor
 *          OUT buffer for SD
 *
 * RETURNS: None
 *
 * NOTES:
 *====================================================================
 */

void cmSdParseSecurityDescriptor(
    CMRpcPacketDescriptor* in,
    CMSdSecurityDescriptor* pSd
    )
{
    CMSdSecurityDescriptorHeader* pHdr;     /* casted pointer to SD header */
    CMSdDomainSid* pSid;                    /* casted pointer to SIDs */
    CMSdAcl* pAcl;                          /* casted pointer to ACL */
    NQ_BYTE* sdStart;                       /* pointer to SD start */

    sdStart = in->current;
    pHdr = (CMSdSecurityDescriptorHeader*)pSd->data;
    cmRpcParseUint16(in, &pHdr->revision);
    cmRpcParseUint16(in, &pHdr->type);
    cmRpcParseUint32(in, &pHdr->ownerSid);
    cmRpcParseUint32(in, &pHdr->groupSid);
    cmRpcParseUint32(in, &pHdr->sacl);
    cmRpcParseUint32(in, &pHdr->dacl);
    if (0 != pHdr->ownerSid)
    {
        pSid = (CMSdDomainSid*)((NQ_BYTE*)pSd->data + pHdr->ownerSid);
        in->current = sdStart + pHdr->ownerSid;
        cmSdParseSid(in, pSid);
    }
    if (0 != pHdr->groupSid)
    {
        pSid = (CMSdDomainSid*)((NQ_BYTE*)pSd->data + pHdr->groupSid);
        in->current = sdStart + pHdr->groupSid;
        cmSdParseSid(in, pSid);
    }
    if (0 != pHdr->sacl)
    {
        pAcl = (CMSdAcl*)((NQ_BYTE*)pSd->data + pHdr->sacl);
        in->current = sdStart + pHdr->sacl;
        cmSdParseAcl(in, pAcl, (const NQ_BYTE*)(pSd + 1));
    }
    if (0 != pHdr->dacl)
    {
        pAcl = (CMSdAcl*)((NQ_BYTE*)pSd->data + pHdr->dacl);
        in->current = sdStart + pHdr->dacl;
        cmSdParseAcl(in, pAcl, (const NQ_BYTE*)(pSd + 1));
    }
    pSd->length = (NQ_UINT32)(in->current - sdStart);
}

/*
 *====================================================================
 * PURPOSE: pack Security Descriptor
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT outgoing packet descriptor
 *          IN SD to pack
 *
 * RETURNS: None
 *
 * NOTES:
 *====================================================================
 */

void cmSdPackSecurityDescriptor(
    CMRpcPacketDescriptor* out,
    const CMSdSecurityDescriptor* pSd
    )
{
    CMSdSecurityDescriptorHeader* pHdr;     /* casted pointer to SD header */
    CMSdDomainSid* pSid;                    /* casted pointer to SIDs */
    CMSdAcl* pAcl;                          /* casted pointer to ACL */
    NQ_BYTE* sdStart, *max;

    sdStart = out->current;
    pHdr = (CMSdSecurityDescriptorHeader*)pSd->data;
    cmRpcPackUint16(out, pHdr->revision);
    cmRpcPackUint16(out, pHdr->type);
    cmRpcPackUint32(out, pHdr->ownerSid);
    cmRpcPackUint32(out, pHdr->groupSid);
    cmRpcPackUint32(out, pHdr->sacl);
    cmRpcPackUint32(out, pHdr->dacl);

    if (0 != pHdr->ownerSid)
    {
        pSid = (CMSdDomainSid*)((NQ_BYTE*)pSd->data + pHdr->ownerSid);
        out->current = sdStart + pHdr->ownerSid;
        cmSdPackSid(out, pSid);
    }

    max = out->current;

    if (0 != pHdr->groupSid)
    {
        pSid = (CMSdDomainSid*)((NQ_BYTE*)pSd->data + pHdr->groupSid);
        out->current = sdStart + pHdr->groupSid;
        cmSdPackSid(out, pSid);
    }

    if (out->current > max)
        max = out->current;

    if (0 != pHdr->sacl)
    {
        pAcl = (CMSdAcl*)((NQ_BYTE*)pSd->data + pHdr->sacl);
        out->current = sdStart + pHdr->sacl;
        cmSdPackAcl(out, pAcl);
    }

    if (out->current > max)
        max = out->current;

    if (0 != pHdr->dacl)
    {
        pAcl = (CMSdAcl*)((NQ_BYTE*)pSd->data + pHdr->dacl);
        out->current = sdStart + pHdr->dacl;
        cmSdPackAcl(out, pAcl);
    }

    /* set current to the most distant point */
    if (out->current < max)
        out->current = max;
}

/*
 *====================================================================
 * PURPOSE: parse Access Control List
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT outgoing packet descriptor
 *          OUT buffer for ACL
 *          IN highest address to use
 *
 * RETURNS: None
 *
 * NOTES:
 *====================================================================
 */

void cmSdParseAcl(
    CMRpcPacketDescriptor* in,
    CMSdAcl* pAcl,
    const NQ_BYTE* limit
    )
{
    CMSdAce* pAce;                          /* pointer to ACE */
    NQ_COUNT i;                             /* just a counter */

    if ((NQ_BYTE*)pAcl > limit - sizeof(*pAcl))
    {
        TRCERR("ACL buffer overflow");
    }
    cmRpcParseUint16(in, &pAcl->revision);
    cmRpcParseUint16(in, &pAcl->size);
    cmRpcParseUint32(in, &pAcl->numAces);

    pAce = (CMSdAce*)(pAcl + 1);
    for (i = 0; i < pAcl->numAces; i++)
    {
        NQ_BYTE* temp = in->current;

        if ((NQ_BYTE*)pAce > limit - sizeof(*pAce))
        {
            TRCERR("Two many ACEs");
        }
        cmSdParseAce(in, pAce);
        pAce = (CMSdAce*)((NQ_BYTE*)pAce + (in->current - temp));
    }
}

/*
 *====================================================================
 * PURPOSE: pack Access Control List
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT outgoing packet descriptor
 *          IN ACL to pack
 *
 * RETURNS: None
 *
 * NOTES:
 *====================================================================
 */

void cmSdPackAcl(
    CMRpcPacketDescriptor* out,
    const CMSdAcl* pAcl
    )
{
    CMSdAce* pAce;                          /* pointer to ACE */
    NQ_COUNT i;                             /* just a counter */

    cmRpcPackUint16(out, pAcl->revision);
    cmRpcPackUint16(out, pAcl->size);
    cmRpcPackUint32(out, pAcl->numAces);

    pAce = (CMSdAce*)(pAcl + 1);
    for (i = 0; i < pAcl->numAces; i++)
    {
        NQ_BYTE* temp = out->current;

        cmSdPackAce(out, pAce);
        pAce = (CMSdAce*)((NQ_BYTE*)pAce + (out->current - temp));
    }
}

/*
 *====================================================================
 * PURPOSE: parse Access Control Entry
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT outgoing packet descriptor
 *          OUT buffer for ACE
 *
 * RETURNS: None
 *
 * NOTES:
 *====================================================================
 */

void cmSdParseAce(
    CMRpcPacketDescriptor* in,
    CMSdAce* pAce
    )
{
    cmRpcParseByte(in, &pAce->type);
    cmRpcParseByte(in, &pAce->flags);
    cmRpcParseUint16(in, &pAce->size);
    cmRpcParseUint32(in, &pAce->accessMask);
    cmSdParseSid(in, &pAce->trustee);
}

/*
 *====================================================================
 * PURPOSE: pack Access Control Entry
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT outgoing packet descriptor
 *          IN ACE to pack
 *
 * RETURNS: None
 *
 * NOTES:
 *====================================================================
 */

void cmSdPackAce(
    CMRpcPacketDescriptor* out,
    const CMSdAce* pAce
    )
{
    cmRpcPackByte(out, pAce->type);
    cmRpcPackByte(out, pAce->flags);
    cmRpcPackUint16(out, pAce->size);
    cmRpcPackUint32(out, pAce->accessMask);
    cmSdPackSid(out, &pAce->trustee);
}

#ifdef UD_CS_INCLUDELOCALUSERMANAGEMENT

/*
 *====================================================================
 * PURPOSE: find local name by RID
 *--------------------------------------------------------------------
 * PARAMS:  IN local RID
 *          OUT buffer for name
 *          OUT buffer for full name
 *
 * RETURNS: TRUE when a user or alias for this RID was found
 *
 * NOTES:   RID may be either local user or a predefined local alias
 *====================================================================
 */

NQ_BOOL
cmSdLookupRid(
    CMSdRid rid,
    NQ_TCHAR* nameBuffer,
    NQ_TCHAR* fullNameBuffer
    )
{
    NQ_UINT i;        /* just a counter */

    for (i = 0; i < sizeof(localAliases)/sizeof(localAliases[0]); i++)
    {
        if (rid == localAliases[i].rid)
        {
            cmAnsiToTchar(nameBuffer, localAliases[i].name);
            cmAnsiToTchar(fullNameBuffer, localAliases[i].fullName);
            return TRUE;
        }
    }
    return udGetUserNameByRid(rid, nameBuffer, fullNameBuffer);
}

/*
 *====================================================================
 * PURPOSE: find RID by local name
 *--------------------------------------------------------------------
 * PARAMS:  IN name to look for
 *          OUT buffer for rid
 *
 * RETURNS: TRUE when a user or alias was found
 *
 * NOTES:   the name may designate either a local user or a predefined
 *          local alias
 *====================================================================
 */

NQ_BOOL
cmSdLookupName(
    const NQ_TCHAR* name,
    CMSdRid* rid
    )
{
    NQ_UINT i;                        /* just a counter */

    cmTcharToAnsiN(staticData->tempName, name, sizeof(staticData->tempName));
    for (i = 0; i < sizeof(localAliases)/sizeof(localAliases[0]); i++)
    {
        if (0 == syStrcmp(staticData->tempName, localAliases[i].name))
        {
            *rid = localAliases[i].rid;
            return TRUE;
        }
    }
    return udGetUserRidByName(name, rid);
}

/*
 *====================================================================
 * PURPOSE:
 *--------------------------------------------------------------------
 * PARAMS:  IN user's RID
 *
 * RETURNS: RID type
 *
 * NOTES:
 *====================================================================
 */


NQ_UINT32
cmSdGetRidType(
    CMSdRid rid
    )
{
    NQ_UINT i;                        /* just a counter */

    for (i = 0; i < sizeof(localAliases)/sizeof(localAliases[0]); i++)
    {
        if (rid == localAliases[i].rid)
        {
            return localAliases[i].type;
        }
    }
    return CM_SD_RIDTYPE_USER;
}

#endif /* UD_CS_INCLUDELOCALUSERMANAGEMENT */

/*
 *====================================================================
 * PURPOSE: create SD with exclusive rights for a given user
 *--------------------------------------------------------------------
 * PARAMS:  IN user token
 *          OUT buffer for the result
 *
 * RETURNS: TRUE on success, FALSE on failure
 *
 * NOTES:
 *====================================================================
 */

NQ_BOOL
cmSdCreateExclusiveSecurityDescriptor(
    const CMSdAccessToken* token,
    CMSdSecurityDescriptor* pSd
    )
{
    CMSdSecurityDescriptorHeader* pHdr; /* casted pointer to the header */
    CMSdAcl* pAcl;                      /* casted pointer to DACL */
    CMSdAce* pAce;                      /* casted pointer to ACE */
    CMSdDomainSid* pSid;                /* casted pointer to SID */

    pHdr = (CMSdSecurityDescriptorHeader*) pSd->data;
    pHdr->revision = 1;
    pHdr->type = CM_SD_DACLPRESENT | CM_SD_SELF_RELATIVE;
    pHdr->groupSid = 0;
    pHdr->ownerSid = 0;
    pHdr->dacl = 20;
    pAcl = (CMSdAcl*) (pSd->data + pHdr->dacl);
    pAcl->revision = 2;
    pAcl->numAces = 2;
    pAcl->size = 68;
    pAce = (CMSdAce*)((NQ_BYTE*)pAcl + sizeof(*pAcl));
    /* DACL: */
    /*   administrator */
    pAce->type = CM_SD_ALLOW;
    pAce->flags = 0x3;  /* container and object inherit */
    pAce->accessMask = 0x0001f01ff;
    pAce->size = 24;
    pAce->trustee.revision = 1;
    pAce->trustee.numAuths = 2;
    pAce->trustee.idAuth[0] = 0;
    pAce->trustee.idAuth[1] = 0;
    pAce->trustee.idAuth[2] = 0;
    pAce->trustee.idAuth[3] = 0;
    pAce->trustee.idAuth[4] = 0;
    pAce->trustee.idAuth[5] = 5;
    pAce->trustee.subs[0] = 32;
    pAce->trustee.subs[1] = CM_SD_RIDALIASADMIN;
    pAce = (CMSdAce*)((NQ_BYTE*)pAce + pAce->size);
    /*    user */
    pAce->type = CM_SD_ALLOW;
    pAce->flags = 0x3; /* container and object inherit */
    pAce->accessMask = 0x0001f01ff;
    pAce->size = 36;
    syMemcpy(&pAce->trustee, &token->domain, sizeof(token->domain));
    pAce->trustee.subs[pAce->trustee.numAuths] = token->rids[0];
    pAce->trustee.numAuths++;
    pAce = (CMSdAce*)((NQ_BYTE*)pAce + pAce->size);
    /* OWNER */
    pSid = (CMSdDomainSid*)pAce;
    pHdr->ownerSid = (NQ_UINT32)((NQ_BYTE*)pSid - pSd->data);
    syMemcpy(pSid, &token->domain, sizeof(token->domain));
    pSid->subs[pSid->numAuths] = token->rids[0];
    pSid->numAuths++;
    /* GROUP */
    pSid = (CMSdDomainSid*)((NQ_BYTE*)pSid->subs + sizeof(pSid->subs[0]) * pSid->numAuths);
    pHdr->groupSid = (NQ_UINT32)((NQ_BYTE*)pSid - pSd->data);
    syMemcpy(pSid, &token->domain, sizeof(token->domain));
    pSid->subs[pSid->numAuths] = CM_SD_RIDGROUPUSERS;
    pSid->numAuths++;

    pSid = (CMSdDomainSid*)((NQ_BYTE*)pSid->subs + sizeof(pSid->subs[0]) * pSid->numAuths);
    pSd->length = (NQ_UINT32)((NQ_BYTE*)pSid - pSd->data);
    return TRUE;
}

/*
 *====================================================================
 * PURPOSE: check that the given SD has exclusive rights for a given user
 *--------------------------------------------------------------------
 * PARAMS:  IN user token
 *          IN descriptor to check
 *
 * RETURNS: TRUE when exclusive
 *
 * NOTES:
 *====================================================================
 */

NQ_BOOL
cmSdIsExclusiveSecurityDescriptor(
    const CMSdAccessToken* token,
    const CMSdSecurityDescriptor* pSd
    )
{
    CMSdSecurityDescriptorHeader* pHdr; /* casted pointer to the header */
    CMSdAcl* pAcl;                      /* casted pointer to DACL */
    CMSdAce* pAce;                      /* casted pointer to ACE */
    CMSdDomainSid* pSid;                /* pointer to owner */
    NQ_COUNT i;                         /* just a counter */

    pHdr = (CMSdSecurityDescriptorHeader*) pSd->data;
    if (pHdr->dacl == 0)
        return FALSE;

    /* Owner */
/*    if (pHdr->ownerSid == 0)
        return FALSE;*/

    if (pHdr->ownerSid != 0)
    {
        pSid = (CMSdDomainSid*)(pSd->data + pHdr->ownerSid);
        if (pSid->subs[pSid->numAuths - 1] != token->rids[0])
            return FALSE;
    }

    /* DACL: */
    pAcl = (CMSdAcl*) (pSd->data + pHdr->dacl);
    if (0 == pAcl->numAces)
        return FALSE;    
    pAce = (CMSdAce*)((NQ_BYTE*)pAcl + sizeof(*pAcl));
    for (i = 0; i < pAcl->numAces; i++)
    {
        if (    pAce->type != CM_SD_ALLOW
             || (pAce->accessMask && 0x0001d0000) != (0x0001f01ff && 0x0001d0000)
             || pAce->trustee.revision != 1
           )
            return FALSE;
           if (    pAce->size == 24
                && pAce->trustee.numAuths == 2
                && pAce->trustee.subs[0] == 32
                && pAce->trustee.subs[1] == CM_SD_RIDALIASADMIN
              )
           {
           }
        else if (    pAce->size == 36
                  && 0 == syMemcmp(pAce->trustee.subs, token->domain.subs, 4 * token->domain.numAuths)
                  && pAce->trustee.numAuths == token->domain.numAuths + 1
                  && pAce->trustee.subs[pAce->trustee.numAuths - 1] == token->rids[0]
           )
        {
        }
        else
            return FALSE;
        pAce = (CMSdAce*)((NQ_BYTE*)pAce + pAce->size);
    }
    return TRUE;
}

#endif /* defined(UD_CS_INCLUDESECURITYDESCRIPTORS) || defined(UD_CC_INCLUDESECURITYDESCRIPTORS) || defined (UD_CC_INCLUDEDOMAINMEMBERSHIP) || defined(UD_CS_INCLUDEPASSTHROUGH)*/

#ifdef UD_CS_INCLUDESECURITYDESCRIPTORS
#ifdef UD_NQ_INCLUDECIFSSERVER
/*
 *====================================================================
 * PURPOSE: check whether given SID matches user's domain and rid pair
 *--------------------------------------------------------------------
 * PARAMS:  IN pointer to the SID to check
 *          IN pointer to SID of user's domain
 *          IN RID in the SID to check
 *          IN user's RID
 *
 * RETURNS: TRUE when matches
 *
 * NOTES:
 *====================================================================
 */

static NQ_BOOL
matchSid(
    const CMSdDomainSid* domain1,
    const CMSdDomainSid* domain2,
    CMSdRid rid1,
    CMSdRid rid2
    )
{
    if (syMemcmp(domain1->subs, domain2->subs, domain2->numAuths * sizeof(domain1->subs[0])) != 0)
    {
        return FALSE;
    }

    return rid1 == rid2;
}
#endif /* UD_NQ_INCLUDECIFSSERVER */

#if SY_DEBUGMODE
static void dumpSid(const NQ_CHAR *title, NQ_BYTE *buffer, NQ_INT length, NQ_INT offset)
{
    syPrintf("  %s: ", title);

    if (offset > 0)
    {
        buffer += offset;
        syPrintf("offset=%d, ", offset);
        dumpDomainSid((CMSdDomainSid *)buffer);
    }
    else
        syPrintf("none");

    syPrintf("\n");
}

static NQ_BYTE *dumpDomainSid(const CMSdDomainSid *sid)
{
    if (sid != NULL)
    {
    	NQ_INT i;

		syPrintf("S-%d-", (NQ_INT)sid->revision);

		for (i = 0; i < 6; i++)
			if (sid->idAuth[i] > 0)
				syPrintf("%d", (NQ_INT)sid->idAuth[i]);

		for (i = 0; i < (NQ_INT)sid->numAuths; i++)
			syPrintf("-%lu", sid->subs[i]);

		return (NQ_BYTE *)&sid->subs[i];
    }
    return NULL;
}

static void dumpAcl(const NQ_CHAR *title, NQ_BYTE *buffer, NQ_INT length, NQ_INT offset)
{
    syPrintf("  %s: ", title);

    if (offset > 0)
    {
        CMSdAcl *acl = (CMSdAcl *)(buffer + offset);
        CMSdAce *ace = (CMSdAce *)(acl + 1);
        NQ_UINT32 i;

        syPrintf("offset=%d, ACL revision: %d, size: %d, aces: %ld\n",
                offset, acl->revision, acl->size, acl->numAces);

        for (i = 0; i < acl->numAces; i++)
            ace = dumpAce(ace);
    }
    else
        syPrintf("none\n");
}

static CMSdAce *dumpAce(const CMSdAce *ace)
{
    NQ_BYTE *next;

    syPrintf("    ACE type: %d, flags: 0x%02X, size: %d, access: 0x%08lX, trustee: ",
           (NQ_INT)ace->type, (NQ_INT)ace->flags, ace->size, ace->accessMask);

    next = dumpDomainSid(&ace->trustee);

    syPrintf("\n");

    return (CMSdAce *)next;
}

void cmSdDumpSecurityDescriptor(NQ_TCHAR *shareName, const CMSdSecurityDescriptor *sd)
{
    CMSdSecurityDescriptorHeader *h = (CMSdSecurityDescriptorHeader *)sd->data;

    syPrintf("\n=== Security descriptor for share %s: length %d, revision %d, type %d %s\n",
           cmTDump(shareName), (int)sd->length, h->revision, h->type, h->type == 33028 ? "admin-only" : "");

    dumpSid("Owner SID", (NQ_BYTE *)h, (NQ_INT)sd->length, (NQ_INT)h->ownerSid);
    dumpSid("Group SID", (NQ_BYTE *)h, (NQ_INT)sd->length, (NQ_INT)h->groupSid);
    dumpAcl("SACL", (NQ_BYTE *)h, (NQ_INT)sd->length, (NQ_INT)h->sacl);
    dumpAcl("DACL", (NQ_BYTE *)h, (NQ_INT)sd->length, (NQ_INT)h->dacl);
}

void cmSdDumpAccessToken(CMSdAccessToken *token)
{
    NQ_COUNT i;

    syPrintf("\n=== Access token\n");

    dumpSid("Domain SID", (NQ_BYTE *)&token->domain, sizeof(CMSdDomainSid), 0);
    syPrintf("\n  %d rids:", token->numRids);
    for (i = 0; i < token->numRids; i++)
        syPrintf("\n\t0x%x (%d)", token->rids[i], token->rids[i]);
    syPrintf("\n");
}

#endif

#endif /* UD_CS_INCLUDESECURITYDESCRIPTORS */


