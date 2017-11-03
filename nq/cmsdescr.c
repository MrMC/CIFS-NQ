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
#if defined(UD_NQ_INCLUDECIFSSERVER) || defined (UD_CS_INCLUDERPC)
#include "cs2disp.h"
#endif
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
    0x00,0x03,0x18,0x00,0xff,0x01,0x1f,0x00,0x01,0x02,0,0,0,0,0,0x05,0x20,0,0,0,0x21,0x02,0,0
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
    0x00,0x0b,0x14,0x00,0xff,0x01,0x1f,0x00,0x01,0x01,0,0,0,0,0,0x01,0,0,0,0,
        /* ACE: S-1-5-18 */
    0x00,0x03,0x14,0x00,0xff,0x01,0x1f,0x00,0x01,0x01,0,0,0,0,0,0x05,0x12,0,0,0,
        /* ACE: S-1-5-32-545 */
    0x00,0x03,0x18,0x00,0xff,0x01,0x1f,0x00,0x01,0x02,0,0,0,0,0,0x05,0x20,0,0,0,0x21,0x02,0,0
};

/* default SD for shares */
static const NQ_BYTE shareSecurityDescriptor[] =
{       /* SD */
    0x01, 0,        /* revision*/
    0x04,0x80,      /* type */
    0x14,0,0,0,     /* owner sid */
    0x24,0,0,0,     /* group sid */
    0,0,0,0,        /* sacl */
    0x34,0,0,0,     /* dacl */
		/* ACE: S-1-5-32-544 */
	0x01,0x02,0,0,0,0,0,0x05,0x20,0,0,0,0x20,0x02,0,0,
		/* ACE: S-1-5-32-545 */
	0x01,0x02,0,0,0,0,0,0x05,0x20,0,0,0,0x21,0x02,0,0,
        /* DACL */
    2,0,            /* revision */
    96,0,           /* size */
    4,0,0,0,        /* num ACEs */
        /* ACE: S-1-1-0 */
    0x00,0x03,0x14,0x00,0xbf,0x01,0x13,0x00,0x01,0x01,0,0,0,0,0,0x01,0,0,0,0,
/*    0x00,0x00,0x14,0x00,0xff,0x01,0x1f,0x00,0x01,0x01,0,0,0,0,0,0x01,0,0,0,0,*/
        /* ACE: S-1-5-32-544 */
    0x00,0x03,0x18,0x00,0xff,0x01,0x1f,0x00,0x01,0x02,0,0,0,0,0,0x05,0x20,0,0,0,0x20,0x02,0,0,
        /* ACE: S-1-5-32-545 */
    0x00,0x03,0x18,0x00,0xbf,0x01,0x13,0x00,0x01,0x02,0,0,0,0,0,0x05,0x20,0,0,0,0x21,0x02,0,0,
		/* ACE: S-1-5-18 */
	0x00,0x03,0x14,0x00,0xff,0x01,0x1f,0x00,0x01,0x01,0,0,0,0,0,0x05,0x12,0,0,0,
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

/* "administrative access only" SD */
static const NQ_BYTE ownerSecurityDescriptor[] =
{       /* SD */
    0x01, 0,        /* revision*/
    0x00,0x80,      /* type */
    0x14,0,0,0,     /* owner sid */
    0,0,0,0,     	/* group sid */
    0,0,0,0,        /* sacl */
    0,0,0,0,     	/* dacl */
		/* ACE: S-1-5-32-544 */
	0x01,0x02,0,0,0,0,0,0x05,0x20,0,0,0,0x20,0x02,0,0
};

/* "administrative access only" SD */
static const NQ_BYTE ownerAndDaclSecurityDescriptor[] =
{       /* SD */
    0x01, 0,        /* revision*/
    0x00,0x80,      /* type */
    0x14,0,0,0,     /* owner sid */
    0,0,0,0,     	/* group sid */
    0,0,0,0,        /* sacl */
    0x24,0,0,0,     /* dacl */
		/* ACE: S-1-5-32-544 */
	0x01,0x02,0,0,0,0,0,0x05,0x20,0,0,0,0x20,0x02,0,0,
    	/* DACL */
	2,0,            /* revision */
	32,0,           /* size */
	1,0,0,0,        /* num ACEs */
    	/* ACE: S-1-5-32-544 */
	0x00,0x03,0x18,0x00,0xff,0x01,0x1f,0x00,0x01,0x02,0,0,0,0,0,0x05,0x20,0,0,0,0x20,0x02,0,0
};

/* "group access only" SD */
static const NQ_BYTE groupSecurityDescriptor[] =
{       /* SD */
    0x01, 0,        /* revision*/
    0x00,0x80,      /* type */
    0,0,0,0,    	/* owner sid */
    0x14,0,0,0,    	/* group sid */
    0,0,0,0,        /* sacl */
    0,0,0,0,     	/* dacl */
    	/* ACE: S-1-5-32-545 */
	0x01,0x02,0,0,0,0,0,0x05,0x20,0,0,0,0x21,0x02,0,0
};

/* "group access only" SD */
static const NQ_BYTE groupAndDaclSecurityDescriptor[] =
{       /* SD */
    0x01, 0,        /* revision*/
    0x00,0x80,      /* type */
    0,0,0,0,    	/* owner sid */
    0x14,0,0,0,    	/* group sid */
    0,0,0,0,        /* sacl */
    0x24,0,0,0,     /* dacl */
    	/* ACE: S-1-5-32-545 */
	0x01,0x02,0,0,0,0,0,0x05,0x20,0,0,0,0x21,0x02,0,0,
		/* DACL */
	2,0,            /* revision */
	32,0,           /* size */
	1,0,0,0,        /* num ACEs */
		/* ACE: S-1-5-32-544 */
	0x00,0x03,0x18,0x00,0xff,0x01,0x1f,0x00,0x01,0x02,0,0,0,0,0,0x05,0x20,0,0,0,0x20,0x02,0,0
};

/* "administrative and group access only" SD */
static const NQ_BYTE ownerAndGroupSecurityDescriptor[] =
{       /* SD */
    0x01, 0,        /* revision*/
    0x00,0x80,      /* type */
    0x14,0,0,0,    	/* owner sid */
    0x24,0,0,0,    	/* group sid */
    0,0,0,0,        /* sacl */
    0,0,0,0,     	/* dacl */
		/* ACE: S-1-5-32-544 */
	0x01,0x02,0,0,0,0,0,0x05,0x20,0,0,0,0x20,0x02,0,0,
		/* ACE: S-1-5-32-545 */
	0x01,0x02,0,0,0,0,0,0x05,0x20,0,0,0,0x21,0x02,0,0
};

/* "administrative and group access only" SD */
static const NQ_BYTE ownerAndGroupAndDaclSecurityDescriptor[] =
{       /* SD */
    0x01, 0,        /* revision*/
    0x00,0x80,      /* type */
    0x14,0,0,0,    	/* owner sid */
    0x24,0,0,0,    	/* group sid */
    0,0,0,0,        /* sacl */
    0x34,0,0,0,     /* dacl */
		/* ACE: S-1-5-32-544 */
	0x01,0x02,0,0,0,0,0,0x05,0x20,0,0,0,0x20,0x02,0,0,
		/* ACE: S-1-5-32-545 */
	0x01,0x02,0,0,0,0,0,0x05,0x20,0,0,0,0x21,0x02,0,0,
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
    0x00,0x03,0x18,0x00,0xff,0x01,0x1f,0x00,0x01,0x02,0,0,0,0,0,0x05,0x20,0,0,0,0x21,0x02,0,0
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
    0x00,0x03,0x14,0x00,0xa9,0x00,0x12,0x00,0x01,0x01,0,0,0,0,0,0x01,0,0,0,0,
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
    NQ_STATUS result = NQ_SUCCESS;

    /* allocate memory */
#ifdef SY_FORCEALLOCATION
    staticData = (StaticData*)cmMemoryAllocate(sizeof(*staticData));
    if (NULL == staticData)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to allocate SD data");
        result = NQ_FAIL;
        goto Exit;
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

Exit:
     return result;
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
        cmMemoryFree(staticData);
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
    const CMSdSecurityDescriptorHeader sdHdr = {0};     /* casted pointer to SD header */
    const CMSdAcl* pAcl;                          /* ACL pointer */
    const CMSdAce* pAce;                          /* running ACE pointer */
    NQ_COUNT aceIdx;                              /* ACE index in ACL */
    const NQ_BYTE* limit;                         /* the highest address ACL can contain */
    NQ_BOOL result = FALSE;                       /* return value */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "pSd:%p", pSd);

    limit = (const NQ_BYTE*)(pSd->data + UD_CM_SECURITYDESCRIPTORLENGTH);
    if (pSd->length > sizeof(pSd->data))
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "SD too long");
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "  length: %ld", pSd->length);
        goto Exit;
    }

    syMemcpy(&sdHdr, pSd->data, sizeof(sdHdr));
    if ((0 == sdHdr.dacl) ||
    	(sdHdr.dacl > UD_CM_SECURITYDESCRIPTORLENGTH - sizeof(CMSdAcl) - sizeof(CMSdAce)))
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Security descriptor has no or invalid DACL offset");
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "DACL: %ld", sdHdr.dacl);
        goto Exit;
    }

    pAcl = (const CMSdAcl*)(pSd->data + sdHdr.dacl);

    for (aceIdx = 0,     \
           pAce = (const CMSdAce*)(pAcl + 1);
         aceIdx < pAcl->numAces;
         aceIdx++,
           pAce = (const CMSdAce*)((NQ_BYTE*)pAce + pAce->size)
         )
    {
        if ((NQ_BYTE*)pAce > limit)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Security descriptor too long, probably corrupted");
            goto Exit;
        }
        if (pAce->size > sizeof(*pAce))
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "ACE too long in descriptor, probably corrupted");
            LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, " index: %d", aceIdx);
            goto Exit;
        }
    }
    result = TRUE;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result ? "TRUE" : "FALSE");
    return result;
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
    NQ_BOOL result = TRUE;

    if (cmSdIsAdmin(token->rids[0]))
        goto Exit;            /* local administrator */

    for (i = 1; i < token->numRids; i++)
    {
        if (   token->rids[i] == CM_SD_RIDADMINISTRATOR
            || token->rids[i] == CM_SD_RIDGROUPADMINS
            || token->rids[i] == CM_SD_RIDALIASADMIN
           )
            goto Exit;        /* domain administrator or alias */
    }
    result = FALSE;

Exit:
    return result;
}

#endif /* defined(UD_CS_INCLUDESECURITYDESCRIPTORS) || defined(UD_CC_INCLUDESECURITYDESCRIPTORS) || defined (UD_CC_INCLUDEDOMAINMEMBERSHIP)*/
#ifdef UD_NQ_INCLUDECIFSSERVER

CMSdAccessFlags cmSdGetAccess(const CMBlob * sd, void * userToken)
{
	NQ_UINT32 result = 0;                         /* return value */
#ifdef UD_CS_INCLUDESECURITYDESCRIPTORS
    const CMSdSecurityDescriptorHeader* pHdr;     /* casted pointer to SD header */
    CMSdSecurityDescriptor pSd;
    const CMSdAcl* pAcl;                          /* ACL pointer */
    const CMSdAce* pAce;                          /* running ACE pointer */
    NQ_COUNT aceIdx;                              /* ACE index in ACL */
    NQ_COUNT ridIdx;                              /* RID index in token */
    const NQ_BYTE* limit;                         /* the highest address ACL can contain */
	const CMSdAccessToken * token = (const CMSdAccessToken *)userToken;
    static const CMSdDomainSid defDomain = {      /* ACE: S-1-5-32 + one unknown sub-authority */
      0x01,0x02,{0,0,0,0,0,0x05},
      {0x20,0,0,0,0,0}
    };
    static const CMSdDomainSid everyone = {       /* ACE: S-1-1-0 */
      0x01,0x01,{0,0,0,0,0,0x01},
      {0,0,0,0,0,0}
    };

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "sd:%p sd->len:%d userToken:%p", sd, sd->len, userToken);

#if SY_DEBUGMODE
	cmSdDumpAccessToken(token);
#endif /* SY_DEBUGMODE */

    /* validate SD */
	syMemcpy(pSd.data, sd->data, sd->len);
	pSd.length = sd->len;
	if (!cmSdIsValid((const CMSdSecurityDescriptor *)&pSd))
	{
		LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Security descriptor is Invalid");
		result = 0xFFFFFFFF;
		goto Exit;
	}

    limit = sd->data + UD_CM_SECURITYDESCRIPTORLENGTH;
    pHdr = (CMSdSecurityDescriptorHeader*)sd->data;
/*	if (0 == pHdr->dacl)
	{
		LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "SD with no DACL");
		result = 0xFFFFFFFF;
		goto Exit;
	}
	if (pHdr->dacl > UD_CM_SECURITYDESCRIPTORLENGTH - sizeof(CMSdAcl) - sizeof(CMSdAce))
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "Security descriptor has no or invalid DACL offset: %ld", pHdr->dacl);
		result = 0xFFFFFFFF;
		goto Exit;
    }*/
    pAcl = (const CMSdAcl*)(sd->data + pHdr->dacl);

    for (aceIdx = 0,
           pAce = (const CMSdAce*)(pAcl + 1);
         aceIdx < pAcl->numAces;
         aceIdx++,
           pAce = (const CMSdAce*)((NQ_BYTE*)pAce + pAce->size)
         )
    {
    	if ((NQ_BYTE*)pAce > limit)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Security descriptor too long, probably corrupted");
            goto Exit;
        }
        if (syMemcmp(
                &pAce->trustee,
                &everyone,
                (NQ_UINT)sizeof(everyone) - (NQ_UINT)(6 - everyone.numAuths) * (NQ_UINT)sizeof(CMSdRid)
            ) == 0)
        {
        	goto Setaccess;
        }
		if (NULL == token)
		{
			continue;
		}
		for (ridIdx = 0; ridIdx < token->numRids; ridIdx++)
		{
			if (syMemcmp(
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
				)
			{
				goto Setaccess;
			}
			if (matchSid(
					&pAce->trustee,
					&token->domain,
					pAce->trustee.subs[pAce->trustee.numAuths - 1],
					token->rids[ridIdx]
					)
			   )
			{
				goto Setaccess;
			}
		}
		continue;
Setaccess:
        if (pAce->type == CM_SD_DENY)
        {
        	result &= ~pAce->accessMask;
        }
        else
        {
        	result |= pAce->accessMask;
        }
    }

    if (0 != pHdr->ownerSid)
    {
    	CMSdDomainSid * pSid;

        pSid = (CMSdDomainSid*)((NQ_BYTE*)sd->data + pHdr->ownerSid);
        if (NULL != token && (pSid->subs[pSid->numAuths - 1] == token->rids[0]))
        	result |= SMB_DESIREDACCESS_WRITEDAC | SMB_DESIREDACCESS_READCONTROL;
    }
Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:0x%x", result);
#endif /* UD_CS_INCLUDESECURITYDESCRIPTORS */
    return result;
}

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
    CMSdSecurityDescriptor pSd;
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

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "token:%p sd:%p access:0x%x", token, sd, access);
    
#if SY_DEBUGMODE
	cmSdDumpAccessToken(token);
#endif /* SY_DEBUGMODE */

    /* allow any DACL access for local administrators */

    if ((access & ANYDACLACCESS) > 0)
    {
        for (ridIdx = 0; ridIdx < token->numRids; ridIdx++
             )
        {
            if (CM_SD_RIDALIASADMIN == token->rids[ridIdx])
            {
                result = TRUE;
                goto Exit;
            }
        }
    }

    /* validate SD */
    limit = sd + UD_CM_SECURITYDESCRIPTORLENGTH;
    pHdr = (CMSdSecurityDescriptorHeader*)sd;
    if (NULL == pHdr || 0 == pHdr->dacl ||
        pHdr->dacl > UD_CM_SECURITYDESCRIPTORLENGTH - sizeof(CMSdAcl) - sizeof(CMSdAce))
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Security descriptor has no or invalid DACL offset");
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "DACL: %ld", NULL == pHdr ? 0 : pHdr->dacl);
        goto Exit;
    }
    pAcl = (const CMSdAcl*)(sd + pHdr->dacl);

    pSd.length = pHdr->dacl + pAcl->size;
	syMemcpy(pSd.data, sd, pSd.length);

	if (!cmSdIsValid((const CMSdSecurityDescriptor *)&pSd))
	{
		LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Security descriptor is Invalid");
		goto Exit;
	}

    for (aceIdx = 0,
           pAce = (const CMSdAce*)(pAcl + 1);
         aceIdx < pAcl->numAces;
         aceIdx++,
           pAce = (const CMSdAce*)((NQ_BYTE*)pAce + pAce->size)
         )
    {
        if ((NQ_BYTE*)pAce > limit)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Security descriptor too long, probably corrupted");
            goto Exit;
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
                    goto Exit;
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
                        continue;
                    result = TRUE;
                }
            }
        }
    }

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result ? "TRUE" : "FALSE");
    return result;
#else  /* UD_CS_INCLUDESECURITYDESCRIPTORS */
    NQ_BOOL result = FALSE;    /* return value */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "token:%p sd:%p access:0x%x", token, sd, access);

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
    		result = FALSE;
    	}
    	else
    		result = TRUE;
    }
    else
    	result = TRUE;
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result ? "TRUE" : "FALSE");
    return result;
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

NQ_BOOL
cmSdGetOwnerAndDaclSecurityDescriptor(
    CMSdSecurityDescriptor* pSd
    )
{
    CMRpcPacketDescriptor descr;    /* packet descriptor for parsing Littel Endian SD */

    cmRpcSetDescriptor(&descr, (NQ_BYTE*)ownerAndDaclSecurityDescriptor, FALSE);
    cmSdParseSecurityDescriptor(&descr, pSd);
    return TRUE;
}

NQ_BOOL
cmSdGetGroupAndDaclSecurityDescriptor(
    CMSdSecurityDescriptor* pSd
    )
{
    CMRpcPacketDescriptor descr;    /* packet descriptor for parsing Littel Endian SD */

    cmRpcSetDescriptor(&descr, (NQ_BYTE*)groupAndDaclSecurityDescriptor, FALSE);
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
 * PURPOSE: get "administrative access only" SD
 *--------------------------------------------------------------------
 * PARAMS:  OUT buffer for resulting descriptor
 *
 * RETURNS: TRUE on success
 *
 * NOTES:   This descriptor has "WorldSid" for owner
 *====================================================================
 */

NQ_BOOL
cmSdGetOwnerSecurityDescriptor(
    CMSdSecurityDescriptor* pSd
    )
{
    CMRpcPacketDescriptor descr;    /* packet descriptor for parsing Little Endian SD */

    cmRpcSetDescriptor(&descr, (NQ_BYTE*)ownerSecurityDescriptor, FALSE);
    cmSdParseSecurityDescriptor(&descr, pSd);
    return TRUE;
}

/*
 *====================================================================
 * PURPOSE: get "group access only" SD
 *--------------------------------------------------------------------
 * PARAMS:  OUT buffer for resulting descriptor
 *
 * RETURNS: TRUE on success
 *
 * NOTES:   This descriptor has Sid for group
 *====================================================================
 */

NQ_BOOL
cmSdGetGroupSecurityDescriptor(
    CMSdSecurityDescriptor* pSd
    )
{
    CMRpcPacketDescriptor descr;    /* packet descriptor for parsing Little Endian SD */

    cmRpcSetDescriptor(&descr, (NQ_BYTE*)groupSecurityDescriptor, FALSE);
    cmSdParseSecurityDescriptor(&descr, pSd);
    return TRUE;
}

/*
 *====================================================================
 * PURPOSE: get "administrative and group access only" SD
 *--------------------------------------------------------------------
 * PARAMS:  OUT buffer for resulting descriptor
 *
 * RETURNS: TRUE on success
 *
 * NOTES:   This descriptor has "WorldSid" for owner and Sid for group
 *====================================================================
 */

NQ_BOOL
cmSdGetOwnerAndGroupSecurityDescriptor(
    CMSdSecurityDescriptor* pSd
    )
{
    CMRpcPacketDescriptor descr;    /* packet descriptor for parsing Little Endian SD */

    cmRpcSetDescriptor(&descr, (NQ_BYTE*)ownerAndGroupSecurityDescriptor, FALSE);
    cmSdParseSecurityDescriptor(&descr, pSd);
    return TRUE;
}

NQ_BOOL
cmSdGetOwnerAndGroupAndDaclSecurityDescriptor(
    CMSdSecurityDescriptor* pSd
    )
{
    CMRpcPacketDescriptor descr;    /* packet descriptor for parsing Little Endian SD */

    cmRpcSetDescriptor(&descr, (NQ_BYTE*)ownerAndGroupAndDaclSecurityDescriptor, FALSE);
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
	pHdr->sacl = 0;
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
    const CMSdDomainSid* pResult;

    if (!staticData->domainSidSet)
    {
        pResult = cmSdGetComputerSid();
        goto Exit;
    }
    pResult = &staticData->domainSid;

Exit:
    return pResult;
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
 * RETURNS: TRUE when we support this alias
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
    NQ_BOOL result = TRUE;

    compSid = cmSdGetComputerSid();
    if (   sid->numAuths != compSid->numAuths + 1
        || 0 != syMemcmp(sid->subs, compSid->subs, compSid->numAuths * sizeof(compSid->subs[0]))
       )
    {
        result = FALSE;
        goto Exit;
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
    }

Exit:
    return result;
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
    const CMSdSecurityDescriptor* pSd,
	NQ_UINT32 flags
    )
{
#define NODATA 4

    CMSdSecurityDescriptorHeader* pHdr;     /* casted pointer to SD header */
    CMSdDomainSid* pSid;                    /* casted pointer to SIDs */
    CMSdAcl* pAcl;                          /* casted pointer to ACL */
    NQ_UINT32 * length;
    NQ_BYTE* sdStart, *max;
    NQ_UINT32 offset = 20;
    NQ_UINT32 mask = 1, i = 4;
    NQ_BYTE padding[16];

    syMemset(padding, 0, 16);

    sdStart = out->current;
    length = (NQ_UINT32 *)&pSd->length;
    pHdr = (CMSdSecurityDescriptorHeader*)pSd->data;
    cmRpcPackUint16(out, pHdr->revision);
    cmRpcPackUint16(out, pHdr->type);
    cmRpcPackBytes(out, padding, 16);
    out->current -= 16;
    max = out->current;

    while (i--)
    {
    	switch (flags & mask)
    	{
    	case CM_SD_OWNER:
    		if (0 != pHdr->ownerSid)
    		{
				out->current = sdStart + sizeof(NQ_UINT32);
				cmRpcPackUint32(out, offset);
				pSid = (CMSdDomainSid*)((NQ_BYTE*)pSd->data + pHdr->ownerSid);
				out->current = sdStart + offset;
				cmSdPackSid(out, pSid);
				offset += (NQ_UINT32)(8 + (sizeof(NQ_UINT32) * pSid->numAuths));
    		}
    		max = out->current;
    		break;
    	case CM_SD_GROUP:
    		if (0 != pHdr->groupSid)
    		{
				out->current = sdStart + 2 * sizeof(NQ_UINT32);
				cmRpcPackUint32(out, offset);
		        pSid = (CMSdDomainSid*)((NQ_BYTE*)pSd->data + pHdr->groupSid);
		        out->current = sdStart + offset;
		        cmSdPackSid(out, pSid);
		        offset += (NQ_UINT32)(8 + (sizeof(NQ_UINT32) * pSid->numAuths));
    		}
    	    if (out->current > max)
    	        max = out->current;
    		break;
    	case CM_SD_SACL:
    		if (0 != pHdr->sacl)
    		{
    			NQ_BYTE * curr;

				out->current = sdStart + 3 * sizeof(NQ_UINT32);
				cmRpcPackUint32(out, offset);
				out->current = sdStart + offset;
		        pAcl = (CMSdAcl*)((NQ_BYTE*)pSd->data + pHdr->sacl);
		        curr = out->current;
		        cmSdPackAcl(out, pAcl);
				offset += (NQ_UINT32)(out->current - curr);
    		}
    	    if (out->current > max)
    	        max = out->current;
    		break;
    	case CM_SD_DACL:
    		if (0 != pHdr->dacl)
    		{
    			NQ_BYTE * curr;

				out->current = sdStart + 4 * sizeof(NQ_UINT32);
				cmRpcPackUint32(out, offset);
				out->current = sdStart + offset;
		        pAcl = (CMSdAcl*)((NQ_BYTE*)pSd->data + pHdr->dacl);
		        curr = out->current;
		        cmSdPackAcl(out, pAcl);
		        offset += (NQ_UINT32)(out->current - curr);
    		}
    		break;
    	}
    	mask <<= 1;
    }

    /* set current to the most distant point */
    if (out->current < max)
        out->current = max;


    *length = (NQ_UINT32)(out->current - sdStart);

    if (NODATA == *length) /* no data had been written */
    {
    	out->current = sdStart;
    	if ((flags & 0xf) == 0)
    	{
			cmRpcPackByte(out, 1);				/* revision */
			cmRpcPackBytes(out, padding, 1);	/* alignment */
		    cmRpcPackUint16(out, CM_SD_SELF_RELATIVE);
		    cmRpcPackBytes(out, padding, 16);
		    *length = (NQ_UINT32)(out->current - sdStart);
    	}
    	else
    	{
    		cmRpcPackBytes(out, padding, 4);	/* alignment */
    	}
    }
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
        LOGERR(CM_TRC_LEVEL_ERROR, "ACL buffer overflow");
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
            LOGERR(CM_TRC_LEVEL_ERROR, "Two many ACEs");
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
    NQ_WCHAR* nameBuffer,
    NQ_WCHAR* fullNameBuffer
    )
{
    NQ_UINT i;        /* just a counter */
    NQ_BOOL result = TRUE;

    for (i = 0; i < sizeof(localAliases)/sizeof(localAliases[0]); i++)
    {
        if (rid == localAliases[i].rid)
        {
            cmAnsiToUnicode(nameBuffer, localAliases[i].name);
            cmAnsiToUnicode(fullNameBuffer, localAliases[i].fullName);
            goto Exit;
        }
    }
    result = udGetUserNameByRid(rid, nameBuffer, fullNameBuffer);

Exit:
    return result;
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
    const NQ_WCHAR* name,
    CMSdRid* rid
    )
{
    NQ_UINT i;                        /* just a counter */
    NQ_BOOL result = TRUE;

    cmUnicodeToAnsiN(staticData->tempName, name, sizeof(staticData->tempName));
    for (i = 0; i < sizeof(localAliases)/sizeof(localAliases[0]); i++)
    {
        if (0 == syStrcmp(staticData->tempName, localAliases[i].name))
        {
            *rid = localAliases[i].rid;
            goto Exit;
        }
    }
    result = udGetUserRidByName(name, rid);

Exit:
    return result;
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
    NQ_UINT i;         /* just a counter */
    NQ_UINT32 result;

    for (i = 0; i < sizeof(localAliases)/sizeof(localAliases[0]); i++)
    {
        if (rid == localAliases[i].rid)
        {
            result = localAliases[i].type;
            goto Exit;
        }
    }
    result = CM_SD_RIDTYPE_USER;

Exit:
    return result;
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
    pHdr->sacl = 0;
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

/* create new ACl from a parent ACL */
void cmSdInherit(const CMBlob * oldSd, CMBlob * newSd, void * userToken)
{
    CMSdSecurityDescriptorHeader* pOldHdr; /* casted pointer to the header */
    CMSdSecurityDescriptorHeader* pNewHdr; /* casted pointer to the header */
    CMSdAcl* pOldAcl;                      /* casted pointer to DACL */
    CMSdAce* pOldAce;                      /* casted pointer to ACE */
    CMSdAcl* pNewAcl;                      /* casted pointer to DACL */
    CMSdAce* pNewAce;                      /* casted pointer to ACE */
    CMSdDomainSid* pSid;        	       /* casted pointer to SID */
    const CMSdDomainSid* pOldSid;          /* casted pointer to SID */
    NQ_INT i;							   /* just a counter */

    const CMSdAccessToken * token = (const CMSdAccessToken *)userToken;

    pOldHdr = (CMSdSecurityDescriptorHeader*) oldSd->data;
    pNewHdr = (CMSdSecurityDescriptorHeader*) newSd->data;
    *pNewHdr = *pOldHdr;
    pOldAcl = (CMSdAcl*) (oldSd->data + pOldHdr->dacl);
    pNewAcl = (CMSdAcl*) (newSd->data + pNewHdr->dacl);
    pNewAcl->revision = 2;
    pNewAcl->numAces = 0;
    pNewAcl->size = pOldAcl->size;
    pOldAce = (CMSdAce*)((NQ_BYTE*)pOldAcl + sizeof(*pOldAcl));
    pNewAce = (CMSdAce*)((NQ_BYTE*)pNewAcl + sizeof(*pNewAcl));
    /* DACL: */
    for (i = 0; (NQ_UINT)i < pOldAcl->numAces; i++)
    {
    	if (pOldAce->flags & (CM_SD_CONTAINERINHERIT | CM_SD_OBJECTINHERIT))
    	{
    		syMemcpy(pNewAce, pOldAce, pOldAce->size);
        	pNewAcl->numAces++;
        	if (pOldAce->flags & CM_SD_NONPROPAGATEINHERIT)
        	{
        		pNewAce->flags &= (NQ_BYTE)(~(CM_SD_CONTAINERINHERIT | CM_SD_OBJECTINHERIT));
        	}
        	pNewAce = (CMSdAce *)((NQ_BYTE*)pNewAce + pNewAce->size);
    	}
    	pOldAce = (CMSdAce *)((NQ_BYTE*)pOldAce + pOldAce->size);
    }
	pSid = (CMSdDomainSid*)pNewAce;
    /* OWNER */
    if (pOldHdr->ownerSid != 0)
    {
		pNewHdr->ownerSid = (NQ_UINT32)((NQ_BYTE*)pSid - newSd->data);
		if (NULL != token)
		{
			syMemcpy(pSid, &token->domain, sizeof(token->domain));
			pSid->subs[pSid->numAuths] = token->rids[0];
			pSid->numAuths++;
		}
		else
		{
			pOldSid = (const CMSdDomainSid*)(oldSd->data + pOldHdr->ownerSid);
			syMemcpy(pSid, pOldSid, (NQ_BYTE *)(&pOldSid->subs[0] + pOldSid->numAuths) - (NQ_BYTE *)pOldSid);
		}
		pSid = (CMSdDomainSid*)((NQ_BYTE*)pSid->subs + sizeof(pSid->subs[0]) * pSid->numAuths);
    }
    else
    {
		if (NULL != token)
		{
			pNewHdr->ownerSid = (NQ_UINT32)((NQ_BYTE*)pSid - newSd->data);
			syMemcpy(pSid, &token->domain, sizeof(token->domain));
			pSid->subs[pSid->numAuths] = token->rids[0];
			pSid->numAuths++;
			pSid = (CMSdDomainSid*)((NQ_BYTE*)pSid->subs + sizeof(pSid->subs[0]) * pSid->numAuths);
		}
    }

    /* GROUP */
    if (pOldHdr->ownerSid != 0)
    {
    	pNewHdr->groupSid = (NQ_UINT32)((NQ_BYTE*)pSid - newSd->data);
    	if (NULL != token)
		{
			syMemcpy(pSid, &token->domain, sizeof(token->domain));
			pSid->subs[pSid->numAuths] = CM_SD_RIDGROUPUSERS;
			pSid->numAuths++;
		}
		else
		{
			pOldSid = (const CMSdDomainSid*)(oldSd->data + pOldHdr->groupSid);
			syMemcpy(pSid, pOldSid, (NQ_BYTE *)(&pOldSid->subs[0] + pOldSid->numAuths) - (NQ_BYTE *)pOldSid);
		}
	    pSid = (CMSdDomainSid*)((NQ_BYTE*)pSid->subs + sizeof(pSid->subs[0]) * pSid->numAuths);
    }
    else
    {
		if (NULL != token)
		{
			pNewHdr->groupSid = (NQ_UINT32)((NQ_BYTE*)pSid - newSd->data);
			syMemcpy(pSid, &token->domain, sizeof(token->domain));
			pSid->subs[pSid->numAuths] = CM_SD_RIDGROUPUSERS;
			pSid->numAuths++;
			pSid = (CMSdDomainSid*)((NQ_BYTE*)pSid->subs + sizeof(pSid->subs[0]) * pSid->numAuths);
		}
    }

    newSd->len = (NQ_UINT32)((NQ_BYTE*)pSid - newSd->data);
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
    NQ_BOOL result = FALSE;             /* return value */

    pHdr = (CMSdSecurityDescriptorHeader*) pSd->data;
    if (pHdr->dacl == 0)
        goto Exit;

    /* Owner */
/*
    if (pHdr->ownerSid == 0)
        goto Exit;
*/

    if (pHdr->ownerSid != 0)
    {
        pSid = (CMSdDomainSid*)(pSd->data + pHdr->ownerSid);
        if (pSid->subs[pSid->numAuths - 1] != token->rids[0])
            goto Exit;
    }

    /* DACL: */
    pAcl = (CMSdAcl*) (pSd->data + pHdr->dacl);
    if (0 == pAcl->numAces)
        goto Exit;

    pAce = (CMSdAce*)((NQ_BYTE*)pAcl + sizeof(*pAcl));
    for (i = 0; i < pAcl->numAces; i++)
    {
        if (    pAce->type != CM_SD_ALLOW
             || (pAce->accessMask & 0x0001d0000) != (0x0001f01ff & 0x0001d0000)
             || pAce->trustee.revision != 1
           )
           goto Exit;
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
            goto Exit;
        pAce = (CMSdAce*)((NQ_BYTE*)pAce + pAce->size);
    }

    result = TRUE;

Exit:
    return result;
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
    NQ_BOOL result = FALSE;

    if (syMemcmp(domain1->subs, domain2->subs, domain2->numAuths * sizeof(domain1->subs[0])) != 0)
    {
        goto Exit;
    }

    result = (rid1 == rid2);

Exit:
    return result;
}
#endif /* UD_NQ_INCLUDECIFSSERVER */

#if SY_DEBUGMODE
static void dumpSid(const NQ_CHAR *title, NQ_BYTE *buffer, NQ_INT length, NQ_INT offset)
{
#if 0
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
#else
	LOGMSG(CM_TRC_LEVEL_MESS_SOME, "%s: ", title);

	if (offset > 0)
	{
		buffer += offset;
		LOGMSG(CM_TRC_LEVEL_MESS_SOME, "offset=%d, ", offset);
		dumpDomainSid((CMSdDomainSid *)buffer);
	}
	else
	{
		LOGMSG(CM_TRC_LEVEL_MESS_SOME, "none");
	}
#endif
}

static NQ_BYTE *dumpDomainSid(const CMSdDomainSid *sid)
{
#if 0
	NQ_BYTE* pResult = NULL;

	if (sid != NULL)
	{
		NQ_INT i;

		syPrintf("S-%d-", (NQ_INT)sid->revision);

		for (i = 0; i < 6; i++)
			if (sid->idAuth[i] > 0)
				syPrintf("%d", (NQ_INT)sid->idAuth[i]);

		for (i = 0; i < (NQ_INT)sid->numAuths; i++)
			syPrintf("-%lu", sid->subs[i]);

		pResult = (NQ_BYTE *)&sid->subs[i];
	}
	return pResult;
#else
	NQ_CHAR buff[256];
	NQ_BYTE* pResult = NULL;

	if (sid != NULL)
	{
		NQ_INT i;

		sySnprintf(buff, sizeof(buff) - 1, "S-%d-", (NQ_INT)sid->revision);

		for (i = 0; i < 6; i++)
			if (sid->idAuth[i] > 0)
				sySnprintf(buff, sizeof(buff) - 1, "%d", (NQ_INT)sid->idAuth[i]);

		for (i = 0; i < (NQ_INT)sid->numAuths; i++)
			sySnprintf(buff, sizeof(buff) - 1, "-%u", (NQ_UINT)sid->subs[i]);

		pResult = (NQ_BYTE *)&sid->subs[i];
		sySnprintf(buff, sizeof(buff) - 1, "\n");
		LOGMSG(CM_TRC_LEVEL_MESS_SOME, "%s", buff);
	}
	return pResult;
#endif
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

void cmSdDumpSecurityDescriptor(NQ_WCHAR *shareName, const CMSdSecurityDescriptor *sd)
{
    CMSdSecurityDescriptorHeader *h = (CMSdSecurityDescriptorHeader *)sd->data;

    syPrintf("\n=== Security descriptor for share %s: length %d, revision %d, type %d %s\n",
           cmWDump(shareName), (int)sd->length, h->revision, h->type, h->type == 33028 ? "admin-only" : "");

    dumpSid("Owner SID", (NQ_BYTE *)h, (NQ_INT)sd->length, (NQ_INT)h->ownerSid);
    dumpSid("Group SID", (NQ_BYTE *)h, (NQ_INT)sd->length, (NQ_INT)h->groupSid);
    dumpAcl("SACL", (NQ_BYTE *)h, (NQ_INT)sd->length, (NQ_INT)h->sacl);
    dumpAcl("DACL", (NQ_BYTE *)h, (NQ_INT)sd->length, (NQ_INT)h->dacl);
}

static NQ_CHAR *ridToStr(CMSdRid rid)
{
	switch (rid)
	{
	case CM_SD_RIDADMINISTRATOR:
		return "CM_SD_RIDADMINISTRATOR";
	case CM_SD_RIDGUEST:
		return "CM_SD_RIDGUEST";
	case CM_SD_RIDGROUPADMINS:
		return "CM_SD_RIDGROUPADMINS";
	case CM_SD_RIDGROUPUSERS:
		return "CM_SD_RIDGROUPUSERS";
	case CM_SD_RIDGROUPGUESTS:
		return "CM_SD_RIDGROUPGUESTS";
	case CM_SD_RIDALIASADMIN:
		return "CM_SD_RIDALIASADMIN";
	case CM_SD_RIDALIASUSER:
		return "CM_SD_RIDALIASUSER";
	case CM_SD_RIDALIASGUEST:
		return "CM_SD_RIDALIASGUEST";
	case CM_SD_RIDALIASACCOUNTOP:
		return "CM_SD_RIDALIASACCOUNTOP";
	default:
		return "unknown";
	}
}

void cmSdDumpAccessToken(const CMSdAccessToken *token)
{
#if 0
	NQ_COUNT i;

	syPrintf("\n=== Access token\n");

	dumpSid("Domain SID", (NQ_BYTE *)&token->domain, sizeof(CMSdDomainSid), 0);
	syPrintf("\n  %d rids:", token->numRids);
	for (i = 0; i < token->numRids; i++)
		syPrintf("\n\t0x%x (%d)", token->rids[i], token->rids[i]);
	syPrintf("\n");
#else	
	NQ_COUNT i;

	LOGMSG(CM_TRC_LEVEL_MESS_SOME, "Access token%s:", token->isAnon ? "(anonymous)" : "");

	dumpSid("Domain SID", (NQ_BYTE *)&token->domain, sizeof(CMSdDomainSid), 0);
	LOGMSG(CM_TRC_LEVEL_MESS_SOME, "%d rids:", token->numRids);
	for (i = 0; i < token->numRids; i++)
	{
		LOGMSG(CM_TRC_LEVEL_MESS_SOME, "0x%x (%d %s)", token->rids[i], token->rids[i], ridToStr(token->rids[i]));
	}
#endif
}

#endif

#endif /* UD_CS_INCLUDESECURITYDESCRIPTORS */


