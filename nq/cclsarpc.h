/*********************************************************************
 *
 *           Copyright (c) 2001 by Visuality Systems, Ltd.
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
 * CREATION DATE : 3-Jul-2001
 * CREATED BY    : Igor Lerner
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _CCLSARPC_H_
#define _CCLSARPC_H_

#include "cmsdescr.h"
#include "ccdcerpc.h"

#if defined(UD_CC_INCLUDESECURITYDESCRIPTORS) || defined(UD_CC_INCLUDEDOMAINMEMBERSHIP) || defined(UD_CS_INCLUDEPASSTHROUGH)

/*
 * Types and definitions
 * ---------------------
 */

typedef NQ_BOOL     /* TRUE when next SID was placed, FALSE otherwise */
(*CCLsaLookupSidsRequestCallback)(
    CMSdDomainSid* out,         /* buffer for next sid */
    NQ_BYTE* params             /* pointer to parameters */
    );

typedef NQ_BOOL     /* TRUE always */
(*CCLsaLookupSidsDomainsCallback)(
    const NQ_WCHAR* name,       /* trusted domain name */
    const CMSdDomainSid* sid,   /* trusted domain SID */
    NQ_UINT32 count,            /* total number of domains */
    NQ_UINT32 maxCount,         /* available number of domains */
    NQ_BYTE* params             /* pointer to parameters */
    );

typedef NQ_BOOL     /* TRUE always */
(*CCLsaLookupSidsNamesCallback)(
    const NQ_WCHAR* name,       /* resolved name (may be NULL) */
    NQ_UINT16 type,             /* SID type */
    NQ_UINT32 index,            /* SID index */
    NQ_UINT32 reserved,         /* not used */
    NQ_UINT32 count,            /* total number of names */
    NQ_BYTE* params             /* pointer to parameters */
    );

/* get pipe information */

const CCDcerpcPipeDescriptor*      /* pointer to pipe descriptor */
ccLsaGetPipe(
    void
    );

/* get user token by acount name */

NQ_STATUS                               /* returns NQ_SUCCESS if DC resolves user's token */
ccLsaGetUserToken(
    NQ_HANDLE pipeHandle,               /* pipe file handle */
    const NQ_WCHAR * name,              /* user name */
    const NQ_WCHAR * domain,             /* domain name */
    CMSdAccessToken * token             /* buffer for token */
    );

/* get name by its SID */

NQ_STATUS                                       /* returns NQ_SUCCESS always */
ccLsaLookupSids(
    NQ_HANDLE pipeHandle,                       /* pipe file handle */
    CCLsaLookupSidsRequestCallback request,     /* request callback */
    CCLsaLookupSidsDomainsCallback domainPacker,/* request callback */
    CCLsaLookupSidsNamesCallback namesPacker,   /* request callback */
    NQ_UINT32 numSids,                          /* number of SIDs to map */
    NQ_BYTE* params                             /* abstract parameters for callbacks */
    );

typedef struct {
    NQ_WCHAR name[CM_BUFFERLENGTH(NQ_WCHAR, DOMAIN_LENGTH)];  /* NetBIOS domain name */
    CMSdDomainSid sid;
}
CCLsaPolicyInfoDomain;

NQ_UINT32
ccLsaPolicyQueryInfoDomain(
    const NQ_WCHAR *server,
    CCLsaPolicyInfoDomain *info
    );

NQ_UINT32
ccLsaDsRoleGetPrimaryDomainInformation(
	const NQ_WCHAR *server,
	CCLsaPolicyInfoDomain *info
	);

#endif /* defined(UD_CC_INCLUDESECURITYDESCRIPTORS) || defined(UD_CC_INCLUDEDOMAINMEMBERSHIP) || defined(UD_CS_INCLUDEPASSTHROUGH) */

#endif /* _CCLSARPC_H_ */
