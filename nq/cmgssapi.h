/*********************************************************************
 *
 *           Copyright (c) 2008 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : GSSAPI
 *--------------------------------------------------------------------
 * MODULE        : CM
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 11-Dec-2008
 ********************************************************************/

#ifndef _CMGSSAPI_H
#define _CMGSSAPI_H

#include "cmasn1.h"

#if defined(UD_CC_INCLUDEEXTENDEDSECURITY) || defined(UD_CS_INCLUDEEXTENDEDSECURITY)

extern const CMAsn1Oid cmGssApiOidSpnego;
extern const CMAsn1Oid cmGssApiOidNtlmSsp;
extern const CMAsn1Oid cmGssApiOidKerberos;
extern const CMAsn1Oid cmGssApiOidKerberosUserToUser;
extern const CMAsn1Oid cmGssApiOidMsKerberos;

/* check whether blob has required mechanism oid */
NQ_BOOL
cmGssDoesBlobHaveMechType(
    NQ_BYTE* blob,
    NQ_COUNT blobLen,
    const CMAsn1Oid *oid
    );

#endif /* defined(UD_CC_INCLUDEEXTENDEDSECURITY) || defined(UD_CS_INCLUDEEXTENDEDSECURITY) */

#endif /* _CMGSSAPI_H */

