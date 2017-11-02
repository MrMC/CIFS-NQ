/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : API definition for system-dependent library
 *--------------------------------------------------------------------
 * MODULE        : SY - System-dependent
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 22-May-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _SYAPI_H_
#define _SYAPI_H_

#include "udparams.h"   /* user defined compilation parameters */
#include "sycompil.h"   /* compiler-dependent definitions   */
#include "udapi.h"      /* project dependent definitions */
#include "syinclud.h"   /* system includes here */
#include "sypltfrm.h"   /* platform-dependent definitions   */
#include "sycommon.h"   /* independent definitions */
#include "syopsyst.h"   /* OS-dependent definitions */
#ifdef UD_CS_INCLUDERPC_SPOOLSS
#include "syprintr.h"   /* printing API */
#endif
#include "sytrace.h"    /* tracing */
#if defined(UD_CC_INCLUDEEXTENDEDSECURITY) && defined(UD_CC_INCLUDEEXTENDEDSECURITY_KERBEROS)
#include "sysasl.h"     /* GSASL interface */
#endif
#ifdef UD_CC_INCLUDELDAP
#include "syldap.h"     /* ldap */
#endif
/* initialize the module */

NQ_BOOL
syInit(
    void
    );

/* stop the module */

void
syStop(
    void
    );

#endif  /* _SYAPI_H_ */

