/*********************************************************************
 *
 *           Copyright (c) 2001 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Domain controller discovery library
 *--------------------------------------------------------------------
 * DEPENDENCIES  : None
 *--------------------------------------------------------------------
 * CREATION DATE : 20-Jan-2005
 * CREATED BY    : Igor Gokhman
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _CMFINDDC_H_
#define _CMFINDDC_H_
#include "nsapi.h"


/* initialize find DC resources */

NQ_STATUS
cmFindDCInit(
    void
    );
    
/* release find DC resources */

void
cmFindDCExit(
    void
    );
    
/* query default domain (NetBIOS or DNS) for its PDC name and return server name */

NQ_STATUS                           /* NQ_SUCCESS or NQ_FAIL */
cmGetDCName(
    NQ_CHAR* pdc,                   /* PDC name upon return */
    const NQ_CHAR** domainBuffer    /* pointer for domain name (may be NULL) */
    );

/* query given domain (NetBIOS or DNS) for its PDC name and return server name */

NQ_STATUS                          /* NQ_SUCCESS or NQ_FAIL */
cmGetDCNameByDomain(
    const NQ_CHAR *domain,         /* domain name to find PDC for */
    NQ_CHAR *pdc                   /* PDC name upon return */
    );

#endif /*_CMFINDDC_H_ */
