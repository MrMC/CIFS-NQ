/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Definitions used by NetBIOS only
 *--------------------------------------------------------------------
 * MODULE        : CM - Common library
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 14-May-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _CMNBAPI_H_
#define _CMNBAPI_H_

#include "cmnbname.h"   /* NetBIOS names and thier processing */
#include "cmnbfram.h"   /* NetBIOS protocol definition */
#include "cmnberr.h"    /* NetBIOS error codes */

/* initialize the NetBIOS part of the library */

NQ_STATUS            /* NQ_SUCCESS or NQ_FAIL */
cmNetBiosInit(
    void
    );

/* close the NetBIOS part of the library */

void
cmNetBiosExit(
    void
    );

#endif  /* _CMNBAPI_H_ */
