/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Definitions used by CIFS only
 *--------------------------------------------------------------------
 * MODULE        : CM - Common library
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 14-May-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _CMFSAPI_H_
#define _CMFSAPI_H_

#include "cmfscifs.h"       /* CIFS protocol definition */
#include "cmfsdes.h"        /* DES encryption */
#include "cmfsutil.h"       /* Other CIFS routines */

/* initilize common routines for CIFS */

NQ_STATUS
cmCifsInit(
    void
    );

/* release resources for CIFS */

void
cmCifsExit(
    void
    );

#endif  /* _CMFSAPI_H_ */
