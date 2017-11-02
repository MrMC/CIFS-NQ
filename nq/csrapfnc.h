
/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : RPC functions
 *--------------------------------------------------------------------
 * MODULE        : CS - CIFS server
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 13-July-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _CSRAPFNC_H_
#define _CSRAPFNC_H_

#include "csapi.h"
#include "cstransa.h"

NQ_UINT32              /* returns error code o 0 on success */
csRapApiEntry(
    CSTransactionDescriptor* descriptor /* transaction descriptor */
    );

#endif  /* _CSRAPFNC_H_ */

