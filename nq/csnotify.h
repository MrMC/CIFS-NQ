
/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Implementation of the NT_TRANSACTION command
 *--------------------------------------------------------------------
 * MODULE        : CS - CIFS Server
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 21-August-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _CSNOTIFY_H_
#define _CSNOTIFY_H_

#include "cmapi.h"

/* init notification module */

NQ_STATUS            /* NQ_SUCCESS or NQ_FAIL */
csNotifyInit(
    void
    );

/* exit notification module */

void
csNotifyExit(
    void
    );

/* immediatelly notify a single file */

void
csNotifyImmediatelly(
    const NQ_TCHAR* fileName,       /* full path to a file */
    NQ_UINT32 action,               /* action taken */
    NQ_UINT32 filter                /* filter */
    );

#endif  /* _CSNOTIFY_H_ */


