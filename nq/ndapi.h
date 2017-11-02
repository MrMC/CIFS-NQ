/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Name Daemon Interface
 *--------------------------------------------------------------------
 * MODULE        : NM - Name Daemon
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 26-August-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _NDAPI_H_
#define _NDAPI_H_

#include "cmapi.h"

NQ_STATUS
ndStart(    /* start ND */
    void
    );

void
ndStop(     /* stop ND and clean the reasorces */
    void
    );

void        /* tell the ND that the adapter configuration has changed */
ndNotifyConfigurationChange(
    void
    );

#endif  /* _NDAPI_H_ */
