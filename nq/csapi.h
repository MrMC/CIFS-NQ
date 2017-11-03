/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : CIFS Server Interface
 *--------------------------------------------------------------------
 * MODULE        : CS - CIFS Server
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 19-June-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _CSAPI_H_
#define _CSAPI_H_

#include "cmapi.h"

/* API to the CIFS Server (CS) module */

NQ_STATUS
csStart(    /* start server */
    void
    );

void
csStop(     /* stop server and clean the resources */
    void
    );

#endif  /* _CSAPI_H_ */
