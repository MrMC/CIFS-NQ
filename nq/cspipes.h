
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

#ifndef _CSPIPES_H_
#define _CSPIPES_H_

#include "csapi.h"
#include "cstransa.h"

/*
    pipe identification
    -------------------
 */

typedef NQ_INT CSRpcPipe;   /* index in the table of pipes */

#define CS_INVALIDPIPE   -1 /* illegal pipe */

/*#define csRpcValidPipe(_pipe) (_pipe != RP_INVALIDPIPE)*/

NQ_UINT32              /* returns error code o 0 on success */
csNamedPipeEntry(
    CSTransactionDescriptor* descriptor /* transaction descriptor */
    );

/* calculate subcommand data pointer and size */

NQ_STATUS                              /* NQ_SUCCESS or error code */
csNamedPipePrepareLateResponse(
    CSLateResponseContext* context     /* saved context */
    );

/* send a response using saved context */

NQ_BOOL                                /* TRUE on success */
csNamedPipeSendLateResponse(
    CSLateResponseContext* context,    /* saved context */
    NQ_UINT32 status,                  /* status to report, zero for success */
    NQ_COUNT dataLength                /* actual command data length */
    );

#endif  /* _CSPIPES_H_ */

