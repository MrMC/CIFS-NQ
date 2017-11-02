/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Socket-set management
 *--------------------------------------------------------------------
 * MODULE        : NS - NetBIOS Sockets
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 22-May-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "nsapi.h"

#include "nssocket.h"

/*
  This file implements "portable" socket sets.

  Our proprietary sets have the same functionality as BSD fd_set but use
  system-independent calls to the underlying socket system. Actually they
  are "wrappers" in BSD-like SY calls, dereferencing NSSocketHandle.
 */

/*
 *====================================================================
 * PURPOSE: Add a socket to a set
 *--------------------------------------------------------------------
 * PARAMS:  socket set
 *          pointer to NS socket descriptor
 *
 * RETURNS: NONE
 *====================================================================
 */

NQ_BOOL
nsAddSocketToSet(
    NSSocketSet* set,
    NSSocketHandle socket
    )
{
    SocketSlot *slot = (SocketSlot *)socket;

    if (!syIsValidSocket(slot->socket))
    {
        TRCERR("Illegal socket passed to nsAddSocketToSet");
        return FALSE;
    }

    syAddSocketToSet(slot->socket, set);

    return TRUE;
}

/*
 *====================================================================
 * PURPOSE: Inspect whether a socket is in a set
 *--------------------------------------------------------------------
 * PARAMS:  socket set
 *          pointer to NS socket descriptor
 *
 * RETURNS: NONE
 *====================================================================
 */

NQ_BOOL
nsSocketInSet(
    NSSocketSet* set,
    NSSocketHandle socket
    )
{
    if (socket == NULL)
        return FALSE;

#if SY_DEBUGMODE
    if (!syIsValidSocket(((SocketSlot*)socket)->socket))
    {
        TRCERR("Illegal socket passed to nsIsSocketInSet");
        return FALSE;
    }
#endif

    return syIsSocketSet(((SocketSlot*)socket)->socket, set);
}

/*
 *====================================================================
 * PURPOSE: Empty a set
 *--------------------------------------------------------------------
 * PARAMS:  socket set
 *
 * RETURNS: NONE
 *====================================================================
 */

void
nsClearSocketSet(
    NSSocketSet* set
    )
{
    syClearSocketSet(set);
}
