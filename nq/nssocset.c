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
	NSSocketSet * set,
    NSSocketHandle socket
    )
{
    NQ_BOOL    result = TRUE;
    SocketSlot *slot  = (SocketSlot *)socket;
#ifdef UD_NQ_INCLUDETRACE
    NSSocketSet *sockSet;

#ifdef CM_NQ_STORAGE
    /* below cast is valied becaue we only print the pointer. */
    sockSet = (NSSocketSet *)&set->socketSet;
#else
    sockSet = set;
#endif

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "set:%p socket:%p",
            sockSet,
   			socket);

#endif

    if (!syIsValidSocket(slot->socket)  || !syIsSocketAlive(slot->socket))
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Illegal socket passed to nsAddSocketToSet");

        result = FALSE; 
        goto Exit;
    }

    syAddSocketToSet(slot->socket, set);

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result ? "TRUE" : "FALSE"); 
    return result;
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
    NQ_BOOL result = FALSE;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "set:%p socket:%p", set, socket);

    if (socket == NULL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "NULL socket");
        goto Exit;
    }

#if SY_DEBUGMODE
    if (!syIsValidSocket(((SocketSlot*)socket)->socket))
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Illegal socket passed to nsIsSocketInSet");
        goto Exit;
    }
#endif

    result = syIsSocketSet(((SocketSlot*)socket)->socket, set);

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result ? "TRUE " : "FALSE");
    return result;
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
	NSSocketSet * set
    )
{
    syClearSocketSet(set);
}

/*
 *====================================================================
 * PURPOSE: remove a socket from a set
 *--------------------------------------------------------------------
 * PARAMS:  socket set
 *
 * RETURNS: NONE
 *====================================================================
 */

void
nsClearSocketFromSet(
    NSSocketSet* set,
    NSSocketHandle socket
    )
{
    syClearSocketFromSet(((SocketSlot*)socket)->socket, set);
}
