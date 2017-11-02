/*********************************************************************
 *
 *           Copyright (c) 2008 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : SMB2 Notify processing
 *--------------------------------------------------------------------
 * MODULE        : CS2
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 04-Jan-2009
 ********************************************************************/

#ifndef _CS2NOTIFY_H_
#define _CS2NOTIFY_H_

#include "cmsmb2.h"

#if defined(UD_NQ_INCLUDECIFSSERVER) && defined(UD_NQ_INCLUDESMB2)

/* init notification module */
NQ_STATUS            /* NQ_SUCCESS or NQ_FAIL */
cs2NotifyInit(
    void
    );

/* exit notification module */

void
cs2NotifyExit(
    void
    );

/* start notification list */
void
cs2NotifyStart(
    NQ_UINT32 filter            /* completion filter */
    );

/* finish notification list and send notifications */

void
cs2NotifyEnd(
    void
    );

/* notify one file */
void
cs2NotifyFile(
    const NQ_TCHAR* fileName,       /* file name pointer */
    NQ_UINT32 action,               /* action code */
    NQ_BOOL notifyParent            /* FALSE to notify thsi file, TRUE to notify its parent folder */
    );

/* send notification gathered so far in the response buffer */
void
cs2NotifySend(
    void
    );

#endif /* UD_NQ_INCLUDESMB2 */

#endif /* defined(UD_NQ_INCLUDECIFSSERVER) && defined(UD_NQ_INCLUDESMB2) */

