/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Common Create procesing (SMB1 and SMB2)
 * NOTES:
 *  This header defines functions common for both SMB1 and SMB2 processing
 *--------------------------------------------------------------------
 * MODULE        : CS - CIFS Server
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 8-Feb-2009
 ********************************************************************/
 
#ifndef _CSCREATE_H_
#define _CSCREATE_H_

#include "cmbuf.h"



/* Create handler. This function performs command Create processing. */

NQ_UINT32 csCreateCommonProcessing(
    CSCreateParams * params     /* create parameters */
    );


#if defined(UD_NQ_INCLUDECIFSSERVER) && defined(UD_NQ_INCLUDESMB2)

/* Pack create contexts */
NQ_UINT32
    cs2PackCreateContexts(
    CMBufferWriter * writer,     /* writer */ 
    CSCreateContext *context     /* create context */
    );
#endif

#endif /* _CSCREATE_H_ */

