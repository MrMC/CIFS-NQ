/*********************************************************************
 *
 *           Copyright (c) 2012 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Oplock breaks functionality
 *--------------------------------------------------------------------
 * DEPENDENCIES  : None
 *--------------------------------------------------------------------
 * CREATION DATE : 02-Apr-2012
 * CREATED BY    : Lilia Wasserman
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _CSBREAK_H_
#define _CSBREAK_H_

#include "cscreate.h"

#ifdef UD_NQ_INCLUDECIFSSERVER

NQ_BOOL 
csBreakCheck(
    CSCreateParams * pParams
    );


NQ_BOOL 
csBreakComplete(
    CSFile *pFile,
    void * pHeaderOut,
    NQ_UINT32 headerInFlags
    );


#endif /* UD_NQ_INCLUDECIFSSERVER */
#endif /* _CSBREAK_H_ */

