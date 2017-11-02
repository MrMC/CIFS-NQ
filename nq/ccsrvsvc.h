/*********************************************************************
 *
 *           Copyright (c) 2005 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : SRVSVC functions for CIFS Client
 *--------------------------------------------------------------------
 * DEPENDENCIES  : None
 *--------------------------------------------------------------------
 * CREATION DATE : 22-Sep-2005
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _CCSRVSVC_H_
#define _CCSRVSVC_H_

#include "ccapi.h"
#include "ccdcerpc.h"
#include "cmlist.h"

/* callback function for storing different names during enumeration */

typedef void
(*CCSrvsvcEnumerateCallback)(
    const NQ_WCHAR* shareName,  /* name of the next share (null terminated) */
    void * params               /* abstract parameters */
    );

/* get pipe descriptor */

const CCDcerpcPipeDescriptor*
ccSrvsvcGetPipe(
    void
    );

/* initialize this module */

NQ_BOOL ccSrvsvcStart(void);

/* stp using this module */

void ccSrvsvcShutdown(void);

/* start enumerating list of shares over a previously opened pipe */

void ccSrvsvcLock(void);

/* start enumerating list of shares over a previously opened pipe */

void ccSrvsvcUnlock(void);

/* enumerate list of shares over a previously opened pipe */

NQ_STATUS                   /* NQ_SUCCESS or NQ_FAIL */
ccSrvsvcEnumerateShares(
    NQ_HANDLE pipeHandle,                       /* pipe handle */
    const NQ_WCHAR* hostName,                   /* server name */
    CCSrvsvcEnumerateCallback callback,         /* callback for getting next share name */
    void* params                                /* abstract parameters for callback */
    );

/* get share information over the previously opened pipe */

NQ_STATUS                   /* NQ_SUCCESS or NQ_FAIL */
ccSrvsvcGetShareInfo(
    NQ_HANDLE pipeHandle,
    const NQ_WCHAR* hostName,
    const NQ_WCHAR* share,
    NQ_UINT16 *type,
    NQ_BYTE *remark,
    NQ_INT maxRemarkSize,
    NQ_BOOL unicodeResult
    );

#endif /* _CCSRVSVC_H_ */
