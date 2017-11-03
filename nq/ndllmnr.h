/*********************************************************************
 *
 *           Copyright (c) 2008 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : LLMNR Resolver
 *--------------------------------------------------------------------
 * MODULE        : RD - Responder Daemon
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 08-Dec-2008
 * CREATED BY    : Lilia Wasserman
 * LAST AUTHOR   : $Author:$
 ********************************************************************/


#ifndef _NDLLMNR_H_
#define _NDLLMNR_H_

#include "cmapi.h"
#include "cmbuf.h"
#include "ndadaptr.h"
#include "nsdns.h"
#include "ndinname.h"
#include "ndexname.h"
#include "nsapi.h"

void ndLLMNRSetSocket(SYSocketHandle socket);

NQ_STATUS
ndLLMNRProcessExternalMessage(
    NDAdapterInfo* adapter
    );



#endif /* _NDLLMNR_H_ */
