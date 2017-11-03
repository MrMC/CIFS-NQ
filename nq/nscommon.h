/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : The internal defintions for this modules
 *--------------------------------------------------------------------
 * MODULE        : NS - NetBIOS Sockets
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 14-May-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _NSCOMMON_H_
#define _NSCOMMON_H_

#include "nsapi.h"
#include "nsinsock.h"

/*
    Internal routines
 */

/* send request to the Name Daemon */

NQ_STATUS                   /* NQ_FAIL or SUCESS */
nsSendRequestToND(
    SYSocketHandle socket,  /* socket to use */
    const NQ_BYTE* msg,     /* message to send */
    NQ_UINT msgLen          /* message length */
    );

/* receive response from the Name Daemon */

NQ_STATUS                   /* NQ_FAIL or SUCESS */
nsReceiveResponseFromND(
    SYSocketHandle socket,  /* socket to use */
    void * addrEntry        /* buffer to place the response message */
    );

/* send request to the Name Daemon and get a response */

NQ_STATUS                   /* NQ_FAIL or SUCESS */
nsProceedRequestToND(
    const NQ_BYTE* msg,     /* message to send */
    NQ_UINT msgLen,         /* message length */
    void* responseBuf       /* buffer to place the response message */
    );

/* send request to the Datagram Daemon and get a response */

NQ_STATUS                   /* NQ_FAIL or SUCESS */
nsProceedRequestToDD(
    const NQ_BYTE* msg,     /* message to send */
    NQ_UINT msgLen,         /* message length */
    const CMNetBiosName name/* socket name to check the response */
    );

/* generate a special NetBIOS name. ND will recognize this name as a
   PID registration reguest */

void
nsCreateInternalName(
    CMNetBiosName  buf      /* buffer for name creation */
    );

#endif  /* _NSCOMMON_H_ */

