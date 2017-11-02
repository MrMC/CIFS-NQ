/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Definition NetBIOS extension to RFC 1002 - IPC
 *--------------------------------------------------------------------
 * MODULE        : CM - Common library
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 4-June-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _CMNBVISU_H_
#define _CMNBVISU_H_

#include "cmapi.h"

/* Beginning of packed structures definition */

#include "sypackon.h"

/****************************************************************************
   IPC is a proprietary NetBIOS extension used solely for Visuality internal
   purposes. These packets are exchanging between application's NetBIOS and
   the Datagram Deamon (DD)
 ****************************************************************************/

/*
    generic definitions
    -------------------
 */

#define CM_NB_VIPCVERSION       0x0001

/*
    packet codes
    ------------
 */

#define CM_NB_LISTENREQUEST     0x0011
#define CM_NB_LISTENRESPONSE    0x0012
#define CM_NB_CANCELLISTEN      0x0019

/*
    registration status for LISTEN_RESPONSE packet
    ----------------------------------------------
 */

#define CM_NB_VIPCOK                0x0007
#define CM_NB_VIPCALREADYREGISTERED 0x00A2
#define CM_NB_VIPCRESOURCELACK      0x00A3
#define CM_NB_VIPCUNSPECIFIED       0x00A4

/*
    types of LISTEN REQUEST and LISTEN CANCEL
    -----------------------------------------
 */
#define CM_NB_VIPCREQUESTDATAGRAM           0x0001
#define CM_NB_VIPCREQUESTBROADCASTDATAGRAM  0x0002
#define CM_NB_VIPCREQUESTSESSION            0x0003

#define CM_NB_VIPCCANCELDATAGRAM    0x0005
#define CM_NB_VIPCCANCELSESSION     0x0006
#define CM_NB_VIPCCANCELALL         0x0007

/*
    generic structure of Visuality IPC message
    ------------------------------------------
 */

typedef SY_PACK_PREFIX struct
{
    NQ_SUINT16 protocolVersion;     /* for backwards compatibility */
    NQ_SUINT16 code;                /* operation code (see above) */
} SY_PACK_ATTR
CMNetBiosVIPCHeader;

/*
    Visuality IPC LISTEN REQUEST message
    ------------------------------------
 */

typedef SY_PACK_PREFIX struct
{
    CMNetBiosVIPCHeader header;     /* common header */
    NQ_SUINT16 type;                    /* request type */
    NQ_SUINT16 port;                    /* listen port */
    CMNetBiosName name;             /* name of the listening socket */
    NQ_SUINT32 pid;                      /* PID of the requesting task */
} SY_PACK_ATTR
CMNetBiosVIPCListen;

/*
    Visuality IPC CANCEL LISTEN message
    -----------------------------------
 */

typedef SY_PACK_PREFIX struct
{
    CMNetBiosVIPCHeader header;     /* common header */
    NQ_SUINT16 type;                    /* request type */
    NQ_SUINT32 pid;                      /* PID of the requesting task */
} SY_PACK_ATTR
CMNetBiosVIPCCancel;

/*
    Visuality IPC LISTEN REPONSE message
    ------------------------------------
 */

typedef SY_PACK_PREFIX struct
{
    CMNetBiosVIPCHeader header;     /* common header */
    NQ_SUINT16 status;              /* the response (see values above) */
} SY_PACK_ATTR
CMNetBiosVIPCResponse;

#include "sypackof.h"

/* End of packed structures definition */

#endif /* _CMNBVISU_H_ */
