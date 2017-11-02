/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Parameters
 *--------------------------------------------------------------------
 * MODULE        : CM - Common library
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 23-May-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _CMNBPARM_H_
#define _CMNBPARM_H_

/*
    NQ-wide parameters
    ------------------
 */

#define CM_DDNAME "VISUALITY NBT DD"        /* NetBIOS name for the DD daemon */

#define CM_SOFTWAREVERSIONMAJOR 7           /* software versions major */
#define CM_SOFTWAREVERSIONMINOR 2           /* ... and minor           */

#define CM_SERVERBUFFERSIZE     (256 * 3 * sizeof(NQ_TCHAR) + 1000)  /* size of the server temporary buffer */
#define CM_COMMONBUFFERSIZE     (UD_NS_BUFFERSIZE + 1000)            /* size of the common temporary buffer */

/*
    NetBIOS parameters
    ------------------
 */

/* datagram buffer size and multiplex count */

#define     CM_NB_DATAGRAMBUFFERSIZE        1500
#define     CM_CS_MAXMPXCOUNT               10   /* should be supported by the TCP underlying system */
#ifdef UD_NS_ASYNCSEND
#define     CM_NB_NUMBUFFERS                4
#else
#define     CM_NB_NUMBUFFERS                2
#endif

/* algorithm parameters */

#define     CM_NB_BROADCASTTIMEOUT          1
#define     CM_NB_UNICASTREQRETRYTIMEOUT    5
#define     CM_NB_UNICASTREQRETRYCOUNT      2
#define     CM_NB_VERYBIGNBTIMEOUT          1 /* 1 sec */ /*(60*60) 1 hour */

/* network constants */

/* NetBIOS ports to send the outgoing packets to */
#define     CM_NB_NAMESERVICEPORT           137
#define     CM_NB_DATAGRAMSERVICEPORT       138
#define     CM_NB_SESSIONSERVICEPORT        139

/* TCP/IP port to send the outgoing packets to */
#define     CM_NB_SESSIONSERVICEPORTIP      445

/* NetBIOS ports to listen on */
#define     CM_IN_NAMESERVICEPORT           udGetPort(CM_NB_NAMESERVICEPORT)
#define     CM_IN_DATAGRAMSERVICEPORT       udGetPort(CM_NB_DATAGRAMSERVICEPORT)
#define     CM_IN_SESSIONSERVICEPORT        udGetPort(CM_NB_SESSIONSERVICEPORT)

/* Internal NetBIOS ports */
#define     CM_IN_INTERNALIPCPORT           udGetPort(UD_BR_INTERNALIPCPORT)
#define     CM_IN_INTERNALNSPORT            udGetPort(UD_NS_INTERNALNSPORT)
#define     CM_IN_INTERNALDSPORT            udGetPort(UD_NS_INTERNALDSPORT)

/* default values (if not specified in the config file) */

#define     CM_NB_DEFAULT_NODETYPE          "B"
#define     CM_NB_DEFAULT_SCOPEID           ""

/* client parameters */

#define CM_DIALECT_NT_LM_012       "NT LM 0.12"
#define CM_NATIVE_OS               "Windows 4.0"
#define CM_NATIVE_LANMAN           CM_NATIVE_OS

/* common values */

#define CM_USERNAMELENGTH      256

#endif  /* _CMNBPARM_H_ */
