
/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Server parameters
 *--------------------------------------------------------------------
 * MODULE        : CS - CIFS Server
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 14-June-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _CSPARAMS_H_
#define _CSPARAMS_H_

#include "cmnbfram.h"

/* value of the flags and flags2 field for a server response */

#define CS_SMBFLAGS   0x88              /* case insensitive & response */
#define CS_SMBFLAGS2  cmHtol16(0x0001)  /* aware of long names */

/* supported dialect */

#define CS_SUPPORTEDDIALECT   "NT LM 0.12"

#define CS_MAXNUMBERVC      1               /* number of virtual connections to the same client */
#define CS_MAXBUFFERSIZE    (UD_NS_BUFFERSIZE - sizeof(CMNetBiosSessionMessage))
                                            /* max SMB message length */
#define CS_MAXRAWSIZE       (1<<16)

#define CS_SESSIONACTION    0               /* in the session response */
#define CS_SESSIONACTION_GUEST    1         /* action in the session setup response: guest login */
#define CS_PASSWORDLEN      16              /* the exact length of the password */

#define CS_SMB2_SESSIONEXPIRATIONTIME  (10*3600)  /* maximal time (in seconds) for smb2 session (uid) to live */
#define CS_SMB2_MAX_READ_SIZE   (CS_MAXBUFFERSIZE - SMB2_HEADERSIZE - 16)   /* 16 = structure size of SMB2 Read command  */
#define CS_SMB2_MAX_WRITE_SIZE  (CS_MAXBUFFERSIZE - SMB2_HEADERSIZE - 48)   /* 48 = structure size of SMB2 Write command */

#endif  /* _CSPARAMS_H_ */

