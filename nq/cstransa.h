
/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Implementation of the TRANSACTION command
 *--------------------------------------------------------------------
 * MODULE        : CS - CIFS Server
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 2-Jan-2005
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _CSTRANSA_H_
#define _CSTRANSA_H_

#include "cmapi.h"
#include "csdispat.h"

/* This structure is used for passing information to a subcommand and returning information
   from the subcommand */

typedef struct
{
    CMCifsHeader* hdrOut;               /* OUT: SMB header of the response */
    const NQ_BYTE* dataIn;              /* IN: pointer to the outgoing data area */
    NQ_UINT16 maxData;                  /* IN: maximum length of the outgoing data */
    NQ_BYTE* dataOut;                   /* OUT: pointer to the outgoing data area */
    NQ_UINT16 dataCount;                /* IN/OUT: number of data bytes */
    const NQ_BYTE* paramIn;             /* IN: pointer to the parameter area */
    NQ_UINT16 maxParam;                 /* IN: maximum number of outgoing parameters */
    NQ_BYTE* paramOut;                  /* OUT: pointer to the outgoing parameter area */
    NQ_UINT16 paramCount;               /* IN/OUT: number of incoimg/outgoing parameters */
    const NQ_UINT16* setupIn;           /* IN: pointer to the setup area */
    NQ_UINT16 maxSetup;                 /* IN: maximum number of the outgoing setups */
    NQ_UINT16 setupCount;               /* IN/OUT: number of incoimg/outgoing setups */
    NQ_UINT16* setupOut;                /* OUT: pointer to the outgoing setup area (is advanced) */
    NQ_BYTE* pBuf;                      /* IN/OUT: pointer to the last byte after TRANSACT response header -
                                           is advanced */
}
CSTransactionDescriptor;

/* calculate subcommand data pointer and size */

NQ_STATUS                            /* NQ_SUCCESS or error code */
csTransactionPrepareLateResponse(
    CSLateResponseContext* context   /* saved context */
    );

/* send a response using saved context */

NQ_BOOL                              /* TRUE on success */
csTransactionSendLateResponse(
    CSLateResponseContext* context,  /* saved context */
    NQ_UINT32 status,                /* status to report, zero for success */
    NQ_COUNT dataLength              /* actual command data length */
    );

#endif  /* _CSTRANSA_H_ */


