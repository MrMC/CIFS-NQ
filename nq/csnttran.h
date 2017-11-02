/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Implementation of the NT_TRANSACTION command
 *--------------------------------------------------------------------
 * MODULE        : CS - CIFS Server
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 21-August-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _CSNTTRAN_H_
#define _CSNTTRAN_H_

#include "cmapi.h"

/* This structure is used for passing information to a subcommand and returning information
   from the subcommand */

typedef struct
{
    const CMCifsNtTransactionRequest*
                        requestData;    /* IN: pointer to the data area in the request */
    const CMCifsHeader* pHeaderOut;     /* IN: pointer to the CIFS header of the response */
    NQ_BYTE* pParams;                      /* IN: pointer to the parameter area in the response
                                               properly alligned */
    NQ_UINT16 parameterCount;              /* OUT: length of the parameter area */
    NQ_BYTE* pData;                        /* OUT: pointer to the data area */
    NQ_UINT16 dataCount;                   /* OUT: length of the data area */
}
CSNtTransactionDescriptor;

/* abstract prototype for a subcommand processor */

typedef
NQ_UINT32
(*NtTransactionFunction)(
    CSNtTransactionDescriptor* descriptor        /* see above */
    );

/* actual prototypes */

NQ_UINT32 csNtTransactionCreate(CSNtTransactionDescriptor*);
NQ_UINT32 csNtTransactionSetSecurityDescriptor(CSNtTransactionDescriptor*);
NQ_UINT32 csNtTransactionQuerySecurityDescriptor(CSNtTransactionDescriptor*);
NQ_UINT32 csNtTransactionNotifyChange(CSNtTransactionDescriptor*);

const NQ_BYTE* csGetEmptySd(NQ_UINT32 filter, NQ_UINT32 *sdLength);

#endif  /* _CSNTTRAN_H_ */


