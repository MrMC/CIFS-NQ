
/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Implementation of the TRANSACTION2 command
 *--------------------------------------------------------------------
 * MODULE        : CS - CIFS Server
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 13-July-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _CSTRANS2_H_
#define _CSTRANS2_H_

#include "cmapi.h"

/* This structure is used for passing information to a subcommand and returning information
   from the subcommand */

typedef struct
{
    const CMCifsTransaction2Request*
                        requestData;    /* IN: pointer to the data area in the request */
    const CMCifsHeader* pHeaderOut;     /* IN: pointer to the CIFS header of the response */
    NQ_BYTE* pParams;                      /* IN: pointer to the parameter area in the response
                                               properly alligned */
    NQ_UINT16 parameterCount;              /* OUT: length of the parameter area */
    NQ_BYTE* pData;                        /* OUT: pointer to the data area */
    NQ_UINT16 dataCount;                   /* OUT: length of the data area */
}
CSTransaction2Descriptor;

/* abstract prototype for a subcommand processor */

typedef
NQ_UINT32
(*Transaction2Function)(
    CSTransaction2Descriptor* descriptor        /* see above */
    );

/* actual prototypes */

NQ_UINT32 csTransaction2Open(CSTransaction2Descriptor*);
NQ_UINT32 csTransaction2FindFirst(CSTransaction2Descriptor*);
NQ_UINT32 csTransaction2FindNext(CSTransaction2Descriptor*);
NQ_UINT32 csTransaction2QueryFsInformation(CSTransaction2Descriptor*);
NQ_UINT32 csTransaction2QueryPathInformation(CSTransaction2Descriptor*);
NQ_UINT32 csTransaction2SetPathInformation(CSTransaction2Descriptor*);
NQ_UINT32 csTransaction2QueryFileInformation(CSTransaction2Descriptor*);
NQ_UINT32 csTransaction2SetFileInformation(CSTransaction2Descriptor*);
NQ_UINT32 csTransaction2CreateDirectory(CSTransaction2Descriptor*);

#endif  /* _CSTRANS2_H_ */


