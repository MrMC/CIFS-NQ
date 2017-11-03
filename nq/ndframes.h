/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Sending different ND frames
 *--------------------------------------------------------------------
 * MODULE        : ND - NetBIOS Daemon
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 2-September-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _NDFRAMES_H_
#define _NDFRAMES_H_

#include "cmapi.h"

#include "ndadaptr.h"

/* Generate Name <whatever> Request packet */

NQ_INT                              /* returns the message length or -1 on error */
ndGenerateNameWhateverRequest(
    CMNetBiosHeader* msgHdr,        /* pointer to the buffer of enough length */
    const CMNetBiosName name,       /* name to use in the request */
    NQ_UINT32 ip,                   /* name's IP in NBO */
    NQ_BOOL nodeTypeB,              /* TRUE for B type */
	NQ_BOOL isGroupName				/* TRUE if its a group name */
    );

/* Generate Name <whatever> Response packet */

NQ_INT                              /* returns the message length or -1 on error */
ndGenerateNameWhateverResponse(
    CMNetBiosHeader* msgHdr,        /* pointer to the buffer of enough length */
    const CMNetBiosName name,       /* name to use in the response */
    NQ_UINT16 type,                 /* resource type as in the RR RECORD */
    const NQ_BYTE* moreData,        /* more data after the resource record */
    NQ_UINT moreLength              /* this data length */
    );

/* Generate Name Query Request packet */

NQ_INT                              /* returns the message length or -1 on error */
ndGenerateNameQueryRequest(
    CMNetBiosHeader* msgHdr,        /* pointer to the buffer of enough length */
    const CMNetBiosName name        /* name to use in the request */
    );

/* Generate Name <whatever> Response packet */

#endif  /* _ndFrameFRAMES_H_ */
