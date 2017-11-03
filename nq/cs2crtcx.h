/*************************************************************************
 * Copyright 2011-2012 by Visuality Systems, Ltd.
 *
 *                     All Rights Reserved
 *
 * This item is the property of Visuality Systems, Ltd., and contains
 * confidential, proprietary, and trade-secret information. It may not
 * be transferred from the custody or control of Visuality Systems, Ltd.,
 * except as expressly authorized in writing by an officer of Visuality
 * Systems, Ltd. Neither this item nor the information it contains may
 * be used, transferred, reproduced, published, or disclosed, in whole
 * or in part, and directly or indirectly, except as expressly authorized
 * by an officer of Visuality Systems, Ltd., pursuant to written agreement.
 **************************************************************************/

#ifndef _CS2CRTCX_H
#define _CS2CRTCX_H

/*  
    Context structure. 
    This structure is passed between Create request parsing and Create response packing. 
*/
typedef struct
{
    NQ_UINT32 flags;        /* contains flags for setup contexts */
    const NQ_BYTE * sdData; /* pointer to security descriptor or NULL if not set */
    NQ_COUNT sdLen;         /* security descriptor length */
    NQ_BYTE * durableReopen;/* pointer to re-open ID */
    NQ_UINT64 allocSize;    /* allocation size */
}
CSCreateContext;

#endif /* _CS2CRTCX_H */
