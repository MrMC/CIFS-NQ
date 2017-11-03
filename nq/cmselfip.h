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

#ifndef _CMSELFIP_H_
#define _CMSELFIP_H_

#include "cmapi.h"

/* Description
   Starts this module.
   Returns
   TRUE on success, FALSE on failure.                          */
typedef struct 
{
    NQ_IPADDRESS ip;    	/* IP address   either v4 or v6 */
    NQ_UINT32 bcast;   	 	/* IPv4 broadcast address */
    NQ_UINT32 subnet;   	/* IPv4 subnet address */
#ifdef CM_NQ_STORAGE
    NQ_UINT osIndex;		/* adapter index as in the OS */
    NQ_BOOL rdmaCapable;	/* TRUE when this adapter supports RDMA */
#endif
}
CMSelfIp;

/* Description
   Starts this module.
   Returns
   TRUE on success, FALSE on failure.                          */
NQ_BOOL cmSelfipStart(void);

/* Description
   Shutdown this module.
   Returns
   None */
void cmSelfipShutdown(void);

/* Description
   This function resest the process of self IP iteration. The next call to cmSelfipGetNext()
   will bring the first IP. 

   Returns
   None. */
void cmSelfipIterate(void);

/* Description
   This function iterates self IP addresses. 

   Returns
   Pointer to the next self IP address or NULL when there are no more addresses. */
const CMSelfIp * cmSelfipNext(void);

/*Description
        This function terminats the iterator after being used by cmSelfipNext */
void cmSelfipTerminate(void);


#endif  /* _CMSELFIP_H_ */

