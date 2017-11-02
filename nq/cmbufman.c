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

#include "cmbufman.h"

/* -- API Functions */

NQ_BOOL cmBufManStart(void)
{
	return TRUE;
}

void cmBufManShutdown(void)
{

}

NQ_BYTE * cmBufManTake(NQ_COUNT size)
{
	return (NQ_BYTE *)cmMemoryAllocate(size);
}

void cmBufManGive(NQ_BYTE * buffer)
{
	if (NULL != buffer)
		cmMemoryFree(buffer);
}

#if SY_DEBUGMODE
/* Description
   This function prints internal information about buffer management.
   Returns
   None                                                                       */
void cmBufManDump(void)
{
	
}
#endif /* SY_DEBUGMODE */

