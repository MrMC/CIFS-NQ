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


#define BUFREPOSITORY_SIZE_MEDIUM       (UD_NS_BUFFERSIZE + 52 + 100)       /* 64K + transform header + space for command structure */
#define BUFREPOSITORY_SIZE_LARGE        (1048576 + 52 + 100)                /* 1MB + transform header + space for command structure */

#define BUFREPOSITORY_NUM_OF_BUFFERS    10


static CMRepository	BufRepoMedium;
#ifdef UD_NQ_INCLUDESMB3
static CMRepository	BufRepoLarge;
#endif /* UD_NQ_INCLUDESMB3*/


typedef struct
{
    CMItem * item;
    CMRepository * rep;
}
Buffer;


/* -- API Functions */

NQ_BOOL cmBufManStart(void)
{
    cmRepositoryInit(&BufRepoMedium, 0, NULL, NULL);
    cmRepositoryItemPoolAlloc(&BufRepoMedium, BUFREPOSITORY_NUM_OF_BUFFERS, sizeof(Buffer) + BUFREPOSITORY_SIZE_MEDIUM);
#ifdef UD_NQ_INCLUDESMB3
    cmRepositoryInit(&BufRepoLarge, 0, NULL, NULL);
    cmRepositoryItemPoolAlloc(&BufRepoLarge, BUFREPOSITORY_NUM_OF_BUFFERS, sizeof(Buffer) + BUFREPOSITORY_SIZE_LARGE);
#endif /* UD_NQ_INCLUDESMB3*/

	return TRUE;
}

void cmBufManShutdown(void)
{
    cmRepositoryShutdown(&BufRepoMedium);
#ifdef UD_NQ_INCLUDESMB3
    cmRepositoryShutdown(&BufRepoLarge);
#endif /* UD_NQ_INCLUDESMB3*/
}

NQ_BYTE * cmBufManTake(NQ_COUNT size)
{
    Buffer *pRepBuffer;
    NQ_BYTE *buf = NULL;
    
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "size:%d", size);

    if (size <= BUFREPOSITORY_SIZE_MEDIUM)
    {
        pRepBuffer = (Buffer *)cmRepositoryGetNewItem(&BufRepoMedium);
        pRepBuffer->rep = &BufRepoMedium;
        buf = (NQ_BYTE *)(++pRepBuffer);
    }
#ifdef UD_NQ_INCLUDESMB3
    else if (size <= BUFREPOSITORY_SIZE_LARGE)
    {
        pRepBuffer = (Buffer *)cmRepositoryGetNewItem(&BufRepoLarge);
        pRepBuffer->rep = &BufRepoLarge;
        buf = (NQ_BYTE *)(++pRepBuffer);
    }
#endif /* UD_NQ_INCLUDESMB3*/
    else
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Size not allowed:%d", size);
    }
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "buf:%p", buf);
    return buf;
}

void cmBufManGive(NQ_BYTE * buffer)
{
    Buffer *pRepBuffer;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "buf:%p", buffer);

    if (NULL != buffer)
    {
        pRepBuffer = (Buffer *)buffer - 1;
        cmRepositoryReleaseItem(pRepBuffer->rep, (CMItem *)pRepBuffer);
    }
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
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

