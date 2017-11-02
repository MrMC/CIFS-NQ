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

#ifndef _CMBUFMAN_H_
#define _CMBUFMAN_H_

#include "cmapi.h"

/* -- API Functions */

/* Description
   Initialize this module.
   Returns 
   None
 */
NQ_BOOL cmBufManStart(void);

/* Description
   Release resources used by this module.
   Returns 
   None
 */
void cmBufManShutdown(void);

/* Description
   This function allocates a buffer of required size of bigger.
   Parameters
   size :  Desired buffer size. The manager can allocate a bigger
           buffer.
   Returns
   Pointer to the buffer.
   Note
   The returned buffer should be released by calling <link cmBufManGive@NQ_BYTE *, cmBufManGive>()
   function                                                                                        */
NQ_BYTE * cmBufManTake(NQ_COUNT size);

/* Description
   This function releases a buffer previously allocated in a <link cmBufManTake@NQ_COUNT, cmBufManTake()>
   call.
   Parameters
   buffer :  Pointer to the buffer to release.
   Returns
   None.
                                                                                                          */
void cmBufManGive(NQ_BYTE * buffer);

#if SY_DEBUGMODE
/* Description
   This function prints internal information about buffer management.
   Returns
   None                                                                       */
void cmBufManDump(void);
#endif /* SY_DEBUGMODE */

#endif /* _CMBUFMAN_H_	 */
