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

#ifndef _CCSMB10_H_
#define _CCSMB10_H_

#include "cmapi.h"
#include "cccifs.h"

/* -- API Functions */

/* Description
   Initialize this module.
   Returns 
   None
 */
NQ_BOOL ccSmb10Start(void);

/* Description
   Release resources used by this module.
   Returns 
   <i>TRUE</i> on success and <i>FALSE</i> on failure.
 */
NQ_BOOL ccSmb10Shutdown(void);

/* Description
   Get dialect descriptor
   Returns 
   Pointer to dialect descriptor.
 */
const CCCifsSmb * ccSmb10GetCifs(void);

#endif /* _CCSMB10_H_	 */
