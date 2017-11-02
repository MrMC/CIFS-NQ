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

#ifndef _CCERRORS_H_
#define _CCERRORS_H_

#include "cmapi.h"

/* -- API Functions */

/* Description
   Get NQ error by SMB NT status.
   Parameters
   status :  SMB/SMB2 NT status.
   isNt: TRUE for NT error
   Returns
   NQ error code.                 */
NQ_UINT32 ccErrorsStatusToNq(NQ_UINT32 status, NQ_BOOL isNT);

#endif /* _CCERRORS_H_	 */
