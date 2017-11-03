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

#ifndef _CMPORTMNG_H_
#define _CMPORTMNG_H_

#include "cmapi.h"

/* Description
   This fucntion releases a previous bound local port.

   Parameters
   port :  Port to release.
   Returns
   None. */
void cmManageFreePort(NQ_PORT port);

/* Description
   This function given the first available dynamic port.

   Returns
   The assigned port. */
NQ_PORT cmPortManage(void);

/* Description
   This function starts this module.
   Returns
   TRUE on success, FALSE on failure.                          */
NQ_BOOL cmPortManageStart(void);

#endif /* _CMPORTMNG_H_ */
