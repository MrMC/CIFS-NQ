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

#ifndef _CCNETWRK_H_
#define _CCNETWRK_H_

#include "cmapi.h"

/* Module-global functions */

NQ_BOOL ccNetworkStart(void);

void ccNetworkShutdown(void);
 
/* Description
   A callback function is called from several result parsers when they encounter another item.  
   This function creates an item and adds it to the respective list.
   
   Parameters
   list : A list to add name to.  
   name : Name to add.  

   Returns
   None.                                                        */
typedef void (* CCNetworkAddNameCallback)(const NQ_WCHAR * name, CMList * list);

#endif /* _CCNETWRK_H_ */
