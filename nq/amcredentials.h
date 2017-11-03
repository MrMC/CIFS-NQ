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

#ifndef _AMCREDENTIALS_H_ 
#define _AMCREDENTIALS_H_

#include "amapi.h"

/* Description
   Convert ASCII credentials to Unicode
   Parameters
   to : Unicode destination.
   from : ASCII source.
   Returns
   None.
 */
void amCredentialsAsciiiToW(AMCredentialsW * to, const AMCredentialsA *from);


#endif /* _AMCREDENTIALS_H_ */
