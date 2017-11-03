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

#ifndef _CCSMB311_H_
#define _CCSMB311_H_

#include "cmapi.h"
#include "cccifs.h"
#include "ccserver.h"

/* -- API Functions */

/* Description
   Initialize this module.
   Returns
   None
 */
NQ_BOOL ccSmb311Start(void);

/* Description
   Release resources used by this module.
   Returns
   <i>TRUE</i> on success and <i>FALSE</i> on failure.
 */
NQ_BOOL ccSmb311Shutdown(void);

/* Description
   Get dialect descriptor
   Returns
   Pointer to dialect descriptor.
 */
const CCCifsSmb * ccSmb311GetCifs(void);

/* Description
   Processor for a foreign response.

   The only expected response is Negotiate.

   CIFS code calls this functions when it encounters
   an SMB2 response on SMB1 Negotiate request.
   Returns
   Pointer to dialect descriptor.

   Parameters
   server :  Server object pointer. On a successful negotiation the dialect pointed by
			 this structure, installs itself as the server's dialect.
   data :  Pointer to the response
   len :  Response length in bytes
   blob :  Pointer to security blob to be set on exit.
   Returns
   NQ_SUCCESS or error code.
 */
NQ_STATUS ccsmb311doNegotiate(CCServer * pServer, CMBlob * inBlob);

#endif /* _CCSMB311_H_	 */
