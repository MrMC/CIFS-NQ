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

#ifndef _CCTRANS_H_
#define _CCTRANS_H_

#include "ccserver.h"

/* Beginning of packed structures definition */

#include "sypackon.h"

typedef SY_PACK_PREFIX struct {
    NQ_SCHAR Data[1];
}
SY_PACK_ATTR TransParamCmd;

#include "sypackof.h"

/* End of packed structures definition */

/* -- API functions -- */

CMCifsTransactionRequest * ccTransGetCmdPacket(NQ_BYTE ** parameters, NQ_BYTE setupCount);

void ccTransPutCmdPacket(CMCifsTransactionRequest * packet);

#ifdef UD_NQ_USETRANSPORTNETBIOS

NQ_STATUS ccTransSendTo(
    NSSocketHandle socket,
    CMNetBiosNameInfo * dstName,
    CMCifsTransactionRequest * trans_cmd,
    NQ_UINT16 transOffset,
    NQ_UINT * paramCount,
    NQ_BYTE * cmdParameters,
    NQ_UINT * dataCount,
    NQ_BYTE * cmdData,
    NQ_UINT maxParamCount
    );

NQ_STATUS ccTransReceiveFrom(
    NSSocketHandle socket,
    CMNetBiosNameInfo * srcName,
    NQ_UINT * paramCount,
    NQ_BYTE ** rspParameters,
    NQ_UINT * dataCount,
    NQ_BYTE ** rspData,
    NQ_BYTE ** buffer,
	NQ_UINT timeoutSec
    );

#endif /* UD_NQ_USETRANSPORTNETBIOS */

#endif /* _CCTRANS_H_ */
