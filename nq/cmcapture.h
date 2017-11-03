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

#ifndef _CMCAPTURE_H_
#define _CMCAPTURE_H_

#include "syapi.h"          /* system-dependent */
#include "cmapi.h"
#include "cmcommon.h"       /* basic types */
#include "cmbuf.h"

#ifdef UD_NQ_INCLUDESMBCAPTURE

typedef struct{
	NQ_IPADDRESS srcIP;
	NQ_PORT srcPort;
	NQ_IPADDRESS dstIP;
	NQ_PORT dstPort;
	NQ_BOOL receiving;
}CMCaptureHeader;

NQ_BOOL cmCaptureStart(void);
void cmCaptureShutdown(void);

void cmCapturePacketWriteStart(const CMCaptureHeader * header ,NQ_UINT length);
void cmCapturePacketWritePacket(NQ_BYTE * packet ,NQ_UINT length  );
void cmCapturePacketWriteEnd();

#endif /* UD_NQ_INCLUDESMBCAPTURE */

#endif /* _CMCAPTURE_H_ */
