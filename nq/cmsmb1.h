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

#ifndef _CMSMB1_H_
#define _CMSMB1_H_

#include "cmapi.h"
#include "cmbuf.h"

#define SMB_SECURITY_SIGNATURE_OFFSET 14	/* shift from header start to signature */

/* SMB header */
typedef struct
{
    NQ_BYTE *_start;        /* header start address in buffers */
    NQ_UINT16 size;         /* should be 32 */
    NQ_BYTE command;		/* command code */
    NQ_UINT32 status;		/* NT status */
    NQ_BYTE flags;			/* basic flags */ 
    NQ_UINT16 flags2;		/* flags extension */
    NQ_UINT32 pid;			/* pid low + pid high */
    NQ_BYTE signature[8];	/* security signature */
    NQ_UINT16 tid;			/* tree ID */ 
    NQ_UINT16 uid;			/* user ID */
    NQ_UINT16 mid;			/* multiplex ID - comamdns equence number */
} CMSmbHeader;

/* SMB packet */
typedef struct
{
	CMSmbHeader header;		/* packet header */
    NQ_BYTE *_start;        /* header start address in buffers */
    NQ_BYTE wordCount;		/* number of packet words */
    NQ_BYTE * pWordCount;	/* pointer to the word count in the packet */
    NQ_UINT16 byteCount;	/* number of packet bytes */
    NQ_BYTE * pByteCount;	/* pointer to the byte count in the packet */
} CMSmbPacket;

/* SMB header size (always 32) */
#define SMB_HEADERSIZE 32

/*
 * Initialize SMB request header structure 
 * The writer must point to the header start address.
 */
void cmSmbHeaderInitForRequest(CMSmbHeader *header, const CMBufferWriter *writer, NQ_BYTE command);
/*
 * Initialize SMB response header structure 
 * The writer must point to the header start address.
 */
void cmSmbHeaderInitForResponse(CMSmbHeader *header, const CMBufferWriter *writer);
/* Prepare response header (it must be initialized before!) */
void cmSmbHeaderSetForResponse(CMSmbHeader *header, const CMBufferWriter *writer);

/* Read SMB header using buffer reader */
void cmSmbHeaderRead(CMSmbHeader *header, CMBufferReader *reader);
/* Shift to the next compound (chained) command */
void cmSmbHeaderWrite(CMSmbHeader *header, CMBufferWriter *writer);

/* Get reader's current position offset relative to header start address */
NQ_UINT cmSmbHeaderGetReaderOffset(const CMSmbHeader *header, const CMBufferReader *reader);
/* Set reader's current position offset relative to header start address */
void cmSmbHeaderSetReaderOffset(const CMSmbHeader *header, CMBufferReader *reader, NQ_UINT16 offset);
/* Align reader relative to the header start address */
void cmSmbHeaderAlignReader(const CMSmbHeader *header, CMBufferReader *reader, NQ_UINT alignment);
/* Get writer's current position offset relative to header start address */
NQ_UINT cmSmbHeaderGetWriterOffset(const CMSmbHeader *header, const CMBufferWriter *writer);
/* Align writer relative to the header start address */
void cmSmbHeaderAlignWriter(const CMSmbHeader *header, CMBufferWriter *writer, NQ_UINT alignment);

#endif /* _CMSMB1_H_ */
