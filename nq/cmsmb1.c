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

#include "cmsmb1.h"
#include "cmfsutil.h"

const NQ_BYTE cmSmbProtocolId[4] = {0xFF, 0x53, 0x4D, 0x42};

static void smbHeaderInit(CMSmbHeader *header)
{
    syMemset(header, 0, sizeof(CMSmbHeader));
    header->size = SMB_HEADERSIZE;
}

void cmSmbHeaderInitForRequest(CMSmbHeader *header, const CMBufferWriter *writer, NQ_BYTE command)
{
    smbHeaderInit(header);

    header->_start = cmBufferWriterGetPosition(writer);
    header->command = command;
    header->pid = (NQ_UINT16)syGetPid();
}

void cmSmbHeaderInitForResponse(CMSmbHeader *header, const CMBufferWriter *writer)
{
    smbHeaderInit(header);

    cmSmbHeaderSetForResponse(header, writer);
}

void cmSmbHeaderSetForResponse(CMSmbHeader *header, const CMBufferWriter *writer)
{
    header->_start = cmBufferWriterGetPosition(writer);
    header->flags |= 0x80;
}

void cmSmbHeaderRead(CMSmbHeader *header, CMBufferReader *reader)
{
	NQ_UINT16 pidHigh;		/* temporary value */
	NQ_UINT16 pidLow;		/* temporary value */
	
    /* set header start address in this buffer */
    header->_start = cmBufferReaderGetPosition(reader);
    header->size = SMB_HEADERSIZE;

    cmBufferReaderSkip(reader, 4);                 /* protocol signature */
    cmBufferReadByte(reader, &header->command);
    cmBufferReadUint32(reader, &header->status);
    cmBufferReadByte(reader, &header->flags);
    cmBufferReadUint16(reader, &header->flags2);
    cmBufferReadUint16(reader, &pidHigh);	/* pid high */
    cmBufferReadBytes(reader, header->signature, sizeof(header->signature));
    cmBufferReaderSkip(reader, sizeof(NQ_UINT16));
    cmBufferReadUint16(reader, &header->tid);
    cmBufferReadUint16(reader, &pidLow);	/* pid low */
    header->pid = (NQ_UINT32)((pidHigh << 16) + pidLow);
    cmBufferReadUint16(reader, &header->uid);
    cmBufferReadUint16(reader, &header->mid);
}

void cmSmbHeaderWrite(CMSmbHeader *header, CMBufferWriter *writer)
{
    /* header start address must be already set */
    cmBufferWriteBytes(writer,  cmSmbProtocolId, sizeof(cmSmbProtocolId));
    cmBufferWriteByte(writer, header->command);
    cmBufferWriteUint32(writer, header->status);
    cmBufferWriteByte(writer, header->flags);
    cmBufferWriteUint16(writer, header->flags2);
    cmBufferWriteUint16(writer, (NQ_UINT16)(header->pid >> 16));	/* pid high */
    cmBufferWriteBytes(writer, header->signature, sizeof(header->signature));
    cmBufferWriteUint16(writer, 0);					/* reserved */
    cmBufferWriteUint16(writer, header->tid);
    cmBufferWriteUint16(writer, header->pid & 0xFFFF); /* pid low */
    cmBufferWriteUint16(writer, header->uid);
    cmBufferWriteUint16(writer, header->mid);
}

void cmSmbHeaderSetReaderOffset(const CMSmbHeader *header, CMBufferReader *reader, NQ_UINT16 offset)
{
    cmBufferReaderSetPosition(reader, header->_start + offset);
}

NQ_UINT cmSmbHeaderGetReaderOffset(const CMSmbHeader *header, const CMBufferReader *reader)
{
    return (NQ_UINT)(cmBufferReaderGetPosition(reader) - header->_start);
}

void cmSmbHeaderAlignReader(const CMSmbHeader *header, CMBufferReader *reader, NQ_UINT alignment)
{
    cmBufferReaderAlign(reader, header->_start, alignment);
}

NQ_UINT cmSmbHeaderGetWriterOffset(const CMSmbHeader *header, const CMBufferWriter *writer)
{
    return (NQ_UINT)(cmBufferWriterGetPosition(writer) - header->_start);
}

void cmSmbHeaderAlignWriter(const CMSmbHeader *header, CMBufferWriter *writer, NQ_UINT alignment)
{
    cmBufferWriterAlign(writer, header->_start, alignment);
}


