/*********************************************************************
 *
 *           Copyright (c) 2008 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : SMB2 definitions
 *--------------------------------------------------------------------
 * MODULE        : CM
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 03-Dec-2008
 ********************************************************************/

#include "cmsmb2.h"
#include "cmfsutil.h"
#include "cmcrypt.h"
#if defined(UD_NQ_INCLUDECIFSSERVER) || defined (UD_CS_INCLUDERPC)
#include "csparams.h"
#endif


#ifdef UD_NQ_INCLUDESMB2

/* SMB2 identification bytes {0xFE, 'S', 'M', 'B'} */
const NQ_BYTE cmSmb2ProtocolId[4] = {0xFE, 0x53, 0x4D, 0x42};
const NQ_BYTE cmSmb2TrnsfrmHdrProtocolId[4] = {0xFD, 0x53, 0x4D, 0x42};

static void smb2HeaderInit(CMSmb2Header *header)
{
    syMemset(header, 0, sizeof(CMSmb2Header));
    header->size = SMB2_HEADERSIZE;
}

void cmSmb2HeaderInitForRequest(CMSmb2Header *header, const CMBufferWriter *writer, NQ_UINT16 command)
{
    smb2HeaderInit(header);

    header->_start = cmBufferWriterGetPosition(writer);
    header->creditCharge = 0;
    header->command = command;
    header->credits = 1;
    header->pid = (NQ_UINT32)syGetPid();
}

void cmSmb2HeaderInitForResponse(CMSmb2Header *header, const CMBufferWriter *writer, NQ_UINT16 credits)
{
    smb2HeaderInit(header);

    cmSmb2HeaderSetForResponse(header, writer, credits);
}

void cmSmb2HeaderSetForResponse(CMSmb2Header *header, const CMBufferWriter *writer, NQ_UINT16 credits)
{
    header->_start = cmBufferWriterGetPosition(writer);
    header->credits = (NQ_UINT16)(credits <= UD_CS_SMB2_NUMCREDITS ? credits : UD_CS_SMB2_NUMCREDITS);
    header->flags |= SMB2_FLAG_SERVER_TO_REDIR;
}

void cmSmb2HeaderRead(CMSmb2Header *header, CMBufferReader *reader)
{
    /* set header start address in this buffer */
    header->_start = cmBufferReaderGetPosition(reader);

    cmBufferReaderSkip(reader, 4);                 /* protocol signature */
    cmBufferReadUint16(reader, &header->size);
    cmBufferReadUint16(reader, &header->creditCharge);
    cmBufferReadUint32(reader, &header->status);
    cmBufferReadUint16(reader, &header->command);
    cmBufferReadUint16(reader, &header->credits);
    cmBufferReadUint32(reader, &header->flags);
    cmBufferReadUint32(reader, &header->next);
    cmBufferReadUint64(reader, &header->mid);

    if (header->flags & SMB2_FLAG_ASYNC_COMMAND)
    {
        cmBufferReadUint64(reader, &header->aid);
        header->pid = 0;
        header->tid = 0;
    }
    else
    {
        cmU64Zero(&header->aid);
        cmBufferReadUint32(reader, &header->pid);
        cmBufferReadUint32(reader, &header->tid);
    }
        
    cmBufferReadUint64(reader, &header->sid);
    cmBufferReadBytes(reader, header->signature, sizeof(header->signature));
}

NQ_BOOL cmSmb2HeaderShiftNext(CMSmb2Header *header, CMBufferReader *reader)
{
    NQ_BOOL result = FALSE;
    if (header->next == 0 || ((header->_start + header->next + 64) - (reader->origin + reader->length)) > 0)
    {
        /* no more commands */
        goto Exit;
    }
    cmBufferReaderSetPosition(reader, header->_start + header->next);
    result = TRUE;

Exit:
    return result;
}

void cmSmb2TransformHeaderRead(CMSmb2TransformHeader *header, CMBufferReader *reader)
{
	/* set header start address in this buffer */
	header->_start = cmBufferReaderGetPosition(reader);

	cmBufferReaderSkip(reader, 4);                 /* protocol signature */
	cmBufferReadBytes(reader , header->signature , sizeof(header->signature));
	cmBufferReadBytes(reader , header->nonce , sizeof(header->nonce));
	cmBufferReadUint32(reader , &header->originalMsgSize);
	cmBufferReaderSkip(reader, 2);
	cmBufferReadUint16(reader , &header->encryptionArgorithm);
	cmBufferReadUint64(reader, &header->sid);
}

void cmSmb2HeaderWrite(CMSmb2Header *header, CMBufferWriter *writer)
{
    /* header start address must be already set */
    cmBufferWriteBytes(writer,  cmSmb2ProtocolId, sizeof(cmSmb2ProtocolId));
    cmBufferWriteUint16(writer, SMB2_HEADERSIZE);
    cmBufferWriteUint16(writer, header->creditCharge);
    cmBufferWriteUint32(writer, header->status);
    cmBufferWriteUint16(writer, header->command);
    cmBufferWriteUint16(writer, header->credits);
    cmBufferWriteUint32(writer, header->flags);
    cmBufferWriteUint32(writer, header->next);
    cmBufferWriteUint64(writer, &header->mid);

    if (header->flags & SMB2_FLAG_ASYNC_COMMAND)
    {
        cmBufferWriteUint64(writer, &header->aid);
    }
    else
    {
        cmBufferWriteUint32(writer, header->pid);
        cmBufferWriteUint32(writer, header->tid);
    }

    cmBufferWriteUint64(writer, &header->sid);
    cmBufferWriteBytes(writer, header->signature, sizeof(header->signature));
}

void cmSmb2TransformHeaderWrite(CMSmb2TransformHeader *header, CMBufferWriter *writer)
{
    /* header start address must be already set */
    cmBufferWriteBytes(writer,  cmSmb2TrnsfrmHdrProtocolId, sizeof(cmSmb2TrnsfrmHdrProtocolId));
    /* we don't copy signature, it will be calculated later.*/
    cmBufferWriterSkip(writer , sizeof(header->signature));
    cmBufferWriteBytes(writer , header->nonce , sizeof(header->nonce));
    cmBufferWriteUint32(writer, header->originalMsgSize);
    cmBufferWriteZeroes(writer , 2);
    cmBufferWriteUint16(writer, header->encryptionArgorithm);
    cmBufferWriteUint64(writer, &header->sid);
}

void cmSmb2HeaderSetReaderOffset(const CMSmb2Header *header, CMBufferReader *reader, NQ_UINT16 offset)
{
    cmBufferReaderSetPosition(reader, header->_start + offset);
}

NQ_UINT cmSmb2HeaderGetReaderOffset(const CMSmb2Header *header, const CMBufferReader *reader)
{
    return (NQ_UINT)(cmBufferReaderGetPosition(reader) - header->_start);
}

void cmSmb2HeaderAlignReader(const CMSmb2Header *header, CMBufferReader *reader, NQ_UINT alignment)
{
    cmBufferReaderAlign(reader, header->_start, alignment);
}

NQ_UINT cmSmb2HeaderGetWriterOffset(const CMSmb2Header *header, const CMBufferWriter *writer)
{
    return (NQ_UINT)(cmBufferWriterGetPosition(writer) - header->_start);
}

void cmSmb2HeaderAlignWriter(const CMSmb2Header *header, CMBufferWriter *writer, NQ_UINT alignment)
{
    cmBufferWriterAlign(writer, header->_start, alignment);
}

void cmZeroUuid(CMUuid *uuid)
{
    syMemset(uuid, 0, sizeof(*uuid));
}

void cmGenerateUuid(CMUuid *uuid)
{
    cmCreateRandomByteSequence((NQ_BYTE *)uuid, sizeof(*uuid));
}

void cmUuidRead(CMBufferReader *reader, CMUuid *uuid)
{
    cmBufferReadUint32(reader, (NQ_UINT32 *)&uuid->timeLow);
    cmBufferReadUint16(reader, (NQ_UINT16 *)&uuid->timeMid);
    cmBufferReadUint16(reader, (NQ_UINT16 *)&uuid->timeHiVersion);
    cmBufferReadBytes(reader, uuid->clockSeq, sizeof(uuid->clockSeq));
    cmBufferReadBytes(reader, uuid->node, sizeof(uuid->node));
}


void cmUuidWrite(CMBufferWriter *writer, const CMUuid *uuid)
{
    cmBufferWriteUint32(writer, (NQ_UINT32)uuid->timeLow);
    cmBufferWriteUint16(writer, (NQ_UINT16)uuid->timeMid);
    cmBufferWriteUint16(writer, (NQ_UINT16)uuid->timeHiVersion);
    cmBufferWriteBytes(writer, uuid->clockSeq, sizeof(uuid->clockSeq));
    cmBufferWriteBytes(writer, uuid->node, sizeof(uuid->node));
}

void cmGetCurrentTime(CMTime *t)
{
    /* the parameter can not be called "time" as it would conflict with syGetTime macro */
    cmCifsTimeToUTC(syGetTimeInMsec(), &t->low, &t->high);
}

void cmTimeRead(CMBufferWriter *reader, CMTime *time)
{
    cmBufferReadUint32(reader, &time->low);
    cmBufferReadUint32(reader, &time->high);
}

void cmTimeWrite(CMBufferWriter *writer, const CMTime *time)
{
    cmBufferWriteUint32(writer, time->low);
    cmBufferWriteUint32(writer, time->high);
}

#endif

