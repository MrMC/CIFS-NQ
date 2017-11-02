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

#ifdef UD_NQ_INCLUDESMB2

/* SMB2 identification bytes {0xFE, 'S', 'M', 'B'} */
const NQ_BYTE cmSmb2ProtocolId[4] = {0xFE, 0x53, 0x4D, 0x42};

static void smb2HeaderInit(CMSmb2Header *header)
{
    syMemset(header, 0, sizeof(CMSmb2Header));
    header->size = SMB2_HEADERSIZE;
}

void cmSmb2HeaderInitForRequest(CMSmb2Header *header, const CMBufferWriter *writer, NQ_UINT16 command)
{
    smb2HeaderInit(header);

    header->_start = cmBufferWriterGetPosition(writer);
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
    header->credits = (NQ_UINT16)(credits <= SMB2_NUMCREDITS? credits : SMB2_NUMCREDITS);
    header->flags |= SMB2_FLAG_SERVER_TO_REDIR;
}

void cmSmb2HeaderRead(CMSmb2Header *header, CMBufferReader *reader)
{
    /* set header start address in this buffer */
    header->_start = cmBufferReaderGetPosition(reader);

    cmBufferReaderSkip(reader, 4);                 /* protocol signature */
    cmBufferReadUint16(reader, &header->size);
    cmBufferReadUint16(reader, &header->epoch);
    cmBufferReadUint32(reader, &header->status);
    cmBufferReadUint16(reader, &header->command);
    cmBufferReadUint16(reader, &header->credits);
    cmBufferReadUint32(reader, &header->flags);
    cmBufferReadUint32(reader, &header->next);
    cmBufferReadUint64(reader, &header->mid);

    if (header->flags & SMB2_FLAG_ASYNC_COMMAND)
    {
        cmBufferReadUint64(reader, &header->aid);
    }
    else
    {
        cmBufferReadUint32(reader, &header->pid);
        cmBufferReadUint32(reader, &header->tid);
    }
        
    cmBufferReadUint64(reader, &header->sid);
    cmBufferReadBytes(reader, header->signature, sizeof(header->signature));
}

NQ_BOOL cmSmb2HeaderShiftNext(CMSmb2Header *header, CMBufferReader *reader)
{
    if (header->next == 0 || ((header->_start + header->next + 64) - (reader->origin + reader->length)) > 0)
    { 
        return FALSE;       /* no more commands */
    }
    cmBufferReaderSetPosition(reader, header->_start + header->next);
    return TRUE;
} 

void cmSmb2HeaderWrite(CMSmb2Header *header, CMBufferWriter *writer)
{
    /* header start address must be already set */
    cmBufferWriteBytes(writer,  cmSmb2ProtocolId, sizeof(cmSmb2ProtocolId));
    cmBufferWriteUint16(writer, SMB2_HEADERSIZE);
    cmBufferWriteUint16(writer, header->epoch);
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

void cmGenerateUuid(CMUuid *uuid)
{
    /* todo: generate proper UUID */
    /* currently we're only cleaning it up */
    syMemset(uuid, 0, sizeof(CMUuid));
}

void cmUuidRead(CMBufferReader *reader, CMUuid *uuid)
{
    cmBufferReadUint32(reader, &uuid->d4);
    cmBufferReadUint16(reader, &uuid->d2[0]);
    cmBufferReadUint16(reader, &uuid->d2[1]);
    cmBufferReadBytes(reader, uuid->d8, sizeof(uuid->d8));
}

void cmUuidWrite(CMBufferWriter *writer, const CMUuid *uuid)
{
    cmBufferWriteUint32(writer, uuid->d4);
    cmBufferWriteUint16(writer, uuid->d2[0]);
    cmBufferWriteUint16(writer, uuid->d2[1]);
    cmBufferWriteBytes(writer, uuid->d8, sizeof(uuid->d8));
}

void cmGetCurrentTime(CMTime *t)
{
    /* the parameter can not be called "time" as it would conflict with syGetTime macro */
    cmCifsTimeToUTC((NQ_TIME)syGetTime(), &t->low, &t->high);
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

