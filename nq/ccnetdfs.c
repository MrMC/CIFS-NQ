/*********************************************************************
 *
 *           Copyright (c) 2010 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : CIFS Client NETDFS pipe related operations
 *--------------------------------------------------------------------
 * MODULE        : CC
 * DEPENDENCIES  : None
 *--------------------------------------------------------------------
 * CREATION DATE : 29-Apr-2010
 ********************************************************************/

 #include "ccnetdfs.h"
 #include "ccdcerpc.h"
 #include "cmbuf.h"
 #include "ccapi.h"
 #include "nqapi.h"

 #if defined(UD_NQ_INCLUDECIFSCLIENT) && defined(UD_CC_INCLUDEDFS)
/*
 * Static data, functions and defintions
 * -------------------------------------
 */

#define NETDFS_GETINFO_OPNUM  4

/* parameters for callbacks */
typedef struct
{
    NQ_UINT32 status;       /* RPC operation status */
}
CallbackParams;


typedef struct {
    const NQ_WCHAR * path;
    NQ_UINT16 level;
    NQ_UINT32 *state;
    NQ_UINT32 *flags;
    NQ_UINT32 status;
}
ParamsNetdfsGetInfo;


/* pipe descriptor */
static const NQ_WCHAR pipeName[] = { cmWChar('n'), cmWChar('e'), cmWChar('t'), cmWChar('d'), cmWChar('f'), cmWChar('s'), cmWChar(0) };
static const CCDcerpcPipeDescriptor pipeDescriptor =
{ pipeName,
  {cmPack32(0x4fc742e0),cmPack16(0x4a10),cmPack16(0x11cf),{0x82,0x73},{0x00,0xaa,0x00,0x4a,0xe6,0x73}},
  cmRpcVersion(3, 0)
};


static
const CCDcerpcPipeDescriptor*
ccNetdfsGetPipe(
    void
    );

/* dfs_GetInfo request callback */

static NQ_COUNT          /* count of outgoing data */
dfsGetInfoRequestCallback (
    NQ_BYTE* buffer,    /* ougoing data buffer */
    NQ_COUNT size,      /* room in the buffer */
    void* params,       /* abstract parameters */
    NQ_BOOL* moreData   /* put here TRUE when more outgoing data available */
    );

/* dfs_GetInfo response callback */

static NQ_STATUS            /* NQ_SUCCESS or error code */
dfsGetInfoResponseCallback (
    const NQ_BYTE* data,    /* data portion pointer */
    NQ_COUNT size,          /* data portion size */
    void* params,           /* abstract parameters */
    NQ_BOOL moreData        /* TRUE when more data avaiable */
    );

static NQ_UINT32 ccNetdfsGetInfo(
    const NQ_HANDLE pipeHandle,
    const NQ_WCHAR* path,
    const NQ_UINT16 level,
    NQ_UINT32 *state,
    NQ_UINT32 *flags
    );

/*====================================================================
 * PURPOSE: Return this pipe descriptor
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: Pipe descriptor
 *
 * NOTES:
 *====================================================================
 */
static const CCDcerpcPipeDescriptor * ccNetdfsGetPipe(void)
{
    return &pipeDescriptor;
}


static NQ_UINT32 ccNetdfsGetInfo(
    const NQ_HANDLE pipeHandle,
    const NQ_WCHAR * path,
    const NQ_UINT16 level,
    NQ_UINT32 *state,
    NQ_UINT32 *flags
    )
{
    ParamsNetdfsGetInfo params; 

    TRCB();

    params.path = path;
    params.level = level;
    params.state = state;
    params.flags = flags;
    params.status = (NQ_UINT32)syGetLastError();
    
    if (!ccDcerpcCall(pipeHandle, dfsGetInfoRequestCallback, dfsGetInfoResponseCallback, &params))
    {
        TRCERR("Error in processing NetdfsGetInfo");
    }

    TRCE();
    return params.status;
}


static NQ_COUNT          /* count of outgoing data */
dfsGetInfoRequestCallback (
    NQ_BYTE* buffer,    /* ougoing data buffer */
    NQ_COUNT size,      /* room in the buffer */
    void* params,       /* abstract parameters */
    NQ_BOOL* moreData   /* put here TRUE when more outgoing data available */
    )
{
    CMBufferWriter w;
    ParamsNetdfsGetInfo *p = (ParamsNetdfsGetInfo *)params;
    NQ_UINT32 length, sz;
    
    TRCB();

    cmBufferWriterInit(&w, buffer, size);
    cmBufferWriteUint16(&w, NETDFS_GETINFO_OPNUM); /* opcode */

    /* dfs path */
    length = (NQ_UINT32)cmWStrlen(p->path);
    sz = length + 1;
    cmBufferWriteUint32(&w, sz);                   /* max count */
    cmBufferWriteUint32(&w, 0);                    /* offset */
    cmBufferWriteUint32(&w, sz);                   /* actual count */
    cmBufferWriteUnicode(&w, p->path);			   /* path */
    cmBufferWriterAlign(&w, buffer + 2, 4);        /* 4 byte alignment */
    cmBufferWriteUint32(&w, 0);                    /* null: servername */
    cmBufferWriteUint32(&w, 0);                    /* null: sharename */
    cmBufferWriteUint32(&w, p->level);             /* info level */

    *moreData = FALSE;

    TRCE();
    return cmBufferWriterGetDataCount(&w);
}

/* dfs_GetInfo response callback */

static NQ_STATUS            /* NQ_SUCCESS or error code */
dfsGetInfoResponseCallback (
    const NQ_BYTE* data,    /* data portion pointer */
    NQ_COUNT size,          /* data portion size */
    void* params,           /* abstract parameters */
    NQ_BOOL moreData        /* TRUE when more data avaiable */
    )
{
    CMBufferReader r;
    ParamsNetdfsGetInfo *p = (ParamsNetdfsGetInfo *)params;
    NQ_UINT32 level, refId;

    TRCB();

    if (size < 48)
    {
        p->status = (NQ_UINT32)NQ_FAIL;
        TRCERR("Invalid server response size");
        TRCE();
        return (NQ_STATUS)p->status;
    }    

    cmBufferReaderInit(&r, data, size);
    cmBufferReadUint32(&r, &level);

    switch (level)
    {
        case 6:
            cmBufferReadUint32(&r, &refId);         /* ref id - struct */
            if (refId != 0)
            {           
                cmBufferReaderSkip(&r, 4);          /* ref id - entry path */
                cmBufferReaderSkip(&r, 4);          /* ref id - comment */
                cmBufferReadUint32(&r, p->state);   /* state */
                cmBufferReaderSkip(&r, 4);          /* timeout */
                cmBufferReaderSkip(&r, 16);         /* guid */
                cmBufferReadUint32(&r, p->flags);   /* flags */
                TRC("state: 0x%x, flags: 0x%x", *p->state, *p->flags);
            }
            /* read status */
            cmBufferReaderSetPosition(&r, cmBufferReaderGetStart(&r) + size - 4);
            cmBufferReadUint32(&r, &p->status);
            TRC("status 0x%x", p->status);
            break;
        default:
            p->status = (NQ_UINT32)NQ_FAIL;
            TRCERR("Invalid level");
    }

    TRCE();
    return (NQ_STATUS)p->status;
}

NQ_UINT32
ccNetDfsGetStatus(
    const NQ_WCHAR *server,
    const NQ_WCHAR *dfsPath,
    NQ_UINT32 *state,
    NQ_UINT32 *flags
    )
{
    NQ_HANDLE netdfs;
    NQ_UINT32 status;

    TRCB();
    
    TRC("server: %s, path: %s", cmTDump(server), cmTDump(dfsPath));
    if ((netdfs = ccDcerpcConnect(server, NULL, ccNetdfsGetPipe(), FALSE)) != NULL)
    {
        status = ccNetdfsGetInfo(netdfs, dfsPath, 6, state, flags);
        ccDcerpcDisconnect(netdfs);
        TRCE();
        return status;
    }
    
    TRCE();       
    return (NQ_UINT32)NQ_FAIL;
}

#endif 

