/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : RPC main access point
 *--------------------------------------------------------------------
 * MODULE        : CS - CIFS Server
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 19-October-2004
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _CSDCERPC_H_
#define _CSDCERPC_H_

#include "cspipes.h"
#include "cmapi.h"
#include "csrpcdef.h"
#include "cstransa.h"
#include "csdataba.h"

/*
    RPC function prototype
    ----------------------
 */
typedef
NQ_UINT32                              /* 0 on success, DCE error code on failure */
(*CSRpcFunction)(
    CMRpcPacketDescriptor* in,         /* incoming packet descriptor */
    CMRpcPacketDescriptor* out         /* outgoing packet descriptor */
    );

/* initialize buffers */
NQ_STATUS               /* NQ_SUCCESS or NQ_FAIL */
csDcerpcInit(
    void
    );

/* release buffers */
void
csDcerpcStop(
    void
    );

/* prototype for preparing late response below RPC later */
typedef void
(*CSDcerpcLateResponseSave)(
    CSLateResponseContext* context
    );

/* prototype for preparing late response below RPC later */
typedef NQ_BOOL
(*CSDcerpcLateResponsePrepare)(
    CSLateResponseContext* context
    );

/* prototype for sending late response below RPC layer */
typedef NQ_BOOL
(*CSDcerpcLateResponseSend)(
    CSLateResponseContext* context,
    NQ_UINT32 status,
    NQ_COUNT dataLength
    );

/* delayed response infromation */
typedef struct
{
    CSLateResponseContext cifsContext;      /* CIFS level information for response */
    NQ_BOOL nbo;                            /* TRUE for Big Endian */
    NQ_UINT32 callId;                       /* call identifier */
    CSDcerpcLateResponsePrepare prepareLateResponse;    /* routine for preparing late response down RPC layer */
    CSDcerpcLateResponseSend sendLateResponse;          /* routine for sending late response down RPC layer */
}
CSDcerpcResponseContext;

/* save information for a delayed response */
void
csDcerpcSaveResponseContext(
    NQ_BOOL isRpc,                           /* TRUE when RPC is onvolved */ 
    const CMRpcPacketDescriptor* descr,      /* packet descriptor to use */
    CSDcerpcResponseContext* context         /* buffer for context */
    );

/* send a delayed response */
NQ_STATUS                                    /* NQ_SUCCESS or error code */
csDcerpcPrepareLateResponse(
    CSDcerpcResponseContext* context         /* saved context */
    );

/* send a delayed response */
NQ_BOOL                                      /* TRUE on success */
csDcerpcSendLateResponse(
    CSDcerpcResponseContext* context,        /* saved context */
    NQ_UINT32 status,                        /* status to report, zero for success */
    NQ_COUNT stubDataSize                    /* amount of the stub data */
    );

/* save a complete response packet by late response for subsequent read(s) */
void
csDcerpcSaveCompleteResponse(
    CSFile * pFile,                         /* contet file */
    const NQ_BYTE *pData,                   /* packet pointer */
    NQ_COUNT dataSize                       /* packet size */
    );

/* get pipe information */
NQ_STATUS                           /* NQ_SUCCESS or NQ_FAIL */
csDcerpcGetPipeInformation(
    const CSFile* pFile,            /* pipe desriptor */
    SYFileInformation *fileInfo     /* result buffer */
    );

/* set late response callbacks */
void
csDcerpcSetLateResponseCallbacks(
    CSDcerpcLateResponseSave    saveLateResponse,   /* routine for saving late response down RPC layer */
    CSDcerpcLateResponsePrepare prepareLateResponse,/* routine for preparing late response down RPC layer */
    CSDcerpcLateResponseSend    sendLateResponse    /* routine for sending late response down RPC layer */
);

/* write request into pipe */
NQ_UINT32                       /* 0 on success or error code on failure */
csDcerpcWrite(
    CSFile* file,               /* file descriptor for the pipe with opened pipe */
    const NQ_BYTE* data,        /* request data */
    NQ_UINT dataLen,            /* data length */
    NQ_BOOL transact            /* TRUE when called internally by Transact */
    );

/* read response from pipe */
NQ_UINT32                           /* number of bytes read */
csDcerpcRead(                       /* number of bytes read */
    CSFile* file,                   /* file descriptor for the pipe with opened pipe */
    NQ_BYTE* readBuffer,            /* buffer for response */
    NQ_UINT readCount,              /* buffer size */
    NQ_UINT32 * remaining           /* pointer to the number of bytes remaining in the pipe */
    );

/*  performing a new or pending DCE RPC request  */
NQ_UINT32                           /* returns error code o 0 on success */
csDcerpcTransact(
    CSFile* file,                       /* file descriptor for the pipe with opened pipe */
    CSTransactionDescriptor* descriptor,/* transaction descriptor */
    NQ_UINT space                       /* number of bytes to fit in the response buffer */
    );

/* core CIFS (NTCreateAndX) calls this point to open a pipe */
NQ_BOOL                             /* pipe identifier or RP_INVALIDPIPE */
csDcerpcOpenPipe(
    const NQ_TCHAR* pipeName,       /* pipe name */
    CSFile* file                    /* file descriptor */
    );

/* core CIFS calls this point to close a pipe */
NQ_UINT32                           /* returns error code o 0 on success */
csDcerpcClosePipe(
    CSFile* file                    /* file descriptor to be filled on exit */
    );

#endif /* _CSDCERPC_H_ */
