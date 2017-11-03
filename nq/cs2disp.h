/*********************************************************************
 *
 *           Copyright (c) 2008 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : SMB2 command dispatcher
 *--------------------------------------------------------------------
 * MODULE        : CS
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 02-Dec-2008
 ********************************************************************/

#ifndef _CS2DISP_H
#define _CS2DISP_H

#include "nsapi.h"
#include "cmsmb2.h"
#include "csdataba.h"

/** Initialize SMB2 dispatcher */
NQ_BOOL cs2DispatchInit(void);

/** Shutdown SMB2 dispatcher module */
void cs2DispatchExit(void);

/**
 * Dispatcher entry point
 * The buffer must contain ONE well formed SMB2 packet
 */
NQ_BOOL                     /* TRUE on success, FALSE on error */ 
csSmb2DispatchRequest(
    NSRecvDescr * recvDescr,		/* connection socket */
    NQ_BYTE *request,       		/* pointer to the beginning of the request packet */
    NQ_COUNT length         		/* packet length without four bytes of signature */
    );

/**
 * SMB1 negotiate request handler 
 * Called by SMB1 negotiate handler when client supports SMB2 dialect 
 * This is a transition from SMB1 to SMB2
 */
NQ_UINT32                       /* response length */
csSmb2OnSmb1Negotiate(
    NQ_BYTE **response,          /* double pointer to the response buffer */
    NQ_BOOL anySmb2				 /* TRUE when dialect SMB2.??? FALSE otherwise*/
    );

/**
 * Prototypes for command processing functions
 *---------------------------------------
 *
 * The following typedef designates command processing function
 */
typedef
NQ_UINT32                           /* returns error code or zero on success */
    (*CS2CommandFunction)(        
    CMSmb2Header * in,              /* pointer to the parsed request SMB2 header descriptor */
    CMSmb2Header * out,             /* pointer to the response SMB2 header descriptor */
    CMBufferReader * reader,        /* pointer to a preset reader pointing to the second field of the 
                                                               command */
    CSSession *connection,          /* pointer to the connection context */
    CSUser *session,                /* pointer to the session context */
    CSTree *tree,                   /* pointer to the share context */
    CMBufferWriter *writer          /* pointer to the preset writer pointing to the first response field */
    );  

/* Get current command header */

CMSmb2Header *						/* header of the currently processed command */
cs2DispatchGetCurrentHeader(
	void
	);
/**
 * Send interim response 
 */
NQ_UINT32                       /* generated Async ID */
csSmb2SendInterimResponse(
    CMSmb2Header * in               /* pointer to the incoming request header */
    );

/* save information for a delayed response */
void
cs2DispatchSaveResponseContext(
    CSLateResponseContext* contextBuffer,   /* buffer for context */
    const CMSmb2Header * header             /* interim response header */
    );

/* compose header and calculate command data pointer and size */
NQ_STATUS                             /* NQ_SUCCESS or error code */
cs2DispatchPrepareLateResponse(
    CSLateResponseContext* context,   /* saved context */
    NQ_UINT32 status                  /* status to return */
    );

/* send a response using saved context */
NQ_STATUS                             /* NQ_SUCCESS or error code */
cs2DispatchSendLateResponse(
    CSLateResponseContext* context,   /* saved context */
    NQ_COUNT dataLength               /* actual command data length */
    );

/* generate next AsyncId */
void cs2GenerateNextAsyncId(
    NQ_UINT64 * id                  /* OUT buffer for next async ID */
    );

/* parse FID - save it or get a saved one previously */
void cs2ParseFid(
    CSFid* fid                      /* IN/OUT fid */
    );

NQ_UINT32 csSmb2OnNegotiate(CMSmb2Header *in, CMSmb2Header *out, CMBufferReader *reader, CSSession *connection, CSUser *session, CSTree *tree, CMBufferWriter *writer);
NQ_UINT32 csSmb2OnSessionSetup(CMSmb2Header *in, CMSmb2Header *out, CMBufferReader *reader, CSSession *connection, CSUser *session, CSTree *tree, CMBufferWriter *writer);
NQ_UINT32 csSmb2OnLogoff(CMSmb2Header *in, CMSmb2Header *out, CMBufferReader *reader, CSSession *connection, CSUser *session, CSTree *tree, CMBufferWriter *writer);
NQ_UINT32 csSmb2OnTreeDisconnect(CMSmb2Header *in, CMSmb2Header *out, CMBufferReader *reader, CSSession *connection, CSUser *session, CSTree *tree, CMBufferWriter *writer);
NQ_UINT32 csSmb2OnTreeConnect(CMSmb2Header *in, CMSmb2Header *out, CMBufferReader *reader, CSSession *connection, CSUser *session, CSTree *tree, CMBufferWriter *writer);
NQ_UINT32 csSmb2OnTreeDisconnect(CMSmb2Header *in, CMSmb2Header *out, CMBufferReader *reader, CSSession *connection, CSUser *session, CSTree *tree, CMBufferWriter *writer);
NQ_UINT32 csSmb2OnCreate(CMSmb2Header *in, CMSmb2Header *out, CMBufferReader *reader, CSSession *connection, CSUser *session, CSTree *tree, CMBufferWriter *writer);
NQ_UINT32 csSmb2OnClose(CMSmb2Header *in, CMSmb2Header *out, CMBufferReader *reader, CSSession *connection, CSUser *session, CSTree *tree, CMBufferWriter *writer);
NQ_UINT32 csSmb2OnFlush(CMSmb2Header *in, CMSmb2Header *out, CMBufferReader *reader, CSSession *connection, CSUser *session, CSTree *tree, CMBufferWriter *writer);
NQ_UINT32 csSmb2OnRead(CMSmb2Header *in, CMSmb2Header *out, CMBufferReader *reader, CSSession *connection, CSUser *session, CSTree *tree, CMBufferWriter *writer);
NQ_UINT32 csSmb2OnWrite(CMSmb2Header *in, CMSmb2Header *out, CMBufferReader *reader, CSSession *connection, CSUser *session, CSTree *tree, CMBufferWriter *writer);
NQ_UINT32 csSmb2OnLock(CMSmb2Header *in, CMSmb2Header *out, CMBufferReader *reader, CSSession *connection, CSUser *session, CSTree *tree, CMBufferWriter *writer);
NQ_UINT32 csSmb2OnIoctl(CMSmb2Header *in, CMSmb2Header *out, CMBufferReader *reader, CSSession *connection, CSUser *session, CSTree *tree, CMBufferWriter *writer);
NQ_UINT32 csSmb2OnCancel(CMSmb2Header *in, CMSmb2Header *out, CMBufferReader *reader, CSSession *connection, CSUser *session, CSTree *tree, CMBufferWriter *writer);
NQ_UINT32 csSmb2OnEcho(CMSmb2Header *in, CMSmb2Header *out, CMBufferReader *reader, CSSession *connection, CSUser *session, CSTree *tree, CMBufferWriter *writer);
NQ_UINT32 csSmb2OnQueryDirectory(CMSmb2Header *in, CMSmb2Header *out, CMBufferReader *reader, CSSession *connection, CSUser *session, CSTree *tree, CMBufferWriter *writer);
NQ_UINT32 csSmb2OnChangeNotify(CMSmb2Header *in, CMSmb2Header *out, CMBufferReader *reader, CSSession *connection, CSUser *session, CSTree *tree, CMBufferWriter *writer);
NQ_UINT32 csSmb2OnQueryInfo(CMSmb2Header *in, CMSmb2Header *out, CMBufferReader *reader, CSSession *connection, CSUser *session, CSTree *tree, CMBufferWriter *writer);
NQ_UINT32 csSmb2OnSetInfo(CMSmb2Header *in, CMSmb2Header *out, CMBufferReader *reader, CSSession *connection, CSUser *session, CSTree *tree, CMBufferWriter *writer);
NQ_UINT32 csSmb2OnOplockBreak(CMSmb2Header *in, CMSmb2Header *out, CMBufferReader *reader, CSSession *connection, CSUser *session, CSTree *tree, CMBufferWriter *writer);
NQ_BOOL cs2TransformHeaderEncrypt(	CSUser	*	user,
									NQ_BYTE * response,
									NQ_COUNT length);
NQ_BOOL cs2TransformHeaderDecrypt(	NSRecvDescr * recvDescr,
									NQ_BYTE * request,
									NQ_COUNT length);

#endif

