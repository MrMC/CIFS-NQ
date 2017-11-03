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
/*
 * ccSmb2Common.h
 *
 *  Created on: Oct 26, 2016
 *      Author: iland
 */

#ifndef NQE2_NQ_CCSMB2COMMON_H_
#define NQE2_NQ_CCSMB2COMMON_H_

/* -- Structures -- */

#define HEADERANDSTRUCT_SIZE (SMB2_HEADERSIZE + sizeof(NQ_UINT16))
#define SEQNUMBEROFFSET 24 + 4

#define SMB2SESSIONFLAG_IS_GUEST        0x0001
#define SMB2SESSIONFLAG_IS_ANON         0x0002
#define SMB2SESSIONFLAG_ENCRYPT_DATA    0x0004

/* SMB 3 common */
#define MAXINFORESPONSE_SIZE 4096
#define REQUESTDURABLEFID_SIGNATURE "DHnQ"
#define RESTOREDURABLEFID_SIGNATURE "DHnC"

#define SMB2DHANDLE_FLAG_NOTPERSISTENT 0x00000000 /* durable handle is not persistent */
#define SMB2DHANDLE_FLAG_PERSISTENT    0x00000002 /* durable handle is persistent     */
/* end SMB 3 */

typedef struct
{
	NQ_BYTE * buffer;		/* buffer pointer */
	CMBufferWriter writer;	/* writer to use */
	CMSmb2Header header;	/* header to use */
	CMBlob tail;			/* variable data (tail) */
	NQ_UINT16 command;		/* command code */
    NQ_UINT64 userId;       /* user id */
    NQ_BOOL	encrypt;        /* whether to encrypt */
}
Request;	/* SMB request descriptor */

typedef struct
{
	NQ_BYTE * buffer;		/* buffer pointer */
	CMBufferReader reader;	/* reader to use */
	CMSmb2Header header;	/* parsed header */
    NQ_COUNT tailLen;       /* payload length */
    NQ_BOOL wasReceived;
}
Response;	/* SMB response descriptor */

typedef struct
{
	CMItem item;
	Response* notifyResponse;
	NQ_BYTE fid[16];			/* File ID. */
}waitingResponse;

#define MATCHINFO_NONE  0x0000;
#define MATCHINFO_WRITE 0x0001;
#define MATCHINFO_READ  0x0002;

typedef struct
{
	CMItem item;			/* inherits from item */
	Response * response;	/* pointer to response structure */
	CCServer * server;		/* server pointer */
	NQ_UINT64 mid;			/* to match request and response */
	CMThreadCond * cond;	/* condition to raise */
	NQ_BYTE hdrBuf[HEADERANDSTRUCT_SIZE];	/* header + structure size for signing check */
	NQ_UINT64 userId;
	NQ_BOOL	isResponseAllocated;
    CMThread * thread;                      /* pointer to thread */
    NQ_UINT32	matchExtraInfo;				/* bitmap with extra match info according to defines above MATCHINFO_XXX */
}
Match;	/* Context between SMB and Transport with one instance per
		   an outstanding request. Used to match request (expected response)
		   with response. Is used as is for sync operations while async operations
		   inherit from it. */

typedef struct
{
	Match match;					/* inherits from Match */
	void *context;					/* context for this callback (MUST be second)*/
	void *hook;						/* hook to find this context when removed the an external function */
    NQ_UINT32 timeCreated;          /* time request is created*/
    NQ_UINT32 setTimeout;           /* timeout that was set when the request was created*/
	CCCifsWriteCallback callback; 	/* callback function to use */
}
WriteMatch;	/* Context between SMB and Transport for Write. Used to match request (expected response)
		   with response */

typedef struct
{
	Match match;					/* inherits from Match */
	void *context;					/* context for this callback (MUST be second)*/
	void *hook;						/* hook to find this context when removed the an external function */
    NQ_UINT32 timeCreated;          /* time request is created*/
    NQ_UINT32 setTimeout;           /* timeout that was set when the request was created*/
	CCCifsReadCallback callback; 	/* callback function to use */
	NQ_BYTE * buffer;				/* buffer to read in */
	NQ_UINT32 count;				/* number of bytes to read */
}
ReadMatch;	/* Context between SMB and Transport for Read. Used to match request (expected response)
		   with response */

typedef struct
{
	NQ_UINT64 mid;		        /* sequence number of the last sent command */
	Match match;		        /* sync to receive callback */
}
Context;	/* SMB context */

typedef struct
{
	NQ_UINT16 requestBufferSize;	/* required buffer size for request */
	NQ_UINT16 requestStructSize;	/* structure size for request */
	NQ_UINT16 responseStructSize;	/* expected structure size in response */
	void (* callback)(CCServer * pServer, Match * pContext);	       /* on response callback - may be NULL */
	void (* notificationHandle)(CCServer *, Response *, CCFile *);     /* handle for a command initiated by server */
} Command;		/* SMB command descriptor */

typedef struct
{
	NQ_BYTE fid[16];	/* context file ID */
}
SearchContext;	/* SMB2 search context */

#endif /* NQE2_NQ_CCSMB2COMMON_H_ */
