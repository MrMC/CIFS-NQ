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

#include "ccapi.h"
#include "ccsmb10.h"
#include "ccsmb20.h"
#include "cctransport.h"
#include "ccserver.h"
#include "ccuser.h"
#include "ccshare.h"
#include "ccfile.h"
#include "ccutils.h"
#include "ccerrors.h"
#include "ccconfig.h"
#include "ccsearch.h"
#include "ccinfo.h"
#include "cmthread.h"
#include "cmfsutil.h"
#include "cmsmb1.h"
#include "cmbufman.h"
#include "cmcrypt.h"
#include "cmsdescr.h"

#ifdef UD_NQ_INCLUDECIFSCLIENT

/* -- macros -- */

/* access 16 byte FID as a 2-byte value */
#define FID(f)  ((NQ_UINT16 *)f->fid)
#define PIDOFFSET 26 + 4    /* mid offset in the header */

/* find message sequene number */
#define MSG_NUMBER(_p) ((_p.pid * 0x10000) + _p.mid)

/* -- Structures -- */

#define MAXINFORESPONSE_SIZE 4096	 

typedef struct 
{
	NQ_BYTE * buffer;		/* buffer pointer */
	CMBufferWriter writer;	/* writer to use */
	CMSmbHeader header;	/* header to use */
	CMBlob tail;			/* variable data (tail) */ 
	NQ_UINT16 command;		/* command code */
	NQ_BYTE * pByteCount;	/* pointer to the byte count field */
	NQ_BYTE * pWordCount;	/* pointer to the word count field */
	NQ_BYTE * pTrans;	    /* pointer to the start of T2/NT words */
	NQ_BYTE * pParams;	    /* pointer to the start of T2/NT parameters */
	NQ_BYTE * pData;	    /* pointer to the start of T2/NT data */
} 
Request;	/* SMB request descriptor */

typedef struct 
{
	NQ_BYTE * buffer;		/* buffer pointer */
	CMBufferReader reader;	/* reader to use */
	CMSmbHeader header;	    /* parsed header */
	NQ_BYTE * pParams;	    /* pointer to the start of T2/NT parameters */
	NQ_BYTE * pData;	    /* pointer to the start of T2/NT data */
    NQ_UINT32 dataCount;    /* number of T2/NT data bytes */
    NQ_COUNT tailLen;       /* payload length */
} 
Response;	/* SMB response descriptor */

typedef struct 
{
	CMItem item;			/* inherits from item */
	Response * response;	/* pointer to response structure */
	CCServer * server;		/* server pointer */
	NQ_UINT16 mid;			/* to match request and response */
	NQ_UINT32 pid;			/* to match request and response */
	CMThreadCond * cond;	/* condition to raise */
	NQ_BYTE hdrBuf[SMB_HEADERSIZE];		/* header + struct size for signing check */
}
Match;	/* Context between SMB and Transport with one instance per 
		   an outstanding request. Used to match request (expected response) 
		   with response. Is used as is for sync operations while async operations
		   inherit from it. */

typedef struct 
{
	Match match;					/* inherits from Match */
    NQ_TIME timeCreated;            /* time request is created*/
    NQ_TIME setTimeout;             /* timeout that was set when the request was created*/
	CCCifsWriteCallback callback; 	/* callback function to use */
	void * context;					/* context for this callback */
}
WriteMatch;	/* Context between SMB and Transport for Write. Used to match request (expected response) 
		   with response */

typedef struct 
{
	Match match;					/* inherits from Match */
    NQ_TIME timeCreated;            /* time request is created*/
    NQ_TIME setTimeout;             /* timeout that was set when the request was created*/
	CCCifsReadCallback callback; 	/* callback function to use */
	void * context;					/* context for this callback */
	NQ_BYTE * buffer;				/* buffer to read in */
	NQ_UINT32 count;				/* number of bytes to read */
}
ReadMatch;	/* Context between SMB and Transport for Read. Used to match request (expected response) 
		   with response */

typedef struct 
{
	NQ_UINT16 mid;		        /* sequence number of the last sent command */
	NQ_UINT32 pid;		        /* to match request and response */
} 
Context;	/* SMB context */

typedef struct 
{
	NQ_UINT16 requestBufferSize;	/* required buffer size for request */
	NQ_BYTE requestWordCount;		/* word count for request: 0xFF means no definition */
	NQ_BYTE responseWordCount;	    /* expected word count in response */
	void (* callback)(CCServer * pServer, Match * pContext);	/* on response callback - may be NULL */
} Command;		/* SMB command descriptor */

typedef struct
{
	NQ_BOOL findFirst;	        /* next query should be FF */
    NQ_UINT16 sid;              /* SID - search is */
    NQ_BOOL sidAvailable;       /* TRUE when SID set */
    NQ_UINT32 resumeKey;        /* set in response, used in FN */
    NQ_BOOL eos;                /* TRUE when EOS was reached */
} 
SearchContext;	/* SMB search context */	

/* -- Forward defintions -- */

static void * allocateContext(CCServer * server);	
static void freeContext(void * context, void * server);	
static void setSolo(NQ_BOOL set);
static NQ_STATUS doNegotiate(CCServer * pServer, CMBlob * blob);
static NQ_STATUS doSessionSetup(CCUser * pUser, const CMBlob * pass1, const CMBlob * pass2);
static NQ_STATUS doSessionSetupExtended(CCUser * pUser, const CMBlob * outBlob, CMBlob * inBlob);
static NQ_STATUS doLogOff(CCUser * pUser);
static NQ_STATUS doTreeConnect(CCShare * pShare);
static NQ_STATUS doTreeDisconnect(CCShare * pShare);
static NQ_STATUS doCreate(CCFile * pFile);
static NQ_STATUS doRestoreHandle(CCFile * pFile);
static NQ_STATUS doClose(CCFile * pFile);
static NQ_STATUS doQueryDfsReferrals(CCShare * share, const NQ_WCHAR * path, CCCifsParseReferral parser, CMList * list);
static NQ_STATUS doFindOpen(CCSearch * pSearch);
static NQ_STATUS doFindMore(CCSearch * pSearch);
static NQ_STATUS doFindClose(CCSearch * pSearch);
static NQ_STATUS doWrite(CCFile * pFile, const NQ_BYTE * data, NQ_UINT bytesToWrite, CCCifsWriteCallback callback, void * context);
static NQ_STATUS doRead(CCFile * pFile, const NQ_BYTE * data, NQ_UINT bytesToRead, CCCifsReadCallback callback, void * context);
#ifdef UD_CC_INCLUDESECURITYDESCRIPTORS
static NQ_STATUS doQuerySecurityDescriptor(CCFile * pFile, CMSdSecurityDescriptor * sd);
static NQ_STATUS doSetSecurityDescriptor(CCFile * pFile, const CMSdSecurityDescriptor * sd);
#endif
static NQ_STATUS doQueryFsInfo(CCShare * pShare, CCVolumeInfo * pInfo);
static NQ_STATUS doQueryFileInfoByName(CCShare * pShare, const NQ_WCHAR * fileName, CCCifsParseFileInfoCallback callback, void * context);
static NQ_STATUS doQueryFileInfoByHandle(CCFile * pFile, CCCifsParseFileInfoCallback callback, void * context);
static NQ_STATUS doSetFileAttributes(CCFile * pFile, NQ_UINT32 attributes);	
static NQ_STATUS doSetFileSize(CCFile * pFile, NQ_UINT64 size);	
static NQ_STATUS doSetFileTime(CCFile * pFile, NQ_UINT64 creationTime, NQ_UINT64 lastAccessTime, NQ_UINT64 lastWriteTime);	
static NQ_STATUS doSetFileDeleteOnClose(CCFile * pFile);	
static NQ_STATUS doRename(CCFile * pFile, const NQ_WCHAR * newName);	
static NQ_STATUS doFlush(CCFile * pFile);	
static NQ_STATUS doRapTransaction(CCShare * share, const CMBlob * inData, CMBlob * outData);
static NQ_STATUS doEcho(CCShare * pShare);


static void writeCallback(CCServer * pServer, Match * pContext);
static void readCallback(CCServer * pServer, Match * pContext);

/* -- Static data */

static const NQ_WCHAR rpcPrefix[] = { cmWChar('\\'), 0 };  /* value to prefix RPC pipe names */

static const CCCifsSmb dialect = 
{ 
		"NT LM 0.12", 
		CCCIFS_ILLEGALSMBREVISION, 
		32,
		TRUE,
        rpcPrefix,
		(void * (*)(void *))allocateContext, 
		freeContext,  
        setSolo,
		(NQ_STATUS (*)(void *, CMBlob *))doNegotiate,
		(NQ_STATUS (*)(void *, const CMBlob *, const CMBlob *))doSessionSetup,
		(NQ_STATUS (*)(void *, const CMBlob *, CMBlob *))doSessionSetupExtended,
		(NQ_STATUS (*)(void *))doLogOff,
		(NQ_STATUS (*)(void *))doTreeConnect,
		(NQ_STATUS (*)(void *))doTreeDisconnect,
		(NQ_STATUS (*)(void *))doCreate,
		(NQ_STATUS (*)(void *))doRestoreHandle,
		(NQ_STATUS (*)(void *))doClose,
		(NQ_STATUS (*)(void *, const NQ_WCHAR *, CCCifsParseReferral, CMList *))doQueryDfsReferrals,
		(NQ_STATUS (*)(void *))doFindOpen,
		(NQ_STATUS (*)(void *))doFindMore,
		(NQ_STATUS (*)(void *))doFindClose,
		(NQ_STATUS (*)(void *, const NQ_BYTE *, NQ_UINT, CCCifsWriteCallback, void *))doWrite,
		(NQ_STATUS (*)(void *, const NQ_BYTE *, NQ_UINT, CCCifsReadCallback, void *))doRead,
#ifdef UD_CC_INCLUDESECURITYDESCRIPTORS	
		(NQ_STATUS (*)(void *, CMSdSecurityDescriptor *))doQuerySecurityDescriptor,
		(NQ_STATUS (*)(void *, const CMSdSecurityDescriptor *))doSetSecurityDescriptor,
#endif /* UD_CC_INCLUDESECURITYDESCRIPTORS */		
		(NQ_STATUS (*)(void *, void *))doQueryFsInfo, 
		(NQ_STATUS (*)(void *, const NQ_WCHAR *, CCCifsParseFileInfoCallback, void *))doQueryFileInfoByName, 
		(NQ_STATUS (*)(void *, CCCifsParseFileInfoCallback, void *))doQueryFileInfoByHandle,
		(NQ_STATUS (*)(void *, NQ_UINT32))doSetFileAttributes,
		(NQ_STATUS (*)(void *, NQ_UINT64))doSetFileSize,
		(NQ_STATUS (*)(void *, NQ_UINT64, NQ_UINT64, NQ_UINT64))doSetFileTime,
		(NQ_STATUS (*)(void *))doSetFileDeleteOnClose,
		(NQ_STATUS (*)(void *, const NQ_WCHAR *))doRename,
		(NQ_STATUS (*)(void * pFile))doFlush,	
        (NQ_STATUS (*)(void *, const CMBlob *, CMBlob *))doRapTransaction,
        (NQ_STATUS (*)(void *))doEcho,
        TRUE,
        FALSE
};

static const Command commandDescriptors[] = /* SMB descriptors */ {
{ 0, 0, 0, NULL },        			/* 0x00 SMB_COM_CREATE_DIRECTORY       */
{ 0, 0, 0, NULL },        			/* 0x01 SMB_COM_DELETE_DIRECTORY       */
{ 0, 0, 0, NULL },        			/* 0x02 SMB_COM_OPEN                   */
{ 0, 0, 0, NULL },        			/* 0x03 SMB_COM_CREATE                 */
{ 100, 3, 0, NULL },       			/* 0x04 SMB_COM_CLOSE                  */
{ 100, 1, 0, NULL },        		/* 0x05 SMB_COM_FLUSH                  */
{ 0, 0, 0, NULL },    				/* 0x06 SMB_COM_DELETE                 */
{ 1000, 1, 0, NULL },              	/* 0x07 SMB_COM_RENAME                 */
{ 0, 0, 0, NULL },       			/* 0x08 SMB_COM_QUERY_INFORMATION      */
{ 0, 0, 0, NULL },         			/* 0x09 SMB_COM_SET_INFORMATION        */
{ 0, 0, 0, NULL },                  /* 0x0A SMB_COM_READ                   */
{ 0, 0, 0, NULL },                  /* 0x0B SMB_COM_WRITE                  */
{ 0, 0, 0, NULL },                  /* 0x0C SMB_COM_LOCK_BYTE_RANGE        */
{ 0, 0, 0, NULL },                  /* 0x0D SMB_COM_UNLOCK_BYTE_RANGE      */
{ 0, 0, 0, NULL },                  /* 0x0E SMB_COM_CREATE_TEMPORARY       */
{ 0, 0, 0, NULL },              	/* 0x0F SMB_COM_CREATE_NEW             */
{ 0, 0, 0, NULL },         			/* 0x10 SMB_COM_CHECK_DIRECTORY        */
{ 0, 0, 0, NULL },            		/* 0x11 SMB_COM_PROCESS_EXIT           */
{ 0, 0, 0, NULL },                  /* 0x12 SMB_COM_SEEK                   */
{ 0, 0, 0, NULL },                  /* 0x13 SMB_COM_LOCK_AND_READ          */
{ 0, 0, 0, NULL },                  /* 0x14 SMB_COM_WRITE_AND_UNLOCK       */
{ 0, 0, 0, NULL },                  /* 0x15 0x15                           */
{ 0, 0, 0, NULL },                  /* 0x16 0x16                           */
{ 0, 0, 0, NULL },                  /* 0x17 0x17                           */
{ 0, 0, 0, NULL },                  /* 0x18 0x18                           */
{ 0, 0, 0, NULL },                  /* 0x19 0x19                           */
{ 0, 0, 0, NULL },                  /* 0x1A SMB_COM_READ_RAW               */
{ 0, 0, 0, NULL },                  /* 0x1B SMB_COM_READ_MPX               */
{ 0, 0, 0, NULL },                  /* 0x1C SMB_COM_READ_MPX_SECONDARY     */
{ 0, 0, 0, NULL },                  /* 0x1D SMB_COM_WRITE_RAW              */
{ 0, 0, 0, NULL },                  /* 0x1E SMB_COM_WRITE_MPX              */
{ 0, 0, 0, NULL },                  /* 0x1f 0x1f                           */
{ 0, 0, 0, NULL },                  /* 0x20 SMB_COM_WRITE_COMPLETE         */
{ 0, 0, 0, NULL },                  /* 0x21 0x21                           */
{ 0, 0, 0, NULL },        			/* 0x22 SMB_COM_SET_INFORMATION2       */
{ 0, 0, 0, NULL },      			/* 0x23 SMB_COM_QUERY_INFORMATION2     */
{ 0, 0, 0, NULL },            		/* 0x24 SMB_COM_LOCKING_ANDX           */
{ 200, 0xe, 0, NULL },         		/* 0x25 SMB_COM_TRANSACTION            */
{ 0, 0, 0, NULL },                  /* 0x26 SMB_COM_TRANSACTION_SECONDARY  */
{ 0, 0, 0, NULL },                  /* 0x27 SMB_COM_IOCTL                  */
{ 0, 0, 0, NULL },                  /* 0x28 SMB_COM_IOCTL_SECONDARY        */
{ 0, 0, 0, NULL },                  /* 0x29 SMB_COM_COPY                   */
{ 0, 0, 0, NULL },                  /* 0x2A SMB_COM_MOVE                   */
{ 7, 1, 1, NULL },                 	/* 0x2B SMB_COM_ECHO                   */
{ 0, 0, 0, NULL },                  /* 0x2C SMB_COM_WRITE_AND_CLOSE        */
{ 0, 0, 0, NULL },               	/* 0x2D SMB_COM_OPEN_ANDX              */
{ 200, 0xc, 0, readCallback },     	/* 0x2E SMB_COM_READ_ANDX              */
{ 200, 0xe, 0, writeCallback },    	/* 0x2F SMB_COM_WRITE_ANDX             */
{ 0, 0, 0, NULL },                  /* 0x30 0x30                           */
{ 0, 0, 0, NULL },                  /* 0x31 SMB_COM_CLOSE_AND_TREE_DISC    */
{ 2000, 0x0f, 0xa, NULL },    		/* 0x32 SMB_COM_TRANSACTION2           */
{ 0, 0, 0, NULL },                  /* 0x33 SMB_COM_TRANSACTION2_SECONDARY */
{ 200, 0x1, 0, NULL },        		/* 0x34 SMB_COM_FIND_CLOSE2            */
{ 0, 0, 0, NULL },                  /* 0x35 SMB_COM_FIND_NOTIFY_CLOSE      */
{ 0, 0, 0, NULL },                  /* 0x36 0x36                           */
{ 0, 0, 0, NULL },                  /* 0x37 0x37                           */
{ 0, 0, 0, NULL },                  /* 0x38 0x38                           */
{ 0, 0, 0, NULL },                  /* 0x39 0x39                           */
{ 0, 0, 0, NULL },                  /* 0x3A 0x3A                           */
{ 0, 0, 0, NULL },                  /* 0x3B 0x3B                           */
{ 0, 0, 0, NULL },                  /* 0x3C 0x3C                           */
{ 0, 0, 0, NULL },                  /* 0x3D 0x3D                           */
{ 0, 0, 0, NULL },                  /* 0x3E 0x3E                           */
{ 0, 0, 0, NULL },                  /* 0x3F 0x3F                           */
{ 0, 0, 0, NULL },                  /* 0x40 0x40                           */
{ 0, 0, 0, NULL },                  /* 0x41 0x41                           */
{ 0, 0, 0, NULL },                  /* 0x42 0x42                           */
{ 0, 0, 0, NULL },                  /* 0x43 0x43                           */
{ 0, 0, 0, NULL },                  /* 0x44 0x44                           */
{ 0, 0, 0, NULL },                  /* 0x45 0x45                           */
{ 0, 0, 0, NULL },                  /* 0x46 0x46                           */
{ 0, 0, 0, NULL },                  /* 0x47 0x47                           */
{ 0, 0, 0, NULL },                  /* 0x48 0x48                           */
{ 0, 0, 0, NULL },                  /* 0x49 0x49                           */
{ 0, 0, 0, NULL },                  /* 0x4A 0x4A                           */
{ 0, 0, 0, NULL },                  /* 0x4B 0x4B                           */
{ 0, 0, 0, NULL },                  /* 0x4C 0x4C                           */
{ 0, 0, 0, NULL },                  /* 0x4D 0x4D                           */
{ 0, 0, 0, NULL },                  /* 0x4E 0x4E                           */
{ 0, 0, 0, NULL },                  /* 0x4F 0x4F                           */
{ 0, 0, 0, NULL },                  /* 0x50 0x50                           */
{ 0, 0, 0, NULL },                  /* 0x51 0x51                           */
{ 0, 0, 0, NULL },                  /* 0x52 0x52                           */
{ 0, 0, 0, NULL },                  /* 0x53 0x53                           */
{ 0, 0, 0, NULL },                  /* 0x54 0x54                           */
{ 0, 0, 0, NULL },                  /* 0x55 0x55                           */
{ 0, 0, 0, NULL },                  /* 0x56 0x56                           */
{ 0, 0, 0, NULL },                  /* 0x57 0x57                           */
{ 0, 0, 0, NULL },                  /* 0x58 0x58                           */
{ 0, 0, 0, NULL },                  /* 0x59 0x59                           */
{ 0, 0, 0, NULL },                  /* 0x5A 0x5A                           */
{ 0, 0, 0, NULL },                  /* 0x5B 0x5B                           */
{ 0, 0, 0, NULL },                  /* 0x5C 0x5C                           */
{ 0, 0, 0, NULL },                  /* 0x5D 0x5D                           */
{ 0, 0, 0, NULL },                  /* 0x5E 0x5E                           */
{ 0, 0, 0, NULL },                  /* 0x5F 0x5F                           */
{ 0, 0, 0, NULL },                  /* 0x60 0x60                           */
{ 0, 0, 0, NULL },                  /* 0x61 0x61                           */
{ 0, 0, 0, NULL },                  /* 0x62 0x62                           */
{ 0, 0, 0, NULL },                  /* 0x63 0x63                           */
{ 0, 0, 0, NULL },                  /* 0x64 0x64                           */
{ 0, 0, 0, NULL },                  /* 0x65 0x65                           */
{ 0, 0, 0, NULL },                  /* 0x66 0x66                           */
{ 0, 0, 0, NULL },                  /* 0x67 0x67                           */
{ 0, 0, 0, NULL },                  /* 0x68 0x68                           */
{ 0, 0, 0, NULL },                  /* 0x69 0x69                           */
{ 0, 0, 0, NULL },                  /* 0x6A 0x6A                           */
{ 0, 0, 0, NULL },                  /* 0x6B 0x6B                           */
{ 0, 0, 0, NULL },                  /* 0x6C 0x6C                           */
{ 0, 0, 0, NULL },                  /* 0x6D 0x6D                           */
{ 0, 0, 0, NULL },                  /* 0x6E 0x6E                           */
{ 0, 0, 0, NULL },                  /* 0x6F 0x6F                           */
{ 0, 0, 0, NULL },            		/* 0x70 SMB_COM_TREE_CONNECT           */
{ 300, 0, 0, NULL },         	    /* 0x71 SMB_COM_TREE_DISCONNECT        */
{ 300, 0, 17, NULL },               /* 0x72 SMB_COM_NEGOTIATE              */
{ 0xFFFF, 0xFF, 3, NULL },   			/* 0x73 SMB_COM_SESSION_SETUP_ANDX     */
{ 300, 2, 0, NULL },        		/* 0x74 SMB_COM_LOGOFF_ANDX            */
{ 2000, 4, 7, NULL },    		    /* 0x75 SMB_COM_TREE_CONNECT_ANDX      */
{ 0, 0, 0, NULL },                  /* 0x76 0x76                           */
{ 0, 0, 0, NULL },                  /* 0x77 0x77                           */
{ 0, 0, 0, NULL },                  /* 0x78 0x78                           */
{ 0, 0, 0, NULL },                  /* 0x79 0x79                           */
{ 0, 0, 0, NULL },                  /* 0x7A 0x7A                           */
{ 0, 0, 0, NULL },                  /* 0x7B 0x7B                           */
{ 0, 0, 0, NULL },                  /* 0x7C 0x7C                           */
{ 0, 0, 0, NULL },                  /* 0x7D 0x7D                           */
{ 0, 0, 0, NULL },                  /* 0x7E 0x7E                           */
{ 0, 0, 0, NULL },                  /* 0x7F 0x7F                           */
{ 0, 0, 0, NULL },   				/* 0x80 SMB_COM_QUERY_INFORMATION_DISK */
{ 0, 0, 0, NULL },                 	/* 0x81 SMB_COM_SEARCH                 */
{ 0, 0, 0, NULL },                  /* 0x82 SMB_COM_FIND                   */
{ 0, 0, 0, NULL },                  /* 0x83 SMB_COM_FIND_UNIQUE            */
{ 0, 0, 0, NULL },                  /* 0x84 SMB_COM_FIND_CLOSE             */
{ 0, 0, 0, NULL },                  /* 0x85 0x85                           */
{ 0, 0, 0, NULL },                  /* 0x86 0x86                           */
{ 0, 0, 0, NULL },                  /* 0x87 0x87                           */
{ 0, 0, 0, NULL },                  /* 0x88 0x88                           */
{ 0, 0, 0, NULL },                  /* 0x89 0x89                           */
{ 0, 0, 0, NULL },                  /* 0x8A 0x8A                           */
{ 0, 0, 0, NULL },                  /* 0x8B 0x8B                           */
{ 0, 0, 0, NULL },                  /* 0x8C 0x8C                           */
{ 0, 0, 0, NULL },                  /* 0x8D 0x8D                           */
{ 0, 0, 0, NULL },                  /* 0x8E 0x8E                           */
{ 0, 0, 0, NULL },                  /* 0x8F 0x8F                           */
{ 0, 0, 0, NULL },                  /* 0x90 0x90                           */
{ 0, 0, 0, NULL },                  /* 0x91 0x91                           */
{ 0, 0, 0, NULL },                  /* 0x92 0x92                           */
{ 0, 0, 0, NULL },                  /* 0x93 0x93                           */
{ 0, 0, 0, NULL },                  /* 0x94 0x94                           */
{ 0, 0, 0, NULL },                  /* 0x95 0x95                           */
{ 0, 0, 0, NULL },                  /* 0x96 0x96                           */
{ 0, 0, 0, NULL },                  /* 0x97 0x97                           */
{ 0, 0, 0, NULL },                  /* 0x98 0x98                           */
{ 0, 0, 0, NULL },                  /* 0x99 0x99                           */
{ 0, 0, 0, NULL },                  /* 0x9A 0x9A                           */
{ 0, 0, 0, NULL },                  /* 0x9B 0x9B                           */
{ 0, 0, 0, NULL },                  /* 0x9C 0x9C                           */
{ 0, 0, 0, NULL },                  /* 0x9D 0x9D                           */
{ 0, 0, 0, NULL },                  /* 0x9E 0x9E                           */
{ 0, 0, 0, NULL },                  /* 0x9F 0x9F                           */
{ 3000, 0x13, 0x12, NULL },    		/* 0xA0 SMB_COM_NT_TRANSACT            */
{ 0, 0, 0, NULL },                  /* 0xA1 SMB_COM_NT_TRANSACT_SECONDARY  */
{ 2000, 0x18, 0, NULL },           	/* 0xA2 SMB_COM_NT_CREATE_ANDX         */
{ 0, 0, 0, NULL },                  /* 0xA3 0xA3                           */
{ 0, 0, 0, NULL },               	/* 0xA4 SMB_COM_NT_CANCEL              */
{ 0, 0, 0, NULL },                  /* 0xA5 0xA5                           */
{ 0, 0, 0, NULL },                  /* 0xA6 0xA6                           */
{ 0, 0, 0, NULL },                  /* 0xA7 0xA7                           */
{ 0, 0, 0, NULL },                  /* 0xA8 0xA8                           */
{ 0, 0, 0, NULL },                  /* 0xA9 0xA9                           */
{ 0, 0, 0, NULL },                  /* 0xAA 0xAA                           */
{ 0, 0, 0, NULL },                  /* 0xAB 0xAB                           */
{ 0, 0, 0, NULL },                  /* 0xAC 0xAC                           */
{ 0, 0, 0, NULL },                  /* 0xAD 0xAD                           */
{ 0, 0, 0, NULL },                  /* 0xAE 0xAE                           */
{ 0, 0, 0, NULL },                  /* 0xAF 0xAF                           */
{ 0, 0, 0, NULL },                  /* 0xB0 0xB0                           */
{ 0, 0, 0, NULL },                  /* 0xB1 0xB1                           */
{ 0, 0, 0, NULL },                  /* 0xB2 0xB2                           */
{ 0, 0, 0, NULL },                  /* 0xB3 0xB3                           */
{ 0, 0, 0, NULL },                  /* 0xB4 0xB4                           */
{ 0, 0, 0, NULL },                  /* 0xB5 0xB5                           */
{ 0, 0, 0, NULL },                  /* 0xB6 0xB6                           */
{ 0, 0, 0, NULL },                  /* 0xB7 0xB7                           */
{ 0, 0, 0, NULL },                  /* 0xB8 0xB8                           */
{ 0, 0, 0, NULL },                  /* 0xB9 0xB9                           */
{ 0, 0, 0, NULL },                  /* 0xBA 0xBA                           */
{ 0, 0, 0, NULL },                  /* 0xBB 0xBB                           */
{ 0, 0, 0, NULL },                  /* 0xBC 0xBC                           */
{ 0, 0, 0, NULL },                  /* 0xBD 0xBD                           */
{ 0, 0, 0, NULL },                  /* 0xBE 0xBE                           */
{ 0, 0, 0, NULL },                  /* 0xBF 0xBF                           */
{ 0, 0, 0, NULL },                  /* 0xC0 SMB_COM_OPEN_PRINT_FILE        */
{ 0, 0, 0, NULL },                  /* 0xC1 SMB_COM_WRITE_PRINT_FILE       */
{ 0, 0, 0, NULL },                  /* 0xC2 SMB_COM_CLOSE_PRINT_FILE       */
{ 0, 0, 0, NULL },                  /* 0xC3 SMB_COM_GET_PRINT_QUEUE        */
}; /* end of the command set */

static SYMutex soloGuard;           /* critical section guard for protetcing next variable */
static NQ_BOOL soloMode = FALSE;    /* negotiation mode */

/* -- API Functions */

NQ_BOOL ccSmb10Start()
{
    syMutexCreate(&soloGuard);
	return TRUE;
}

NQ_BOOL ccSmb10Shutdown()
{
    syMutexDelete(&soloGuard);
	return TRUE;
}

const CCCifsSmb * ccSmb10GetCifs(void)
{
	return &dialect;
}

/* -- Static functions -- */

static void * allocateContext(CCServer * server)
{
	Context * pContext;
	if (NULL == (pContext = (Context *)cmMemoryAllocate(sizeof(Context))))
	{
		return NULL;
	}
	pContext->mid = 0;
	pContext->pid = 0;
    return pContext;
}

static void freeContext(void * context, void * server)
{
	CCServer * pServer = (CCServer *)server;	/* casted pointer */
	Context * pContext = (Context *)pServer->smbContext;
	
	ccTransportRemoveResponseCallback(&pServer->transport);
	if (NULL != pContext)
	{
		cmMemoryFree(pContext);
		pServer->smbContext = NULL;
	}
}

static void setSolo(NQ_BOOL set)
{
    if (set)
    {
        syMutexTake(&soloGuard);
        soloMode = TRUE;
    }
    else
    {
        syMutexGive(&soloGuard);
        soloMode = FALSE;
    }
}

static NQ_BOOL prepareSingleRequest(CCServer * pServer, Request * pRequest, NQ_BYTE command)
{
	NQ_BYTE * pBuffer;		/* allocated request buffer */ 
	NQ_COUNT bufferSize;	/* this buffer size */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	/* this call:
	 * - allocates request buffer
	 * - creates request header
	 */
	/* allocate buffer for request */
	bufferSize = (NQ_COUNT)(commandDescriptors[command].requestBufferSize + SMB_HEADERSIZE + 4);
	pBuffer = cmBufManTake(bufferSize);
	if (NULL == pBuffer)
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return FALSE;
	}
	cmBufferWriterInit(&pRequest->writer, pBuffer, bufferSize);
	pRequest->buffer = pBuffer;
	pRequest->command = command;
	pRequest->tail.data = NULL;
	pRequest->tail.len = 0;
	cmBufferWriterSkip(&pRequest->writer, 4);	/* NBT header */
	cmSmbHeaderInitForRequest(&pRequest->header, &pRequest->writer, command);
	pRequest->header.flags = 0x18;
	pRequest->header.flags2 = (NQ_UINT16)(  SMB_FLAGS2_UNICODE
								| SMB_FLAGS2_32_BIT_ERROR_CODES
								| SMB_FLAGS2_IS_LONG_NAME
                                | SMB_FLAGS2_KNOWS_LONG_NAMES
#ifdef UD_CC_INCLUDEDFS
                                | ((pServer->capabilities & CC_CAP_DFS) ? SMB_FLAGS2_DFS_PATHNAMES : 0)
#endif /* UD_CC_INCLUDEDFS */                                
#ifdef UD_CC_INCLUDEEXTENDEDSECURITY									
                                | (pServer->useExtendedSecurity ? SMB_FLAGS2_EXTENDED_SECURITY : 0)
#endif /* UD_CC_INCLUDEEXTENDEDSECURITY */
                                | (ccServerUseSignatures(pServer) ? SMB_FLAGS2_SMB_SECURITY_SIGNATURES : 0)
                                );                                
	pRequest->header.mid = 0;
    pRequest->header.pid = 0;
	pRequest->header.tid = 0;
	pRequest->header.uid = 0;

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return TRUE;
}

static NQ_BOOL prepareSingleRequestByShare(Request * pRequest, const CCShare * pShare, NQ_UINT16 command)
{
	if (!prepareSingleRequest(pShare->user->server, pRequest, (NQ_BYTE)command))
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return FALSE;
	}
	pRequest->header.tid = (NQ_UINT16)pShare->tid;
	pRequest->header.uid = (NQ_UINT16)pShare->user->uid.low;
	return TRUE;
}

static void writeHeader(Request * pRequest)
{
	cmSmbHeaderWrite(&pRequest->header, &pRequest->writer);
	pRequest->pWordCount = cmBufferWriterGetPosition(&pRequest->writer);
    if (0xFF != commandDescriptors[pRequest->command].requestWordCount)
	    cmBufferWriteByte(&pRequest->writer, commandDescriptors[pRequest->command].requestWordCount);
}

/* write next AndX command (0xFF) and offset */
static void writeAndX(Request * pRequest)
{
    cmBufferWriteByte(&pRequest->writer, 0xFF);   /* no next AndX */
    cmBufferWriteByte(&pRequest->writer, 0);      /* reserved */
    cmBufferWriteUint16(&pRequest->writer, 0);    /* AndX offset */
}

/* set or just mark byte count */
static void markByteCount(Request * pRequest, NQ_UINT16 byteCount)
{
	pRequest->pByteCount = cmBufferWriterGetPosition(&pRequest->writer);
	cmBufferWriteUint16(&pRequest->writer, byteCount);
}

static void writeByteCount(Request * pRequest, NQ_UINT16 tailLen)
{
	NQ_BYTE * pTemp;		/* current position */
    NQ_UINT16 byteCount;    /* calculated count */
	
    byteCount = (NQ_UINT16)(cmBufferWriterGetPosition(&pRequest->writer) - pRequest->pByteCount + tailLen - (NQ_UINT16)sizeof(NQ_UINT16));
	pTemp = cmBufferWriterGetPosition(&pRequest->writer);
	cmBufferWriterSetPosition(&pRequest->writer, pRequest->pByteCount);
	cmBufferWriteUint16(&pRequest->writer, byteCount);
	cmBufferWriterSetPosition(&pRequest->writer, pTemp);
}

static void markTransParams(Request * pRequest)
{
    pRequest->pParams = cmBufferWriterGetPosition(&pRequest->writer);
}

static void markTransData(Request * pRequest)
{
    pRequest->pData = cmBufferWriterGetPosition(&pRequest->writer);
}

static void markTrans2Start(Request * pRequest, NQ_BYTE trans2Command)
{
    pRequest->pTrans = cmBufferWriterGetPosition(&pRequest->writer);
    cmBufferWriterSkip(&pRequest->writer, sizeof (NQ_UINT16) * (SMB_TRANSACTION2_REQUEST_WORDCOUNT - 2));
	cmBufferWriteByte(&pRequest->writer, 1);                /* setup count */
	cmBufferWriteByte(&pRequest->writer, 0);                /* reserved */
	cmBufferWriteUint16(&pRequest->writer, trans2Command);  /* subcommand */
    markByteCount(pRequest, 0);
	cmBufferWriteZeroes(&pRequest->writer, 3);              /* reserved */
    markTransParams(pRequest);
}

static void writeTrans2(CCServer * pServer, Request * pRequest, NQ_UINT16 maxParamCount, NQ_BYTE maxSetupCount)
{
    NQ_BYTE * pEnd;         /* pointer to the end of packet */
    NQ_UINT32 maxBuffer = UD_NS_BUFFERSIZE - 100;
    NQ_UINT16 dataCount;    /* data count */

    if (maxBuffer > pServer->maxTrans - 100)
        maxBuffer = pServer->maxTrans - 100;
    writeByteCount(pRequest, 0);
    pEnd = cmBufferWriterGetPosition(&pRequest->writer);
    cmBufferWriterSetPosition(&pRequest->writer, pRequest->pTrans);
    cmBufferWriteUint16(&pRequest->writer, (NQ_UINT16)(pRequest->pData - pRequest->pParams));        /* total params count */
    cmBufferWriteUint16(&pRequest->writer, (NQ_UINT16)(pEnd - pRequest->pData));                     /* total data count */
    cmBufferWriteUint16(&pRequest->writer, maxParamCount);                              /* max params count */
    cmBufferWriteUint16(&pRequest->writer, (NQ_UINT16)(maxBuffer > 0xFFFF? 0xFFFF : maxBuffer));     /* max data count */
    cmBufferWriteByte(&pRequest->writer, maxSetupCount);                                /* max setup count */
    cmBufferWriteByte(&pRequest->writer, 0);                                            /* reserved */
    cmBufferWriteUint16(&pRequest->writer, 0);                                          /* flags */
    cmBufferWriteUint32(&pRequest->writer, 0);                                          /* timeout */
    cmBufferWriteUint16(&pRequest->writer, 0);                                          /* reserved */
    cmBufferWriteUint16(&pRequest->writer, (NQ_UINT16)(pRequest->pData - pRequest->pParams));        /* params count */
    cmBufferWriteUint16(&pRequest->writer, (NQ_UINT16)(pRequest->pParams - pRequest->header._start));/* params offset */
    dataCount = (NQ_UINT16)(pEnd - pRequest->pData);
    cmBufferWriteUint16(&pRequest->writer, dataCount);                                  /* data count */
    cmBufferWriteUint16(&pRequest->writer, 
        dataCount == 0? 0: (NQ_UINT16)(pRequest->pData - pRequest->header._start));                  /* data offset */
    cmBufferWriterSetPosition(&pRequest->writer, pEnd);
}

static void markTransStart(Request * pRequest, const NQ_CHAR * transName)
{
    pRequest->pTrans = cmBufferWriterGetPosition(&pRequest->writer);
    cmBufferWriterSkip(&pRequest->writer, sizeof (NQ_UINT16) * (SMB_TRANSACTION_REQUEST_WORDCOUNT - 1));
	cmBufferWriteByte(&pRequest->writer, 0);                                /* setup count */
	cmBufferWriteByte(&pRequest->writer, 0);                                /* reserved */
    markByteCount(pRequest, 0);
	cmBufferWriteBytes(&pRequest->writer, (NQ_BYTE *)transName, (NQ_COUNT)syStrlen(transName));
	cmBufferWriteByte(&pRequest->writer, 0);                                /* transaction name */
    markTransParams(pRequest);
}

static void writeTrans(CCServer * pServer, Request * pRequest, NQ_UINT16 maxParamCount)
{
    NQ_BYTE * pEnd;         /* pointer to the end of packet */
    NQ_UINT32 maxBuffer = UD_NS_BUFFERSIZE - 100;
    NQ_UINT16 dataCount;    /* data count */

    if (maxBuffer > pServer->maxTrans - 100)
        maxBuffer = pServer->maxTrans - 100;
    writeByteCount(pRequest, 0);
    pEnd = cmBufferWriterGetPosition(&pRequest->writer);
    cmBufferWriterSetPosition(&pRequest->writer, pRequest->pTrans);
    cmBufferWriteUint16(&pRequest->writer, (NQ_UINT16)(pRequest->pData - pRequest->pParams));        /* total params count */
    cmBufferWriteUint16(&pRequest->writer, (NQ_UINT16)(pEnd - pRequest->pData));                     /* total data count */
    cmBufferWriteUint16(&pRequest->writer, maxParamCount);                              /* max params count */
    cmBufferWriteUint16(&pRequest->writer, (NQ_UINT16)(maxBuffer > 0xFFFF? 0xFFFF : maxBuffer));     /* max data count */
    cmBufferWriteByte(&pRequest->writer, 0);                                            /* max setup count */
    cmBufferWriteByte(&pRequest->writer, 0);                                            /* reserved */
    cmBufferWriteUint16(&pRequest->writer, 0);                                          /* flags */
    cmBufferWriteUint32(&pRequest->writer, 0);                                          /* timeout */
    cmBufferWriteUint16(&pRequest->writer, 0);                                          /* reserved */
    cmBufferWriteUint16(&pRequest->writer, (NQ_UINT16)(pRequest->pData - pRequest->pParams));        /* params count */
    cmBufferWriteUint16(&pRequest->writer, (NQ_UINT16)(pRequest->pParams - pRequest->header._start));/* params offset */
    dataCount = (NQ_UINT16)(pEnd - pRequest->pData);
    cmBufferWriteUint16(&pRequest->writer, dataCount);                                  /* data count */
    cmBufferWriteUint16(&pRequest->writer, 
        dataCount == 0? 0: (NQ_UINT16)(pRequest->pData - pRequest->header._start));                  /* data offset */
    cmBufferWriterSetPosition(&pRequest->writer, pEnd);
}

static void parseTrans(Response * pResponse)
{
    NQ_UINT16 temp16;       /* for parsing 16-bit values */

    cmBufferReaderSkip(
        &pResponse->reader, 
        sizeof(NQ_BYTE) + sizeof(NQ_UINT16) * 4
        );                                                          /* skip to parameter offset */
    cmBufferReadUint16(&pResponse->reader, &temp16);                /* parameter offset */
    pResponse->pParams = pResponse->header._start + temp16;
    cmBufferReaderSkip(&pResponse->reader, sizeof(NQ_UINT16) * 1);  /* skip to data count */
    cmBufferReadUint16(&pResponse->reader, &temp16);                /* data count */
    pResponse->dataCount = temp16;
    cmBufferReadUint16(&pResponse->reader, &temp16);                /* data offset */
    pResponse->pData = pResponse->header._start + temp16;
}       

static void setTransData(Response * pResponse)
{
    cmBufferReaderSetPosition(&pResponse->reader, pResponse->pData);
}

static void setTransParams(Response * pResponse)
{
    cmBufferReaderSetPosition(&pResponse->reader, pResponse->pParams);
}


static NQ_STATUS sendRequest(CCServer * pServer, CCUser * pUser, Request * pRequest, Match * pMatch)
{
	NQ_UINT32 packetLen;		/* packet length of both in and out packets */
    Context * pContext;         /* server context */
	CMBufferWriter writer;      /* to write down MID */
	
	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	if (pServer->smbContext == NULL)
	{
		LOGERR(CM_TRC_LEVEL_ERROR, " smbContext in CCServer ibject is missing");
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NQ_ERR_NOTCONNECTED;
	}

    packetLen = cmBufferWriterGetDataCount(&pRequest->writer) - 4;	/* NBT header */

    if (!ccServerWaitForCredits(pServer))
    {
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NQ_ERR_TIMEOUT;
    }
    ccTransportLock(&pServer->transport);

    /* write down MID */
    pContext = (Context *)pServer->smbContext;
	pRequest->header.mid = pContext->mid;
	pRequest->header.pid = pContext->pid;
	pContext->mid = (NQ_UINT16)(pContext->mid +2);
    if (0 == pContext->mid)
    {
        pContext->pid++;
    }
    cmBufferWriterInit(&writer, pRequest->buffer + PIDOFFSET, packetLen);
    cmBufferWriteUint16(&writer, (NQ_UINT16)(pRequest->header.pid));
    cmBufferWriterSkip(&writer, sizeof(NQ_UINT16));
    cmBufferWriteUint16(&writer, pRequest->header.mid);
    pMatch->mid = pRequest->header.mid;
    pMatch->pid = pRequest->header.pid;

    /* compose signature */
    if (ccServerUseSignatures(pServer) && NULL != pServer->masterUser && ccUserUseSignatures(pUser))
	{
        CCUser * pMasterUser = (CCUser *)pServer->masterUser;
        if (NULL != pMasterUser && NULL != pMasterUser->macSessionKey.data)
        {
#ifdef UD_CC_INCLUDEEXTENDEDSECURITY
            if (pServer->useExtendedSecurity)
            {
                cmSmbCalculateMessageSignature(
                    pMasterUser->macSessionKey.data, 
				    pMasterUser->macSessionKey.len, 
                    MSG_NUMBER(pRequest->header),
                    pRequest->buffer + 4,
                    packetLen,
    			    pRequest->tail.data,
    			    pRequest->tail.len, 
                    NULL,
                    0,
    			    pRequest->header._start + SMB_SECURITY_SIGNATURE_OFFSET
                    );
            }
            else
#endif /* UD_CC_INCLUDEEXTENDEDSECURITY */
            {
       cmSmbCalculateMessageSignature(
				    pMasterUser->macSessionKey.data, 
				    pMasterUser->macSessionKey.len, 
                    MSG_NUMBER(pRequest->header),
                    pRequest->buffer + 4,
                    packetLen,
    			    pRequest->tail.data,
    			    pRequest->tail.len, 
                    pMasterUser->sessionKey.data,
                    pMasterUser->sessionKey.len,
    			    pRequest->header._start + SMB_SECURITY_SIGNATURE_OFFSET
                    );
            }
        }
	}
	if (!ccTransportSend(
			&pServer->transport, 
			pRequest->buffer, 
			packetLen + pRequest->tail.len,
			packetLen
			)
		)
	{
        ccTransportUnlock(&pServer->transport);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return (NQ_STATUS)syGetLastError();
	}
	if (0 != pRequest->tail.len && 
		!ccTransportSendTail(&pServer->transport, pRequest->tail.data, pRequest->tail.len)
		)
	{
        ccTransportUnlock(&pServer->transport);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return (NQ_STATUS)syGetLastError();
	}
    ccTransportUnlock(&pServer->transport);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return NQ_SUCCESS;
}

static NQ_STATUS sendReceive(CCServer * pServer, CCUser * pUser, Request * pRequest, Response * pResponse)
{
	NQ_STATUS res;				/* send result */
    CMThread * pThread;         /* current thread */
    Match * pMatch;             /* match structure pointer */
    NQ_BOOL statusNT;           /* TRUE if status is NT , FALSE if it isnt*/

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    pResponse->buffer = NULL;
    pThread = cmThreadGetCurrent();
    pMatch = (Match *)cmThreadGetContext(pThread, sizeof(Match));
    if (NULL == pMatch)
    {
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_OUTOFMEMORY;
    }
	pMatch->response = pResponse;
	pMatch->cond = &pThread->syncCond;
    pMatch->server = pServer;
	cmListItemAdd(&pServer->expectedResponses, (CMItem *)pMatch, NULL);
	cmThreadCondClear(pMatch->cond); /* Cleaning up the condition socket before sending*/
	
	res = sendRequest(pServer, pUser, pRequest, pMatch);
    if (NQ_SUCCESS != res)
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
	}
	
	if (!cmThreadCondWait(pMatch->cond, ccConfigGetTimeout()))
	{
	    (pServer->transport.cleanupCallback)(pServer->transport.cleanupContext);
		if ((!pServer->transport.connected || NULL == pResponse->buffer) 
            && pRequest->command != SMB_COM_NEGOTIATE && pRequest->command != SMB_COM_SESSION_SETUP_ANDX
           )
        {
            if (!ccServerReconnect(pServer))
            {
                LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                return NQ_ERR_NOTCONNECTED;
            }
        }
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_TIMEOUT;
	}

	/* check connection */
    if (!pServer->transport.connected)
    {
	    (pServer->transport.cleanupCallback)(pServer->transport.cleanupContext);
        if (pRequest->command != SMB_COM_NEGOTIATE && pRequest->command != SMB_COM_SESSION_SETUP_ANDX)
        {
            if (ccServerReconnect(pServer))
            {
		        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		        return NQ_ERR_TIMEOUT;              /* simulate timeout - causing retry */
            }
        }
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NQ_ERR_NOTCONNECTED;
    }

    /* check signatures */
	if (ccServerUseSignatures(pServer) && (pResponse->header.flags2 & SMB_FLAGS2_SMB_SECURITY_SIGNATURES) && pResponse->header.command != SMB_COM_SESSION_SETUP_ANDX && ccUserUseSignatures(pUser))
	{
		NQ_BYTE * pSignature = pMatch->hdrBuf + SMB_SECURITY_SIGNATURE_OFFSET;
        CCUser * pMasterUser = (CCUser *)pServer->masterUser;

        if (NULL != pMasterUser && NULL != pMasterUser->macSessionKey.data)
        {
#ifdef UD_CC_INCLUDEEXTENDEDSECURITY
            if (pServer->useExtendedSecurity)
            {
                cmSmbCalculateMessageSignature(
				    pMasterUser->macSessionKey.data, 
				    pMasterUser->macSessionKey.len, 
                    MSG_NUMBER(pRequest->header) + 1,
    			    pMatch->hdrBuf,
    			    SMB_HEADERSIZE,
    			    pResponse->buffer, 
    			    pResponse->tailLen, 
                    NULL,
                    0,
    			    pSignature
                    );
            }
            else
    #endif /* UD_CC_INCLUDEEXTENDEDSECURITY */
            {
                cmSmbCalculateMessageSignature(
				    pMasterUser->macSessionKey.data, 
				    pMasterUser->macSessionKey.len, 
                    MSG_NUMBER(pRequest->header) + 1,
				    pMatch->hdrBuf,
    			    SMB_HEADERSIZE,
				    pResponse->buffer, 
				    pResponse->tailLen, 
				    pMasterUser->sessionKey.data,
				    pMasterUser->sessionKey.len,
				    pSignature
                    );
            }
		    if (0 != syMemcmp(pResponse->header.signature, pSignature, sizeof(pResponse->header.signature)))
		    {
		        LOGERR(CM_TRC_LEVEL_ERROR, "bad incoming signature");
			    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
			    return NQ_ERR_SIGNATUREFAIL;
		    }
        }
	}
	statusNT = (pResponse->header.flags2 & SMB_FLAGS2_32_BIT_ERROR_CODES);
	sySetLastError((NQ_UINT32)ccErrorsStatusToNq((NQ_UINT32)pResponse->header.status, statusNT));

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return (NQ_STATUS)ccErrorsStatusToNq((NQ_UINT32)pResponse->header.status, statusNT);
}

static NQ_STATUS exchangeEmptyCommand(CCShare * pShare, NQ_UINT16 command)
{
	Request request;		/* request dscriptor */
	Response response;		/* response descriptor */
	CCServer * pServer;		/* server object pointer */
	NQ_STATUS res;			/* exchange status */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	pServer = pShare->user->server;
	if (!prepareSingleRequestByShare(&request, pShare, command))
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_OUTOFMEMORY;
	}
	
	/* compose request */
	writeHeader(&request);
	cmBufferWriteUint16(&request.writer, 0);		/* reserved */
	
    res = sendReceive(pServer, pShare->user, &request, &response);
	cmBufManGive(request.buffer);
	cmBufManGive(response.buffer);

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return res;
}

static void anyResponseCallback(void * transport)
{
	CCTransport * pTransport = (CCTransport *)transport; 	/* casted to transport entry */
	CCServer * pServer;							/* casted pointer */
	CMIterator iterator;						/* iterates through expected responses */
	CMSmbHeader header;							/* response header */
	CMBufferReader reader;						/* to parse header */
	NQ_COUNT res;								/* bytes read */
	NQ_BYTE buffer[SMB_HEADERSIZE];				/* we will read header */
    const NQ_CHAR SIGNATURE[] = {(NQ_CHAR)0xff, 'S', 'M', 'B' }; /* SMB signature */
	
	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
	
    pServer = (CCServer *)pTransport->context;
	
    if (!pTransport->connected) /* proceed disconnect */
    {
    	LOGERR(CM_TRC_LEVEL_ERROR, "Connection broken with %s", cmWDump(pServer->item.name));

        /* match with request */
    	cmListIteratorStart(&pServer->expectedResponses, &iterator);
	    while (cmListIteratorHasNext(&iterator))
	    {
		    Match * pMatch;
    		
		    pMatch = (Match *)cmListIteratorNext(&iterator);    
		    if (pMatch->server == pServer) 
		    {
                /* signal the first match */
			    cmListItemRemove((CMItem *)pMatch);
    		    cmThreadCondSignal(pMatch->cond);

                /* remove others */
	            while (cmListIteratorHasNext(&iterator))
	            {
		            pMatch = (Match *)cmListIteratorNext(&iterator);    
		            if (pMatch->server == pServer) 
		            {
        			    cmListItemRemove((CMItem *)pMatch);
                    }
                }
			    cmListIteratorTerminate(&iterator);
			    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
			    return;
		    }
	    }
	    cmListIteratorTerminate(&iterator);

    	LOGERR(CM_TRC_LEVEL_ERROR, "Response not matched. server: %s", cmWDump(pServer->item.name));
	    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	    return;
    }

    /* read & parse SMB header */
    res = ccTransportReceiveBytes(pTransport, buffer, sizeof(buffer));
    if (NQ_FAIL == res)
    {
	    ccTransportReceiveEnd(&pServer->transport);
	    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	    return;
    }
    if (0 != syMemcmp(buffer, SIGNATURE, sizeof(SIGNATURE)))
    {
	    ccTransportReceiveEnd(&pServer->transport);
	    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	    return;
    }

    cmBufferReaderInit(&reader, buffer, res); /* starting from SMB header */
    cmSmbHeaderRead(&header, &reader);

    /* match with request */
	cmListIteratorStart(&pServer->expectedResponses, &iterator);
	while (cmListIteratorHasNext(&iterator))
	{
		Match * pMatch;
		pMatch = (Match *)cmListIteratorNext(&iterator);
		if (pMatch->server == pServer && pMatch->mid == header.mid) 
		{ 
			cmListIteratorTerminate(&iterator);
			pMatch->response->header = header;              /* header start address will be wrong */
			cmBufferReaderSkip(&reader, sizeof(NQ_UINT16)); /* word count */

			cmListItemRemove((CMItem *)pMatch);
			if (pServer->useSigning && NULL != pMatch->hdrBuf)
				syMemcpy(pMatch->hdrBuf, buffer, SMB_HEADERSIZE);
            if (NULL != commandDescriptors[header.command].callback)
			{
				commandDescriptors[header.command].callback(pServer, pMatch);
			}
			else
			{	
   	                if (pServer->transport.recv.remaining > 0)
	                {
                        Response * pResponse = pMatch->response;  /* associated response */
		                pResponse->tailLen = pServer->transport.recv.remaining;
		                pResponse->buffer = cmMemoryAllocate(pResponse->tailLen);
		                if (NULL != pResponse->buffer)
		                {
		                    if (pResponse->tailLen == ccTransportReceiveBytes(&pServer->transport, pResponse->buffer, pResponse->tailLen))
		                    {
		                        cmBufferReaderInit(&pResponse->reader, pResponse->buffer, pResponse->tailLen);
		                        pResponse->header._start = 	/* set virtual header start */
			                        pResponse->buffer - 
			                        SMB_HEADERSIZE;	/* shift back on header size     */
                            }
                        }
                    }
	                ccTransportReceiveEnd(&pServer->transport);
					cmThreadCondSignal(pMatch->cond);
			}
        	ccServerPostCredits(pServer, 1);	/* count MPX */	
			LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
			return;
		}
	}
	cmListIteratorTerminate(&iterator);
    ccTransportReceiveEnd(&pServer->transport);
	LOGERR(CM_TRC_LEVEL_ERROR, "Response not matched. Mid: %d server: %s", header.mid, cmWDump(pServer->item.name));
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

static NQ_STATUS doNegotiate(CCServer * pServer, CMBlob * inBlob)
{
	Request request;		/* request descriptor */
	Response response;		/* response descriptor */
	const CCCifsSmb ** dialects;	/* pointer to an array of supported dialects */
	NQ_UINT16 numDialects;	/* number of dialects */
	NQ_UINT16 tempUint16;	/* for parsing 2-byte values */
	NQ_UINT32 tempUint32;	/* for parsing 4-byte values */
	NQ_BYTE tempByte;		/* for parsing byte values */
	NQ_COUNT packetLen;		/* packet length of both in and out packets */
	NQ_STATUS res;			/* exchange status */
	NQ_UINT16 actualDialects;	/* number of dialects to negotiate */
	NQ_UINT16 dialectIndex;		/* dialect index in response */
	NQ_INT i;				    /* just a counter */
	NQ_UINT16 byteCount = 0;	/* to calculate bytes */	
    NQ_UINT32 rawBuffSize;      /* buffer size for raw operations */
    NQ_BOOL statusNT;           /* TRUE if error is NT False if it isnt */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	if (!prepareSingleRequest(pServer, &request, SMB_COM_NEGOTIATE))
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_OUTOFMEMORY;
	}
	
	/* initialize correspondance with transports */
	ccTransportSetResponseCallback(&pServer->transport, anyResponseCallback, pServer);
	
	numDialects = (NQ_UINT16)ccCifsGetDialects(&dialects);
	for (i = 0, actualDialects = 0; i < numDialects; i++)
	{
		const CCCifsSmb * pDialect = dialects[i];
		
		if (pDialect->name != NULL)
			actualDialects++;
	}
	/* compose request */
	writeHeader(&request);
	markByteCount(&request, 0);
	numDialects = (NQ_UINT16)ccCifsGetDialects(&dialects);
    if (soloMode)
    {
        NQ_COUNT nameLen;	/* dialect name length */
	    
        nameLen = (NQ_COUNT)syStrlen(dialect.name);
		cmBufferWriteByte(&request.writer, 2);
        cmBufferWriteBytes(&request.writer, (NQ_BYTE *)dialect.name, nameLen);
		cmBufferWriteByte(&request.writer, 0);
		byteCount = (NQ_UINT16)(byteCount + (nameLen + 2));
    }
    else
    {
	    for (i = 0, byteCount = 0; i < numDialects; i++)
	    {
		    const CCCifsSmb * pDialect = dialects[i];
		    if (pDialect->name != NULL)
		    {
			    NQ_COUNT nameLen;	/* dialect name length */
    			
			    nameLen = (NQ_COUNT)syStrlen(pDialect->name);
			    cmBufferWriteByte(&request.writer, 2);
			    cmBufferWriteBytes(&request.writer, (NQ_BYTE *)pDialect->name, nameLen);
			    cmBufferWriteByte(&request.writer, 0);
			    byteCount = (NQ_UINT16)(byteCount + (nameLen + 2));
		    }
	    }
    }
    writeByteCount(&request, 0);
	
	/* send and receive. Since no context was established yet - this is done inlined */
	packetLen = cmBufferWriterGetDataCount(&request.writer) - 4;	/* NBT header */
    ccTransportLock(&pServer->transport);
	if (!ccTransportSendSync(
			&pServer->transport, 
			request.buffer, 
			packetLen,
			packetLen
			)
		)
	{
        ccTransportUnlock(&pServer->transport);
		cmBufManGive(request.buffer);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return (NQ_STATUS)syGetLastError();
	}
	cmBufManGive(request.buffer);
	response.buffer = ccTransportReceiveAll(&pServer->transport, &packetLen);
    ccTransportUnlock(&pServer->transport);
	if (NULL == response.buffer)
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_OUTOFMEMORY;
	}
	if (0xFF != response.buffer[0])
	{
#ifdef UD_NQ_INCLUDESMB2
		res = ccSmb20DoNegotiateResponse(pServer, response.buffer, packetLen, inBlob);
		if (NQ_SUCCESS != res)
		{
			cmBufManGive(response.buffer);
			LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
			return res;
		}
#else /* UD_NQ_INCLUDESMB2 */
        LOGERR(CM_TRC_LEVEL_ERROR, "SMB2 not supported");
	    cmBufManGive(response.buffer);
	    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	    return NQ_ERR_NOSUPPORT;
#endif /* UD_NQ_INCLUDESMB2 */
	}
	else
	{
		cmBufferReaderInit(&response.reader, response.buffer, packetLen); /* starting from SMB header */
		cmSmbHeaderRead(&response.header, &response.reader);
		res = (NQ_STATUS)response.header.status;
        statusNT = (response.header.flags2 & SMB_FLAGS2_32_BIT_ERROR_CODES);
        sySetLastError((NQ_UINT32)ccErrorsStatusToNq((NQ_UINT32)res, statusNT));
        res = (NQ_STATUS)ccErrorsStatusToNq((NQ_UINT32)res, statusNT);
        if (NQ_SUCCESS != res)
        {
            cmBufManGive(response.buffer);
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return res;
        }
        cmBufferReadByte(&response.reader, &tempByte); /* word count */

        /* parse response */
        pServer->capabilities = 0;
        cmBufferReadUint16(&response.reader, &dialectIndex);		/* dialect */
        cmBufferReadByte(&response.reader, &tempByte);			    /* security mode */
        pServer->userSecurity = (tempByte & SMB_SECURITY_USER) ? TRUE : FALSE; 
        if (tempByte & 0x004)
        {
            pServer->capabilities |= CC_CAP_MESSAGESIGNING;
        }
        if (0 == (tempByte & 0x002))
        {
            cmBufManGive(response.buffer);
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return NQ_ERR_NOSUPPORT;
        }
        cmBufferReadUint16(&response.reader, &tempUint16);          /* MPX count */
        pServer->credits = (NQ_UINT32)tempUint16;
        cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT16));	/* max VCs */
        cmBufferReadUint32(&response.reader, &pServer->maxTrans);	/* max buffer size */
        if (pServer->maxTrans >= 0x20000)   /* fix for Leopard and Lion hopefully temporary bug of BE */
            pServer->maxTrans = 0xFFFF;
        cmBufferReadUint32(&response.reader, &rawBuffSize);	        /* max raw buffer size */
        pServer->maxRead  = pServer->maxTrans - 64;
        pServer->maxWrite = pServer->maxRead;
        cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT32));	/* session key */
        cmBufferReadUint32(&response.reader, &tempUint32);			/* capabilities */
        if (SMB_CAP_DFS & tempUint32)
        {
            pServer->capabilities |= CC_CAP_DFS;
        }
        if (SMB_CAP_INFOLEVEL_PASSTHRU & tempUint32)
		{
			pServer->capabilities |= CC_CAP_INFOPASSTHRU;
		}
		cmBufferReaderSkip(&response.reader, 2 * sizeof(NQ_UINT32) + sizeof(NQ_UINT16));	/* system time + time zone */
        if (0 == (pServer->capabilities & CC_CAP_MESSAGESIGNING))
        {
            if (SMB_CAP_LARGE_READX & tempUint32)
            {
                pServer->maxRead = 60*1024;
            }
            if (SMB_CAP_LARGE_WRITEX & tempUint32)
            {
                pServer->maxWrite = rawBuffSize - 64;
            }
        }
		cmBufferReadByte(&response.reader, &tempByte);					/* challenge length */
		cmBufferReadUint16(&response.reader, &byteCount);	/* byte count */
        if (0 == byteCount)
        {
        	cmBufManGive(response.buffer);
	
	        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return NQ_ERR_NOSUPPORT;
        }
		if (0 == tempByte)	/* extended security */
		{
			cmBufferReaderSkip(&response.reader, 16);	/* server GUID */
			inBlob->data = cmMemoryAllocate((NQ_UINT)(byteCount - 16));
		    if (NULL == inBlob->data && byteCount > 16)
		    {
			    cmBufManGive(response.buffer);
			    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
			    return NQ_ERR_OUTOFMEMORY;
		    }
		    inBlob->len = (NQ_COUNT)(byteCount - 16);
		    cmBufferReadBytes(&response.reader, inBlob->data, inBlob->len);				/* challenge */	
		}
		else
		{
            pServer->useExtendedSecurity = FALSE;
            pServer->firstSecurityBlob.len = tempByte;
			pServer->firstSecurityBlob.data = cmMemoryAllocate((NQ_COUNT)tempByte);
		    if (NULL == pServer->firstSecurityBlob.data)
		    {
			    cmBufManGive(response.buffer);
			    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
			    return NQ_ERR_OUTOFMEMORY;
		    }
		    cmBufferReadBytes(&response.reader, pServer->firstSecurityBlob.data, pServer->firstSecurityBlob.len); /* encryption key */	
		}
		
		/* set dialect */
		for (i = 0; i < numDialects; i++)
		{
			const CCCifsSmb * pDialect = dialects[i];
			
			if (pDialect->name != NULL)
            {
				if (0 == dialectIndex--)
				{
					pServer->smb = dialects[i];
					break;
				}
            }
		}
	}
	cmBufManGive(response.buffer);
	
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return NQ_SUCCESS;	 
}

static NQ_STATUS doSessionSetup(CCUser * pUser, const CMBlob * pass1, const CMBlob * pass2)
{
	Request request;		/* request descriptor */
	Response response;		/* response descriptor */
	NQ_STATUS res;			/* exchange status */
    CCServer * pServer;     /* server pointer */
    Context * pContext;     /* SMB context pointer */
    const NQ_WCHAR * pDecorator;    /* pointer to @ sign in account name */
	NQ_UINT16 tempUint16;   /* for parsing 16-bit values */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    pServer = pUser->server;
	
	if (pServer->smbContext == NULL)
	{
		LOGERR(CM_TRC_LEVEL_ERROR, " smbContext in CCServer ibject is missing");
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NQ_ERR_NOTCONNECTED;
	}
	
    if (!prepareSingleRequest(pServer, &request, SMB_COM_SESSION_SETUP_ANDX))
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_OUTOFMEMORY;
	}

    if (pServer->capabilities & CC_CAP_MESSAGESIGNING)
        request.header.flags2 |= SMB_FLAGS2_SMB_SECURITY_SIGNATURES;

    pContext = (Context *)pServer->smbContext;
    pContext->mid = 0;
    pServer->useExtendedSecurity = FALSE;   /* deny extended security */
	
	/* compose request */
	writeHeader(&request);
    cmBufferWriteByte(&request.writer, SMB_SESSIONSETUPANDX_REQUEST_WORDCOUNT); /* for low security SessionSetup */
    writeAndX(&request);
    cmBufferWriteUint16(&request.writer, 0xFFFF);                       /* MaxBufferSize */
    cmBufferWriteUint16(&request.writer, (NQ_UINT16)pUser->server->credits);       /* MaxMpxCount */
    cmBufferWriteUint16(&request.writer, pServer->vcNumber);            /* VcNumber */
    cmBufferWriteUint32(&request.writer, 0);                            /* SessionKey */
    cmBufferWriteUint16(&request.writer, pass1->data == NULL? 0 : (NQ_UINT16)pass1->len);  /* OEMPasswordLen */
    cmBufferWriteUint16(&request.writer, pass2->data == NULL? 0 : (NQ_UINT16)pass2->len);  /* UnicodePasswordLen */
    cmBufferWriteUint32(&request.writer, 0);                            /* reserved */
    cmBufferWriteUint32(&request.writer,                                /* capablities */
        SMB_CAP_LARGE_FILES |
        SMB_CAP_UNICODE |
        SMB_CAP_NT_SMBS |
        SMB_CAP_LARGE_READX | 
        SMB_CAP_LARGE_WRITEX |
        SMB_CAP_NT_STATUS
        );
    markByteCount(&request, 0);
    cmBufferWriteBytes(&request.writer, pass1->data, pass1->data == NULL? 0 : pass1->len);       /* OEMPassword */
    cmBufferWriteBytes(&request.writer, pass2->data, pass2->data == NULL? 0 : pass2->len);       /* UnicodePassword */
    cmBufferWriterAlign(&request.writer, request.header._start, 2);     /* pad */
    pDecorator = cmWStrchr(pUser->item.name, cmWChar('@'));
    if (NULL != pDecorator)
    {
        cmBufferWriteBytes(&request.writer, (NQ_BYTE *)pUser->item.name, (NQ_COUNT)((NQ_BYTE *)pDecorator - (NQ_BYTE *)pUser->item.name));                /* account */
        cmBufferWriteUint16(&request.writer, 0);                        /* zero terminated */
    }
    else
    {
        cmBufferWriteUnicode(&request.writer, pUser->item.name);                /* account */
    }
    cmBufferWriteUnicode(&request.writer, pUser->credentials->domain.name);     /* domain */
    cmBufferWriteAsciiAsUnicodeN(&request.writer, SY_OSNAME, 1000, CM_BSF_WRITENULLTERM);         /* OS */
    cmBufferWriteAsciiAsUnicodeN(&request.writer, "NQ", 1000, CM_BSF_WRITENULLTERM);              /* native LAN manager */
    writeByteCount(&request, 0);

    res = sendReceive(pServer, pUser, &request, &response);
	cmBufManGive(request.buffer);
	if (NQ_SUCCESS != res)
	{
	    cmU64Zero(&pUser->uid);
		cmBufManGive(response.buffer);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
	}
	/* parse response */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_BYTE) * 3 + sizeof(NQ_UINT16));	/* WordCount+AndXComand+AndXReserved+AndXOffset */	
	cmBufferReadUint16(&response.reader, &tempUint16);  /* Action */
	if (tempUint16 & 0x1)
		pUser->isGuest = TRUE;
    pUser->uid.high = 0;
    pUser->uid.low = (NQ_UINT32)response.header.uid;
    if (NULL == pServer->masterUser && !pUser->isAnonymous)
    {
        pServer->masterUser = (CMItem *)pUser;
    }

	cmBufManGive(response.buffer);

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return NQ_SUCCESS;
}

static NQ_STATUS doSessionSetupExtended(CCUser * pUser, const CMBlob * outBlob, CMBlob * inBlob)
{
	Request request;		/* request descriptor */
	Response response;		/* response descriptor */
	NQ_STATUS res;			/* exchange status */
    CCServer * pServer;     /* server pointer */
    CMBlob blob;            /* response blob */
    NQ_UINT16 tempUint16;   /* for parsing 16-bit values */
    Context * pContext;     /* SMB context pointer */
    NQ_BOOL realUserLogged; /* TRUE when user was already logged once */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    pServer = pUser->server;

	if (pServer->smbContext == NULL)
	{
		LOGERR(CM_TRC_LEVEL_ERROR, " smbContext in CCServer ibject is missing");
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NQ_ERR_NOTCONNECTED;
	}
	
    if (!prepareSingleRequest(pServer, &request, SMB_COM_SESSION_SETUP_ANDX))
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_OUTOFMEMORY;
	}
    realUserLogged = pServer->isLoggedIn;

    if (pServer->capabilities & CC_CAP_MESSAGESIGNING)
        request.header.flags2 |= SMB_FLAGS2_SMB_SECURITY_SIGNATURES;

    pContext = (Context *)pServer->smbContext;
    pContext->mid = pContext->mid <= 2 ? 0 : (NQ_UINT16)pContext->mid;

	/* compose request */
    request.header.uid = (NQ_UINT16)pUser->uid.low;
	writeHeader(&request);
    cmBufferWriteByte(&request.writer, SMB_SESSIONSETUPANDXSSP_REQUEST_WORDCOUNT); /* for high security SessionSetup */
    writeAndX(&request);
    cmBufferWriteUint16(&request.writer, 0xFFFF);                       /* MaxBufferSize */
    cmBufferWriteUint16(&request.writer, (NQ_UINT16)pServer->credits);             /* MaxMpxCount */
    cmBufferWriteUint16(&request.writer, 0);                            /* VcNumber */
    cmBufferWriteUint32(&request.writer, 0);                            /* SessionKey */
    cmBufferWriteUint16(&request.writer, (NQ_UINT16)outBlob->len);                 /* SecurityBlobLength */
    cmBufferWriteUint32(&request.writer, 0);                            /* reserved */
    cmBufferWriteUint32(&request.writer,                                /* capablities */
        SMB_CAP_LARGE_FILES |
        SMB_CAP_UNICODE |
        SMB_CAP_NT_SMBS |
        SMB_CAP_EXTENDED_SECURITY |
        SMB_CAP_LARGE_READX | 
        SMB_CAP_LARGE_WRITEX |
        SMB_CAP_NT_STATUS
        );
    markByteCount(&request, 0);
    cmBufferWriteBytes(&request.writer, outBlob->data, outBlob->len);   /* SecurityBlob */
    cmBufferWriterAlign(&request.writer, request.header._start, 2);     /* pad */
    cmBufferWriteAsciiAsUnicodeN(&request.writer, SY_OSNAME, 1000, CM_BSF_WRITENULLTERM);         /* OS */
    cmBufferWriteAsciiAsUnicodeN(&request.writer, "NQ", 1000, CM_BSF_WRITENULLTERM);              /* native LAN manager */
    writeByteCount(&request, 0);

	res = sendReceive(pServer, pUser, &request, &response);
	cmBufManGive(request.buffer);
	if (NQ_SUCCESS != res && NQ_ERR_MOREDATA != res)
	{
	    if (response.buffer != NULL)
            cmBufManGive(response.buffer);
	    cmU64Zero(&pUser->uid);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
	}
    
	/* parse response */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_BYTE) * 3 + sizeof(NQ_UINT16));	/* WordCount+AndXComand+AndXReserved+AndXOffset */
	cmBufferReadUint16(&response.reader, &tempUint16); /* Action */
	pUser->isGuest = (tempUint16 & 0x1) ? TRUE : FALSE;
    cmBufferReadUint16(&response.reader, &tempUint16);	        /* SecurityBlobLength */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT16));	/* ByteCount */
	blob.data = cmBufferReaderGetPosition(&response.reader);
    blob.len = tempUint16;
    if (0 != blob.len)
		*inBlob = cmMemoryCloneBlob(&blob);

	cmBufManGive(response.buffer);
    pUser->uid.high = 0;
    pUser->uid.low = (NQ_UINT32)response.header.uid;

    if (pServer->capabilities & CC_CAP_MESSAGESIGNING)
    {
        if (pServer->maxTrans < (32*1024))   
            pServer->credits = 10;
    }
    if (res == NQ_SUCCESS && !realUserLogged && !pUser->isAnonymous)
        pContext->mid = 2;
    if (NQ_SUCCESS == res && NULL == pServer->masterUser && !pUser->isAnonymous)
    {
        pServer->masterUser = (CMItem *)pUser;
    }

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return res;
}

static NQ_STATUS doLogOff(CCUser * pUser)
{
	Request request;		/* request dscriptor */
	Response response;		/* response descriptor */
	CCServer * pServer;		/* server object pointer */
	NQ_STATUS res;			/* exchange result */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
    
    pServer = pUser->server;
    if (!prepareSingleRequest(pServer, &request, SMB_COM_LOGOFF_ANDX))
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_OUTOFMEMORY;
	}

	/* compose request */
    request.header.uid = (NQ_UINT16)pUser->uid.low;
	writeHeader(&request);
    writeAndX(&request);
	cmBufferWriteUint16(&request.writer, 0);		/* ByteCount */

	res = sendReceive(pServer, pUser, &request, &response);
	cmBufManGive(request.buffer);
	if (NQ_SUCCESS != res)
	{
		cmBufManGive(response.buffer);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
	}

	/* parse response - noting to parse */

	cmBufManGive(response.buffer);

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return NQ_SUCCESS;
}

static NQ_STATUS doTreeConnect(CCShare * pShare)
{
	Request request;		/* request dscriptor */
	Response response;		/* response descriptor */
	CCServer * pServer;		/* server object pointer */
	CCUser * pUser;			/* user object pointer */
	NQ_UINT16 tempUint16;	/* for parsing 2-byte values */
	NQ_WCHAR * path;		/* full network path */
	NQ_STATUS res;			/* exchange result */
#define SERVICE "?????"    /* SMB "Service" */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	pUser = pShare->user;
	pServer = pUser->server;
    if (!prepareSingleRequest(pServer, &request, SMB_COM_TREE_CONNECT_ANDX))
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_OUTOFMEMORY;
	}
	
	/* compose request */
    request.header.uid = (NQ_UINT16)pUser->uid.low;
	writeHeader(&request);
    writeAndX(&request);
	cmBufferWriteUint16(&request.writer, 0);	/* Flags */
    if (!pServer->userSecurity && !pShare->isIpc)
    {
        CMBlob pass1 = {NULL, 0}, pass2 = {NULL, 0};

        amSpnegoDefineLevel(AM_MAXSECURITYLEVEL + 1, AM_CRYPTER_LM2, AM_CRYPTER_NTLM2, 0 );
        amSpnegoGeneratePasswordBlobs(pUser->credentials, 3, &pass1, &pass2, &pServer->firstSecurityBlob, NULL);
        cmBufferWriteUint16(&request.writer, (NQ_UINT16)pass1.len);	/* PasswordLength */
        markByteCount(&request, 0);
        cmBufferWriteBytes(&request.writer, pass1.data, pass1.len); /* Password */
        cmMemoryFreeBlob(&pass1);
        cmMemoryFreeBlob(&pass2);
    }
    else
    {
        cmBufferWriteUint16(&request.writer, 1);	/* PasswordLength */
        markByteCount(&request, 0);
        cmBufferWriteByte(&request.writer, 0);	    /* Password */
    }
    cmBufferWriterAlign(&request.writer, request.header._start, 2);     /* pad */
	if (pServer->useName)
    {
	    path = ccUtilsComposeRemotePathToShare(pServer->item.name, pShare->item.name);
    }
    else
    {
        NQ_WCHAR  * ipW;
        NQ_CHAR   * ip;

        ip = (NQ_CHAR *)cmMemoryAllocate(CM_IPADDR_MAXLEN * sizeof(NQ_CHAR));
        ipW = (NQ_WCHAR *)cmMemoryAllocate(CM_IPADDR_MAXLEN * sizeof(NQ_WCHAR));
        
        cmIpToAscii(ip, &pServer->ips[0]);
        cmAnsiToUnicode(ipW, ip);
        path = ccUtilsComposeRemotePathToShare(ipW, pShare->item.name);
        cmMemoryFree(ip);
        cmMemoryFree(ipW);
    }
	if (NULL == path)
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return FALSE;
	}
    cmBufferWriteUnicode(&request.writer, path);                    /* Path */
    cmBufferWriteBytes(&request.writer, (NQ_BYTE *)SERVICE, sizeof(SERVICE));  /* Service */
    writeByteCount(&request, 0);
			
	res = sendReceive(pServer, pUser, &request, &response);
	cmMemoryFree(path);
	cmBufManGive(request.buffer);
	if (NQ_SUCCESS != res)
	{
		cmBufManGive(response.buffer);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
	}

	/* parse response */
	pShare->tid = (NQ_UINT32)response.header.tid;
	cmBufferReaderSkip(&response.reader, sizeof(NQ_BYTE) * 3 + sizeof(NQ_UINT16));	/* WordCount+AndXComand+AndXReserved+AndXOffset */
	cmBufferReadUint16(&response.reader, &tempUint16);	/* OptionalSupport */	
    pShare->flags = 0;
    if (tempUint16 & SMB_TREECONNECTANDX_SHAREISINDFS)
        pShare->flags |= CC_SHARE_IN_DFS;

	cmBufManGive(response.buffer);

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return NQ_SUCCESS;
}

static NQ_STATUS doTreeDisconnect(CCShare * pShare)
{
	return exchangeEmptyCommand(pShare, SMB_COM_TREE_DISCONNECT);
}

static NQ_STATUS doCreate(CCFile * pFile)
{
	Request request;			/* request dscriptor */
	Response response;			/* response descriptor */
	CCServer * pServer;			/* server object pointer */
	CCShare * pShare;			/* share object pointer */
	NQ_UINT16 nameLen;			/* name length in bytes (not including terminator) */
	NQ_STATUS res;				/* exchange result */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	pShare = pFile->share;

	pServer = pShare->user->server;
    if (!prepareSingleRequestByShare(&request, pShare, SMB_COM_NT_CREATE_ANDX))
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_OUTOFMEMORY;
	}
	
	/* compose request */
	writeHeader(&request);
    writeAndX(&request);
    nameLen = (NQ_UINT16)(sizeof(NQ_WCHAR) * syWStrlen(pFile->item.name));

    cmBufferWriteByte(&request.writer, 0);	                    /* reserved */
    cmBufferWriteUint16(&request.writer, nameLen);	            /* NameLength */
	cmBufferWriteUint32(&request.writer, 0);	                /* Flags */
	cmBufferWriteUint32(&request.writer, 0);	                /* RootDirectoryFID */
    cmBufferWriteUint32(&request.writer, pFile->accessMask);    /* DesiredAccess */
    cmBufferWriteUint32(&request.writer, 0);                    /* AllocationSize */
    cmBufferWriteUint32(&request.writer, 0);                    /* AllocationSize */
    cmBufferWriteUint32(&request.writer, pFile->attributes);    /* ExtAttributes */
	cmBufferWriteUint32(&request.writer, pFile->sharedAccess);	/* ShareAccess */
    cmBufferWriteUint32(&request.writer, pFile->disposition);	/* CreateDisposition */
	cmBufferWriteUint32(&request.writer, pFile->options);		/* CreateOptions */
	cmBufferWriteUint32(&request.writer, 2);		            /* ImpersonationLevel */
	cmBufferWriteByte(&request.writer, 3);		                /* SecurityFlags */
    markByteCount(&request, 0);
	/* file name */
	cmBufferWriterAlign(&request.writer, request.header._start, 2);
	cmBufferWriteUnicode(&request.writer, pFile->item.name);	/* FileName */
    writeByteCount(&request, 0);

	res = sendReceive(pServer, pShare->user, &request, &response);
	cmBufManGive(request.buffer);
	if (NQ_SUCCESS != res)
	{
        cmBufManGive(response.buffer);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return res;
	}

	/* parse response */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_BYTE) * 3 + sizeof(NQ_UINT16));	/* WordCount+AndXComand+AndXReserved+AndXOffset */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_BYTE));		/* oplock level */
    cmBufferReadUint16(&response.reader, FID(pFile));	        /* FID */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT32));	/* create action */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT64));	/* creation time */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT64));	/* last access time */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT64));	/* last write time */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT64));	/* change time */
	cmBufferReadUint32(&response.reader, &pFile->attributes);	/* attributes */

	cmBufManGive(response.buffer);

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return NQ_SUCCESS;
}

static NQ_STATUS doRestoreHandle(CCFile * pFile)
{
	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return NQ_ERR_NOSUPPORT;
}

static NQ_STATUS doClose(CCFile * pFile)
{
	Request request;		/* request dscriptor */
	Response response;		/* response descriptor */
	CCServer * pServer;		/* server object pointer */
	CCShare * pShare;		/* share object pointer */
	NQ_UINT16 * pFid;       /* fid */
	NQ_STATUS res;			/* exchange result */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	pShare = pFile->share;
	pServer = pShare->user->server;
    pFid = FID(pFile);
    if (!prepareSingleRequestByShare(&request, pShare, SMB_COM_CLOSE))
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_OUTOFMEMORY;
	}
	
	/* compose request */
	writeHeader(&request);
	cmBufferWriteUint16(&request.writer, *pFid);                /* FID */
	cmBufferWriteUint32(&request.writer, 0);		            /* LastTimeModified */
	cmBufferWriteUint32(&request.writer, 0);		            /* LastTimeModified */
    markByteCount(&request, 0);                 

	res = sendReceive(pServer,  pShare->user, &request, &response);
	cmBufManGive(request.buffer);
	if (NQ_SUCCESS != res)
	{
		cmBufManGive(response.buffer);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
	}

	/* parse response - we ingnore response parameters */

	cmBufManGive(response.buffer);

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return NQ_SUCCESS;
}

static NQ_STATUS doQueryDfsReferrals(CCShare * pShare, const NQ_WCHAR * path, CCCifsParseReferral parser, CMList * list)
{
	Request request;		/* request dscriptor */
	Response response;		/* response descriptor */
	CCServer * pServer;		/* server object pointer */
	NQ_STATUS res;			/* exchange result */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	pServer = pShare->user->server;
    if (!prepareSingleRequestByShare(&request, pShare, SMB_COM_TRANSACTION2))
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_OUTOFMEMORY;
	}
	
	/* compose request */
	writeHeader(&request);
    markTrans2Start(&request, SMB_TRANS2_GETDFSREFERRAL); 
    /* T2 params */
	cmBufferWriteUint16(&request.writer, 4);		            /* max refrerral level */
    cmBufferWriteUnicode(&request.writer, path);	            /* file name */
    markTransData(&request);
    writeTrans2(pServer, &request, 0, 0);            

	res = sendReceive(pServer, pShare->user, &request, &response);
	cmBufManGive(request.buffer);
	if (NQ_SUCCESS != res)
	{
		cmBufManGive(response.buffer);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
	}

	/* parse response */
    parseTrans(&response);
    setTransData(&response);
	parser(&response.reader, list);

    cmBufManGive(response.buffer);

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return NQ_SUCCESS;
}

static NQ_STATUS doFindOpen(CCSearch * pSearch)
{
	SearchContext * pContext;	/* casted pointer */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
	
	/* create context */
	pContext = cmMemoryAllocate(sizeof(SearchContext));
	if (NULL == pContext)
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_OUTOFMEMORY;
	}
	pSearch->context = pContext;
	pContext->findFirst = TRUE;	
    pContext->eos = FALSE;
    pContext->sidAvailable = FALSE;

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return NQ_SUCCESS;
}

static NQ_STATUS doFindMore(CCSearch * pSearch)
{
	SearchContext * pContext;	/* casted pointer */
	Request request;		    /* request descriptor */
	Response response;		    /* response descriptor */
	CCServer * pServer;		    /* server object pointer */
	NQ_STATUS res;			    /* exchange result */
    NQ_UINT16 level;            /* info level */
    NQ_UINT16 temp16;           /* for parsing 16 bit values */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    pContext = (SearchContext *)pSearch->context;
    if (pContext->eos)
    {
        pContext->sid = 0xFFFF;
	    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NQ_ERR_NOFILES;
    }

    pServer = pSearch->server;
    if (!prepareSingleRequestByShare(&request, pSearch->share, SMB_COM_TRANSACTION2))
	{
        pContext->sid = 0xFFFF;
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_OUTOFMEMORY;
	}
	
	/* compose request */
	writeHeader(&request);
    markTrans2Start(&request, pContext->findFirst? SMB_TRANS2_FINDFIRST : SMB_TRANS2_FINDNEXT); 
    /* T2 params */
    level = SMB_FINDFIRST2_FINDFILEBOTHDIRECTORYINFO;               /* level:260 */
    if (pContext->findFirst)
    {
	    cmBufferWriteUint16(&request.writer, 0x16);		            /* search attributes */
	    cmBufferWriteUint16(&request.writer, 0xFFFE);     	        /* search count */
	    cmBufferWriteUint16(&request.writer, 0x4|0x2);	            /* flags */
	    cmBufferWriteUint16(&request.writer, level);   	            /* level */
	    cmBufferWriteUint32(&request.writer, 0);   	                /* storage type */
        cmBufferWriteUnicode(&request.writer, pSearch->item.name);	/* search pattern */
    }
    else
    {
        cmBufferWriteUint16(&request.writer, pContext->sid);        /* SID */
	    cmBufferWriteUint16(&request.writer, 0xFFFE);   	        /* search count */
	    cmBufferWriteUint16(&request.writer, level);   	            /* level */
	    cmBufferWriteUint32(&request.writer, pContext->resumeKey);  /* resume key */
	    cmBufferWriteUint16(&request.writer, 0x4 | 0x8);           /* flags */
        cmBufferWriteBytes(
            &request.writer, 
            pSearch->lastFile.data, 
            pSearch->lastFile.len
            );                                                      /* file name */
    }
    markTransData(&request);
    writeTrans2(pServer, &request, 10, 0);            

    res = sendReceive(pServer, pSearch->share->user, &request, &response);
	cmBufManGive(request.buffer);
	if (NQ_SUCCESS != res)
	{
        pContext->sid = 0xFFFF;
		cmBufManGive(response.buffer);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
	}

	/* parse response */
    parseTrans(&response);
    setTransParams(&response);
    if (pContext->findFirst)
    {
        cmBufferReadUint16(&response.reader, &pContext->sid);       /* SID */
        pContext->findFirst = FALSE;
    }
    pContext->sidAvailable = TRUE;
    cmBufferReadUint16(&response.reader, &temp16);                  /* search count */
    cmBufferReadUint16(&response.reader, &temp16);                  /* EOS */
    pContext->eos = (0 != temp16);
    setTransData(&response);
	cmBufferReaderInit(
		&pSearch->parser,
		cmBufferReaderGetPosition(&response.reader),
        response.dataCount
		);
    pSearch->buffer = response.buffer;

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return NQ_SUCCESS;
}

static NQ_STATUS doFindClose(CCSearch * pSearch)
{
	SearchContext * pContext;	/* casted pointer */
	Request request;		    /* request dscriptor */
	Response response;		    /* response descriptor */
	CCServer * pServer;		    /* server object pointer */
	NQ_STATUS res;			    /* exchange result */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    pContext = (SearchContext *)pSearch->context;
    if (pContext->eos || !pContext->sidAvailable)
    {
        /* search was already closed by server */
	    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NQ_SUCCESS;
    }

    pServer = pSearch->server;
    if (!prepareSingleRequestByShare(&request, pSearch->share, SMB_COM_FIND_CLOSE2))
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_OUTOFMEMORY;
	}
	
	/* compose request */
	writeHeader(&request);
    cmBufferWriteUint16(&request.writer, pContext->sid);         /* search handle */
    markByteCount(&request, 0);

    res = sendReceive(pServer, pSearch->share->user, &request, &response);
	cmBufManGive(request.buffer);
	if (NQ_SUCCESS != res)
	{
		cmBufManGive(response.buffer);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
	}

    cmBufManGive(response.buffer);

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return NQ_SUCCESS;
}

static void writeCallback(CCServer * pServer, Match * pContext)
{
	WriteMatch * pMatch = (WriteMatch *)pContext;	/* casted pointer */
	NQ_BYTE buffer[20];								/* buffer for structure */
	NQ_UINT tailLen = pServer->transport.recv.remaining;	/* bytes remaining */
	Response * pResponse = pContext->response;				/* response structure ptr */
	NQ_UINT32 count = 0;									/* bytes written */
    NQ_UINT16 countLow;                                     /* low 16 bit of count */
    NQ_UINT16 countHigh;                                    /* high 16 bit of count */
    NQ_TIME currentTime;                                    /* Current Time for checking timed-out responses*/

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	/* receive the rest of command */
	if (tailLen != ccTransportReceiveBytes(&pServer->transport, buffer, tailLen))
	{
    	ccTransportReceiveEnd(&pServer->transport);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return;
	}
	ccTransportReceiveEnd(&pServer->transport);
	cmBufferReaderInit(&pResponse->reader, buffer, tailLen);

	/* parse the response */
	if (NQ_SUCCESS == pResponse->header.status)
	{
		cmBufferReaderSkip(&pResponse->reader, sizeof(NQ_BYTE) + 
                                               sizeof(NQ_UINT16) * 2);  /* andx command/reserved/offset */
		cmBufferReadUint16(&pResponse->reader, &countLow);	            /* count */
		cmBufferReaderSkip(&pResponse->reader, sizeof(NQ_UINT16) * 1);	/* avilable */
		cmBufferReadUint16(&pResponse->reader, &countHigh);	            /* count high */
        count = (NQ_UINT32)((countHigh << 16) + countLow);
	}
	currentTime = (NQ_TIME)syGetTime();

    /* call up */
	if ((pMatch->timeCreated + pMatch->setTimeout) > currentTime)
    {
        NQ_BOOL statusNT;                                       /* TRUE for NT stgtaus */
	    statusNT = (pResponse->header.flags2 & SMB_FLAGS2_32_BIT_ERROR_CODES);
	    pMatch->callback(pResponse->header.status == 0? 0 : (NQ_STATUS)ccErrorsStatusToNq(pResponse->header.status, statusNT), count, pMatch->context);
    }
	
	/* release context */
	cmMemoryFree(pMatch->match.response);
    cmListItemDispose((CMItem *)pMatch);

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

static NQ_STATUS doWrite(CCFile * pFile, const NQ_BYTE * data, NQ_UINT bytesToWrite, CCCifsWriteCallback callback, void * context)
{
	Request request;		    /* request dscriptor */
	CCServer * pServer;		    /* server object pointer */
	NQ_STATUS res;			    /* exchange result */
    NQ_BYTE * pDataOffset;      /* pointer to the data offset field */
    NQ_BYTE * pTemp;            /* temporray pointer in the packet */
   	NQ_UINT16 * pFid;           /* fid */
    WriteMatch * pMatch;        /* item for matching response to request */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    pServer = pFile->share->user->server;
    pFid = FID(pFile);
    if (!prepareSingleRequestByShare(&request, pFile->share, SMB_COM_WRITE_ANDX))
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_OUTOFMEMORY;
	}
	
	/* compose request */
	writeHeader(&request);
    writeAndX(&request);
    cmBufferWriteUint16(&request.writer, *pFid);                    /* fid */
    cmBufferWriteUint32(&request.writer, pFile->offset.low);        /* offset */
    cmBufferWriteUint32(&request.writer, 0);                        /* timeout */
    cmBufferWriteUint16(&request.writer, 0);                        /* write mode */
    cmBufferWriteUint16(&request.writer, 0);                        /* remaining */
    cmBufferWriteUint16(&request.writer, (NQ_UINT16)(bytesToWrite / 0x10000));   /* reserved/data length high */
    cmBufferWriteUint16(&request.writer, (NQ_UINT16)(bytesToWrite % 0x10000));   /* data length */
    pDataOffset = cmBufferWriterGetPosition(&request.writer);
    cmBufferWriterSkip(&request.writer, sizeof(NQ_UINT16));         /* data offset */
    cmBufferWriteUint32(&request.writer, pFile->offset.high);       /* offset high */
    markByteCount(&request, 0);
    cmBufferWriterAlign(&request.writer, request.header._start, 8); /* allign data */
    writeByteCount(&request, (NQ_UINT16)bytesToWrite);
    request.tail.data = (NQ_BYTE *)data;
    request.tail.len = bytesToWrite;
    pTemp = cmBufferWriterGetPosition(&request.writer);
    cmBufferWriterSetPosition(&request.writer, pDataOffset);
    cmBufferWriteUint16(&request.writer, (NQ_UINT16)(pTemp - request.header._start));   /* data offset */
    cmBufferWriterSetPosition(&request.writer, pTemp);

    /* create match */
	pMatch = (WriteMatch *)cmListItemCreate(sizeof(WriteMatch), NULL , FALSE);
	if (NULL == pMatch)
	{
    	cmBufManGive(request.buffer);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_OUTOFMEMORY;
	}
	pMatch->match.response = (Response *)cmMemoryAllocate(sizeof(Response));
	if (NULL == pMatch->match.response)
	{
    	cmBufManGive(request.buffer);
		cmMemoryFree(pMatch);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_OUTOFMEMORY;
	}
	pMatch->match.server = pFile->share->user->server;
    pMatch->timeCreated = (NQ_TIME)syGetTime();
    pMatch->setTimeout = ccConfigGetTimeout();
	pMatch->callback = callback;
	pMatch->context = context;
	cmListItemAdd(&pServer->expectedResponses, (CMItem *)pMatch, NULL);

    res = sendRequest(pServer, pFile->share->user, &request, &pMatch->match);
	cmBufManGive(request.buffer);
	if (NQ_SUCCESS != res)
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
	}

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return NQ_SUCCESS;
}

static void readCallback(CCServer * pServer, Match * pContext)
{
#define READSTRUCT_SIZE 27                          /* word count + packet words + byte count */
	ReadMatch * pMatch = (ReadMatch *)pContext;		/* casted pointer */
	NQ_BYTE buffer[64];								/* buffer for structure and padding */
	Response * pResponse = pContext->response;		/* response structure ptr */
	NQ_UINT32 count = 0;							/* bytes read */
	NQ_UINT16 countLow;								/* bytes read (low 2 bytes) */
	NQ_UINT16 countHigh;							/* bytes read (high two bytes) */
	NQ_UINT16 dataOffset;							/* data offset */
    NQ_TIME currentTime;                            /* Current Time for checking timed-out responses*/

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	/* receive the structure but not padding nor the buffer (payload) */
	if (READSTRUCT_SIZE == ccTransportReceiveBytes(&pServer->transport, buffer, READSTRUCT_SIZE))
	{
		/* parse the response */
		cmBufferReaderInit(&pResponse->reader, buffer, sizeof(buffer));
		if (NQ_SUCCESS == pResponse->header.status)
		{
			cmBufferReaderSkip(
                &pResponse->reader, 
                sizeof(NQ_BYTE) * 3 +                               /* word count + AndX command/reserved/offset */ 
                 sizeof(NQ_UINT16) * 4                              /* available, datacompaction model, reserved1 */
                );				            
			cmBufferReadUint16(&pResponse->reader, &countLow);	    /* count low */
            cmBufferReadUint16(&pResponse->reader, &dataOffset);	/* data offset */
			cmBufferReadUint16(&pResponse->reader, &countHigh);	    /* count high */
            count = (NQ_UINT32)((countHigh << 16) + countLow);
            if (dataOffset > 0 )
	        {
                dataOffset = (NQ_UINT16)(dataOffset - (SMB_HEADERSIZE + READSTRUCT_SIZE));
		        ccTransportReceiveBytes(&pServer->transport, buffer, (NQ_COUNT)dataOffset);	/* read padding */
	        }
	        ccTransportReceiveBytes(&pServer->transport, pMatch->buffer, count);	/* read into application buffer */
		}
	}
	else
	{
		count = 0;
	}
	ccTransportReceiveEnd(&pServer->transport);
    currentTime = (NQ_TIME)syGetTime();
    
    /* call up */
    if ((pMatch->timeCreated + pMatch->setTimeout) > currentTime)
    {
        NQ_BOOL statusNT;                               /* TRUE for NT stgtaus */
    
        statusNT = (pResponse->header.flags2 & SMB_FLAGS2_32_BIT_ERROR_CODES);
	    pMatch->callback(pResponse->header.status == 0? (count == 0 ? NQ_ERR_QEOF : 0) : (NQ_STATUS)ccErrorsStatusToNq(pResponse->header.status, statusNT), count, pMatch->context, count < pMatch->count);
    }
	
	/* release */
	cmMemoryFree(pMatch->match.response);
    cmListItemDispose((CMItem *)pMatch);

   	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

static NQ_STATUS doRead(CCFile * pFile, const NQ_BYTE * buffer, NQ_UINT bytesToRead, CCCifsReadCallback callback, void * context)
{
	Request request;		    /* request dscriptor */
	CCServer * pServer;		    /* server object pointer */
	NQ_STATUS res;			    /* exchange result */
   	NQ_UINT16 * pFid;           /* fid */
    ReadMatch * pMatch;         /* item for matching response to request */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    pServer = pFile->share->user->server;
    pFid = FID(pFile);
    if (!prepareSingleRequestByShare(&request, pFile->share, SMB_COM_READ_ANDX))
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_OUTOFMEMORY;
	}
	
	/* compose request */
	writeHeader(&request);
    writeAndX(&request);
    cmBufferWriteUint16(&request.writer, *pFid);                /* fid */
    cmBufferWriteUint32(&request.writer, pFile->offset.low);    /* offset */

    cmBufferWriteUint16(&request.writer, bytesToRead&0xFFFF);   /* max count of bytes to return - low */
    cmBufferWriteUint16(&request.writer, 0);                    /* min count of bytes to return - low */
    cmBufferWriteUint32(&request.writer, bytesToRead>>16);      /* max count of bytes to return - high */
    cmBufferWriteUint16(&request.writer, (bytesToRead&0xFFFF0000) == 0xFFFF0000? 0xFFFF:0x0000);
                                                                /* reserved */
    cmBufferWriteUint32(&request.writer, pFile->offset.high);   /* offset high */
    markByteCount(&request, 0);
    writeByteCount(&request, 0);

	pMatch = (ReadMatch *)cmListItemCreate(sizeof(ReadMatch), NULL , FALSE);
	if (NULL == pMatch)
	{
    	cmBufManGive(request.buffer);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_OUTOFMEMORY;
	}
	pMatch->match.response = (Response *)cmMemoryAllocate(sizeof(Response));
	if (NULL == pMatch->match.response)
	{
    	cmBufManGive(request.buffer);
		cmMemoryFree(pMatch);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_OUTOFMEMORY;
	}
	pMatch->match.server = pFile->share->user->server;
    pMatch->timeCreated = (NQ_TIME)syGetTime();
    pMatch->setTimeout = ccConfigGetTimeout();
	pMatch->callback = callback;
	pMatch->context = context;
	pMatch->count = bytesToRead;
	pMatch->buffer = (NQ_BYTE *)buffer;
	cmListItemAdd(&pServer->expectedResponses, (CMItem *)pMatch, NULL);

    res = sendRequest(pServer, pFile->share->user, &request, &pMatch->match);
	cmBufManGive(request.buffer);
	if (NQ_SUCCESS != res)
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
	}

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return NQ_SUCCESS;
}

#ifdef UD_CC_INCLUDESECURITYDESCRIPTORS

static void markNtTransStart(Request * pRequest, NQ_UINT16 ntTransCommand)
{
    pRequest->pTrans = cmBufferWriterGetPosition(&pRequest->writer);
    cmBufferWriterSkip(
        &pRequest->writer, 
        sizeof(NQ_BYTE) +                                   /* max setup count */
        sizeof(NQ_UINT16) +                                 /* reserved */
        sizeof(NQ_UINT32) * 8 +                             /* counts and offset */
        sizeof(NQ_BYTE)                                     /* setup count */
        );
	cmBufferWriteUint16(&pRequest->writer, ntTransCommand); /* subcommand */
    markByteCount(pRequest, 0);
    cmBufferWriteZeroes(&pRequest->writer, 3);              /* padding */
    markTransParams(pRequest);
}

static void writeNtTrans(CCServer * pServer, Request * pRequest, NQ_UINT16 maxParamCount, NQ_BYTE maxSetupCount, NQ_UINT32 tailLen)
{
    NQ_BYTE * pEnd;                                 /* pointer to the end of packet */
    NQ_UINT32 maxBuffer = UD_NS_BUFFERSIZE - 100;   /* for calculating max dara count */
    NQ_UINT32 dataCount;                            /* data count */

    if (maxBuffer > pServer->maxTrans - 100)
        maxBuffer = pServer->maxTrans - 100;
    pEnd = cmBufferWriterGetPosition(&pRequest->writer);
    dataCount = (NQ_UINT32)(pEnd - pRequest->pData) + tailLen;
    cmBufferWriterSetPosition(&pRequest->writer, pRequest->pTrans);
    cmBufferWriteByte(&pRequest->writer, maxSetupCount);                                /* max setup count */
    cmBufferWriterSkip(&pRequest->writer, sizeof(NQ_UINT16));                           /* reserved */
    cmBufferWriteUint32(&pRequest->writer, (NQ_UINT32)(pRequest->pData - pRequest->pParams));        /* total params count */
    cmBufferWriteUint32(&pRequest->writer, (NQ_UINT32)(pEnd - pRequest->pData + tailLen));           /* total data count */
    cmBufferWriteUint32(&pRequest->writer, maxParamCount);                              /* max params count */
    cmBufferWriteUint32(&pRequest->writer, maxBuffer);                                  /* max data count */
    cmBufferWriteUint32(&pRequest->writer, (NQ_UINT32)(pRequest->pData - pRequest->pParams));        /* params count */
    cmBufferWriteUint32(&pRequest->writer, (NQ_UINT32)(pRequest->pParams - pRequest->header._start));/* params offset */
    cmBufferWriteUint32(&pRequest->writer, dataCount);                                  /* data count */
    cmBufferWriteUint32(&pRequest->writer, dataCount ==0? 
        0: (NQ_UINT32)(pRequest->pData - pRequest->header._start));                                   /* data offset */
    cmBufferWriterSetPosition(&pRequest->writer, pEnd);
    writeByteCount(pRequest, (NQ_UINT16)tailLen);
}

static void parseNtTrans(Response * pResponse)
{
    NQ_UINT32 temp32;       /* for parsing 16-bit values */

    cmBufferReaderSkip(&pResponse->reader, sizeof(NQ_BYTE) +        /* word count */
                                           sizeof(NQ_BYTE) * 3 +    /* reserved */
                                           sizeof(NQ_UINT32) * 3);  /* skip to parameter offset */
    cmBufferReadUint32(&pResponse->reader, &temp32);                /* parameter offset */
    pResponse->pParams = pResponse->header._start + temp32;
    cmBufferReaderSkip(&pResponse->reader, sizeof(NQ_UINT32) * 1);  /* skip to data count */
    cmBufferReadUint32(&pResponse->reader, &pResponse->dataCount);  /* data count */
    cmBufferReadUint32(&pResponse->reader, &temp32);                /* data offset */
    pResponse->pData = pResponse->header._start + temp32;
}       

static NQ_STATUS doQuerySecurityDescriptor(CCFile * pFile, CMSdSecurityDescriptor * sd)
{
	Request request;		    /* request dscriptor */
	Response response;		    /* response descriptor */
	CCServer * pServer;		    /* server object pointer */
	NQ_STATUS res;			    /* exchange result */
	CMRpcPacketDescriptor in;	/* for parsing SD */
   	NQ_UINT16 * pFid;           /* fid */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    pServer = pFile->share->user->server;
    pFid = FID(pFile);
    if (!prepareSingleRequestByShare(&request, pFile->share, SMB_COM_NT_TRANSACT))
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_OUTOFMEMORY;
	}
	
	/* compose request */
	writeHeader(&request);
    markNtTransStart(&request, SMB_NTTRANSACT_QUERYSECURITYDESCRIPTOR); 
    /* NTTrans params */
	cmBufferWriteUint16(&request.writer, *pFid);	            /* FID */
	cmBufferWriteUint16(&request.writer, 0);	                /* reserved */
	cmBufferWriteUint32(&request.writer, 0x4);	                /* security information - DACL */
    markTransData(&request);
    writeNtTrans(pServer, &request, 4, 0, 0);    /* no data - no tail */            

    res = sendReceive(pServer, pFile->share->user, &request, &response);
	cmBufManGive(request.buffer);
	if (NQ_SUCCESS != res)
	{
		cmBufManGive(response.buffer);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
	}

	/* parse response */
    parseNtTrans(&response);
    setTransParams(&response);
	cmBufferReadUint32(&response.reader, &sd->length);	/* length */
    setTransData(&response);
	cmRpcSetDescriptor(&in, cmBufferReaderGetPosition(&response.reader), FALSE);
	cmSdParseSecurityDescriptor(&in, sd);			/* security descriptor */

    cmBufManGive(response.buffer);

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return NQ_SUCCESS;
}

static NQ_STATUS doSetSecurityDescriptor(CCFile * pFile, const CMSdSecurityDescriptor * sd)
{
	Request request;		    /* request dscriptor */
	Response response;		    /* response descriptor */
	CCServer * pServer;		    /* server object pointer */
	NQ_STATUS res;			    /* exchange result */
	CMRpcPacketDescriptor out;	/* for packing SD */
	NQ_BYTE * sdBuffer;			/* buffer for packing SD - the same size as SD itself */
   	NQ_UINT16 * pFid;           /* fid */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	pServer = pFile->share->user->server;
	sdBuffer = cmBufManTake(sd->length + 32);
    pFid = FID(pFile);
    if (NULL == sdBuffer)
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_OUTOFMEMORY;
	}
	cmRpcSetDescriptor(&out, sdBuffer, FALSE);
	cmSdPackSecurityDescriptor(&out, sd);

    if (!prepareSingleRequestByShare(&request, pFile->share, SMB_COM_NT_TRANSACT))
	{
		cmBufManGive(sdBuffer);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_OUTOFMEMORY;
	}
	
	/* compose request */
	writeHeader(&request);
    markNtTransStart(&request, SMB_NTTRANSACT_SETSECURITYDESCRIPTOR); 
    /* NTTrans params */
	cmBufferWriteUint16(&request.writer, *pFid);	            /* FID */
	cmBufferWriteUint16(&request.writer, 0);	                /* reserved */
	cmBufferWriteUint32(&request.writer, 0x4);	                /* security information - DACL */
    markTransData(&request);

    /* NTTrans data */
	request.tail.data = sdBuffer;
	request.tail.len = (NQ_COUNT)(out.current - sdBuffer);
    writeNtTrans(pServer, &request, 0, 0, request.tail.len);
    
    res = sendReceive(pServer, pFile->share->user, &request, &response);
	cmBufManGive(sdBuffer);
	cmBufManGive(request.buffer);
	if (NQ_SUCCESS != res)
	{
		cmBufManGive(response.buffer);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
	}

	/* parse response */
    cmBufManGive(response.buffer);

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return NQ_SUCCESS;
}

#endif /* UD_CC_INCLUDESECURITYDESCRIPTORS */

static NQ_STATUS doQueryFileInfoByHandle(CCFile * pFile, CCCifsParseFileInfoCallback callback, void * context)
{
	Request request;		    /* request dscriptor */
	Response response;		    /* response descriptor */
	CCServer * pServer;		    /* server object pointer */
	NQ_STATUS res;			    /* exchange result */
    NQ_UINT16 level;            /* information level */
    NQ_UINT16 * pFid;           /* fid */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	pServer = pFile->share->user->server;
	pFid = FID(pFile);
    if (!prepareSingleRequestByShare(&request, pFile->share, SMB_COM_TRANSACTION2))
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_OUTOFMEMORY;
	}
	
	/* compose request */
	writeHeader(&request);
    markTrans2Start(&request, SMB_TRANS2_QUERYFILEINFORMATION); 
    /* T2 params */
	cmBufferWriteUint16(&request.writer, *pFid);     	        /* FID */
    level = (pServer->capabilities & CC_CAP_INFOPASSTHRU)? SMB_PASSTHRU_FILE_ALLINFO : SMB_QUERYPATH2_NT_ALLINFO;
    cmBufferWriteUint16(&request.writer, level);	            /* info level */
    markTransData(&request);
    writeTrans2(pServer, &request, 2, 0);
    
    res = sendReceive(pServer, pFile->share->user, &request, &response);
	cmBufManGive(request.buffer);
	if (NQ_SUCCESS != res)
	{
		cmBufManGive(response.buffer);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
	}

	/* parse response */
    parseTrans(&response);
    setTransData(&response);
	(*callback)(&response.reader, context);

    cmBufManGive(response.buffer);

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return NQ_SUCCESS;
}

static NQ_STATUS doQueryFileInfoByName(CCShare * pShare, const NQ_WCHAR * fileName, CCCifsParseFileInfoCallback callback, void * context)
{
	Request request;		    /* request dscriptor */
	Response response;		    /* response descriptor */
	CCServer * pServer;		    /* server object pointer */
	NQ_STATUS res;			    /* exchange result */
    NQ_UINT16 level;            /* information level */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	pServer = pShare->user->server;
    if (!prepareSingleRequestByShare(&request, pShare, SMB_COM_TRANSACTION2))
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_OUTOFMEMORY;
	}
	
	/* compose request */
	writeHeader(&request);
    markTrans2Start(&request, SMB_TRANS2_QUERYPATHINFORMATION); 
    /* T2 params */
    level = (pServer->capabilities & CC_CAP_INFOPASSTHRU)? SMB_PASSTHRU_FILE_ALLINFO : SMB_QUERYPATH2_NT_ALLINFO;
    cmBufferWriteUint16(&request.writer, level);	            /* info level */
    cmBufferWriterSkip(&request.writer, sizeof(NQ_UINT32));     /* reserved */
    cmBufferWriteUnicode(&request.writer, fileName);
    markTransData(&request);
    writeTrans2(pServer, &request, 2, 0);
    
    res = sendReceive(pServer, pShare->user, &request, &response);
	cmBufManGive(request.buffer);  
	if (NQ_SUCCESS != res)
	{
		cmBufManGive(response.buffer);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
	}

	/* parse response */
    parseTrans(&response);
    setTransData(&response);
	(*callback)(&response.reader, context);

    cmBufManGive(response.buffer);

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return NQ_SUCCESS;
}

typedef void (* FsInfoCallback) (CMBufferReader * pReader, CCVolumeInfo * pInfo);

static NQ_STATUS queryFsInfoByLevel(CCShare * pShare, CCVolumeInfo * pInfo, NQ_UINT16 level, FsInfoCallback callback)
{
	Request request;		    /* request dscriptor */
	Response response;		    /* response descriptor */
	CCServer * pServer;		    /* server object pointer */
	NQ_STATUS res;			    /* exchange result */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	pServer = pShare->user->server;
    if (!prepareSingleRequestByShare(&request, pShare, SMB_COM_TRANSACTION2))
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_OUTOFMEMORY;
	}
	
	/* compose request */
	writeHeader(&request);
    markTrans2Start(&request, SMB_TRANS2_QUERYFSINFORMATION); 
    /* T2 params */
    cmBufferWriteUint16(&request.writer, level);	            /* info level */
    markTransData(&request);
    writeTrans2(pServer, &request, 0, 0);
    
    res = sendReceive(pServer, pShare->user, &request, &response);
	cmBufManGive(request.buffer);
	if (NQ_SUCCESS != res)
	{
		cmBufManGive(response.buffer);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
	}

	/* parse response */
    parseTrans(&response);
    setTransData(&response);
	(*callback)(&response.reader, pInfo);

    cmBufManGive(response.buffer);

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return NQ_SUCCESS;
}

void fsSizeCallback(CMBufferReader * pReader, CCVolumeInfo * pInfo)
{
	NQ_UINT64 temp64;		/* for parsing 64-bit values */
	NQ_UINT32 temp32;		/* for parsing 32-bit values */

    /* parse response */
	cmBufferReadUint64(pReader, &temp64);	/* total allocation units */
	pInfo->totalClusters = temp64.low;
	cmBufferReadUint64(pReader, &temp64);	/* available allocation units */
	pInfo->freeClusters = temp64.low;
	cmBufferReadUint32(pReader, &temp32);	/* sectors per allocation unit */
	pInfo->sectorsPerCluster = (NQ_UINT)temp32;
	cmBufferReadUint32(pReader, &temp32);	/* bytes per sectors */
	pInfo->bytesPerSector = (NQ_UINT)temp32;
}

void fsVolumeCallback(CMBufferReader * pReader, CCVolumeInfo * pInfo)
{
	NQ_UINT32 temp32;		/* for parsing 32-bit values */

    /* parse response */
    cmBufferReaderSkip(pReader, sizeof(NQ_UINT64));	/* creation time */
	cmBufferReadUint32(pReader, &temp32);				/* volume serial number */
	pInfo->serialNumber = (NQ_UINT)temp32;
}

static NQ_STATUS doQueryFsInfo(CCShare * pShare, CCVolumeInfo * pInfo)
{
	NQ_STATUS res;			    /* query result */

    /* issue two queries with different level */
    res = queryFsInfoByLevel(pShare, pInfo, SMB_QUERYFS_NT_SIZEINFO, fsSizeCallback);
    if (NQ_SUCCESS == res)
        res = queryFsInfoByLevel(pShare, pInfo, SMB_QUERYFS_NT_VOLUMEINFO, fsVolumeCallback);
	return res;
}

static NQ_STATUS writeSetFileInfo(CCFile * pFile, Request * pRequest, NQ_UINT16 level)
{
    NQ_UINT16 * pFid;           /* fid */

    pFid = FID(pFile);
    if (!prepareSingleRequestByShare(pRequest, pFile->share, SMB_COM_TRANSACTION2))
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_OUTOFMEMORY;
	}
	
	/* compose request */
	writeHeader(pRequest);
    markTrans2Start(pRequest, SMB_TRANS2_SETFILEINFORMATION); 
    /* T2 params */
    cmBufferWriteUint16(&pRequest->writer, *pFid);	        /* FID */
    cmBufferWriteUint16(&pRequest->writer, level);          /* info level */
    cmBufferWriteUint16(&pRequest->writer, 0);	            /* reserved */
    markTransData(pRequest);
    return NQ_SUCCESS;
}

static NQ_STATUS doSetFileAttributes(CCFile * pFile, NQ_UINT32 attributes)
{
	Request request;		    /* request dscriptor */
	Response response;		    /* response descriptor */
	CCServer * pServer;		    /* server object pointer */
	NQ_STATUS res;			    /* exchange result */
    NQ_UINT16 level;            /* information level */
	static const NQ_UINT64 doNotChange = 
	{ 0x0, 0x0 };	/* the "do-not-change" value in the time fields */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    pServer = pFile->share->user->server;
    level = pServer->capabilities & CC_CAP_INFOPASSTHRU? 
                SMB_PASSTHRU_FILE_BASICINFO : SMB_SETPATH2_NT_BASICINFO;
    
    res = writeSetFileInfo(pFile, &request, level);
    if (NQ_SUCCESS != res)
    {
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
    }
	cmBufferWriteUint64(&request.writer, &doNotChange);	/* creation time */
	cmBufferWriteUint64(&request.writer, &doNotChange);	/* last access time */
	cmBufferWriteUint64(&request.writer, &doNotChange);	/* last write time */
	cmBufferWriteUint64(&request.writer, &doNotChange);	/* change time */
	cmBufferWriteUint32(&request.writer, attributes);	/* file attributes */
	cmBufferWriteUint32(&request.writer, 0);			/* reserved */
    writeTrans2(pServer, &request, 2, 0);
    
    res = sendReceive(pServer, pFile->share->user, &request, &response);
	cmBufManGive(request.buffer);
	if (NQ_SUCCESS != res)
	{
		cmBufManGive(response.buffer);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
	}

	/* parse response */
    cmBufManGive(response.buffer);

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return NQ_SUCCESS;
}

static NQ_STATUS doSetFileSize(CCFile * pFile, NQ_UINT64 size)
{
	Request request;		    /* request dscriptor */
	Response response;		    /* response descriptor */
	CCServer * pServer;		    /* server object pointer */
	NQ_STATUS res;			    /* exchange result */
    NQ_UINT16 level;            /* information level */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    pServer = pFile->share->user->server;
    level = SMB_SETPATH2_NT_ENDOFFILEINFO;
    
    res = writeSetFileInfo(pFile, &request, level);
    if (NQ_SUCCESS != res)
    {
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
    }
	cmBufferWriteUint64(&request.writer, &size);	/* end of file */
    writeTrans2(pServer, &request, 2, 0);
    
    res = sendReceive(pServer, pFile->share->user, &request, &response);
	cmBufManGive(request.buffer);
	if (NQ_SUCCESS != res)
	{
		cmBufManGive(response.buffer);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
	}

	/* parse response */
    cmBufManGive(response.buffer);

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return NQ_SUCCESS;
}

static NQ_STATUS doSetFileTime(CCFile * pFile, NQ_UINT64 creationTime, NQ_UINT64 lastAccessTime, NQ_UINT64 lastWriteTime)
{
	Request request;		    /* request dscriptor */
	Response response;		    /* response descriptor */
	CCServer * pServer;		    /* server object pointer */
	NQ_STATUS res;			    /* exchange result */
    NQ_UINT16 level;            /* information level */
	static const NQ_UINT64 doNotChange = 
	{ 0x0, 0x0 };	/* the "do-not-change" value in the time fields */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    pServer = pFile->share->user->server;
    level = SMB_SETPATH2_NT_BASICINFO;
    
    res = writeSetFileInfo(pFile, &request, level);
    if (NQ_SUCCESS != res)
    {
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
    }
	cmBufferWriteUint64(&request.writer, &creationTime);	/* creation time */
	cmBufferWriteUint64(&request.writer, &lastAccessTime);	/* last access time */
	cmBufferWriteUint64(&request.writer, &lastWriteTime);	/* last write time */
	cmBufferWriteUint64(&request.writer, &doNotChange);		/* change time */
	cmBufferWriteUint32(&request.writer, 0);				/* file attributes */
	cmBufferWriteUint32(&request.writer, 0);				/* reserved */
    writeTrans2(pServer, &request, 2, 0);
    
    res = sendReceive(pServer, pFile->share->user, &request, &response);
	cmBufManGive(request.buffer);
	if (NQ_SUCCESS != res)
	{
		cmBufManGive(response.buffer);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
	}

	/* parse response */
    cmBufManGive(response.buffer);

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return NQ_SUCCESS;
}

static NQ_STATUS doSetFileDeleteOnClose(CCFile * pFile)
{
	Request request;		    /* request dscriptor */
	Response response;		    /* response descriptor */
	CCServer * pServer;		    /* server object pointer */
	NQ_STATUS res;			    /* exchange result */
    NQ_UINT16 level;            /* info level to sue */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    pServer = pFile->share->user->server;
    level = pServer->capabilities & CC_CAP_INFOPASSTHRU?
        SMB_PASSTHRU_FILE_DISPOSITIONINFO : SMB_SETPATH2_NT_DISPOSITIONINFO;
    res = writeSetFileInfo(pFile, &request, level);
    if (NQ_SUCCESS != res)
    {
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
    }
	cmBufferWriteByte(&request.writer, 1);	/* delete pending */
    writeTrans2(pServer, &request, 2, 0);
    
    res = sendReceive(pServer, pFile->share->user, &request, &response);
	cmBufManGive(request.buffer);
	if (NQ_SUCCESS != res)
	{
		cmBufManGive(response.buffer);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
	}

	/* parse response */
    cmBufManGive(response.buffer);

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return NQ_SUCCESS;
}

static NQ_STATUS doRename(CCFile * pFile, const NQ_WCHAR * newName)
{
	Request         request;		/* request dscriptor */
	Response        response;		/* response descriptor */
	CCServer *      pServer;		/* server object pointer */
	CCShare *       pShare;		    /* share object pointer */
	NQ_STATUS       res;			/* exchange result */
    NQ_BYTE *       tailData;
    CMBufferWriter  tailWriter;

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	pShare = pFile->share;
	pServer = pShare->user->server;
    if (!prepareSingleRequestByShare(&request, pShare, SMB_COM_RENAME))
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_OUTOFMEMORY;
	}
    request.tail.len = 3;
	request.tail.len += syWStrlen(pFile->item.name)*2 +2;
    request.tail.len += syWStrlen(newName)*2 +2;
    
    /* compose request */
    writeHeader(&request);
    cmBufferWriteUint16(&request.writer, 0x16);                 /* search attributes */
    markByteCount(&request, 0);   

    tailData = (NQ_BYTE *)cmMemoryAllocate(request.tail.len * sizeof(NQ_BYTE));

    cmBufferWriterInit(&tailWriter, tailData, request.tail.len);
    cmBufferWriteByte(&tailWriter, 0x4);                    /* buffer format */
	cmBufferWriteUnicodeNoNull(&tailWriter, pFile->item.name);    /* old name */
	cmBufferWriteUint16(&tailWriter, 0);
	cmBufferWriteByte(&tailWriter, 0x4);                    /* buffer format */
	cmBufferWriterSkip(&tailWriter , 1);
    cmBufferWriteUnicodeNoNull(&tailWriter, newName);             /* new name */
	cmBufferWriteUint16(&tailWriter, 0);

    request.tail.data = tailData;
    
    writeByteCount(&request, (NQ_UINT16)request.tail.len);


    cmListItemLock(&pFile->item);
    /* close the file */
  	ccCloseHandle(pFile);
    cmListItemUnlock(&pFile->item);

	res = sendReceive(pServer,  pShare->user, &request, &response);
	cmBufManGive(request.buffer);
	if (NQ_SUCCESS != res)
	{
	    cmMemoryFree(tailData);
		cmBufManGive(response.buffer);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
	}

	/* parse response - we ingnore response parameters */
    cmMemoryFree(tailData);
	cmBufManGive(response.buffer);

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return NQ_SUCCESS;
}

static NQ_STATUS doFlush(CCFile * pFile)
{
	Request request;		/* request dscriptor */
	Response response;		/* response descriptor */
	CCServer * pServer;		/* server object pointer */
	CCShare * pShare;		/* share object pointer */
    NQ_UINT16 * pFid;           /* fid */
	NQ_STATUS res;			/* exchange result */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	pShare = pFile->share;
	pServer = pShare->user->server;
	pFid = FID(pFile);
    if (!prepareSingleRequestByShare(&request, pShare, SMB_COM_FLUSH))
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_OUTOFMEMORY;
	}
	
	/* compose request */
	writeHeader(&request);
	cmBufferWriteUint16(&request.writer, *pFid);          /* FID */
    markByteCount(&request, 0);                 
	res = sendReceive(pServer, pShare->user, &request, &response);
	cmBufManGive(request.buffer);
	if (NQ_SUCCESS != res)
	{
		cmBufManGive(response.buffer);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
	}

	/* parse response - we ingnore response parameters */

	cmBufManGive(response.buffer);

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return NQ_SUCCESS;
}
 
static NQ_STATUS doRapTransaction(CCShare * pShare, const CMBlob * inData, CMBlob * outData)	
{
	CCServer * pServer;		/* server object pointer */
	Request request;		/* request dscriptor */
	Response response;		/* response descriptor */
    CMBlob tempData;        /* response parameter + data */
    NQ_STATUS res;          /* operation result */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    outData->data = NULL;
	pServer = pShare->user->server;
    if (!prepareSingleRequestByShare(&request, pShare, SMB_COM_TRANSACTION))
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_OUTOFMEMORY;
	}
	
	/* compose request:
       force ASCII
     */
    request.header.flags2 = (NQ_UINT16)(request.header.flags2 & ~SMB_FLAGS2_UNICODE);
    writeHeader(&request);
    markTransStart(&request, "\\PIPE\\LANMAN"); 
    /* T params */
    cmBufferWriteBytes(&request.writer, inData->data, inData->len);	 /* RAP parameters */
    markTransData(&request);
    writeTrans(pServer, &request, (NQ_UINT16)inData->len);
    
    res = sendReceive(pServer, pShare->user, &request, &response);
	cmBufManGive(request.buffer);
	if (NQ_SUCCESS != res)
	{
		cmBufManGive(response.buffer);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
	}

	/* parse response */
    parseTrans(&response);
    setTransData(&response);
    tempData.data = response.pParams;
    tempData.len = (NQ_COUNT)(response.dataCount + (response.pData - response.pParams));
    *outData = cmMemoryCloneBlob(&tempData);

	cmBufManGive(response.buffer);

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return NQ_SUCCESS;
}

static NQ_STATUS doEcho(CCShare * pShare)
{
    Request     request;
    Response    response;
    CCServer  * pServer;
    CCUser    * pUser;
    NQ_STATUS   res;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
    
    pUser = pShare->user;
    pServer = pUser->server;
    
    if (!prepareSingleRequestByShare(&request, pShare, SMB_COM_ECHO))
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_OUTOFMEMORY;
	}

    writeHeader(&request);
    cmBufferWriteUint16(&request.writer, 1);  
    cmBufferWriteUint32(&request.writer, 0); 
    
    res = sendReceive(pServer, pUser, &request, &response);
    cmBufManGive(request.buffer);
    if (NQ_SUCCESS != res)
	{
		cmBufManGive(response.buffer);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return res;
	}
    
    cmBufManGive(response.buffer);
    
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return NQ_SUCCESS;
}

#endif /* UD_NQ_INCLUDECIFSCLIENT */
