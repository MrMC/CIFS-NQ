/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Dispatching Simple (AndX) packets
 *--------------------------------------------------------------------
 * MODULE        : CS - CIFS Server
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 23-June-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "csdispat.h"
#include "csdataba.h"
#include "csparams.h"
#include "csnotify.h"
#ifdef UD_NQ_INCLUDESMB2
#include "cs2disp.h"
#endif
#ifdef UD_CS_MESSAGESIGNINGPOLICY
#include "cmcrypt.h"
#include "cssignin.h"
#endif
#include "nssocket.h"

#ifdef UD_NQ_INCLUDECIFSSERVER

/* This code implements the command dispatcher.
   Server calls dispatcher when it accepts an incoming CIFS command. Dispatcher reads this
   command, analyzes the command code and calls an appropriate processor.
   If the message contains AndX commands, dispatcher performs each of AndX commands
   separately.

   NOTE: Dispatcher analyzes CIFS-level commands only. TRANSACTION and TRANSACTION2
         sub commands are dispatched by appropriate command processors.

   Dispatcher uses two static message buffers - one for an incoming request and another
   one for the response.

   Dispatcher assumes that calls are synchronous - no reentrant processing. Each message
   has an appropriate source socket. This socket may be used as an additional session ID.
 */

/*
    Static data & functions
    -----------------------
*/

/* SMB1 protocol identification sequence */
static const NQ_BYTE cmSmb1ProtocolId[4] = {0xFF, 0x53, 0x4D, 0x42};

static void             /* callback function for releasing a buffer */
releaseCallback(
    const NQ_BYTE* buffer
    );

typedef struct
{
    NQ_BYTE responseBuffer[CM_NB_DATAGRAMBUFFERSIZE];/* buffer for late response */
    NSSocketHandle currentSocket;       /* handle of the socket over which the current
                                           command was accepted */
    CMCifsHeader* currentPacket;        /* handle of the socket over which the current */
    NQ_IPADDRESS* currentIpAddress;     /* pointer to the IP address for the socket over which the current
                                           command was accepted */
    NQ_BOOL ntErrorCode;                /* TRUE when the current error code should be NT */
#ifdef UD_NQ_INCLUDESMB2    
    NQ_BOOL isSmb2;                     /* TRUE when the current package is SMB2 */
#endif /* UD_NQ_INCLUDESMB2 */
#ifdef UD_CS_INCLUDEDIRECTTRANSFER    
    SYFile savedDtFile;                 /* file for Direct Transfer */
    NQ_COUNT savedDtCount;              /* number of bytes to transfer */
    NSRecvDescr * savedRecvDescr;       /* saved receive descriptor */
    NQ_BYTE * savedBuf;                 /* saved pointer in the buffer for discarded DT */
    NQ_BOOL dtIn;                       /* incoming Data Transfer flag */
    NQ_BOOL dtOut;                      /* outgoing Data Transfer flag */
#endif /* UD_CS_INCLUDEDIRECTTRANSFER */
}
StaticData;

#ifdef SY_FORCEALLOCATION
static StaticData* staticData = NULL;
#else  /* SY_FORCEALLOCATION */
static StaticData staticDataSrc;
static StaticData* staticData = &staticDataSrc;
#endif /* SY_FORCEALLOCATION */

/* Table of converting "internal" statuses to standard NT statuses
 * Internal statuses are used to report condition that requires normal response 
 * and not an error response but with non-zero status.
 * In this case NQ functions report internal codes, which are considered
 * as non-errors by cmCifsIsError(). Here they are converted to the proper 
 * NT statuses.  
 */
typedef struct
{
    NQ_UINT32 internal;    /* internal status */
    NQ_UINT32 external;    /* real NT status */
}
CodeTable;
const static CodeTable codeTable[] = 
{
    { SMB_STATUS_INTERNAL_BUFFER_TOO_SMALL, SMB_STATUS_BUFFER_TOO_SMALL },
};


/* The command set defines commands that we support and also defines those of the above
   that may be batch (AndX) processed. The set is a table of CommandDescriptor structures
   indexed by the command code. */

/* command flags */

#define nqVALID 1     /* flag for a valid command */
#define BATCH 2     /* flag for an AndX command */
#define NOUSR 4     /* flag for commands without user context */
#define DTIN 8    /* flag for incoming Direct Transfer */
#define DTOUT 16  /* flag for outgoing Direct Transfer */

#define isValidCommand(_c)  (commandSet[_c].flags & nqVALID)
#define isBatchCommand(_c)  (commandSet[_c].flags & BATCH)
#define isNoContextCommand(_c)  (commandSet[_c].flags & NOUSR)

/* Command descriptor:
   This structure defines a single SMB command that our server supports */

typedef struct
{
    NQ_UINT flags;              /* command flags - see above */
    CSCommandFunction function; /* pointer to the command processor routine */
}
CommandDescriptor;

/* Array of command descriptors as above - a particular command descriptor is indexed by
   the command code */

static const CommandDescriptor  commandSet[256] =
{
    { nqVALID        , csComCreateDirectory },        /* 0x00 SMB_COM_CREATE_DIRECTORY       */
    { nqVALID        , csComDeleteDirectory },        /* 0x01 SMB_COM_DELETE_DIRECTORY       */
    { nqVALID        , csComOpen },                   /* 0x02 SMB_COM_OPEN                   */
    { nqVALID        , csComCreate },                 /* 0x03 SMB_COM_CREATE                 */
    { nqVALID        , csComClose },                  /* 0x04 SMB_COM_CLOSE                  */
    { nqVALID        , csComFlush },                  /* 0x05 SMB_COM_FLUSH                  */
    { nqVALID        , csComDelete },                 /* 0x06 SMB_COM_DELETE                 */
    { nqVALID        , csComRename },                 /* 0x07 SMB_COM_RENAME                 */
    { nqVALID        , csComQueryInformation },       /* 0x08 SMB_COM_QUERY_INFORMATION      */
    { nqVALID        , csComSetInformation },         /* 0x09 SMB_COM_SET_INFORMATION        */
    { nqVALID        , csComRead },                   /* 0x0A SMB_COM_READ                   */
    { nqVALID        , csComWrite },                  /* 0x0B SMB_COM_WRITE                  */
    { 0            , NULL },                        /* 0x0C SMB_COM_LOCK_BYTE_RANGE        */
    { 0            , NULL },                        /* 0x0D SMB_COM_UNLOCK_BYTE_RANGE      */
    { 0            , NULL },                        /* 0x0E SMB_COM_CREATE_TEMPORARY       */
    { nqVALID        , csComCreateNew },              /* 0x0F SMB_COM_CREATE_NEW             */
    { nqVALID        , csComCheckDirectory },         /* 0x10 SMB_COM_CHECK_DIRECTORY        */
    { nqVALID        , csComProcessExit },            /* 0x11 SMB_COM_PROCESS_EXIT           */
    { nqVALID        , csComSeek },                   /* 0x12 SMB_COM_SEEK                   */
    { 0            , NULL },                        /* 0x13 SMB_COM_LOCK_AND_READ          */
    { 0            , NULL },                        /* 0x14 SMB_COM_WRITE_AND_UNLOCK       */
    { 0            , NULL },                        /* 0x15 0x15                           */
    { 0            , NULL },                        /* 0x16 0x16                           */
    { 0            , NULL },                        /* 0x17 0x17                           */
    { 0            , NULL },                        /* 0x18 0x18                           */
    { 0            , NULL },                        /* 0x19 0x19                           */
    { 0            , NULL },                        /* 0x1A SMB_COM_READ_RAW               */
    { 0            , NULL },                        /* 0x1B SMB_COM_READ_MPX               */
    { 0            , NULL },                        /* 0x1C SMB_COM_READ_MPX_SECONDARY     */
    { 0            , NULL },                        /* 0x1D SMB_COM_WRITE_RAW              */
    { 0            , NULL },                        /* 0x1E SMB_COM_WRITE_MPX              */
    { 0            , NULL },                        /* 0x1f 0x1f                           */
    { 0            , NULL },                        /* 0x20 SMB_COM_WRITE_COMPLETE         */
    { 0            , NULL },                        /* 0x21 0x21                           */
    { nqVALID        , csComSetInformation2 },        /* 0x22 SMB_COM_SET_INFORMATION2       */
    { nqVALID        , csComQueryInformation2 },      /* 0x23 SMB_COM_QUERY_INFORMATION2     */
    { nqVALID | BATCH, csComLockingAndX },            /* 0x24 SMB_COM_LOCKING_ANDX           */
    { nqVALID        , csComTransaction },            /* 0x25 SMB_COM_TRANSACTION            */
    { 0            , NULL },                        /* 0x26 SMB_COM_TRANSACTION_SECONDARY  */
    { 0            , NULL },                        /* 0x27 SMB_COM_IOCTL                  */
    { 0            , NULL },                        /* 0x28 SMB_COM_IOCTL_SECONDARY        */
    { 0            , NULL },                        /* 0x29 SMB_COM_COPY                   */
    { 0            , NULL },                        /* 0x2A SMB_COM_MOVE                   */
    { nqVALID | NOUSR, csComEcho },                   /* 0x2B SMB_COM_ECHO                   */
    { 0            , NULL },                        /* 0x2C SMB_COM_WRITE_AND_CLOSE        */
    { nqVALID | BATCH, csComOpenAndX },               /* 0x2D SMB_COM_OPEN_ANDX              */
    { nqVALID | BATCH | DTOUT, csComReadAndX },               /* 0x2E SMB_COM_READ_ANDX              */
    { nqVALID | BATCH | DTIN, csComWriteAndX },              /* 0x2F SMB_COM_WRITE_ANDX             */
    { 0            , NULL },                        /* 0x30 0x30                           */
    { 0            , NULL },                        /* 0x31 SMB_COM_CLOSE_AND_TREE_DISC    */
    { nqVALID        , csComTransaction2 },           /* 0x32 SMB_COM_TRANSACTION2           */
    { 0            , NULL },                        /* 0x33 SMB_COM_TRANSACTION2_SECONDARY */
    { nqVALID        , csComFindClose2 },             /* 0x34 SMB_COM_FIND_CLOSE2            */
    { 0            , NULL },                        /* 0x35 SMB_COM_FIND_NOTIFY_CLOSE      */
    { 0            , NULL },                        /* 0x36 0x36                           */
    { 0            , NULL },                        /* 0x37 0x37                           */
    { 0            , NULL },                        /* 0x38 0x38                           */
    { 0            , NULL },                        /* 0x39 0x39                           */
    { 0            , NULL },                        /* 0x3A 0x3A                           */
    { 0            , NULL },                        /* 0x3B 0x3B                           */
    { 0            , NULL },                        /* 0x3C 0x3C                           */
    { 0            , NULL },                        /* 0x3D 0x3D                           */
    { 0            , NULL },                        /* 0x3E 0x3E                           */
    { 0            , NULL },                        /* 0x3F 0x3F                           */
    { 0            , NULL },                        /* 0x40 0x40                           */
    { 0            , NULL },                        /* 0x41 0x41                           */
    { 0            , NULL },                        /* 0x42 0x42                           */
    { 0            , NULL },                        /* 0x43 0x43                           */
    { 0            , NULL },                        /* 0x44 0x44                           */
    { 0            , NULL },                        /* 0x45 0x45                           */
    { 0            , NULL },                        /* 0x46 0x46                           */
    { 0            , NULL },                        /* 0x47 0x47                           */
    { 0            , NULL },                        /* 0x48 0x48                           */
    { 0            , NULL },                        /* 0x49 0x49                           */
    { 0            , NULL },                        /* 0x4A 0x4A                           */
    { 0            , NULL },                        /* 0x4B 0x4B                           */
    { 0            , NULL },                        /* 0x4C 0x4C                           */
    { 0            , NULL },                        /* 0x4D 0x4D                           */
    { 0            , NULL },                        /* 0x4E 0x4E                           */
    { 0            , NULL },                        /* 0x4F 0x4F                           */
    { 0            , NULL },                        /* 0x50 0x50                           */
    { 0            , NULL },                        /* 0x51 0x51                           */
    { 0            , NULL },                        /* 0x52 0x52                           */
    { 0            , NULL },                        /* 0x53 0x53                           */
    { 0            , NULL },                        /* 0x54 0x54                           */
    { 0            , NULL },                        /* 0x55 0x55                           */
    { 0            , NULL },                        /* 0x56 0x56                           */
    { 0            , NULL },                        /* 0x57 0x57                           */
    { 0            , NULL },                        /* 0x58 0x58                           */
    { 0            , NULL },                        /* 0x59 0x59                           */
    { 0            , NULL },                        /* 0x5A 0x5A                           */
    { 0            , NULL },                        /* 0x5B 0x5B                           */
    { 0            , NULL },                        /* 0x5C 0x5C                           */
    { 0            , NULL },                        /* 0x5D 0x5D                           */
    { 0            , NULL },                        /* 0x5E 0x5E                           */
    { 0            , NULL },                        /* 0x5F 0x5F                           */
    { 0            , NULL },                        /* 0x60 0x60                           */
    { 0            , NULL },                        /* 0x61 0x61                           */
    { 0            , NULL },                        /* 0x62 0x62                           */
    { 0            , NULL },                        /* 0x63 0x63                           */
    { 0            , NULL },                        /* 0x64 0x64                           */
    { 0            , NULL },                        /* 0x65 0x65                           */
    { 0            , NULL },                        /* 0x66 0x66                           */
    { 0            , NULL },                        /* 0x67 0x67                           */
    { 0            , NULL },                        /* 0x68 0x68                           */
    { 0            , NULL },                        /* 0x69 0x69                           */
    { 0            , NULL },                        /* 0x6A 0x6A                           */
    { 0            , NULL },                        /* 0x6B 0x6B                           */
    { 0            , NULL },                        /* 0x6C 0x6C                           */
    { 0            , NULL },                        /* 0x6D 0x6D                           */
    { 0            , NULL },                        /* 0x6E 0x6E                           */
    { 0            , NULL },                        /* 0x6F 0x6F                           */
    { nqVALID        , csComTreeConnect },            /* 0x70 SMB_COM_TREE_CONNECT           */
    { nqVALID        , csComTreeDisconnect },         /* 0x71 SMB_COM_TREE_DISCONNECT        */
    { nqVALID | NOUSR, csComNegotiate },              /* 0x72 SMB_COM_NEGOTIATE              */
    { nqVALID | BATCH | NOUSR, csComSessionSetupAndX },       /* 0x73 SMB_COM_SESSION_SETUP_ANDX     */
    { nqVALID | BATCH, csComLogoffAndX },             /* 0x74 SMB_COM_LOGOFF_ANDX            */
    { nqVALID | BATCH, csComTreeConnectAndX },        /* 0x75 SMB_COM_TREE_CONNECT_ANDX      */
    { 0            , NULL },                        /* 0x76 0x76                           */
    { 0            , NULL },                        /* 0x77 0x77                           */
    { 0            , NULL },                        /* 0x78 0x78                           */
    { 0            , NULL },                        /* 0x79 0x79                           */
    { 0            , NULL },                        /* 0x7A 0x7A                           */
    { 0            , NULL },                        /* 0x7B 0x7B                           */
    { 0            , NULL },                        /* 0x7C 0x7C                           */
    { 0            , NULL },                        /* 0x7D 0x7D                           */
    { 0            , NULL },                        /* 0x7E 0x7E                           */
    { 0            , NULL },                        /* 0x7F 0x7F                           */
    { nqVALID        , csComQueryInformationDisk },   /* 0x80 SMB_COM_QUERY_INFORMATION_DISK */
    { nqVALID        , csComSearch },                 /* 0x81 SMB_COM_SEARCH                 */
    { 0            , NULL },                        /* 0x82 SMB_COM_FIND                   */
    { 0            , NULL },                        /* 0x83 SMB_COM_FIND_UNIQUE            */
    { 0            , NULL },                        /* 0x84 SMB_COM_FIND_CLOSE             */
    { 0            , NULL },                        /* 0x85 0x85                           */
    { 0            , NULL },                        /* 0x86 0x86                           */
    { 0            , NULL },                        /* 0x87 0x87                           */
    { 0            , NULL },                        /* 0x88 0x88                           */
    { 0            , NULL },                        /* 0x89 0x89                           */
    { 0            , NULL },                        /* 0x8A 0x8A                           */
    { 0            , NULL },                        /* 0x8B 0x8B                           */
    { 0            , NULL },                        /* 0x8C 0x8C                           */
    { 0            , NULL },                        /* 0x8D 0x8D                           */
    { 0            , NULL },                        /* 0x8E 0x8E                           */
    { 0            , NULL },                        /* 0x8F 0x8F                           */
    { 0            , NULL },                        /* 0x90 0x90                           */
    { 0            , NULL },                        /* 0x91 0x91                           */
    { 0            , NULL },                        /* 0x92 0x92                           */
    { 0            , NULL },                        /* 0x93 0x93                           */
    { 0            , NULL },                        /* 0x94 0x94                           */
    { 0            , NULL },                        /* 0x95 0x95                           */
    { 0            , NULL },                        /* 0x96 0x96                           */
    { 0            , NULL },                        /* 0x97 0x97                           */
    { 0            , NULL },                        /* 0x98 0x98                           */
    { 0            , NULL },                        /* 0x99 0x99                           */
    { 0            , NULL },                        /* 0x9A 0x9A                           */
    { 0            , NULL },                        /* 0x9B 0x9B                           */
    { 0            , NULL },                        /* 0x9C 0x9C                           */
    { 0            , NULL },                        /* 0x9D 0x9D                           */
    { 0            , NULL },                        /* 0x9E 0x9E                           */
    { 0            , NULL },                        /* 0x9F 0x9F                           */
    { nqVALID        , csComNtTransaction },          /* 0xA0 SMB_COM_NT_TRANSACT            */
    { 0            , NULL },                        /* 0xA1 SMB_COM_NT_TRANSACT_SECONDARY  */
    { nqVALID | BATCH, csComNtCreateAndX },           /* 0xA2 SMB_COM_NT_CREATE_ANDX         */
    { 0            , NULL },                        /* 0xA3 0xA3                           */
    { nqVALID        , csComNtCancel },               /* 0xA4 SMB_COM_NT_CANCEL              */
    { 0            , NULL },                        /* 0xA5 0xA5                           */
    { 0            , NULL },                        /* 0xA6 0xA6                           */
    { 0            , NULL },                        /* 0xA7 0xA7                           */
    { 0            , NULL },                        /* 0xA8 0xA8                           */
    { 0            , NULL },                        /* 0xA9 0xA9                           */
    { 0            , NULL },                        /* 0xAA 0xAA                           */
    { 0            , NULL },                        /* 0xAB 0xAB                           */
    { 0            , NULL },                        /* 0xAC 0xAC                           */
    { 0            , NULL },                        /* 0xAD 0xAD                           */
    { 0            , NULL },                        /* 0xAE 0xAE                           */
    { 0            , NULL },                        /* 0xAF 0xAF                           */
    { 0            , NULL },                        /* 0xB0 0xB0                           */
    { 0            , NULL },                        /* 0xB1 0xB1                           */
    { 0            , NULL },                        /* 0xB2 0xB2                           */
    { 0            , NULL },                        /* 0xB3 0xB3                           */
    { 0            , NULL },                        /* 0xB4 0xB4                           */
    { 0            , NULL },                        /* 0xB5 0xB5                           */
    { 0            , NULL },                        /* 0xB6 0xB6                           */
    { 0            , NULL },                        /* 0xB7 0xB7                           */
    { 0            , NULL },                        /* 0xB8 0xB8                           */
    { 0            , NULL },                        /* 0xB9 0xB9                           */
    { 0            , NULL },                        /* 0xBA 0xBA                           */
    { 0            , NULL },                        /* 0xBB 0xBB                           */
    { 0            , NULL },                        /* 0xBC 0xBC                           */
    { 0            , NULL },                        /* 0xBD 0xBD                           */
    { 0            , NULL },                        /* 0xBE 0xBE                           */
    { 0            , NULL },                        /* 0xBF 0xBF                           */
#ifdef UD_CS_INCLUDERPC_SPOOLSS
    { nqVALID        , csComOpenPrintFile },          /* 0xC0 SMB_COM_OPEN_PRINT_FILE        */
#else
    { 0            , NULL },                        /* 0xC0 SMB_COM_OPEN_PRINT_FILE        */
#endif /* UD_CS_INCLUDERPC_SPOOLSS */
    { 0            , NULL },                        /* 0xC1 SMB_COM_WRITE_PRINT_FILE       */
#ifdef UD_CS_INCLUDERPC_SPOOLSS
    { nqVALID        , csComClosePrintFile },         /* 0xC2 SMB_COM_CLOSE_PRINT_FILE       */
#else
    { 0            , NULL },                        /* 0xC2 SMB_COM_CLOSE_PRINT_FILE       */
#endif /* UD_CS_INCLUDERPC_SPOOLSS */
    { 0            , NULL },                        /* 0xC3 SMB_COM_GET_PRINT_QUEUE        */
    { 0            , NULL },                        /* 0xC4 0xC4                           */
    { 0            , NULL },                        /* 0xC5 0xC5                           */
    { 0            , NULL },                        /* 0xC6 0xC6                           */
    { 0            , NULL },                        /* 0xC7 0xC7                           */
    { 0            , NULL },                        /* 0xC8 0xC8                           */
    { 0            , NULL },                        /* 0xC9 0xC9                           */
    { 0            , NULL },                        /* 0xCA 0xCA                           */
    { 0            , NULL },                        /* 0xCB 0xCB                           */
    { 0            , NULL },                        /* 0xCC 0xCC                           */
    { 0            , NULL },                        /* 0xCD 0xCD                           */
    { 0            , NULL },                        /* 0xCE 0xCE                           */
    { 0            , NULL },                        /* 0xCF 0xCF                           */
    { 0            , NULL },                        /* 0xD0 0xD0                           */
    { 0            , NULL },                        /* 0xD1 0xD1                           */
    { 0            , NULL },                        /* 0xD2 0xD2                           */
    { 0            , NULL },                        /* 0xD3 0xD3                           */
    { 0            , NULL },                        /* 0xD4 0xD4                           */
    { 0            , NULL },                        /* 0xD5 0xD5                           */
    { 0            , NULL },                        /* 0xD6 0xD6                           */
    { 0            , NULL },                        /* 0xD7 0xD7                           */
    { 0            , NULL },                        /* 0xD8 SMB_COM_READ_BULK              */
    { 0            , NULL },                        /* 0xD9 SMB_COM_WRITE_BULK             */
    { 0            , NULL },                        /* 0xDA SMB_COM_WRITE_BULK_DATA        */
    { 0            , NULL },                        /* 0xDB 0xDB                           */
    { 0            , NULL },                        /* 0xDC 0xDC                           */
    { 0            , NULL },                        /* 0xDD 0xDD                           */
    { 0            , NULL },                        /* 0xDE 0xDE                           */
    { 0            , NULL },                        /* 0xDF 0xDF                           */
    { 0            , NULL },                        /* 0xE0 0xE0                           */
    { 0            , NULL },                        /* 0xE1 0xE1                           */
    { 0            , NULL },                        /* 0xE2 0xE2                           */
    { 0            , NULL },                        /* 0xE3 0xE3                           */
    { 0            , NULL },                        /* 0xE4 0xE4                           */
    { 0            , NULL },                        /* 0xE5 0xE5                           */
    { 0            , NULL },                        /* 0xE6 0xE6                           */
    { 0            , NULL },                        /* 0xE7 0xE7                           */
    { 0            , NULL },                        /* 0xE8 0xE8                           */
    { 0            , NULL },                        /* 0xE9 0xE9                           */
    { 0            , NULL },                        /* 0xEA 0xEA                           */
    { 0            , NULL },                        /* 0xEB 0xEB                           */
    { 0            , NULL },                        /* 0xEC 0xEC                           */
    { 0            , NULL },                        /* 0xED 0xED                           */
    { 0            , NULL },                        /* 0xEE 0xEE                           */
    { 0            , NULL },                        /* 0xEF 0xEF                           */
    { 0            , NULL },                        /* 0xF0 0xF0                           */
    { 0            , NULL },                        /* 0xF1 0xF1                           */
    { 0            , NULL },                        /* 0xF2 0xF2                           */
    { 0            , NULL },                        /* 0xF3 0xF3                           */
    { 0            , NULL },                        /* 0xF4 0xF4                           */
    { 0            , NULL },                        /* 0xF5 0xF5                           */
    { 0            , NULL },                        /* 0xF6 0xF6                           */
    { 0            , NULL },                        /* 0xF7 0xF7                           */
    { 0            , NULL },                        /* 0xF8 0xF8                           */
    { 0            , NULL },                        /* 0xF9 0xF9                           */
    { 0            , NULL },                        /* 0xFA 0xFA                           */
    { 0            , NULL },                        /* 0xFB 0xFB                           */
    { 0            , NULL },                        /* 0xFC 0xFC                           */
    { 0            , NULL },                        /* 0xFD 0xFD                           */
    { 0            , NULL },                        /* 0xFE 0xFE                           */
    { 0            , NULL }                         /* 0xFF 0xFF                           */
}; /* end of the command set */

#ifdef UD_CS_INCLUDEDIRECTTRANSFER

void csDispatchDtSet(
  SYFile file,      
  NQ_COUNT count      
  )
{
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "file:%d count:%d", file, count);
    staticData->savedDtFile = file;
    staticData->savedDtCount = count;
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

void csDispatchDtDiscard(
  )
{
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
    if (staticData->dtIn)
    {
        nsRecvIntoBuffer(
            staticData->savedRecvDescr,
            staticData->savedBuf,
            staticData->savedRecvDescr->remaining
            );
        staticData->dtIn = FALSE;
    }
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

NQ_BOOL 
csDispatchIsDtIn(
  )
{
  return staticData->dtIn;
}

NQ_BOOL 
csDispatchIsDtOut(
  )
{
  return staticData->dtOut;
}

void
csDispatchSetDtIn(NQ_BOOL isOn)
{
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "%s", isOn ? "on" : "off");
    staticData->dtIn = isOn;
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

void
csDispatchSetDtOut(NQ_BOOL isOn)
{
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "%s", isOn ? "on" : "off");
    staticData->dtOut = isOn;
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

NQ_BOOL 
csDispatchDtFromSocket(
  NSRecvDescr * recvDescr,
  NQ_COUNT required
  )
{
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "recvDescr:%p required:%d", recvDescr, required);

    if (syIsValidFile(staticData->savedDtFile))
    {
        NQ_STATUS returnValue;

        /* Transfer bytes from socket to file */
        returnValue = syDtFromSocket(
            ((SocketSlot*)recvDescr->socket)->socket, 
            staticData->savedDtFile, 
            &staticData->savedDtCount
            );
        if (returnValue != NQ_SUCCESS || staticData->savedDtCount != required)
        {
            TRC2P("DT IN: required: %d, written: %d", required, staticData->savedDtCount);
            TRCERR("DT IN: Error performing incoming Direct Transfer");
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "FALSE");
            return FALSE;
        }
        recvDescr->remaining -= staticData->savedDtCount;
    }
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "TRUE");
    return TRUE;
}

NQ_BOOL        
csDispatchDtToSocket(
    NSRecvDescr * recvDescr
  )
{
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "recvDescr:%p", recvDescr);

    if (syIsValidFile(staticData->savedDtFile))
    {
        NQ_STATUS returnValue;
        /* Transfer bytes from file to socket */
        returnValue = syDtToSocket(
            ((SocketSlot*)recvDescr->socket)->socket, 
            staticData->savedDtFile, 
            &staticData->savedDtCount
            );
        if (returnValue != NQ_SUCCESS)
        {
            TRCERR("DT OUT: Error performing outgoing Direct Transfer");
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "FALSE");
            return FALSE;
        }
    }
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "TRUE");
    return TRUE;
}

NQ_BOOL
csDispatchDtAvailable()
{
  return syIsValidFile(staticData->savedDtFile);
}

void
csDispatchDtSaveParameters(
  NQ_BYTE * buf, 
  NSRecvDescr * recvDescr
  )
{
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "buf:%p recvDescr:%p", buf, recvDescr);
    staticData->savedBuf = buf;
    staticData->savedRecvDescr = recvDescr;
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

NQ_COUNT 
csDispatchDtGetCount(
  )
{
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "%d", staticData->savedDtCount);
    return staticData->savedDtCount;
}

#endif /* UD_CS_INCLUDEDIRECTTRANSFER */

/*====================================================================
 * PURPOSE: initialize resources
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:
 *====================================================================
 */

NQ_STATUS
csDispatchInit(
    void
    )
{
    TRCB();

    /* allocate memory */
#ifdef SY_FORCEALLOCATION
    staticData = (StaticData *)syMalloc(sizeof(*staticData));
    if (NULL == staticData)
    {
        TRCE();
        return NQ_FAIL;
    }
#endif /* SY_FORCEALLOCATION */

    TRCE();
    return NQ_SUCCESS;
}

/*====================================================================
 * PURPOSE: release resources
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: None
 *
 * NOTES:
 *====================================================================
 */

void
csDispatchExit(
    void
    )
{
    TRCB();

    /* release memory */
#ifdef SY_FORCEALLOCATION
    if (NULL != staticData)
        syFree(staticData);
    staticData = NULL;
#endif /* SY_FORCEALLOCATION */

    TRCE();
}

/*
 *====================================================================
 * PURPOSE: Obtain the socket handle for the command being processed
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: Socket handle
 *
 * NOTES:
 *====================================================================
 */

NSSocketHandle
csDispatchGetSocket(
    void
    )
{
    return staticData->currentSocket;
}


/*
 *====================================================================
 * PURPOSE: Set current socket
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: Socket handle
 *
 * NOTES:
 *====================================================================
 */

void
csDispatchSetSocket(
    NSSocketHandle newSocket
    )
{
    staticData->currentSocket = newSocket;
}


/*
 *====================================================================
 * PURPOSE: Obtain the socket IP for the command being processed
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: Socket IP
 *
 * NOTES:
 *====================================================================
 */

const NQ_IPADDRESS*
csDispatchGetSocketIp(
    void
    )
{
    return staticData->currentIpAddress;
}

/*
 *====================================================================
 * PURPOSE: Responding with error
 *--------------------------------------------------------------------
 * PARAMS:  IN socket over which to send an error response
 *          IN/OUT buffer for output the message
 *          IN error code in the NT format
 *
 * RETURNS: Size of the error response or zero if the SMB command was not truncated
 *
 * NOTES:   - error code is accepted in the NT format
 *          - we assume that the output message already contains a header,
 *            copied from the incoming header (with the same PID, TID and UID)
 *          - the outgoing message will contain a header followed by three zero
 *            bytes (word count and byte count)
 *          - if the status (NT status case) is not an error, the message should
 *            not be truncated
 *====================================================================
 */

static NQ_INT
dispatchError(
    NSSocketHandle socket,
    CMCifsHeader* outMsg,
    CMCifsStatus error
    )
{
    NQ_BYTE* pBlock;       /* pointer to the word and byte blocks */

    /* 
    outMsg->flags = CS_SMBFLAGS;
    cmPutSUint16(outMsg->flags2, CS_SMBFLAGS2);
    */

    /* fill in the error code */

    cmPutSUint32(outMsg->status, cmHtol32(error));
    if (staticData->ntErrorCode)    /* NT error */
    {
        cmPutSUint16(outMsg->flags2, cmGetSUint16(outMsg->flags2) | cmHtol16(SMB_FLAGS2_32_BIT_ERROR_CODES));
    }

    /* zero counts */

    pBlock = (NQ_BYTE*)(outMsg + 1);
    *pBlock++ = 0;  /* word count */
    *pBlock++ = 0;  /* byte count lsb */
    *pBlock++ = 0;  /* bye count msb */

    return (NQ_INT)(pBlock - (NQ_BYTE*)outMsg);
}

/*
 *====================================================================
 * PURPOSE: Responding with error on no resources to create a connection
 *--------------------------------------------------------------------
 * PARAMS:  IN socket that has an incoming packet
 *
 * RETURNS: NQ_FAIL or NQ_SUCCESS
 *
 * NOTES:   No session is created, error message is returned immediately
 *====================================================================
 */

NQ_STATUS
csDispatchErrorNoResources(
    NSSocketHandle socket
    )
{
    NQ_INT msgLen;                              /* this message length */
    NQ_INT sndLen;                              /* number of bytes send */
    CMCifsStatus error;                         /* error structure */
    NQ_BYTE* buffer;                            /* pointer to the message buffer */
    NSRecvDescr recvDescr;            /* receive descriptor */
    NQ_INT expected;              /* expected number of bytes in NBT packet */

    TRCB();

    /* allocate buffer */

    buffer = nsGetBuffer();

    /* read packet from the socket */

    expected = nsStartRecvIntoBuffer(socket, &recvDescr);
    if (NQ_FAIL == expected)
    {
        TRCERR("Error reading NBT header");
        nsPutBuffer(buffer);
        TRCE();
        return NQ_FAIL;
    }

    msgLen = nsRecvIntoBuffer(&recvDescr, buffer, (NQ_COUNT)expected);

    if (msgLen == NQ_FAIL || msgLen == 0)
    {
        TRCERR("Error reading from socket");
        nsPutBuffer(buffer);
        TRCE();

        return NQ_FAIL;
    }
    
    nsEndRecvIntoBuffer(&recvDescr);

    /* compose and send the error message */

    error = csErrorReturn(SMB_STATUS_INSUFFICIENT_RESOURCES, SRV_ERRnoresource);

    msgLen = dispatchError(socket, (CMCifsHeader*)buffer, error);

    /* send the response - this will also release the buffer */
    msgLen = (NQ_INT)nsPrepareNBBuffer(buffer, (NQ_UINT)msgLen, (NQ_UINT)msgLen);
    if(0 == msgLen)
    {
        TRCERR("Error prepare buffer for response");
        TRCE();
        return NQ_FAIL;
    }

    sndLen = nsSendFromBuffer(socket, buffer, (NQ_UINT)msgLen, (NQ_UINT)msgLen, &releaseCallback);
    if (sndLen != msgLen)
    {
        TRCERR("Error sending response");
        TRC2P("Required: %d, sent: %d", msgLen, sndLen);
        TRCE();
        return NQ_FAIL;
    }

    TRCE();
    return NQ_SUCCESS;
}

/*
 *====================================================================
 * PURPOSE: Batch processing
 *--------------------------------------------------------------------
 * PARAMS:  IN socket that has an incoming packet
 *
 * RETURNS: NQ_FAIL or NQ_SUCCESS
 *
 * NOTES:   This function proceeds a request, dispatching it to an
 *          appropriate parser function. BATCH (AndX) requests are
 *          chained inside this function.
 *          Even on error response we return NQ_SUCCESS. NQ_FAIL is returned on
 *          internal error or dead socket (communication problem)
 *====================================================================
 */

NQ_STATUS
csDispatchRequest(
  CSSocketDescriptor * sockDescr
    )
{
    NQ_INT msgLen;                      /* message length for input and output */
    NQ_INT sndLen;                      /* send message length */
    NQ_BYTE* rcvBuf;                    /* pointer to the incoming message buffer */
    NQ_BYTE* sndBuf;                    /* pointer to the response message buffer */
    NQ_BYTE* cifsData;                  /* pointer to the beginning of SMB header */
    CMCifsHeader* pHeaderInp;           /* pointer to the incoming header (the header of the
                                           1st command */
    CMCifsHeader* pHeaderOut;           /* pointer to the outgoing header (the header of the
                                           1st command */
    NQ_BYTE currentCommand;             /* current batch command */
    NQ_BYTE nextCommand;                /* next batch command */
    NQ_UINT16 offset;                   /* offset to the next command in chain */
    CMCifsSessionSetupAndXRequest* pRequest;    /* is used for a pointer to the next command
                                                   structure in the chain */
    CMCifsSessionSetupAndXResponse* pResponse;  /* is used as a pointer to the next command
                                                   structure in the chain */
    NQ_BYTE* response;                  /* auxiliary pointer */                              
    NQ_UINT32 returnValue;              /* return value from command processing */
#ifdef UD_CS_MESSAGESIGNINGPOLICY
    CSSession * pSession;               /* session pointer */
    NQ_COUNT signLen;                   /* length of the signed packet (may be the entire packet for AndX chain) */
#endif /* UD_CS_MESSAGESIGNINGPOLICY */
    NSRecvDescr recvDescr;              /* receive descriptor */
    NQ_INT expected;                    /* expected number of bytes in NBT packet */
    NQ_BYTE * pBuf;                     /* pointer into the receive buffer */
    CSUser* pUser;                      /* user pointer */
#ifdef UD_CS_INCLUDEDIRECTTRANSFER
    NQ_BYTE wordCount;                  /* word count */
    NQ_BYTE andX;                       /* andx command */
#endif /* UD_CS_INCLUDEDIRECTTRANSFER */

    TRCB();

#ifdef UD_CS_INCLUDEDIRECTTRANSFER
    syInvalidateFile(&staticData->savedDtFile);
#endif /* UD_CS_INCLUDEDIRECTTRANSFER */

    /* allocate receive buffer and read data */
    rcvBuf = nsGetBuffer();
    expected = nsStartRecvIntoBuffer(sockDescr->socket, &recvDescr);
#ifdef UD_CS_MESSAGESIGNINGPOLICY
    signLen = (NQ_COUNT)expected;
#endif /* UD_CS_MESSAGESIGNINGPOLICY */
    if (NQ_FAIL == expected)
    {
        TRCERR("Error reading NBT header");
        nsPutBuffer(rcvBuf);
        TRCE();
        return NQ_FAIL;
    }
    if (expected == 0)
    {
        nsPutBuffer(rcvBuf);
        TRCE();
        return NQ_SUCCESS;     /* this is a SESSION_KEEP_ALIVE packet - do nothing */
    }
#ifdef UD_NQ_INCLUDESMBCAPTURE
	{
		SocketSlot * pSock = (SocketSlot *) recvDescr.socket;
		sockDescr->captureHdr.receiving = TRUE;
		syGetSocketPortAndIP(pSock->socket, &pSock->ip, &pSock->port);
		sockDescr->captureHdr.srcIP = pSock->ip;
		sockDescr->captureHdr.srcPort = pSock->transport == NS_TRANSPORT_NETBIOS ? 139 : 445;
	}
#endif /* UD_NQ_INCLUDESMBCAPTURE */

    pBuf = rcvBuf;
    msgLen = nsRecvIntoBuffer(&recvDescr, pBuf, 4); /* read SMB signature */
    if (msgLen == NQ_FAIL)
    {
        TRCERR("Error reading from socket");
        nsPutBuffer(rcvBuf);
        TRCE();
        return NQ_FAIL;
    }
#ifdef UD_NQ_INCLUDESMBCAPTURE
#ifdef UD_NQ_INCLUDESMB3
    if (syMemcmp(rcvBuf , cmSmb2TrnsfrmHdrProtocolId , sizeof(cmSmb2TrnsfrmHdrProtocolId)) != 0)
#endif /* UD_NQ_INCLUDESMB3  */
    {
    	cmCapturePacketWriteStart(&sockDescr->captureHdr , recvDescr.remaining + 4);
    	cmCapturePacketWritePacket(pBuf, 4);
    }
#ifdef UD_NQ_INCLUDESMB3
    else
    {
    	cmCapturePacketWriteStart(&sockDescr->captureHdr , recvDescr.remaining  - (SMB2_TRANSFORMHEADER_SIZE - 4)  /*expected*/);
    }
#endif /* UD_NQ_INCLUDESMB3  */
#endif /* UD_NQ_INCLUDESMBCAPTURE */
    expected -= 4;
    pBuf += 4;

    /* save the current socket handle
       Negotiate uses this handle as a unique ID to:
       1) prevent second Negotiate command
       2) uniquely identify objects in the database */
    csDispatchSetSocket(sockDescr->socket);
    staticData->currentIpAddress = &sockDescr->ip;

#ifdef UD_NQ_INCLUDESMB2    
    /* check for SMB2 signature */
    staticData->isSmb2 = FALSE;
    if (syMemcmp(rcvBuf, cmSmb2ProtocolId, sizeof(cmSmb2ProtocolId)) == 0
	 || syMemcmp(rcvBuf , cmSmb2TrnsfrmHdrProtocolId , sizeof(cmSmb2TrnsfrmHdrProtocolId)) == 0)
    {
        /* handle SMB2 request, then release request buffer */
        NQ_BOOL result;
        staticData->isSmb2 = TRUE;
        result = csSmb2DispatchRequest(&recvDescr, rcvBuf, (NQ_COUNT)expected);
        nsPutBuffer(rcvBuf);

        TRCE();
        return result ? NQ_SUCCESS : NQ_FAIL;
    }
#endif

    /* check for SMB1 protocol identificator */
    if (syMemcmp(rcvBuf, cmSmb1ProtocolId, sizeof(cmSmb1ProtocolId)) != 0)
    {
#ifdef UD_NQ_INCLUDESMBCAPTURE
    	NQ_BYTE *	fakeBuf;

    	fakeBuf = (NQ_BYTE *)cmMemoryAllocate(recvDescr.remaining);
    	syMemset(fakeBuf , 0 , recvDescr.remaining);
    	cmCapturePacketWritePacket(fakeBuf, recvDescr.remaining);
    	cmCapturePacketWriteEnd();
    	cmMemoryFree(fakeBuf);
#endif /* UD_NQ_INCLUDESMBCAPTURE */
        /* disconnect client, release request buffer */
        nsPutBuffer(rcvBuf);
        TRCERR("No SMB protocol identificator in the packet");
        TRCE();
        return NQ_FAIL;
    }
    
    msgLen = nsRecvIntoBuffer(&recvDescr, pBuf, 30); /* header (without SMB signature) + word count + AndXCommand */
    if (msgLen == NQ_FAIL)
    {
        TRCERR("Error reading from socket");
        nsPutBuffer(rcvBuf);
        TRCE();
        return NQ_FAIL;
    }
#ifdef UD_NQ_INCLUDESMBCAPTURE
    cmCapturePacketWritePacket(pBuf, 30);
#endif /* UD_NQ_INCLUDESMBCAPTURE */
    expected -= 30;
    pBuf += 30;

    /* prepare pointers:
        - incoming and outgoing header pointers
        - pointer to the 1st command response- command processors will advance this
          pointer */

    sndBuf = nsGetBuffer();
    pHeaderInp = (CMCifsHeader*)rcvBuf;
    staticData->currentPacket = pHeaderInp;
    cifsData = nsSkipHeader(sockDescr->socket, sndBuf);
    pHeaderOut = (CMCifsHeader*)cifsData;
    pResponse = (CMCifsSessionSetupAndXResponse*)(pHeaderOut + 1);
    currentCommand = pHeaderInp->command;

    /* copy request header into response */

    syMemcpy((NQ_BYTE*)pHeaderOut, (NQ_BYTE*)pHeaderInp, sizeof(CMCifsHeader));

    /* set new flags preserving the client's UNICODE flag */

    pHeaderOut->flags = (NQ_BYTE)(CS_SMBFLAGS | (pHeaderOut->flags & 0x10));
    cmPutSUint16(pHeaderOut->flags2, (NQ_UINT16)(CS_SMBFLAGS2 | (cmGetSUint16(pHeaderInp->flags2) & cmHtol16(SMB_FLAGS2_UNICODE))));

    /* set offset to the 1st command - offset to subsequent commands will be
       calculated during the loop */

    offset = sizeof(*pHeaderInp);

    /* loop over the chain of batch commands */

    msgLen = 0;     /* will be non zero on error */

    pUser = csGetUserByUid(cmHtol16(cmGetSUint16(pHeaderInp->uid)));
#ifdef UD_CS_MESSAGESIGNINGPOLICY            
    pSession = csGetSessionBySocket();
#endif /* UD_CS_MESSAGESIGNINGPOLICY */

#ifdef UD_CS_INCLUDEDIRECTTRANSFER
    csDispatchSetDtOut(FALSE);
    csDispatchSetDtIn(FALSE);

    syInvalidateFile(&staticData->savedDtFile);
    wordCount = *(rcvBuf + 32); /* word count */
    andX = *(rcvBuf + 33);      /* andx command */

    /* DT does not work on chained (andX) commands and neither it works with message signing */
    if ((!(commandSet[currentCommand].flags & BATCH) || andX == 0xFF) && 
      (commandSet[currentCommand].flags & DTIN) 
#ifdef UD_CS_MESSAGESIGNINGPOLICY            
      && (pUser == NULL || pSession == NULL || !pSession->signingOn)
#endif /* UD_CS_MESSAGESIGNINGPOLICY */            
    )
    {
        /* use DirectTransfer - read according to word count */
        csDispatchSetDtIn(TRUE);
        msgLen = nsRecvIntoBuffer(&recvDescr, pBuf, (NQ_COUNT)(wordCount * 2 + 2)); /* read remaining words + byte count + padding */
        csDispatchDtSaveParameters(pBuf + (wordCount * 2) + 2, &recvDescr);
    }
    else
#endif /* UD_CS_INCLUDEDIRECTTRANSFER */
    {
        msgLen = nsRecvIntoBuffer(&recvDescr, pBuf, (NQ_COUNT)expected); /* read the rest of the packet */
    }
    if (msgLen == NQ_FAIL)
    {
        TRCERR("Error reading from socket");
        nsPutBuffer(rcvBuf);
        TRCE();
        return NQ_FAIL;
    }
#ifdef UD_NQ_INCLUDESMBCAPTURE
#ifdef UD_CS_INCLUDEDIRECTTRANSFER
    if ((!(commandSet[currentCommand].flags & BATCH) || andX == 0xFF) &&
    	      (commandSet[currentCommand].flags & DTIN) && pSession == NULL && !pSession->signingOn)
    {
    	NQ_BYTE *	tempBuf;
    	NQ_UINT16	dataLen;
    	NQ_UINT16	offset;
    	CMBufferReader	reader;

    	cmBufferReaderInit(&reader , pBuf , (NQ_COUNT)msgLen);
    	cmBufferReaderSkip(&reader , 19);
    	cmBufferReadUint16(&reader , &dataLen);
    	cmBufferReadUint16(&reader , &offset);

    	if (offset > (32 +  msgLen ) )
    	{
    		dataLen = (NQ_UINT16)(dataLen + (offset - ( 32 + msgLen )));
    	}

    	tempBuf = (NQ_BYTE *)cmMemoryAllocate(dataLen);
    	syMemset(tempBuf , 0 , dataLen);

    	cmCapturePacketWritePacket(pBuf, (NQ_UINT)msgLen);
    	cmCapturePacketWritePacket(tempBuf, (NQ_UINT)dataLen);
		cmCapturePacketWriteEnd();

    	cmMemoryFree(tempBuf);
    }
    else
#endif /* UD_CS_INCLUDEDIRECTTRANSFER */
    {
    	cmCapturePacketWritePacket(pBuf, (NQ_UINT)msgLen);
    }
	cmCapturePacketWriteEnd();
#endif /* UD_NQ_INCLUDESMBCAPTURE */
    
#ifdef UD_CS_INCLUDEDIRECTTRANSFER
  if ((!(commandSet[currentCommand].flags & BATCH) || andX == 0xFF) && 
    (commandSet[currentCommand].flags & DTOUT)
#ifdef UD_CS_MESSAGESIGNINGPOLICY            
      && (pUser == NULL || pSession == NULL || !pSession->signingOn)
#endif /* UD_CS_MESSAGESIGNINGPOLICY */            
    )
    { 
          /* use DirectTransfer - prepare socket */
          syDtStartPacket(((SocketSlot*)sockDescr->socket)->socket);
          csDispatchSetDtOut(TRUE);
    }
#endif /* UD_CS_INCLUDEDIRECTTRANSFER */
  
    msgLen = 0;
    while (currentCommand != 0xff)
    {
        pRequest = (CMCifsSessionSetupAndXRequest*)((NQ_BYTE*)pHeaderInp + offset);

        /* calculate next command's (if any) code and offset */

        if (isBatchCommand(currentCommand))
        {
            nextCommand = pRequest->andXCommand;
            offset = cmLtoh16(cmGetSUint16(pRequest->andXOffset));
        }
        else
        {
            nextCommand = 0xff;     /* simulate end of AndX chain */
        }
        TRC("Command 0x%x", currentCommand);

        /* check command code for the current command */

        if (!isValidCommand(currentCommand))
        {
            CMCifsStatus error;     /* CIFS error format */

            TRC("Command %x is not supported", currentCommand);
            error = csErrorReturn(SMB_STATUS_NOT_SUPPORTED, (NQ_UINT32)SRV_ERRnosupport);
            msgLen = dispatchError(sockDescr->socket, pHeaderOut, error);
            break;
        }
        else
        {
            /* calculate NT status vs DOS errors */
            staticData->ntErrorCode = 0 != (cmLtoh16(cmGetSUint16(pHeaderInp->flags2)) & SMB_FLAGS2_32_BIT_ERROR_CODES);
            if (!isNoContextCommand(currentCommand))
            {
                if (NULL != pUser)
                {
                    staticData->ntErrorCode = pUser->supportsNtErrors;
                }
            }
            
            LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Request: command=0x%x, mid=0/%u, pid=0x%08x, sid=%lu, tid=0x%08x", pHeaderInp->command, cmGetSUint16(pHeaderInp->mid), cmGetSUint16(pHeaderInp->pid), cmGetSUint16(pHeaderInp->uid), cmGetSUint16(pHeaderInp->tid));

#ifdef UD_CS_MESSAGESIGNINGPOLICY            
            /* check incoming message signature */
			if (!csCheckMessageSignatureSMB(pSession, pUser, (NQ_BYTE*)pHeaderInp, signLen))
			{
				TRCERR("Bad incoming signature");
				returnValue = csErrorReturn(SMB_STATUS_ACCESS_DENIED, NQ_ERR_ACCESS);
				msgLen = dispatchError(sockDescr->socket, pHeaderOut, returnValue);
				break;
			}
#endif /* UD_CS_MESSAGESIGNINGPOLICY */

            /* call command processor - it will advance the response pointer */
            response = (NQ_BYTE *)pResponse;
            returnValue = (*commandSet[currentCommand].function)(
                (NQ_BYTE*)pRequest,
                pHeaderOut,
                &response
                );
				
            pResponse = (CMCifsSessionSetupAndXResponse*)response;
           
            if (cmCifsIsError(returnValue) && returnValue != csErrorReturn(SMB_STATUS_MORE_PROCESSING_REQUIRED, NQ_ERR_MOREDATA))
            {
                if (returnValue == SMB_STATUS_NORESPONSE) /* do not send response */
                {
                    /* release the request buffer */
                    /* release the response buffer */

                    nsPutBuffer(rcvBuf);
                    nsPutBuffer(sndBuf);

                    TRCE();
                    return NQ_SUCCESS;
                }
                else
                {
                    msgLen = dispatchError(sockDescr->socket, pHeaderOut, returnValue);
                    break;
                }
            }
            else
            {                
#ifdef UD_NQ_INCLUDESMB2
                /* update flags and status only for SMB1 packets */
                if (syMemcmp(pHeaderOut, cmSmb2ProtocolId, sizeof(cmSmb2ProtocolId)) != 0)
#endif /* UD_NQ_INCLUDESMB2 */
                {
                    /* convert internal codes */
                    if (0 != returnValue)
                    {
                        NQ_COUNT i;
                        for (i = 0; i < sizeof(codeTable)/sizeof(codeTable[0]); i++)
                        {
                            if (codeTable[i].internal == returnValue)
                            {
                                returnValue = codeTable[i].external;
                            }
                        }
                    }
                    cmPutSUint32(pHeaderOut->status, cmHtol32(returnValue));
                    if (   cmCifsIsNtError(returnValue)
                        || (0==returnValue && staticData->ntErrorCode
                       ))
                    {
                        cmPutSUint16(pHeaderOut->flags2, cmGetSUint16(pHeaderOut->flags2) | cmHtol16(SMB_FLAGS2_32_BIT_ERROR_CODES));
                    }
                }
            }
        }
        currentCommand = nextCommand;
    }

#ifdef UD_CS_INCLUDEDIRECTTRANSFER
    if (csDispatchIsDtIn())
    {
        if (!csDispatchDtFromSocket(&recvDescr, staticData->savedDtCount))
        {
            nsPutBuffer(rcvBuf);
            nsPutBuffer(sndBuf);

            TRCE();
            return NQ_SUCCESS;
        }
    }   
#endif /* UD_CS_INCLUDEDIRECTTRANSFER */

    nsEndRecvIntoBuffer(&recvDescr);

    if (msgLen == 0)        /* no errors so far */
    {
        /* command processor(s) have advanced the response pointer - this is used now to
           calculate the entire length of the response message */

        msgLen = (NQ_INT)((NQ_BYTE*)pResponse - (NQ_BYTE*)pHeaderOut);
    }

#ifdef UD_CS_MESSAGESIGNINGPOLICY
    /* sign outgoing message */ 
    csCreateMessageSignatureSMB(pSession, csGetUserByUid(cmHtol16(cmGetSUint16(pHeaderOut->uid))), (NQ_BYTE*)pHeaderOut, (NQ_COUNT)msgLen);
#endif /* UD_CS_MESSAGESIGNINGPOLICY */

    /* release the request buffer */

    nsPutBuffer(rcvBuf);

    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Response: command=0x%x, mid=0/%u, pid=0x%08x, sid=%lu, tid=0x%08x, status=0x%x", pHeaderOut->command, cmGetSUint16(pHeaderOut->mid), cmGetSUint16(pHeaderOut->pid), cmGetSUint16(pHeaderOut->uid), cmGetSUint16(pHeaderOut->tid), cmGetSUint32(pHeaderOut->status));

    /* send the response */

    sndLen = msgLen;
#ifdef UD_CS_INCLUDEDIRECTTRANSFER
    if (csDispatchIsDtOut() && syIsValidFile(staticData->savedDtFile))
    {
        sndLen += (NQ_INT)csDispatchDtGetCount();
    }
#endif /* UD_CS_INCLUDEDIRECTTRANSFER */
#ifdef UD_NQ_INCLUDESMBCAPTURE
    sockDescr->captureHdr.receiving = FALSE;
    cmCapturePacketWriteStart(&sockDescr->captureHdr, (NQ_UINT)sndLen);
#ifdef UD_CS_INCLUDEDIRECTTRANSFER
    if (csDispatchIsDtOut() && csDispatchDtAvailable())
    {
    	NQ_BYTE *	tempBuf;
    	NQ_COUNT	len;

    	len = csDispatchDtGetCount();
    	tempBuf = (NQ_BYTE *)cmMemoryAllocate(len);
    	syMemset(tempBuf , 0 , len);

    	cmCapturePacketWritePacket(response + 4 , (NQ_UINT)msgLen );
    	cmCapturePacketWritePacket(tempBuf , len);

    	cmMemoryFree(tempBuf);
    }
    else
#endif /* UD_CS_INCLUDEDIRECTTRANSFER */
    {
    	cmCapturePacketWritePacket(sndBuf + 4, (NQ_UINT)sndLen);
    }
	cmCapturePacketWriteEnd();

#endif /* UD_NQ_INCLUDESMBCAPTURE */
    /* send and release buffer */
	msgLen = (NQ_INT)nsPrepareNBBuffer(sndBuf, (NQ_UINT)sndLen, (NQ_UINT)msgLen);
    if(0 == msgLen)
    {
        TRCERR("Error prepare buffer for response");
        TRCE();
        return NQ_FAIL;
    }

    sndLen = nsSendFromBuffer(
        sockDescr->socket, 
        sndBuf, 
        (NQ_UINT)sndLen,
        (NQ_UINT)msgLen,
        &releaseCallback
        );

    /* check if other side's socket is closed */

    if (sndLen != msgLen)
    {
        TRCERR("Error sending response");
        TRC2P("Required: %d, sent: %d", msgLen, sndLen);
        TRCE();
        return NQ_FAIL;
    }

#ifdef UD_CS_INCLUDEDIRECTTRANSFER
    if (csDispatchIsDtOut())
    {
        /* Transfer bytes from file to socket */
        if (!csDispatchDtToSocket(&recvDescr))
        {
            TRCE();
            return NQ_SUCCESS;
        }
        syDtEndPacket(((SocketSlot*)sockDescr->socket)->socket);
    }
#endif /* UD_CS_INCLUDEDIRECTTRANSFER */

    TRCE();

    return NQ_SUCCESS;
}

/*
 *====================================================================
 * PURPOSE: save information for a delayed response
 *--------------------------------------------------------------------
 * PARAMS:  OUT pointer to the buffer for response context
 *          IN pointer to the beginning of the response command
 *          IN expected length of the response command
 *
 * RETURNS: None
 *
 * NOTES:
 *====================================================================
 */

void
csDispatchSaveResponseContext(
    CSLateResponseContext* contextBuffer
    )
{
    TRCB();
#ifdef UD_NQ_INCLUDESMB2
    contextBuffer->isSmb2 = staticData->isSmb2; 
    if (staticData->isSmb2)
    {
        cs2DispatchSaveResponseContext(contextBuffer, cs2DispatchGetCurrentHeader());
    }
    else
    {
#endif /* UD_NQ_INCLUDESMB2 */
        contextBuffer->prot.smb1.tid = cmLtoh16(cmGetSUint16(staticData->currentPacket->tid));
        contextBuffer->prot.smb1.uid = cmLtoh16(cmGetSUint16(staticData->currentPacket->uid));
        contextBuffer->prot.smb1.mid = cmLtoh16(cmGetSUint16(staticData->currentPacket->mid));
        contextBuffer->prot.smb1.pid = cmLtoh16(cmGetSUint16(staticData->currentPacket->pid));
        contextBuffer->prot.smb1.pidHigh = cmLtoh16(cmGetSUint16(staticData->currentPacket->status1.extra.pidHigh));
        contextBuffer->socket = staticData->currentSocket;
        contextBuffer->prot.smb1.command = staticData->currentPacket->command;
        contextBuffer->prot.smb1.flags = staticData->currentPacket->flags;
        contextBuffer->prot.smb1.flags2 = cmGetSUint16(staticData->currentPacket->flags2);
#ifdef UD_CS_MESSAGESIGNINGPOLICY        
        contextBuffer->sequenceNum = (csGetSessionBySocket())->sequenceNumRes;
#endif
#ifdef UD_NQ_INCLUDESMB2
    }
#endif /* UD_NQ_INCLUDESMB2 */
    TRCE();
}

/*
 *====================================================================
 * PURPOSE: compose header and calculate command data pointer and size
 *--------------------------------------------------------------------
 * PARAMS:  IN saved context
 *
 * RETURNS: NQ_SUCCESS or error code
 *
 * NOTES:   prepares CIFS header
 *====================================================================
 */

NQ_STATUS
csDispatchPrepareLateResponse(
    CSLateResponseContext* context
    )
{
    CMCifsHeader* pHdr;        /* casted pointer */

    TRCB();
    
#ifdef UD_NQ_INCLUDESMB2
    if (context->isSmb2)
    {
        TRCE();
        return cs2DispatchPrepareLateResponse(context, (NQ_UINT32)context->status);
    }
    else
    {
#endif /* UD_NQ_INCLUDESMB2 */
        pHdr = (CMCifsHeader*)nsSkipHeader(context->socket, staticData->responseBuffer);
        pHdr->protocol[0] = 0xFF;
        pHdr->protocol[1] = 'S';
        pHdr->protocol[2] = 'M';
        pHdr->protocol[3] = 'B';
        pHdr->command = context->prot.smb1.command;
        pHdr->flags = (NQ_BYTE)(CS_SMBFLAGS | (context->prot.smb1.flags & 0x10));
        cmPutSUint16(pHdr->flags2, (NQ_UINT16)(CS_SMBFLAGS2 | (context->prot.smb1.flags2 & cmHtol16(SMB_FLAGS2_UNICODE))));

        cmPutSUint16(pHdr->tid, cmHtol16(context->prot.smb1.tid));
        cmPutSUint16(pHdr->uid, cmHtol16(context->prot.smb1.uid));
        cmPutSUint16(pHdr->mid, cmHtol16(context->prot.smb1.mid));
        cmPutSUint16(pHdr->pid, cmHtol16(context->prot.smb1.pid));
        cmPutSUint16(pHdr->status1.extra.pidHigh, cmHtol16(context->prot.smb1.pidHigh));
        context->commandData = (NQ_BYTE*)(pHdr + 1);
        context->commandDataSize = (NQ_COUNT)(sizeof(staticData->responseBuffer) - (NQ_COUNT)(context->commandData - staticData->responseBuffer));
        
        TRCE();
        return NQ_SUCCESS;
#ifdef UD_NQ_INCLUDESMB2
    }
#endif /* UD_NQ_INCLUDESMB2 */
}

/*
 *====================================================================
 * PURPOSE: send a response using saved context
 *--------------------------------------------------------------------
 * PARAMS:  IN saved context
 *          IN status to respond
 *          IN command data length
 *
 * RETURNS: TRUE for success
 *
 * NOTES:   prepares CIFS header
 *====================================================================
 */

NQ_BOOL
csDispatchSendLateResponse(
    CSLateResponseContext* context,
    NQ_UINT32 status,
    NQ_COUNT dataLength
    )
{
    CMCifsHeader* pHdr;        /* casted pointer */
    NQ_COUNT packetLen;        /* actual packet length */
#ifdef UD_NQ_INCLUDESMBCAPTURE
    CSSocketDescriptor *	sockDescr;
#endif /* UD_NQ_INCLUDESMBCAPTURE */

    TRCB();

#ifdef UD_NQ_INCLUDESMB2
    if (context->isSmb2)
    {
        TRCE();
        return cs2DispatchSendLateResponse(context, dataLength);
    }
    else
    {
#endif /* UD_NQ_INCLUDESMB2 */
        pHdr = (CMCifsHeader*)nsSkipHeader(context->socket, staticData->responseBuffer);
        cmPutSUint32(pHdr->status, status);
        if (staticData->ntErrorCode)    /* NT error */
        {
            cmPutSUint16(pHdr->flags2, cmGetSUint16(pHdr->flags2) | cmHtol16(SMB_FLAGS2_32_BIT_ERROR_CODES));
        }

        packetLen = (NQ_COUNT)(context->commandData + dataLength - (NQ_BYTE*)pHdr);
#ifdef UD_CS_MESSAGESIGNINGPOLICY
        {
            CSSession * pSession;       /* current session */
            NQ_UINT32 savedSequenceNum; /* original sequence number */
            
            pSession = csGetSessionBySocket();
            savedSequenceNum = pSession->sequenceNumRes; 
            pSession->sequenceNumRes = context->sequenceNum;
            csCreateMessageSignatureSMB(pSession,
                                        csGetUserByUid(cmLtoh16(context->prot.smb1.uid)), 
                                        (NQ_BYTE *)pHdr, packetLen);
            pSession->sequenceNumRes = savedSequenceNum;
        }
#endif /* UD_CS_MESSAGESIGNINGPOLICY */
#ifdef UD_NQ_INCLUDESMBCAPTURE
		sockDescr = csGetClientSocketDescriptorBySocket(context->socket);
		if (sockDescr != NULL)
		{
			sockDescr->captureHdr.receiving = FALSE;
			cmCapturePacketWriteStart(&sockDescr->captureHdr , packetLen);
			cmCapturePacketWritePacket(staticData->responseBuffer + 4 , packetLen);
			cmCapturePacketWriteEnd();
		}
#endif /* UD_NQ_INCLUDESMBCAPTURE */
		packetLen = nsPrepareNBBuffer(staticData->responseBuffer, packetLen, packetLen);
	    if(0 == packetLen)
	    {
            TRCERR("Error prepare buffer for late response");
            TRCE();
            return FALSE;
	    }

        if (packetLen != (NQ_COUNT)nsSendFromBuffer(
            context->socket, 
            staticData->responseBuffer, 
            packetLen, 
            packetLen, 
            NULL
            )
          )
        {
            TRCERR("Error sending late response");
            TRCE();
            return FALSE;
        }
    
        TRCE();
        return TRUE;
#ifdef UD_NQ_INCLUDESMB2
    }
#endif /* UD_NQ_INCLUDESMB2 */
}

/*
 *====================================================================
 * PURPOSE: Check output buffer for enough room
 *--------------------------------------------------------------------
 * PARAMS:  IN pointer to the beginning of the output buffer
 *          IN pointer to the beginning of the response command
 *          IN expected length of the response command
 *
 * RETURNS: 0 on success or NT error code
 *
 * NOTES:
 *====================================================================
 */

NQ_UINT32
csDispatchCheckSpace(
    const CMCifsHeader* header,
    const NQ_BYTE* pResponse,
    NQ_UINT size
    )
{
    CMCifsStatus error;                         /* error structure */

    TRCB();

    error = 0L;

    /* check space and compose the error message */

    if (((NQ_UINT)(pResponse - (NQ_BYTE*)header) + size) > CS_MAXBUFFERSIZE)
    {
        TRCERR("Buffer overflow");
        error = csErrorReturn(SMB_STATUS_BUFFER_TOO_SMALL, SRV_ERRerror);
    }

    TRCE();
    return error;
}

/*
 *====================================================================
 * PURPOSE: determine type of error code to be returned in the current response
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: TRUE when NT error code should be used, FALSE for DOS code
 *
 * NOTES:
 *====================================================================
 */

NQ_BOOL
csDispatchIsNtError(
    void
    )
{
    return staticData->ntErrorCode;
}

/*
 *====================================================================
 * PURPOSE: set type of error code to be returned in the current response
 *--------------------------------------------------------------------
 * PARAMS:  IN TRUE for NT status, FALSE for DOS code
 *
 * RETURNS: TRUE when NT error code should be used, FALSE for DOS code
 *
 * NOTES:
 *====================================================================
 */

void
csDispatchSetNtError(
    NQ_BOOL type
    )
{
    staticData->ntErrorCode = type;
}

/*
 *====================================================================
 * PURPOSE: callback function for releasing a buffer
 *--------------------------------------------------------------------
 * PARAMS:  IN buffer to release
 *
 * RETURNS: None
 *
 * NOTES:
 *====================================================================
 */

static void
releaseCallback(
    const NQ_BYTE* buffer
    )
{
    nsPutBuffer((NQ_BYTE*)buffer);
}

#endif /* UD_NQ_INCLUDECIFSSERVER */

