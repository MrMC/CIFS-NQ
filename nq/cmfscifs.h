/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : CIFS definition
 *--------------------------------------------------------------------
 * MODULE        : CM - Common Library
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 22-June-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _CMFSCIFS_H_
#define _CMFSCIFS_H_

#include "cmapi.h"

#define CIFS_MAX_DATA_SIZE  (UD_NS_BUFFERSIZE - sizeof(CMNetBiosSessionMessage))    /* Max CIFS Packet data size */
#if (UD_NS_BUFFERSIZE - 4) > 0xFFFF
    #define CIFS_MAX_DATA_SIZE16 ((NQ_UINT16)0xFFFF) 
#else
    #define CIFS_MAX_DATA_SIZE16 ((NQ_UINT16)CIFS_MAX_DATA_SIZE)
#endif

/* Beginning of packed structures definition */

#include "sypackon.h"

/*
    CIFS Header
    -----------
 Is common for any CIFS message, regardless of the carried over-CIFS protocol. A CIFS
 message starts with this header.

 Constants are defined following the header definition.

 */

#define CMCifsStatus NQ_UINT32              /* we always use NT error code format even */
                                            /* with DOS contents */


#define SMB_SECURITY_SIGNATURE_LENGTH  8

typedef SY_PACK_PREFIX struct {
    NQ_SBYTE protocol[4];           /* should contain 0xFF,'SMB' */
    NQ_SBYTE command;               /* command code */
    NQ_SUINT32 status;              /* error code in optional formats */
    NQ_SBYTE flags;                 /* flags */
    NQ_SUINT16 flags2;              /* flags extension */
    union                           /* optional PID extension */
    {
        NQ_SUINT16 pad[6];          /* ensure is 12 bytes */
        struct
        {
            NQ_SUINT16 pidHigh;                                          /* high part of PID */
            NQ_SBYTE securitySignature[SMB_SECURITY_SIGNATURE_LENGTH];   /* Reserved for security */
        }
        extra;
    }
    status1;
    NQ_SUINT16 tid;                      /* tree identifier */
    NQ_SUINT16 pid;                      /* caller's process id */
    NQ_SUINT16 uid;                      /* unauthenticated user id */
    NQ_SUINT16 mid;                      /* multiplex id - client-dependent */
}
SY_PACK_ATTR CMCifsHeader;

/* 64-bit integer */

typedef SY_PACK_PREFIX struct
{
    NQ_SUINT32 low;     /* low 32 bits */
    NQ_SUINT32 high;    /* high 32 bits */
}
SY_PACK_ATTR LargeInteger;

/* Word and byte blocks */

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE count;          /* number of parameter words */
    NQ_SUINT16 data[1] ;     /* the 1st parameter */
}
SY_PACK_ATTR CMCifsWordBlock;

typedef SY_PACK_PREFIX struct
{
    NQ_SUINT16 count;        /* number of data bytes */
    NQ_SBYTE data[1];        /* the 1st byte of the data */
}
SY_PACK_ATTR CMCifsByteBlock;

/*
    SMB commands
 */

#define SMB_COM_NO_ANDX_COMMAND          0xFF

#define SMB_COM_CREATE_DIRECTORY         0x00
#define SMB_COM_DELETE_DIRECTORY         0x01
#define SMB_COM_OPEN                     0x02
#define SMB_COM_CREATE                   0x03
#define SMB_COM_CLOSE                    0x04
#define SMB_COM_FLUSH                    0x05
#define SMB_COM_DELETE                   0x06
#define SMB_COM_RENAME                   0x07
#define SMB_COM_QUERY_INFORMATION        0x08
#define SMB_COM_SET_INFORMATION          0x09
#define SMB_COM_READ                     0x0A
#define SMB_COM_WRITE                    0x0B
#define SMB_COM_LOCK_BYTE_RANGE          0x0C
#define SMB_COM_UNLOCK_BYTE_RANGE        0x0D
#define SMB_COM_CREATE_TEMPORARY         0x0E
#define SMB_COM_CREATE_NEW               0x0F
#define SMB_COM_CHECK_DIRECTORY          0x10
#define SMB_COM_PROCESS_EXIT             0x11
#define SMB_COM_SEEK                     0x12
#define SMB_COM_LOCK_AND_READ            0x13
#define SMB_COM_WRITE_AND_UNLOCK         0x14
#define SMB_COM_READ_RAW                 0x1A
#define SMB_COM_READ_MPX                 0x1B
#define SMB_COM_READ_MPX_SECONDARY       0x1C
#define SMB_COM_WRITE_RAW                0x1D
#define SMB_COM_WRITE_MPX                0x1E
#define SMB_COM_WRITE_COMPLETE           0x20
#define SMB_COM_SET_INFORMATION2         0x22
#define SMB_COM_QUERY_INFORMATION2       0x23
#define SMB_COM_LOCKING_ANDX             0x24
#define SMB_COM_TRANSACTION              0x25
#define SMB_COM_TRANSACTION_SECONDARY    0x26
#define SMB_COM_IOCTL                    0x27
#define SMB_COM_IOCTL_SECONDARY          0x28
#define SMB_COM_COPY                     0x29
#define SMB_COM_MOVE                     0x2A
#define SMB_COM_ECHO                     0x2B
#define SMB_COM_WRITE_AND_CLOSE          0x2C
#define SMB_COM_OPEN_ANDX                0x2D
#define SMB_COM_READ_ANDX                0x2E
#define SMB_COM_WRITE_ANDX               0x2F
#define SMB_COM_CLOSE_AND_TREE_DISC      0x31
#define SMB_COM_TRANSACTION2             0x32
#define SMB_COM_TRANSACTION2_SECONDARY   0x33
#define SMB_COM_FIND_CLOSE2              0x34
#define SMB_COM_FIND_NOTIFY_CLOSE        0x35
#define SMB_COM_TREE_CONNECT             0x70
#define SMB_COM_TREE_DISCONNECT          0x71
#define SMB_COM_NEGOTIATE                0x72
#define SMB_COM_SESSION_SETUP_ANDX       0x73
#define SMB_COM_LOGOFF_ANDX              0x74
#define SMB_COM_TREE_CONNECT_ANDX        0x75
#define SMB_COM_QUERY_INFORMATION_DISK   0x80
#define SMB_COM_SEARCH                   0x81
#define SMB_COM_FIND                     0x82
#define SMB_COM_FIND_UNIQUE              0x83
#define SMB_COM_FIND_CLOSE               0x84
#define SMB_COM_NT_TRANSACT              0xA0
#define SMB_COM_NT_TRANSACT_SECONDARY    0xA1
#define SMB_COM_NT_CREATE_ANDX           0xA2
#define SMB_COM_NT_CANCEL                0xA4
#define SMB_COM_OPEN_PRINT_FILE          0xC0
#define SMB_COM_WRITE_PRINT_FILE         0xC1
#define SMB_COM_CLOSE_PRINT_FILE         0xC2
#define SMB_COM_GET_PRINT_QUEUE          0xC3
#define SMB_COM_READ_BULK                0xD8
#define SMB_COM_WRITE_BULK               0xD9
#define SMB_COM_WRITE_BULK_DATA          0xDA

/*
    The flags in FLAGS2
 */

#define SMB_FLAGS2_KNOWS_LONG_NAMES        0x0001
#define SMB_FLAGS2_EXTENDED_ATTRIBUTES     0x0002
#define SMB_FLAGS2_SMB_SECURITY_SIGNATURES 0x0004
#define SMB_FLAGS2_IS_LONG_NAME            0x0040
#define SMB_FLAGS2_EXTENDED_SECURITY       0x0800
#define SMB_FLAGS2_DFS_PATHNAMES           0x1000
#define SMB_FLAGS2_READ_PERMIT_NO_EXECUTE  0x2000
#define SMB_FLAGS2_32_BIT_ERROR_CODES      0x4000
#define SMB_FLAGS2_UNICODE                 0x8000

/*
    Error handling
 */

/* defines whether a 32-bit error code is an NT code */
#define cmCifsIsNtError(code)   ((code & 0xFF) > 3)

/* defines if a return code is an error code */
#define cmCifsIsError(code)                     \
    (   cmCifsIsNtError(code)?                  \
          ((code & 0xf0000000) == 0xc0000000)   \
        : (code != 0)                           \
    )                                           \

/* pseudo code with meaning - send no response */
#define SMB_STATUS_NORESPONSE   0xff000000

/*
    Abstract data definitions
    -------------------------

 */

/* Data portion follows the header. It starts with an identifier byte which defines the futher format */

#define SMB_FIELD_DATABLOCK 1
#define SMB_FIELD_DIALECT   2
#define SMB_FIELD_PATHNAME  3
#define SMB_FIELD_ASCII     4
#define SMB_FIELD_VARIABLE  5

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE identifier;         /* data portion type (see above) */
    NQ_SUINT16 length;           /* number of bytes for DATA BLOCK or VARIABLE */
    /* NQ_BYTE data[0]; */      /* data bytes */
}
SY_PACK_ATTR CMCifsData;

/*
    File Acsess Encoding
    --------------------
 */

#define SMB_ACCESS_W            0x4000  /* write-through */
#define SMB_ACCESS_C            0x1000  /* do not cache */
#define SMB_ACCESS_L            0x0f00  /* locality of reference */
#define SMB_ACCESS_S            0x00f0  /* sharing mode */
#define SMB_ACCESS_A            0x000f  /* access mode */

#define SMB_ACCESS_L_UNKNOWN            0x0000  /* locality unknown */
#define SMB_ACCESS_L_SEQUENTIAL         0x0100  /* mainly sequential access */
#define SMB_ACCESS_L_RANDOM             0x0200  /* mainly random access */
#define SMB_ACCESS_L_RANDOMLOCALITY     0x0300  /* random access with some locality */

#define SMB_ACCESS_S_COMPATIBILITY      0x0000  /* compatibility mode */
#define SMB_ACCESS_S_READWRITEEXECUTE   0x0010  /* deny read/write/execute (exclusive) */
#define SMB_ACCESS_S_WRITE              0x0020  /* deny write */
#define SMB_ACCESS_S_READEXECUTE        0x0030  /* deny read/execute */
#define SMB_ACCESS_S_NONE               0x0040  /* deny none */
#define SMB_ACCESS_S_FCB                0x00F0  /* deny FCB */

#define SMB_ACCESS_S_DELETE             0x0800  /* shared for delete - NQ extension */

#define SMB_ACCESS_A_READ               0x0000  /* open for reading */
#define SMB_ACCESS_A_WRITE              0x0001  /* open for writing */
#define SMB_ACCESS_A_READWRITE          0x0002  /* open for reading and writing */
#define SMB_ACCESS_A_EXECUTE            0x0003  /* open for execute */
#define SMB_ACCESS_A_NONE               0x0004  /* open for info queries */
#define SMB_ACCESS_A_FCB                0x000F  /* open for all */

#define SMB_ACCESS_A_DELETE             0x8000  /* access for delete - NQ extension */

/*
    File Attribute Encoding + Extended
    ----------------------------------
 */

#define SMB_ATTR_MASK           0x7F

#define SMB_ATTR_READONLY               0x001
#define SMB_ATTR_HIDDEN                 0x002
#define SMB_ATTR_SYSTEM                 0x004
#define SMB_ATTR_VOLUME                 0x008
#define SMB_ATTR_DIRECTORY              0x010
#define SMB_ATTR_ARCHIVE                0x020
#define SMB_ATTR_DEVICE                 0x040
#define SMB_ATTR_NORMAL                 0x080

#define SMB_ATTR_FILETYPE (SMB_ATTR_VOLUME | SMB_ATTR_DIRECTORY | SMB_ATTR_DEVICE | SMB_ATTR_NORMAL)

#define SMB_ATTR_TEMPORARY              0x100
#define SMB_ATTR_SPARSE_FILE            0x200
#define SMB_ATTR_REPARSE_POINT          0x400
#define SMB_ATTR_COMPRESSED             0x800
#define SMB_ATTR_OFFLINE                0x1000
#define SMB_ATTR_NOT_CONTENT_INDEXED    0x2000
#define SMB_ATTR_ENCRYPTED              0x4000

/*
    Values in the DesiredAccess field
    ---------------------------------
 */

#define SMB_DESIREDACCESS_READDATA              0x00000001  /* file */
#define SMB_DESIREDACCESS_WRITEDATA             0x00000002  /* file */
#define SMB_DESIREDACCESS_APPENDDATA            0x00000004  /* file */
#define SMB_DESIREDACCESS_READEA                0x00000008  /* file */
#define SMB_DESIREDACCESS_WRITEEA               0x00000010  /* file */
#define SMB_DESIREDACCESS_EXECUTE               0x00000020  /* file */
#define SMB_DESIREDACCESS_DELETECHILD           0x00000040  /* file */
#define SMB_DESIREDACCESS_READATTRIBUTES        0x00000080  /* file */
#define SMB_DESIREDACCESS_WRITEATTRIBUTES       0x00000100  /* file */
#define SMB_DESIREDACCESS_DELETE                0x00010000  /* generic */
#define SMB_DESIREDACCESS_GENREAD               0x80000000  /* generic */
#define SMB_DESIREDACCESS_GENWRITE              0x40000000  /* generic */
#define SMB_DESIREDACCESS_GENEXECUTE            0x20000000  /* generic */
#define SMB_DESIREDACCESS_GENALL                0x10000000  /* generic */
#define SMB_DESIREDACCESS_GENMAXIMUMALLOWED     0x02000000  /* generic */
#define SMB_DESIREDACCESS_GENSYSTEMSECURITY     0x01000000  /* generic */
#define SMB_DESIREDACCESS_SYNCHRONISE           0x00100000  /* standard */
#define SMB_DESIREDACCESS_WRITEOWNER            0x00080000  /* standard */
#define SMB_DESIREDACCESS_WRITEDAC              0x00040000  /* standard */
#define SMB_DESIREDACCESS_READCONTROL           0x00020000  /* standard */
#define SMB_DESIREDACCESS_PRINTERUSE            0x00000008  /* printer use */
#define SMB_DESIREDACCESS_PRINTERADMIN          0x00000004  /* printer admin */
#define SMB_DESIREDACCESS_JOBASSIGNPROCESS      0x00000001  /* print job assign */
#define SMB_DESIREDACCESS_JOBSETATTRIBUTES      0x00000002  /* print job set */
#define SMB_DESIREDACCESS_JOBQUERY              0x00000004  /* print job get */
#define SMB_DESIREDACCESS_JOBTERMINATE          0x00000008  /* print job cancel */
#define SMB_DESIREDACCESS_JOBSETSECURITY        0x00000010  /* print job change access rights */

#define SMB_DESIREDACCESS_GENMASK               0xf0000000  /* generic access mask */

/*
    Values in the ShareAccess field
    -------------------------------
 */

#define SMB_SHAREACCESS_NONE 0
#define SMB_SHAREACCESS_READ 1
#define SMB_SHAREACCESS_WRITE 2
#define SMB_SHAREACCESS_DELETE 4

/*
    Share types (reported in LANMAN and SRVSVC)
    -----------
 */

#define SMB_SHARETYPE_DISKTREE 0            /* directory tree */
#define SMB_SHARETYPE_PRINTQ   1            /* print queue */
#define SMB_SHARETYPE_DEVICE   2            /* Serial device */
#define SMB_SHARETYPE_IPC      3            /* Interprocess communication (IPC) */
#define SMB_SHARETYPE_HIDDEN   0x80000000   /* share is a hidden one */

/*
    Negotiate Protocol
    ------------------
 */

/* negotiate request */

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE        wordCount;          /* count of parameters words = 0  */
    NQ_SUINT16      byteCount;          /* number of data bytes */
}
SY_PACK_ATTR CMCifsNegotiateRequest;

/* positive server response */

#define SMB_ENCRYPTION_LENGTH 8              /* length of the encryption key */
#define SMB_SESSIONKEY_LENGTH 16             /* length of the session key */

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE          wordCount;        /* count of parameters words = 17  */
    NQ_SUINT16        dialectIndex;     /* index of choosen negotiated dialect */
    NQ_SBYTE          securityMode;     /* security flags (see above) */
    NQ_SUINT16        maxMpxCount;      /* max number of pending multiplex requests - always 1 */
    NQ_SUINT16        maxNumberVcs;     /* max number of VCs between client and server */
    NQ_SUINT32        maxBufferSize;    /* max size of the message that may be sent */
    NQ_SUINT32        maxRawSize;       /* max size of the message for SMB_COM_WRITE_RAW or SMB_COM_READ_RAW */  
    NQ_SUINT32        sessionKey;       /* server-assigned token for this session */
    NQ_SUINT32        capabilities;     /* server capabilities */
    LargeInteger      systemTime;       /* server (UTC) time */
    NQ_SUINT16        serverTimeZone;   /* time zone at the server */
    NQ_SBYTE          encryptKeyLength; /* length of the encryption key */
    NQ_SUINT16        byteCount;        /* number of data bytes */
    NQ_SBYTE          encryptKey[SMB_ENCRYPTION_LENGTH];   /* the challenge encryption key */
}
SY_PACK_ATTR CMCifsNegotiateResponse;

/* negative server response - server does not understand any of the dialects */

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE          wordCount;        /* count of parameters words = 1  */
    NQ_SUINT16        dialectIndex;     /* index of choosen negotiated dialect */
    NQ_SUINT16        byteCount;        /* number of data bytes - always 0 */
}
SY_PACK_ATTR CMCifsNegotiateNegative;

#define SMB_NEGOTIATE_RESPONSE_WORDCOUNT 17          /* expected WorCount */

#define SMB_SECURITY_USER                       0x01    /* security flag: 0 - share, 1- user */
#define SMB_SECURITY_ENCRYPT_PASSWORD           0x02    /* password should be encrypted */
#define SMB_SECURITY_SM_SIGNATURES_ENABLED      0x04    /* signatures enabled, not required */
#define SMB_SECURITY_SM_SIGNATURES_REQUIRED     0x08    /* signatures enabled, required*/

/* server capabilities */

#define SMB_CAP_RAW_MODE            0x0001  /* The server supports SMB_COM_READ_RAW and SMB_COM_WRITE_RAW */
#define SMB_CAP_MPX_MODE            0x0002  /* The server supports SMB_COM_READ_MPX and SMB_COM_WRITE_MPX */
#define SMB_CAP_UNICODE             0x0004  /* The server supports Unicode strings */
#define SMB_CAP_LARGE_FILES         0x0008  /* The server supports large files with 64 bit offsets */
#define SMB_CAP_NT_SMBS             0x0010  /* The server supports the SMBs particular to the NT LM 0.12 dialect */
#define SMB_CAP_RPC_REMOTE_APIS     0x0020  /* The sever supports remote API requests via RPC */
#define SMB_CAP_NT_STATUS           0x0040  /* The server can respond with 32 bit status codes in Status.NtStatus */
#define SMB_CAP_LEVEL_II_OPLOCKS    0x0080  /* The server supports level 2 oplocks */
#define SMB_CAP_LOCK_AND_READ       0x0100  /* The server supports the SMB_COM_LOCK_AND_READ SMB */
#define SMB_CAP_NT_FIND             0x0200  /* The server supports the TRANS2_FIND_FIRST2, TRANS2_FIND_NEXT2, and FIND_CLOSE2 commands */
#define SMB_CAP_DFS                 0x1000  /* This server is DFS aware */
#define SMB_CAP_LARGE_READX         0x4000  /* The server supports SMB_COM_READ_ANDX requests which exceed the negotiated buffer size */
#define SMB_CAP_LARGE_WRITEX        0x8000  /* The server supports SMB_COM_WRITE_ANDX requests which exceed the negotiated buffer size */
#define SMB_CAP_BULK_TRANSFER       0x20000000  /* Supports SMB_BULK_READ, SMB_BULK_WRITE */
#define SMB_CAP_COMPRESSED_DATA     0x40000000  /* Supports compressed data transfer */
#define SMB_CAP_EXTENDED_SECURITY   0x80000000  /* Supports extended security validation */
#define SMB_CAP_INFOLEVEL_PASSTHRU  0x00002000  /* Supports additional info levels in SMB_COM_TRANSACTION2 */


/*
    Session Setup AndX
    ------------------
 */

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;                         /* must read 13 */
    NQ_SBYTE andXCommand;                       /* code of the next command in the chain or 0xFF */
    NQ_SBYTE andXReserved;                      /* must be zero */
    NQ_SUINT16 andXOffset;                      /* offset to the wordCount of the next command */
    NQ_SUINT16 maxBufferSize;                   /* max buffer size on the client */
    NQ_SUINT16 maxMpxCount;                     /* maximum multiplexed pending requests */
    NQ_SUINT16 vcNumber;                        /* 0 - client was rebooted - first VC,
                                               nonzero - additional VC */
    NQ_SUINT32 sessionKey;                      /* session key (if vcNumber is not zero) */
    NQ_SUINT16 caseInsensitivePasswordLength;   /* account password size, ANSI */
    NQ_SUINT16 caseSensitivePasswordLength;     /* account password size, UNICODE */
    NQ_SUINT32 reserved;                        /* must be zero */
    NQ_SUINT32 capabilities;                    /* client capabilities */
    NQ_SUINT16 byteCount;                       /* count of data bytes */
}
SY_PACK_ATTR CMCifsSessionSetupAndXRequest;

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;                         /* must read 3 */
    NQ_SBYTE andXCommand;                       /* code of the next command in the chain or 0xFF */
    NQ_SBYTE andXReserved;                      /* must be zero */
    NQ_SUINT16 andXOffset;                      /* offset to the wordCount of the next command */
    NQ_SUINT16 action;                          /* request mode: bit0 - logged in as a guest */
    NQ_SUINT16 byteCount;                       /* number of bytes in names, going after thsi field */
}
SY_PACK_ATTR CMCifsSessionSetupAndXResponse;

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;                         /* must read 13 */
    NQ_SBYTE andXCommand;                       /* code of the next command in the chain or 0xFF */
    NQ_SBYTE andXReserved;                      /* must be zero */
    NQ_SUINT16 andXOffset;                      /* offset to the wordCount of the next command */
    NQ_SUINT16 maxBufferSize;                   /* max buffer size on the client */
    NQ_SUINT16 maxMpxCount;                     /* maximum multiplexed pending requests */
    NQ_SUINT16 vcNumber;                        /* 0 - client was rebooted - first VC,
                                               nonzero - additional VC */
    NQ_SUINT32 sessionKey;                      /* session key (if vcNumber is not zero) */
    NQ_SUINT16 blobLength;                      /* security blob length */
    NQ_SUINT32 reserved;                        /* must be zero */
    NQ_SUINT32 capabilities;                    /* client capabilities */
    NQ_SUINT16 byteCount;                       /* count of data bytes */
}
SY_PACK_ATTR CMCifsSessionSetupAndXSSPRequest;

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;                         /* must read 3 */
    NQ_SBYTE andXCommand;                       /* code of the next command in the chain or 0xFF */
    NQ_SBYTE andXReserved;                      /* must be zero */
    NQ_SUINT16 andXOffset;                      /* offset to the wordCount of the next command */
    NQ_SUINT16 action;                          /* request mode: bit0 - logged in as a guest */
    NQ_SUINT16 blobLength;                      /* security blob length */
    NQ_SUINT16 byteCount;                       /* number of bytes in names, going after thsi field */
}
SY_PACK_ATTR CMCifsSessionSetupAndXSSPResponse;

#define SMB_SESSIONSETUPANDX_REQUEST_WORDCOUNT 13   /* expected WordCount */
#define SMB_SESSIONSETUPANDX_RESPONSE_WORDCOUNT 3   /* WordCount in response */
#define SMB_SESSIONSETUPANDXSSP_REQUEST_WORDCOUNT 12/* expected WordCount */
#define SMB_SESSIONSETUPANDXSSP_RESPONSE_WORDCOUNT 4/* WordCount in response */
#define SMB_SESSIONSETUPANDX_ACTION_GUEST       1   /* logged as a guest */
#define SMB_SESSIONSETUPANDX_CREDENTIALS_LENGTH 48  /* maximum credentials length */

/*
    Logoff AndX
    -----------
 */

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;                         /* must read 2 */
    NQ_SBYTE andXCommand;                       /* code of the next command in the chain or 0xFF */
    NQ_SBYTE andXReserved;                      /* must be zero */
    NQ_SUINT16 andXOffset;                      /* offset to the wordCount of the next command */
    NQ_SUINT16 byteCount;                       /* count of data bytes - must be 0 */
}
SY_PACK_ATTR CMCifsLogoffAndXRequest;

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;                         /* must read 2 */
    NQ_SBYTE andXCommand;                       /* code of the next command in the chain or 0xFF */
    NQ_SBYTE andXReserved;                      /* must be zero */
    NQ_SUINT16 andXOffset;                      /* offset to the wordCount of the next command */
    NQ_SUINT16 byteCount;                       /* must be 0 */
}
SY_PACK_ATTR CMCifsLogoffAndXResponse;

#define SMB_LOGOFFANDX_REQUEST_WORDCOUNT  2   /* expected WordCount */
#define SMB_LOGOFFANDX_RESPONSE_WORDCOUNT 2   /* WordCount in response */

/*
    Tree Connect (AndX) and Disconnect
    ----------------------------------
 */

/* Tree Connect request and response */

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;             /* must be 0 */
    NQ_SUINT16 byteCount;           /* must be at least 4 */
    NQ_SBYTE bufferFormat;          /* must read 0x04 */
}
SY_PACK_ATTR CMCifsTreeConnectRequest;

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;             /* must read 2 */
    NQ_SUINT16 maxBufferSize;       /* message limit on server */
    NQ_SUINT16 tid;                 /* newly created TID */
    NQ_SUINT16 byteCount;           /* must read 0 */
}
SY_PACK_ATTR CMCifsTreeConnectResponse;

/* Tree Connect AndX request and response */

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;             /* must be 4 */
    NQ_SBYTE andXCommand;           /* next command */
    NQ_SBYTE andXReserved;          /* must be 0 */
    NQ_SUINT16 andXOffset;          /* offset to the next command */
    NQ_SUINT16 flags;               /* if bit 0 set - disconnect TID */
    NQ_SUINT16 passwordLength;      /* password length */
    NQ_SUINT16 byteCount;           /* must be at least 4 */
}
SY_PACK_ATTR CMCifsTreeConnectAndXRequest;

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;             /* must read 2 */
    NQ_SBYTE andXCommand;           /* next command */
    NQ_SBYTE andXReserved;          /* must be 0 */
    NQ_SUINT16 andXOffset;          /* offset to the next command */
    NQ_SUINT16 optionalSupport;     /* optional support bits (see below) */
    NQ_SUINT16 byteCount;           /* must be at least 3 */
}
SY_PACK_ATTR CMCifsTreeConnectAndXResponse;

/* bits in OptionalSupoort */

#define SMB_TREECONNECTANDX_SUPPORT_SEARCHBITS  1   /* exclusive search bits */
#define SMB_TREECONNECTANDX_SHAREISINDFS        2   /* undocumented */

/* Tree Disconnect request and response */

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;             /* must read 0 */
    NQ_SUINT16 byteCount;           /* must read 0 */
}
SY_PACK_ATTR CMCifsTreeDisconnect;

#define SMB_TREECONNECT_REQUEST_MINBYTES 4          /* minimum ByteCount */
#define SMB_TREECONNECT_RESPONSE_WORDCOUNT 3        /* WordCount in response */
#define SMB_TREECONNECTANDX_REQUEST_WORDCOUNT 4     /* expected WordCount */
#define SMB_TREECONNECTANDX_REQUEST_MINBYTES 4      /* minimum ByteCount */
#define SMB_TREECONNECTANDX_RESPONSE_WORDCOUNT 3    /* WordCount in response */

/*
    File Open/Create commands
    -------------------------
 */

/* Open File */

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;             /* must read 2 */
    NQ_SUINT16 desiredAccess;       /* mode: read/write/share */
    NQ_SUINT16 searchAttributes;    /* expected file attributes */
    NQ_SUINT16 byteCount;           /* must be at least 2 */
    NQ_SBYTE bufferFormat;          /* must read 0x04 */
}
SY_PACK_ATTR CMCifsOpenFileRequest;

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;             /* must read 2 */
    NQ_SUINT16 fid;                 /* assigned file ID */
    NQ_SUINT16 fileAttributes;      /* of the opened file */
    NQ_SUINT16 lastWriteTime;       /* time the file was last written */
    NQ_SUINT16 lastWriteDate;       /* date the file was last written */
    NQ_SUINT32 dataSize;            /* file size */
    NQ_SUINT16 grantedAccess;       /* access allowed */
    NQ_SUINT16 byteCount;           /* must be 0 */
}
SY_PACK_ATTR CMCifsOpenFileResponse;

#define SMB_OPEN_REQUEST_WORDCOUNT 2    /* expected WordCount */
#define SMB_OPEN_REQUEST_MINBYTES 2     /* minimum ByteCount */
#define SMB_OPEN_RESPONSE_WORDCOUNT 7   /* WordCount in response */

/* Open AndX */

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;             /* must read 15 */
    NQ_SBYTE andXCommand;           /* next command */
    NQ_SBYTE andXReserved;          /* must be 0 */
    NQ_SUINT16 andXOffset;          /* offset to the next command */
    NQ_SUINT16 flags;               /* see below */
    NQ_SUINT16 desiredAccess;       /* mode: read/write/share */
    NQ_SUINT16 searchAttributes;    /* expected file attributes */
    NQ_SUINT16 fileAttributes;      /* */
    NQ_SUINT32 creationTime;        /* Unix time of file creation */
    NQ_SUINT16 openFunction;        /* */
    NQ_SUINT32 allocationSize;      /* bytes to reserve on create or truncate */
    NQ_SUINT32 reserved[2];         /* must be 0 */
    NQ_SUINT16 byteCount;           /* must be at least 2 */
    NQ_SBYTE bufferFormat;          /* must read 0x04 */
}
SY_PACK_ATTR CMCifsOpenAndXRequest;

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;             /* must read 15 */
    NQ_SBYTE andXCommand;           /* next command */
    NQ_SBYTE andXReserved;          /* must be 0 */
    NQ_SUINT16 andXOffset;          /* offset to the next command */
    NQ_SUINT16 fid;                 /* assigned file ID */
    NQ_SUINT16 fileAttributes;      /* of the opened file */
    NQ_SUINT32 lastWriteTime;       /* (Unix) time the file was last written */
    NQ_SUINT32 dataSize;            /* file size */
    NQ_SUINT16 grantedAccess;       /* access allowed */
    NQ_SUINT16 fileType;            /* must be 0 */
    NQ_SUINT16 deviceState;         /* access allowed */
    NQ_SUINT16 action;              /* action taken */
    NQ_SUINT32 serverFid;           /* server unique FID */
    NQ_SUINT16 reserved;            /* must be 0 */
    NQ_SUINT16 byteCount;           /* must be 0 */
}
SY_PACK_ATTR CMCifsOpenAndXResponse;

#define SMB_OPENANDX_REQUEST_WORDCOUNT 15       /* expected WordCount */
#define SMB_OPENANDX_REQUEST_MINBYTES 1         /* minimum ByteCount */
#define SMB_OPENANDX_RESPONSE_WORDCOUNT 15      /* WordCount in response */

#define SMB_OPENANDX_ADDITIONALINFORMATION 1    /* flag for add info */
#define SMB_OPENANDX_EXCLUSIVEOPLOCK 2          /* required exclusive oplock */

#define SMB_OPENANDX_OPENACTION 0x0003      /* mask for action when file exists */
#define SMB_OPENANDX_DOOPEN 0x0001          /* - value for action when file exists */
#define SMB_OPENANDX_DOTRUNCATE 0x0002      /* - value for action when file exists */
#define SMB_OPENANDX_CREATEACTION 0x0010    /* mask for action when file does not exist */
#define SMB_OPENANDX_DOCREATE 0x0010        /* - value for action when file does not exist */
#define SMB_OPENANDX_DOFAIL 0x0000          /* - value for action when file does not exist */

#define SMB_OPENANDX_OPENRESPONSE 0x0003    /* mask for open result in response */
#define SMB_OPENANDX_WASOPENED 0x0001       /* - value for action when file was opened */
#define SMB_OPENANDX_WASCREATED 0x0002      /* - value for action when file was created */
#define SMB_OPENANDX_WASTRUNCATED 0x0003    /* - value for action when file was truncated */
#define SMB_OPENANDX_LOCKRESPONSE 0x8000    /* mask for lock in response */
#define SMB_OPENANDX_WASLOCKED 0x8000       /* - file was exculsively opened */

/* Open Print File */

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;                     /* must read 2 */
    NQ_SUINT16 setupLength;                 /* Length of printer setup data */
    NQ_SUINT16 mode;                        /* 0 = Text mode (DOS expands TABs), 1 = Graphics mode  */
    NQ_SUINT16 byteCount;                   /* byte count must be >= 0x0002 */
    NQ_SBYTE bufferFormat;                  /* buffer format:  0x04 (ASCII string) */
}
SY_PACK_ATTR CMCifsOpenPrintFileRequest;

#define SMB_OPENPRINT_REQUEST_WORDCOUNT     2 /* expected WordCount */  
#define SMB_OPENRPINT_REQUEST_MINBYTES      2 /* minimum ByteCount */
#define SMB_OPENRPINT_REQUEST_BUFFERFORMAT  4 /* buffer format */


typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;                     /* must read 1 */
    NQ_SUINT16 fid;                         /* file handle */
    NQ_SUINT16 byteCount;                   /* byte count must be 0 */
}
SY_PACK_ATTR CMCifsOpenPrintFileResponse;

#define SMB_OPENRPINT_RESPONSE_WORDCOUNT    1 /* expected WordCount */
#define SMB_OPENRPINT_RESPONSE_BYTECOUNT    0 /* expected WordCount */


/* Create File */

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;             /* must read 3 */
    NQ_SUINT16 fileAttributes;      /* DOS FS format */
    NQ_SUINT16 creationTime;        /* time of the file creation */
    NQ_SUINT16 creationDate;        /* date of the file creation */
    NQ_SUINT16 byteCount;           /* must be at least 2 */
    NQ_SBYTE bufferFormat;          /* must read 0x04 */
}
SY_PACK_ATTR CMCifsCreateFileRequest;

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;             /* must read 1 */
    NQ_SUINT16 fid;                 /* assigned file ID */
    NQ_SUINT16 byteCount;           /* must be 0 */
}
SY_PACK_ATTR CMCifsCreateFileResponse;

#define SMB_CREATE_REQUEST_WORDCOUNT 3    /* expected WordCount */
#define SMB_CREATE_REQUEST_MINBYTES 2     /* minimum ByteCount */
#define SMB_CREATE_RESPONSE_WORDCOUNT 1   /* WordCount in response */

/* Create Directory */

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;             /* must read 0 */
    NQ_SUINT16 byteCount;           /* must be at least 2 */
    NQ_SBYTE bufferFormat;          /* must read 0x04 */
}
SY_PACK_ATTR CMCifsCreateDirectoryRequest;

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;             /* must read 0 */
    NQ_SUINT16 byteCount;           /* must be 0 */
}
SY_PACK_ATTR CMCifsCreateDirectoryResponse;

#define SMB_CREATEDIRECTORY_REQUEST_MINBYTES 2     /* minimum ByteCount */

/* NT Create AndX */

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;             /* must read 24 */
    NQ_SBYTE andXCommand;           /* next command */
    NQ_SBYTE andXReserved;          /* must be 0 */
    NQ_SUINT16 andXOffset;          /* offset to the next command */
    NQ_SBYTE reserved;              /* must be 0 */
    NQ_SUINT16 nameLength;          /* length of the name in bytes */
    NQ_SUINT32 flags;               /* see below */
    NQ_SUINT32 rootDirectoryFid;    /* if not zero the create is relative to this directory */
    NQ_SUINT32 desiredAccess;       /* NT access desired */
    LargeInteger allocationSize;    /* initial allocation size */
    NQ_SUINT32 fileAttributes;      /* for creation */
    NQ_SUINT32 shareAccess;         /* deny flags */
    NQ_SUINT32 createDisposition;   /* actions to take if the file exists or not */
    NQ_SUINT32 createOptions;       /* options to use for creation */
    NQ_SUINT32 impersonationLevel;  /* security QOS information */
    NQ_SBYTE securityFlags;         /* security QOS information:
                                       1 dynamic tracking, 2 effective only */
    NQ_SUINT16 byteCount;           /* must be at least 1 */
}
SY_PACK_ATTR CMCifsNtCreateAndXRequest;

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;             /* must read 34 */
    NQ_SBYTE andXCommand;           /* next command */
    NQ_SBYTE andXReserved;          /* must be 0 */
    NQ_SUINT16 andXOffset;          /* offset to the next command */
    NQ_SBYTE oplockLevel;           /* the oplock level granted */
    NQ_SUINT16 fid;                 /* assigned file ID */
    NQ_SUINT32 createAction;        /* the action taken */
    LargeInteger creationTime;      /* the time file was created */
    LargeInteger lastAccessTime;    /* the time file was last accessed */
    LargeInteger lastWriteTime;     /* the time file was last written */
    LargeInteger lastChangeTime;    /* the time file was last changed */
    NQ_SUINT32 fileAttributes;      /* of the opened file */
    LargeInteger allocationSize;    /* the number of bytes allocated */
    LargeInteger endOfFile;         /* the end-of-file offset */
    NQ_SUINT16 fileType;            /* see below */
    NQ_SUINT16 deviceState;         /* state of IPC device (e.g., - pipe) */
    NQ_SBYTE directory;             /* TRUE if this is a directory */
    NQ_SUINT16 byteCount;           /* must be 0 */
}
SY_PACK_ATTR CMCifsNtCreateAndXResponse;

#define SMB_NTCREATEANDX_REQUEST_WORDCOUNT 24   /* expected WordCount */
#define SMB_NTCREATEANDX_REQUEST_MINBYTES 1     /* minimum ByteCount */
#define SMB_NTCREATEANDX_RESPONSE_WORDCOUNT 34  /* WordCount in response */

/* bits in flags if the request */
#define SMB_NTCREATEANDX_REQUESTOPLOCKNONE       0x00000000     /* request no oplock */
#define SMB_NTCREATEANDX_REQUESTOPLOCKEXCLUS     0x00000002     /* request an exclusive oplock */
#define SMB_NTCREATEANDX_REQUESTOPLOCKBATCH      0x00000004     /* requesting a batch oplock */
#define SMB_NTCREATEANDX_OPENTARGET_DIR          0x00000008     /* parent directory should be opened */
#define SMB_NTCREATEANDX_REQUESTEXTENDEDRESPONSE 0x00000010     /* extended information in response */

/* oplock level in response */
#define SMB_NTCREATEANDX_RESPONSENOOPLOCK      0x00    /* no oplock granted */
#define SMB_NTCREATEANDX_RESPONSESOPLOCKEXCLUS 0x01    /* exclusive oplock granted */
#define SMB_NTCREATEANDX_RESPONSEOPLOCKBATCH   0x02    /* batch oplock granted */

/* bits in createOptions of the request */

#define SMB_NTCREATEANDX_DIRECTORY      0x0001      /* open or create a directory */
#define SMB_NTCREATEANDX_WRITETHROUGH   0x0002      /* flush buffers after write */
#define SMB_NTCREATEANDX_SEQUENTIAL     0x0004      /* sequential access only */
#define SMB_NTCREATEANDX_SYNCALERT      0x0010      /* operation should be synchronous */
#define SMB_NTCREATEANDX_NOSYNCALERT    0x0020      /* operation may be asynchronous */
#define SMB_NTCREATEANDX_NONDIRECTORY   0x0040      /* open or create a file */
#define SMB_NTCREATEANDX_NOEAKNOWLEDGE  0x0200      /* client do not understand EAs */
#define SMB_NTCREATEANDX_SHORTNAMES     0x0400      /* client understands only 8.3 names */
#define SMB_NTCREATEANDX_RANDOMACCESS   0x0800      /* file will be accessed randomly */
#define SMB_NTCREATEANDX_DELETEONCLOSE  0x1000      /* delete file on close */

/* bits in share acces of the request */
#define SMB_NTCREATEANDX_FILESHARENONE      0x00000000  /* file cannot be shared */
#define SMB_NTCREATEANDX_FILESHAREREAD      0x00000001  /* share for read */
#define SMB_NTCREATEANDX_FILESHAREWRITE     0x00000002  /* share for write */
#define SMB_NTCREATEANDX_FILESHAREDELETE    0x00000001  /* share for delete */

/* bits in impersonation level of the request */
#define SMB_NTCREATEANDX_SECURITYANONYMOUS      0x00000000  /* Anonymous level */
#define SMB_NTCREATEANDX_SECURITYIDENTIFICATION 0x00000001  /* Identification level */
#define SMB_NTCREATEANDX_SECURITYIMPERSONATION  0x00000002  /* Impersonation level */
#define SMB_NTCREATEANDX_SECURITYDELEGATION     0x00000003  /* Delegation level */

/* bits in security options */

#define SMB_NTCREATEANDX_DYNAMICTRACKING 0x01   /* security option */
#define SMB_NTCREATEANDX_EFFECTIVEONLY   0x02   /* security option */

/* disposition values */

#define SMB_NTCREATEANDX_SUPERSEDE 0            /* do nothing action */
#define SMB_NTCREATEANDX_FILEOPEN 1             /* open file action */
#define SMB_NTCREATEANDX_FILECREATE 2           /* create action */
#define SMB_NTCREATEANDX_FILEOPENIF 3           /* open or create action */
#define SMB_NTCREATEANDX_FILEOVERWRITE 4        /* recreate action */
#define SMB_NTCREATEANDX_FILEOVERWRITEIF 5      /* create or recreate action */

/* values in file type field */

#define SMB_NTCREATEANDX_FILEORDIR      0       /* file or directory */
#define SMB_NTCREATEANDX_MESSAGEPIPE    2       /* named pipe in message mode */

/* pipe state bits and masks */

#define SMB_NTCREATEANDX_ICOUNT         0x00ff  /* ?? */
#define SMB_NTCREATEANDX_READMASK       0x0300  /* pipe access options */
#define SMB_NTCREATEANDX_READ           0x0100  /* read messages from pipe */
#define SMB_NTCREATEANDX_TYPEMASK       0x0c00  /* pipe type options */
#define SMB_NTCREATEANDX_MESSAGETYPE    0x0400  /* messages pipe */
#define SMB_NTCREATEANDX_ENDPOINT       0x4000  /* end point (0 means consumer end point) */

/*
    File control commands
    ---------------------
 */

/* Close file */

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;             /* must read 3 */
    NQ_SUINT16 fid;                 /* assigned file ID */
    NQ_SUINT32 lastWriteTime;       /* the Unix format time when file was last written */
    NQ_SUINT16 byteCount;           /* must be 0 */
}
SY_PACK_ATTR CMCifsCloseFileRequest;

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;             /* must be 0 */
    NQ_SUINT16 byteCount;           /* must be 0 */
}
SY_PACK_ATTR CMCifsCloseFileResponse;

#define SMB_CLOSEFILE_REQUEST_WORDCOUNT 3  /* expected WordCount */

/* Close Print File */

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;             /* must read 1 */
    NQ_SUINT16 fid;                 /* assigned file ID */
    NQ_SUINT16 byteCount;           /* byte count must be 0 */
}
SY_PACK_ATTR CMCifsClosePrintRequest;

#define SMB_CLOSEPRINT_REQUEST_WORDCOUNT 1  /* expected WordCount */
#define SMB_CLOSEPRINT_REQUEST_BYTECOUNT 0  /* expected byteCount */

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;             /* must read 0 */
    NQ_SUINT16 byteCount;           /* byte count must be 0 */
}
SY_PACK_ATTR CMCifsClosePrintResponse;

#define SMB_CLOSEPRINT_RESPONSE_WORDCOUNT 0  /* expected WordCount */
#define SMB_CLOSEPRINT_RESPONSE_BYTECOUNT 0  /* expected byteCount */


/* Delete file */

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;             /* must read 1 */
    NQ_SUINT16 searchAttributes;    /* file types allowed for delete */
    NQ_SUINT16 byteCount;           /* must be at least 2 */
    NQ_SBYTE bufferFormat;          /* must read 0x04 */
}
SY_PACK_ATTR CMCifsDeleteFileRequest;

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;             /* must be 0 */
    NQ_SUINT16 byteCount;           /* must be 0 */
}
SY_PACK_ATTR CMCifsDeleteFileResponse;

#define SMB_DELETEFILE_REQUEST_WORDCOUNT 1  /* expected WordCount */
#define SMB_DELETEFILE_REQUEST_MINBYTES 2   /* minimum ByteCount */

/* Rename file */

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;             /* must read 1 */
    NQ_SUINT16 searchAttributes;    /* file types allowed for delete */
    NQ_SUINT16 byteCount;           /* must be at least 2 */
    NQ_SBYTE bufferFormat;          /* must read 0x04 */
}
SY_PACK_ATTR CMCifsRenameFileRequest;

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;             /* must be 0 */
    NQ_SUINT16 byteCount;           /* must be 0 */
}
SY_PACK_ATTR CMCifsRenameFileResponse;

#define SMB_RENAMEFILE_REQUEST_WORDCOUNT 1  /* expected WordCount */
#define SMB_RENAMEFILE_REQUEST_MINBYTES 4   /* minimum ByteCount */

/* Flush file */

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;             /* must read 1 */
    NQ_SUINT16 fid;                 /* file to flush on */
    NQ_SUINT16 byteCount;           /* must be 0 */
}
SY_PACK_ATTR CMCifsFlushFileRequest;

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;             /* must be 0 */
    NQ_SUINT16 byteCount;           /* must be 0 */
}
SY_PACK_ATTR CMCifsFlushFileResponse;

#define SMB_FLUSHFILE_REQUEST_WORDCOUNT 1  /* expected WordCount */

/* Read file */

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;             /* must read 5 */
    NQ_SUINT16 fid;                 /* file to flush on */
    NQ_SUINT16 count;               /* number of bytes to read */
    NQ_SUINT32 offset;              /* position to read from */
    NQ_SUINT16 remaining;           /* must be 0 */
    NQ_SUINT16 byteCount;           /* must be 0 */
}
SY_PACK_ATTR CMCifsReadFileRequest;

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;             /* must be 5 */
    NQ_SUINT16 count;               /* bytes in data */
    NQ_SUINT16 reserved[4];         /* must be 0 */
    NQ_SUINT16 byteCount;           /* must be as count */
}
SY_PACK_ATTR CMCifsReadFileResponse;

#define SMB_READFILE_REQUEST_WORDCOUNT 5    /* expected WordCount */
#define SMB_READFILE_RESPONSE_WORDCOUNT 5   /* response WordCount */

/* Read AndX */

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;              /* must read 10 or 12 */
    NQ_SBYTE andXCommand;            /* next command */
    NQ_SBYTE andXReserved;           /* must be 0 */
    NQ_SUINT16 andXOffset;           /* offset to the next command */
    NQ_SUINT16 fid;                  /* file to flush on */
    NQ_SUINT32 offset;               /* position to read from */
    NQ_SUINT16 maxCount;             /* maximum number of bytes to read */
    NQ_SUINT16 minCount;             /* maximum number of bytes to read */
    NQ_SUINT32 maxCountHigh;         /* union of timeout (32 bit) or max count high (16 bit) when CAP_LARGE_READX supported */
    NQ_SUINT16 remaining;            /* must be 0 (ignored) */
}
SY_PACK_ATTR CMCifsReadAndXRequest;

typedef SY_PACK_PREFIX struct
{
    CMCifsReadAndXRequest read;     /* previous format */
    NQ_SUINT32 offsetHigh;          /* position to read from (high portion) */
}
SY_PACK_ATTR CMCifsReadAndXRequest1;

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;             /* must be 12 */
    NQ_SBYTE andXCommand;           /* next command */
    NQ_SBYTE andXReserved;          /* must be 0 */
    NQ_SUINT16 andXOffset;          /* offset to the next command */
    NQ_SUINT16 remaining;           /* must be -1 */
    NQ_SUINT16 dataCompactionMode;  /* must be 0 */
    NQ_SUINT16 reserved1;           /* must be 0 */
    NQ_SUINT16 dataLength;          /* bytes in data */
    NQ_SUINT16 dataOffset;          /* offset from header start to data */
    NQ_SUINT16 reserved2[5];        /* must be 0 */
    NQ_SUINT16 byteCount;           /* must be as dataLength + possible padding */
}
SY_PACK_ATTR CMCifsReadAndXResponse;

#define SMB_READANDX_REQUEST_WORDCOUNT  10  /* expected WordCount */
#define SMB_READANDX_REQUEST_WORDCOUNT1 12  /* expected WordCount */
#define SMB_READANDX_RESPONSE_WORDCOUNT 12  /* response WordCount */

/* Write bytes */

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;             /* must read 5 */
    NQ_SUINT16 fid;                 /* file to write to */
    NQ_SUINT16 count;               /* number of bytes to write */
    NQ_SUINT32 offset;              /* position to write to */
    NQ_SUINT16 remaining;           /* must be 0 */
    NQ_SUINT16 byteCount;           /* number of data bytes */
}
SY_PACK_ATTR CMCifsWriteBytesRequest;

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;             /* must be 1 */
    NQ_SUINT16 count;               /* number of bytes actually written */
    NQ_SUINT16 byteCount;           /* must be 0 */
}
SY_PACK_ATTR CMCifsWriteBytesResponse;

#define SMB_WRITEBYTES_REQUEST_WORDCOUNT 5   /* expected WordCount */
#define SMB_WRITEBYTES_RESPONSE_WORDCOUNT 1  /* response WordCount */

/* Write AndX */

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;              /* must read 12 */
    NQ_SBYTE andXCommand;            /* next command */
    NQ_SBYTE andXReserved;           /* must be 0 */
    NQ_SUINT16 andXOffset;           /* offset to the next command */
    NQ_SUINT16 fid;                  /* file to write to */
    NQ_SUINT32 offset;               /* position to write to */
    NQ_SUINT32 reserved;             /* must be 0 */
    NQ_SUINT16 writeMode;            /* Bit 0 - write through */
    NQ_SUINT16 remaining;            /* bytes remaining to satisfy request */
    NQ_SUINT16 dataLengthHigh;       /* high portion of the data length (used when LARGE_WRITEX supported) */
    NQ_SUINT16 dataLength;           /* low portion of the data length */
    NQ_SUINT16 dataOffset;           /* data offset from the CIFS header */
}
SY_PACK_ATTR CMCifsWriteAndXRequest;

typedef SY_PACK_PREFIX struct
{
    CMCifsWriteAndXRequest request; /* as above */
    NQ_SUINT32 offsetHigh;           /* high portion of the data offset */
}
SY_PACK_ATTR CMCifsWriteAndXRequest1;

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;              /* must be 6 */
    NQ_SBYTE andXCommand;            /* next command */
    NQ_SBYTE andXReserved;           /* must be 0 */
    NQ_SUINT16 andXOffset;           /* offset to the next command */
    NQ_SUINT16 count;                /* number of bytes actually written */
    NQ_SUINT16 remaining;            /* reserved */
    NQ_SUINT16 countHigh;            /* upper bits of the number of bytes */
    NQ_SUINT16 reserved;             /* reserved */
    NQ_SUINT16 byteCount;            /* must be 0 */
}
SY_PACK_ATTR CMCifsWriteAndXResponse;

#define SMB_WRITEANDX_REQUEST_WORDCOUNT  12 /* expected WordCount */
#define SMB_WRITEANDX_REQUEST_WORDCOUNT1 14 /* expected WordCount */
#define SMB_WRITEANDX_RESPONSE_WORDCOUNT 6  /* response WordCount */

/* Seek */

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;             /* must read 4 */
    NQ_SUINT16 fid;                 /* file to flush on */
    NQ_SUINT16 mode;                /* see below */
    NQ_SUINT32 offset;              /* new file position */
    NQ_SUINT16 byteCount;           /* number of data bytes */
}
SY_PACK_ATTR CMCifsSeekRequest;

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;             /* must be 2 */
    NQ_SUINT32 offset;              /* new file position */
    NQ_SUINT16 byteCount;           /* must be 0 */
}
SY_PACK_ATTR CMCifsSeekResponse;

#define SMB_SEEK_START 0                /* offset from file start */
#define SMB_SEEK_CURRENT 1              /* offset from current position */
#define SMB_SEEK_END 2                  /* offset from file end */
#define SMB_SEEK_REQUEST_WORDCOUNT 4    /* expected WordCount */
#define SMB_SEEK_RESPONSE_WORDCOUNT 2   /* response WordCount */

/* Query Information Disk */

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;             /* must read 0 */
    NQ_SUINT16 byteCount;           /* must be 0 */
}
SY_PACK_ATTR CMCifsQueryInformationDiskRequest;

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;             /* must be 5 */
    NQ_SUINT16 totalUnits;          /* number of allocation units */
    NQ_SUINT16 blocksPerUnit;       /* number of blocks in a unit */
    NQ_SUINT16 blockSize;           /* number of bytes in a block */
    NQ_SUINT16 freeUnits;           /* number of free units */
    NQ_SUINT16 reserved;            /* number of free units */
    NQ_SUINT16 byteCount;           /* must be 0 */
}
SY_PACK_ATTR CMCifsQueryInformationDiskResponse;

#define SMB_QUERYINFORMATIONDISK_RESPONSE_WORDCOUNT 5  /* response WordCount */

/* Query Information */

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;             /* must read 0 */
    NQ_SUINT16 byteCount;           /* must be at least 2 */
    NQ_SBYTE bufferFormat;          /* must be 4 */
}
SY_PACK_ATTR CMCifsQueryInformationRequest;

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;             /* must be 10 */
    NQ_SUINT16 fileAttributes;      /* file attributes */
    NQ_SUINT32 lastWriteTime;       /* Unix-format time the file was last written */
    NQ_SUINT32 fileSize;            /* file size */
    NQ_SUINT16 reserved[5];         /* any */
    NQ_SUINT16 byteCount;           /* must be 0 */
}
SY_PACK_ATTR CMCifsQueryInformationResponse;

#define SMB_QUERYINFORMATION_REQUEST_MINBYTES 2     /* minimum ByteCount */
#define SMB_QUERYINFORMATION_RESPONSE_WORDCOUNT 10  /* response WordCount */

/* Set Information */

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;             /* must read 8 */
    NQ_SUINT16 fileAttributes;      /* file attributes */
    NQ_SUINT32 lastWriteTime;       /* Unix-format time the file was last written */
    NQ_SUINT16 reserved[5];         /* must be zeroes */
    NQ_SUINT16 byteCount;           /* must be at least 2 */
    NQ_SBYTE bufferFormat;          /* must be 4 */
}
SY_PACK_ATTR CMCifsSetInformationRequest;

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;             /* must be 0 */
    NQ_SUINT16 byteCount;           /* must be 0 */
}
SY_PACK_ATTR CMCifsSetInformationResponse;

#define SMB_SETINFORMATION_REQUEST_MINBYTES 2       /* minimum ByteCount */
#define SMB_SETINFORMATION_REQUEST_WORDCOUNT 8      /* expected WordCount */

/* Query Information 2 */

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;             /* must read 1 */
    NQ_SUINT16 fid;                 /* file to query */
    NQ_SUINT16 byteCount;           /* must be 0 */
}
SY_PACK_ATTR CMCifsQueryInformation2Request;

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;             /* must be 11 */
    NQ_SUINT16 creationDate;        /* SMB-format date the file was last created */
    NQ_SUINT16 creationTime;        /* SMB-format time the file was last created */
    NQ_SUINT16 lastAccessDate;      /* SMB-format date the file was last accessed */
    NQ_SUINT16 lastAccessTime;      /* SMB-format time the file was last accessed */
    NQ_SUINT16 lastWriteDate;       /* SMB-format date the file was last written */
    NQ_SUINT16 lastWriteTime;       /* SMB-format time the file was last written */
    NQ_SUINT32 fileDataSize;        /* file data size */
    NQ_SUINT32 fileAllocationSize;  /* file space */
    NQ_SUINT16 fileAttributes;      /* file attributes */
    NQ_SUINT16 byteCount;           /* must be 0 */
}
SY_PACK_ATTR CMCifsQueryInformation2Response;

#define SMB_QUERYINFORMATION2_REQUEST_WORDCOUNT 1   /* expected WordCount */
#define SMB_QUERYINFORMATION2_RESPONSE_WORDCOUNT 11 /* response WordCount */

/* Set Information 2 */

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;             /* must read 7 */
    NQ_SUINT16 fid;                 /* file to set information for */
    NQ_SUINT16 creationDate;        /* SMB-format date the file was last created */
    NQ_SUINT16 creationTime;        /* SMB-format time the file was last created */
    NQ_SUINT16 lastAccessDate;      /* SMB-format date the file was last accessed */
    NQ_SUINT16 lastAccessTime;      /* SMB-format time the file was last accessed */
    NQ_SUINT16 lastWriteDate;       /* SMB-format date the file was last written */
    NQ_SUINT16 lastWriteTime;       /* SMB-format time the file was last written */
    NQ_SUINT16 byteCount;           /* must be 0 */
}
SY_PACK_ATTR CMCifsSetInformation2Request;

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;             /* must be 0 */
    NQ_SUINT16 byteCount;           /* must be 0 */
}
SY_PACK_ATTR CMCifsSetInformation2Response;

#define SMB_SETINFORMATION2_REQUEST_WORDCOUNT 7   /* expected WordCount */

/* Check Directory */

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;             /* must read 0 */
    NQ_SUINT16 byteCount;           /* must be at least 2 */
    NQ_SBYTE bufferFormat;          /* must be 0x04 */
}
SY_PACK_ATTR CMCifsCheckDirectoryRequest;

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;             /* must be 0 */
    NQ_SUINT16 byteCount;           /* must be 0 */
}
SY_PACK_ATTR CMCifsCheckDirectoryResponse;

#define SMB_CHECKDIRECTORY_REQUEST_MINBYTES 2      /* minimum ByteCount */

/* Delete Directory */

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;             /* must read 0 */
    NQ_SUINT16 byteCount;           /* must be at least 2 */
    NQ_SBYTE bufferFormat;          /* must be 0x04 */
}
SY_PACK_ATTR CMCifsDeleteDirectoryRequest;

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;             /* must be 0 */
    NQ_SUINT16 byteCount;           /* must be 0 */
}
SY_PACK_ATTR CMCifsDeleteDirectoryResponse;

#define SMB_DELETEDIRECTORY_REQUEST_MINBYTES 2      /* minimum ByteCount */

/* Search (directory) */

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;             /* must read 2 */
    NQ_SUINT16 maxCount;            /* limit of directory entries to return */
    NQ_SUINT16 searchAttributes;    /* file attributes to search for */
    NQ_SUINT16 byteCount;           /* must be at least 2 */
    NQ_SBYTE bufferFormat;          /* must be 0x04 */
}
SY_PACK_ATTR CMCifsSearchRequest;

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE bufferFormat;          /* must be 0x05 */
    NQ_SUINT16 resumeKeyLength;     /* length of the resume key - may be 0 for the 1st call */
}
SY_PACK_ATTR CMCifsSearchRequestExtension;

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;             /* must be 1 */
    NQ_SUINT16 count;               /* number of direntries returned */
    NQ_SUINT16 byteCount;           /* must be at least 3 */
    NQ_SBYTE bufferFormat;          /* must be 0x05 */
    NQ_SUINT16 dataLength;          /* length of subsequent data */
}
SY_PACK_ATTR CMCifsSearchResponse;

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE reserved;              /* see below */
    NQ_SBYTE fileName[11];          /* name of the returned file */
    NQ_SBYTE serverCookie[5];       /* server hook (client does not modify) */
    NQ_SBYTE clientCookie[4];       /* client hook (server does not modify) */
}
SY_PACK_ATTR CMCifsSearchResumeKey;

#define SMB_SEARCH_CONSUMERUSE  0x80    /* mask of bits for consumer use */
#define SMB_SEARCH_SYSTEMUSE 0x60       /* mask of bits for system use */
#define SMB_SEARCH_SERVERUSE 0x1f       /* mask of bits for server use */

typedef SY_PACK_PREFIX struct
{
    CMCifsSearchResumeKey resumeKey;    /* see above */
    NQ_SBYTE fileAttributes;             /* attributes of the reported file */
    NQ_SUINT16 lastWriteTime;            /* SMB-format time this file was last written */
    NQ_SUINT16 lastWriteDate;            /* SMB-format date this file was last written */
    NQ_SUINT32 fileSize;                 /* file size in bytes */
    NQ_SCHAR fileName[13];               /* ANSI space-filled null-terminated */
}
SY_PACK_ATTR CMCifsSearchDirectoryEntry;

#define SMB_SEARCH_REQUEST_WORDCOUNT 2          /* expected WordCount */
#define SMB_SEARCH_REQUEST_MINBYTES 5           /* minimum ByteCount */
#define SMB_SEARCH_RESPONSE_WORDCOUNT 1         /* expected WordCount */

/* Locking AndX */

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;             /* must read 8 */
    NQ_SBYTE andXCommand;           /* next command */
    NQ_SBYTE andXReserved;          /* must be 0 */
    NQ_SUINT16 andXOffset;          /* offset to the next command */
    NQ_SUINT16 fid;                 /* file to lock */
    NQ_SBYTE lockType;              /* see below */
    NQ_SBYTE oplockLevel;           /* the new oplock level */
    NQ_SUINT32 timeout;             /* millisecnds to wait for unlock */
    NQ_SUINT16 numOfUnlocks;        /* number of unlock range structures following */
    NQ_SUINT16 numOfLocks;          /* number of lock range structures following */
    NQ_SUINT16 byteCount;           /* */
}
SY_PACK_ATTR CMCifsLockingAndXRequest;

typedef SY_PACK_PREFIX struct
{
    NQ_SUINT16 pid;                 /* pid of process, "owning" lock */
    NQ_SUINT32 offset;              /* offset to bytes to (un)lock */
    NQ_SUINT32 length;              /* number of bytes to (un)lock */
}
SY_PACK_ATTR CMCifsLockingAndXRange;

typedef SY_PACK_PREFIX struct
{
    NQ_SUINT16 pid;                 /* pid of process, "owning" lock */
    NQ_SUINT16 pad;                 /* pad to 4 bytes (must be 0) */
    NQ_SUINT32 highOffset;          /* offset to bytes to (un)lock (high) */
    NQ_SUINT32 lowOffset;           /* offset to bytes to (un)lock (low)  */
    NQ_SUINT32 highLength;          /* number of bytes to (un)lock (high) */
    NQ_SUINT32 lowLength;           /* number of bytes to (un)lock (low)  */
}
SY_PACK_ATTR CMCifsLockingAndXLongRange;

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;             /* must be 2 */
    NQ_SBYTE andXCommand;           /* next command */
    NQ_SBYTE andXReserved;          /* must be 0 */
    NQ_SUINT16 andXOffset;          /* offset to the next command */
    NQ_SUINT16 byteCount;           /* must be as dataLength + possible padding */
}
SY_PACK_ATTR CMCifsLockingAndXResponse;

#define SMB_LOCKINGANDX_SHAREDLOCK 0x01     /* read-only lock */
#define SMB_LOCKINGANDX_OPLOCKRELEASE 0x02  /* oplock break notification */
#define SMB_LOCKINGANDX_CHANEGLOCKTYPE 0x04 /* change lock type */
#define SMB_LOCKINGANDX_CANCLELLOCK 0x08    /* cancel outstanding request */
#define SMB_LOCKINGANDX_LARGEFILES 0x10     /* large files locking format */

#define SMB_LOCKINGANDX_REQUEST_WORDCOUNT 8          /* expected WordCount */
#define SMB_LOCKINGANDX_REQUEST_MINBYTES 5           /* minimum ByteCount */
#define SMB_LOCKINGANDX_RESPONSE_WORDCOUNT 2         /* expected WordCount */

/*
    FIND_CLOSE2
    -----------
*/

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;             /* must be 1 */
    NQ_SUINT16 sid;                 /* search ID */
    NQ_SUINT16 byteCount;           /* must be 0 */
}
SY_PACK_ATTR CMCifsFindClose2Request;

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;             /* must be 0 */
    NQ_SUINT16 byteCount;           /* must be 0 */
}
SY_PACK_ATTR CMCifsFindClose2Response;

#define SMB_FINDCLOSE2_REQUEST_WORDCOUNT 1  /* expected WordCount */

/*
    Transaction subprotocols
    ------------------------

    Those transactions are named symbolically (TRANSACTION) or numerically
    (TRANSACTION2) and are not associated with any file

    These subprotocols do not use data portion format as for "pure" CIFS messages.

    TRANSACTION may span a message border

    a TRANSACTION consists of:
    1) header
    2) setup
    3) name
    4) parameters
    5) data

    Primary client request - the first frament of a fragmented request
 */

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;             /* value = (14 + SetupCount) */
    NQ_SUINT16 totalParameterCount; /* parameter bytes sent in all fragments */
    NQ_SUINT16 totalDataCount;      /* data bytes in all fragments */
    NQ_SUINT16 maxParameterCount;   /* max parameter bytes expected in response */
    NQ_SUINT16 maxDataCount;        /* max data bytes expected in response */
    NQ_SBYTE  maxSetupCount;        /* max setup words expected in response */
    NQ_SBYTE  reserved;
    NQ_SUINT16 flags;               /* additional information - see below */
    NQ_SUINT32 timeout;             /* not used */
    NQ_SUINT16 reserved2;
    NQ_SUINT16 parameterCount;      /* parameter bytes in this fragment */
    NQ_SUINT16 parameterOffset;     /* an offset from the header start to the parameter section */
    NQ_SUINT16 dataCount;           /* data bytes in this fragment */
    NQ_SUINT16 dataOffset;          /* an offset from the header start to the data section */
    NQ_SBYTE setupCount;            /* number of setup words in this fragment */
    NQ_SBYTE reserved3;
}
SY_PACK_ATTR CMCifsTransactionRequest;

/* values in the FLAGS field */

#define SMB_DISCONNECT_TID      0x1     /* additionally disconnect TID */
#define SMB_NO_RESPONSE         0x2     /* do not send a response */

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;                 /* value = (10 + SetupCount) */
    NQ_SUINT16 totalParameterCount;     /* parameter bytes sent in all fragments */
    NQ_SUINT16 totalDataCount;          /* data bytes in all fragments */
    NQ_SUINT16 reserved;                /* */
    NQ_SUINT16 parameterCount;          /* parameter bytes in this fragment */
    NQ_SUINT16 parameterOffset;         /* an offset from the header start to the parameter section */
    NQ_SUINT16 parameterDisplacement;   /* should be 0 */
    NQ_SUINT16 dataCount;               /* data bytes in this fragment */
    NQ_SUINT16 dataOffset;              /* an offset from the header start to the data section */
    NQ_SUINT16 dataDisplacement;        /* should be 0 */
    NQ_SBYTE setupCount;                /* number of setup words in this fragment */
    NQ_SBYTE reserved2;
}
SY_PACK_ATTR CMCifsTransactionResponse;

typedef SY_PACK_PREFIX struct
{
    NQ_SUINT16 setup[1];
}
SY_PACK_ATTR CMCifsTransactionSetup;

#define SMB_TRANSACTION_REQUEST_WORDCOUNT 14   /* expected WordCount */
#define SMB_TRANSACTION_RESPONSE_WORDCOUNT 10  /* response WordCount */

/*
    NT Transaction formats
    ----------------------
    Much like TRANSACTION2 subprotocol
 */

#define SMB_NTTRANSACT_SETSECURITYDESCRIPTOR 3      /* set security desriptor subcommand */
#define SMB_NTTRANSACT_QUERYSECURITYDESCRIPTOR 6    /* query security desriptor subcommand */

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;             /* value = 19 */
    NQ_SBYTE maxSetupCount;         /* max setup words expected in response */
    NQ_SUINT16 reserved;            /* */
    NQ_SUINT32 totalParameterCount; /* parameter bytes sent in all fragments */
    NQ_SUINT32 totalDataCount;      /* data bytes in all fragments */
    NQ_SUINT32 maxParameterCount;   /* max parameter bytes expected in response */
    NQ_SUINT32 maxDataCount;        /* max data bytes expected in response */
    NQ_SUINT32 parameterCount;      /* parameter bytes in this fragment */
    NQ_SUINT32 parameterOffset;     /* an offset from the header start to the parameter section */
    NQ_SUINT32 dataCount;           /* data bytes in this fragment */
    NQ_SUINT32 dataOffset;          /* an offset from the header start to the data section */
    NQ_SBYTE setupCount;            /* number of setup words in this fragment */
    NQ_SUINT16 function;            /* next level subcommand code */
    NQ_SUINT16 byteCount;           /* length of subsequent data */
}
SY_PACK_ATTR CMCifsNtTransactionRequest;

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;                 /* value = 18 */
    NQ_SBYTE reserved[3];               /* */
    NQ_SUINT32 totalParameterCount;     /* parameter bytes sent in all fragments */
    NQ_SUINT32 totalDataCount;          /* data bytes in all fragments */
    NQ_SUINT32 parameterCount;          /* parameter bytes in this fragment */
    NQ_SUINT32 parameterOffset;         /* an offset from the header start to the parameter section */
    NQ_SUINT32 parameterDisplacement;   /* should be 0 */
    NQ_SUINT32 dataCount;               /* data bytes in this fragment */
    NQ_SUINT32 dataOffset;              /* an offset from the header start to the data section */
    NQ_SUINT32 dataDisplacement;        /* should be 0 */
    NQ_SBYTE setupCount;                /* is zero */
    NQ_SUINT16 byteCount;               /* number of bytes, following this word */
}
SY_PACK_ATTR CMCifsNtTransactionResponse;

#define SMB_NTTRANSACTION_REQUEST_WORDCOUNT 19  /* request WordCount */
#define SMB_NTTRANSACTION_RESPONSE_WORDCOUNT 18  /* response WordCount */

/* NT_TRANSACT_CREATE */

typedef SY_PACK_PREFIX struct
{
    NQ_SUINT32 flags;                    /* creation flags (see below) */
    NQ_SUINT32 rootDirectoryFid;         /* optional directory for relative open */
    NQ_SUINT32 desiredAccess;            /* access desired */
    LargeInteger allocationSize;        /* the initial allocation size in bytes, if file created */
    NQ_SUINT32 extFileAttributes;        /* the extended file attributes */
    NQ_SUINT32 shareAccess;              /* the share access */
    NQ_SUINT32 createDisposition;        /* action if file does/does not exist */
    NQ_SUINT32 createOptions;            /* options for creating a new file */
    NQ_SUINT32 securityDescriptorLength; /* length of SD in bytes */
    NQ_SUINT32 eaLength;                 /* length of EA in bytes */
    NQ_SUINT32 nameLength;               /* length of name in characters */
    NQ_SUINT32 impersonationLevel;       /* security QOS information */
    NQ_SUINT32 securityFlags;            /* security QOS information */
}
SY_PACK_ATTR CMCifsNtTransactionCreateRequest;

#define SMB_NTTRANSACTCREATE_DIRECTORY 0x08         /* open or create a directory */

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE oplockLevel;                /* the oplock level granted */
    NQ_SBYTE reserved;                   /* */
    NQ_SUINT16 fid;                      /* the file ID */
    NQ_SUINT32 createAction;             /* the action taken */
    NQ_SUINT32 eaErrorOffset;            /* offset of the EA error */
    LargeInteger creationTime;          /* the time the file was created */
    LargeInteger lastAccessTime;        /* the time the file was accessed */
    LargeInteger lastWriteTime;         /* the time the file was last written */
    LargeInteger lastChangeTime;        /* the time the file was last changed */
    NQ_SUINT32 extFileAttributes;        /* the file attributes */
    LargeInteger allocationSize;        /* the number of byes allocated */
    LargeInteger endOfFile;             /* the end of file offset */
    NQ_SUINT16 fileType;                 /* */
    NQ_SUINT16 deviceState;              /* state of IPC device (e.g. pipe) */
    NQ_SBYTE directory;                  /* TRUE if this is a directory */
}
SY_PACK_ATTR CMCifsNtTransactionCreateResponse;

/* NT_TRANSACT QUERY_SECURITY_DESCRIPTOR */

typedef SY_PACK_PREFIX struct
{
    NQ_SUINT16 fid;                         /* the file ID */
    NQ_SUINT16 reserved;                    /* state of IPC device (e.g. pipe) */
    NQ_SUINT32 securityInformation;         /* fields of the descxriptor to get */
}
SY_PACK_ATTR CMCifsNtTransactionSecurityRequest;

/* NT_TRANSACT NOTIFY_CHANGE */

typedef SY_PACK_PREFIX struct
{
    NQ_SUINT32 completionFilter;         /* operations to monitor (see below) */
    NQ_SUINT16 fid;                      /* the file ID */
    NQ_SBYTE watchTree;                  /* if TRUE - monitor subdirectories also */
    NQ_SBYTE reserved;                   /* must be zero */
}
SY_PACK_ATTR CMCifsNtTransactionNotifyRequest;

/* Values of Completion Filter (see above) */

#define SMB_NOTIFYCHANGE_FILENAME       0x00000001
#define SMB_NOTIFYCHANGE_DIRNAME        0x00000002
#define SMB_NOTIFYCHANGE_NAME           0x00000003
#define SMB_NOTIFYCHANGE_ATTRIBUTES     0x00000004
#define SMB_NOTIFYCHANGE_SIZE           0x00000008
#define SMB_NOTIFYCHANGE_LAST_WRITE     0x00000010
#define SMB_NOTIFYCHANGE_LAST_ACCESS    0x00000020
#define SMB_NOTIFYCHANGE_CREATION       0x00000040
#define SMB_NOTIFYCHANGE_EA             0x00000080
#define SMB_NOTIFYCHANGE_SECURITY       0x00000100
#define SMB_NOTIFYCHANGE_STREAM_NAME    0x00000200
#define SMB_NOTIFYCHANGE_STREAM_SIZE    0x00000400
#define SMB_NOTIFYCHANGE_STREAM_WRITE   0x00000800

typedef SY_PACK_PREFIX struct
{
    NQ_SUINT32 nextEntryOffset;          /* offset from this entry yo the next one (4 bytes aligned) */
    NQ_SUINT32 action;                   /* action taken (see below) */
    NQ_SUINT32 fileNameLength;           /* file name length in bytes */
                                        /* file name in Unicode */
}
SY_PACK_ATTR CMCifsNtTransactionFileNotify;

/* Values in the Action field (see above) */

#define SMB_NOTIFYCHANGE_ADDED          0x00000001
#define SMB_NOTIFYCHANGE_REMOVED        0x00000002
#define SMB_NOTIFYCHANGE_MODIFIED       0x00000003
#define SMB_NOTIFYCHANGE_RENAMEDOLDNAME 0x00000004
#define SMB_NOTIFYCHANGE_RENAMEDNEWNAME 0x00000005
#define SMB_NOTIFYCHANGE_ADDEDSTREAM    0x00000006
#define SMB_NOTIFYCHANGE_REMOVEDSTREAM  0x00000007
#define SMB_NOTIFYCHANGE_MODIFIEDSTREAM 0x00000008
#define SMB_NOTIFYCHANGE_ACTIONMASK     0x0000000F

#define SMB_NOTIFYCHANGE_ISDIRECTORY    0x00001000

/*
    Server Announcement
    Our server sends a Windows-dialect message
 */

#define SMB_SERVER_NAMELEN 16                   /* lengths of NetBIOS name */
#define SMB_SERVERANNOUNCEMENT_SETUPCOUNT 3    /* number of setups */
#define SMB_SERVERANNOUNCEMENT_WORDCOUNT 10    /* response WordCount */
#define SMB_SERVERANNOUNCEMENT_BROWSER "\\MAILSLOT\\BROWSE"  /* mail slot for announcement */
#define SMB_SERVERANNOUNCEMENT_NAMELEN 17                 /* previous name zero-terminated */

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE browseType;                        /* browse opcode */
    NQ_SBYTE reserved;                          /* should be 0 */
    NQ_SUINT32 periodicity;                     /* announcement frequency in milliseconds */
    NQ_SBYTE serverName[SMB_SERVER_NAMELEN];    /* server name - null terminated */
    NQ_SBYTE versionMajor;                      /* major version number of our software */
    NQ_SBYTE versionMinor;                      /* minor version number of our software */
    NQ_SUINT32 installedServices;               /* see below */
    NQ_SUINT32 signature;                       /* should read: 0xAA55001F */
    NQ_SBYTE comment;                           /* we use 1 byte zer-length string */
}
SY_PACK_ATTR CMCifsServerAnnouncementData;

typedef SY_PACK_PREFIX struct
{
    CMCifsHeader cifsHeader;                        /* CIFS header */
    CMCifsTransactionRequest transHeader;           /* TRANSACTION header */
    NQ_SUINT16 setup1;                                  /* should be 1 */
    NQ_SUINT16 setup2;                                  /* any */
    NQ_SUINT16 setup3;                                  /* any */
    NQ_SUINT16 byteCount;                               /* byte count (subsequent data) */
    NQ_SBYTE name[SMB_SERVERANNOUNCEMENT_NAMELEN];      /* mailslot name */
    CMCifsServerAnnouncementData data;              /* announcement data */
}
SY_PACK_ATTR CMCifsServerAnnouncementRequest;

typedef SY_PACK_PREFIX struct
{
    CMCifsTransactionResponse transHeader;          /* TRANSACTION header */
    NQ_SUINT16 byteCount;                               /* byte count (subsequent data) */
    CMCifsServerAnnouncementData data;              /* announcement data */
}
SY_PACK_ATTR CMCifsServerAnnouncementResponse;

/* flags for services */

#define SMB_SERVICE_WORKSTATION     0x1
#define SMB_SERVICE_SERVER          0x2
#define SMB_SERVICE_SQL             0x4
#define SMB_SERVICE_NT              0x800
#define SMB_SERVICE_UNIX            0x1000

/* parameters of the announcement algorithm */

#define SMB_MIN_SERVER_ANNOUNCEMENT_INTERVAL    60         /* 1 min */
#define SMB_MAX_SERVER_ANNOUNCEMENT_INTERVAL    (12*60)    /* 12 min */

/*
    RAP call (\PIPE\LANMAN)
 */

#define SMB_PIPE_SETUPCOUNT 2           /* number of setups */
#define SMB_PIPE_PARAMETERCOUNT 4       /* number of parameter bytes in response */
#define SMB_PIPE_TRANSACTCODE 0x26      /* read/write operation on pipe */
#define SMB_PIPE_RESPONSE_WORDCOUNT 10  /* response WordCount */

typedef SY_PACK_PREFIX struct
{
    NQ_SUINT16 byteCount;                            /* byte count (subsequent data) */
    NQ_SBYTE pad[3];                                 /* any */
}
SY_PACK_ATTR CMCifsRapResponse;

/*
    RAP API
    -------
 */

/* status codes */

#define SMB_RAPSTATUS_NERR_Success          0   /* No errors encountered */
#define SMB_RAPSTATUS_ACCESS_DENIED         5   /* User has insufficient privilege */
#define SMB_RAPSTATUS_NETWORK_ACCESS_DENIED 65  /* Network access is denied */
#define SMB_RAPSTATUS_MORE_DATA             234 /* Additional data is available */
#define SMB_RAPSTATUS_ServerNotStarted      2114/* The server service on the remote computer is not running */
#define SMB_RAPSTATUS_BadTransactConfig     2141/* The server is not configured for transactions, IPC$ is not shared */

/*
    PIPE call
 */

typedef SY_PACK_PREFIX struct
{
    NQ_SUINT16 byteCount;                            /* byte count (subsequent data) */
    NQ_SBYTE pad;                                    /* any */
}
SY_PACK_ATTR CMCifsPipeResponse;

/* Pipe functions */

#define SMB_PIPE_CALL           0x54 /* open/write/read/close pipe */
#define SMB_PIPE_WAIT           0x53 /* wait for pipe to be nonbusy */
#define SMB_PIPE_PEEK           0x23 /* read but don't remove data */
#define SMB_PIPE_QUERYHANDSTATE 0X21 /* query pipe handle modes */
#define SMB_PIPE_SETHANDSTATE   0x01 /* set pipe handle modes */
#define SMB_PIPE_QUERYINFO      0X22 /* query pipe attributes */
#define SMB_PIPE_TRANSACT       0x26 /* write/read operation on pipe */
#define SMB_PIPE_RAWREAD        0x11 /* read pipe in "raw" (non message mode) */
#define SMB_PIPE_RAWWRITE       0x31 /* write pipe "raw" (non message mode) */

/* bits for SMB_PIPE_QUERYHANDSTATE function */

#define SMB_PIPE_HANDSTATE_RETURNIMMEDIATELY    0x8000  /* if no data avaiable */
#define SMB_PIPE_HANDSTATE_WAITFORDATA          0x0000  /* if no data avaiable */
#define SMB_PIPE_HANDSTATE_SERVERENDPOINT       0x4000  /* */
#define SMB_PIPE_HANDSTATE_CLIENTENDPOINT       0x0000  /* */
#define SMB_PIPE_HANDSTATE_BYTESTREAM           0x0000  /* pipe type */
#define SMB_PIPE_HANDSTATE_MESSAGEPIPE          0x0400  /* pipe type */
#define SMB_PIPE_HANDSTATE_READBYTES            0x0000  /* read mode */
#define SMB_PIPE_HANDSTATE_READMESSAGES         0x0100  /* read mode */
#define SMB_PIPE_HANDSTATE_INSTANCECOUNT        0x00FF  /* mask for instance count */

/* Pipe information response block */

typedef SY_PACK_PREFIX struct
{
    NQ_SUINT16 outputBufferSize;     /* actual size of buffer for outgoing (server) I/O */
    NQ_SUINT16 inputBufferSize;      /* actual size of buffer for incoming (client) I/O */
    NQ_SBYTE maximumInstances;       /* maximum allowed number of instances */
    NQ_SBYTE currentInstances;       /* current number of instances */
    NQ_SBYTE pipeNameLength;         /* length of pipe name (including the null) */
}
SY_PACK_ATTR CMCifsPipeInfo;

/*
    Transaction2 subprotocol
    ------------------------
 */

/* subcommand codes */

#define SMB_TRANS2_OPEN                     0x00 /* Create file with extended attributes */
#define SMB_TRANS2_FINDFIRST                0x01 /* Begin search for files */
#define SMB_TRANS2_FINDNEXT                 0x02 /* Resume search for files */
#define SMB_TRANS2_QUERYFSINFORMATION       0x03 /* Get file system information */
#define SMB_TRANS2_QUERYPATHINFORMATION     0x05 /* Get information about a named file or directory */
#define SMB_TRANS2_SETPATHINFORMATION       0x06 /* Set information about a named file or directory */
#define SMB_TRANS2_QUERYFILEINFORMATION     0x07 /* Get information about a handle */
#define SMB_TRANS2_SETFILEINFORMATION       0x08 /* Set information by handle */
#define SMB_TRANS2_CREATEDIRECTORY          0x0D /* Create directory with extended attributes */
#define SMB_TRANS2_GETDFSREFERRAL           0x10 /* Set information by handle */
#define SMB_TRANS2_REEPORTDFSINCONSISTENCY  0x11 /* Set information by handle */

typedef SY_PACK_PREFIX struct
{
    CMCifsTransactionRequest transHeader;       /* transaction header */
    NQ_SUINT16 subCommand;                       /* setup[0] */
}
SY_PACK_ATTR CMCifsTransaction2Request;

typedef SY_PACK_PREFIX struct
{
    CMCifsTransactionResponse transHeader;          /* TRANSACTION header */
    NQ_SUINT16 byteCount;                            /* byte count (subsequent data) */
    NQ_SBYTE pad;                                    /* any */
}
SY_PACK_ATTR CMCifsTransaction2Response;

#define SMB_TRANSACTION2_REQUEST_WORDCOUNT 15   /* expected WordCount */
#define SMB_TRANSACTION2_RESPONSE_WORDCOUNT 10  /* response WordCount */

/*
    Get DFS refferal (transaction2)
    ----------------
 */

#define SMB_GETDFS2_FIELDING      1   /* servers in referrals are capable of fielding(handling) TRANS2_GET_DFS_REFERRAL */
#define SMB_GETDFS2_HOLDSTORAGE   2   /* servers in referrals should hold the storage for the requested file */
#define SMB_GETDFS2_STRIPOFF      1   /* strip off consumed characters */

/*
    Open2 (transaction2)
    -----
 */

typedef SY_PACK_PREFIX struct
{
    NQ_SUINT16 flags;           /* additional information (see below) */
    NQ_SUINT16 desiredAccess;   /* requested file access */
    NQ_SUINT16 reserved1;       /* ought to be zero - ignored by the server */
    NQ_SUINT16 fileAttributes;  /* attributes for file if create */
    NQ_SUINT16 creationTime;    /* creation time to apply to file if create */
    NQ_SUINT16 creationDate;    /* creation date to apply to file if create */
    NQ_SUINT16 openFunction;    /* open function */
    NQ_SUINT32 allocationSize;  /* bytes to reserve on create or truncate */
    NQ_SUINT16 reserved [5];    /* must be zero */
}
SY_PACK_ATTR CMCifsOpen2Request;

typedef SY_PACK_PREFIX struct
{
    NQ_SUINT16 fid;             /* file handle */
    NQ_SUINT16 fileAttributes;  /* attributes of file */
    NQ_SUINT16 creationTime;    /* last modification time */
    NQ_SUINT16 creationDate;    /* last modification date */
    NQ_SUINT32 dataSize;        /* current file size */
    NQ_SUINT16 grantedAccess;   /* aAccess permissions actually allowed */
    NQ_SUINT16 fileType;        /* type of file */
    NQ_SUINT16 deviceState;     /* state of IPC device (e.g. pipe) */
    NQ_SUINT16 action;          /* action taken */
    NQ_SUINT32 reserved;        /* any */
    NQ_SUINT16 eaErrorOffset;   /* offset into EA list if EA error */
    NQ_SUINT32 eaLength;        /* total EA length for opened file */
}
SY_PACK_ATTR CMCifsOpen2Response;

/* bits in Flags */

#define SMB_OPEN2FLAGS_ADDINFO 1            /* return additional information */
#define SMB_OPEN2FLAGS_EXCLUSIVEOPLOCK 2    /* exclusive oplock requested */
#define SMB_OPEN2FLAGS_BATCHOPLOCK 4        /* batch oplock requested */
#define SMB_OPEN2FLAGS_EAS 8                /* return total length of EAs */

/* open function and action taken encoding */

#define SMB_OPEN2_ADDITIONALINFORMATION 1    /* flag for add info */
#define SMB_OPEN2_EXCLUSIVEOPLOCK 2          /* required exclusive oplock */

#define SMB_OPEN2_OPENACTION 0x0003      /* mask for action when file exists */
#define SMB_OPEN2_DOOPEN 0x0001          /* - value for action when file exists */
#define SMB_OPEN2_DOTRUNCATE 0x0002      /* - value for action when file exists */
#define SMB_OPEN2_CREATEACTION 0x0010    /* mask for action when file does not exist */
#define SMB_OPEN2_DOCREATE 0x0010        /* - value for action when file does not exist */
#define SMB_OPEN2_DOFAIL 0x0000          /* - value for action when file does not exist */

#define SMB_OPEN2_OPENRESPONSE 0x0003    /* mask for open result in response */
#define SMB_OPEN2_WASOPENED 0x0001       /* - value for action when file exists */
#define SMB_OPEN2_WASCREATED 0x0002      /* - value for action when file exists */
#define SMB_OPEN2_WASTRUNCATED 0x0003    /* - value for action when file exists */
#define SMB_OPEN2_LOCKRESPONSE 0x8000    /* mask for lock problem in response */
#define SMB_OPEN2_WASLOCKED 0x8000       /* - value for lock problem in response */

/*
    Find_First2 (transaction2)
    -----------
 */

typedef SY_PACK_PREFIX struct
{
    NQ_SUINT16 searchAttributes;    /* desired file attributes */
    NQ_SUINT16 searchCount;         /* maximum number of entries to return */
    NQ_SUINT16 flags;               /* additional information (see below) */
    NQ_SUINT16 informationLevel;    /* see below */
    NQ_SUINT32 searchStorageType;   /* */
    /* NQ_SBYTE fileName[0];*/      /* file name in ASCII/UNICOE */
}
SY_PACK_ATTR CMCifsFindFirst2Request;

typedef SY_PACK_PREFIX struct
{
    NQ_SUINT16 sid;                 /* search handle */
    NQ_SUINT16 searchCount;         /* number of entries returned */
    NQ_SUINT16 endOfSearch;         /* was last entry returned? */
    NQ_SUINT16 eaErrorOffset;       /* offset into EA list if EA error */
    NQ_SUINT16 lastNameOffset;      /* offset into data to file name of last entry, if
                                   server needs it to resume search; else 0 */
}
SY_PACK_ATTR CMCifsFindFirst2Response;

/* bits in Flags */

#define SMB_FINDFIRST2_CLOSE 1              /* bit 0 - close search after this request */
#define SMB_FINDFIRST2_CLOSEIF 2            /* bit 1 - close search if end of search reached */
#define SMB_FINDFIRST2_RESUMEKEY 4          /* bit 2 - return resume keys for each entry found */
#define SMB_FINDFIRST2_RESUME 8             /* bit 3 - continue search from previous ending place */

/* informationLevel values */

#define SMB_FINDFIRST2_INFOSTANDARD                 1
#define SMB_FINDFIRST2_INFOQUERYEASIZE              2
#define SMB_FINDFIRST2_INFOQUERYEASFROMLIST         3
#define SMB_FINDFIRST2_FINDFILEDIRECTORYINFO        0x101
#define SMB_FINDFIRST2_FINDFILEFULLDIRECTORYINFO    0x102
#define SMB_FINDFIRST2_FINDFILENAMESINFO            0x103
#define SMB_FINDFIRST2_FINDFILEBOTHDIRECTORYINFO    0x104
#define SMB_FINDFIRST2_FINDIDFULLDIRECTORYINFO      0x105
#define SMB_FINDFIRST2_FINDIDBOTHDIRECTORYINFO      0x106

/* passthru/SMB2 informationLevel values */

#define SMB_PASSTHRU_FILE_DIR_INFO                  1001    /* same as SMB_FINDFIRST2_FINDFILEDIRECTORYINFO */
#define SMB_PASSTHRU_FILE_DIR_FULL_INFO             1002    /* same as SMB_FINDFIRST2_FINDFILEFULLDIRECTORYINFO */
#define SMB_PASSTHRU_FILE_BOTH_DIR_INFO             1003    /* same as SMB_FINDFIRST2_FINDFILEBOTHDIRECTORYINFO */
#define SMB_PASSTHRU_FILE_NAMES_INFO                1012    /* same as SMB_FINDFIRST2_FINDFILENAMESINFO */
#define SMB_PASSTHRU_FILE_ID_BOTH_DIR_INFO          1037    /* same as SMB_FINDFIRST2_FINDIDBOTHDIRECTORYINFO */
#define SMB_PASSTHRU_FILE_ID_FULL_DIR_INFO          1038    /* same as SMB_FINDFIRST2_FINDIDFULLDIRECTORYINFO */

/* passthru/SMB2 SetInfo and QueryInfo classes */
#define SMB_PASSTHRU_FILE_BASICINFO                 1004    /* equivalent to: SMB_SETPATH2_NT_BASICINFO       (4) SMB2  */
#define SMB_PASSTHRU_FILE_STANDARDINFO              1005    /* equivalent to: SMB_QUERYPATH2_NT_STANDARDINFO  (5) SMB2  */
#define SMB_PASSTHRU_FILE_INTERNALINFO              1006    /* equivalent to: FileInternalInformation         (6) SMB2  */
#define SMB_PASSTHRU_FILE_EAINFO                    1007    /* equivalent to: SMB_QUERYPATH2_NT_EAINFO        (7) SMB2  */
#define SMB_PASSTHRU_FILE_NAMEINFO                  1009    /* equivalent to: SMB_QUERYPATH2_NT_NAMEINFO      (9) SMB2  */
#define SMB_PASSTHRU_FILE_RENAMEINFO                1010    /* equivalent to: FileRenameInformation           (10)SMB2  */                                                   
#define SMB_PASSTHRU_FILE_DISPOSITIONINFO           1013    /* equivalent to: SMB_SETPATH2_NT_DISPOSITIONINFO (13)SMB2  */
#define SMB_PASSTHRU_FILE_ALLINFO                   1018    /* equivalent to: SMB_QUERYPATH2_NT_ALLINFO       (18)SMB2  */
#define SMB_PASSTHRU_FILE_ALLOCATIONINFO            1019    /* equivalent to: SMB_SETPATH2_NT_ALLOCATIONINFO  (19)SMB2  */
#define SMB_PASSTHRU_FILE_ENDOFFILEINFO             1020    /* equivalent to: SMB_SETPATH2_NT_ENDOFFILEINFO   (20)SMB2  */
#define SMB_PASSTHRU_FILE_ALTNAMEINFO               1021    /* equivalent to: SMB_QUERYPATH2_NT_ALTNAMEINFO   (21)SMB2  */
#define SMB_PASSTHRU_FILE_NETWORKINFO               1034    /* equivalent to: FileNetworkOpenInformation      (34)SMB2  */


/* file information structures for different information levels:
    filename length (byte) and the file name follows the structure */

typedef SY_PACK_PREFIX struct
{
    NQ_SUINT16 creationDate;    /* date when file was created */
    NQ_SUINT16 creationTime;    /* time when file was created */
    NQ_SUINT16 lastAccessDate;  /* date of last file access */
    NQ_SUINT16 lastAccessTime;  /* time of last file access */
    NQ_SUINT16 lastWriteDate;   /* date of last write to the file */
    NQ_SUINT16 lastWriteTime;   /* time of last write to the file */
    NQ_SUINT32 dataSize;        /* file Size */
    NQ_SUINT32 allocationSize;  /* size of filesystem allocation unit */
    NQ_SUINT16 attributes;      /* file Attributes */
}
SY_PACK_ATTR CMCifsFileInformationStandard;

typedef SY_PACK_PREFIX struct
{
    CMCifsFileInformationStandard standard;     /* previous structure */
    NQ_SUINT32 eaSize;                           /* size of EA's information */
}
SY_PACK_ATTR CMCifsFileInformationEaSize;

typedef SY_PACK_PREFIX struct
{
    NQ_SUINT32 nextEntryOffset;      /* offset from this structure to beginning of next one */
    NQ_SUINT32 fileIndex;            /* file index in the result */
    LargeInteger creationTime;      /* file creation time */
    LargeInteger lastAccessTime;    /* last access time */
    LargeInteger lastWriteTime;     /* last write time */
    LargeInteger lastChangeTime;    /* last attribute change time */
    LargeInteger endOfFile;         /* file size */
    LargeInteger allocationSize;    /* size of filesystem allocation information  */
    NQ_SUINT32 fileAttributes;       /* NT style encoding of file attributes */
    NQ_SUINT32 fileNameLength;       /* length of filename in bytes */
}
SY_PACK_ATTR CMCifsFileDirectoryInformation;

typedef SY_PACK_PREFIX struct
{
    CMCifsFileDirectoryInformation information; /* as above */
    NQ_SUINT32 eaSize;              /* size of file's extended attributes */
}
SY_PACK_ATTR CMCifsFileFullDirectoryInformation;

typedef SY_PACK_PREFIX struct
{
    CMCifsFileFullDirectoryInformation information; /* as above */
    NQ_SBYTE shortNameLength;       /* length of the 8.3 name */
    NQ_SBYTE reserved;              /* any */
    NQ_SWCHAR shortName[12];        /* 8.3 name */
    /* NQ_SBYTE fileName[0];*/      /* file name in UNICODE/ASCII */
}
SY_PACK_ATTR CMCifsFileBothDirectoryInformation;

typedef SY_PACK_PREFIX struct
{
    CMCifsFileFullDirectoryInformation information; /* as above */
    NQ_SUINT32 reserved0;           /* unknown */
    LargeInteger fileIndex;          /* file index */
    /* NQ_SBYTE fileName[0];*/      /* file name in UNICODE/ASCII */
}
SY_PACK_ATTR CMCifsIdFullDirectoryInformation;

typedef SY_PACK_PREFIX struct
{
    CMCifsFileBothDirectoryInformation information; /* as above */
    NQ_SUINT16 reserved0;           /* unknown */
    LargeInteger fileIndex;          /* file index */
    /* NQ_SBYTE fileName[0];*/      /* file name in UNICODE/ASCII */
}
SY_PACK_ATTR CMCifsIdBothDirectoryInformation;

typedef SY_PACK_PREFIX struct
{
    NQ_SUINT32 nextEntryOffset;     /* offset from this structure to beginning of next one */
    NQ_SUINT32 fileIndex;           /* file index in the result */
    NQ_SUINT32 fileNameLength;      /* length of filename in bytes */
}
SY_PACK_ATTR CMCifsFileNamesInformation;

/*
    Find_Next2 (transaction2)
    ----------
 */

typedef SY_PACK_PREFIX struct
{
    NQ_SUINT16 sid;                 /* search ID (server-generated) */
    NQ_SUINT16 searchCount;         /* maximum number of entries to return */
    NQ_SUINT16 informationLevel;    /* as in FIND_FIRST */
    NQ_SUINT32 resumeKey;           /* value returned by previous FIND_NEXT calls */
    NQ_SUINT16 flags;               /* additional information (see below) */
    /* NQ_SBYTE fileName[0]; */     /* */
}
SY_PACK_ATTR CMCifsFindNext2Request;

typedef SY_PACK_PREFIX struct
{
    NQ_SUINT16 searchCount;         /* number of entries returned */
    NQ_SUINT16 endOfSearch;         /* was last entry returned? */
    NQ_SUINT16 eaErrorOffset;       /* offset into EA list if EA errors */
    NQ_SUINT16 lastNameOffset;      /* offset into data to file name of last entry, if
                                   server needs it to resume search; else 0 */
}
SY_PACK_ATTR CMCifsFindNext2Response;

/*
    CREATE_DIRECTORY (transaction2)
    ----------------
 */

typedef SY_PACK_PREFIX struct
{
    NQ_SUINT32 reserved;            /* must be 0 */
}
SY_PACK_ATTR CMCifsCreateDirectory2Request;

typedef SY_PACK_PREFIX struct
{
    NQ_SUINT16 eaErrorOffset;       /* offset into EA list if EA errors */
}
SY_PACK_ATTR CMCifsCreateDirectory2Response;

/*
    QUERY_FS_INFORMATION (transaction2)
    --------------------
 */

typedef SY_PACK_PREFIX struct
{
    NQ_SUINT16 informationLevel;    /* see below */
}
SY_PACK_ATTR CMCifsQueryFsInformation2Request;

/* information levels */

#define SMB_QUERYFS_INFOALLOCATION      1
#define SMB_QUERYFS_INFOVOLUME          2
#define SMB_QUERYFS_NT_VOLUMEINFO       0x102  /* FileFsVolumeInformation    (1) SMB2  */
#define SMB_QUERYFS_NT_SIZEINFO         0x103  /* FileFsSizeInformation      (3) SMB2  */
#define SMB_QUERYFS_NT_DEVICEINFO       0x104  /* FileFsDeviceInformation    (4) SMB2  */
#define SMB_QUERYFS_NT_ATTRIBUTEINFO    0x105  /* FileFsAttributeInformation (5) SMB2  */
#define SMB_QUERYFS_NT_FULLSIZEINFO     0x107  /* FileFsFullSizeInformation  (7) SMB2  */
#define SMB_QUERYFS_NT_OBJECTIDINFO     0x108  /* FileFsObjectIdInformation  (8) SMB2  */


typedef SY_PACK_PREFIX struct
{
    NQ_SUINT32 idFileSystem;    /* file system identifier.  NT server always returns 0 */
    NQ_SUINT32 sectorsPerUnit;  /* number of sectors per allocation unit */
    NQ_SUINT32 totalUnits;      /* total number of allocation units */
    NQ_SUINT32 freeUnits;       /* total number of available allocation units */
    NQ_SUINT16 sectorSize;      /* number of bytes per sector */
}
SY_PACK_ATTR CMCifsQueryFsInfoAllocationResponse;

typedef SY_PACK_PREFIX struct
{
    NQ_SUINT32 serialNumber;    /* volume serial number */
    NQ_SBYTE labelLength;       /* number of  characters in label */
}
SY_PACK_ATTR CMCifsQueryFsInfoVolumeResponse;

typedef SY_PACK_PREFIX struct
{
    LargeInteger creationTime;      /* UTC format time of valueme creation */
    NQ_SUINT32 serialNumber;        /* volume serial number */
    NQ_SUINT32 labelLength;         /* length of the volume label in bytes */
    NQ_SBYTE reserved[2];
}
SY_PACK_ATTR CMCifsQueryFsInfoNtVolumeResponse;

typedef SY_PACK_PREFIX struct
{
    LargeInteger totalUnits;        /* total number of allocation units on the volume */
    LargeInteger freeUnits;         /* number of free allocation units on the volume */
    NQ_SUINT32 sectorsPerUnit;      /* number of sectors in each allocation unit */
    NQ_SUINT32 sectorSize;          /* number of bytes in each sector */
}
SY_PACK_ATTR CMCifsQueryFsInfoNtSizeResponse;

typedef SY_PACK_PREFIX struct
{
    NQ_SUINT32 deviceType;              /* see below */
    NQ_SUINT32 deviceCharacteristics;   /* characteristics of the device - see below */
}
SY_PACK_ATTR CMCifsQueryFsInfoNtDeviceResponse;

/* file system attribute flags */
#define CM_FS_CASESENSITIVESEARCH  0x00000001
#define CM_FS_CASEPRESERVEDNAMES   0x00000002
#define CM_FS_PERSISTENTACLS       0x00000004
#define CM_FS_FILECOMPRESSION      0x00000008
#define CM_FS_VOLUMEQUOTAS         0x00000010
#define CM_FS_DEVICEISMOUNTED      0x00000020
#define CM_FS_VOLUMEISCOMPRESSED   0x00008000

typedef SY_PACK_PREFIX struct
{
    NQ_SUINT32 attributes;              /* file system attributes as defined above */
    NQ_SUINT32 maxNameLength;           /* maximum length of each file name component in bytes */
    NQ_SUINT32 fileSystemNameLength;    /* length of the filesystem name */
}
SY_PACK_ATTR CMCifsQueryFsInfoNtAttributeResponse;

typedef SY_PACK_PREFIX struct
{
    LargeInteger totalUnits;        /* total number of allocation units on the volume */
    LargeInteger callerTotalUnits;  /* total number of allocation units on the volume */
    LargeInteger freeUnits;         /* number of free allocation units on the volume */
    NQ_SUINT32 sectorsPerUnit;      /* number of sectors in each allocation unit */
    NQ_SUINT32 sectorSize;          /* number of bytes in each sector */
}
SY_PACK_ATTR CMCifsQueryFsInfoNtFullSizeResponse;

/*
    QUERY_PATH_INFORMATION (transaction2)
    ----------------------
    QUERY_FILE_INFORMATION (transaction2)
    ----------------------
    SET_PATH_INFORMATION (transaction2)
    ----------------------
    SET_FILE_INFORMATION (transaction2)
    ----------------------
 */

typedef SY_PACK_PREFIX struct
{
    NQ_SUINT16 informationLevel;    /* required detalization */
    NQ_SUINT32 reserved;            /* must be 0 */
}
SY_PACK_ATTR CMCifsPathInformation2Request;

typedef SY_PACK_PREFIX struct
{
    NQ_SUINT16 fid;                  /* file of interest */
    NQ_SUINT16 informationLevel;     /* required detalization */
    NQ_SUINT16 reserved;             /* undocumented */
}
SY_PACK_ATTR CMCifsFileInformation2Request;

#define SMB_QUERYPATH2_STANDARD             1
#define SMB_QUERYPATH2_EASIZE               2
#define SMB_QUERYPATH2_EASFROMLIST          3
#define SMB_QUERYPATH2_ALLEAS               4
#define SMB_QUERYPATH2_ISNAMEVALID          6
#define SMB_QUERYPATH2_NT_BASICINFO         0x101   /* equivalent to: FileBasicInformation         */
#define SMB_QUERYPATH2_NT_STANDARDINFO      0x102   /* equivalent to: FileStandardInformation      */
#define SMB_QUERYPATH2_NT_EAINFO            0x103   /* equivalent to: FileEaInformation            */
#define SMB_QUERYPATH2_NT_NAMEINFO          0x104   /* equivalent to: FileNameInformation          */
#define SMB_QUERYPATH2_NT_ALLINFO           0x107   /* equivalent to: FileAllInformation           */
#define SMB_QUERYPATH2_NT_ALLOCATIONINFO    0x105   /* equivalent to: FileAllocationInformation    */
#define SMB_QUERYPATH2_NT_ENDOFFILEINFO     0x106   /* equivalent to: FileEndOfFileInformation     */
#define SMB_QUERYPATH2_NT_ALTNAMEINFO       0x108   /* equivalent to: FileAlternateNameInformation */
#define SMB_QUERYPATH2_NT_STREAMINFO        0x109   /* equivalent to: FileStreamInformation        */

#define SMB_SETPATH2_STANDARD               1
#define SMB_SETPATH2_EASIZE                 2
#define SMB_SETPATH2_ALLEAS                 4
#define SMB_SETPATH2_NT_BASICINFO           0x101  /* equivalent to: FileBasicInformation          */
#define SMB_SETPATH2_NT_DISPOSITIONINFO     0x102  /* equivalent to: FileDispositionInformation    */
#define SMB_SETPATH2_NT_ALLOCATIONINFO      0x103  /* equivalent to: FileAllocationInformation     */
#define SMB_SETPATH2_NT_ENDOFFILEINFO       0x104  /* equivalent to: FileEndOfFileInformation      */

typedef SY_PACK_PREFIX struct
{
    NQ_SUINT16 creationDate;        /* date when file was created */
    NQ_SUINT16 creationTime;        /* time when file was created */
    NQ_SUINT16 lastAccessDate;      /* date of last file access */
    NQ_SUINT16 lastAccessTime;      /* time of last file access */
    NQ_SUINT16 lastWriteDate;       /* date of last write to the file */
    NQ_SUINT16 lastWriteTime;       /* time of last write to the file */
    NQ_SUINT32 dataSize;            /* file size */
    NQ_SUINT32 allocationSize;      /* size of filesystem allocation unit */
    NQ_SUINT16 attributes;          /* file Attributes */
}
SY_PACK_ATTR CMCifsFileInformation2Standard;

typedef SY_PACK_PREFIX struct
{
    CMCifsFileInformation2Standard standardInfo;    /* as above */
    NQ_SUINT32 eaSize;                               /* size of file's EA information (SMB_INFO_QUERY_EA_SIZE) */
}
SY_PACK_ATTR CMCifsFileInformation2EaSize;

typedef SY_PACK_PREFIX struct
{
    NQ_SUINT32 listLength;          /* size of EA error list (always 0) */
}
SY_PACK_ATTR CMCifsFileInformation2Eas;

typedef SY_PACK_PREFIX struct
{
    LargeInteger creationTime;     /* time when file was created */
    LargeInteger lastAccessTime;   /* time of last file access */
    LargeInteger lastWriteTime;    /* time of last write to the file */
    LargeInteger lastChangeTime;   /* time when file was last changed */
    NQ_SUINT32 attributes;         /* file Attributes */
    NQ_SUINT32 pad;                /* undocumented */
}
SY_PACK_ATTR CMCifsFileInformation2NtBasic;

typedef SY_PACK_PREFIX struct
{
    LargeInteger allocationSize;    /* number of bytes allocated to the file */
    LargeInteger endOfFile;         /* offset to the 1st free byte in the file */
    NQ_SUINT32 numberOfLinks;       /* number of hard links to the file */
    NQ_SBYTE deletePending;         /* 1 when the file is being deleted */
    NQ_SBYTE directory;             /* 1 when the file is a directory */
    NQ_SUINT16 unknown;             /* undocumented */
}
SY_PACK_ATTR CMCifsFileInformation2NtStandard;

typedef SY_PACK_PREFIX struct
{
    NQ_SUINT32 eaSize;                  /* size of file's extended attributes in bytes */
}
SY_PACK_ATTR CMCifsFileInformation2NtEaSize;

typedef SY_PACK_PREFIX struct
{
    NQ_SUINT32 fileNameLength;          /* size of the filename in bytes */
}
SY_PACK_ATTR CMCifsFileInformation2NtFileName;

typedef SY_PACK_PREFIX struct
{
    LargeInteger creationTime;      /* time when file was created */
    LargeInteger lastAccessTime;    /* time of last file access */
    LargeInteger lastWriteTime;     /* time of last write to the file */
    LargeInteger lastChangeTime;    /* time when file was last changed */
    NQ_SUINT32 attributes;          /* file attributes */
    NQ_SUINT32 pad1;                /* reserved */
    LargeInteger allocationSize;    /* allocated size of the file in number of bytes */
    LargeInteger endOfFile;         /* offset to the first free byte in the file */
    NQ_SUINT32 numberOfLinks;       /* number of hard links to the file */
    NQ_SBYTE deletePending;         /* indicates whether the file is marked for deletion */
    NQ_SBYTE directory;             /* indicates whether the file is a directory */
    NQ_SUINT16 pad2;                /* reserved */
    LargeInteger fileIndex;         /* file index */
    NQ_SUINT32 eaSize;              /* size of the file's extended attributes in number of bytes */
    NQ_SUINT32 accessFlags;         /* access rights of a file that were granted when the file was opened */
    LargeInteger byteOffset;        /* current byte offset */
    NQ_SUINT32 mode;				/* file mode - how the file will subsequently be accessed */
    NQ_SUINT32 alignment;			/* buffer alignment */
    NQ_SUINT32 fileNameLength;      /* length of the file name in number of bytes */
}
SY_PACK_ATTR CMCifsFileInformation2NtAll;

typedef SY_PACK_PREFIX struct
{
    LargeInteger allocationSize;    /* allocated size of the file in number of bytes */
}
SY_PACK_ATTR CMCifsFileInformation2NtAllocation;

typedef SY_PACK_PREFIX struct
{
    LargeInteger endOfFile;         /* offset to the first free byte in the file */
}
SY_PACK_ATTR CMCifsFileInformation2NtEndOfFile;

typedef SY_PACK_PREFIX struct
{
    LargeInteger creationTime;      /* time when file was created */
    LargeInteger lastAccessTime;    /* time of last file access */
    LargeInteger lastWriteTime;     /* time of last write to the file */
    LargeInteger lastChangeTime;    /* time when file was last changed */
    LargeInteger allocationSize;    /* allocated size of the file in number of bytes */
    LargeInteger endOfFile;         /* offset to the first free byte in the file */
    NQ_SUINT32 attributes;          /* file attributes */
    NQ_SUINT32 reserved;            /* reserved */    
}
SY_PACK_ATTR CMCifsFileNetworkOpenInformation;

typedef SY_PACK_PREFIX struct
{
    LargeInteger fileIndex;         /* file index */
}
SY_PACK_ATTR CMCifsFileInternalInformation;

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE      replaceIfExists;  /* whether to replace file if exists */
    NQ_SBYTE      pad1;             /* padding */
    NQ_SUINT16    pad2;             /* padding */
    NQ_SUINT32    rootDirFid;       /* root directory fid (always 0) */
    NQ_SUINT32    nameLength;       /* file name length */
}
SY_PACK_ATTR CMCifsFileRenameInformation;


/* SMB_COM_ECHO */

#define SMB_ECHO_WORDCOUNT  1       /* expected word count value */

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE wordCount;             /* word count */
    NQ_SUINT16 echoCount;           /* number of times the server is to echo back */
    NQ_SUINT16 byteCount;           /* byte count of echoed data */
}
SY_PACK_ATTR CMCifsEcho;


#include "sypackof.h"

/* End of packed structures definition */

/*
    Useful Macros
    -------------
 */

#define cmCifsSizeofWordParam(blockSize)  (sizeof(NQ_BYTE) + (blockSize))
#define cmCifsSizeofByteParam(blockSize)  (2 + (blockSize))
#define cmCifsEncodeAccessMode(access, shareMode, locality, writeThrough) \
    ((NQ_UINT16) (access | \
              (shareMode << 4) | \
              (locality << 8) | \
              (writeThrough ? SMB_ACCESS_W : 0)))
#define cmCifsEncodeOpenFunction(createAction, openAction) \
    ((NQ_UINT16) (openAction | \
              (createAction << 4)))

#define cmCifsSetFlags(header, flags_1, flags_2) \
    header->flags |= flags_1; \
    header->flags2 |= cmHtol16(flags_2)

#define cmCifsSetFlags2(header, flags_2) \
    { \
        cmPutSUint16(header->flags2, cmGetSUint16(header->flags2) | cmHtol16(flags_2)); \
    }

#define cmCifsGetFlags2(header, flags2) \
    { \
        flags2 = cmLtoh16(cmGetSUint16(header->flags2));\
    }

#endif    /* _CMFSCIFS_H_ */
