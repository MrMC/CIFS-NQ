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

#ifndef _CMSMB2_H_
#define _CMSMB2_H_

#include "cmapi.h"
#include "cmbuf.h"

/* SMB2 protocol identification bytes */
extern const NQ_BYTE cmSmb2ProtocolId[4];
extern const NQ_BYTE cmSmb2TrnsfrmHdrProtocolId[4];

typedef NQ_UINT16 CSDialect;
/* SMB2 negotiate dialect string */
#define SMB2GNRL_DIALECTSTRING   "SMB 2.???"
#define SMB2GNRL_DIALECTREVISION 0x0200

/* SMB2 negotiate dialect string */
#define SMB2_DIALECTSTRING   "SMB 2.002"
#define SMB2_DIALECTREVISION 0x0202

#define SMB2_1_DIALECTSTRING   "SMB 2.100"
#define SMB2_1_DIALECTREVISION 0x0210

/* SMB2 negotiate dialect string */
#define SMB2ANY_DIALECTSTRING   "SMB 2.???"
#define SMB2ANY_DIALECTREVISION 0x02ff

#define SMB3_DIALECTSTRING   "SMB 3.0.0"
#define SMB3_DIALECTREVISION 0x0300

#define SMB3_0_2_DIALECTSTRING   "SMB 3.0.2"
#define SMB3_0_2_DIALECTREVISION 0x0302

#define SMB3_1_1_DIALECTSTRING   "SMB 3.1.1"
#define SMB3_1_1_DIALECTREVISION 0x0311


/* SMB2 context types */
#define SMB2_PREAUTH_INTEGRITY_CAPABILITIES 0x0001
#define SMB2_ENCRYPTION_CAPABILITIES        0x0002

/* SMB2 context lengths */
#define SMB2_PREAUTH_INTEGRITY_CONTEXT_LEN_BYTES 0x0026
#define SMB2_ENCRYPTION_CCONTEXT_LEN_BYTES       0x0006

/* Cipher Types */
#define CIPHER_NO_CIPHER		0x0000
#define CIPHER_AES128CCM        0x0001
#define CIPHER_AES128GCM        0x0002

/* Hash algorithms */
#define SHA_512                 0x0001

/* dialect control functions */
void csSetSmbDialect(CSDialect smbDialect, NQ_BOOL on);
NQ_BOOL csGetSmbDialect(CSDialect smbDialect);

/* SMB2 command codes */
#define SMB2_CMD_NEGOTIATE      0x0000
#define SMB2_CMD_SESSIONSETUP   0x0001
#define SMB2_CMD_LOGOFF         0x0002
#define SMB2_CMD_TREECONNECT    0x0003
#define SMB2_CMD_TREEDISCONNECT 0x0004
#define SMB2_CMD_CREATE         0x0005
#define SMB2_CMD_CLOSE          0x0006
#define SMB2_CMD_FLUSH          0x0007
#define SMB2_CMD_READ           0x0008
#define SMB2_CMD_WRITE          0x0009
#define SMB2_CMD_LOCK           0x000A
#define SMB2_CMD_IOCTL          0x000B
#define SMB2_CMD_CANCEL         0x000C
#define SMB2_CMD_ECHO           0x000D
#define SMB2_CMD_QUERYDIRECTORY 0x000E
#define SMB2_CMD_CHANGENOTIFY   0x000F
#define SMB2_CMD_QUERYINFO      0x0010
#define SMB2_CMD_SETINFO        0x0011
#define SMB2_CMD_OPLOCKBREAK    0x0012
#define SMB2_CMD_NOCOMMAND	    0xFFFF

/* SMB2 header flags */
#define SMB2_FLAG_SERVER_TO_REDIR    0x00000001
#define SMB2_FLAG_ASYNC_COMMAND      0x00000002
#define SMB2_FLAG_RELATED_OPERATIONS 0x00000004
#define SMB2_FLAG_SIGNED             0x00000008
#define SMB2_FLAG_DFS_OPERATIONS     0x10000000
#define SMB2_FLAG_REPLAY_OPERATIONS  0x20000000

/* Reserved PID */
#define SMB2_PID_RESERVED 0x0000FEFF

/* Security signature */
#define SMB2_SECURITY_SIGNATURE_SIZE   16
#define SMB2_SECURITY_SIGNATURE_OFFSET 48
#define SMB2_PREAUTH_INTEGRITY_SALT_SIZE 32

/* OPLOCK levels for Create */
#define SMB2_OPLOCK_LEVEL_NONE      0x00
#define SMB2_OPLOCK_LEVEL_II        0x01
#define SMB2_OPLOCK_LEVEL_EXCLUSIVE 0x08
#define SMB2_OPLOCK_LEVEL_BATCH     0x09
#define SMB2_OPLOCK_LEVEL_LEASE     0xFF


/* Encryption Parameters */
#define SMB2_ENCRYPTION_AES128_CCM	0x0001
#define SMB2_ENCRYPTION_AES128_GCM	0x0002

/* nonce sizes */
#define SMB2_ENCRYPTION_HDR_NONCE_SIZE	   16
#define SMB2_AES128_CCM_NONCE_SIZE		   11
#define SMB2_AES128_GCM_NONCE_SIZE		   12

/* */

/* Transform header flags */
#define SMB2_USE_NEGOTIATED_CIPHER 0x0001

/* SMB2 header */
typedef struct
{
    NQ_BYTE *_start;        /* header start address in buffers */
    NQ_UINT16 size;         /* should be 64 */
    NQ_UINT16 creditCharge; /* number of charged credits */
    NQ_UINT32 status;
    NQ_UINT16 command;
    NQ_UINT16 credits;		/* number of requested credits */
    NQ_UINT32 flags;
    NQ_UINT32 next;         /* next header offset aligned 8 bytes relative to this header start */
    NQ_UINT64 mid;
    NQ_UINT64 aid;
    NQ_UINT32 pid;
    NQ_UINT32 tid;
    NQ_UINT64 sid;
    NQ_BYTE signature[SMB2_SECURITY_SIGNATURE_SIZE];
    NQ_UINT16 structSize;    /* payload size */
} CMSmb2Header;

/* SMB2 header size (always 64) */
#define SMB2_HEADERSIZE 64

typedef struct
{
	NQ_BYTE 	*_start;         /* header start address in buffers */
	NQ_BYTE 	signature[SMB2_SECURITY_SIGNATURE_SIZE];
	NQ_BYTE 	nonce[SMB2_ENCRYPTION_HDR_NONCE_SIZE];
	NQ_UINT32 	originalMsgSize;
	NQ_UINT16 	encryptionArgorithm; /* renamed on 3.1.1 to flags. only value is 0x0001
										which means SMB2_ENCRYPTION_AES128_CCM in 3.0 or "Encrypted" starting 3.1.1 */
	NQ_UINT64 	sid;

}CMSmb2TransformHeader;

#define SMB2_TRANSFORMHEADER_SIZE 52

/*
 * Initialize SMB2 request header structure 
 * The writer must point to the header start address.
 */
void cmSmb2HeaderInitForRequest(CMSmb2Header *header, const CMBufferWriter *writer, NQ_UINT16 command);
/*
 * Initialize SMB2 response header structure 
 * The writer must point to the header start address.
 */
void cmSmb2HeaderInitForResponse(CMSmb2Header *header, const CMBufferWriter *writer, NQ_UINT16 credits);
/* Prepare response header (it must be initialized before!) */
void cmSmb2HeaderSetForResponse(CMSmb2Header *header, const CMBufferWriter *writer, NQ_UINT16 credits);

/* Read SMB2 header using buffer reader */
void cmSmb2HeaderRead(CMSmb2Header *header, CMBufferReader *reader);
/* Shift to the next compound (chained) command */
NQ_BOOL cmSmb2HeaderShiftNext(CMSmb2Header *header, CMBufferReader *reader); 
/* Write SMB2 header using buffer writer (header is not const as its "start" field gets updated) */
void cmSmb2HeaderWrite(CMSmb2Header *header, CMBufferWriter *writer);

/* Get reader's current position offset relative to header start address */
NQ_UINT cmSmb2HeaderGetReaderOffset(const CMSmb2Header *header, const CMBufferReader *reader);
/* Set reader's current position offset relative to header start address */
void cmSmb2HeaderSetReaderOffset(const CMSmb2Header *header, CMBufferReader *reader, NQ_UINT16 offset);
/* Align reader relative to the header start address */
void cmSmb2HeaderAlignReader(const CMSmb2Header *header, CMBufferReader *reader, NQ_UINT alignment);
/* Get writer's current position offset relative to header start address */
NQ_UINT cmSmb2HeaderGetWriterOffset(const CMSmb2Header *header, const CMBufferWriter *writer);
/* Align writer relative to the header start address */
void cmSmb2HeaderAlignWriter(const CMSmb2Header *header, CMBufferWriter *writer, NQ_UINT alignment);

/* SMB2 Transform Header Functions*/
void cmSmb2TransformHeaderRead(CMSmb2TransformHeader *header, CMBufferReader *reader);
void cmSmb2TransformHeaderWrite(CMSmb2TransformHeader *header, CMBufferWriter *writer);

/* UUID (GUID) */
#define CMUuid NQ_Uuid

/* Generate random GUID */
void cmGenerateUuid(CMUuid *uuid);
/* Generate zero GUID */
void cmZeroUuid(CMUuid *uuid);
/* Read UUID using buffer reader */
void cmUuidRead(CMBufferReader *reader, CMUuid *uuid);
/* Write UUID using buffer writer */
void cmUuidWrite(CMBufferWriter *writer, const CMUuid *uuid);

/* Windows FILETIME structure (known as UTC in SMB1) */
typedef struct
{
    NQ_UINT32 low;
    NQ_UINT32 high;
}
CMTime;

/* Get current time as CMFileTime */
void cmGetCurrentTime(CMTime *time);

/* Read SMB2 time */
void cmTimeRead(CMBufferWriter *reader, CMTime *time);

/* Write SMB2 time value */
void cmTimeWrite(CMBufferWriter *writer, const CMTime *time);

/* SMB2 negotiate security mode flags */
#define SMB2_NEGOTIATE_SIGNINGENABLED  0x0001
#define SMB2_NEGOTIATE_SIGNINGREQUIRED 0x0002

/* SMB2 capabilities flag */
#define SMB2_CAPABILITY_DFS 				0x00000001
#define SMB2_CAPABILITY_LEASING 			0x00000002
#define SMB2_CAPABILITY_LARGE_MTU 			0x00000004
#define SMB2_CAPABILITY_MULTI_CHANNEL 		0x00000008
#define SMB2_CAPABILITY_PERSISTENT_HANDLES 	0x00000010
#define SMB2_CAPABILITY_DIRECTORY_LEASING 	0x00000020
#define SMB2_CAPABILITY_ENCRYPTION 			0x00000040

/* SMB2 session flags */
#define SMB2_SESSIONSETUP_GUEST				0x0001
#define SMB2_SESSIONSETUP_ANONYM			0x0002
#define SMB2_SESSIONSETUP_ENCRYPT			0x0004

#define SMB2_SESSIONSETUP_FLAGBINDING		0x01

#define SMB2_0_IOCTL_IS_FSCTL				0x00000001

/* Oplock levels */
#define SMB2_OPLOCK_NONE      0x00
#define SMB2_OPLOCK_II        0x01
#define SMB2_OPLOCK_EXCLUSIVE 0x08
#define SMB2_OPLOCK_BATCH     0x09

/* Impersonation levels */
#define SMB2_IMPERSONATION_ANONYMOUS      0x00000000
#define SMB2_IMPERSONATION_IDENTIFICATION 0x00000001
#define SMB2_IMPERSONATION_IMPERSONATION  0x00000002
#define SMB2_IMPERSONATION_DELEGATE       0x00000003

/* Share access */
#define SMB2_SHAREACCESS_READ   0x00000001
#define SMB2_SHAREACCESS_WRITE  0x00000002
#define SMB2_SHAREACCESS_DELETE 0x00000004

/* Create disposition */
#define SMB2_CREATEDISPOSITION_SUPERSEDE    0x00000000
#define SMB2_CREATEDISPOSITION_OPEN         0x00000001
#define SMB2_CREATEDISPOSITION_CREATE       0x00000002
#define SMB2_CREATEDISPOSITION_OPEN_IF      0x00000003
#define SMB2_CREATEDISPOSITION_OVERWRITE    0x00000004
#define SMB2_CREATEDISPOSITION_OVERWRITE_IF 0x00000005

/* Create options */
#define SMB2_CREATEOPTIONS_NONE                      0x00000000
#define SMB2_CREATEOPTIONS_DIRECTORY_FILE            0x00000001
#define SMB2_CREATEOPTIONS_WRITE_THROUGH             0x00000002
#define SMB2_CREATEOPTIONS_SEQUENTIAL_ONLY           0x00000004
#define SMB2_CREATEOPTIONS_NO_INTERMEDIATE_BUFFERING 0x00000008
#define SMB2_CREATEOPTIONS_SYNCHRONOUS_OPERATIONS    0x00000020
#define SMB2_CREATEOPTIONS_NON_DIRECTORY_FILE        0x00000040
#define SMB2_CREATEOPTIONS_NO_EA_KNOWLEDGE           0x00000200
#define SMB2_CREATEOPTIONS_DELETE_ON_CLOSE           0x00001000
#define SMB2_CREATEOPTIONS_OPEN_FOR_BACKUP_INTENT    0x00004000
#define SMB2_CREATEOPTIONS_RANDOM_ACCESS             0x00000800
#define SMB2_CREATEOPTIONS_NO_COMPRESSION            0x00008000
#define SMB2_CREATEOPTIONS_OPEN_REPARSE_POINT        0x00200000
#define SMB2_CREATEOPTIONS_OPEN_NO_RECALL            0x00400000
#define SMB2_CREATEOPTIONS_MASK                      0xFF000000
#define SMB2_CREATEOPTIONS_INVALIDMASK               0x0CE0FE00

/* Access mask bits (file, pipe, printer) */
#define SMB2_ACCESSMASKFPP_READ_DATA              0x00000001
#define SMB2_ACCESSMASKFPP_WRITE_DATA             0x00000002
#define SMB2_ACCESSMASKFPP_APPEND_DATA            0x00000004
#define SMB2_ACCESSMASKFPP_READ_EA                0x00000008
#define SMB2_ACCESSMASKFPP_WRITE_EA               0x00000010
#define SMB2_ACCESSMASKFPP_EXECUTE                0x00000020
#define SMB2_ACCESSMASKFPP_READ_ATTRIBUTES        0x00000080
#define SMB2_ACCESSMASKFPP_WRITE_ATTRIBUTES       0x00000100
#define SMB2_ACCESSMASKFPP_DELETE                 0x00010000
#define SMB2_ACCESSMASKFPP_READ_CONTROL           0x00020000
#define SMB2_ACCESSMASKFPP_WRITE_DAC              0x00040000
#define SMB2_ACCESSMASKFPP_WRITE_OWNER            0x00080000
#define SMB2_ACCESSMASKFPP_SYNCHRONIZE            0x00100000
#define SMB2_ACCESSMASKFPP_ACCESS_SYSTEM_SECURITY 0x01000000
#define SMB2_ACCESSMASKFPP_MAXIMAL_ACCESS         0x02000000
#define SMB2_ACCESSMASKFPP_GENERIC_ALL            0x10000000
#define SMB2_ACCESSMASKFPP_GENERIC_EXECUTE        0x20000000
#define SMB2_ACCESSMASKFPP_GENERIC_WRITE          0x40000000
#define SMB2_ACCESSMASKFPP_GENERIC_READ           0x80000000

/* Access mask bits (directory) */
#define SMB2_ACCESSMASKDIR_LIST_DIRECTORY         0x00000001
#define SMB2_ACCESSMASKDIR_ADD_FILE               0x00000002
#define SMB2_ACCESSMASKDIR_ADD_SUBDIRECTORY       0x00000004
#define SMB2_ACCESSMASKDIR_READ_EA                0x00000008
#define SMB2_ACCESSMASKDIR_WRITE_EA               0x00000010
#define SMB2_ACCESSMASKDIR_TRAVERSE               0x00000020
#define SMB2_ACCESSMASKDIR_DELETE_CHILD           0x00000040
#define SMB2_ACCESSMASKDIR_READ_ATTRIBUTES        0x00000080
#define SMB2_ACCESSMASKDIR_WRITE_ATTRIBUTES       0x00000100
#define SMB2_ACCESSMASKDIR_DELETE                 0x00010000
#define SMB2_ACCESSMASKDIR_READ_CONTROL           0x00020000
#define SMB2_ACCESSMASKDIR_WRITE_DAC              0x00040000
#define SMB2_ACCESSMASKDIR_WRITE_OWNER            0x00080000
#define SMB2_ACCESSMASKDIR_SYNCHRONIZE            0x00100000
#define SMB2_ACCESSMASKDIR_ACCESS_SYSTEM_SECURITY 0x01000000
#define SMB2_ACCESSMASKDIR_MAXIMAL_ACCESS         0x02000000
#define SMB2_ACCESSMASKDIR_GENERIC_ALL            0x10000000
#define SMB2_ACCESSMASKDIR_GENERIC_EXECUTE        0x20000000
#define SMB2_ACCESSMASKDIR_GENERIC_WRITE          0x40000000
#define SMB2_ACCESSMASKDIR_GENERIC_READ           0x80000000
#define SMB2_ACCESSMASK                           0x0C000000

/* File attributes */
#define SMB2_FILEATTRIBUTE_READONLY			   0x00000001
#define SMB2_FILEATTRIBUTE_HIDDEN              0x00000002
#define SMB2_FILEATTRIBUTE_SYSTEM              0x00000004
#define SMB2_FILEATTRIBUTE_DIRECTORY           0x00000010
#define SMB2_FILEATTRIBUTE_ARCHIVE             0x00000020
#define SMB2_FILEATTRIBUTE_NORMAL              0x00000080
#define SMB2_FILEATTRIBUTE_TEMPORARY           0x00000100
#define SMB2_FILEATTRIBUTE_SPARSE_FILE         0x00000200
#define SMB2_FILEATTRIBUTE_REPARSE_POINT       0x00000400
#define SMB2_FILEATTRIBUTE_COMPRESSED          0x00000800
#define SMB2_FILEATTRIBUTE_OFFLINE             0x00001000
#define SMB2_FILEATTRIBUTE_NOT_CONTENT_INDEXED 0x00002000
#define SMB2_FILEATTRIBUTE_ENCRYPTED           0x00004000
#define SMB2_FILEATTRIBS_MASK                  0xFFFF0048

/* Query/Set Info types */
#define SMB2_INFO_FILE       0x01    /* The file information is requested. */
#define SMB2_INFO_FILESYSTEM 0x02    /* The file system information is requested. */
#define SMB2_INFO_SECURITY   0x03    /* The security information is requested. */
#define SMB2_INFO_QUOTA      0x04    /* The file system quota information is requested. */

/*
  todo: probably merge SMB2_SET_FILE_XXX/SMB2_QUERY_FILE_XXX constants into SMB2_FILEINFO_XXX
        the following file information classes required:
            FileInfoBothDirectory
            FileInfoBasic
            FileInfoStandard
            FileInfoRename
            FileInfoLink
            FileInfoDisposition
            FileInfoPosition
            FileInfoFullEa
            FileInfoMode
            FileInfoAllocation
            FileInfoEndOfFile
            FileInfoPipe
            FileInfoValidDataLength
            FileInfoShortName
*/

/* File information levels */
#define SMB2_FILEINFO_BOTHDIRECTORY   3
#define SMB2_FILEINFO_ALLINFORMATION  18
#define SMB2_FILEINFO_BASIC           4
#define SMB2_FILEINFO_STANDARD        5
#define SMB2_FILEINFO_INTERNAL        6
#define SMB2_FILEINFO_RENAME          10
#define SMB2_FILEINFO_LINK
#define SMB2_FILEINFO_DISPOSITION     13
#define SMB2_FILEINFO_POSITION
#define SMB2_FILEINFO_FULLEA
#define SMB2_FILEINFO_MODE
#define SMB2_FILEINFO_ALLOCATION      19
#define SMB2_FILEINFO_EOF             20
#define SMB2_FILEINFO_PIPE
#define SMB2_FILEINFO_VALIDDATALENGTH
#define SMB2_FILEINFO_SHORTNAME

/* File rename information structure */
typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE      replaceIfExists;  /* whether to replace file if exists */
    NQ_SBYTE      pad1;             /* padding */
    NQ_SUINT32    pad2;             /* padding */
    NQ_SUINT16    pad3;             /* padding */
    LargeInteger  rootDirFid;       /* root directory fid (always 0) */
    NQ_SUINT32    nameLength;       /* file name length */
}
SY_PACK_ATTR CMSmb2FileRenameInformation;

/* File system information levels */
#define SMB2_FSINFO_VOLUME     1
#define SMB2_FSINFO_LABEL
#define SMB2_FSINFO_SIZE       3
#define SMB2_FSINFO_DEVICE
#define SMB2_FSINFO_ATTRIBUTE
#define SMB2_FSINFO_CONTROL
#define SMB2_FSINFO_FULLSIZE
#define SMB2_FSINFO_OBJECTID
#define SMB2_FSINFO_DRIVERPATH

/* Security information levels */
#define SMB2_SECINFO_0 0

/* Security information flags */
#define SMB2_SIF_OWNER 1
#define SMB2_SIF_GROUP 2
#define SMB2_SIF_DACL  4
#define SMB2_SIF_SACL  8

/* QueryDirectory flags */
#define SMB2_QDF_RESTARTSCANS      0x01
#define SMB2_QDF_RETURNSINGLEENTRY 0x02
#define SMB2_QDF_INDEXSPECIFIED    0x04
#define SMB2_QDF_REOPEN            0x10

/* File attributes */
#define SMB2_ATTRIBUTE_NORMAL  0x80

/* SMB2 share types */
#define SMB2_SHARE_TYPE_DISK                            0x01        /* Disk share */
#define SMB2_SHARE_TYPE_PIPE                            0x02        /* Named pipe share */
#define SMB2_SHARE_TYPE_PRINT                           0x03        /* Printer share */

/* SMB2 share types for SRVSVC */
#define SMB2_SHARE_SRV_TYPE_DISK                            		0x00000000        /* Disk share */
#define SMB2_SHARE_SRV_TYPE_PRINT                           		0x00000001        /* Printer share */
#define SMB2_SHARE_SRV_TYPE_DEVICE									0x00000002		  /* Device share */
#define SMB2_SHARE_SRV_TYPE_IPC	                            		0x00000003        /* IPC share */
#define SMB2_SHARE_SRV_TYPE_CLUSTER                           		0x02000000        /* Cluster share */
#define SMB2_SHARE_SRV_TYPE_CLUSTER_SCALE                           0x04000000        /* Cluster Scale-Out share */
#define SMB2_SHARE_SRV_TYPE_CLUSTER_DFS                           	0x08000000        /* Cluster DFS share */
#define SMB2_SHARE_SRV_TYPE_HIDDEN	                         		0x80000000        /* Hidden share */


/* SMB2 share flags */
#define SMB2_SHARE_FLAG_MANUAL_CACHING                  0x00000000  /* The client MAY cache files that are explicitly selected by the user for offline use. */
#define SMB2_SHARE_FLAG_AUTO_CACHING                    0x00000010  /* The client MAY automatically cache files that are used by the user for offline access. */
#define SMB2_SHARE_FLAG_VDO_CACHING                     0x00000020  /* The client MAY automatically cache files that are used by the user for offline access, and MAY use those files in an offline mode */
#define SMB2_SHARE_FLAG_NO_CACHING                      0x00000030  /* Offline caching MUST NOT occur. */
#define SMB2_SHARE_FLAG_DFS                             0x00000001  /* The specified share is present in a DFS tree structure. */
#define SMB2_SHARE_FLAG_DFS_ROOT                        0x00000002  /* The specified share is the root volume in a DFS tree structure. */
#define SMB2_SHARE_FLAG_RESTRICT_EXCLUSIVE_OPENS        0x00000100  /* The specified share disallows exclusive file opens that deny reads to an open file. */
#define SMB2_SHARE_FLAG_FORCE_SHARED_DELETE             0x00000200  /* Shared files in the specified share can be forcibly deleted. */
#define SMB2_SHARE_FLAG_ALLOW_NAMESPACE_CACHING         0x00000400  /* Clients are allowed to cache the namespace of the specified share. */
#define SMB2_SHARE_FLAG_ACCESS_BASED_DIRECTORY_ENUM     0x00000800  /* The server will filter directory entries based on the access permissions of the client. */
#define SMB2_SHARE_FLAG_ENCRYPT_DATA					0x00008000  /* The server requires encryption of remote file access messages on this share. Only valid for SMB 3.X dialect family */

/* SMB2 share capabilities */
#define SMB2_SHARE_CAPS_DFS                             0x00000008  /* The share is in DFS. */
#define SMB2_SHARE_CAP_SCALEOUT                         0x00000020  /* The share is has faster recovery of durable handles.*/

/* channel info */
#define SMB2_CHANNEL_INFO_LEN 16 /* V1 */

#endif

