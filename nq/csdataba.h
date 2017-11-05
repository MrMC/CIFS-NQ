/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Server database
 *--------------------------------------------------------------------
 * MODULE        : CS - CIFS Server
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 29-June-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _CSDATABA_H_
#define _CSDATABA_H_

#include "nsapi.h"

#include "csfnames.h"
#ifdef UD_CS_INCLUDERPC
#include "cspipes.h"
#endif
#ifdef UD_NQ_INCLUDESMB2
#include "cmsmb2.h"
#endif
#ifdef UD_CS_MESSAGESIGNINGPOLICY
#include "cmcrypt.h"
#endif 
#include "cslaters.h"

/*
    Data model
    ----------

  The internal server database holds structures of the following types:
  - sessions
  - users
  - shares

  Logical structure is:
    <session>
        <user>
            <tree>
                <name>
                    <file>
                    ...
                    <file>
                ...
                <name>
                <sear.h"
                ...
                <sear.h"
            ...
            <tree>
        ...
        <user>
    <session>
    ...
    <session>

    <share>
    ...
    <share>
 */

/*
    Types
    -----
*/

#define CS_ILLEGALID (NQ_UINT16)-1 /* illegal value for <whatever>ID */

#define CS_DIALECT_SMB1		1
#define CS_DIALECT_SMB2		2
#define CS_DIALECT_SMB210	4
#define CS_DIALECT_SMB30        6
#define CS_DIALECT_SMB311	8


typedef NQ_UINT32 CSSessionKey;    /* session key - an index in the session table */
typedef NQ_UINT16 CSUid;           /* UID - an index in the users table */
typedef NQ_UINT16 CSTid;           /* TID - an index in the tree table */
typedef NQ_UINT16 CSFid;           /* FID - an index in the file table */
typedef NQ_UINT16 CSMid;           /* MID - client-generated multiplex ID */
typedef NQ_UINT16 CSNid;           /* NID - an index in the file name table */
typedef NQ_UINT32 CSPid;           /* PID - client-generated process ID */
typedef NQ_UINT16 CSSid;           /* SID - an index in the table of search operations */

typedef struct                  /* share descriptor */
{
    NQ_UINT16 idx;                                  /* share index */
    NQ_BOOL isFree;                                 /* whether the slot is in use */
    NQ_WCHAR name[CM_BUFFERLENGTH(NQ_WCHAR, UD_FS_MAXSHARELEN)];                /* share name */
    NQ_WCHAR map[CM_BUFFERLENGTH(NQ_WCHAR, UD_FS_MAXPATHLEN)];                  /* share mapping */
    NQ_WCHAR description[CM_BUFFERLENGTH(NQ_WCHAR, UD_FS_MAXDESCRIPTIONLEN)];   /* share description */
    NQ_BOOL ipcFlag;                                /* TRUE if this is a pseudo-tree */
    NQ_BOOL isPrintQueue;                           /* TRUE if this is a print queue */
    NQ_BOOL isDevice;                               /* TRUE if this is a device */
    NQ_BOOL isHidden;                               /* TRUE is this is a hidden share (C$) */
#ifdef UD_NQ_INCLUDESMB3
    NQ_BOOL	isEncrypted;						    /* TRUE if this share requires encrypted data transfer (SMB3)*/
#endif /* UD_NQ_INCLUDESMB3 */
#ifdef UD_CS_INCLUDESECURITYDESCRIPTORS
    CMSdSecurityDescriptor sd;                      /* security descriptor */
#endif /* UD_CS_INCLUDESECURITYDESCRIPTORS */
} CSShare;

typedef struct                  /* server session */
{
    NSSocketHandle socket;      /* the session's client socket */
    NQ_UINT16 vc;               /* session VC */
    CSSessionKey key;           /* "self" index and session key */
    NQ_BYTE encryptionKey[SMB_ENCRYPTION_LENGTH];  /* a key for data encryption between client and server */

#ifdef UD_NQ_INCLUDESMB3
    NQ_BOOL isAesGcm;           /* AES-128-CCM or AES_128_GCM */ 
    NQ_BYTE preauthIntegHashVal[SMB3_PREAUTH_INTEG_HASH_LENGTH]; /* array to hold hash results of negotiate packets */
    NQ_BOOL preauthIntegOn;		/* for smb 311 and higher pre authentication integrity is on during negotiation and session setup stages */
#endif
    NQ_IPADDRESS ip;            /* next side IP address */
    NQ_UINT32 capabilities;     /* capabilities */
    NQ_INT 	dialect;			/* which dialect the session uses */
#ifdef UD_CS_INCLUDEPASSTHROUGH
    NQ_BOOL usePassthrough;     /* whether to use pass-through */
#endif  /* UD_CS_INCLUDEPASSTHROUGH      */
#ifdef UD_NQ_INCLUDESMB2
    NQ_UINT credits;            /* remaining credits */
    NQ_UINT creditsToGrant;     /* credits to grant in interim response */
#endif /* UD_NQ_INCLUDESMB2 */
#if defined(UD_CS_INCLUDELOCALUSERMANAGEMENT) || defined(UD_CS_INCLUDEEXTENDEDSECURITY) || defined(UD_CS_MESSAGESIGNINGPOLICY)
    NQ_BYTE sessionNonce[SMB_SESSIONKEY_LENGTH]; /* a key used for session security */
#endif /* defined(UD_CS_INCLUDELOCALUSERMANAGEMENT) || defined(UD_CS_INCLUDEEXTENDEDSECURITY) || defined(UD_CS_MESSAGESIGNINGPOLICY) */
#ifdef UD_CS_MESSAGESIGNINGPOLICY
    NQ_BOOL signingOn;          /* whether message signing is enabled for this session */
    NQ_BYTE sessionKey[SMB_SESSIONKEY_LENGTH]; /* session key for signing of all messages in this session */
    NQ_BOOL isBsrspyl;          /* whether messages are signed with BSRSPYL */
    NQ_UINT32 sequenceNum;      /* sequence number for the next incoming request */
    NQ_UINT32 sequenceNumRes;   /* sequence number for the response*/
#endif /* UD_CS_MESSAGESIGNINGPOLICY */
#ifdef UD_CS_INCLUDEEXTENDEDSECURITY
    const void * securityMech;  /* abstract pointer to security mechanism */
#endif /* UD_CS_INCLUDEEXTENDEDSECURITY */
} 
CSSession;

#ifdef UD_NQ_INCLUDESMB2
/* Conversion between internal and external forms of session ID - aka UID in SMB1 */
#define sessionIdToUid(_id) (_id - 1001)  /* index in the table */
#define uidToSessionId(_id) (_id + 1001)  /* 1001-based */
#endif /* UD_NQ_INCLUDESMB2 */  

typedef struct                  /* server session */
{
    CSSessionKey session;       /* the index in array of sessions */
    CSUid uid;                  /* "self" index and UID */
    const NQ_IPADDRESS *ip;     /* next side IP address */
    NQ_BOOL preservesCase;      /* TRUE for case preserving file system (of a client) */
    NQ_BOOL supportsReadAhead;  /* TRUE for case a client supporting read ahead */
    NQ_BOOL isAnonymous;        /* TRUE for an anonymous user */
    NQ_WCHAR name[CM_BUFFERLENGTH(NQ_WCHAR, CM_USERNAMELENGTH)];    /* user name */
    NQ_BYTE credentials[SMB_SESSIONSETUPANDX_CREDENTIALS_LENGTH];   /* saved user credentials */
    NQ_BOOL isDomainUser;       /* TRUE for domain user */
    CMSdAccessToken token;      /* security token for the session user */
#if defined (UD_CS_INCLUDELOCALUSERMANAGEMENT) || defined(UD_CS_INCLUDEEXTENDEDSECURITY) || defined(UD_CS_MESSAGESIGNINGPOLICY)
    NQ_BYTE sessionKey[SMB_SESSIONKEY_LENGTH];  /* a key for password encryption */
#endif /* defined (UD_CS_INCLUDELOCALUSERMANAGEMENT) || defined(UD_CS_INCLUDEEXTENDEDSECURITY) || defined(UD_CS_MESSAGESIGNINGPOLICY) */
    NQ_BOOL supportsNotify;     /* this client properly supports NOTIFY */
    NQ_BOOL supportsNtErrors;   /* this client understands NT errors */
    NQ_BOOL authenticated;      /* user authentication process status */
#ifdef UD_CS_INCLUDEEXTENDEDSECURITY
    NQ_BOOL isExtendSecAuth;    /* whether extended security authentication was performed */
#endif /* UD_CS_INCLUDEEXTENDEDSECURITY */
#ifdef UD_CS_MESSAGESIGNINGPOLICY
    CMBlob  password;
#endif /* UD_CS_MESSAGESIGNINGPOLICY */
#ifdef UD_CS_INCLUDEPASSTHROUGH
     NQ_BOOL authBySamlogon;    /* whether user was authenticated by Netlogon SamLogon */ 
#endif /* UD_CS_INCLUDEPASSTHROUGH */
    NQ_BOOL isGuest;            /* whether user has no password and authenticated as guest */
    NQ_UINT32 rid;              /* user RID*/
#ifdef UD_NQ_INCLUDESMB2
    NQ_UINT32 createdTime;      /* creation timestamp, used for session expiration in smb2 */
    NQ_BYTE signingKey[SMB_SESSIONKEY_LENGTH];      /* a key for signing packets*/
#ifdef UD_NQ_INCLUDESMB3
    NQ_BOOL isEncrypted;                            /* encrypted session */
    NQ_BYTE encryptionKey[SMB_SESSIONKEY_LENGTH];   /* a key for encrypting packets*/
    NQ_BYTE decryptionKey[SMB_SESSIONKEY_LENGTH];   /* a key for decrypting packets*/
	NQ_BYTE applicationKey[SMB_SESSIONKEY_LENGTH];  /* a key for RPC packets*/
    NQ_BYTE encryptNonce[SMB2_ENCRYPTION_HDR_NONCE_SIZE];
    NQ_BYTE preauthIntegHashVal[SMB3_PREAUTH_INTEG_HASH_LENGTH]; /* array to hold hash results of negotiate packets */
    NQ_BOOL preauthIntegOn;		/* for smb 311 and higher pre authentication integrity is on during negotiation and session setup stages */
#endif /* UD_NQ_INCLUDESMB3 */
#endif /* UD_NQ_INCLUDESMB2 */
}
CSUser;

typedef struct                  /* tree descriptor */
{
    CSSessionKey session;       /* master session */
    CSUid uid;                  /* master UID */
    CSTid tid;                  /* "self" index */
    CSShare* share;             /* pointer to the share */
    NQ_UINT32 maxAccessRights;  /* max access rights */
} CSTree;

#define CS_DURABLE_REQUIRED     0x1     /* this flag is set when FID is requested to be durable */
#define CS_DURABLE_DISCONNECTED 0x2     /* this flag is set when FID was disconnected and was not re-open yet */

typedef struct _CSFile                  /* file descriptor */
{
    CSSessionKey session;               /* master session */
    CSTid tid;                          /* master TID */
    CSUid uid;                          /* master's master UID */
    CSPid pid;                          /* master PID */
    CSFid fid;                          /* "self" index */
#ifdef UD_CS_INCLUDEPERSISTENTFIDS
    NQ_UINT16 durableFlags;            /* see above */
#endif
#ifdef UD_CS_INCLUDERPC
    NQ_BOOL isPipe;
    CSRpcPipe pipes[CM_RPC_MAXNUMBEROFCONTEXTS]; /* pipe index for an opened pipe */
    NQ_UINT16 maxFragment;              /* max size of transmit fragment */
    NQ_BYTE* rpcBuffer;                 /* pointer to RPC buffer or NULL */
#endif
    SYFile file;                        /* underlying file handle */
    CSNid nid;                          /* file name descriptor */
    CSUser *user;                       /* user that opened this file */
    struct _CSFile* prev;               /* back link in the chain of file name */
    struct _CSFile* next;               /* forward link in the chain of file name */
    SYDirectory directory;              /* underlying directory handle */
    NQ_UINT16 mode;                     /* file open mode */
    NQ_BOOL isDirectory;                /* directory flag */
    NQ_UINT16 access;                   /* access for this file */
    NQ_UINT32 offsetLow;                /* low part of the current offset */
    NQ_UINT32 offsetHigh;               /* high part of the current offset */
    NQ_BOOL notifyPending;              /* whether notify request is pending for this file */
    NQ_UINT32 notifyFilter;             /* notify completion filter */
    CSLateResponseContext notifyContext;/* context for notify response */
    NQ_BOOL notifyTree;                 /* whether to notify on subtree */
    NQ_UINT32 options;                  /* NT open options */
#ifdef UD_CS_INCLUDERPC_SPOOLSS
    NQ_BOOL isPrint;                    /* whether it's print file */
    SYPrinterHandle printerHandle;      /* printer handle */
#endif
#ifdef UD_NQ_INCLUDESMB2
    CSSid sid;                          /* search id */
    NQ_UINT64 notifyAid;                /* async ID of the interim Notify response */
#endif
    CSLateResponseContext breakContext; /* context for oplock breaks */
    NQ_BOOL oplockGranted;              /* TRUE when oplock was granted */
    NQ_BOOL isBreakingOpLock;			/* this file is breaking its oplock */
    NQ_BOOL isCreatePending;			/* this file caused oplock break - waiting for late create response */
}CSFile;

typedef struct
{
    NQ_UINT32 creationTimeLow;          /* UTC times */
    NQ_UINT32 creationTimeHigh;
    NQ_UINT32 lastAccessTimeLow;
    NQ_UINT32 lastAccessTimeHigh;
    NQ_UINT32 lastWriteTimeLow;
    NQ_UINT32 lastWriteTimeHigh;
    NQ_UINT32 lastChangeTimeLow;
    NQ_UINT32 lastChangeTimeHigh;
}CSTime;

typedef struct                          /* file name descriptor */
{
    CSNid nid;                          /* self ID */
    NQ_WCHAR name[CM_BUFFERLENGTH(NQ_WCHAR, UD_FS_FILENAMELEN)];    /* file name */
    CSFile* first;                      /* file chain */
    CSUid uid;                          /* first client UID */
    NQ_BOOL markedForDeletion;          /* whether file was marked for deletion */
    NQ_BOOL isDirty;                    /* file was changed */
    NQ_BOOL wasOplockBroken;            /* whether file's oplock was broken already */
    CSTime time;                        /* times saved on last received Set File Info */
#ifdef UD_NQ_INCLUDEEVENTLOG
	NQ_UINT32 deletingUserRid;          /* RID of user who marked file for deletion */
	NQ_UINT32 deletingTid;              /* TID of user who marked file for deletion */
    NQ_CHAR deletingIP[CM_IPADDR_MAXLEN];/* IP of user who marked file for deletion */
#endif /* UD_NQ_INCLUDEEVENTLOG */
} CSName;

typedef struct                          /* search operation descriptor */
{
    CSSessionKey session;               /* master session */
    CSSid sid;                          /* "self" index */
    CSTid tid;                          /* master tree */
    CSFileEnumeration enumeration;      /* descriptor for directory search */
    NQ_UINT16 attributes;               /* search file attributes */
    NQ_BOOL resumeKey;                  /* true to add resume key for particular levels */
} CSSearch;

/**
  Parameter structure. This structure is used by both SMB1 and SMB2 command handlers for
  passing parameters to the common code.
 */

typedef struct
{
    CSTid tid;                  /* IN */
    CSPid pid;                  /* IN */
    CSUid uid;                  /* IN */
    CSUser * user;              /* IN */
    const CSShare * share;      /* IN */
    NQ_UINT32 fileAttributes;   /* IN */
    NQ_BOOL unicodeRequired;    /* IN from request header */
    NQ_UINT32 createOptions;    /* IN create options */
    NQ_UINT32 disposition;      /* IN create disposition */
    NQ_UINT32 desiredAccess;    /* IN desired access */
    NQ_UINT32 sharedAccess;     /* IN shared access */
    NQ_WCHAR * fileName;        /* IN file name pointer - localized and normalized */
    SYFileInformation fileInfo; /* IN OUT file information */
    CSFile * file;              /* OUT file pointer */
    NQ_UINT32 takenAction;      /* OUT response action */
    CSCreateContext context;    /* OUT data used for composing contexts */
} 
CSCreateParams;


#ifdef UD_NQ_INCLUDECIFSSERVER
/*
    Functions
    ---------
*/

/* return appropriate error code */

NQ_UINT32                    /* code to return */
csErrorReturn(
    NQ_UINT32 nt,            /* NT error code */
    NQ_UINT32 dos            /* dos error code */
    );

/* obtain last system error converted to SMB error */

NQ_UINT32                    /* code to return */
csErrorGetLast(
    void
    );
/* initialize session resources */

NQ_STATUS
csInitDatabase(
    void (*pause)(void),    /* callback for pausing the server */
    void (*resume)(void)    /* callback for resuming the server */
    );

/* release database */

void
csCloseDatabase(
    void
    );

/* allocate a session slot */

CSSession*                  /* pointer or NULL */
csGetNewSession(
    void
    );

/* find a session with the same socket */

CSSession*                  /* pointer or NULL */
csGetSessionBySocket(
    void
    );

/* find a session with the same socket as provided */

CSSession*                  /* pointer or NULL */
csGetSessionBySpecificSocket(
    NSSocketHandle socket
    );


/* find a session by session key */

CSSession*                  /* pointer or NULL */
csGetSessionById(
    CSSessionKey id         /* session ID */
    );

/* find a session by client IP address */

CSSession*                  /* pointer or NULL */
csGetSessionByIp(
    const NQ_IPADDRESS* pIp /* client IP */
    );

/* check if the session already exists */

NQ_BOOL                        /* TRUE or FALSE */
csSessionExists(
    void
    );

/* release all resources connected with this socket's sessions */

void
csReleaseSessions(
    NSSocketHandle socket,   /* the socket to release resources for */
    NQ_BOOL expected  /* is the release expected (used for EventLog)*/
    );

/* allocate a user slot */

CSUser*                         /* pointer or NULL */
csGetNewUser(
    const CSSession* key        /* master session */
    );

/* find a user with given index */

CSUser*                     /* pointer or NULL */
csGetUserByIndex(
    NQ_UINT idx             /* user index */
    );

/* find a user providing UID */

CSUser*                     /* pointer or NULL */
csGetUserByUid(
    CSUid uid               /* UID to find the user descriptor */
    );

/* find a user providing its name and credentials */

CSUser*                     /* pointer or NULL */
csGetUserByNameAndCredentials(
    const NQ_WCHAR* name,       /* user name */
    const NQ_BYTE* credentials, /* credentials */
    NQ_INT credentialsLen       /* total credentials length */
    );

/* find a user providing its name and session */

CSUser*                     /* pointer or NULL */
csGetUserByNameAndSession(
    const NQ_WCHAR* name,       /* user name */
    CSSessionKey sessKey        /* session key */
    );

/* get number of logged users */

NQ_UINT                     /* number of users */
csGetUsersCount(
    void
    );
/* get User RID*/

NQ_UINT32
csGetUserRid(
    const CSUser * pUser
    );

/* get user by session */

CSUser*
csGetUserBySession(
    CSSession *pSession     /* pointer to session */
    );

/* release user descriptor */

void
csReleaseUser(
    CSUid uid ,              /* UID to release */
    NQ_BOOL expected
    );

/* release user descriptor and disconnect the
 * client if there are no more users for the same connection
 */

void
csReleaseUserAndDisconnect(
    CSUid uid ,              /* UID to release */
    NQ_BOOL expected
    );

#ifdef UD_NQ_INCLUDESMB2

/* get first expired user (session in smb2 terms) */ 

CSUser*                     /* pointer or NULL */
csGetExpiredUser(
    void
    );

/* check whether user (session in smb2 terms) has expired */

NQ_BOOL                     /* TRUE or FALSE */
csUserHasExpired(
    CSUid uid               /* user ID*/ 
    ); 

/* renew user (session in smb2 terms) time stamp */

void
csRenewUserTimeStamp(
    CSUser* pUser           /* pointer to user */     
    );
    
#endif /* UD_NQ_INCLUDESMB2 */  

/* allocate a tree slot */

CSTree*                     /* pointer or NULL */
csGetNewTree(
    const CSUser* user      /* master user */
    );

/* find a tree providing TID */

CSTree*                     /* pointer or NULL */
csGetTreeByTid(
    CSTid tid               /* TID to find the tree descriptor */
    );

/* enumerate trees for a given share */

CSTree*                     /* next tree for this share or NULL */
csGetNextTreeByShare(
    const CSShare* pShare,  /* share descriptor */
    CSTid tid               /* previous tree id or CS_ILLEGALID */
    );

/* release tree descriptor */

void
csReleaseTree(
    CSTid tid,               /* TID to release */
    NQ_BOOL expected
    );

#ifdef UD_CS_INCLUDESECURITYDESCRIPTORS

/* change share security descriptor */

NQ_BOOL                     /* TRUE or FALSE on overflow */
csSetShareSecurityDescriptor(
    CSShare* share          /* share pointer */
    );

/* load share security descriptor */

NQ_BOOL                     /* TRUE or FALSE on overflow */
csLoadShareSecurityDescriptor(
    CSShare* share          /* share pointer */
    );

#endif /* UD_CS_INCLUDESECURITYDESCRIPTORS */

/* allocate a name slot */

CSName*                     /* pointer or NULL */
csGetNewName(
    const NQ_WCHAR* name,    /* file name */
    CSUid uid               /* first client UID */
    );

/* get filename descriptor providing NID */

CSName*                     /* pointer or NULL */
csGetNameByNid(
    CSNid nid               /* filename ID */
    );

/* find a file name descriptor providing file name */

CSName*                     /* pointer or NULL */
csGetNameByName(
    const NQ_WCHAR* name     /* name to look for */
    );

/* determine if a file was marked for delition */

NQ_BOOL                      /* TRUE or FALSE */
csFileMarkedForDeletion(
    const NQ_WCHAR* name     /* name to look for */
    );

/* find a file providing its name descriptor and prevoius FID */

CSFile*                     /* pointer or NULL */
csGetNextFileByName(
    CSFid fid               /* previous file ID */
    );

/* release name descriptor */

void
csReleaseName(
#ifdef UD_NQ_INCLUDEEVENTLOG
    CSUser* pUser,    /* user pointer */
    CSTid tid,
#endif /* UD_NQ_INCLUDEEVENTLOG */
    CSNid nid               /* name ID */
    );

/* get unique files count */

NQ_UINT                     /* number of files */
csGetUniqueFilesCount(
    void
    );

/* allocate a file slot */

CSFile*                     /* pointer or NULL */
csGetNewFile(
    const CSTree* pTree,    /* master session */
    CSName* name,           /* file name descriptor */
    NQ_UINT16 access        /* file access bits */
    );

/* find a file providing FID */

CSFile*                     /* pointer or NULL */
csGetFileByFid(
    CSFid fid,              /* file ID */
    CSTid tid,              /* tree ID */
    CSUid uid               /* user ID */
    );

/* find a file providing FID */

CSFile*                     /* pointer or NULL */
csGetFileByJustFid(
    CSFid fid
    );

CSFile*                     /* pointer or NULL */
csGetFileByIndex(
    NQ_UINT idx             /* file index */
    );

/* find a file providing PID */

CSFile*                     /* pointer or NULL */
csGetFileByContext(
    CSPid pid,              /* process ID */
    CSMid mid,              /* multiplex ID */
    CSTid tid,              /* tree ID */
    CSUid uid               /* user ID */
    );

#ifdef UD_NQ_INCLUDESMB2

/* find a file providing PID (SMB2 version) */

CSFile*                     /* pointer or NULL */
cs2GetFileByContext(
    NQ_UINT64 aid,          /* Async ID */
    CSUid uid               /* user ID */
    );

#endif /* UD_NQ_INCLUDESMB2 */

/* obtain file providing FID */

const NQ_WCHAR*              /* pointer or NULL */
csGetFileName(
    CSFid fid               /* file ID */
    );

/* find a file providing PID and prevoius FID */

CSFile*                     /* pointer or NULL */
csGetNextFileByPid(
    CSPid pid,              /* process ID */
    CSFid fid               /* previous file ID */
    );

/* enumerate file openings */

CSFid                       /* next file FID or CS_ILLIGALID when no more file openings */
csGetNextFileOpen(
    CSFid fid               /* previous file ID or CS_ILLEGALID */
    );

/* release file descriptor */

void
csReleaseFile(
    CSFid fid               /* file ID */
    );

/* get open files count */

NQ_UINT                     /* number of files */
csGetFilesCount(
    void
    );

/* find share by name */

CSShare*                    /* pointer to descriptor or NULL */
csGetShareByName(
    const NQ_WCHAR* name    /* share to find */
    );

/* find share mapping b UID and TID */

const CSShare*              /* share or NULL */
csGetShareByUidTid(
    CSUid uid,              /* UID should match the uid in TID table */
    CSTid tid               /* TID table index */
    );

/* enumerate shares */

NQ_UINT
csGetSharesCount(
    void
    );

/* enumerate sessions */

NQ_UINT
csGetSessionsCount(
    void
    );

/* get a share by number */

CSShare*            /* share structure */
csGetShareByIndex(
    NQ_UINT idx        /* share index */
    );

/* get a number of opened files for this share */

NQ_COUNT                    /* number of files */
csGetNumberOfShareFiles(
    const CSShare* share    /* pointer to share */
    );

/* get a number of opened files for this user */

NQ_COUNT                    /* number of files */
csGetNumberOfUserFiles(
    const CSUser* user      /* pointer to user */
    );

/* get a number of users for this share */

NQ_COUNT                       /* number of users */
csGetNumberOfShareUsers(
    const CSShare* share    /* pointer to share */
    );

/* allocate a search slot */

CSSearch*                   /* pointer or NULL */
csGetNewSearch(
    const CSTree* tree      /* master tree */
    );

/* find a search providing SID */

CSSearch*                   /* pointer or NULL */
csGetSearchBySid(
    CSSid sid               /* search ID */
    );

/* release search descriptor */

void
csReleaseSearch(
    CSSid sid               /* search ID */
    );


/* start enumerating opened directories with notify request pending */

void
csStartNotifyRequestSearch(
    void
    );

/* get next opened directory with notify request pending */

CSFile*
csEnumerateNotifyRequest(
    void
    );



#ifdef UD_NQ_INCLUDESMB2
const CMUuid *cs2GetServerUuid(void);
const CMTime *cs2GetServerStartTime(void);

#ifdef UD_NQ_INCLUDESMB3
NQ_BOOL csIsServerEncrypted(void);
void csSetServerEncryption(NQ_BOOL encrypt);
#endif /* UD_NQ_INCLUDESMB3 */

#endif /* UD_NQ_INCLUDESMB2 */

/* whether hidden administrative share (e.g. C$) is present */

NQ_BOOL
csHasAdminShare(
    void
    );


CSShare*
csGetHiddenShareByMap(
        const NQ_WCHAR* map
    );    

#ifdef UD_CS_MESSAGESIGNINGPOLICY
/* whether message signing is enabled */

NQ_BOOL
csIsMessageSigningEnabled(
  void
  );

/* whether message signing is enabled and required */

NQ_BOOL
csIsMessageSigningRequired(
  void
  );

void
csSetMessageSigningPolicy(
		NQ_INT newPolicy
		);
#endif

/* debug only */

#if SY_DEBUGMODE

void
csDumpDatabase(
    void
    );

#endif /* SY_DEBUGMODE */


#endif /* UD_NQ_INCLUDECIFSSERVER */

#endif  /* _CSDATABA_H_ */

