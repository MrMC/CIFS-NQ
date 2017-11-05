/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : User-defined parameters
 *--------------------------------------------------------------------
 * MODULE        : UD - User-defined
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 14-May-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/
#ifndef _UDPARAMS_H_
#define _UDPARAMS_H_

#ifdef NQ_DEBUG
#ifndef UD_NQ_INCLUDETRACE
#define UD_NQ_INCLUDETRACE
#endif
#endif

#define UD_NQ_INCLUDEBROWSERDAEMON
/*  CIFS transport options
    ----------------------
   At least one transport should be defined
   Comment out lines with transports you don't want to be used */

#define UD_NQ_USETRANSPORTNETBIOS   /* NetBIOS over TCP/IP */
#define UD_NQ_USETRANSPORTIPV4       /* plain TCP/IP */
/*#define UD_NQ_USETRANSPORTIPV6 */    /* plain TCP/IP version 6 */

/*#define UD_NQ_INCLUDESMBCAPTURE */  /* Internal NQ Network packet capturing*/

/* maximum length of the host name for the case of DNS 
   as required by RFC. You can decrease this value to save of footprint */
#define UD_NQ_HOSTNAMESIZE          256

/* Application Interface
    ---------------------
    NQ exposes three application interfaces: 1) ASCII only, 2) Unicode only and 3) default.
    While first two interfaces are explicit, the default one may be implicitly ASCII or
    implicitly Unicode. The following parameter, when defined, makes the default interface
  Unicode. When it is commented, the default interface is ASCII. This parameter affects
  definition of NQ_TCHAR */

#define UD_CM_UNICODEAPPLICATION    /* comment this definition for ACSII application */

/*  Code pages configuration
    ------------------------
    This section defines which Code Page is used. User may either disable all
    codepages by commenting UD_NQ_INCLUDECODEPAGE or enable some components by uncommenting
    UD_NQ_CODEPAGE<codepage> components that correspond to desired code page.
    All definitions should match the number of the code pages and shouldn't be redefined.
*/

/*#define UD_NQ_INCLUDECODEPAGE*/
/*#define UD_NQ_CODEPAGE437      437*/  /* US */
/*#define UD_NQ_CODEPAGE850      850*/  /* Multilingual Latin I */
/*#define UD_NQ_CODEPAGE852      852*/  /* Latin II */
/*#define UD_NQ_CODEPAGE858      858*/  /* Multilingual Latin I + Euro */
/*#define UD_NQ_CODEPAGE862      862*/  /* Hebrew */
/*#define UD_NQ_CODEPAGE932      932*/  /* Japanese Shift-JIS */
/*#define UD_NQ_CODEPAGE936      936*/  /* Simplified Chinese GBK */
/*#define UD_NQ_CODEPAGE949      949*/  /* Korean */
/*#define UD_NQ_CODEPAGE950      950*/  /* Traditional Chinese Big5 */
/*#define UD_NQ_CODEPAGEUTF8     8  */  /* UTF-8  */

/*  Event logging
    -------------
    Event logging turns on (on compile level) NQ events and enables information
    calls. On an NQ event the core NQ calls event logging functions on UD level.
    Turning on this option requires implementing those logging callbacks in UD.
*/

/*#define UD_NQ_INCLUDEEVENTLOG*/  /* comment this line to exclude event logging and information calls */

 /*
    NS resources
    ------------
  NS uses internally static buffers. Those buffers are used on per-task basis
  so that there is one buffer per concurrent task. We expect the following
  concurrent tasks:
  1. CS
  2. Browser
  3. CC driver
  The CC driver may either synchronize its NS calls or not. In the first case
  CS is treated as a single task and we expect 3 tasks. In the second case CC may
  represent any number of tasks and the number of buffers should be suggested by user.
  Each task may use up to two buffers (one for incoming message and another one for
  outgoing message.

  The size of a buffer limits messages that may be sent. Usually, this applies to data
  messages (datagram, session message).

  WARNING:   when all buffers are in use and a task requires a buffer, this task
             will be suspended until another task releases a buffer.

  NS uses "socket slots" for keeping trek of "NetBIOS sockets". The maximum number of
  slots is a predefined number. An approximate number of "alive" sockets may be calculated as:
    server: 2 + number of concurrent sessions
    client: number of client sessions (usually - a number of concurrent applications using CC)

  WARNING:   when all slots are in use and another tasks requires a slot NS will fail
             this operation.

  NS uses "internal sockets" to contact to DD and ND. The number of internal sockets is
  limited to a predefined number. Concurrent tasks, calling the same NQ code use different
  internal sockets. The number of internal sockets is calculated as half of the number of
  buffers.

  WARNING:   when all internal sockets are in use and a tasks requires an internal socket
             this task will be suspended until another task releases internal socket.

    UD_NS_NUMNDCHANNALS
    UD_NS_NUMDDCHANNALS number of sockets to internally connect to the Datagram Daemon
    UD_NS_BUFFERSIZE    buffer length
 */

#define UD_NS_SCOPEIDLEN        100     /* maximum length of scope ID */
#define UD_NS_MAXADAPTERS       2       /* maximum number of network adapters plugged
                                           into the target */
#define UD_NS_NUMSOCKETS        35      /* number of socket slots to allocate */
#define UD_NS_NUMNDCHANNELS     2       /* number of sockets to internally connect to ND */
#define UD_NS_NUMDDCHANNELS     2       /* number of sockets to internally connect to DD */

/* Various sockets, like name resolution sockets, can be either left open
   all the time or opened and closed per usage. When the following parameter is defined,
   sockets are opened and closed per usage. When software resides in untrusted network,
   it is advisable to enable the following parameter. */

/*#define UD_NQ_CLOSESOCKETS*/

/* Buffer size: 
 * This value should be at least 64K+headers for NQ to support SMB2. This happens because
 * Windows 7 does not appreciate server's limits 
 * Buffers size for SMB1 support may be any number greater than 1460. A multiple of 1460
 * is recommended to decrease TCP fragmentation. */
#define UD_NS_BUFFERSIZE        65700   /*(1460*24)*/ 

/* The following parameter may be undefined. Then the default value is used which guarantees
   the minimum footprint. A value grater then 2 may be specified to enforce better
   performance.
   Specifying this parameter has no effect when UD_NS_ASYNCSEND is undefined. */

/* #define UD_NS_NUMBUFFERS        6 */        /* number of buffers to allocate */

/* The following two ports are used for internal communications. Their numbers should not
   be used by other network protocols on the target. */

#define UD_BR_INTERNALIPCPORT   1025     /* internal Browser Service */
#define UD_NS_INTERNALNSPORT    1026     /* internal Name Service */
#define UD_NS_INTERNALDSPORT    1027     /* internal Datagram Distribution Service */

#define UD_ND_DAEMONTIMEOUT     1       /* seconds waiting for incoming NetBIOS message */
#define UD_ND_MAXINTERNALNAMES  20      /* maximum number of internal NetBIOS names */
#define UD_ND_MAXEXTERNALNAMES  20      /* maximum number of external NetBIOS names */
#define UD_ND_REGISTRATIONCOUNT 3       /* repeat count for registration */
#define UD_ND_MAXQUERYREQUESTS  3       /* number of concurrent query requests to the same name */
#define UD_NQ_MAXDNSSERVERS     4       /* maximum number of DNS servers */
#define UD_NQ_MAXWINSSERVERS    4       /* maximum number of WINS servers */
/* Some implementations contain external (non NQ) NetBIOS implementation. In this case NQ
   should be compiled without NetBIOS. When this definition is omitted, UD_CS_INCLUDEPASSTHROUGH,
   UD_NB_INCLUDENAMESERVICE and UD_NB_RETARGETSESSIONS (see below) should be also omitted.
   Otherwise, there will be an error during pre-processing */

#define UD_ND_INCLUDENBDAEMON       /* comment this line for no NQ NetBIOS */

/* When NetBIOS is defined, NQ may use it for DC resolution. With a B-node this resolution may slow down the
   entire DC resolution because of broadcast response timeout. This may become very time-costly with DFS enabled.
   The following parameter, when defined forces NQ to skip DC resolution over NetBIOS even when NetBIOS is
   available. */

/* #define UD_NQ_AVOIDDCRESOLUTIONNETBIOS */    /* comment this line to use 1b resolution over NetBIOS. */

/* NetBIOS may support more than one server application on the target (more than just
   CIFS Server). For this reason Session Request messages should be accepted by the NetBIOS
   Daemon and retargeted to the application listening ports. This requires from connecting
   CIFS clients to support Session Retarget packages.
   If there is only one NetBIOS Server application on the target (CIFS Server), client's
   Session Requests may be directly handled by the server application. */

/* #define UD_NB_RETARGETSESSIONS */      /* comment this line for single server application */

/* Some implementations contain external (non NQ) NetBIOS Naming Service - NBNS. In this case NQ
   should be compiled without NBNS. */

#define UD_NB_INCLUDENAMESERVICE    /* comment this line when using external NBNS */

/* NQ allows to delegate user authentication to the domain controller. This mechanism is called
   "pass-through". This functionality is optional and it requires UD_ND_INCLUDENBDAEMON to be defined */
#define UD_CS_INCLUDEPASSTHROUGH    /* comment the following parameter to exclude pass-through authentication feature */

/* Usually NetBIOS checks that a SESSION REQUEST message was send to a known name (the name of the
   host computer or SMB alias - *SMBSERV). In some projects CIFS should answer to multiple names, not
   necessarily the same as the host name. In this case it does not check the called name in a
   SESSION REQUEST packet. */

#define UD_NB_CHECKCALLEDNAME       /* comment this line to omit called name check */

/* In a standard implementation of BSD sockets a binded socket gets both unicasts and
   broadcasts. In this case binding socket to a broadcast address is not necessary and
   sometimes it is an illegal operation.
   However, in some implementations a bound socket does not get broadcasts. There we need
   two separate sockets - one for broadcasts and another one for unicasts.
   Define the following parameter if two separate sockets are required. */

#define UD_NB_BINDBROADCASTS       /* comment this line if the target BSD sockets are standard */

/* When this parameter is defined, send operation is asynchronous. It returns immediately while
   the buffer contents is being sent in a background process. This feature requires OS support
   for asynchronous socket operations. */

/* #define UD_NS_ASYNCSEND */             /* Comment this line to use synchronous send */
/* When this parameter is defined NetBIOS component skips host name registration. */

/*#define UD_CM_DONOTREGISTERHOSTNAMENETBIOS*/

/* When this parameter is defined DNS component skips host name registration. */

/*#define UD_CM_DONOTREGISTERHOSTNAMEDNS*/

#define UD_NQ_INCLUDESMB2              /* comment this line to disable SMB2 support */
#define UD_NQ_INCLUDESMB3              /* comment this line to disable SMB3 support */
#define UD_NQ_INCLUDESMB311            /* comment this line to disable SMB3.1.1 support */
#define UD_CS_INCLUDEPERSISTENTFIDS    /* comment this line to disable SMB2 durable file ID support */
/*#define UD_CS_FORCEINTERIMRESPONSES*/    /* comment this line to suppress sending interim responses */


/* Default number of credits NQ server grants:
   The bigger number may cause timeout on bulk upload/download operation,
   especially when the client is W2k8 Server.*/
#define UD_CS_SMB2_NUMCREDITS 30

/* When this parameter is defined message signing is supported and can take the following values:
   1    message signing enabled, but not required
   2    message signing required   
   Comment out this parameter to disable message signing support
   NOTE: Windows 8 and above require message signing to be at least 1 */

#define UD_CS_MESSAGESIGNINGPOLICY  1

/* When this parameter is defined NQ Server joins its default domain */
#define UD_CS_INCLUDEDOMAINMEMBERSHIP

#define UD_CM_SECURITYDESCRIPTORLENGTH 512  /* maximum length of a SD in bytes */
#define UD_CM_MAXUSERGROUPS 5               /* maximum number of groups a user may be member of */

/*
    CIFS server parameters
    ---------------------

  The values in this section parameterize the CIFS implementation behavior
 */

/* comment out the next line if your configuration does not contain NO server */

#define UD_NQ_INCLUDECIFSSERVER

/* Comment out the next line if you do not want your CIFS server to transmit HOST
   ANNONCEMENT messages. Then this server will not be listed under My Network Places */

#define UD_CS_INCLUDEHOSTANNOUNCEMENT

/* Name length limits */
#define UD_FS_MAXSHARELEN  64        /* share name length */
#define UD_FS_MAXPATHLEN 250         /* share mapping length */
#define UD_FS_MAXDESCRIPTIONLEN 250  /* share description length */

/* NQ Server keeps trek of session sockets (those that were created on nsAccept()). The space for
   keeping information about those sockets is limited to a user-defined number. This number limits
   also the number of client computers that may be simultaneously connected to NQ Server. */
#define UD_FS_NUMSERVERSESSIONS        50

/* if this parameter is defined , when session table is full , the new connection will be refused.
   if it isn't defined the least active connection will be released */
/*#define UD_CS_REFUSEONSESSIONTABLEOVERFLOW*/

/* number of connection requests that may be queued during one listen() call */
#define UD_FS_LISTENQUEUELEN    10

/* Maximum number of connected users (UIDs) */
#define UD_FS_NUMSERVERUSERS    30

/* Maximum number of connected shares (TIDs) */
#define UD_FS_NUMSERVERTREES    50

/* Maximum number of active search operations (SIDs) */
#define UD_FS_NUMSERVERSEARCHES 30

/* Maximum number of shares, supported by server */
#define UD_FS_NUMSERVERSHARES       15

/* Maximum number of unique files */
#define UD_FS_NUMSERVERFILENAMES     60

/* Maximum number of opened files (FIDs) */
#define UD_FS_NUMSERVERFILEOPEN      65

/* Maximum filename length in host file system characters */
#define UD_FS_FILENAMELEN           256     /* full path, this is the VxWorks restriction */
#define UD_FS_FILENAMECOMPONENTLEN  256     /* of one component */

/* File system name as reported to a CIFS client */
#define UD_FS_FILESYSTEMNAME    "NTFS"      /* recommended to keep it NTFS to avoid problems with Windows 9x/ME */

/* CIFS requires server to report its File System's ID. NT should report zero, while
   other file systems are not specified, so - this number is not very critical. But, do notice
   it should be other then 0 if the target file system is not NT. */
#define UD_FS_FILESYSTEMID      1

/* File access flags:
 these flags are any combination of the following values:
    FILE_READ_DATA          0x00000001  Data can be read from the file
    FILE_WRITE_DATA         0x00000002  Data can be written to the file
    FILE_APPEND_DATA        0x00000004  Data can be appended to the file
    FILE_READ_EA            0x00000008  Extended attributes associated with the file can be read
    FILE_WRITE_EA           0x00000010  Extended attributes associated with the file can be written
    FILE_EXECUTE            0x00000020  Data can be read into memory from the file using system
                                        paging I/O
    FILE_READ_ATTRIBUTES    0x00000080  Attributes associated with the file can be read
    FILE_WRITE_ATTRIBUTES   0x00000100  Attributes associated with the file can be written
    DELETE                  0x00010000  The file can be deleted
    READ_CONTROL            0x00020000  The access control list and ownership associated with the file
                                        can be read
    WRITE_DAC               0x00040000  The access control list and ownership associated with the file
                                        can be written
    WRITE_OWNER             0x00080000  Ownership information associated with the file can be written
    SYNCHRONIZE             0x00100000  The file handle can waited on to synchronize with the
                                        completion of an input/output request

    these bit sets are different for a file and a directory.
 */

#define UD_FS_DIRECTORYACCESSFLAGS  0x000000A9  /* recommended value */
#define UD_FS_FILEACCESSFLAGS       0x000101B7  /* recommended value */

/* File open mode flags:
 these flags are any combination of the following values:
    FILE_WRITE_THROUGH          0x00000002  File is opened in a mode where data is written to the
                                            file before the driver completes a write request
    FILE_SEQUENTIAL_ONLY        0x00000004  All access to the file is sequential
    FILE_SYNCHRONOUS_IO_ALERT   0x00000010  All operations on the file are performed
                                            synchronously
    FILE_SYNCHRONOUS_IO_NONALERT 0x00000020 All operations on the file are to be performed
                                            synchronously. Waits in the system to
                                            synchronize I/O queuing and completion are
                                            not subject to alerts. */

#define UD_FS_OPENMODEFLAGS  0          /* recommended value */

/* Buffer alignment may have any of the following values:
    FILE_BYTE_ALIGNMENT     0x00000000 The buffer needs to be aligned on a byte boundary
    FILE_WORD_ALIGNMENT     0x00000001 The buffer needs to be aligned on a word boundary
    FILE_LONG_ALIGNMENT     0x00000003 The buffer needs to be aligned on a 4 byte boundary */

#define UD_FS_BUFFERALIGNMENT  0x3      /* recommended value */

/* File system attributes may have any combination of the following values:
    CM_FS_CASESENSITIVESEARCH  0x00000001
    CM_FS_CASEPRESERVEDNAMES   0x00000002
    CM_FS_PERSISTENTACLS       0x00000004
    CM_FS_FILECOMPRESSION      0x00000008
    CM_FS_VOLUMEQUOTAS         0x00000010
    CM_FS_DEVICEISMOUNTED      0x00000020
    CM_FS_VOLUMEISCOMPRESSED   0x00008000 */

#define UD_FS_FILESYSTEMATTRIBUTES 3    /* recommended value (can not use the actual names defined in cmfscifs.h */

#define UD_FS_READAHEAD     /* define this parameter to allow pre-reading (optimistic locking assumed) */

/*#define UD_CS_AVOIDSHAREACCESSCHECK */    /* define this parameter to avoid checking share before approving TreeConnect*/
#define UD_CS_INCLUDESECURITYDESCRIPTORS    /* define this parameter if SDs are supported */
/*#define UD_CS_INCLUDELOCALUSERMANAGEMENT*//* define this parameter to be able to set personal ACL for a local user */
/*#define UD_CS_AUTHENTICATEANONYMOUS  */   /* allow anonymous user authentication */

#define UD_CS_INCLUDEEXTENDEDSECURITY       /* SPNEGO NTLMSSP support */

/*#define UD_CS_INCLUDEDIRECTTRANSFER*/		/* allow socket-to-file transfer */

/*#define UD_CS_HIDE_NOACCESS_SHARE*/       /* define this parameter to hide shares for users that have no rights to use them */

/*#define UD_CS_ALLOW_NONENCRYPTED_ACCESS_TO_ENCRYPTED_SHARE*/ /* define this parameter to allow non encrypted access to encrypted share */

/*
    CIFS Server RPC configuration
    -------------------------
    This section defines which RPC components of CIFS server will be generated
    User may either disable all components by commenting UD_CS_INCLUDERPC or enable
    some of them by uncommenting UD_CS_INCLUDERPC and those of UD_CS_INCLUDERPC_<service>
    components that correspond to desired services.
 */

#define UD_CS_INCLUDERPC             /* define this parameter to include any services */
#define UD_CS_INCLUDERPC_SRVSVC      /* define this parameter to include SRVSVC pipe */
#define UD_CS_INCLUDERPC_WKSSVC      /* define this parameter to include WKSSVC pipe */
/*#define UD_CS_INCLUDERPC_SPOOLSS */    /* define this parameter to include SPOOLSS pipe */
/*#define UD_CS_INCLUDERPC_LSARPC*/      /* define this parameter to include LSA pipe */
/*#define UD_CS_INCLUDERPC_SAMRPC*/      /* define this parameter to include SAMR pipe */
#define UD_CS_INCLUDERPC_SRVSVC_EXTENSION     /* define this parameter to include the extension of SRVSVC pipe */
#define UD_CS_INCLUDERPC_WINREG               /* define this parameter to include WINREG pipe */

/* SPOOLSS parameters */

#define UD_CS_SPOOLSS_MAXOPENPRINTERS 50	  /* maximum number of simultaneous OpenPrinter(Ex) operations */

/*
    CIFS client parameters
    ----------------------
*/

/* comment out the next line if your configuration does not contain NO client */

#define UD_NQ_INCLUDECIFSCLIENT

/* number of seconds the NQ client waits for response before fail the operation */

#define UD_CC_CLIENTRESPONSETIMEOUT 15

/* maximum number of client retry times*/
/*#define UD_CC_CLIENTRETRYCOUNT      3*/

/* maximum number of client retry times when browsing*/
/*#define UD_CC_BROWSERETRYCOUNT      3 */

/*#define UD_CC_INCLUDEDFS */            /* uncomment this line for DFS support in the client */


#define UD_CC_INCLUDEEXTENDEDSECURITY   /* comment this line to restrict */
/*#define UD_CC_INCLUDEEXTENDEDSECURITY_KERBEROS */

/*#define UD_CC_INCLUDESECURITYDESCRIPTORS*/  /* define this parameter to include security descriptors */
#define UD_CC_INCLUDEDOMAINMEMBERSHIP         /* define this parameter to include domain membership functionality */
/*#define UD_CC_INCLUDELDAP   */              /* define this parameter to include ldap functionality */
/*#define UD_CC_INCLUDEFSDRIVER*/             /* define this parameter to include file system driver functionality (currently FUSE) */

#define UD_CC_INCLUDEOLDBROWSERAPI            /* old style browser API */

#define UD_CC_CACHECREDENTIALS                /* include credentials caching mechanism */

/* File name for capture output. This parameter is only used when
   the UD_NQ_INCLUDESMBCAPTURE Macro is defined. */
#define UD_CM_CAPTURE_FILENAME "nq.pcap"

#endif  /* _UDPARAMS_H_ */
