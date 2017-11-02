/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : API for user-defined features
 *--------------------------------------------------------------------
 * MODULE        : UD - User-defined
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 14-May-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/
#include "udparams.h"

#ifndef _UDAPI_H_
#define _UDAPI_H_

/* Primitive data types */

typedef char                NQ_CHAR;
typedef unsigned char       NQ_BYTE;
typedef int                 NQ_INT;
typedef unsigned int        NQ_UINT;
typedef int                 NQ_BOOL;
typedef NQ_UINT             NQ_INDEX;
typedef NQ_UINT             NQ_COUNT;
typedef short               NQ_INT16;
#ifdef SY_INT32
typedef SY_INT32            NQ_INT32;
#else
typedef long                NQ_INT32;
#endif
typedef unsigned short      NQ_UINT16;
#ifdef SY_INT32
typedef unsigned SY_INT32   NQ_UINT32;
#else
typedef unsigned long       NQ_UINT32;
#endif
typedef NQ_UINT16           NQ_WCHAR;
typedef void                *NQ_HANDLE;
typedef NQ_INT              NQ_STATUS;
typedef NQ_UINT32           NQ_TIME;
typedef NQ_UINT16           NQ_PORT;
typedef NQ_UINT32           NQ_IPADDRESS4;
typedef NQ_UINT16           NQ_IPADDRESS6[8];
typedef unsigned long       NQ_ULONG;

#define UD_DNS_SERVERSTRINGSIZE (16 * sizeof(NQ_TCHAR) * UD_NQ_MAXDNSSERVERS * UD_NS_MAXADAPTERS)

#ifdef UD_NQ_USETRANSPORTIPV6
typedef struct _NQ_IPADDRESS
{
    NQ_BYTE version;
    union
    {
        NQ_IPADDRESS6 v6;
        NQ_IPADDRESS4 v4;
    } addr;
} NQ_IPADDRESS;
#else /* UD_NQ_USETRANSPORTIPV6 */
typedef NQ_IPADDRESS4 NQ_IPADDRESS;
#endif /* UD_NQ_USETRANSPORTIPV6 */

#ifdef UD_CM_UNICODEAPPLICATION
#define NQ_TCHAR NQ_WCHAR
#else
#define NQ_TCHAR NQ_CHAR
#endif

/*
    SMB Errors

    SMB error in "DOS" format consists of an error class and error code
 */

#define SMB_DOSERR(_class, _code)   ((_code << 16) | _class)

#define SMB_ERRsuccess              0x00000000

#define DOS_ERRbadfunc              SMB_DOSERR(1, 1)
#define DOS_ERRbadfile              SMB_DOSERR(1, 2)
#define DOS_ERRbadpath              SMB_DOSERR(1, 3)
#define DOS_ERRnofids               SMB_DOSERR(1, 4)
#define DOS_ERRnoaccess             SMB_DOSERR(1, 5)
#define DOS_ERRbadfid               SMB_DOSERR(1, 6)
#define DOS_ERRbadmcb               SMB_DOSERR(1, 7)
#define DOS_ERRnomem                SMB_DOSERR(1, 8)
#define DOS_ERRbadmem               SMB_DOSERR(1, 9)
#define DOS_ERRbadenv               SMB_DOSERR(1, 10)
#define DOS_ERRbadformat            SMB_DOSERR(1, 11)
#define DOS_ERRbadaccess            SMB_DOSERR(1, 12)
#define DOS_ERRbaddata              SMB_DOSERR(1, 13)
#define DOS_ERRbaddrive             SMB_DOSERR(1, 15)
#define DOS_ERRremcd                SMB_DOSERR(1, 16)
#define DOS_ERRdiffdevice           SMB_DOSERR(1, 17)
#define DOS_ERRnofiles              SMB_DOSERR(1, 18)
#define DOS_ERRbadshare             SMB_DOSERR(1, 32)
#define DOS_ERRlock                 SMB_DOSERR(1, 33)
#define DOS_ERRdontsupportipc       SMB_DOSERR(1, 66)
#define DOS_ERRnoshare              SMB_DOSERR(1, 67)
#define DOS_ERRfileexists           SMB_DOSERR(1, 80)
#define DOS_ERRbaddirectory         SMB_DOSERR(1, 87)
#define DOS_ERRinsufficientbuffer   SMB_DOSERR(1, 122)
#define DOS_ERRinvalidname          SMB_DOSERR(1, 123)
#define DOS_ERRdirnotempty          SMB_DOSERR(1, 145)
#define DOS_ERRalreadyexists        SMB_DOSERR(1, 183)
#define DOS_ERRbadpipe              SMB_DOSERR(1, 230)
#define DOS_ERRpipebusy             SMB_DOSERR(1, 231)
#define DOS_ERRpipeclosing          SMB_DOSERR(1, 232)
#define DOS_ERRnotconnected         SMB_DOSERR(1, 233)
#define DOS_ERRmoredata             SMB_DOSERR(1, 234)

#define SRV_ERRerror                SMB_DOSERR(2, 1)
#define SRV_ERRbadpw                SMB_DOSERR(2, 2)
#define SRV_ERRaccess               SMB_DOSERR(2, 4)
#define SRV_ERRinvtid               SMB_DOSERR(2, 5)
#define SRV_ERRinvnetname           SMB_DOSERR(2, 6)
#define SRV_ERRinvdevice            SMB_DOSERR(2, 7)
#define SRV_ERRqfull                SMB_DOSERR(2, 49)
#define SRV_ERRqtoobig              SMB_DOSERR(2, 50)
#define SRV_ERRqeof                 SMB_DOSERR(2, 51)
#define SRV_ERRinvfid               SMB_DOSERR(2, 52)
#define SRV_ERRsmbcmd               SMB_DOSERR(2, 64)
#define SRV_ERRsrverror             SMB_DOSERR(2, 65)
#define SRV_ERRfilespecs            SMB_DOSERR(2, 67)
#define SRV_ERRbadpermits           SMB_DOSERR(2, 69)
#define SRV_ERRsetattrmode          SMB_DOSERR(2, 71)
#define SRV_ERRpaused               SMB_DOSERR(2, 81)
#define SRV_ERRmsgoff               SMB_DOSERR(2, 82)
#define SRV_ERRnoroom               SMB_DOSERR(2, 83)
#define SRV_ERRrmuns                SMB_DOSERR(2, 87)
#define SRV_ERRtimeout              SMB_DOSERR(2, 88)
#define SRV_ERRnoresource           SMB_DOSERR(2, 89)
#define SRV_ERRtoomanyuids          SMB_DOSERR(2, 90)
#define SRV_ERRinvuid               SMB_DOSERR(2, 91)
#define SRV_ERRusempx               SMB_DOSERR(2, 250)
#define SRV_ERRusestd               SMB_DOSERR(2, 251)
#define SRV_ERRcontmpx              SMB_DOSERR(2, 252)
#define SRV_ERRnosupport            SMB_DOSERR(2, 65535)

#define HRD_ERRnowrite              SMB_DOSERR(3, 19)
#define HRD_ERRbadunit              SMB_DOSERR(3, 20)
#define HRD_ERRnotready             SMB_DOSERR(3, 21)
#define HRD_ERRbadcmd               SMB_DOSERR(3, 22)
#define HRD_ERRdata                 SMB_DOSERR(3, 23)
#define HRD_ERRbadreq               SMB_DOSERR(3, 24)
#define HRD_ERRseek                 SMB_DOSERR(3, 25)
#define HRD_ERRbadmedia             SMB_DOSERR(3, 26)
#define HRD_ERRbadsector            SMB_DOSERR(3, 27)
#define HRD_ERRnopaper              SMB_DOSERR(3, 28)
#define HRD_ERRwrite                SMB_DOSERR(3, 29)
#define HRD_ERRread                 SMB_DOSERR(3, 30)
#define HRD_ERRgeneral              SMB_DOSERR(3, 31)
#define HRD_ERRbadshare             SMB_DOSERR(3, 32)
#define HRD_ERRlock                 SMB_DOSERR(3, 33)
#define HRD_ERRwrongdisk            SMB_DOSERR(3, 34)
#define HRD_ERRFCBUnavail           SMB_DOSERR(3, 35)
#define HRD_ERRsharebufexc          SMB_DOSERR(3, 36)
#define HRD_ERRdiskfull             SMB_DOSERR(3, 39)

/* NT statuses (only some of them used
   ERRORMASK bits indicate that this is an error and SMB command response should be
   truncated to 3 bytes */

#define SMB_STATUS_OK                                   0xc0000000
#define SMB_STATUS_INVALID                              0xffffffff

#define SMB_STATUS_ENUMDIR                              0x0000010c
#define SMB_STATUS_PENDING                              0x00000103
#define SMB_STATUS_MORE_ENTRIES                         0x00000105
#define SMB_STATUS_SOME_UNMAPPED                        0x00000107
#define SMB_STATUS_INSUFFICIENT_BUFFER                  0x0000007a
#define SMB_STATUS_UNKNOWN_PRINTER_DRIVER               0x00000705
#define SMB_STATUS_INVALID_DATATYPE                     0x0000070c

#define SMB_STATUS_BUFFER_OVERFLOW                      0x80000005
#define SMB_STATUS_NO_MORE_FILES                        0x80000006
#define SMB_STATUS_NO_MORE_ENTRIES                      0x8000001a

#define SMB_STATUS_UNSUCCESSFUL                         0xc0000001
#define SMB_STATUS_NOT_IMPLEMENTED                      0xc0000002
#define SMB_STATUS_INVALID_INFO_CLASS                   0xc0000003
#define SMB_STATUS_INFO_LENGTH_MISMATCH                 0xc0000004
#define SMB_STATUS_ACCESS_VIOLATION                     0xc0000005
#define SMB_STATUS_IN_PAGE_ERROR                        0xc0000006
#define SMB_STATUS_PAGEFILE_QUOTA                       0xc0000007
#define SMB_STATUS_INVALID_HANDLE                       0xc0000008
#define SMB_STATUS_BAD_INITIAL_STACK                    0xc0000009
#define SMB_STATUS_BAD_INITIAL_PC                       0xc000000a
#define SMB_STATUS_INVALID_CID                          0xc000000b
#define SMB_STATUS_TIMER_NOT_CANCELED                   0xc000000c
#define SMB_STATUS_INVALID_PARAMETER                    0xc000000d
#define SMB_STATUS_NO_SUCH_DEVICE                       0xc000000e
#define SMB_STATUS_NO_SUCH_FILE                         0xc000000f
#define SMB_STATUS_INVALID_DEVICE_REQUEST               0xc0000010
#define SMB_STATUS_END_OF_FILE                          0xc0000011
#define SMB_STATUS_WRONG_VOLUME                         0xc0000012
#define SMB_STATUS_NO_MEDIA_IN_DEVICE                   0xc0000013
#define SMB_STATUS_UNRECOGNIZED_MEDIA                   0xc0000014
#define SMB_STATUS_NONEXISTENT_SECTOR                   0xc0000015
#define SMB_STATUS_MORE_PROCESSING_REQUIRED             0xc0000016
#define SMB_STATUS_NO_MEMORY                            0xc0000017
#define SMB_STATUS_CONFLICTING_ADDRESSES                0xc0000018
#define SMB_STATUS_NOT_MAPPED_VIEW                      0xc0000019
#define SMB_STATUS_UNABLE_TO_FREE_VM                    0xc000001a
#define SMB_STATUS_UNABLE_TO_DELETE_SECTION             0xc000001b
#define SMB_STATUS_INVALID_SYSTEM_SERVICE               0xc000001c
#define SMB_STATUS_ILLEGAL_INSTRUCTION                  0xc000001d
#define SMB_STATUS_INVALID_LOCK_SEQUENCE                0xc000001e
#define SMB_STATUS_INVALID_VIEW_SIZE                    0xc000001f
#define SMB_STATUS_INVALID_FILE_FOR_SECTION             0xc0000020
#define SMB_STATUS_ALREADY_COMMITTED                    0xc0000021
#define SMB_STATUS_ACCESS_DENIED                        0xc0000022
#define SMB_STATUS_BUFFER_TOO_SMALL                     0xc0000023
#define SMB_STATUS_OBJECT_TYPE_MISMATCH                 0xc0000024
#define SMB_STATUS_NONCONTINUABLE_EXCEPTION             0xc0000025
#define SMB_STATUS_INVALID_DISPOSITION                  0xc0000026
#define SMB_STATUS_UNWIND                               0xc0000027
#define SMB_STATUS_BAD_STACK                            0xc0000028
#define SMB_STATUS_INVALID_UNWIND_TARGET                0xc0000029
#define SMB_STATUS_NOT_LOCKED                           0xc000002a
#define SMB_STATUS_PARITY_ERROR                         0xc000002b
#define SMB_STATUS_UNABLE_TO_DECOMMIT_VM                0xc000002c
#define SMB_STATUS_NOT_COMMITTED                        0xc000002d
#define SMB_STATUS_INVALID_PORT_ATTRIBUTES              0xc000002e
#define SMB_STATUS_PORT_MESSAGE_TOO_LONG                0xc000002f
#define SMB_STATUS_INVALID_PARAMETER_MIX                0xc0000030
#define SMB_STATUS_INVALID_QUOTA_LOWER                  0xc0000031
#define SMB_STATUS_DISK_CORRUPT_ERROR                   0xc0000032
#define SMB_STATUS_OBJECT_NAME_INVALID                  0xc0000033
#define SMB_STATUS_OBJECT_NAME_NOT_FOUND                0xc0000034
#define SMB_STATUS_OBJECT_NAME_COLLISION                0xc0000035
#define SMB_STATUS_HANDLE_NOT_WAITABLE                  0xc0000036
#define SMB_STATUS_PORT_DISCONNECTED                    0xc0000037
#define SMB_STATUS_DEVICE_ALREADY_ATTACHED              0xc0000038
#define SMB_STATUS_OBJECT_PATH_INVALID                  0xc0000039
#define SMB_STATUS_OBJECT_PATH_NOT_FOUND                0xc000003a
#define SMB_STATUS_OBJECT_PATH_SYNTAX_BAD               0xc000003b
#define SMB_STATUS_DATA_OVERRUN                         0xc000003c
#define SMB_STATUS_DATA_LATE_ERROR                      0xc000003d
#define SMB_STATUS_DATA_ERROR                           0xc000003e
#define SMB_STATUS_CRC_ERROR                            0xc000003f
#define SMB_STATUS_SECTION_TOO_BIG                      0xc0000040
#define SMB_STATUS_PORT_CONNECTION_REFUSED              0xc0000041
#define SMB_STATUS_INVALID_PORT_HANDLE                  0xc0000042
#define SMB_STATUS_SHARING_VIOLATION                    0xc0000043
#define SMB_STATUS_QUOTA_EXCEEDED                       0xc0000044
#define SMB_STATUS_INVALID_PAGE_PROTECTION              0xc0000045
#define SMB_STATUS_MUTANT_NOT_OWNED                     0xc0000046
#define SMB_STATUS_SEMAPHORE_LIMIT_EXCEEDED             0xc0000047
#define SMB_STATUS_PORT_ALREADY_SET                     0xc0000048
#define SMB_STATUS_SECTION_NOT_IMAGE                    0xc0000049
#define SMB_STATUS_SUSPEND_COUNT_EXCEEDED               0xc000004a
#define SMB_STATUS_THREAD_IS_TERMINATING                0xc000004b
#define SMB_STATUS_BAD_WORKING_SET_LIMIT                0xc000004c
#define SMB_STATUS_INCOMPATIBLE_FILE_MAP                0xc000004d
#define SMB_STATUS_SECTION_PROTECTION                   0xc000004e
#define SMB_STATUS_EAS_NOT_SUPPORTED                    0xc000004f
#define SMB_STATUS_EA_TOO_LARGE                         0xc0000050
#define SMB_STATUS_NONEXISTENT_EA_ENTRY                 0xc0000051
#define SMB_STATUS_NO_EAS_ON_FILE                       0xc0000052
#define SMB_STATUS_EA_CORRUPT_ERROR                     0xc0000053
#define SMB_STATUS_FILE_LOCK_CONFLICT                   0xc0000054
#define SMB_STATUS_LOCK_NOT_GRANTED                     0xc0000055
#define SMB_STATUS_DELETE_PENDING                       0xc0000056
#define SMB_STATUS_CTL_FILE_NOT_SUPPORTED               0xc0000057
#define SMB_STATUS_UNKNOWN_REVISION                     0xc0000058
#define SMB_STATUS_REVISION_MISMATCH                    0xc0000059
#define SMB_STATUS_INVALID_OWNER                        0xc000005a
#define SMB_STATUS_INVALID_PRIMARY_GROUP                0xc000005b
#define SMB_STATUS_NO_IMPERSONATION_TOKEN               0xc000005c
#define SMB_STATUS_CANT_DISABLE_MANDATORY               0xc000005d
#define SMB_STATUS_NO_LOGON_SERVERS                     0xc000005e
#define SMB_STATUS_NO_SUCH_LOGON_SESSION                0xc000005f
#define SMB_STATUS_NO_SUCH_PRIVILEGE                    0xc0000060
#define SMB_STATUS_PRIVILEGE_NOT_HELD                   0xc0000061
#define SMB_STATUS_INVALID_ACCOUNT_NAME                 0xc0000062
#define SMB_STATUS_USER_EXISTS                          0xc0000063
#define SMB_STATUS_NO_SUCH_USER                         0xc0000064
#define SMB_STATUS_GROUP_EXISTS                         0xc0000065
#define SMB_STATUS_NO_SUCH_GROUP                        0xc0000066
#define SMB_STATUS_MEMBER_IN_GROUP                      0xc0000067
#define SMB_STATUS_MEMBER_NOT_IN_GROUP                  0xc0000068
#define SMB_STATUS_LAST_ADMIN                           0xc0000069
#define SMB_STATUS_WRONG_PASSWORD                       0xc000006a
#define SMB_STATUS_ILL_FORMED_PASSWORD                  0xc000006b
#define SMB_STATUS_PASSWORD_RESTRICTION                 0xc000006c
#define SMB_STATUS_LOGON_FAILURE                        0xc000006d
#define SMB_STATUS_ACCOUNT_RESTRICTION                  0xc000006e
#define SMB_STATUS_INVALID_LOGON_HOURS                  0xc000006f
#define SMB_STATUS_INVALID_WORKSTATION                  0xc0000070
#define SMB_STATUS_PASSWORD_EXPIRED                     0xc0000071
#define SMB_STATUS_ACCOUNT_DISABLED                     0xc0000072
#define SMB_STATUS_NONE_MAPPED                          0xc0000073
#define SMB_STATUS_TOO_MANY_LUIDS_REQUESTED             0xc0000074
#define SMB_STATUS_LUIDS_EXHAUSTED                      0xc0000075
#define SMB_STATUS_INVALID_SUB_AUTHORITY                0xc0000076
#define SMB_STATUS_INVALID_ACL                          0xc0000077
#define SMB_STATUS_INVALID_SID                          0xc0000078
#define SMB_STATUS_INVALID_SECURITY_DESCR               0xc0000079
#define SMB_STATUS_PROCEDURE_NOT_FOUND                  0xc000007a
#define SMB_STATUS_INVALID_IMAGE_FORMAT                 0xc000007b
#define SMB_STATUS_NO_TOKEN                             0xc000007c
#define SMB_STATUS_BAD_INHERITANCE_ACL                  0xc000007d
#define SMB_STATUS_RANGE_NOT_LOCKED                     0xc000007e
#define SMB_STATUS_DISK_FULL                            0xc000007f
#define SMB_STATUS_SERVER_DISABLED                      0xc0000080
#define SMB_STATUS_SERVER_NOT_DISABLED                  0xc0000081
#define SMB_STATUS_TOO_MANY_GUIDS_REQUESTED             0xc0000082
#define SMB_STATUS_GUIDS_EXHAUSTED                      0xc0000083
#define SMB_STATUS_INVALID_ID_AUTHORITY                 0xc0000084
#define SMB_STATUS_AGENTS_EXHAUSTED                     0xc0000085
#define SMB_STATUS_INVALID_VOLUME_LABEL                 0xc0000086
#define SMB_STATUS_SECTION_NOT_EXTENDED                 0xc0000087
#define SMB_STATUS_NOT_MAPPED_DATA                      0xc0000088
#define SMB_STATUS_RESOURCE_DATA_NOT_FOUND              0xc0000089
#define SMB_STATUS_RESOURCE_TYPE_NOT_FOUND              0xc000008a
#define SMB_STATUS_RESOURCE_NAME_NOT_FOUND              0xc000008b
#define SMB_STATUS_ARRAY_BOUNDS_EXCEEDED                0xc000008c
#define SMB_STATUS_FLOAT_DENORMAL_OPERAND               0xc000008d
#define SMB_STATUS_FLOAT_DIVIDE_BY_ZERO                 0xc000008e
#define SMB_STATUS_FLOAT_INEXACT_RESULT                 0xc000008f
#define SMB_STATUS_FLOAT_INVALID_OPERATION              0xc0000090
#define SMB_STATUS_FLOAT_OVERFLOW                       0xc0000091
#define SMB_STATUS_FLOAT_STACK_CHECK                    0xc0000092
#define SMB_STATUS_FLOAT_UNDERFLOW                      0xc0000093
#define SMB_STATUS_INTEGER_DIVIDE_BY_ZERO               0xc0000094
#define SMB_STATUS_INTEGER_OVERFLOW                     0xc0000095
#define SMB_STATUS_PRIVILEGED_INSTRUCTION               0xc0000096
#define SMB_STATUS_TOO_MANY_PAGING_FILES                0xc0000097
#define SMB_STATUS_FILE_INVALID                         0xc0000098
#define SMB_STATUS_ALLOTTED_SPACE_EXCEEDED              0xc0000099
#define SMB_STATUS_INSUFFICIENT_RESOURCES               0xc000009a
#define SMB_STATUS_DFS_EXIT_PATH_FOUND                  0xc000009b
#define SMB_STATUS_DEVICE_DATA_ERROR                    0xc000009c
#define SMB_STATUS_DEVICE_NOT_CONNECTED                 0xc000009d
#define SMB_STATUS_DEVICE_POWER_FAILURE                 0xc000009e
#define SMB_STATUS_FREE_VM_NOT_AT_BASE                  0xc000009f
#define SMB_STATUS_MEMORY_NOT_ALLOCATED                 0xc00000a0
#define SMB_STATUS_WORKING_SET_QUOTA                    0xc00000a1
#define SMB_STATUS_MEDIA_WRITE_PROTECTED                0xc00000a2
#define SMB_STATUS_DEVICE_NOT_READY                     0xc00000a3
#define SMB_STATUS_INVALID_GROUP_ATTRIBUTES             0xc00000a4
#define SMB_STATUS_BAD_IMPERSONATION_LEVEL              0xc00000a5
#define SMB_STATUS_CANT_OPEN_ANONYMOUS                  0xc00000a6
#define SMB_STATUS_BAD_VALIDATION_CLASS                 0xc00000a7
#define SMB_STATUS_BAD_TOKEN_TYPE                       0xc00000a8
#define SMB_STATUS_BAD_MASTER_BOOT_RECORD               0xc00000a9
#define SMB_STATUS_INSTRUCTION_MISALIGNMENT             0xc00000aa
#define SMB_STATUS_INSTANCE_NOT_AVAILABLE               0xc00000ab
#define SMB_STATUS_PIPE_NOT_AVAILABLE                   0xc00000ac
#define SMB_STATUS_INVALID_PIPE_STATE                   0xc00000ad
#define SMB_STATUS_PIPE_BUSY                            0xc00000ae
#define SMB_STATUS_ILLEGAL_FUNCTION                     0xc00000af
#define SMB_STATUS_PIPE_DISCONNECTED                    0xc00000b0
#define SMB_STATUS_PIPE_CLOSING                         0xc00000b1
#define SMB_STATUS_PIPE_CONNECTED                       0xc00000b2
#define SMB_STATUS_PIPE_LISTENING                       0xc00000b3
#define SMB_STATUS_INVALID_READ_MODE                    0xc00000b4
#define SMB_STATUS_IO_TIMEOUT                           0xc00000b5
#define SMB_STATUS_FILE_FORCED_CLOSED                   0xc00000b6
#define SMB_STATUS_PROFILING_NOT_STARTED                0xc00000b7
#define SMB_STATUS_PROFILING_NOT_STOPPED                0xc00000b8
#define SMB_STATUS_COULD_NOT_INTERPRET                  0xc00000b9
#define SMB_STATUS_FILE_IS_A_DIRECTORY                  0xc00000ba
#define SMB_STATUS_NOT_SUPPORTED                        0xc00000bb
#define SMB_STATUS_REMOTE_NOT_LISTENING                 0xc00000bc
#define SMB_STATUS_DUPLICATE_NAME                       0xc00000bd
#define SMB_STATUS_BAD_NETWORK_PATH                     0xc00000be
#define SMB_STATUS_NETWORK_BUSY                         0xc00000bf
#define SMB_STATUS_DEVICE_DOES_NOT_EXIST                0xc00000c0
#define SMB_STATUS_TOO_MANY_COMMANDS                    0xc00000c1
#define SMB_STATUS_ADAPTER_HARDWARE_ERROR               0xc00000c2
#define SMB_STATUS_INVALID_NETWORK_RESPONSE             0xc00000c3
#define SMB_STATUS_UNEXPECTED_NETWORK_ERROR             0xc00000c4
#define SMB_STATUS_BAD_REMOTE_ADAPTER                   0xc00000c5
#define SMB_STATUS_PRINT_QUEUE_FULL                     0xc00000c6
#define SMB_STATUS_NO_SPOOL_SPACE                       0xc00000c7
#define SMB_STATUS_PRINT_CANCELLED                      0xc00000c8
#define SMB_STATUS_NETWORK_NAME_DELETED                 0xc00000c9
#define SMB_STATUS_NETWORK_ACCESS_DENIED                0xc00000ca
#define SMB_STATUS_BAD_DEVICE_TYPE                      0xc00000cb
#define SMB_STATUS_BAD_NETWORK_NAME                     0xc00000cc
#define SMB_STATUS_TOO_MANY_NAMES                       0xc00000cd
#define SMB_STATUS_TOO_MANY_SESSIONS                    0xc00000ce
#define SMB_STATUS_SHARING_PAUSED                       0xc00000cf
#define SMB_STATUS_REQUEST_NOT_ACCEPTED                 0xc00000d0
#define SMB_STATUS_REDIRECTOR_PAUSED                    0xc00000d1
#define SMB_STATUS_NET_WRITE_FAULT                      0xc00000d2
#define SMB_STATUS_PROFILING_AT_LIMIT                   0xc00000d3
#define SMB_STATUS_NOT_SAME_DEVICE                      0xc00000d4
#define SMB_STATUS_FILE_RENAMED                         0xc00000d5
#define SMB_STATUS_VIRTUAL_CIRCUIT_CLOSED               0xc00000d6
#define SMB_STATUS_NO_SECURITY_ON_OBJECT                0xc00000d7
#define SMB_STATUS_CANT_WAIT                            0xc00000d8
#define SMB_STATUS_PIPE_EMPTY                           0xc00000d9
#define SMB_STATUS_CANT_ACCESS_DOMAIN_INFO              0xc00000da
#define SMB_STATUS_CANT_TERMINATE_SELF                  0xc00000db
#define SMB_STATUS_INVALID_SERVER_STATE                 0xc00000dc
#define SMB_STATUS_INVALID_DOMAIN_STATE                 0xc00000dd
#define SMB_STATUS_INVALID_DOMAIN_ROLE                  0xc00000de
#define SMB_STATUS_NO_SUCH_DOMAIN                       0xc00000df
#define SMB_STATUS_DOMAIN_EXISTS                        0xc00000e0
#define SMB_STATUS_DOMAIN_LIMIT_EXCEEDED                0xc00000e1
#define SMB_STATUS_OPLOCK_NOT_GRANTED                   0xc00000e2
#define SMB_STATUS_INVALID_OPLOCK_PROTOCOL              0xc00000e3
#define SMB_STATUS_INTERNAL_DB_CORRUPTION               0xc00000e4
#define SMB_STATUS_INTERNAL_ERROR                       0xc00000e5
#define SMB_STATUS_GENERIC_NOT_MAPPED                   0xc00000e6
#define SMB_STATUS_BAD_DESCRIPTOR_FORMAT                0xc00000e7
#define SMB_STATUS_INVALID_USER_BUFFER                  0xc00000e8
#define SMB_STATUS_UNEXPECTED_IO_ERROR                  0xc00000e9
#define SMB_STATUS_UNEXPECTED_MM_CREATE_ERR             0xc00000ea
#define SMB_STATUS_UNEXPECTED_MM_MAP_ERROR              0xc00000eb
#define SMB_STATUS_UNEXPECTED_MM_EXTEND_ERR             0xc00000ec
#define SMB_STATUS_NOT_LOGON_PROCESS                    0xc00000ed
#define SMB_STATUS_LOGON_SESSION_EXISTS                 0xc00000ee
#define SMB_STATUS_INVALID_PARAMETER_1                  0xc00000ef
#define SMB_STATUS_INVALID_PARAMETER_2                  0xc00000f0
#define SMB_STATUS_INVALID_PARAMETER_3                  0xc00000f1
#define SMB_STATUS_INVALID_PARAMETER_4                  0xc00000f2
#define SMB_STATUS_INVALID_PARAMETER_5                  0xc00000f3
#define SMB_STATUS_INVALID_PARAMETER_6                  0xc00000f4
#define SMB_STATUS_INVALID_PARAMETER_7                  0xc00000f5
#define SMB_STATUS_INVALID_PARAMETER_8                  0xc00000f6
#define SMB_STATUS_INVALID_PARAMETER_9                  0xc00000f7
#define SMB_STATUS_INVALID_PARAMETER_10                 0xc00000f8
#define SMB_STATUS_INVALID_PARAMETER_11                 0xc00000f9
#define SMB_STATUS_INVALID_PARAMETER_12                 0xc00000fa
#define SMB_STATUS_REDIRECTOR_NOT_STARTED               0xc00000fb
#define SMB_STATUS_REDIRECTOR_STARTED                   0xc00000fc
#define SMB_STATUS_STACK_OVERFLOW                       0xc00000fd
#define SMB_STATUS_NO_SUCH_PACKAGE                      0xc00000fe
#define SMB_STATUS_BAD_FUNCTION_TABLE                   0xc00000ff
#define SMB_STATUS_DIRECTORY_NOT_EMPTY                  0xc0000101
#define SMB_STATUS_FILE_CORRUPT_ERROR                   0xc0000102
#define SMB_STATUS_NOT_A_DIRECTORY                      0xc0000103
#define SMB_STATUS_BAD_LOGON_SESSION_STATE              0xc0000104
#define SMB_STATUS_LOGON_SESSION_COLLISION              0xc0000105
#define SMB_STATUS_NAME_TOO_LONG                        0xc0000106
#define SMB_STATUS_FILES_OPEN                           0xc0000107
#define SMB_STATUS_CONNECTION_IN_USE                    0xc0000108
#define SMB_STATUS_MESSAGE_NOT_FOUND                    0xc0000109
#define SMB_STATUS_PROCESS_IS_TERMINATING               0xc000010a
#define SMB_STATUS_INVALID_LOGON_TYPE                   0xc000010b
#define SMB_STATUS_NO_GUID_TRANSLATION                  0xc000010c
#define SMB_STATUS_CANNOT_IMPERSONATE                   0xc000010d
#define SMB_STATUS_IMAGE_ALREADY_LOADED                 0xc000010e
#define SMB_STATUS_ABIOS_NOT_PRESENT                    0xc000010f
#define SMB_STATUS_ABIOS_LID_NOT_EXIST                  0xc0000110
#define SMB_STATUS_ABIOS_LID_ALREADY_OWNED              0xc0000111
#define SMB_STATUS_ABIOS_NOT_LID_OWNER                  0xc0000112
#define SMB_STATUS_ABIOS_INVALID_COMMAND                0xc0000113
#define SMB_STATUS_ABIOS_INVALID_LID                    0xc0000114
#define SMB_STATUS_ABIOS_SELECTOR_NOT_AVAILABLE         0xc0000115
#define SMB_STATUS_ABIOS_INVALID_SELECTOR               0xc0000116
#define SMB_STATUS_NO_LDT                               0xc0000117
#define SMB_STATUS_INVALID_LDT_SIZE                     0xc0000118
#define SMB_STATUS_INVALID_LDT_OFFSET                   0xc0000119
#define SMB_STATUS_INVALID_LDT_DESCRIPTOR               0xc000011a
#define SMB_STATUS_INVALID_IMAGE_NE_FORMAT              0xc000011b
#define SMB_STATUS_RXACT_INVALID_STATE                  0xc000011c
#define SMB_STATUS_RXACT_COMMIT_FAILURE                 0xc000011d
#define SMB_STATUS_MAPPED_FILE_SIZE_ZERO                0xc000011e
#define SMB_STATUS_TOO_MANY_OPENED_FILES                0xc000011f
#define SMB_STATUS_CANCELLED                            0xc0000120
#define SMB_STATUS_CANNOT_DELETE                        0xc0000121
#define SMB_STATUS_INVALID_COMPUTER_NAME                0xc0000122
#define SMB_STATUS_FILE_DELETED                         0xc0000123
#define SMB_STATUS_SPECIAL_ACCOUNT                      0xc0000124
#define SMB_STATUS_SPECIAL_GROUP                        0xc0000125
#define SMB_STATUS_SPECIAL_USER                         0xc0000126
#define SMB_STATUS_MEMBERS_PRIMARY_GROUP                0xc0000127
#define SMB_STATUS_FILE_CLOSED                          0xc0000128
#define SMB_STATUS_TOO_MANY_THREADS                     0xc0000129
#define SMB_STATUS_THREAD_NOT_IN_PROCESS                0xc000012a
#define SMB_STATUS_TOKEN_ALREADY_IN_USE                 0xc000012b
#define SMB_STATUS_PAGEFILE_QUOTA_EXCEEDED              0xc000012c
#define SMB_STATUS_COMMITMENT_LIMIT                     0xc000012d
#define SMB_STATUS_INVALID_IMAGE_LE_FORMAT              0xc000012e
#define SMB_STATUS_INVALID_IMAGE_NOT_MZ                 0xc000012f
#define SMB_STATUS_INVALID_IMAGE_PROTECT                0xc0000130
#define SMB_STATUS_INVALID_IMAGE_WIN_16                 0xc0000131
#define SMB_STATUS_LOGON_SERVER_CONFLICT                0xc0000132
#define SMB_STATUS_TIME_DIFFERENCE_AT_DC                0xc0000133
#define SMB_STATUS_SYNCHRONIZATION_REQUIRED             0xc0000134
#define SMB_STATUS_DLL_NOT_FOUND                        0xc0000135
#define SMB_STATUS_OPEN_FAILED                          0xc0000136
#define SMB_STATUS_IO_PRIVILEGE_FAILED                  0xc0000137
#define SMB_STATUS_ORDINAL_NOT_FOUND                    0xc0000138
#define SMB_STATUS_ENTRYPOINT_NOT_FOUND                 0xc0000139
#define SMB_STATUS_CONTROL_C_EXIT                       0xc000013a
#define SMB_STATUS_LOCAL_DISCONNECT                     0xc000013b
#define SMB_STATUS_REMOTE_DISCONNECT                    0xc000013c
#define SMB_STATUS_REMOTE_RESOURCES                     0xc000013d
#define SMB_STATUS_LINK_FAILED                          0xc000013e
#define SMB_STATUS_LINK_TIMEOUT                         0xc000013f
#define SMB_STATUS_INVALID_CONNECTION                   0xc0000140
#define SMB_STATUS_INVALID_ADDRESS                      0xc0000141
#define SMB_STATUS_DLL_INIT_FAILED                      0xc0000142
#define SMB_STATUS_MISSING_SYSTEMFILE                   0xc0000143
#define SMB_STATUS_UNHANDLED_EXCEPTION                  0xc0000144
#define SMB_STATUS_APP_INIT_FAILURE                     0xc0000145
#define SMB_STATUS_PAGEFILE_CREATE_FAILED               0xc0000146
#define SMB_STATUS_NO_PAGEFILE                          0xc0000147
#define SMB_STATUS_INVALID_LEVEL                        0xc0000148
#define SMB_STATUS_WRONG_PASSWORD_CORE                  0xc0000149
#define SMB_STATUS_ILLEGAL_FLOAT_CONTEXT                0xc000014a
#define SMB_STATUS_PIPE_BROKEN                          0xc000014b
#define SMB_STATUS_REGISTRY_CORRUPT                     0xc000014c
#define SMB_STATUS_REGISTRY_IO_FAILED                   0xc000014d
#define SMB_STATUS_NO_EVENT_PAIR                        0xc000014e
#define SMB_STATUS_UNRECOGNIZED_VOLUME                  0xc000014f
#define SMB_STATUS_SERIAL_NO_DEVICE_INITED              0xc0000150
#define SMB_STATUS_NO_SUCH_ALIAS                        0xc0000151
#define SMB_STATUS_MEMBER_NOT_IN_ALIAS                  0xc0000152
#define SMB_STATUS_MEMBER_IN_ALIAS                      0xc0000153
#define SMB_STATUS_ALIAS_EXISTS                         0xc0000154
#define SMB_STATUS_LOGON_NOT_GRANTED                    0xc0000155
#define SMB_STATUS_TOO_MANY_SECRETS                     0xc0000156
#define SMB_STATUS_SECRET_TOO_LONG                      0xc0000157
#define SMB_STATUS_INTERNAL_DB_ERROR                    0xc0000158
#define SMB_STATUS_FULLSCREEN_MODE                      0xc0000159
#define SMB_STATUS_TOO_MANY_CONTEXT_IDS                 0xc000015a
#define SMB_STATUS_LOGON_TYPE_NOT_GRANTED               0xc000015b
#define SMB_STATUS_NOT_REGISTRY_FILE                    0xc000015c
#define SMB_STATUS_NT_CROSS_ENCRYPTION_REQUIRED         0xc000015d
#define SMB_STATUS_DOMAIN_CTRLR_CONFIG_ERROR            0xc000015e
#define SMB_STATUS_FT_MISSING_MEMBER                    0xc000015f
#define SMB_STATUS_ILL_FORMED_SERVICE_ENTRY             0xc0000160
#define SMB_STATUS_ILLEGAL_CHARACTER                    0xc0000161
#define SMB_STATUS_UNMAPPABLE_CHARACTER                 0xc0000162
#define SMB_STATUS_UNDEFINED_CHARACTER                  0xc0000163
#define SMB_STATUS_FLOPPY_VOLUME                        0xc0000164
#define SMB_STATUS_FLOPPY_ID_MARK_NOT_FOUND             0xc0000165
#define SMB_STATUS_FLOPPY_WRONG_CYLINDER                0xc0000166
#define SMB_STATUS_FLOPPY_UNKNOWN_ERROR                 0xc0000167
#define SMB_STATUS_FLOPPY_BAD_REGISTERS                 0xc0000168
#define SMB_STATUS_DISK_RECALIBRATE_FAILED              0xc0000169
#define SMB_STATUS_DISK_OPERATION_FAILED                0xc000016a
#define SMB_STATUS_DISK_RESET_FAILED                    0xc000016b
#define SMB_STATUS_SHARED_IRQ_BUSY                      0xc000016c
#define SMB_STATUS_FT_ORPHANING                         0xc000016d
#define SMB_STATUS_PARTITION_FAILURE                    0xc0000172
#define SMB_STATUS_INVALID_BLOCK_LENGTH                 0xc0000173
#define SMB_STATUS_DEVICE_NOT_PARTITIONED               0xc0000174
#define SMB_STATUS_UNABLE_TO_LOCK_MEDIA                 0xc0000175
#define SMB_STATUS_UNABLE_TO_UNLOAD_MEDIA               0xc0000176
#define SMB_STATUS_EOM_OVERFLOW                         0xc0000177
#define SMB_STATUS_NO_MEDIA                             0xc0000178
#define SMB_STATUS_NO_SUCH_MEMBER                       0xc000017a
#define SMB_STATUS_INVALID_MEMBER                       0xc000017b
#define SMB_STATUS_KEY_DELETED                          0xc000017c
#define SMB_STATUS_NO_LOG_SPACE                         0xc000017d
#define SMB_STATUS_TOO_MANY_SIDS                        0xc000017e
#define SMB_STATUS_LM_CROSS_ENCRYPTION_REQUIRED         0xc000017f
#define SMB_STATUS_KEY_HAS_CHILDREN                     0xc0000180
#define SMB_STATUS_CHILD_MUST_BE_VOLATILE               0xc0000181
#define SMB_STATUS_DEVICE_CONFIGURATION_ERROR           0xc0000182
#define SMB_STATUS_DRIVER_INTERNAL_ERROR                0xc0000183
#define SMB_STATUS_INVALID_DEVICE_STATE                 0xc0000184
#define SMB_STATUS_IO_DEVICE_ERROR                      0xc0000185
#define SMB_STATUS_DEVICE_PROTOCOL_ERROR                0xc0000186
#define SMB_STATUS_BACKUP_CONTROLLER                    0xc0000187
#define SMB_STATUS_LOG_FILE_FULL                        0xc0000188
#define SMB_STATUS_TOO_LATE                             0xc0000189
#define SMB_STATUS_NO_TRUST_LSA_SECRET                  0xc000018a
#define SMB_STATUS_NO_TRUST_SAM_ACCOUNT                 0xc000018b
#define SMB_STATUS_TRUSTED_DOMAIN_FAILURE               0xc000018c
#define SMB_STATUS_TRUSTED_RELATIONSHIP_FAILURE         0xc000018d
#define SMB_STATUS_EVENTLOG_FILE_CORRUPT                0xc000018e
#define SMB_STATUS_EVENTLOG_CANT_START                  0xc000018f
#define SMB_STATUS_TRUST_FAILURE                        0xc0000190
#define SMB_STATUS_MUTANT_LIMIT_EXCEEDED                0xc0000191
#define SMB_STATUS_NETLOGON_NOT_STARTED                 0xc0000192
#define SMB_STATUS_ACCOUNT_EXPIRED                      0xc0000193
#define SMB_STATUS_POSSIBLE_DEADLOCK                    0xc0000194
#define SMB_STATUS_NETWORK_CREDENTIAL_CONFLICT          0xc0000195
#define SMB_STATUS_REMOTE_SESSION_LIMIT                 0xc0000196
#define SMB_STATUS_EVENTLOG_FILE_CHANGED                0xc0000197
#define SMB_STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT    0xc0000198
#define SMB_STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT    0xc0000199
#define SMB_STATUS_NOLOGON_SERVER_TRUST_ACCOUNT         0xc000019a
#define SMB_STATUS_DOMAIN_TRUST_INCONSISTENT            0xc000019b
#define SMB_STATUS_FS_DRIVER_REQUIRED                   0xc000019c
#define SMB_STATUS_NO_USER_SESSION_KEY                  0xc0000202
#define SMB_STATUS_USER_SESSION_DELETED                 0xc0000203
#define SMB_STATUS_RESOURCE_LANG_NOT_FOUND              0xc0000204
#define SMB_STATUS_INSUFF_SERVER_RESOURCES              0xc0000205
#define SMB_STATUS_INVALID_BUFFER_SIZE                  0xc0000206
#define SMB_STATUS_INVALID_ADDRESS_COMPONENT            0xc0000207
#define SMB_STATUS_INVALID_ADDRESS_WILDCARD             0xc0000208
#define SMB_STATUS_TOO_MANY_ADDRESSES                   0xc0000209
#define SMB_STATUS_ADDRESS_ALREADY_EXISTS               0xc000020a
#define SMB_STATUS_ADDRESS_CLOSED                       0xc000020b
#define SMB_STATUS_CONNECTION_DISCONNECTED              0xc000020c
#define SMB_STATUS_CONNECTION_RESET                     0xc000020d
#define SMB_STATUS_TOO_MANY_NODES                       0xc000020e
#define SMB_STATUS_TRANSACTION_ABORTED                  0xc000020f
#define SMB_STATUS_TRANSACTION_TIMED_OUT                0xc0000210
#define SMB_STATUS_TRANSACTION_NO_RELEASE               0xc0000211
#define SMB_STATUS_TRANSACTION_NO_MATCH                 0xc0000212
#define SMB_STATUS_TRANSACTION_RESPONDED                0xc0000213
#define SMB_STATUS_TRANSACTION_INVALID_ID               0xc0000214
#define SMB_STATUS_TRANSACTION_INVALID_TYPE             0xc0000215
#define SMB_STATUS_NOT_SERVER_SESSION                   0xc0000216
#define SMB_STATUS_NOT_CLIENT_SESSION                   0xc0000217
#define SMB_STATUS_CANNOT_LOAD_REGISTRY_FILE            0xc0000218
#define SMB_STATUS_DEBUG_ATTACH_FAILED                  0xc0000219
#define SMB_STATUS_SYSTEM_PROCESS_TERMINATED            0xc000021a
#define SMB_STATUS_DATA_NOT_ACCEPTED                    0xc000021b
#define SMB_STATUS_NO_BROWSER_SERVERS_FOUND             0xc000021c
#define SMB_STATUS_VDM_HARD_ERROR                       0xc000021d
#define SMB_STATUS_DRIVER_CANCEL_TIMEOUT                0xc000021e
#define SMB_STATUS_REPLY_MESSAGE_MISMATCH               0xc000021f
#define SMB_STATUS_MAPPED_ALIGNMENT                     0xc0000220
#define SMB_STATUS_IMAGE_CHECKSUM_MISMATCH              0xc0000221
#define SMB_STATUS_LOST_WRITEBEHIND_DATA                0xc0000222
#define SMB_STATUS_CLIENT_SERVER_PARAMETERS_INVALID     0xc0000223
#define SMB_STATUS_PASSWORD_MUST_CHANGE                 0xc0000224
#define SMB_STATUS_NOT_FOUND                            0xc0000225
#define SMB_STATUS_NOT_TINY_STREAM                      0xc0000226
#define SMB_STATUS_RECOVERY_FAILURE                     0xc0000227
#define SMB_STATUS_STACK_OVERFLOW_READ                  0xc0000228
#define SMB_STATUS_FAIL_CHECK                           0xc0000229
#define SMB_STATUS_DUPLICATE_OBJECTID                   0xc000022a
#define SMB_STATUS_OBJECTID_EXISTS                      0xc000022b
#define SMB_STATUS_CONVERT_TO_LARGE                     0xc000022c
#define SMB_STATUS_RETRY                                0xc000022d
#define SMB_STATUS_FOUND_OUT_OF_SCOPE                   0xc000022e
#define SMB_STATUS_ALLOCATE_BUCKET                      0xc000022f
#define SMB_STATUS_PROPSET_NOT_FOUND                    0xc0000230
#define SMB_STATUS_MARSHALL_OVERFLOW                    0xc0000231
#define SMB_STATUS_INVALID_VARIANT                      0xc0000232
#define SMB_STATUS_DOMAIN_CONTROLLER_NOT_FOUND          0xc0000233
#define SMB_STATUS_ACCOUNT_LOCKED_OUT                   0xc0000234
#define SMB_STATUS_HANDLE_NOT_CLOSABLE                  0xc0000235
#define SMB_STATUS_CONNECTION_REFUSED                   0xc0000236
#define SMB_STATUS_GRACEFUL_DISCONNECT                  0xc0000237
#define SMB_STATUS_ADDRESS_ALREADY_ASSOCIATED           0xc0000238
#define SMB_STATUS_ADDRESS_NOT_ASSOCIATED               0xc0000239
#define SMB_STATUS_CONNECTION_INVALID                   0xc000023a
#define SMB_STATUS_CONNECTION_ACTIVE                    0xc000023b
#define SMB_STATUS_NETWORK_UNREACHABLE                  0xc000023c
#define SMB_STATUS_HOST_UNREACHABLE                     0xc000023d
#define SMB_STATUS_PROTOCOL_UNREACHABLE                 0xc000023e
#define SMB_STATUS_PORT_UNREACHABLE                     0xc000023f
#define SMB_STATUS_REQUEST_ABORTED                      0xc0000240
#define SMB_STATUS_CONNECTION_ABORTED                   0xc0000241
#define SMB_STATUS_BAD_COMPRESSION_BUFFER               0xc0000242
#define SMB_STATUS_USER_MAPPED_FILE                     0xc0000243
#define SMB_STATUS_AUDIT_FAILED                         0xc0000244
#define SMB_STATUS_TIMER_RESOLUTION_NOT_SET             0xc0000245
#define SMB_STATUS_CONNECTION_COUNT_LIMIT               0xc0000246
#define SMB_STATUS_LOGIN_TIME_RESTRICTION               0xc0000247
#define SMB_STATUS_LOGIN_WKSTA_RESTRICTION              0xc0000248
#define SMB_STATUS_IMAGE_MP_UP_MISMATCH                 0xc0000249
#define SMB_STATUS_INSUFFICIENT_LOGON_INFO              0xc0000250
#define SMB_STATUS_BAD_DLL_ENTRYPOINT                   0xc0000251
#define SMB_STATUS_BAD_SERVICE_ENTRYPOINT               0xc0000252
#define SMB_STATUS_LPC_REPLY_LOST                       0xc0000253
#define SMB_STATUS_IP_ADDRESS_CONFLICT1                 0xc0000254
#define SMB_STATUS_IP_ADDRESS_CONFLICT2                 0xc0000255
#define SMB_STATUS_REGISTRY_QUOTA_LIMIT                 0xc0000256
#define SMB_STATUS_PATH_NOT_COVERED                     0xc0000257
#define SMB_STATUS_NO_CALLBACK_ACTIVE                   0xc0000258
#define SMB_STATUS_LICENSE_QUOTA_EXCEEDED               0xc0000259
#define SMB_STATUS_PWD_TOO_SHORT                        0xc000025a
#define SMB_STATUS_PWD_TOO_RECENT                       0xc000025b
#define SMB_STATUS_PWD_HISTORY_CONFLICT                 0xc000025c
#define SMB_STATUS_PLUGPLAY_NO_DEVICE                   0xc000025e
#define SMB_STATUS_UNSUPPORTED_COMPRESSION              0xc000025f
#define SMB_STATUS_INVALID_HW_PROFILE                   0xc0000260
#define SMB_STATUS_INVALID_PLUGPLAY_DEVICE_PATH         0xc0000261
#define SMB_STATUS_DRIVER_ORDINAL_NOT_FOUND             0xc0000262
#define SMB_STATUS_DRIVER_ENTRYPOINT_NOT_FOUND          0xc0000263
#define SMB_STATUS_RESOURCE_NOT_OWNED                   0xc0000264
#define SMB_STATUS_TOO_MANY_LINKS                       0xc0000265
#define SMB_STATUS_QUOTA_LIST_INCONSISTENT              0xc0000266
#define SMB_STATUS_FILE_IS_OFFLINE                      0xc0000267
#define SMB_STATUS_VOLUME_DISMOUNTED                    0xC000026E
#define SMB_STATUS_NOT_A_REPARSE_POINT                  0xc0000275
#define SMB_STATUS_IO_REPARSE_TAG_NOT_HANDLED           0xc0000279
#define SMB_STATUS_NO_SUCH_JOB                          0xc0000ede

/* Custom (internal) NT statuses */
#define SMB_STATUS_DISCONNECT                           0xe0000001
#define SMB_STATUS_CUSTOM_ERROR_RESPONSE                0xe0000002
#define SMB_STATUS_INTERNAL_BUFFER_TOO_SMALL            0xe0000004

/*
    NQ Return codes
    ---------------
 */

#define NQ_ERR_MODULE   (255 << 16)     /* This module defines the NQ error subset */

/**** Errors ****/
#define NQ_ERR_OK               0  /* Success */
#define NQ_ERR_BADPARAM         (NQ_ERR_MODULE | 3)  /* Parameter error */
#define NQ_ERR_GETDATA          (NQ_ERR_MODULE | 18) /* error retrieving data */
#define NQ_ERR_INVALIDMODE      (NQ_ERR_MODULE | 19) /* Invalid open mode */
#define NQ_ERR_NOSERVERMAC      (NQ_ERR_MODULE | 20) /* Server doesn't support MAC signing */
#define NQ_ERR_SIGNATUREFAIL    (NQ_ERR_MODULE | 21) /* MAC signature in incoming packet was broken */
#define NQ_ERR_OBJEXISTS        (NQ_ERR_MODULE | 22) /* database object already exists and cannot be created */
#define NQ_ERR_MOUNTERROR       (NQ_ERR_MODULE | 23) /* mount failed for a reason other then authentication */
#define NQ_ERR_UNABLETODISPOSE  (NQ_ERR_MODULE | 24) /* unable to dispose resources */
#define NQ_ERR_INVALIDHANDLE    (NQ_ERR_MODULE | 25) /* invalid handle passed */
#define NQ_ERR_NEGOTIATEFAILED  (NQ_ERR_MODULE | 26) /* SPNEGO negotiation did not find a match */
#define NQ_ERR_PATHNOTCOVERED   (NQ_ERR_MODULE | 27) /* path should be resolved over DFS */
#define NQ_ERR_DFSCACHEOVERFLOW (NQ_ERR_MODULE | 28) /* DFS cache overflow */
#define NQ_ERR_ACCOUNTLOCKEDOUT (NQ_ERR_MODULE | 29) /* account locked out */
#define NQ_ERR_USEREXISTS       (NQ_ERR_MODULE | 30) /* acount already exists */
#define NQ_ERR_USERNOTFOUND     (NQ_ERR_MODULE | 31) /* account name not mapped */
#define NQ_ERR_NOTFOUND         (NQ_ERR_MODULE | 32) /* not found */
#define NQ_ERR_LOGONFAILURE     (NQ_ERR_MODULE | 33) /* logon failure */
#define NQ_ERR_VOLUMEDISMOUNTED (NQ_ERR_MODULE | 34) /* vlume not mounted */

#define NQ_ERR_BADFUNC          (NQ_ERR_MODULE | 1001)   /* SMB_ERRbadfunc                       1 */
#define NQ_ERR_BADFILE          (NQ_ERR_MODULE | 1002)   /* SMB_ERRbadfile                       2 */
#define NQ_ERR_BADPATH          (NQ_ERR_MODULE | 1003)   /* SMB_ERRbadpath                       3 */
#define NQ_ERR_NOFIDS           (NQ_ERR_MODULE | 1004)   /* SMB_ERRnofids                        4 */
#define NQ_ERR_NOACCESS         (NQ_ERR_MODULE | 1005)   /* SMB_ERRnoaccess                      5 */
#define NQ_ERR_BADFID           (NQ_ERR_MODULE | 1006)   /* SMB_ERRbadfid                        6 */
#define NQ_ERR_BADMCB           (NQ_ERR_MODULE | 1007)   /* SMB_ERRbadmcb                        7 */
#define NQ_ERR_NOMEM            (NQ_ERR_MODULE | 1008)   /* SMB_ERRnomem                         8 */
#define NQ_ERR_BADMEM           (NQ_ERR_MODULE | 1009)   /* SMB_ERRbadmem                        9 */
#define NQ_ERR_BADENV           (NQ_ERR_MODULE | 1010)   /* SMB_ERRbadenv                        10 */
#define NQ_ERR_BADFORMAT        (NQ_ERR_MODULE | 1011)   /* SMB_ERRbadformat                     11 */
#define NQ_ERR_BADACCESS        (NQ_ERR_MODULE | 1012)   /* SMB_ERRbadaccess                     12 */
#define NQ_ERR_BADDATA          (NQ_ERR_MODULE | 1013)   /* SMB_ERRbaddata                       13 */
#define NQ_ERR_BADDRIVE         (NQ_ERR_MODULE | 1015)   /* SMB_ERRbaddrive                      15 */
#define NQ_ERR_REMCD            (NQ_ERR_MODULE | 1016)   /* SMB_ERRremcd                         16 */
#define NQ_ERR_DIFFDEVICE       (NQ_ERR_MODULE | 1017)   /* SMB_ERRdiffdevice                    17 */
#define NQ_ERR_NOFILES          (NQ_ERR_MODULE | 1018)   /* SMB_ERRnofiles                       18 */
#define NQ_ERR_BADSHARE         (NQ_ERR_MODULE | 1032)   /* SMB_ERRbadshare                      32 */
#define NQ_ERR_LOCK             (NQ_ERR_MODULE | 1033)   /* SMB_ERRlock                          33 */
#define NQ_ERR_DONTSUPPORTIPC   (NQ_ERR_MODULE | 1066)   /* SMB_ERRdontsupportipc                66 */
#define NQ_ERR_NOSHARE          (NQ_ERR_MODULE | 1067)   /* SMB_ERRnoshare                       67 */
#define NQ_ERR_FILEXISTS        (NQ_ERR_MODULE | 1080)   /* SMB_ERRfilexists                     80 */
#define NQ_ERR_BADDIRECTORY     (NQ_ERR_MODULE | 1087)   /* SMB_ERRbaddirectory                  87 */
#define NQ_ERR_INSUFFICIENTBUFFER (NQ_ERR_MODULE | 1122) /* SMB_ERRinsufficientbuffer            122 */
#define NQ_ERR_INVALIDNAME      (NQ_ERR_MODULE | 1123)   /* SMB_ERRinvalidname                   123 */
#define NQ_ERR_DIRNOTEMPTY      (NQ_ERR_MODULE | 1145)   /* DOS_ERRdirnotempty                   145 */
#define NQ_ERR_ALREADYEXISTS    (NQ_ERR_MODULE | 1183)   /* SMB_ERRalreadyexists                 183 */
#define NQ_ERR_BADPIPE          (NQ_ERR_MODULE | 1230)   /* SMB_ERRbadpipe                       230 */
#define NQ_ERR_PIPEBUSY         (NQ_ERR_MODULE | 1231)   /* SMB_ERRpipebusy                      231 */
#define NQ_ERR_PIPECLOSING      (NQ_ERR_MODULE | 1232)   /* SMB_ERRpipeclosing                   232 */
#define NQ_ERR_NOTCONNECTED     (NQ_ERR_MODULE | 1233)   /* SMB_ERRnotconnected                  233 */
#define NQ_ERR_MOREDATA         (NQ_ERR_MODULE | 1234)   /* SMB_ERRmoredata                      234 */

#define NQ_ERR_ERROR            (NQ_ERR_MODULE | 2001)   /* SMB_ERRerror                         1 */
#define NQ_ERR_BADPW            (NQ_ERR_MODULE | 2002)   /* SMB_ERRbadpw                         2 */
#define NQ_ERR_ACCESS           (NQ_ERR_MODULE | 2004)   /* SMB_ERRaccess                        4 */
#define NQ_ERR_INVTID           (NQ_ERR_MODULE | 2005)   /* SMB_ERRinvtid                        5 */
#define NQ_ERR_INVNETNAME       (NQ_ERR_MODULE | 2006)   /* SMB_ERRinvnetname                    6 */
#define NQ_ERR_INVDEVICE        (NQ_ERR_MODULE | 2007)   /* SMB_ERRinvdevice                     7 */
#define NQ_ERR_QFULL            (NQ_ERR_MODULE | 2049)   /* SMB_ERRqfull                         49 */
#define NQ_ERR_QTOOBIG          (NQ_ERR_MODULE | 2050)   /* SMB_ERRqtoobig                       50 */
#define NQ_ERR_QEOF             (NQ_ERR_MODULE | 2051)   /* SMB_ERRqeof                          51 */
#define NQ_ERR_INVFID           (NQ_ERR_MODULE | 2052)   /* SMB_ERRinvfid                        52 */
#define NQ_ERR_SMBCMD           (NQ_ERR_MODULE | 2064)   /* SMB_ERRsmbcmd                        64 */
#define NQ_ERR_SRVERROR         (NQ_ERR_MODULE | 2065)   /* SMB_ERRsrverror                      65 */
#define NQ_ERR_FILESPECS        (NQ_ERR_MODULE | 2067)   /* SMB_ERRfilespecs                     67 */
#define NQ_ERR_BADPERMITS       (NQ_ERR_MODULE | 2069)   /* SMB_ERRbadpermits                    69 */
#define NQ_ERR_SETATTRMODE      (NQ_ERR_MODULE | 2071)   /* SMB_ERRsetattrmode                   71 */
#define NQ_ERR_PAUSED           (NQ_ERR_MODULE | 2081)   /* SMB_ERRpaused                        81 */
#define NQ_ERR_MSGOFF           (NQ_ERR_MODULE | 2082)   /* SMB_ERRmsgoff                        82 */
#define NQ_ERR_NOROOM           (NQ_ERR_MODULE | 2083)   /* SMB_ERRnoroom                        83 */
#define NQ_ERR_RMUNS            (NQ_ERR_MODULE | 2087)   /* SMB_ERRrmuns                         87 */
#define NQ_ERR_TIMEOUT          (NQ_ERR_MODULE | 2088)   /* SMB_ERRtimeout                       88 */
#define NQ_ERR_NORESOURCE       (NQ_ERR_MODULE | 2089)   /* SMB_ERRnoresource                    89 */
#define NQ_ERR_TOOMANYUIDS      (NQ_ERR_MODULE | 2090)   /* SMB_ERRtoomanyuids                   90 */
#define NQ_ERR_INVUID           (NQ_ERR_MODULE | 2091)   /* SMB_ERRinvuid                        91 */
#define NQ_ERR_USEMPX           (NQ_ERR_MODULE | 2250)   /* SMB_ERRusempx                        250 */
#define NQ_ERR_USESTD           (NQ_ERR_MODULE | 2251)   /* SMB_ERRusestd                        251 */
#define NQ_ERR_CONTMPX          (NQ_ERR_MODULE | 2252)   /* SMB_ERRcontmpx                       252 */
#define NQ_ERR_NOSUPPORT        (NQ_ERR_MODULE | 2999)   /* SMB_ERRnosupport                     65535 */

#define NQ_ERR_NOWRITE          (NQ_ERR_MODULE | 3019)   /* SMB_ERRnowrite                       19 */
#define NQ_ERR_BADUNIT          (NQ_ERR_MODULE | 3020)   /* SMB_ERRbadunit                       20 */
#define NQ_ERR_NOTREADY         (NQ_ERR_MODULE | 3021)   /* SMB_ERRnotready                      21 */
#define NQ_ERR_BADCMD           (NQ_ERR_MODULE | 3022)   /* SMB_ERRbadcmd                        22 */
#define NQ_ERR_DATA             (NQ_ERR_MODULE | 3023)   /* SMB_ERRdata                          23 */
#define NQ_ERR_BADREQ           (NQ_ERR_MODULE | 3024)   /* SMB_ERRbadreq                        24 */
#define NQ_ERR_SEEK             (NQ_ERR_MODULE | 3025)   /* SMB_ERRseek                          25 */
#define NQ_ERR_BADMEDIA         (NQ_ERR_MODULE | 3026)   /* SMB_ERRbadmedia                      26 */
#define NQ_ERR_BADSECTOR        (NQ_ERR_MODULE | 3027)   /* SMB_ERRbadsector                     27 */
#define NQ_ERR_NOPAPER          (NQ_ERR_MODULE | 3028)   /* SMB_ERRnopaper                       28 */
#define NQ_ERR_WRITE            (NQ_ERR_MODULE | 3029)   /* SMB_ERRwrite                         29 */
#define NQ_ERR_READ             (NQ_ERR_MODULE | 3030)   /* SMB_ERRread                          30 */
#define NQ_ERR_GENERAL          (NQ_ERR_MODULE | 3031)   /* SMB_ERRgeneral                       31 */
#define NQ_ERR_WRONGDISK        (NQ_ERR_MODULE | 3034)   /* SMB_ERRwrongdisk                     34 */
#define NQ_ERR_FCBUNAVAIL       (NQ_ERR_MODULE | 3035)   /* SMB_ERRFCBUnavail                    35 */
#define NQ_ERR_SHAREBUFEXC      (NQ_ERR_MODULE | 3036)   /* SMB_ERRsharebufexc                   36 */
#define NQ_ERR_DISKFULL         (NQ_ERR_MODULE | 3039)   /* SMB_ERRdiskfull                      39 */

/* TCP and NetBIOS layer error codes */
#define NQ_ERR_NBILLEGALSOCKETSLOT          (NQ_ERR_MODULE | 4000)  /* Internal error */
#define NQ_ERR_NBNOTNETBIOSNAME             (NQ_ERR_MODULE | 4001)  /* NetBIOS name has illegal format */
#define NQ_ERR_NBTIMEOUT                    (NQ_ERR_MODULE | 4002)  /* Select timeout on NBT/TCP layer */
#define NQ_ERR_NBNEGATIVERESPONSE           (NQ_ERR_MODULE | 4003)  /* Negative NetBIOS response received */
#define NQ_ERR_NBHOSTNAMENOTRESOLVED        (NQ_ERR_MODULE | 4004)  /* NQ failed to reslve host over NetBIOS */
#define NQ_ERR_NBCANCELLISTENFAIL           (NQ_ERR_MODULE | 4005)  /* Unable to cancel a listen opertaion */
#define NQ_ERR_NBSOCKETOVERFLOW             (NQ_ERR_MODULE | 4006)  /* Too many sockets in use */
#define NQ_ERR_NBNOBINDBEFORELISTEN         (NQ_ERR_MODULE | 4007)  /* Listen attempt on a socket that was not bound yet */
#define NQ_ERR_NBILLEGALDATAGRAMSOURCE      (NQ_ERR_MODULE | 4008)  /* Source name has illegal format */
#define NQ_ERR_NBILLEGALDATAGRAMDESTINATION (NQ_ERR_MODULE | 4009)  /* Destination name has illegal format */
#define NQ_ERR_NBINVALIDPARAMETER           (NQ_ERR_MODULE | 4010)  /* Invalid parameter */
#define NQ_ERR_NBINTERNALERROR              (NQ_ERR_MODULE | 4011)  /* Internal error */
#define NQ_ERR_NBILLEGALDATAGRAMTYPE        (NQ_ERR_MODULE | 4012)  /* Unexpected datagram type */
#define NQ_ERR_NBDDCOMMUNICATIONERROR       (NQ_ERR_MODULE | 4013)  /* NQ failed to communicate with NetbIOS daemon */
#define NQ_ERR_NBBUFFEROVERFLOW             (NQ_ERR_MODULE | 4014)  /* Internal buffer size exceeded */
#define NQ_ERR_NBRELEASENAMEFAIL            (NQ_ERR_MODULE | 4015)  /* NQ failed to release a registered name */


#define NQ_ERR_RECONNECTREQUIRED (0xfffffffe)           /* Error used when send fails and reconnect is required */

#define NQ_ERR_SIZEERROR       (0xffffffff) /* Error requesting file size */
#define NQ_ERR_SEEKERROR       (0xffffffff) /* Invalid seek result */
#define NQ_ERR_ATTRERROR       (0xffffffff) /* Error requesting file attributes */

/* Password Length*/

#define UD_NQ_MAXPWDLEN  100    /*password buffer length*/


/* udGetPassword() return codes */

#define NQ_CS_PWDFOUND  0       /* password was found for the user, the same as 3 */
#define NQ_CS_PWDNOAUTH 1       /* authentication is not required */
#define NQ_CS_PWDNOUSER 2       /* no such user */
#define NQ_CS_PWDLMHASH 3       /* password found for the user and it is LM hash */
#define NQ_CS_PWDANY    4       /* password found for the user and its encryption is reported */

/* initialize UD module */

NQ_STATUS                 /* NQ_SUCCESS or NQ_FAIL */
udInit(
    void
    );

/* stop UD module */

void
udStop(
    void
    );

/* signal to the user level of NQ Server readiness */

void
udCifsServerStarted(
    void
    );

/* signal to the user level of NQ Server shutdown */

void
udCifsServerClosed(
    void
    );

/* signal to the user level of NetBIOS Daemon readiness */

void
udNetBiosDaemonStarted(
    void
    );

/* signal to the user level of NetBIOS Daemon shutdown */

void
udNetBiosDaemonClosed(
    void
    );

/* signal to the user level of Browser Daemon readiness */

void
udBrowserDaemonStarted(
    void
    );

/* signal to the user level of Browser Daemon shutdown */

void
udBrowserDaemonClosed(
    void
    );

/* get the system's Scope ID */

void
udGetScopeID(
    NQ_TCHAR* buffer            /* buffer for the result */
    );

/* get wins address information */

NQ_IPADDRESS4                   /* wins address in NBO or 0 */
udGetWins(
    void
    );

/* get domain name */

void
udGetDomain(
    NQ_TCHAR *buffer,           /* buffer for the result */
    NQ_BOOL *isWorkgroup        /* 0 - false, 1 - true */
    );

#if defined(UD_NQ_USETRANSPORTIPV4) || defined(UD_NQ_USETRANSPORTIPV6)
/* get DNS initialization parameters */

void
udGetDnsParams(
    NQ_TCHAR *domain,           /* The default domain target belongs to */
    NQ_TCHAR *server            /* The DNS server IP address */
    );
#endif /* defined(UD_NQ_USETRANSPORTIPV4) || defined(UD_NQ_USETRANSPORTIPV6) */

/* get authentication parameters for CC */

NQ_BOOL            /* TRUE - got credentials, FALSE - failed */
udGetCredentials(
    const void* resource,   /* URI about to connect to */
    NQ_TCHAR* userName,             /* buffer for user name */
    NQ_TCHAR* password,             /* buffer for password */
    NQ_TCHAR* domain                /* buffer for domain name */
    );

/* determine fielsystem for the given share */

void
udGetFileSystemName(
    const NQ_TCHAR* shareName,  /* pointer to the share name */
    const NQ_TCHAR* sharePath,  /* pointer to the share path */
    NQ_TCHAR* fileSystemName    /* buffer for the filesystem name */
    );

/* get next share in the list of shares for CS */

NQ_BOOL                  /* TRUE - a share read FALSE - no more shares */
udGetNextShare(
    NQ_TCHAR* name,         /* buffer for share name */
    NQ_TCHAR* map,          /* buffer for the map path */
    NQ_INT* printQueue,    /* 0 for file system, 1 for print queue */
    NQ_TCHAR* description   /* buffer for the share description */
    );

/* get next mount in the list of mounted volumes for CC */

NQ_BOOL                 /* TRUE more valumes in the list, FALSE when no more volumes available */
udGetNextMount(
    NQ_TCHAR* name,     /* buffer for volume name */
    NQ_TCHAR* map       /* buffer for the map path */
    );

/* check password for a specific user */

NQ_INT              /* See values above */
udGetPassword(
    const NQ_TCHAR* userName,   /* user name */
    NQ_CHAR* password,          /* buffer for password */
    NQ_INT* pwdIsHashed,        /* TRUE - paasword hashed, FALSE - plain text */
    NQ_UINT32* userNumber       /* >1000 for administrators */
    );

/* reads last system error and tries to convert it to an SMB error */

NQ_UINT32              /* SMB error or 0 to use the default conversion */
udGetSmbError(
    NQ_UINT32 sysErr   /* system error code to convert */
    );

/* converts NQ error into OS error code */

NQ_UINT32              /* system error or 0 (then the system-dependent conversion will be
                       taken) */
udNqToSystemError(
    NQ_UINT32 nqErr     /* NQ error code */
    );

/* query user-defined security descriptor */

NQ_INT                      /* returns descriptor length */
udGetSecurityDescriptor(
    NQ_INT file,            /* ID of an opened file */
    NQ_UINT32 information,  /* descriptor to get */
    void* buffer            /* output buffer */
    );

/* write user-defined security descriptor */

NQ_STATUS                   /* NQ_SUCCESS or erro code */
udSetSecurityDescriptor(
    NQ_INT file,            /* ID of an opened file */
    NQ_UINT32 information,  /* descriptor to set */
    const void* buffer,     /* input buffer */
    NQ_UINT32 len           /* descriptor length */
    );

/* get transport priority */

NQ_INT                      /* 0 - the transport isn't used */
                            /* 1..3 - the bigger number is highest priority */
                            /* if more then one transport has same priority */
                            /* built in order is used: IPv6, IPv4, NetBIOS */
udGetTransportPriority(
    NQ_UINT transport
    );

/* get task priorities */

NQ_INT
udGetTaskPriorities(
    void
    );

/* get server comment string */

void
udGetServerComment(
    NQ_TCHAR *buffer            /* buffer for the result */
    );

/* get CIFS driver name */

void
udGetDriverName(
    NQ_CHAR* buffer        /* buffer for the result */
    );

/* project-level processing on incoming data to NetBios Daemon */

void
udNetBiosDataIn(
    void
    );

/* project-level processing on incoming data to NQ Server */

void
udServerDataIn(
    void
    );

/* project-level processing on client connection to a share */

void
udServerShareConnect(
    const NQ_TCHAR* share           /* share name */
    );

/* project-level processing on client disconnect from a share */

void
udServerShareDisconnect(
    const NQ_TCHAR* share           /* share name */
    );

/* allocate buffer in the user space */

NQ_BYTE*
udAllocateBuffer(
    NQ_INT idx,         /* buffer index zero based */
    NQ_COUNT numBufs,   /* total number of buffers to be allocated */
    NQ_UINT bufferSize  /* buffer size in bytes */
    );

/* release buffer in the user space */

void
udReleaseBuffer(
    NQ_INT idx,         /* buffer index zero based */
    NQ_COUNT numBufs,   /* total number of buffers to be released */
    NQ_BYTE* buffAddr,  /* buffer address */
    NQ_UINT bufferSize  /* buffer size in bytes */
    );

#ifdef UD_NQ_INCLUDECODEPAGE

/* get current code page number */

NQ_INT
udGetCodePage(
    void
    );

#endif /* UD_NQ_INCLUDECODEPAGE */

/* redefine port number */

NQ_PORT                     /* port number to use in HBO */
udGetPort(
    NQ_PORT port            /* default port number in HBO */
    );

#if defined(UD_CS_INCLUDESECURITYDESCRIPTORS) || defined(UD_CC_INCLUDESECURITYDESCRIPTORS) || defined (UD_CC_INCLUDEDOMAINMEMBERSHIP) || defined(UD_CS_INCLUDEPASSTHROUGH)

/* get unique ID for the current machine */

void
udGetComputerId(
    NQ_BYTE* buf        /* 12 - byte buffer to be filled with unique value */
    );

/* Get persistent security descriptor for share */

NQ_COUNT                        /* SD length or zero on error */
udLoadShareSecurityDescriptor(
    const NQ_TCHAR* shareName,  /* share name */
    NQ_BYTE* buffer,            /* buffer to read SD in */
    NQ_COUNT bufferLen          /* buffer length */
    );

/* Save persistent security descriptor for share */

void
udSaveShareSecurityDescriptor(
    const NQ_TCHAR* shareName,  /* share name */
    const NQ_BYTE* sd,          /* pointer to SD */
    NQ_COUNT sdLen              /* SD length */
    );

#ifdef UD_CS_INCLUDELOCALUSERMANAGEMENT

/* get number of local users */

NQ_COUNT                    /* number of local users */
udGetUserCount(
    void
    );

/* get user ID by name */

NQ_BOOL                     /* TRUE when user was found */
udGetUserRidByName(
    const NQ_TCHAR* name,   /* user name */
    NQ_UINT32* rid          /* buffer for user ID */
    );

/* get user name by ID */

NQ_BOOL                     /* TRUE when user was found */
udGetUserNameByRid(
    NQ_UINT32 rid,              /* user id */
    NQ_TCHAR* nameBuffer,       /* buffer for user name */
    NQ_TCHAR* fullNameBuffer    /* buffer for full name */
    );

/* enumerate users */

NQ_BOOL                     /* TRUE when user was available */
udGetUserInfo(
    NQ_UINT index,          /* user index (zero based) */
    NQ_UINT32* rid,         /* user id */
    NQ_TCHAR* name,         /* buffer for user name */
    NQ_TCHAR* fullName,     /* buffer for full user name */
    NQ_TCHAR* description   /* buffer for user description */
    );

/* set user administrative rights */

NQ_BOOL                     /* TRUE when opration succeeded */
udSetUserAsAdministrator(
    NQ_UINT32 rid,          /* user RID */
    NQ_BOOL isAdmin         /* TRUE to set user as administrator */
    );

/* modify user */

NQ_BOOL                     /* TRUE when user was added/modified */
udSetUserInfo(
    NQ_UINT32 rid,                  /* user RID */
    const NQ_TCHAR* name,           /* user name */
    const NQ_TCHAR* fullName,       /* full user name */
    const NQ_TCHAR* description,    /* user description */
    const NQ_WCHAR* password        /* Unicode text password or NULL */
    );

/* add user */

NQ_BOOL                     /* TRUE when user was added/modified */
udCreateUser(
    const NQ_TCHAR* name,           /* user name */
    const NQ_TCHAR* fullName,       /* full user name */
    const NQ_TCHAR* description     /* user description */
    );

/* remove user */

NQ_BOOL                     /* TRUE when user was deleted */
udDeleteUserByRid(
    NQ_UINT32 rid           /* user RID */
    );

#endif /* UD_CS_INCLUDELOCALUSERMANAGEMENT */

#endif /* defined(UD_CS_INCLUDESECURITYDESCRIPTORS) || defined(UD_CC_INCLUDESECURITYDESCRIPTORS) || defined (UD_CC_INCLUDEDOMAINMEMBERSHIP) || defined(UD_CS_INCLUDEPASSTHROUGH)*/

#ifdef UD_CS_INCLUDERPC_SRVSVC_EXTENSION

/* modify/create share information in a persistent store */

NQ_BOOL
udSaveShareInformation(
    const NQ_TCHAR* name,           /* share to modify or NULL for a new share */
    const NQ_TCHAR* newName,        /* new share name */
    const NQ_TCHAR* newMap,         /* new share path */
    const NQ_TCHAR* newDescription  /* new share description */
    );

/* remove share from the persistent store */

NQ_BOOL
udRemoveShare(
    const NQ_TCHAR* name            /* share to remove */
    );

#endif /* UD_CS_INCLUDERPC_SRVSVC_EXTENSION */

#ifdef UD_NQ_INCLUDEEVENTLOG

/*
    Event log constants
    -------------------
 */

/* event triggering module */
#define UD_LOG_MODULE_CS        1   /* Designates NQ CIFS Server as the event origin */
#define UD_LOG_MODULE_CC        2   /* Designates NQ CIFS Client as the event origin */
/* event class for server */
#define UD_LOG_CLASS_GEN        1   /* Event class for start and stop events */
#define UD_LOG_CLASS_FILE       2   /* Event class for file/directory access events */
#define UD_LOG_CLASS_SHARE      3   /* Event class for share connect/disconnect events */
#define UD_LOG_CLASS_USER       4   /* Event class for user */
#define UD_LOG_CLASS_CONNECTION 5   /* Event class for connections */

/* start/stop evemts */
#define UD_LOG_GEN_START        1   /* Start event type */
#define UD_LOG_GEN_STOP         2   /* Stop event type */

#define UD_LOG_GEN_NAMECONFLICT 3 	/* Name Conflict has occured*/

/* file access events */
#define UD_LOG_FILE_CREATE      1   /* File/directory create event type */
#define UD_LOG_FILE_OPEN        2   /* File/directory open event type */
#define UD_LOG_FILE_CLOSE       3   /* File/directory close event type */
#define UD_LOG_FILE_DELETE      4   /* File/directory delete event type */
#define UD_LOG_FILE_RENAME      5   /* File/directory rename event type */
#define UD_LOG_FILE_ATTRIBGET   6   /* File/directory query attributes event type */
#define UD_LOG_FILE_ATTRIBSET	7	/* File/directory change attributes event type */
#define	UD_LOG_FILE_SIZESET		8	/* File turncate/extend event type */
#define UD_LOG_FILE_VOLUMEINFO	9   /* Volume information query event type*/
#define UD_LOG_FILE_QUERYDIRECTORY 10 /* folder enumeration event type*/
#define UD_LOG_FILE_SEEK		11  /* File position change event type*/
#define UD_LOG_FILE_LOCK		12	/* File range lock event type */
#define UD_LOG_FILE_UNLOCK		13  /* File range unlock event type*/

/* share access events */
#define UD_LOG_SHARE_CONNECT    1   /* Share connection event type */
#define UD_LOG_SHARE_DISCONNECT 2   /* Share disconnection event type */
/* user access events*/
#define UD_LOG_USER_LOGON       1   /* User connection event type */
#define UD_LOG_USER_LOGOFF  2   /* User disconnection event type */
/* connection access events */
#define UD_LOG_CONNECTION_CONNECT 1 /* New connection connected [SYN]*/
#define UD_LOG_CONNECTION_DISCONNECT 2  /* disconnected connection [FIN]*/


/*
    Event log structures
    -------------------
 */

/* Data structure for an event from File/Directory Access class.
   Depending on the event type, some members of this structure may be undefined */

typedef struct {
    const NQ_TCHAR* fileName;   /* file to access */
    const NQ_TCHAR* newName;    /* new file name for rename operation */
    NQ_UINT32 access;           /* this value is has different meaning for different events:
                                   for UD_LOG_FILE_CREATE, UD_LOG_FILE_DELETE and UD_LOG_FILE_RENAME - no meaning.
                                   for UD_LOG_FILE_OPEN and UD_LOG_FILE_CLOSE:
                                    0x0 - read
                                    0x1 - write
                                    0x2 - read/write
                                    0x3 - execute
                                    0x8000 - delete
                                    0xF - all
                                   for UD_LOG_FILE_ATTRIB:
                                    0x1 - readonly
                                    0x2 - hidden
                                    0x4 - system
                                    0x8 - volume
                                    0x10 - directory
                                    0x20  - archive
                                    0x80 - normal
                                 */
    NQ_BOOL   before;
    NQ_UINT32 rid;              /* Unique user ID */
    NQ_UINT32 tid;				/* Unique tree ID */
    NQ_UINT32 sizeLow;			/* First 32 bits of file size or range size*/
    NQ_UINT32 sizeHigh;			/* Last 32 bits of file size or range size*/
    NQ_UINT32 offsetLow;		/* First 32 bits of a position in file*/
    NQ_UINT32 offsetHigh;		/* Last 32 bits of a position in file*/
    NQ_UINT32 infoLevel;		/* Information lever for query and set info*/
}
UDFileAccessEvent;

/* Data structure for an event from Share Access class.
   Depending on the event type, some members of this structure may be undefined */

typedef struct {
    const NQ_TCHAR* shareName;      /* name of the share being accessed */
    NQ_BOOL 		ipc;          	/* TRUE for IPC$ share */
    NQ_BOOL 		printQueue;    	/* TRUE for a printer queue share */
    NQ_UINT32  		rid;           	/* Unique user ID */
    NQ_UINT32 		tid;			/* Unique tree ID */
}
UDShareAccessEvent;

typedef struct{
    NQ_UINT32         rid;          /* Unique user ID */
}
UDUserAccessEvent;

/*
    Event log functions
    -------------------
 */

void
udEventLog (
    NQ_UINT module,                 /* NQ module that originated this event */
    NQ_UINT class,                  /* event class */
    NQ_UINT type,                   /* event type */
    const NQ_TCHAR* userName,       /* name of the user */
    const NQ_IPADDRESS* pIp,        /* next side IP address */
    NQ_UINT32 status,               /* zero if the operation has succeeded or error code on failure
                                       for server event this code is the same that will be transmitted
                                       to the client
                                       for an NQ CIFS client event this value is the same
                                       that will be installed as system error */
    const NQ_BYTE* parameters       /* pointer to a structure that is filled with event data
                                       actual structure depends on event type */
    );

#endif /* UD_NQ_INCLUDEEVENTLOG */

void
udNetBiosError(
    NQ_STATUS cause,                /* error code */
    const NQ_CHAR* name             /* NetBIOS name that caused that error */
    );

#ifdef UD_CS_INCLUDEDOMAINMEMBERSHIP

NQ_BOOL
udGetComputerSecret(
    NQ_BYTE **secret
    );

void
udSetComputerSecret(
    NQ_BYTE *secret
    );

#endif /* UD_CS_INCLUDEDOMAINMEMBERSHIP */


#endif /* _UDAPI_H_ */


