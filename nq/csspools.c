/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : SRVSVC pipe
 *--------------------------------------------------------------------
 * MODULE        : CS - CIFS Server
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 23-October-2004
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

/* This source implements spooling capabilities by means of RPC
 * calls - SPOOLSS.
 *
 * SPOOLSS specification virtually does not exist in an open source .
 * What we have is a mixture of Microsoft API specs, various folklore, guesses,
 * rumors, etc. Nobody in the outer world seems to know how it works.
 * Anyway, logic does not work here as well.
 * As such, SPOOLSS implementation is very sensitive to a modifications
 * that may affect more then just one spot in the code. Therefore,
 * we designate here new ideas rather then immediately placing them into
 * the code. Instead we try them carefully before applying to the entire source.
 *
 * ++++
 *  Idea:   use CM_RP_UNKNOWNLEVEL instead of CM_RP_FAULTUNSUPPORTED
 *          when we do not support required information level
 *  In:     spoolssGetPrinterDriver2()
 *  To do:  replace all other occurrences
 * ++++
*/

#include "csspools.h"

#include "csdataba.h"
#include "csdcerpc.h"

#ifdef UD_NQ_INCLUDECIFSSERVER

#ifdef UD_CS_INCLUDERPC_SPOOLSS

#ifndef UD_CS_INCLUDERPC
#error illegal combination of parametsrs UD_CS_INCLUDERPC_SPOOLSS (defined) and UD_CS_INCLUDERPC (not defined)
#endif

/*
    Static data and definitions
    ---------------------------
 */

/*
 * Entries for open operations.
 *  an entry is allocated on spoolssOpenPrinterEx command and is released
 *  on spoolssClosePrinter command. Entry table is initialized on initData()
 */
typedef struct                  /* descriptor of an open printer */
{
    NQ_BOOL isFree;             /* TRUE when this entry is free */
    SYPrinterHandle handle;     /* printer handle */
    CSShare* pShare;            /* share pointer or NULL */
    NQ_UINT32 jobId;            /* job ID */
    const NQ_BYTE* user;        /* owner */
    NQ_BOOL isIpAsServerName;   /* whether IP is used instead of server name */
    NQ_CHAR ipServer[0x40];     /* buffer for IP (enough space for ipv6) */
} OpenEntry;

typedef struct
{
    OpenEntry openEntries[UD_CS_SPOOLSS_MAXOPENPRINTERS];   /* entry table */
    NQ_CHAR txtBuffer[CM_BUFFERLENGTH(NQ_CHAR, UD_FS_FILENAMELEN)];
    NQ_WCHAR txtBufferW[CM_BUFFERLENGTH(NQ_WCHAR, UD_FS_FILENAMELEN)];
    NQ_WCHAR fullNameW[CM_BUFFERLENGTH(NQ_WCHAR, UD_FS_FILENAMELEN)];
    NQ_WCHAR fileNameW[CM_BUFFERLENGTH(NQ_WCHAR, UD_FS_FILENAMELEN)];
    NQ_UINT32 fakePrinterHandle; /* to have different handles for subseq. openings */
    CMSdSecurityDescriptor sd;   /* temporary security descriptor */
    SYPrinterInfo printInfo;     /* printer information structure */
    SYPrintFormInfo formInfo;    /* printer information structure */
    SYPrintJobInfo jobInfo;      /* job information structure */
    NQ_UINT32 changeId;
}
StaticData;

#ifdef SY_FORCEALLOCATION
static StaticData* staticData = NULL;
#else  /* SY_FORCEALLOCATION */
static StaticData staticDataSrc;
static StaticData* staticData = &staticDataSrc;
#endif /* SY_FORCEALLOCATION */

static NQ_STATUS    /* initialialization of the open entry table */
initData(
    void
    );

static void         /* release open entry table */
stopData(
    void
    );

/* various specific data */

#define NOSHARE 0xFFFF              /* share index when the entire server was requested */

/* packet sizes - maximum packet sizes not including strings */

#define ENUMPRINTERS_ENTRYSIZE      84
#define ENUMDRIVERS_ENTRYSIZE       100
#define ENUMPRINTERS_DEVMODESIZE    220

/* Printer status mask that cannot be modified over SMB */

#define PRINTERSTATUS_INTERNALYSAVED    (SY_PRINTERSTATUS_PRINTING)

/* access flags for OpenPrinterEx */

#define ACCESS_MAXIMUM      0x02000000
#define ACCESS_SYNCHRONIZE  0x00100000
#define ACCESS_WRITEOWNER   0x00080000
#define ACCESS_WRITEDAC     0x00040000
#define ACCESS_READCONTROL  0x00020000
#define ACCESS_DELETE       0x00010000
#define ACCESS_PRINTERUSE   0x00000008
#define ACCESS_PRINTERADMIN 0x00000004
#define ACCESS_SERVERENUM   0x00000002
#define ACCESS_SERVERADMIN  0x00000001

#define ACCESS_ALLOWED (ACCESS_MAXIMUM | ACCESS_READCONTROL | ACCESS_PRINTERUSE | ACCESS_PRINTERADMIN | ACCESS_SERVERENUM | ACCESS_SERVERADMIN)

/*
    GetPrinterData functions, data, structures and definitions
    ----------------------------------------------------------
 */

/* data types */

#define TYPE_NONE                    0  /* No value type */
#define TYPE_SZ                      1  /* Unicode nul terminated string */
#define TYPE_BINARY                  3  /* Free form binary */
#define TYPE_DWORD                   4  /* 32-bit number */

/* data values */

/*static const NQ_BYTE architectureValue[] = {'N', 0, 'Q', 0, 0, 0};*/
static const NQ_BYTE architectureValue[] = {'W',0,'i',0,'n',0,'d',0,'o',0,'w',0,'s',0,' ',0,'N',0,'T',0,' ',0,'x',0,'8',0,'6',0,0,0};
static const NQ_UINT32 majorVersionValue = 2;

/* data retrieval functions */

static NQ_UINT32
getChangeId(
    CMRpcPacketDescriptor* out
    )
{
    cmRpcPackUint32(out, staticData->changeId);
    return 4;
}

typedef struct
{
    const NQ_CHAR* name;  /* data name */
    NQ_BOOL server;       /* when TRUE this is server data */
    NQ_UINT32 type;       /* data type */
    const NQ_BYTE* data;  /* pointer to data value or NULL */
    NQ_UINT32 size;       /* data size */
    NQ_UINT32 (*function)(CMRpcPacketDescriptor*); /* data retrieval function or NULL */
} PrinterData;

static const PrinterData printerData[] =
{
 { "ChangeId", FALSE, TYPE_DWORD, NULL, 0, getChangeId },
 { "Architecture", TRUE, TYPE_SZ, (NQ_BYTE*)architectureValue, sizeof(architectureValue), NULL },
 { "MajorVersion", TRUE, TYPE_DWORD, (NQ_BYTE*)&majorVersionValue, sizeof(majorVersionValue), NULL },
};

/* error codes */

#define ERROR_PRINTCANCELLED  0x0000003F

/* pipe function prototypes */

static NQ_UINT32 spoolssEnumPrinters(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
/* static NQ_UINT32 spoolssOpenPrinter(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
static NQ_UINT32 spoolssSetJob(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
static NQ_UINT32 spoolssGetJob(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
static NQ_UINT32 spoolssEnumJobs(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
/* static NQ_UINT32 spoolssAddPrinter(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 spoolssDeletePrinter(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
static NQ_UINT32 spoolssSetPrinter(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
static NQ_UINT32 spoolssGetPrinter(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
/* static NQ_UINT32 spoolssAddPrinterDriver(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 spoolssEnumPrinterDrivers(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 spoolssGetPrinterDriver(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 spoolssGetPrinterDriverDirectory(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 spoolssDeletePrinterDriver(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 spoolssAddPrintProcessor(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 spoolssEnumPrintProcessors(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 spoolssGetPrintProcessorDirectory(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
static NQ_UINT32 spoolssStartDocPrinter(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
static NQ_UINT32 spoolssStartPagePrinter(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
static NQ_UINT32 spoolssWritePrinter(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
static NQ_UINT32 spoolssEndPagePrinter(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
static NQ_UINT32 spoolssAbortPrinter(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
/* static NQ_UINT32 spoolssReadPrinter(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
static NQ_UINT32 spoolssEndDocPrinter(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
static NQ_UINT32 spoolssAddJob(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); 
/* static NQ_UINT32 spoolssScheduleJob(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
static NQ_UINT32 spoolssGetPrinterData(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
static NQ_UINT32 spoolssSetPrinterData(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
/* static NQ_UINT32 spoolssWaitForPrinterChange(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
static NQ_UINT32 spoolssClosePrinter(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
/* static NQ_UINT32 spoolssAddForm(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 spoolssDeleteForm(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
static NQ_UINT32 spoolssGetForm(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
/* static NQ_UINT32 spoolssSetForm(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
static NQ_UINT32 spoolssEnumForms(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
/* static NQ_UINT32 spoolssEnumPorts(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 spoolssEnumMonitors(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 spoolssAddPort(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 spoolssConfigurePort(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 spoolssDeletePort(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 spoolssCreatePrinterIC(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 spoolssPlayGDIScriptOnPrinterIC(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 spoolssDeletePrinterIC(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 spoolssAddPrinterConnection(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 spoolssDeletePrinterConnection(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 spoolssPrinterMessageBox(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 spoolssAddMonitor(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 spoolssDeleteMonitor(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 spoolssDeletePrintProcessor(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 spoolssAddPrintProvidor(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 spoolssDeletePrintProvidor(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 spoolssEnumPrintProcDataTypes(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
static NQ_UINT32 spoolssResetPrinter(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
static NQ_UINT32 spoolssGetPrinterDriver2(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
/* static NQ_UINT32 spoolssFindFirstPrinterChangeNotification(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 spoolssFindNextPrinterChangeNotification(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
static NQ_UINT32 spoolssFindClosePrinterNotify(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); 
/* static NQ_UINT32 spoolssRouterFindFirstPrinterChangeNotificationOld(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 spoolssReplyOpenPrinter(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 spoolssRouterReplyPrinter(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 spoolssReplyClosePrinter(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 spoolssAddPortEx(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 spoolssRouterFindFirstPrinterChangeNotification(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 spoolssSpoolerInit(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 spoolssResetPrinterEx(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
static NQ_UINT32 spoolssRemoteFindFirstPrinterChangeNotifyEx(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
/* static NQ_UINT32 spoolssRouterRefreshPrinterChangeNotification(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
static NQ_UINT32 spoolssRemoteFindNextPrinterChangeNotifyEx(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
/* static NQ_UINT32 spoolss44(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
static NQ_UINT32 spoolssOpenPrinterEx(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
/* static NQ_UINT32 spoolssAddPrinterEx(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 spoolss47(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 spoolssEnumPrinterData(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 spoolssDeletePrinterData(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 spoolss4a(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 spoolss4b(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 spoolss4c(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 spoolssSetPrinterDataEx(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 spoolssGetPrinterDataEx(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 spoolssEnumPrinterDataEx(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 spoolssEnumPrinterKey(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 spoolssDeletePrinterDataEx(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 spoolssDeletePrinterKey(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 spoolss53(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 spoolssDeletePrinterDriverEx(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 spoolss55(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 spoolss56(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 spoolss57(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 spoolss58(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 spoolssAddPrinterDriverEx(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 spoolss5a(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 spoolss5b(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 spoolss5c(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 spoolss5d(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 spoolss5e(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 spoolss5f(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */

static const CSRpcFunctionDescriptor functions[] =
{
    { spoolssEnumPrinters                                           /* 0x00 */ },
    { NULL /* spoolssOpenPrinter */                                 /* 0x01 */ },
    { spoolssSetJob                                                 /* 0x02 */ },
    { spoolssGetJob                                                 /* 0x03 */ },
    { spoolssEnumJobs                                               /* 0x04 */ },
    { NULL /* spoolssAddPrinter */                                  /* 0x05 */ },
    { NULL /* spoolssDeletePrinter */                               /* 0x06 */ },
    { spoolssSetPrinter                                             /* 0x07 */ },
    { spoolssGetPrinter                                             /* 0x08 */ },
    { NULL /* spoolssAddPrinterDriver */                            /* 0x09 */ },
    { NULL /* spoolssEnumPrinterDrivers */                          /* 0x0a */ },
    { NULL /* spoolssGetPrinterDriver */                            /* 0x0b */ },
    { NULL /* spoolssGetPrinterDriverDirectory */                   /* 0x0c */ },
    { NULL /* spoolssDeletePrinterDriver */                         /* 0x0d */ },
    { NULL /* spoolssAddPrintProcessor */                           /* 0x0e */ },
    { NULL /* spoolssEnumPrintProcessors */                         /* 0x0f */ },
    { NULL /* spoolssGetPrintProcessorDirectory */                  /* 0x10 */ },
    { spoolssStartDocPrinter                                        /* 0x11 */ },
    { spoolssStartPagePrinter                                       /* 0x12 */ },
    { spoolssWritePrinter                                           /* 0x13 */ },
    { spoolssEndPagePrinter                                         /* 0x14 */ },
    { spoolssAbortPrinter                                           /* 0x15 */ },
    { NULL /* spoolssReadPrinter */                                 /* 0x16 */ },
    { spoolssEndDocPrinter                                          /* 0x17 */ },
    { spoolssAddJob                                                 /* 0x18 */ },
    { NULL /* spoolssScheduleJob */                                 /* 0x19 */ },
    { spoolssGetPrinterData                                         /* 0x1a */ },
    { spoolssSetPrinterData                                         /* 0x1b */ },
    { NULL /* spoolssWaitForPrinterChange */                        /* 0x1c */ },
    { spoolssClosePrinter                                           /* 0x1d */ },
    { NULL /* spoolssAddForm */                                     /* 0x1e */ },
    { NULL /* spoolssDeleteForm */                                  /* 0x1f */ },
    { spoolssGetForm                                     /* 0x20 */ },
    { NULL /* spoolssSetForm */                                     /* 0x21 */ },
    { spoolssEnumForms                                   /* 0x22 */ },
    { NULL /* spoolssEnumPorts */                                   /* 0x23 */ },
    { NULL /* spoolssEnumMonitors */                                /* 0x24 */ },
    { NULL /* spoolssAddPort */                                     /* 0x25 */ },
    { NULL /* spoolssConfigurePort */                               /* 0x26 */ },
    { NULL /* spoolssDeletePort */                                  /* 0x27 */ },
    { NULL /* spoolssCreatePrinterIC */                             /* 0x28 */ },
    { NULL /* spoolssPlayGDIScriptOnPrinterIC */                    /* 0x29 */ },
    { NULL /* spoolssDeletePrinterIC */                             /* 0x2a */ },
    { NULL /* spoolssAddPrinterConnection */                        /* 0x2b */ },
    { NULL /* spoolssDeletePrinterConnection */                     /* 0x2c */ },
    { NULL /* spoolssPrinterMessageBox */                           /* 0x2d */ },
    { NULL /* spoolssAddMonitor */                                  /* 0x2e */ },
    { NULL /* spoolssDeleteMonitor */                               /* 0x2f */ },
    { NULL /* spoolssDeletePrintProcessor */                        /* 0x30 */ },
    { NULL /* spoolssAddPrintProvidor */                            /* 0x31 */ },
    { NULL /* spoolssDeletePrintProvidor */                         /* 0x32 */ },
    { NULL /* spoolssEnumPrintProcDataTypes */                      /* 0x33 */ },
    { spoolssResetPrinter                                           /* 0x34 */ },
    { spoolssGetPrinterDriver2                                      /* 0x35 */ },
    { NULL /* spoolssFindFirstPrinterChangeNotification */          /* 0x36 */ },
    { NULL /* spoolssFindNextPrinterChangeNotification */           /* 0x37 */ },
    { spoolssFindClosePrinterNotify                                 /* 0x38 */ },
    { NULL /* spoolssRouterFindFirstPrinterChangeNotificationOld */ /* 0x39 */ },
    { NULL /* spoolssReplyOpenPrinter */                            /* 0x3a */ },
    { NULL /* spoolssRouterReplyPrinter */                          /* 0x3b */ },
    { NULL /* spoolssReplyClosePrinter */                           /* 0x3c */ },
    { NULL /* spoolssAddPortEx */                                   /* 0x3d */ },
    { NULL /* spoolssRouterFindFirstPrinterChangeNotification */    /* 0x3e */ },
    { NULL /* spoolssSpoolerInit */                                 /* 0x3f */ },
    { NULL /* spoolssResetPrinterEx */                              /* 0x40 */ },
    { spoolssRemoteFindFirstPrinterChangeNotifyEx                   /* 0x41 */ },
    { NULL /* spoolssRouterRefreshPrinterChangeNotification */      /* 0x42 */ },
    { spoolssRemoteFindNextPrinterChangeNotifyEx                    /* 0x43 */ },
    { NULL /* spoolss44 */                                          /* 0x44 */ },
    { spoolssOpenPrinterEx                                          /* 0x45 */ },
    { NULL /* spoolssAddPrinterEx */                                /* 0x46 */ },
    { NULL /* spoolss47 */                                          /* 0x47 */ },
    { NULL /* spoolssEnumPrinterData */                             /* 0x48 */ },
    { NULL /* spoolssDeletePrinterData */                           /* 0x49 */ },
    { NULL /* spoolss4a */                                          /* 0x4a */ },
    { NULL /* spoolss4b */                                          /* 0x4b */ },
    { NULL /* spoolss4c */                                          /* 0x4c */ },
    { NULL /* spoolssSetPrinterDataEx */                            /* 0x4d */ },
    { NULL /* spoolssGetPrinterDataEx */                            /* 0x4e */ },
    { NULL /* spoolssEnumPrinterDataEx */                           /* 0x4f */ },
    { NULL /* spoolssEnumPrinterKey */                              /* 0x50 */ },
    { NULL /* spoolssDeletePrinterDataEx */                         /* 0x51 */ },
    { NULL /* spoolssDeletePrinterKey */                            /* 0x52 */ },
    { NULL /* spoolss53 */                                          /* 0x53 */ },
    { NULL /* spoolssDeletePrinterDriverEx */                       /* 0x54 */ },
    { NULL /* spoolss55 */                                          /* 0x55 */ },
    { NULL /* spoolss56 */                                          /* 0x56 */ },
    { NULL /* spoolss57 */                                          /* 0x57 */ },
    { NULL /* spoolss58 */                                          /* 0x58 */ },
    { NULL /* spoolssAddPrinterDriverEx */                          /* 0x59 */ },
    { NULL /* spoolss5a */                                          /* 0x5a */ },
    { NULL /* spoolss5b */                                          /* 0x5b */ },
    { NULL /* spoolss5c */                                          /* 0x5c */ },
    { NULL /* spoolss5d */                                          /* 0x5d */ },
    { NULL /* spoolss5e */                                          /* 0x5e */ },
    { NULL /* spoolss5f */                                          /* 0x5f */ }
};

static const CSRpcPipeDescriptor pipeDescriptor =
{
  initData,
  stopData,
  NULL,
  "spoolss",
  {cmPack32(0x12345678),cmPack16(0x1234),cmPack16(0xabcd),{0xef,0x00},{0x01,0x23,0x45,0x67,0x89,0xab}},
  cmRpcVersion(1, 0),
  (sizeof(functions) / sizeof(functions[0])),
  functions,
  NULL
};

/* pack time in Windows portion format */

static void
packTimePortions(
    CMRpcPacketDescriptor* out,     /* output packet descriptor */
    NQ_UINT32 time                  /* UNIX style time */
    );

/* calculate length of one entry for EnumForms */

static NQ_UINT32
enumFormEntryLength(
    SYPrinterHandle printHandle,    /* printer handle */
    NQ_UINT32 formIdx,              /* form index */
    NQ_UINT32 infoLevel             /* information level */
    );

/* create one entry for EnumForms */

static NQ_UINT32
enumFormEntry(
    CMRpcPacketDescriptor* out,     /* output packet descriptor */
    SYPrinterHandle printHandle,    /* printer handle */
    NQ_UINT32 formIdx,              /* form index */
    NQ_UINT32 infoLevel,            /* information level */
    NQ_BYTE* bufferStart,           /* beginning of the buffer */
    NQ_WCHAR** buffer               /* running pointer for placing strings */
    );

/* create one entry for EnumPrinters */

static NQ_UINT32
enumPrinterEntry(
    const CMRpcPacketDescriptor* in,    /* incoming packet descriptor */
    CMRpcPacketDescriptor* out,         /* output packet descriptor */
    NQ_UINT32 infoLevel,                /* information level */
    const CSShare* pShare,              /* printer share */
    const NQ_CHAR* serverIp,            /* server ip */
    NQ_BYTE* bufferStart,               /* pointer to the buffer start */
    NQ_WCHAR** buffer                   /* running pointer for placing strings */
    );

/* calculate entry length for EnumPrinters */

static NQ_UINT32
enumPrinterEntryLength(
    NQ_UINT32 infoLevel,            /* information level */
    const CSShare* pShare,          /* printer share */
    const NQ_CHAR* serverIp         /* server ip */
    );

/* create one entry for EnumJobs */

static NQ_UINT32
enumJobEntry(
    const CMRpcPacketDescriptor* in,    /* incoming packet descriptor */
    CMRpcPacketDescriptor* out,         /* output packet descriptor */
    const CSShare* pShare,              /* printer share */
    NQ_UINT32 jobId,                    /* job ID */
    SYPrinterHandle printHandle,        /* printer handle */
    const SYPrinterInfo* printInfo,     /* printer information structure */
    NQ_UINT32 infoLevel,                /* information level */
    NQ_BYTE* bufferStart,               /* beginning of the buffer */
    NQ_WCHAR** buffer,                  /* running pointer for placing strings */
    const NQ_CHAR* serverIp             /* pointer to server IP */     
    );

/* calculates entry length for EnumJobs */

static NQ_UINT32
enumJobEntryLength(
    const CMRpcPacketDescriptor* in,    /* incoming packet descriptor */
    const CSShare* pShare,              /* printer share */
    NQ_UINT32 jobId,                    /* job ID */
    SYPrinterHandle printHandle,        /* printer handle */
    const SYPrinterInfo* printInfo,     /* printer information structure */
    NQ_UINT32 infoLevel,                /* information level */
    const NQ_CHAR *serverIP             /* pointer to server IP */
    );

/* create one entry for EnumDrivers */

static NQ_UINT32                        /* 0 or error code */
enumDriverEntry(
    const CMRpcPacketDescriptor* in,    /* incoming packet descriptor */
    CMRpcPacketDescriptor* out,         /* output packet descriptor */
    const NQ_WCHAR *requiredOS,         /* required OS */
    NQ_UINT32 infoLevel,                /* information level */
    const CSShare* pShare,              /* printer share */
    NQ_WCHAR** buffer,                  /* running pointer for placing strings */
    const NQ_CHAR* serverIp             /* pointer to server IP */ 
    );

/* place Unicode string backwards from the end of the buffer according to SPOOLSS
   problem reported in MS client */

static NQ_UINT32                    /* zero or error code */
placeAsciiAsUnicode(
    CMRpcPacketDescriptor* out,     /* output packet descriptor for placing offsets */
    NQ_WCHAR** buffer,              /* running pointer for placing strings */
    NQ_BYTE* bufferStart,           /* pointer to the start of the buffer */
    const NQ_CHAR* src              /* source string */
    );

static NQ_UINT32                    /* zero or error code */
placeTcharAsUnicode(
    CMRpcPacketDescriptor* out,     /* output packet descriptor for placing offsets */
    NQ_WCHAR** buffer,              /* running pointer for placing strings */
    NQ_BYTE* bufferStart,           /* pointer to the start of the buffer */
    const NQ_WCHAR* src             /* source string */
    );

static NQ_UINT32                    /* zero or error code */
placeListAsUnicode(
    CMRpcPacketDescriptor* out,     /* output packet descriptor for placing offsets */
    NQ_WCHAR** buffer,              /* running pointer for placing strings */
    NQ_BYTE* bufferStart,           /* pointer to the start of the buffer */
    const NQ_WCHAR** src             /* source string */
    );

static NQ_UINT32                    /* zero or error code */
placePathAsUnicode(
    CMRpcPacketDescriptor* out,     /* output packet descriptor for placing offsets */
    NQ_WCHAR** buffer,              /* running pointer for placing strings */
    NQ_BYTE* bufferStart,           /* pointer to the start of the buffer */
    const NQ_WCHAR* src,            /* source string */
    const NQ_CHAR* serverIp         /* IN pointer to server IP */
    );

static NQ_UINT32                    /* zero or error code */
placePathListAsUnicode(
    CMRpcPacketDescriptor* out,     /* output packet descriptor for placing offsets */
    NQ_WCHAR** buffer,              /* running pointer for placing strings */
    NQ_BYTE* bufferStart,           /* pointer to the start of the buffer */
    const NQ_WCHAR** src,           /* pointer to string array, the last name is empty */
    const NQ_CHAR* serverIp         /* IN pointer to server IP */
    );

/* place DevMode structure into the buffer */

static NQ_UINT32                    /* zero or error code */
placeDevMode(
    CMRpcPacketDescriptor* out,     /* output packet descriptor */
    const SYDeviceMode* devMode,    /* pointer to the devmode structure */
    const CSShare* pShare,          /* share pointer */
    const NQ_CHAR* serverIp         /* pointer to server IP */
    );

/* parse device mode structure */

static NQ_UINT32
parseDevMode(
    CMRpcPacketDescriptor* in,      /* input packet descriptor */
    NQ_UINT32 size,                 /* data size */
    SYDeviceMode* devMode           /* pointer to the devmode structure */
    );

/* check access rights to printer and job */

static NQ_BOOL                          /* TRUE when access is allowed */
checkAccessToPrinter(
    SYPrinterHandle handle,             /* printer handle */
    const CMRpcPacketDescriptor* in,    /* request descriptor */
    NQ_UINT32 desiredAccess             /* access bits */
    );

static NQ_BOOL                          /* TRUE when access is allowed */
checkAccessToJob(
    SYPrinterHandle handle,             /* printer handle */
    NQ_UINT32 jobId,                    /* job ID in the queue */
    const CMRpcPacketDescriptor* in,    /* request descriptor */
    NQ_UINT32 desiredAccess             /* access bits */
    );

/* find printer share */

static NQ_STATUS                /* NQ_SUCCESS or error code */
getPrinterShare(
    CMRpcPacketDescriptor* in,  /* incoming descriptor*/
    NQ_INT16 *entry,            /* buffer for entry number in the openEntries table */
    CSShare **share,            /* buffer for resulting share pointer */
    SYPrinterHandle *h,         /* buffer for printer handle */
    NQ_BOOL skipPolicyHandle
    );

/*====================================================================
 * PURPOSE: Get pipe descriptor
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: pipe descriptor for this pipe
 *
 * NOTES:
 *====================================================================
 */

const CSRpcPipeDescriptor*
csRpcSpoolss(
    )
{
    return &pipeDescriptor;
}

/*
    Pipe functions
    --------------

    All pipe functions have the same signature:

 *====================================================================
 * PURPOSE: A pipe function
 *--------------------------------------------------------------------
 * PARAMS:  IN incoming packet descriptor
 *          OUT outgoing packet descriptor
 *
 * RETURNS: zero on success or error code
 *
 * NOTES:   a pipe function parses incoming packet and packs outgoing
 *          packet
 *====================================================================
 */

/* Get list of printers information */

static NQ_UINT32
spoolssEnumPrinters(
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    CMRpcUnicodeString serverName;  /* requested server name */
    NQ_UINT32 infoLevel;            /* requested information level */
    CMRpcPacketDescriptor outTemp;  /* this descriptor creates actual output,
                                       on error it will be discarded, on success
                                       its pointer will be copied into "out" */
    NQ_BYTE* savedPtr;              /* saved pointer to the entry referral */
    NQ_BYTE* bufferStart;           /* pointer to the data buffer start */
    NQ_UINT32 numPrinters;          /* number of printers */
    NQ_UINT32 numShares;            /* number of shares */
    NQ_UINT32 status;               /* entry status */
    NQ_UINT32 bufferSize;           /* number of bytes in the resulting buffer*/
    NQ_UINT i;                      /* just a counter */
    NQ_UINT32 flags;                /* enum flags */
    NQ_WCHAR* stringPointer;        /* pointer for placing strings */
    NQ_UINT32 requiredLength;       /* required room for entries */
    NQ_UINT32 needed;               /* actual numebr of bytes */
    const NQ_CHAR *pServerIP;       /* pointer to server IP */
    NQ_IPADDRESS ip;                /* IP address */

    TRCB();

    /* parse input parameters */

    cmRpcParseUint32(in, &flags);  /* flags */
    cmRpcParseSkip(in, 4);  /* referent ID */
    cmRpcParseUnicode(in, &serverName, CM_RP_SIZE32 | CM_RP_FRAGMENT32);
    cmRpcAllign(in, 4);
    cmRpcParseUint32(in, &infoLevel);
    cmRpcParseSkip(in, 4);  /* buffer ref id */
    cmRpcParseUint32(in, &bufferSize);      /* buffer size */
    if (bufferSize < cmRpcSpace(out))
    {
        out->length = (NQ_UINT)bufferSize;
    }

    cmUnicodeToAnsiN(staticData->txtBuffer, serverName.text, (NQ_UINT)(serverName.length * sizeof(NQ_WCHAR)));
    staticData->txtBuffer[serverName.length] = '\0';
    pServerIP = cmAsciiToIp(staticData->txtBuffer, &ip) == NQ_SUCCESS ? staticData->txtBuffer : NULL;

    TRC1P("server: %s", staticData->txtBuffer);
    TRC3P("flags: %08lx, info level: %ld, buffer size: %ld", flags, infoLevel, bufferSize);

    /* pack the result header */

    savedPtr = out->current;
    cmRpcPackUint32(out, 0);                /* referal ID - null pointer meanwhile */
    cmRpcPackUint32(out, 0);                /* buffer size */
    cmRpcCloneDescriptor(out, &outTemp);

    /* calculate required room */

    numShares = csGetSharesCount();
    requiredLength = 4 * 3;
    for (i = 0; i < numShares; i++)
    {
        const CSShare* pShare = csGetShareByIndex(i);
        if (NULL == pShare)
        {
            TRCERR("Unable to get share information");
            TRC1P(" share index: %d", i);

            TRCE();
            return CM_RP_FAULTOBJECTNOTFOUND;
        }
        if (pShare->isPrintQueue)
        {
            status = enumPrinterEntryLength(infoLevel, pShare, pServerIP);
            if (status == 0)
            {
                TRCE();
                return CM_RP_FAULTUNSUPPORTED;
            }
            requiredLength += status;
        }
    }

    if (bufferSize < requiredLength)
    {
        out->current = savedPtr;    /* advance the original descriptor */
        cmRpcPackUint32(out, 0);    /* NULL pointer */
        cmRpcPackUint32(out, requiredLength);  /* needed */
        cmRpcPackUint32(out, 0);    /* number of entries */
        TRCE();
        return CM_RP_INSUFFICIENTBUFFER;
    }

    /* pack entries */

    numShares = csGetSharesCount();
    numPrinters = 0;
    bufferStart = outTemp.current;
    stringPointer = (NQ_WCHAR*)(bufferStart + bufferSize);
    for (i = 0; i < numShares; i++)
    {
        const CSShare* pShare = csGetShareByIndex(i);
        if (NULL == pShare)
        {
            TRCERR("Unable to get share information");
            TRC1P(" share index: %d", i);

            TRCE();
            return CM_RP_FAULTOBJECTNOTFOUND;
        }
        if (pShare->isPrintQueue)
        {
            status = enumPrinterEntry(in, &outTemp, infoLevel, pShare, pServerIP, bufferStart, &stringPointer);
            if (status == CM_RP_FAULTOTHER)
            {
                continue;
            }
            if (status != 0)
            {
                TRCE();
                return status;
            }
            numPrinters++;
        }
    }

    needed = (NQ_UINT32)(outTemp.current - out->current);
    out->current = savedPtr;    /* advance the original descriptor */
    cmRpcPackUint32(out, 1);    /* a referral instead of null */
    cmRpcPackUint32(out, bufferSize);  /* real value */
    out->current += bufferSize; /* advance the original descriptor */
    cmRpcPackUint32(out, needed);    /* needed */
    cmRpcPackUint32(out, numPrinters);   /* entry count */
    TRCE();
    return 0;
}

/* Get list of jobs in a queue */

static NQ_UINT32
spoolssEnumJobs(
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    NQ_UINT32 infoLevel;            /* requested information level */
    CMRpcPacketDescriptor outTemp;  /* this descriptor creates actual output,
                                       on error it will be discarded, on success
                                       its pointer will be copied into "out" */
    NQ_BYTE* savedPtr;              /* saved pointer to the entry referral */
    NQ_UINT32 firstJob;             /* first job index */
    NQ_UINT32 nextJob;              /* next job index */
    NQ_INT32 nextJobId;             /* next job ID */
    NQ_UINT32 numJobs;              /* number of jobs */
    NQ_UINT32 status;               /* entry status */
    NQ_UINT32 bufferSize;           /* number of bytes in the resulting buffer*/
    NQ_UINT16 entryIdx;             /* open entry index */
    const CSShare* pShare;          /* pointer to share descriptor */
    NQ_UINT32 offeredSize;          /* offered buffer size */
    SYPrinterHandle printHandle;    /* internal printer handle */
    NQ_WCHAR* stringPointer;        /* pointer for placing strings */
    NQ_BYTE* bufferEnd;             /* saved pointer to the buffer end */
    NQ_UINT32 requiredSpace;        /* buffer length required for entries */
    NQ_UINT32 numEntries;           /* number of entries */
    NQ_CHAR *pServerIp;             /* pointer to server IP */

    TRCB();

    savedPtr = out->current;

    /* parse input parameters */

    cmRpcParseSkip(in, 4);  /* flags */
    cmRpcParseUint16(in, &entryIdx);
    cmRpcParseSkip(in, sizeof(CMRpcUuid) - 2);
    cmRpcPackUint32(out, 0);                /* referal ID - null pointer meanwhile */
    cmRpcPackUint32(out, 0);                /* buffer size */
    if (entryIdx > UD_CS_SPOOLSS_MAXOPENPRINTERS)
    {
        TRCERR("Open entry index out of range");
        TRC1P(" index: %d", entryIdx);
        cmRpcPackUint32(out, 0);                /* num entries */
        TRCE();
        return CM_RP_FAULTCONTEXTMISMATCH;
    }
    if (staticData->openEntries[entryIdx].isFree)
    {
        TRCERR("Open entry index designates a free entry");
        TRC1P(" index: %d", entryIdx);
        cmRpcPackUint32(out, 0);                /* num entries */
        TRCE();
        return CM_RP_FAULTCONTEXTMISMATCH;
    }
    pShare = staticData->openEntries[entryIdx].pShare;
    if (pShare == NULL)
    {
        TRCERR("Illegal printer handle in request");
        TRC1P("  value: %d", entryIdx);
        cmRpcPackUint32(out, 0);                /* num entries */
        TRCE();
        return CM_RP_FAULTINVALIDPRINTERNAME;
    }

    /* get printer info */
    printHandle = syGetPrinterHandle(pShare->map);
    if (!syIsValidPrinter(printHandle))
    {
        TRCERR("Unable to find printer by handle");
        TRC1P(" printer: %s", cmWDump(pShare->map));
        cmRpcPackUint32(out, 0);                /* num entries */
        TRCE();
        return CM_RP_FAULTINVALIDPRINTERNAME;
    }

    cmRpcParseUint32(in, &firstJob);
    cmRpcParseUint32(in, &numJobs);
    cmRpcParseUint32(in, &infoLevel);
    cmRpcParseSkip(in, 4);    /* buffer referent ID */
    cmRpcParseUint32(in, &offeredSize);

    if (offeredSize > out->length)
    {
        TRCERR("Offered buffer is too big");
        cmRpcPackUint32(out, 0);                /* num entries */
        TRCE();
        return CM_RP_OUTOFMEMORY;
    }

    /* pack the result header */

    cmRpcCloneDescriptor(out, &outTemp);
    bufferEnd = out->current + offeredSize; /* start strings from the end of the buffer */
    stringPointer = (NQ_WCHAR*)bufferEnd;

    if (NQ_FAIL == syGetPrinterInfo(printHandle, &staticData->printInfo))
    {
        TRCERR("Unable to get printer information");
        TRC1P(" printer handle: %d", printHandle);
        cmRpcPackUint32(out, 0);                /* num entries */
        TRCE();
        return CM_RP_FAULTINVALIDPRINTERNAME;
    }

    requiredSpace = 0;

    if (numJobs > staticData->printInfo.cJobs)
        numJobs = staticData->printInfo.cJobs;

    pServerIp = staticData->openEntries[entryIdx].isIpAsServerName ? staticData->openEntries[entryIdx].ipServer : NULL;

    for (nextJob = 0; nextJob < numJobs; nextJob++)
    {
        if (nextJob < firstJob)
        {
            continue;       /* just skip */
        }
        nextJobId = syGetPrintJobIdByIndex(printHandle, (NQ_INT)nextJob);
        if (nextJobId == NQ_FAIL)
            break;
        status = enumJobEntryLength(in,
                                    pShare,
                                    (NQ_UINT32)nextJobId,
                                    printHandle,
                                    &staticData->printInfo,
                                    infoLevel,
                                    pServerIp
                                    );
        if (0 == status)
        {
            break;
        }
        if (status != (NQ_UINT32)-1)
        {
            requiredSpace += status;
        }
    }

    TRC2P("offered: %ld, required: %ld", offeredSize, requiredSpace);
    
    if (offeredSize < requiredSpace)
    {
        TRC("Insufficient buffer calculated");
        out->current = savedPtr;
        cmRpcPackUint32(out, 0);                /* referal ID - null pointer meanwhile */
        cmRpcPackUint32(out, requiredSpace);    /* required buffer size */
        cmRpcPackUint32(out, 0);                /* num entries */
        TRCE();
        return CM_RP_INSUFFICIENTBUFFER;
    }

    /* compose entries */

    for (nextJob = 0, numEntries = 0; nextJob < numJobs; nextJob++)
    {
        if (nextJob < firstJob)
        {
            continue;       /* just skip */
        }
        nextJobId = syGetPrintJobIdByIndex(printHandle, (NQ_INT)nextJob);
        if (nextJobId == NQ_FAIL)
            break;
        status = enumJobEntry(in,
                              &outTemp,
                              pShare,
                              (NQ_UINT32)nextJobId,
                              printHandle,
                              &staticData->printInfo,
                              infoLevel,
                              outTemp.current,
                              &stringPointer,
                              pServerIp
                              );
        if (status == CM_RP_FAULTOBJECTNOTFOUND)
        {
            break;
        }
        if (status == CM_RP_FAULTOTHER)
        {
            continue;
        }
        if (status == CM_RP_INSUFFICIENTBUFFER)
        {
            TRC("Insufficient buffer");
            out->current = savedPtr;
            cmRpcPackUint32(out, 0);                /* referal ID - null pointer meanwhile */
            cmRpcPackUint32(out, (offeredSize < 1024)? 1024: offeredSize * 2);  /* buffer size */
        }
        if (status != 0)
        {
            cmRpcPackUint32(out, 0);  /* num entries */
            TRCE();
            return status;
        }
        numEntries++;
    }

    bufferSize = (NQ_UINT32)(bufferEnd - out->current);
    outTemp.current = bufferEnd;
    cmRpcAllign(&outTemp, 4);   /* allign to four */
    cmRpcPackUint32(&outTemp, requiredSpace);    /* needed: undocumented */
    cmRpcPackUint32(&outTemp, numEntries);   /* entry count */

    out->current = savedPtr;    /* advance the original descriptor */
    cmRpcPackUint32(out, 1);    /* a referral instead of null */
    cmRpcPackUint32(out, bufferSize);  /* real value */
    out->current = outTemp.current;    /* advance the original descriptor */

    TRCE();
    return 0;
}

/* Get list of forms */

static NQ_UINT32
spoolssEnumForms(
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    NQ_UINT32 infoLevel;            /* requested information level */
    CMRpcPacketDescriptor outTemp;  /* this descriptor creates actual output,
                                       on error it will be discarded, on success
                                       its pointer will be copied into "out" */
    NQ_BYTE* savedPtr;              /* saved pointer to the entry referral */
    NQ_UINT32 nextForm;             /* next form index */
    NQ_UINT32 numForms;             /* number of forms */
    NQ_UINT32 status;               /* entry status */
    NQ_UINT16 entryIdx;             /* open entry index */
    const CSShare* pShare;          /* pointer to share descriptor */
    NQ_UINT32 offeredSize;          /* offered buffer size */
    SYPrinterHandle printHandle;    /* internal printer handle */
    NQ_WCHAR* stringPointer;        /* pointer for placing strings */
    NQ_BYTE* bufferStart;           /* pointer to the data buffer start */
    NQ_BYTE* bufferEnd;             /* saved pointer to the buffer end */
    NQ_UINT32 requiredSpace;        /* buffer length required for entries */

    TRCB();

    savedPtr = out->current;

    /* parse input parameters */

    cmRpcParseSkip(in, 4);  /* flags */
    cmRpcParseUint16(in, &entryIdx);
    cmRpcParseSkip(in, sizeof(CMRpcUuid) - 2);
    cmRpcPackUint32(out, 0);                /* referal ID - null pointer meanwhile */
    cmRpcPackUint32(out, 0);                /* buffer size */
    if (entryIdx > UD_CS_SPOOLSS_MAXOPENPRINTERS)
    {
        TRCERR("Open entry index out of range");
        TRC1P(" index: %d", entryIdx);
        TRCE();
        return CM_RP_FAULTCONTEXTMISMATCH;
    }
    if (staticData->openEntries[entryIdx].isFree)
    {
        TRCERR("Open entry index designates a free entry");
        TRC1P(" index: %d", entryIdx);
        TRCE();
        return CM_RP_FAULTCONTEXTMISMATCH;
    }
    pShare = staticData->openEntries[entryIdx].pShare;
    if (pShare == NULL)
    {
        TRCERR("Illegal printer handle in request");
        TRC1P("  value: %d", entryIdx);
        TRCE();
        return CM_RP_FAULTINVALIDPRINTERNAME;
    }

    /* get printer info */
    printHandle = syGetPrinterHandle(pShare->map);
    if (!syIsValidPrinter(printHandle))
    {
        TRCERR("Unable to find printer by handle");
        TRC1P(" printer: %s", cmWDump(pShare->map));
        TRCE();
        return CM_RP_FAULTINVALIDPRINTERNAME;
    }

    /* get request info */
    cmRpcParseUint32(in, &infoLevel);
    cmRpcParseSkip(in, 4);    /* buffer referent ID */
    cmRpcParseUint32(in, &offeredSize);

    if (offeredSize > out->length)
    {
        TRCERR("Offered buffer is too big");
        TRCE();
        return CM_RP_OUTOFMEMORY;
    }

    /* pack the result header */

    cmRpcCloneDescriptor(out, &outTemp);
    requiredSpace = 0;

    for (nextForm = 0; ; nextForm++)
    {
        status = enumFormEntryLength(printHandle, nextForm, infoLevel);
        if (0 == status)
        {
            break;
        }
        if (0xFFFFFFFF == status)
        {
            cmRpcPackUint32(out, 0);  /* num entries */
            TRCE();
            return CM_RP_UNKNOWNLEVEL;
        }
        requiredSpace += status;
    }

    bufferEnd = out->current + offeredSize; /* start strings from the end of the buffer */
    stringPointer = (NQ_WCHAR*)bufferEnd;
    numForms = nextForm;

    TRC2P("offered: %ld, required: %ld", offeredSize, requiredSpace);

    if (offeredSize < requiredSpace)
    {
        out->current = savedPtr;
        cmRpcPackUint32(out, 0);                                         /* referal ID - null pointer meanwhile */
        cmRpcPackUint32(out, requiredSpace < 1000? 1000: requiredSpace); /* required buffer size */
        cmRpcPackUint32(out, 0);                                         /* num entries */
        TRCE();
        return CM_RP_INSUFFICIENTBUFFER;
    }

    /* compose entries */

    bufferStart = outTemp.current;
    for (nextForm = 0; nextForm < numForms; nextForm++)
    {
        status = enumFormEntry(&outTemp,
                              printHandle,
                              nextForm,
                              infoLevel,
                              bufferStart,
                              &stringPointer
                              );
        if (status == CM_RP_FAULTOBJECTNOTFOUND)
        {
            break;
        }
        if (status == CM_RP_INSUFFICIENTBUFFER)
        {
            TRC("Insufficient buffer");
            out->current = savedPtr;
            cmRpcPackUint32(out, 0);                /* referal ID - null pointer meanwhile */
            cmRpcPackUint32(out, (offeredSize < 500)? 500: offeredSize * 2);  /* buffer size */
        }
        if (status != 0)
        {
            cmRpcPackUint32(out, 0);  /* num entries */
            TRCE();
            return status;
        }
    }

    outTemp.current = bufferEnd;
    cmRpcPackUint32(&outTemp, (numForms == 0? 0:requiredSpace));    /* buffer size */
    cmRpcPackUint32(&outTemp, numForms);      /* entry count */

    out->current = savedPtr;    /* advance the original descriptor */
    cmRpcPackUint32(out, 1);    /* a referral instead of null */
    cmRpcPackUint32(out, offeredSize);  /* real value */
    out->current = outTemp.current;    /* advance the original descriptor */

    TRCE();
    return 0;
}

/* Get jobs information */

static NQ_UINT32
spoolssGetJob(
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    NQ_UINT32 infoLevel;            /* requested information level */
    CMRpcPacketDescriptor outTemp;  /* this descriptor creates actual output,
                                       on error it will be discarded, on success
                                       its pointer will be copied into "out" */
    NQ_BYTE* savedPtr;              /* saved pointer to the entry referral */
    NQ_UINT32 jobId;                /* job index */
    NQ_UINT32 status;               /* entry status */
    NQ_UINT16 entryIdx;             /* open entry index */
    const CSShare* pShare;          /* pointer to share descriptor */
    NQ_UINT32 offeredSize;          /* offered buffer size */
    SYPrinterHandle printHandle;    /* internal printer handle */
    NQ_WCHAR* stringPointer;        /* pointer for placing strings */
    NQ_BYTE* bufferEnd;             /* saved pointer to the buffer end */
    NQ_UINT32 requiredSpace;        /* buffer length required for entries */
    const NQ_CHAR* serverIp;        /* pointer to server IP */

    TRCB();

    savedPtr = out->current;

    /* parse input parameters */

    cmRpcParseSkip(in, 4);  /* flags */
    cmRpcParseUint16(in, &entryIdx);
    cmRpcParseSkip(in, sizeof(CMRpcUuid) - 2);
    cmRpcPackUint32(out, 0);                /* referal ID - null pointer meanwhile */
    cmRpcPackUint32(out, 0);                /* buffer size */
    if (entryIdx > UD_CS_SPOOLSS_MAXOPENPRINTERS)
    {
        TRCERR("Open entry index out of range");
        TRC1P(" index: %d", entryIdx);
        TRCE();
        return CM_RP_FAULTCONTEXTMISMATCH;
    }
    if (staticData->openEntries[entryIdx].isFree)
    {
        TRCERR("Open entry index designates a free entry");
        TRC1P(" index: %d", entryIdx);
        TRCE();
        return CM_RP_FAULTCONTEXTMISMATCH;
    }
    pShare = staticData->openEntries[entryIdx].pShare;
    if (pShare == NULL)
    {
        TRCERR("Illegal printer handle in request");
        TRC1P("  value: %d", entryIdx);
        TRCE();
        return CM_RP_FAULTINVALIDPRINTERNAME;
    }

    /* get printer info */
    printHandle = syGetPrinterHandle(pShare->map);
    if (!syIsValidPrinter(printHandle))
    {
        TRCERR("Unable to find printer by handle");
        TRC1P(" printer: %s", cmWDump(pShare->map));
        TRCE();
        return CM_RP_FAULTINVALIDPRINTERNAME;
    }

    cmRpcParseUint32(in, &jobId);
    cmRpcParseUint32(in, &infoLevel);
    cmRpcParseSkip(in, 4);    /* buffer referent ID */
    cmRpcParseUint32(in, &offeredSize);
    if (offeredSize > out->length)
    {
        TRCERR("Offered buffer is too big");
        TRCE();
        return CM_RP_OUTOFMEMORY;
    }

    /* check access to job */
    if (!checkAccessToJob(printHandle, jobId, in, SMB_DESIREDACCESS_JOBQUERY))
    {
        TRCE();
        return CM_RP_FAULTLOGONFAILURE;
    }

    /* pack the result header */

    cmRpcCloneDescriptor(out, &outTemp);
    bufferEnd = out->current + offeredSize; /* start strings from the end of the buffer */
    stringPointer = (NQ_WCHAR*)bufferEnd;

    if (NQ_FAIL == syGetPrinterInfo(printHandle, &staticData->printInfo))
    {
        TRCERR("Unable to get printer information");
        TRC1P(" printer handle: %d", printHandle);
        TRCE();
        return CM_RP_FAULTINVALIDPRINTERNAME;
    }

    serverIp = staticData->openEntries[entryIdx].isIpAsServerName ? staticData->openEntries[entryIdx].ipServer : NULL;

    /* calculate required buffer size */

    requiredSpace = enumJobEntryLength(
                                in,
                                pShare,
                                jobId,
                                printHandle,
                                &staticData->printInfo,
                                infoLevel,
                                serverIp
                               );
    TRC2P("offered: %ld, required: %ld", offeredSize, requiredSpace);

    if (offeredSize < requiredSpace)
    {
        out->current -= 4;
        cmRpcPackUint32(out, requiredSpace);    /* required buffer size */
        TRCE();
        return CM_RP_INSUFFICIENTBUFFER;
    }

    /* compose entry */

    status = enumJobEntry(in,
                          &outTemp,
                          pShare,
                          jobId,
                          printHandle,
                          &staticData->printInfo,
                          infoLevel,
                          outTemp.current,
                          &stringPointer,
                          serverIp
                          );
    if (status == CM_RP_INSUFFICIENTBUFFER)
    {
        TRC("Insufficient buffer");
        out->current = savedPtr;
        cmRpcPackUint32(out, 0);                /* referal ID - null pointer meanwhile */
        cmRpcPackUint32(out, (offeredSize < 1024)? 1024: offeredSize * 2);  /* buffer size */
    }
    if (status != 0)
    {
        cmRpcPackUint32(out, 0);  /* num entries */
        TRCE();
        return status;
    }

    outTemp.current = bufferEnd;
    cmRpcPackUint32(&outTemp, requiredSpace);    /* needed */

    out->current = savedPtr;    /* advance the original descriptor */
    cmRpcPackUint32(out, 1);    /* a referral instead of null */
    cmRpcPackUint32(out, offeredSize);  /* real value */
    out->current = outTemp.current;     /* advance the original descriptor */

    TRCE();
    return 0;
}

/* Get form information */

static NQ_UINT32
spoolssGetForm(
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    CMRpcUnicodeString formName;    /* requested form name */
    NQ_UINT32 infoLevel;            /* requested information level */
    CMRpcPacketDescriptor outTemp;  /* this descriptor creates actual output,
                                       on error it will be discarded, on success
                                       its pointer will be copied into "out" */
    NQ_BYTE* savedPtr;              /* saved pointer to the entry referral */
    NQ_UINT32 formId;               /* form index */
    NQ_UINT32 status;               /* entry status */
    NQ_UINT32 bufferSize;           /* number of bytes in the resulting buffer*/
    const CSShare* pShare;          /* pointer to share descriptor */
    NQ_UINT16 entryIdx;             /* open entry index */
    NQ_UINT32 offeredSize;          /* offered buffer size */
    SYPrinterHandle printHandle;    /* internal printer handle */
    NQ_WCHAR* stringPointer;        /* pointer for placing strings */
    NQ_BYTE* bufferEnd;             /* saved pointer to the buffer end */
    NQ_UINT32 requiredSpace;        /* buffer length required for entries */

    TRCB();

    savedPtr = out->current;

    /* parse input parameters */

    cmRpcParseSkip(in, 4);  /* flags */
    cmRpcParseUint16(in, &entryIdx);
    cmRpcParseSkip(in, sizeof(CMRpcUuid) - 2);
    cmRpcPackUint32(out, 0);                /* referal ID - null pointer meanwhile */
    cmRpcPackUint32(out, 0);                /* buffer size */
    if (entryIdx > UD_CS_SPOOLSS_MAXOPENPRINTERS)
    {
        TRCERR("Open entry index out of range");
        TRC1P(" index: %d", entryIdx);
        TRCE();
        return CM_RP_FAULTCONTEXTMISMATCH;
    }
    if (staticData->openEntries[entryIdx].isFree)
    {
        TRCERR("Open entry index designates a free entry");
        TRC1P(" index: %d", entryIdx);
        TRCE();
        return CM_RP_FAULTCONTEXTMISMATCH;
    }
    pShare = staticData->openEntries[entryIdx].pShare;
    if (pShare == NULL)
    {
        TRCERR("Illegal printer handle in request");
        TRC1P("  value: %d", entryIdx);
        TRCE();
        return CM_RP_FAULTINVALIDPRINTERNAME;
    }

    /* get printer info */
    printHandle = syGetPrinterHandle(pShare->map);
    if (!syIsValidPrinter(printHandle))
    {
        TRCERR("Unable to find printer by handle");
        TRC1P(" printer: %s", cmWDump(pShare->map));
        TRCE();
        return CM_RP_FAULTINVALIDPRINTERNAME;
    }

    cmRpcParseUnicode(in, &formName, CM_RP_SIZE32 | CM_RP_FRAGMENT32);
    syWStrncpy(staticData->txtBufferW, formName.text, formName.length);
    staticData->txtBufferW[formName.length] = cmWChar(0);
    cmRpcParseUint32(in, &infoLevel);
    cmRpcParseSkip(in, 4);    /* buffer referent ID */
    cmRpcParseUint32(in, &offeredSize);
    if (offeredSize > out->length)
    {
        TRCERR("Offered buffer is too big");
        TRCE();
        return CM_RP_OUTOFMEMORY;
    }

    /* pack the result header */

    cmRpcCloneDescriptor(out, &outTemp);
    bufferEnd = out->current + offeredSize; /* start strings from the end of the buffer */
    stringPointer = (NQ_WCHAR*)bufferEnd;

    /* find form */

    for (formId = 0; ; formId++)
    {
        if (NQ_FAIL == syGetPrintForm(printHandle, formId, &staticData->formInfo))
        {
            TRCERR("Unable to find form");
            TRC1P(" form: %s", cmWDump(staticData->txtBufferW));
            TRCE();
            return CM_RP_FAULTOTHER;
        }
        if (0 == syWStrcmp(staticData->txtBufferW, staticData->formInfo.name))
            break;
    }

    /* calculate required buffer size */

    requiredSpace = enumFormEntryLength(printHandle, formId, infoLevel);
    TRC2P("offered: %ld, required: %ld", offeredSize, requiredSpace);

    if (offeredSize < requiredSpace)
    {
        out->current -= 4;
        cmRpcPackUint32(out, requiredSpace < 500? 500: requiredSpace);    /* required buffer size */
        TRCE();
        return CM_RP_INSUFFICIENTBUFFER;
    }

    /* compose entry */

    status = enumFormEntry(&outTemp,
                          printHandle,
                          formId,
                          infoLevel,
                          outTemp.current,
                          &stringPointer
                          );
    if (status == CM_RP_INSUFFICIENTBUFFER)
    {
        TRC("Insufficient buffer");
        out->current = savedPtr;
        cmRpcPackUint32(out, 0);                /* referal ID - null pointer meanwhile */
        cmRpcPackUint32(out, (offeredSize < 1024)? 1024: offeredSize * 2);  /* buffer size */
    }
    if (status != 0)
    {
        TRCE();
        return status;
    }

    bufferSize = (NQ_UINT32)(bufferEnd - out->current);
    outTemp.current = bufferEnd;
    cmRpcPackUint32(&outTemp, bufferSize);    /* buffer size */

    out->current = savedPtr;    /* advance the original descriptor */
    cmRpcPackUint32(out, 1);    /* a referral instead of null */
    cmRpcPackUint32(out, bufferSize);  /* real value */
    out->current = outTemp.current;    /* advance the original descriptor */

    TRCE();
    return 0;
}

/* Contorl job and/or set job information */

static NQ_UINT32
spoolssSetJob(
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    NQ_UINT32 containerOffset;      /* offset to job container struct */
    NQ_UINT32 jobId;                /* job index */
    NQ_STATUS status;               /* entry status */
    NQ_UINT16 entryIdx;             /* open entry index */
    const CSShare* pShare;          /* pointer to share descriptor */
    SYPrinterHandle printHandle;    /* internal printer handle */
    NQ_UINT32 command;              /* required command */

    TRCB();

    /* parse input parameters */

    cmRpcParseSkip(in, 4);  /* flags */
    cmRpcParseUint16(in, &entryIdx);
    if (entryIdx > UD_CS_SPOOLSS_MAXOPENPRINTERS)
    {
        TRCERR("Open entry index out of range");
        TRC1P(" index: %d", entryIdx);
        TRCE();
        return CM_RP_FAULTCONTEXTMISMATCH;
    }
    if (staticData->openEntries[entryIdx].isFree)
    {
        TRCERR("Open entry index designates a free entry");
        TRC1P(" index: %d", entryIdx);
        TRCE();
        return CM_RP_FAULTCONTEXTMISMATCH;
    }
    pShare = staticData->openEntries[entryIdx].pShare;
    if (pShare == NULL)
    {
        TRCERR("Illegal printer handle in request");
        TRC1P("  value: %d", entryIdx);
        TRCE();
        return CM_RP_FAULTINVALIDPRINTERNAME;
    }

    /* get printer info */
    printHandle = syGetPrinterHandle(pShare->map);
    if (!syIsValidPrinter(printHandle))
    {
        TRCERR("Unable to find printer by handle");
        TRC1P(" printer: %s", cmWDump(pShare->map));
        TRCE();
        return CM_RP_FAULTINVALIDPRINTERNAME;
    }

    cmRpcParseSkip(in, sizeof(CMRpcUuid) - 2);
    cmRpcParseUint32(in, &jobId);
    cmRpcParseUint32(in, &containerOffset);

    /* check access to job */
    if (!checkAccessToJob(printHandle, jobId, in, SMB_DESIREDACCESS_JOBSETATTRIBUTES))
    {
        TRCE();
        return CM_RP_FAULTLOGONFAILURE;
    }

    /* we do not use job information meanwhile */

    if (containerOffset != 0)
    {
        TRCERR("Info levels are not supported");
        TRCE();
        return 0;   /* simulate success */
    }

    cmRpcParseUint32(in, &command);

    if (command == 0)
    {
        TRCERR("Command == 0 is not supported");
        TRCE();
        return 0;
    }
    status = syControlPrintJob(printHandle, jobId, command);
    if (command == SY_PRINTJOBCOM_CANCEL)
        staticData->openEntries[entryIdx].jobId = 0;

    TRCE();
    return status == NQ_SUCCESS? 0:CM_RP_FAULTUSERDEFINED;
}

/* Open printer with extra parameters */

static NQ_UINT32
spoolssOpenPrinterEx(
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    CMRpcUnicodeString printerName; /* requested server name */
    SYPrinterHandle printHandle;    /* internal printer handle */
    NQ_BYTE* outPtr;                /* saved pointer to the end of packet */
    NQ_BYTE* savedPtr;              /* saved pointer to the entry referral */
    const NQ_WCHAR* pStr;           /* pointer to various places in a string */
    NQ_CHAR* pSt;                   /* pointer to various places in a string */
    CSShare* pShare;                /* pointer to share descriptor */
    NQ_UINT32 parsedValue;          /* temporary value parsed */
    CMRpcUuid uuid;                 /* returned handle */
    NQ_INT openIdx;                 /* index of an open entry */
    NQ_IPADDRESS ip;                /* ip address */

    TRCB();

    cmRpcParseSkip(in, 4);
    cmRpcParseUnicode(in, &printerName, CM_RP_SIZE32 | CM_RP_FRAGMENT32);
    syWStrncpy(staticData->txtBufferW, printerName.text, printerName.length);
    staticData->txtBufferW[printerName.length] = cmWChar(0);
    syUnicodeToAnsi(staticData->txtBuffer, staticData->txtBufferW);
    
    savedPtr = out->current;
    cmRpcPackUint32(out, 0);                /* null pointer meanwhile */

    /* prepare null handle to be returned on error */

    syMemset((NQ_BYTE*)&uuid, 0, sizeof(uuid));
    cmRpcPackBytes(out, (NQ_BYTE*)&uuid, sizeof(uuid));

    /* check printer name */

    if (cmWChar('\\') != staticData->txtBufferW[0] ||
        cmWChar('\\') != staticData->txtBufferW[1])
    {
        TRCERR("Printer name does not start from '\\\\'");
        TRCE();
        return CM_RP_FAULTINVALIDPRINTERNAME;
    }

    /* look for printer name - server name otherwise */
    pStr = syWStrchr(staticData->txtBufferW + 2, cmWChar('\\'));
    if (NULL == pStr)
    {
        pShare = NULL;
    }
    else
    {
        pShare = csGetShareByName(pStr + 1);
        if (NULL == pShare)
        {
            TRCERR("Printer share not found");
            TRC1P("Share name: %s", cmWDump(pStr + 1));
            TRCE();
            return CM_RP_FAULTINVALIDPRINTERNAME;
        }
        if (!pShare->isPrintQueue)
        {
            TRCERR("Share is not print queue");
            TRCE();
            return CM_RP_FAULTINVALIDPRINTERNAME;
        }
        pSt = syStrchr(staticData->txtBuffer + 2, '\\');
        *pSt = '\0';
    }

    /* skip printer defaults */
    cmRpcParseUint32(in, &parsedValue);    /* printer datatype */
    if (0 != parsedValue)
    {
        cmRpcParseUnicode(in, &printerName, CM_RP_SIZE32 | CM_RP_FRAGMENT32);
    }
    cmRpcParseUint32(in, &parsedValue);    /* devmode container size */
    cmRpcParseSkip(in, 4); /* ignore devmode pointer */
    if (0 != parsedValue)
    {
        /* devmode exists */
        cmRpcParseUint32(in, &parsedValue);    /* DEVMODE extra (driver) size */
        cmRpcParseSkip(in, parsedValue);
    }

    /* parse desired access */
    cmRpcParseUint32(in, &parsedValue);    /* access required */

    /* allocate an open entry */
    for (openIdx = 0; openIdx < UD_CS_SPOOLSS_MAXOPENPRINTERS; openIdx++)
    {
        if (staticData->openEntries[openIdx].isFree)
            break;
    }
    if (openIdx >= UD_CS_SPOOLSS_MAXOPENPRINTERS)
    {
        TRCERR("Open entry table overflow");
        TRCE();
        return CM_RP_INSUFFICIENTRESOURCE;
    }

    staticData->openEntries[openIdx].pShare = pShare;
    staticData->openEntries[openIdx].isFree = FALSE;
    staticData->openEntries[openIdx].jobId = 0;
    staticData->openEntries[openIdx].isIpAsServerName = cmAsciiToIp(staticData->txtBuffer + 2, &ip) == NQ_SUCCESS;
    if (staticData->openEntries[openIdx].isIpAsServerName)
    {
        syStrcpy(staticData->openEntries[openIdx].ipServer, staticData->txtBuffer + 2);
    }

    /* generate handle as open entry index padded by fake handle and zeros (already) */
    outPtr = out->current;
    out->current = savedPtr;    /* advance the original descriptor */
    cmRpcPackUint32(out, 1);    /* a referral instead of null */
    cmRpcPackUint16(out, (NQ_UINT16)openIdx);
    cmRpcPackUint32(out, staticData->fakePrinterHandle++);
    out->current = outPtr;      /* advance the original descriptor end */

    /* check access */
    if (NULL != pShare)
    {
        printHandle = syGetPrinterHandle(pShare->map);
        if (!checkAccessToPrinter(printHandle, in, parsedValue))
        {
            staticData->openEntries[openIdx].isFree = TRUE;
            TRCERR("Required access not supported");
            TRCE();
            return CM_RP_FAULTLOGONFAILURE;
        }
    }
    TRCE();
    return 0;
}

/* Close printer  */

static NQ_UINT32
spoolssClosePrinter(
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    NQ_UINT16 entryIdx;             /* open entry index */
    CMRpcUuid uuid;                 /* returned handle */

    TRCB();

    /* parse input parameters */

    cmRpcParseSkip(in, 4);  /* flags */
    cmRpcParseUint16(in, &entryIdx);

    /* pack the result header */

    syMemset((NQ_BYTE*)&uuid, 0, sizeof(uuid));
    cmRpcPackUint32(out, 0);                /* referral */
    cmRpcPackBytes(out, (NQ_BYTE*)&uuid, sizeof(uuid));

    /* release open entry */

    if (entryIdx > UD_CS_SPOOLSS_MAXOPENPRINTERS)
    {
        TRCERR("Open entry index out of range");
        TRC1P(" index: %d", entryIdx);
        TRCE();
        return CM_RP_FAULTCONTEXTMISMATCH;
    }
    if (staticData->openEntries[entryIdx].isFree)
    {
        TRCERR("Open entry index designates a free entry");
        TRC1P(" index: %d", entryIdx);
        TRCE();
        return CM_RP_FAULTCONTEXTMISMATCH;
    }
    staticData->openEntries[entryIdx].isFree = TRUE;

    TRCE();
    return 0;
}

/* Get printer information by handle */

static NQ_UINT32
spoolssGetPrinter(
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    NQ_UINT32 infoLevel;            /* requested information level */
    CMRpcPacketDescriptor outTemp;  /* this descriptor points to the beginning of the
                                       output buffer for updating buffer size and referral */
    NQ_BYTE* bufferEnd;             /* saved pointer to the buffer end */
    NQ_UINT32 status;               /* entry status */
    NQ_UINT16 entryIdx;             /* open entry index */
    const CSShare* pShare;          /* pointer to share descriptor */
    NQ_UINT32 offeredSize;          /* offered buffer size */
    NQ_WCHAR* stringPointer;        /* pointer for placing strings */
    NQ_UINT32 requiredLength;       /* required room in the buffer */
    NQ_UINT32 referentId;           /* running number */
    NQ_CHAR *pServerIP;

    TRCB();

    cmRpcCloneDescriptor(out, &outTemp);

    /* parse input parameters */

    cmRpcParseSkip(in, 4);  /* flags */
    cmRpcParseUint16(in, &entryIdx);
    cmRpcParseSkip(in, sizeof(CMRpcUuid) - 2);
    cmRpcPackUint32(out, 0);                /* buffer ref id */
    cmRpcPackUint32(out, 0);                /* buffer size */
    if (entryIdx > UD_CS_SPOOLSS_MAXOPENPRINTERS)
    {
        TRCERR("Open entry index out of range");
        TRC1P(" index: %d", entryIdx);
        TRCE();
        return CM_RP_FAULTCONTEXTMISMATCH;
    }
    if (staticData->openEntries[entryIdx].isFree)
    {
        TRCERR("Open entry index designates a free entry");
        TRC1P(" index: %d", entryIdx);
        TRCE();
        return CM_RP_FAULTCONTEXTMISMATCH;
    }
    pShare = staticData->openEntries[entryIdx].pShare;
    if (pShare == NULL)
    {
        TRCERR("Illegal printer handle in request");
        TRC1P("  value: %d", entryIdx);
        TRCE();
        return CM_RP_FAULTINVALIDPRINTERNAME;
    }

    cmRpcParseUint32(in, &infoLevel);
    cmRpcParseSkip(in, 4);    /* buffer referent ID */
    cmRpcParseUint32(in, &offeredSize);

    if (offeredSize > out->length)
    {
        TRCERR("Offered buffer is too big");
        TRCE();
        return CM_RP_OUTOFMEMORY;
    }

    /* zero buffer (may be required by MS) */

    syMemset(out->current, 0, offeredSize);

    /* prepare results */

    referentId = 2;                             /* an arbitrary value */

    /* calculate required room */

    pServerIP = staticData->openEntries[entryIdx].isIpAsServerName ? staticData->openEntries[entryIdx].ipServer : NULL;
    requiredLength = enumPrinterEntryLength(infoLevel, pShare, pServerIP);
    if (requiredLength == 0)
    {
        TRCE();
        return CM_RP_UNKNOWNLEVEL;
    }

    if (offeredSize < requiredLength)
    {
        out->current = outTemp.current;    /* advance the original descriptor */
        cmRpcPackUint32(out, 0);    /* NULL pointer */
        cmRpcPackUint32(out, requiredLength + 2);  /* needed + allignment to 4 */
        TRCE();
        return CM_RP_INSUFFICIENTBUFFER;
    }

    /* calculate buffer end */

    bufferEnd = out->current + offeredSize; /* start strings from the end of the buffer */
    /*bufferEnd = out->current + requiredLength;*/ /* start strings from the end of the buffer */
    stringPointer = (NQ_WCHAR*)bufferEnd;

    /* pack entry */

    status = enumPrinterEntry(in, out, infoLevel, pShare, pServerIP, out->current, &stringPointer);
    if (status != 0)
    {
        TRCE();
        return status;
    }
    cmRpcPackUint32(&outTemp, referentId++); /* buffer pointer */
    cmRpcPackUint32(&outTemp, offeredSize);  /* buffer size */
    out->current = outTemp.current + ((offeredSize + 3) & (NQ_UINT32)~3); /* allign */
    cmRpcPackUint32(out, requiredLength);  /* so-called 'needed' */
    TRCE();
    return 0;
}

/* Get printer data by keyword */

static NQ_UINT32
spoolssGetPrinterData(
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    CMRpcUnicodeString dataKey;     /* key value */
    NQ_UINT16 entryIdx;             /* open entry index */
    const CSShare* pShare;          /* pointer to share descriptor */
    SYPrinterHandle printHandle;    /* internal printer handle */
    NQ_UINT32 offeredSize;          /* offered buffer size */
    NQ_UINT32 needed;               /* data size */
    NQ_BYTE* bufferEnd;             /* place after the buffer */
    NQ_COUNT i;                     /* just an index */

    TRCB();

    /* parse input parameters */

    cmRpcParseSkip(in, 4);  /* flags */
    cmRpcParseUint16(in, &entryIdx);
    if (entryIdx > UD_CS_SPOOLSS_MAXOPENPRINTERS)
    {
        TRCERR("Open entry index out of range");
        TRC1P(" index: %d", entryIdx);
        TRCE();
        return CM_RP_FAULTCONTEXTMISMATCH;
    }
    if (staticData->openEntries[entryIdx].isFree)
    {
        TRCERR("Open entry index designates a free entry");
        TRC1P(" index: %d", entryIdx);
        TRCE();
        return CM_RP_FAULTCONTEXTMISMATCH;
    }
    pShare = staticData->openEntries[entryIdx].pShare;
    cmRpcParseSkip(in, sizeof(CMRpcUuid) - 2);
    cmRpcParseUnicode(in, &dataKey, CM_RP_SIZE32 | CM_RP_FRAGMENT32);
    cmUnicodeToAnsiN(staticData->txtBuffer, dataKey.text, (NQ_UINT)(dataKey.length * sizeof(NQ_WCHAR)));
    staticData->txtBuffer[dataKey.length] = '\0';
    cmRpcAllign(in, 4);
    cmRpcParseUint32(in, &offeredSize);

    if (pShare != NULL)
    {
        /* get printer info */
        printHandle = syGetPrinterHandle(pShare->map);
        if (!syIsValidPrinter(printHandle))
        {
            TRCERR("Unable to find printer by handle");
            TRC1P(" printer: %s", cmWDump(pShare->map));
            TRCE();
            return CM_RP_FAULTINVALIDPRINTERNAME;
        }
    }

    for (i = 0; i < sizeof(printerData) / sizeof(printerData[0]); i++)
    {
        if (   0 == syStrcmp(printerData[i].name, staticData->txtBuffer)
            && printerData[i].server == (pShare == NULL)
           )
        {
            cmRpcPackUint32(out, printerData[i].type);  /* type */
            cmRpcPackUint32(out, offeredSize);  /* size */
            bufferEnd = out->current + offeredSize;
            if (printerData[i].data == NULL)
            {
                needed = (*printerData[i].function)(out);
            }
            else
            {
                needed = printerData[i].size;
                switch (printerData[i].type)
                {
                case TYPE_SZ:
                case TYPE_BINARY:
                    cmRpcPackBytes(out, printerData[i].data, printerData[i].size);
                    break;
                case TYPE_DWORD:
                    cmRpcPackUint32(out, *(NQ_UINT32*)printerData[i].data);
                    break;
                default:
                    TRCERR("Unsupported type");
                    TRC1P("  value: %ld", printerData[i].type);
                    break;
                }
            }
            out->current = bufferEnd;
            cmRpcPackUint32(out, needed);  /* needed */

            TRCE();
            return 0;
        }
    }

    cmRpcPackUint32(out, 0xeab2f8);     /* type - undocumented */
    cmRpcPackUint32(out, offeredSize);  /* size */
    out->current += offeredSize;
    cmRpcPackUint32(out, offeredSize);  /* needed */

    TRCE();
    return CM_RP_FILENOTFOUND;
}

/* Set printer data by keyword */

static NQ_UINT32
spoolssSetPrinterData(
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
)
{
    CMRpcUnicodeString key, value;
    NQ_UINT32 type, offered;
    NQ_CHAR k[32], v[64];

    /* skip flags, entry index and policy handle */
    cmRpcParseSkip(in, 4);
    cmRpcParseSkip(in, 2);
    cmRpcParseSkip(in, sizeof(CMRpcUuid) - 2);

    cmRpcParseUnicode(in, &key, CM_RP_SIZE32 | CM_RP_FRAGMENT32);
    cmUnicodeToAnsiN(k, key.text, (NQ_UINT)(key.length * sizeof(NQ_WCHAR)));
    k[key.length] = '\0';
    cmRpcParseUint32(in, &type);

    switch (type)
    {
        case 1:   /* null terminated string */
            cmRpcParseUnicode(in, &value, CM_RP_SIZE32);
            cmUnicodeToAnsiN(v, value.text, (NQ_UINT)(value.length * sizeof(NQ_WCHAR)));
            v[value.length] = '\0';
            break;

        default:
            break;
    }

    cmRpcParseUint32(in, &offered);
    cmRpcPackUint32(out, 0);

    return 0;
}

/* Set printer information by handle */

static NQ_UINT32
spoolssSetPrinter(
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    NQ_UINT32 infoLevel;            /* requested information level */
    CMRpcPacketDescriptor inTemp;   /* this descriptor points to the beginning of the
                                       output buffer for updating buffer size and referral */
    NQ_UINT16 entryIdx;             /* open entry index */
    CSShare* pShare;                /* pointer to share descriptor */
    NQ_UINT32 size;                 /* object size for different objects */
    SYPrinterHandle printHandle;    /* internal printer handle */
    NQ_BOOL update;                 /* TRUE when printer info has changed */
    CMRpcUnicodeString strDesc;     /* unicode string descriptor */
    NQ_UINT32 newStatus;            /* new printer status */
    NQ_UINT32 serverName, printerName, shareName, portName, driverName, comment;
    NQ_UINT32 location, sepFile, printProc, dataType, parameters;

    TRCB();

    /* parse input parameters */

    cmRpcParseSkip(in, 4);  /* flags */
    cmRpcParseUint16(in, &entryIdx);
    if (entryIdx > UD_CS_SPOOLSS_MAXOPENPRINTERS)
    {
        TRCERR("Open entry index out of range");
        TRC1P(" index: %d", entryIdx);
        TRCE();
        return CM_RP_FAULTCONTEXTMISMATCH;
    }
    if (staticData->openEntries[entryIdx].isFree)
    {
        TRCERR("Open entry index designates a free entry");
        TRC1P(" index: %d", entryIdx);
        TRCE();
        return CM_RP_FAULTCONTEXTMISMATCH;
    }
    pShare = staticData->openEntries[entryIdx].pShare;
    if (pShare == NULL)
    {
        TRCERR("Illegal printer handle in request");
        TRC1P("  value: %d", entryIdx);
        TRCE();
        return CM_RP_FAULTINVALIDPRINTERNAME;
    }

    printHandle = syGetPrinterHandle(pShare->map);
    if (!syIsValidPrinter(printHandle))
    {
        TRCERR("Unable to find printer by handle");
        TRC1P(" printer: %s", cmWDump(pShare->map));
        TRCE();
        return CM_RP_FAULTOTHER;
    }

    if (NQ_FAIL == syGetPrinterInfo(printHandle, &staticData->printInfo))
    {
        TRCERR("Unable to get printer information");
        TRC1P(" printer handle: %d", printHandle);
        TRCE();
        return CM_RP_FAULTOTHER;
    }

    if (!checkAccessToPrinter(printHandle, in, SMB_DESIREDACCESS_PRINTERADMIN))
    {
        TRCERR("Access denied");
        TRC1P(" printer handle: %d", printHandle);
        TRCE();
        return CM_RP_FAULTLOGONFAILURE;
    }

    update = FALSE;
    cmRpcParseSkip(in, sizeof(CMRpcUuid) - 2);
    cmRpcParseUint32(in, &infoLevel);
    cmRpcParseUint32(in, &infoLevel);           /* once again */

    switch (infoLevel)
    {
    case 0:
        cmRpcParseSkip(in, 4 * 5);  /* undocumented */
        cmRpcParseUint32(in, &size);/* printer command */
        if (NQ_FAIL == syControlPrinter(printHandle, size))
        {
            TRCERR("Unable to perform printer command");
            TRC2P(" printer handle: %d, command: %ld", printHandle, size);
            TRCE();
            return CM_RP_FAULTOTHER;
        }

        break;
    case 2:
        cmRpcParseSkip(in, 4);      /* buffer pointer */
        cmRpcParseUint32(in, &serverName);
        cmRpcParseUint32(in, &printerName);
        cmRpcParseUint32(in, &shareName);
        cmRpcParseUint32(in, &portName);
        cmRpcParseUint32(in, &driverName);
        cmRpcParseUint32(in, &comment);
        cmRpcParseUint32(in, &location);
        cmRpcParseUint32(in, &size);/* devmode pointer */
        if (0 != size)
        {
            TRCERR("Dev mode is not supported for info level 2");
            TRC1P(" printer handle: %d", printHandle);
            TRCE();
            return CM_RP_FAULTOTHER;
        }
        cmRpcParseUint32(in, &sepFile);
        cmRpcParseUint32(in, &printProc);
        cmRpcParseUint32(in, &dataType);
        cmRpcParseUint32(in, &parameters);
        cmRpcParseUint32(in, &size);/* sec descriptor pointer */
        if (0 != size)
        {
            TRCERR("Security descriptor is not supported for info level 2");
            TRC1P(" printer handle: %d", printHandle);
            TRCE();
            return CM_RP_FAULTOTHER;
        }
        cmRpcParseUint32(in, &staticData->printInfo.attributes);
        cmRpcParseUint32(in, &staticData->printInfo.priority);
        cmRpcParseUint32(in, &staticData->printInfo.defaultPriority);
        cmRpcParseUint32(in, &staticData->printInfo.startTime);
        cmRpcParseUint32(in, &staticData->printInfo.untilTime);
        cmRpcParseUint32(in, &newStatus);
        staticData->printInfo.status = newStatus | (PRINTERSTATUS_INTERNALYSAVED & staticData->printInfo.status); 
        cmRpcParseUint32(in, &staticData->printInfo.cJobs);
        cmRpcParseUint32(in, &staticData->printInfo.averagePpm);
        if (serverName  != 0)   cmRpcParseUnicode(in, &strDesc, (CM_RP_SIZE32 | CM_RP_FRAGMENT32)); 
        if (printerName != 0)   cmRpcParseUnicode(in, &strDesc, (CM_RP_SIZE32 | CM_RP_FRAGMENT32));
        if (shareName   != 0)   cmRpcParseUnicode(in, &strDesc, (CM_RP_SIZE32 | CM_RP_FRAGMENT32));
        if (portName    != 0)   cmRpcParseUnicode(in, &strDesc, (CM_RP_SIZE32 | CM_RP_FRAGMENT32));
        if (driverName  != 0)   cmRpcParseUnicode(in, &strDesc, (CM_RP_SIZE32 | CM_RP_FRAGMENT32));
        if (comment != 0)     
        {
            cmRpcParseUnicode(in, &strDesc, (CM_RP_SIZE32 | CM_RP_FRAGMENT32));
            if (NULL != staticData->printInfo.comment)
            {
                syWStrncpy(staticData->printInfo.comment, strDesc.text, UD_FS_MAXDESCRIPTIONLEN);
            }
        }
        if (location != 0)    
        {
            cmRpcParseUnicode(in, &strDesc, (CM_RP_SIZE32 | CM_RP_FRAGMENT32));
            if (NULL != staticData->printInfo.location)
            {
                syWStrncpy(staticData->printInfo.location, strDesc.text, UD_FS_MAXDESCRIPTIONLEN);
            }
        }
        if (sepFile != 0)
        {
            cmRpcParseUnicode(in, &strDesc, (CM_RP_SIZE32 | CM_RP_FRAGMENT32));
            if (NULL != staticData->printInfo.sepFile)
            {
                syWStrncpy(staticData->printInfo.sepFile, strDesc.text, UD_FS_MAXPATHLEN);
            }
        }
        if (printProc != 0)
        {
           cmRpcParseUnicode(in, &strDesc, (CM_RP_SIZE32 | CM_RP_FRAGMENT32));
            if (NULL != staticData->printInfo.printProcessor)
            {
                syWStrncpy(staticData->printInfo.printProcessor, strDesc.text, UD_FS_MAXDESCRIPTIONLEN);
            }
        }
        if (dataType != 0)
        {
            cmRpcParseUnicode(in, &strDesc, (CM_RP_SIZE32 | CM_RP_FRAGMENT32));
            if (NULL != staticData->printInfo.dataType)
            {
                syWStrncpy(staticData->printInfo.dataType, strDesc.text, UD_FS_MAXDESCRIPTIONLEN);
            }
        }
        if (parameters != 0)
        {
            cmRpcParseUnicode(in, &strDesc, (CM_RP_SIZE32 | CM_RP_FRAGMENT32));
            if (NULL != staticData->printInfo.parameters)
            {
                syWStrncpy(staticData->printInfo.parameters, strDesc.text, UD_FS_MAXDESCRIPTIONLEN);
            }
        }
        update = TRUE;
        break;
    case 3:
        cmRpcParseSkip(in, 4);      /* devmode container pointer */
        cmRpcParseSkip(in, 4);      /* security descriptor container pointer */
        cmRpcParseUint32(in, &size);/* devmode size */
        if (size > 0)
        {
            cmRpcCloneDescriptor(in, &inTemp);
            parseDevMode(&inTemp, size, &staticData->printInfo.devMode);
            update = TRUE;
            cmRpcParseSkip(in, size);   /* skip devmode */
        }
        else
        {
            cmRpcParseSkip(in, 4);  /* null devmode pointer */
        }
        cmRpcParseUint32(in, &size);
        if (size > 0)
        {
            cmRpcParseSkip(in, 4);  /* ref id */
            cmRpcParseSkip(in, 4);  /* sd length */
            cmSdParseSecurityDescriptor(in, &staticData->sd);                /* security descriptor size */
            if (NQ_FAIL == syPrinterSetSecurityDescriptor(printHandle, staticData->sd.data, staticData->sd.length))
            {
                TRCERR("Unable to set printer security descriptor");
                TRC1P(" printer handle: %d", printHandle);
                TRCE();
                return CM_RP_FAULTOTHER;
            }
        }
        else
        {
            cmRpcParseSkip(in, 4);  /* null sec desc pointer */
        }
        break;
    default:
        return CM_RP_FAULTUNSUPPORTED;
    }

    if (update)
    {
        if (NQ_FAIL == sySetPrinterInfo(printHandle, &staticData->printInfo))
        {
            TRCERR("Unable to set printer information");
            TRC1P(" printer handle: %d", printHandle);
            TRCE();
            return CM_RP_FAULTOTHER;
        }
    }

    /* compose response */

    if (NQ_FAIL == syGetPrinterInfo(printHandle, &staticData->printInfo))
    {
        TRCERR("Unable to get printer information");
        TRC1P(" printer handle: %d", printHandle);
        TRCE();
        return CM_RP_FAULTOTHER;
    }

    staticData->changeId++;
    /* the next line should not be here at least for level 0 */
    /* cmRpcPackUint32(out, staticData->printInfo.status); */
    TRCE();
    return 0;
}

/* First Change Notify */

static NQ_UINT32
spoolssRemoteFindFirstPrinterChangeNotifyEx(
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    TRCB();
    TRCE();
    return CM_RP_SERVER_UNAVAILABLE;
}

/* Next Change Notify */

static NQ_UINT32
spoolssRemoteFindNextPrinterChangeNotifyEx(
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    /*SYPrinterHandle h;
    NQ_UINT32 refID = 1;
    NQ_STATUS result;*/

    TRCB();

#if 1
    TRCE();
    return CM_RP_INVALIDFID;

#else    
    if ((result = getPrinterShare(in, NULL, NULL, &h, TRUE)) == NQ_SUCCESS)
    {
        SYPrinterInfo info;

        if (syGetPrinterInfo(h, &info) == NQ_FAIL)
        {
            TRCERR("Unable to get printer information");
            TRC1P(" printer handle: %d", (NQ_INT)h);
            TRCE();
            return CM_RP_FAULTOTHER;
        }

        /* notify info header - only about status for now */
        cmRpcPackUint32(out, refID++);      /* notify pointer */
        cmRpcPackUint32(out, 1);            /* max count */
        cmRpcPackUint32(out, 2);            /* version 2 */
        cmRpcPackUint32(out, 0);            /* flags */
        cmRpcPackUint32(out, 1);            /* count - 1 notification only */
        /* printer notify - status information */
        cmRpcPackUint16(out, 0);            /* notification type - printer notify */
        cmRpcPackUint16(out, 18);           /* field - 18 (printer status) */
        cmRpcPackUint32(out, 1);            /* count */
        cmRpcPackUint32(out, 6);            /* job ID? - 6 */
        cmRpcPackUint32(out, 1);            /* count */
        cmRpcPackUint32(out, info.status);  /* printer status */
        cmRpcPackUint32(out, 0);            /* undocumented */
    }
    else
    {
        cmRpcPackUint32(out, 0);            /* NULL pointer */
    }
    TRCE();
    return result;
#endif
}

/* Close notification */

static NQ_UINT32 
spoolssFindClosePrinterNotify(
        CMRpcPacketDescriptor* in, 
        CMRpcPacketDescriptor* out
        )
{
    TRCB();

    TRCE();
    return 0;
}

/* Get driver information by handle */

static NQ_UINT32
spoolssGetPrinterDriver2(
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    CMRpcUnicodeString unicodeOsName;   /* requested OS name in Unicode */
    NQ_UINT32 infoLevel;            /* requested information level */
    CMRpcPacketDescriptor outTemp;  /* this descriptor points to the beginning of the
                                       output buffer for updating buffer size and referral */
    NQ_BYTE* bufferEnd;             /* saved pointer to the buffer end */
    NQ_UINT32 status;               /* entry status */
    NQ_UINT16 entryIdx;             /* open entry index */
    const CSShare* pShare;          /* pointer to share descriptor */
    NQ_UINT32 offeredSize;          /* offered buffer size */
    NQ_WCHAR* stringPointer;        /* pointer for placing strings */
    NQ_UINT32 referentId;           /* running number */
    const NQ_CHAR* serverIp;        /* pointer to server IP */

    TRCB();

    /* buffer descriptor for filling with data */
    cmRpcCloneDescriptor(out, &outTemp);

    /* start parsing */
    cmRpcParseSkip(in, 4);  /* flags */
    cmRpcParseUint16(in, &entryIdx);
    cmRpcPackUint32(out, 0);                /* NULL buffer ref id meanwhile */
    if (entryIdx > UD_CS_SPOOLSS_MAXOPENPRINTERS || staticData->openEntries[entryIdx].isFree)
    {
        TRCERR("Open entry index out of range or designates a free entry");
        TRC1P(" index: %d", entryIdx);

        cmRpcPackUint32(out, 0);  /* needed */
        cmRpcPackUint32(out, CM_SOFTWAREVERSIONMAJOR);
        cmRpcPackUint32(out, CM_SOFTWAREVERSIONMINOR);
        TRCE();
        return CM_RP_FAULTCONTEXTMISMATCH;
    }
    pShare = staticData->openEntries[entryIdx].pShare;
    if (pShare == NULL)
    {
        cmRpcPackUint32(out, 0);           /* buffer pointer */
        cmRpcPackUint32(out, 0);           /* needed */
        TRCERR("Illegal printer handle in request");
        TRC1P("  value: %d", entryIdx);

        cmRpcPackUint32(out, 0);  /* needed */
        cmRpcPackUint32(out, CM_SOFTWAREVERSIONMAJOR);
        cmRpcPackUint32(out, CM_SOFTWAREVERSIONMINOR);
        TRCE();
        return CM_RP_FAULTINVALIDPRINTERNAME;
    }

    cmRpcParseSkip(in, sizeof(CMRpcUuid) - 2);
    cmRpcParseSkip(in, 4);  /* ref id for OS name */
    cmRpcParseUnicode(in, &unicodeOsName, CM_RP_SIZE32 | CM_RP_FRAGMENT32);
    cmUnicodeToAnsiN(staticData->txtBuffer, unicodeOsName.text, (NQ_UINT)(unicodeOsName.length * sizeof(NQ_WCHAR)));
    staticData->txtBuffer[unicodeOsName.length] = '\0';
    cmRpcParseUint32(in, &infoLevel);
    cmRpcParseSkip(in, 4);    /* buffer referent ID */
    cmRpcParseUint32(in, &offeredSize);
    if (offeredSize > out->length)
    {
        TRCERR("Offered buffer is too big");

        cmRpcPackUint32(out, 0);  /* needed */
        cmRpcPackUint32(out, CM_SOFTWAREVERSIONMAJOR);
        cmRpcPackUint32(out, CM_SOFTWAREVERSIONMINOR);
        TRCE();
        return CM_RP_OUTOFMEMORY;
    }

    /* zero buffer (my be required by MS) */
    cmRpcPackUint32(out, 0);                /* ref id */
    syMemset(out->current, 0, offeredSize);

    /* prepare results */

    referentId = 2;                             /* an arbitrary value */

    /* pack the result header */

    bufferEnd = out->current + offeredSize; /* start strings from the end of the buffer */
    stringPointer = (NQ_WCHAR*)bufferEnd;

    syAnsiToUnicode(staticData->txtBufferW, staticData->txtBuffer);
    serverIp = staticData->openEntries[entryIdx].isIpAsServerName ? staticData->openEntries[entryIdx].ipServer : NULL;
    status = enumDriverEntry(in, out, staticData->txtBufferW, infoLevel, pShare, &stringPointer, serverIp);
    if (status == 0)
    {
        if ((NQ_BYTE*)stringPointer < out->current)
        {
            NQ_UINT32 neededSize = (NQ_UINT32)(100 + offeredSize + (NQ_UINT32)(out->current - (NQ_BYTE*)stringPointer));

            neededSize = (neededSize + 3) & (NQ_UINT32)~3;
            cmRpcPackUint32(&outTemp, 0);            /* buffer ref id */
            cmRpcPackUint32(&outTemp, neededSize);   /* needed */
            out->current = outTemp.current;
            return CM_RP_INSUFFICIENTBUFFER;
        }

        cmRpcPackUint32(&outTemp, referentId++); /* buffer ref id */
        cmRpcPackUint32(&outTemp, offeredSize);  /* buffer size */
        out->current = bufferEnd;
        cmRpcPackUint32(out, offeredSize);  /* needed */
    }
    else
    {
        out->current = outTemp.current;
        cmRpcPackUint32(out, referentId++);     /* buffer ref id */
        cmRpcPackUint32(out, offeredSize);      /* buffer size */
        out->current += offeredSize;            /* empty buffer */
        cmRpcPackUint32(out, 0);                /* needed */
    }
    cmRpcPackUint32(out, CM_SOFTWAREVERSIONMAJOR);
    cmRpcPackUint32(out, CM_SOFTWAREVERSIONMINOR);
    TRCE();
    return status ;
}

/* Add print job */
static NQ_UINT32
spoolssAddJob(
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    TRCB();
    TRCE();
    return CM_RP_FAULTINVALIDPARAMETER;
}

/* Start print job */
static NQ_UINT32
spoolssStartDocPrinter(
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    CMRpcUnicodeString nextName;    /* for converting Unicode to filesystem encoding */
    NQ_UINT32 infoLevel;            /* requested information level */
    NQ_UINT16 entryIdx;             /* open entry index */
    const CSShare* pShare;          /* pointer to share descriptor */
    NQ_BOOL hasDataType;            /* whether this request specifies data type */
    NQ_UINT32 refId;                /* next referent ID */
    NQ_UINT32 jobId;                /* new JobID */
    SYPrinterHandle printHandle;    /* system printer handle */

    TRCB();

    /* parse input parameters */

    cmRpcParseSkip(in, 4);  /* flags */
    cmRpcParseUint16(in, &entryIdx);
    if (entryIdx > UD_CS_SPOOLSS_MAXOPENPRINTERS)
    {
        TRCERR("Open entry index out of range");
        TRC1P(" index: %d", entryIdx);
        TRCE();
        return CM_RP_FAULTCONTEXTMISMATCH;
    }
    if (staticData->openEntries[entryIdx].isFree)
    {
        TRCERR("Open entry index designates a free entry");
        TRC1P(" index: %d", entryIdx);
        TRCE();
        return CM_RP_FAULTCONTEXTMISMATCH;
    }
    pShare = staticData->openEntries[entryIdx].pShare;
    if (pShare == NULL)
    {
        TRCERR("Illegal printer handle in request");
        TRC1P("  value: %d", entryIdx);
        TRCE();
        return CM_RP_FAULTINVALIDPRINTERNAME;
    }
    printHandle = syGetPrinterHandle(pShare->map);
    if (!syIsValidPrinter(printHandle))
    {
        TRCERR("Unable to find printer by handle");
        TRC1P(" printer: %s", cmWDump(pShare->map));
        TRCE();
        return CM_RP_FAULTINVALIDPRINTERNAME;
    }

    /* generate default SD */
    cmSdGetDefaultSecurityDescriptorByToken((CMSdAccessToken*)in->token, &staticData->sd);

    /* generate response */
    cmRpcParseSkip(in, sizeof(CMRpcUuid) - 2);  /* rest of the policy handle */
    cmRpcParseUint32(in, &infoLevel);
    cmRpcParseUint32(in, &infoLevel);       /* twice */

    switch (infoLevel)
    {
    case 1:
    case 2:
    {
    	NQ_UINT32	docNameId , fileNameId;

        cmRpcParseSkip(in, 4);  /* ref id for Doc Info structure */
        cmRpcParseUint32(in, &docNameId);  /* ref id for Doc name */
        cmRpcParseUint32(in, &fileNameId);  /* ref id for File name */
        cmRpcParseUint32(in, &refId);
        if (infoLevel == 2)
        {
            cmRpcParseSkip(in, 4);  /* dwMode */
            cmRpcParseSkip(in, 4);  /* jobId */
        }
        hasDataType = refId != 0;
        if (docNameId != 0)
        {
			cmRpcParseUnicode(in, &nextName, CM_RP_SIZE32 | CM_RP_FRAGMENT32);
			syWStrncpy(staticData->fullNameW, nextName.text, nextName.length);  /* document name */
			staticData->fullNameW[nextName.length] = cmWChar(0);
        }
        if (fileNameId != 0)
        {
			cmRpcAllign(in, 4);
			cmRpcParseUnicode(in, &nextName, CM_RP_SIZE32 | CM_RP_FRAGMENT32);
			syWStrncpy(staticData->txtBufferW, nextName.text, nextName.length); /* file name */
			staticData->txtBufferW[nextName.length] = cmWChar(0);
        }

        syWStrcpy(staticData->fileNameW, pShare->map);
        if (syWStrlen(staticData->txtBufferW) > 0)
        {
            staticData->fileNameW[syWStrlen(staticData->fileNameW)] = cmWChar(SY_PATHSEPARATOR);
            staticData->fileNameW[syWStrlen(staticData->fileNameW) + 1] = cmWChar(0);
            syWStrcat(staticData->fileNameW, staticData->txtBufferW);
        }
        cmRpcAllign(in, 4);
        if (hasDataType)
        {
            cmRpcParseUnicode(in, &nextName, CM_RP_SIZE32 | CM_RP_FRAGMENT32);
            syWStrncpy(staticData->txtBufferW, nextName.text, nextName.length); /* data type */
            staticData->txtBufferW[nextName.length] = cmWChar(0);

            jobId = syStartPrintJob(printHandle, staticData->fullNameW, staticData->fileNameW, staticData->txtBufferW, (NQ_BYTE*)&staticData->sd.data, (NQ_COUNT)staticData->sd.length, in->user);
        }
        else
        {
            jobId = syStartPrintJob(printHandle, staticData->fullNameW, staticData->fileNameW, NULL, staticData->sd.data, (NQ_COUNT)staticData->sd.length, in->user);
        }
        staticData->openEntries[entryIdx].jobId = jobId;
        break;
    }
    default:
        return CM_RP_FAULTUNSUPPORTED;
    }

    cmRpcPackUint32(out, jobId);
    TRCE();
    return jobId == (NQ_UINT32)-1? CM_RP_FAULTUNSUPPORTED : 0;
}

/* Reset printer - do nothing */
static NQ_UINT32
spoolssResetPrinter(
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    NQ_UINT16 entryIdx;             /* open entry index */
    const CSShare* pShare;          /* pointer to share descriptor */
    SYPrinterHandle printHandle;    /* system printer handle */

    TRCB();

    /* parse input parameters */

    cmRpcParseSkip(in, 4);  /* flags */
    cmRpcParseUint16(in, &entryIdx);
    if (entryIdx > UD_CS_SPOOLSS_MAXOPENPRINTERS)
    {
        TRCERR("Open entry index out of range");
        TRC1P(" index: %d", entryIdx);
        TRCE();
        return CM_RP_FAULTCONTEXTMISMATCH;
    }
    if (staticData->openEntries[entryIdx].isFree)
    {
        TRCERR("Open entry index designates a free entry");
        TRC1P(" index: %d", entryIdx);
        TRCE();
        return CM_RP_FAULTCONTEXTMISMATCH;
    }
    pShare = staticData->openEntries[entryIdx].pShare;
    if (pShare == NULL)
    {
        TRCERR("Illegal printer handle in request");
        TRC1P("  value: %d", entryIdx);
        TRCE();
        return CM_RP_FAULTINVALIDPRINTERNAME;
    }
    printHandle = syGetPrinterHandle(pShare->map);
    if (!syIsValidPrinter(printHandle))
    {
        TRCERR("Unable to find printer by handle");
        TRC1P(" printer: %s", cmWDump(pShare->map));
        TRCE();
        return CM_RP_FAULTINVALIDPRINTERNAME;
    }

    TRCE();
    return 0;
}

/* End print job */

static NQ_UINT32
spoolssEndDocPrinter(
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    SYPrinterHandle printHandle;    /* system printer handle */
    NQ_UINT16 entryIdx;             /* open entry index */
    const CSShare* pShare;          /* pointer to share descriptor */
    NQ_STATUS status;               /* call status */

    TRCB();

    /* parse input parameters */

    cmRpcParseSkip(in, 4);  /* flags */
    cmRpcParseUint16(in, &entryIdx);
    if (entryIdx > UD_CS_SPOOLSS_MAXOPENPRINTERS)
    {
        TRCERR("Open entry index out of range");
        TRC1P(" index: %d", entryIdx);
        TRCE();
        return CM_RP_FAULTCONTEXTMISMATCH;
    }
    if (staticData->openEntries[entryIdx].isFree)
    {
        TRCERR("Open entry index designates a free entry");
        TRC1P(" index: %d", entryIdx);
        TRCE();
        return CM_RP_FAULTCONTEXTMISMATCH;
    }
    pShare = staticData->openEntries[entryIdx].pShare;
    if (pShare == NULL)
    {
        TRCERR("Illegal printer handle in request");
        TRC1P("  value: %d", entryIdx);
        TRCE();
        return CM_RP_FAULTINVALIDPRINTERNAME;
    }
    printHandle = syGetPrinterHandle(pShare->map);
    if (!syIsValidPrinter(printHandle))
    {
        TRCERR("Unable to find printer by handle");
        TRC1P(" printer: %s", cmWDump(pShare->map));
        TRCE();
        return CM_RP_FAULTINVALIDPRINTERNAME;
    }

    status = syEndPrintJob(printHandle, staticData->openEntries[entryIdx].jobId);
    staticData->openEntries[entryIdx].jobId = 0;
    TRCE();
    return status == NQ_FAIL ? CM_RP_FAULTOBJECTNOTFOUND : 0;
}

/* Start new page */

static NQ_UINT32
spoolssStartPagePrinter(
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    SYPrinterHandle printHandle;    /* system printer handle */
    NQ_UINT16 entryIdx;             /* open entry index */
    const CSShare* pShare;          /* pointer to share descriptor */
    NQ_STATUS status;               /* call status */

    TRCB();

    /* parse input parameters */

    cmRpcParseSkip(in, 4);  /* flags */
    cmRpcParseUint16(in, &entryIdx);
    if (entryIdx > UD_CS_SPOOLSS_MAXOPENPRINTERS)
    {
        TRCERR("Open entry index out of range");
        TRC1P(" index: %d", entryIdx);
        TRCE();
        return CM_RP_FAULTCONTEXTMISMATCH;
    }
    if (staticData->openEntries[entryIdx].isFree)
    {
        TRCERR("Open entry index designates a free entry");
        TRC1P(" index: %d", entryIdx);
        TRCE();
        return CM_RP_FAULTCONTEXTMISMATCH;
    }
    pShare = staticData->openEntries[entryIdx].pShare;
    if (pShare == NULL)
    {
        TRCERR("Illegal printer handle in request");
        TRC1P("  value: %d", entryIdx);
        TRCE();
        return CM_RP_FAULTINVALIDPRINTERNAME;
    }
    printHandle = syGetPrinterHandle(pShare->map);
    if (!syIsValidPrinter(printHandle))
    {
        TRCERR("Unable to find printer by handle");
        TRC1P(" printer: %s", cmWDump(pShare->map));
        TRCE();
        return CM_RP_FAULTINVALIDPRINTERNAME;
    }

    status = syStartPrintPage(printHandle, staticData->openEntries[entryIdx].jobId);
    TRCE();
    return status == NQ_FAIL ? CM_RP_FAULTOBJECTNOTFOUND : 0;
}

/* End page */

static NQ_UINT32
spoolssEndPagePrinter(
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    SYPrinterHandle printHandle;    /* system printer handle */
    NQ_UINT16 entryIdx;             /* open entry index */
    const CSShare* pShare;          /* pointer to share descriptor */
    NQ_STATUS status;               /* call status */

    TRCB();

    /* parse input parameters */

    cmRpcParseSkip(in, 4);  /* flags */
    cmRpcParseUint16(in, &entryIdx);
    if (entryIdx > UD_CS_SPOOLSS_MAXOPENPRINTERS)
    {
        TRCERR("Open entry index out of range");
        TRC1P(" index: %d", entryIdx);
        TRCE();
        return CM_RP_FAULTCONTEXTMISMATCH;
    }
    if (staticData->openEntries[entryIdx].isFree)
    {
        TRCERR("Open entry index designates a free entry");
        TRC1P(" index: %d", entryIdx);
        TRCE();
        return CM_RP_FAULTCONTEXTMISMATCH;
    }
    pShare = staticData->openEntries[entryIdx].pShare;
    if (pShare == NULL)
    {
        TRCERR("Illegal printer handle in request");
        TRC1P("  value: %d", entryIdx);
        TRCE();
        return CM_RP_FAULTINVALIDPRINTERNAME;
    }
    printHandle = syGetPrinterHandle(pShare->map);
    if (!syIsValidPrinter(printHandle))
    {
        TRCERR("Unable to find printer by handle");
        TRC1P(" printer: %s", cmWDump(pShare->map));
        TRCE();
        return CM_RP_FAULTINVALIDPRINTERNAME;
    }

    status = syEndPrintPage(printHandle, staticData->openEntries[entryIdx].jobId);
    TRCE();
    return status == NQ_FAIL ? CM_RP_FAULTOBJECTNOTFOUND : 0;
}

static NQ_UINT32
spoolssAbortPrinter(
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    NQ_INT16 entry;
    SYPrinterHandle h;
    NQ_STATUS result;

    TRCB();

    if ((result = getPrinterShare(in, &entry, NULL, &h, FALSE)) == NQ_SUCCESS)
    {
        result = syControlPrinter(h, SY_PRINTERCONTROL_PURGE);
    }

    TRCE();
    return (NQ_UINT32)result;
}

/* Print data portion */

static NQ_UINT32
spoolssWritePrinter(
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    SYPrinterHandle printHandle;    /* system printer handle */
    NQ_UINT16 entryIdx;             /* open entry index */
    const CSShare* pShare;          /* pointer to share descriptor */
    NQ_INT32 length;                /* data length */
    CSDcerpcResponseContext *rctx = NULL;   /* casted late response context */
    void *p = NULL;                         /* late response context pointer */

    TRCB();

    /* parse input parameters */

    cmRpcParseSkip(in, 4);  /* flags */
    cmRpcParseUint16(in, &entryIdx);
    if (entryIdx > UD_CS_SPOOLSS_MAXOPENPRINTERS)
    {
        TRCERR("Open entry index out of range");
        TRC1P(" index: %d", entryIdx);
        TRCE();
        return CM_RP_FAULTCONTEXTMISMATCH;
    }
    if (staticData->openEntries[entryIdx].isFree)
    {
        TRCERR("Open entry index designates a free entry");
        TRC1P(" index: %d", entryIdx);
        TRCE();
        return CM_RP_FAULTCONTEXTMISMATCH;
    }
    pShare = staticData->openEntries[entryIdx].pShare;
    if (pShare == NULL)
    {
        TRCERR("Illegal printer handle in request");
        TRC1P("  value: %d", entryIdx);
        TRCE();
        return CM_RP_FAULTINVALIDPRINTERNAME;
    }
    printHandle = syGetPrinterHandle(pShare->map);
    if (!syIsValidPrinter(printHandle))
    {
        TRCERR("Unable to find printer by handle");
        TRC1P(" printer: %s", cmWDump(pShare->map));
        TRCE();
        return CM_RP_FAULTINVALIDPRINTERNAME;
    }

    cmRpcParseSkip(in, sizeof(CMRpcUuid) - 2);  /* rest of the policy handle */
    cmRpcParseUint32(in, (NQ_UINT32 *)&length);

    length = syWritePrintData(printHandle, staticData->openEntries[entryIdx].jobId,
                              in->current, (NQ_UINT32)length, &p);
    rctx = (CSDcerpcResponseContext *)p;
    
    switch (length)
    {
        case -1:
            /* either job not found or printer write error occured - report 0 bytes writted and 
               print cancelled */
            cmRpcPackUint32(out, 0);
            TRCE();
            return ERROR_PRINTCANCELLED;

        case 0:
            /* 0 bytes written or response has to be delayed */
            if (rctx != NULL)
            {
                /* response has to be delayed */
                csDcerpcSaveResponseContext(TRUE, out, rctx);
                TRCE();
                return SMB_STATUS_NORESPONSE;
            }

        default:
            cmRpcPackUint32(out, (NQ_UINT32)length);
    }

    TRCE();
    return 0;
}

/*
 *====================================================================
 * PURPOSE: calculate length of one entry of EnumPrinters
 *--------------------------------------------------------------------
 * PARAMS:  IN information level
 *          IN pointer to the share
 *          IN pointer to server IP
 * RETURNS: entry length or zero on error
 *
 * NOTES:   a pipe function parses incoming packet and packs outgoing
 *          packet
 *====================================================================
 */

static NQ_UINT32
enumPrinterEntryLength(
    NQ_UINT32 infoLevel,
    const CSShare* pShare,
    const NQ_CHAR* serverIp
    )
{
    SYPrinterHandle printHandle;        /* internal printer handle */
    NQ_UINT32 result = 0;               /* required length */

    TRCB();

    /* get printer info */

    printHandle = syGetPrinterHandle(pShare->map);
    if (!syIsValidPrinter(printHandle))
    {
        TRCERR("Unable to find printer by handle");
        TRC1P(" printer: %s", cmWDump(pShare->map));
        TRCE();
        return 0;
    }
    staticData->sd.length = syPrinterGetSecurityDescriptor(printHandle, staticData->sd.data, sizeof(staticData->sd.data));
    if (0 == staticData->sd.length)
    {
        TRCERR("Unable read printer security descriptor");
        TRCE();
        return 0;
    }

    if (NQ_FAIL == syGetPrinterInfo(printHandle, &staticData->printInfo))
    {
        TRCERR("Unable to get printer information");
        TRC1P(" printer handle: %d", printHandle);
        TRCE();
        return 0;
    }

    switch (infoLevel)
    {
    case 0:
        /* printer name */
        syStrcpy(staticData->txtBuffer, "\\\\");
        syStrcat(staticData->txtBuffer, serverIp ? serverIp : cmNetBiosGetHostNameZeroed());
        syStrcat(staticData->txtBuffer, "\\");
        syAnsiToUnicode(staticData->txtBufferW, staticData->txtBuffer);
        syWStrcat(staticData->txtBufferW, pShare->name);
        result += (NQ_UINT32)(4 + sizeof(NQ_WCHAR) * (cmRpcTcharAsUnicodeLength(staticData->txtBufferW) + 1));
        /* server name */
        syStrcpy(staticData->txtBuffer, "\\\\");
        syStrcat(staticData->txtBuffer, serverIp ? serverIp : cmNetBiosGetHostNameZeroed());
        result += (NQ_UINT32)(4 + sizeof(NQ_WCHAR) * (syStrlen(staticData->txtBuffer) + 1));        
        /* scalars */
        result += 25 * 4 + 2 * 2;
        break;
    case 1:
        result += 4;
        /* name */
        result += (NQ_UINT32)(4 + (pShare->name == NULL? 0:sizeof(NQ_WCHAR) * (cmRpcTcharAsUnicodeLength(pShare->name) + 1)));
        /* description */
        result += (NQ_UINT32)(4 + (pShare->description == NULL? 0:sizeof(NQ_WCHAR) * (cmRpcTcharAsUnicodeLength(pShare->description) + 1)));
        /* comment */
        result += (NQ_UINT32)(4 + (staticData->printInfo.comment == NULL? 0:sizeof(NQ_WCHAR) * (cmRpcTcharAsUnicodeLength(staticData->printInfo.comment) + 1)));
        break;
    case 2:
        /* server name */
        syStrcpy(staticData->txtBuffer, "\\\\");
        syStrcat(staticData->txtBuffer, serverIp ? serverIp : cmNetBiosGetHostNameZeroed());
        result += (NQ_UINT32)(4 + sizeof(NQ_WCHAR) * (syStrlen(staticData->txtBuffer) + 1));
        /* printer name */
        syStrcpy(staticData->txtBuffer, "\\\\");
        syStrcat(staticData->txtBuffer, serverIp ? serverIp : cmNetBiosGetHostNameZeroed());
        syStrcat(staticData->txtBuffer, "\\");
        syAnsiToUnicode(staticData->txtBufferW, staticData->txtBuffer);
        syWStrcat(staticData->txtBufferW, pShare->name);
        result += (NQ_UINT32)(4 + sizeof(NQ_WCHAR) * (cmRpcTcharAsUnicodeLength(staticData->txtBufferW) + 1));
        /* share name */
        result += (NQ_UINT32)(4 + (pShare->name == NULL? 0:sizeof(NQ_WCHAR) * (cmRpcTcharAsUnicodeLength(pShare->name) + 1)));
        /* port name */
        result += (NQ_UINT32)(4 + (staticData->printInfo.portName == NULL? 0:sizeof(NQ_WCHAR) * (cmRpcTcharAsUnicodeLength(staticData->printInfo.portName) + 1)));
        /* driver name */
        result += (NQ_UINT32)(4 + (staticData->printInfo.driverName == NULL? 0:sizeof(NQ_WCHAR) * (cmRpcTcharAsUnicodeLength(staticData->printInfo.driverName) + 1)));
        /* comment */
        result += (NQ_UINT32)(4 + (staticData->printInfo.comment == NULL? 0:sizeof(NQ_WCHAR) * (cmRpcTcharAsUnicodeLength(staticData->printInfo.comment) + 1)));
        /* location */
        result += (NQ_UINT32)(4 + (staticData->printInfo.location == NULL? 0:sizeof(NQ_WCHAR) * (cmRpcTcharAsUnicodeLength(staticData->printInfo.location) + 1)));
        /* devmode */
        result += (NQ_UINT32)(4 + ENUMPRINTERS_DEVMODESIZE + staticData->printInfo.devMode.driverExtraLength);
        /* sepfile */
        result += (NQ_UINT32)(4 + (staticData->printInfo.sepFile == NULL? 0:sizeof(NQ_WCHAR) * (cmRpcTcharAsUnicodeLength(staticData->printInfo.sepFile) + 1)));
        /* print processor */
        result += (NQ_UINT32)(4 + (staticData->printInfo.printProcessor == NULL? 0:sizeof(NQ_WCHAR) * (cmRpcTcharAsUnicodeLength(staticData->printInfo.printProcessor) + 1)));
        /* data type */
        result += (NQ_UINT32)(4 + (staticData->printInfo.dataType == NULL? 0:sizeof(NQ_WCHAR) * (cmRpcTcharAsUnicodeLength(staticData->printInfo.dataType) + 1)));
        /* parameters */
        result += (NQ_UINT32)(4 + (staticData->printInfo.parameters == NULL? 0:sizeof(NQ_WCHAR) * (cmRpcTcharAsUnicodeLength(staticData->printInfo.parameters) + 1)));
        /* security descriptor */
        result += (NQ_UINT32)(4 + staticData->sd.length);
        /* 8 scalars */
        result += 8 * 4;
        break;
    case 3:
        /* security descriptor */
        result += (NQ_UINT32)(4* 2 + staticData->sd.length);
        break;
    case 4:
        /* printer name */
        syStrcpy(staticData->txtBuffer, "\\\\");
        syStrcat(staticData->txtBuffer, serverIp ? serverIp : cmNetBiosGetHostNameZeroed());
        syStrcat(staticData->txtBuffer, "\\");
        syAnsiToUnicode(staticData->txtBufferW, staticData->txtBuffer);
        syWStrcat(staticData->txtBufferW, pShare->name);
        result += (NQ_UINT32)(4 + sizeof(NQ_WCHAR) * (cmRpcTcharAsUnicodeLength(staticData->txtBufferW) + 1));
        /* server name */
        syStrcpy(staticData->txtBuffer, "\\\\");
        syStrcat(staticData->txtBuffer, serverIp ? serverIp : cmNetBiosGetHostNameZeroed());
        syAnsiToUnicode(staticData->txtBufferW, staticData->txtBuffer);
        result += (NQ_UINT32)(4 + sizeof(NQ_WCHAR) * (cmRpcTcharAsUnicodeLength((const NQ_WCHAR*)staticData->txtBufferW) + 1));
        /* attributes */
        result += 4;
        break;
    case 5:
        /* printer name */
        syStrcpy(staticData->txtBuffer, "\\\\");
        syStrcat(staticData->txtBuffer, serverIp ? serverIp : cmNetBiosGetHostNameZeroed());
        syStrcat(staticData->txtBuffer, "\\");
        syAnsiToUnicode(staticData->txtBufferW, staticData->txtBuffer);
        syWStrcat(staticData->txtBufferW, pShare->name);
        result += (NQ_UINT32)(4 + sizeof(NQ_WCHAR) * (syStrlen(staticData->txtBuffer) + 1));
        /* port name */
        result += (NQ_UINT32)(4 + (staticData->printInfo.portName == NULL? 0:sizeof(NQ_WCHAR) * (cmRpcTcharAsUnicodeLength(staticData->printInfo.portName) + 1)));
        /* attributes */
        result += 4;
        /* timeouts */
        result += 2 * 4;
        break;
    default:
        return 0;
    }

    TRCE();
    return result + 16; /* 16 = ref id + buffer size + needed + status */
}

/*
 *====================================================================
 * PURPOSE: place one entry of EnumPrinters
 *--------------------------------------------------------------------
 * PARAMS:  IN incoming packet descriptor
 *          OUT outgoing packet descriptor
 *          IN information level
 *          IN pointer to the share
 *          IN pointer to server IP
 *          IN pointer to the buffer start
 *          IN/OUT running pointer for placing strings
 * RETURNS: zero on success or error code
 *          CM_RP_NQ_FAILTOTHER means cannot access this printer info
 *
 * NOTES:   a pipe function parses incoming packet and packs outgoing
 *          packet
 *====================================================================
 */

static NQ_UINT32
enumPrinterEntry(
    const CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out,
    NQ_UINT32 infoLevel,
    const CSShare* pShare,
    const NQ_CHAR* serverIp,
    NQ_BYTE* bufferStart,
    NQ_WCHAR** buffer
    )
{
    SYPrinterHandle printHandle;        /* internal printer handle */
    NQ_BYTE* tempPtr;                   /* temporary pointer inside descriptor */
    NQ_UINT32 status;                   /* temporary status */
    CMRpcPacketDescriptor outTemp;      /* for placing referenced data */
    NQ_BYTE * devModePtr;               /* devmode pointer location */

    TRCB();

    /* check space according to the largest variant */

    CS_RP_CHECK(out, ENUMPRINTERS_ENTRYSIZE + ENUMPRINTERS_DEVMODESIZE);

    /* get printer info */
    printHandle = syGetPrinterHandle(pShare->map);
    if (!syIsValidPrinter(printHandle))
    {
        TRCERR("Unable to find printer by handle");
        TRC1P(" printer: %s", cmWDump(pShare->map));
        TRCE();
        return CM_RP_FAULTINVALIDPRINTERNAME;
    }

    /* check access to printer */
    if (!checkAccessToPrinter(printHandle, in, SMB_DESIREDACCESS_PRINTERUSE))
    {
        TRCE();
        return CM_RP_FAULTOTHER;
    }

    staticData->sd.length = syPrinterGetSecurityDescriptor(printHandle, staticData->sd.data, sizeof(staticData->sd.data));
    if (staticData->sd.length == 0)
    {
        TRCERR("Unable to get printer security descriptor");
        TRC1P(" printer: %s", cmWDump(pShare->map));
        TRCE();
        return CM_RP_FAULTINVALIDPRINTERNAME;
    }

    if (NQ_FAIL == syGetPrinterInfo(printHandle, &staticData->printInfo))
    {
        TRCERR("Unable to get printer information");
        TRC1P(" printer handle: %d", printHandle);
        TRCE();
        return CM_RP_FAULTINVALIDPRINTERNAME;
    }

    /* place data */

    switch (infoLevel)
    {
    case 0:
        /* printer name */
        syStrcpy(staticData->txtBuffer, "\\\\");
        syStrcat(staticData->txtBuffer, serverIp ? serverIp : cmNetBiosGetHostNameZeroed());
        syStrcat(staticData->txtBuffer, "\\");
        syAnsiToUnicode(staticData->txtBufferW, staticData->txtBuffer);
        syWStrcat(staticData->txtBufferW, pShare->name);
        CS_RP_CALL(placeTcharAsUnicode(out, buffer, bufferStart,  staticData->txtBufferW));
        /* server name */
        syStrcpy(staticData->txtBuffer, "\\\\");
        syStrcat(staticData->txtBuffer, serverIp ? serverIp : cmNetBiosGetHostNameZeroed());
        CS_RP_CALL(placeAsciiAsUnicode(out, buffer, bufferStart, staticData->txtBuffer));
        /* scalars */
        cmRpcPackUint32(out, staticData->printInfo.cJobs);
        cmRpcPackUint32(out, staticData->printInfo.totalJobs);
        cmRpcPackUint32(out, staticData->printInfo.totalBytes);
        /* time (?) */
        packTimePortions(out, staticData->printInfo.startTime);
        /* global counter */
        cmRpcPackUint32(out, staticData->printInfo.globalCounter);
        cmRpcPackUint32(out, staticData->printInfo.totalPages);
        cmRpcPackUint16(out, staticData->printInfo.majorVersion);
        cmRpcPackUint16(out, staticData->printInfo.buildVersion);
        cmRpcPackUint32(out, 1);    /* unknown */
        cmRpcPackUint32(out, 0);    /* unknown */
        cmRpcPackUint32(out, 0);    /* unknown */
        cmRpcPackUint32(out, staticData->printInfo.sessionCounter);
        cmRpcPackUint32(out, 0);    /* unknown */
        cmRpcPackUint32(out, staticData->printInfo.printerErrors);
        cmRpcPackUint32(out, 0);    /* unknown */
        cmRpcPackUint32(out, 1);    /* unknown */
        cmRpcPackUint32(out, 586);  /* unknown */
        cmRpcPackUint32(out, 0);    /* unknown */
        cmRpcPackUint32(out, 0);    /* change ID */
        cmRpcPackUint32(out, 0);    /* unknown */
        cmRpcPackUint32(out, staticData->printInfo.status);
        cmRpcPackUint32(out, 0);    /* unknown */
        cmRpcPackUint32(out, staticData->printInfo.cSetPrinter);
        cmRpcPackUint32(out, 0);    /* unknown */
        cmRpcPackUint32(out, 6);    /* unknown */
        cmRpcPackUint32(out, 0);    /* unknown */
        cmRpcPackUint32(out, 0);    /* unknown */
        cmRpcPackUint32(out, 0);    /* unknown */
        cmRpcPackUint32(out, 0);    /* unknown */
        cmRpcPackUint32(out, 0);    /* unknown */
        cmRpcPackUint32(out, 0);    /* unknown */
        break;
    case 1:
        cmRpcPackUint32(out, staticData->printInfo.flags);
        CS_RP_CALL(placeTcharAsUnicode(out, buffer, bufferStart, pShare->name));         /* name */
        CS_RP_CALL(placeTcharAsUnicode(out, buffer, bufferStart, pShare->description)); /* description */
        CS_RP_CALL(placeTcharAsUnicode(out, buffer, bufferStart, staticData->printInfo.comment));        /* comment */
        break;
    case 2:
        cmRpcCloneDescriptor(out, &outTemp);
        /* server name */
        syStrcpy(staticData->txtBuffer, "\\\\");
        syStrcat(staticData->txtBuffer, serverIp ? serverIp : cmNetBiosGetHostNameZeroed());
        CS_RP_CALL(placeAsciiAsUnicode(out, buffer, bufferStart, staticData->txtBuffer));
        /* printer name */
        syStrcpy(staticData->txtBuffer, "\\\\");
        syStrcat(staticData->txtBuffer, serverIp ? serverIp : cmNetBiosGetHostNameZeroed());
        syStrcat(staticData->txtBuffer, "\\");
        syAnsiToUnicode(staticData->txtBufferW, staticData->txtBuffer);
        syWStrcat(staticData->txtBufferW, pShare->name);
        CS_RP_CALL(placeTcharAsUnicode(out, buffer, bufferStart,  staticData->txtBufferW));
        /* share name */
        CS_RP_CALL(placeTcharAsUnicode(out, buffer, bufferStart, pShare->name));
        /* port name */
        CS_RP_CALL(placeTcharAsUnicode(out, buffer, bufferStart, staticData->printInfo.portName));
        /* driver name */
        CS_RP_CALL(placeTcharAsUnicode(out, buffer, bufferStart, staticData->printInfo.driverName));
        /* comment */
        CS_RP_CALL(placeTcharAsUnicode(out, buffer, bufferStart, staticData->printInfo.comment));
        /* location */
        CS_RP_CALL(placeTcharAsUnicode(out, buffer, bufferStart, staticData->printInfo.location));
        /* device mode */
        devModePtr = out->current;
        cmRpcPackUint32(out, 0);    /* will be set later */
        /* sepfile */
        CS_RP_CALL(placeTcharAsUnicode(out, buffer, bufferStart, staticData->printInfo.sepFile));
        /* print processor */
        CS_RP_CALL(placeTcharAsUnicode(out, buffer, bufferStart, staticData->printInfo.printProcessor));
        /* data type */
        CS_RP_CALL(placeTcharAsUnicode(out, buffer, bufferStart, staticData->printInfo.dataType));
        /* parameters */
        CS_RP_CALL(placeTcharAsUnicode(out, buffer, bufferStart, staticData->printInfo.parameters));
        /* ++ device mode */
        *buffer -= (NQ_UINT)(ENUMPRINTERS_DEVMODESIZE + staticData->printInfo.devMode.driverExtraLength)/sizeof(NQ_WCHAR);
        *buffer = (NQ_WCHAR*)(bufferStart + (((NQ_BYTE*)*buffer - bufferStart) & ~3));  
        tempPtr = out->current;
        out->current = devModePtr;
        cmRpcPackUint32(out, (NQ_UINT32)((NQ_BYTE*)*buffer - bufferStart));
        out->current = tempPtr;
        tempPtr = (NQ_BYTE*)*buffer;
        outTemp.current = (NQ_BYTE*)*buffer;
        status = placeDevMode(
                &outTemp,
                &staticData->printInfo.devMode, 
                pShare,
                serverIp
                );
        if (status != 0)
        {
            TRCE();
            return status;
        }
        *buffer = (NQ_WCHAR*)tempPtr;
        /* -- device mode */
        /* ++ security descriptor */
        /* place it twice - first from the current position just to determine
         * the SD length. Then, place it for real backwards from the last referenced data
         */
        outTemp.current = out->current;
        cmSdPackSecurityDescriptor(&outTemp, &staticData->sd, 0x0f);
        syMemset(out->current,0, (NQ_UINT32)(outTemp.current - out->current));       
        *buffer -= (NQ_UINT)(outTemp.current - out->current)/sizeof(NQ_WCHAR); 
        *buffer = (NQ_WCHAR*)(bufferStart + (((NQ_BYTE*)*buffer - bufferStart) & ~3));
        cmRpcPackUint32(out, (NQ_UINT32)((NQ_BYTE*)*buffer - bufferStart));
        tempPtr = (NQ_BYTE*)*buffer;
        outTemp.current = (NQ_BYTE*)*buffer;
        cmSdPackSecurityDescriptor(&outTemp, &staticData->sd, 0x0f);
        *buffer = (NQ_WCHAR*)tempPtr;
        /* -- security descriptor */
        /* scalars */
        cmRpcPackUint32(out, 0x1048 /*staticData->printInfo.attributes*/ );
        cmRpcPackUint32(out, staticData->printInfo.priority);
        cmRpcPackUint32(out, staticData->printInfo.defaultPriority);
        cmRpcPackUint32(out, staticData->printInfo.startTime);
        cmRpcPackUint32(out, staticData->printInfo.untilTime);
        cmRpcPackUint32(out, staticData->printInfo.status);
        cmRpcPackUint32(out, staticData->printInfo.cJobs);
        cmRpcPackUint32(out, staticData->printInfo.averagePpm);
        break;
    case 3:
        tempPtr = out->current + 4;
        cmRpcPackUint32(out, (NQ_UINT32)(tempPtr - bufferStart));
        cmSdPackSecurityDescriptor(out, &staticData->sd, 0x0f);
        break;
    case 4:
        /* printer name */
        syStrcpy(staticData->txtBuffer, "\\\\");
        syStrcat(staticData->txtBuffer, serverIp ? serverIp : cmNetBiosGetHostNameZeroed());
        syStrcat(staticData->txtBuffer, "\\");
        syAnsiToUnicode(staticData->txtBufferW, staticData->txtBuffer);
        syWStrcat(staticData->txtBufferW, pShare->name);
        CS_RP_CALL(placeTcharAsUnicode(out, buffer, bufferStart,  staticData->txtBufferW));
        /* server name */
        syStrcpy(staticData->txtBuffer, "\\\\");
        syStrcat(staticData->txtBuffer, serverIp ? serverIp : cmNetBiosGetHostNameZeroed());
        CS_RP_CALL(placeAsciiAsUnicode(out, buffer, bufferStart, staticData->txtBuffer));
        /* attributes */
        cmRpcPackUint32(out, staticData->printInfo.attributes);
        break;
    case 5:
        /* printer name */
        syStrcpy(staticData->txtBuffer, "\\\\");
        syStrcat(staticData->txtBuffer, serverIp ? serverIp : cmNetBiosGetHostNameZeroed());
        syStrcat(staticData->txtBuffer, "\\");
        syAnsiToUnicode(staticData->txtBufferW, staticData->txtBuffer);
        syWStrcat(staticData->txtBufferW, pShare->name);
        CS_RP_CALL(placeTcharAsUnicode(out, buffer, bufferStart,  staticData->txtBufferW));
        /* port name */
        CS_RP_CALL(placeTcharAsUnicode(out, buffer, bufferStart, staticData->printInfo.portName));
        /* attributes */
        cmRpcPackUint32(out, staticData->printInfo.attributes);
        /* timeouts */
        cmRpcPackUint32(out, staticData->printInfo.deviceNotSelectedTimeout);
        cmRpcPackUint32(out, staticData->printInfo.transmissionRetryTimeout);
        break;
    default:
        return CM_RP_FAULTUNSUPPORTED;
    }
    cmRpcAllignZero(out, 4);

    TRCE();
    return 0;
}

/*
 *====================================================================
 * PURPOSE: calculate length of one entry of EnumForms
 *--------------------------------------------------------------------
 * PARAMS:  IN printer handle
 *          IN form index
 *          IN info level
 * RETURNS: entry length or zero on error
 *
 * NOTES:   a pipe function parses incoming packet and packs outgoing
 *          packet
 *====================================================================
 */

static NQ_UINT32
enumFormEntryLength(
    SYPrinterHandle printHandle,
    NQ_UINT32 formIdx,
    NQ_UINT32 infoLevel
    )
{
    NQ_UINT32 result = 0;               /* required length */

    TRCB();

    /* get form info */

    if (NQ_FAIL == syGetPrintForm(printHandle, formIdx, &staticData->formInfo))
    {
        TRCERR("Unable to get form information");
        TRC1P(" printer handle: %d", printHandle);
        TRCE();
        return 0;
    }

    switch (infoLevel)
    {
    case 1:
        /* form name */
        result += (NQ_UINT32)(4 + sizeof(NQ_WCHAR) * (cmRpcTcharAsUnicodeLength(staticData->formInfo.name) + 1));
        /* scalars */
        result += 4;    /* flags */
        result += (NQ_UINT32)sizeof(SYPrintSize);  /* size */
        result += (NQ_UINT32)sizeof(SYPrintRect);  /* imageable area */
        break;
    default:
        TRCERR("Level not supported");
        TRC1P("  level: %ld", infoLevel);
        TRCE();
        return 0xFFFFFFFF;
    }

    TRCE();
    return result + 10;
}

/*
 *====================================================================
 * PURPOSE: place one entry of EnumForms
 *--------------------------------------------------------------------
 * PARAMS:  OUT outgoing packet descriptor
 *          IN printer handle
 *          IN form index
 *          IN information level
 *          IN pointer to the buffer start
 *          IN/OUT running pointer for placing strings
 * RETURNS: zero on success or error code
 *
 * NOTES:   a pipe function parses incoming packet and packs outgoing
 *          packet
 *====================================================================
 */

static NQ_UINT32
enumFormEntry(
    CMRpcPacketDescriptor* out,
    SYPrinterHandle printHandle,
    NQ_UINT32 formIdx,
    NQ_UINT32 infoLevel,
    NQ_BYTE* bufferStart,
    NQ_WCHAR** buffer
    )
{
    TRCB();

    /* get form info */

    if (NQ_FAIL == syGetPrintForm(printHandle, formIdx, &staticData->formInfo))
    {
        TRC1P(" printer handle: %d", printHandle);
        TRCE();
        return CM_RP_FAULTINVALIDPRINTERNAME;
    }

    /* place data */

    bufferStart = out->current;

    switch (infoLevel)
    {
    case 1:
        /* flags */
        cmRpcPackUint32(out, staticData->formInfo.flags);
        /* form name */
        CS_RP_CALL(placeTcharAsUnicode(out, buffer, bufferStart,  staticData->formInfo.name));
        /* scalars */
        cmRpcPackUint32(out, staticData->formInfo.size.width);
        cmRpcPackUint32(out, staticData->formInfo.size.height);
        cmRpcPackUint32(out, staticData->formInfo.imageableArea.left);
        cmRpcPackUint32(out, staticData->formInfo.imageableArea.top);
        cmRpcPackUint32(out, staticData->formInfo.imageableArea.right);
        cmRpcPackUint32(out, staticData->formInfo.imageableArea.bottom);
        break;
    default:
        TRCERR("Level not supported");
        TRC1P("  level: %ld", infoLevel);
        TRCE();
        return CM_RP_UNKNOWNLEVEL;
    }
    cmRpcAllignZero(out, 4);

    TRCE();
    return 0;
}

/*
 *====================================================================
 * PURPOSE: calculates entry length for EnumJobs
 *--------------------------------------------------------------------
 * PARAMS:  IN incoming packet descriptor
 *          IN job ID
 *          IN printer handle
 *          IN printer information structure
 *          IN information level
 * RETURNS: entry length or zero
 *
 * NOTES:
 *====================================================================
 */

static NQ_UINT32
enumJobEntryLength(
    const CMRpcPacketDescriptor* in,
    const CSShare* pShare,
    NQ_UINT32 jobId,
    SYPrinterHandle printHandle,
    const SYPrinterInfo* printInfo,
    NQ_UINT32 infoLevel,
    const NQ_CHAR *serverIP
    )
{
    NQ_UINT32 result = 0;               /* required length */
    NQ_COUNT secDescLen;                /* security descriptor length */

    TRCB();

    if (syGetPrintJobById(printHandle, jobId, &staticData->jobInfo) == NQ_FAIL)
    {
        TRCE();
        return 0;
    }

    /* check access to job */
    if (!checkAccessToJob(printHandle, jobId, in, SMB_DESIREDACCESS_JOBQUERY))
    {
        TRC("unable to access job");
        return (NQ_UINT32)-1;
    }

    secDescLen = syPrinterGetSecurityDescriptor(printHandle, staticData->sd.data, sizeof(staticData->sd.data));
    if (0 == secDescLen)
    {
        TRCE();
        return 0;
    }

    /* place data */
    switch (infoLevel)
    {
    case 1:
        /* job id */
        result += 4;
        /* printer name */
        result += (NQ_UINT32)(4 + sizeof(NQ_WCHAR) * (cmRpcTcharAsUnicodeLength(pShare->name) + 1));
        /* machine name */
        syStrcpy(staticData->txtBuffer, "\\\\");
        syStrcat(staticData->txtBuffer, serverIP ? serverIP : cmNetBiosGetHostNameZeroed());
        result += (NQ_UINT32)(4 + sizeof(NQ_WCHAR) * (syStrlen(staticData->txtBuffer) + 1));
        /* user name */
        result += 4;
        /* document name */
        result += (NQ_UINT32)(4 + (staticData->jobInfo.documentName == NULL? 0:sizeof(NQ_WCHAR) * (cmRpcTcharAsUnicodeLength(staticData->jobInfo.documentName) + 1)));
        /* data type */
        result += (NQ_UINT32)(4 + (printInfo->dataType == NULL? 0:sizeof(NQ_WCHAR) * (cmRpcTcharAsUnicodeLength(printInfo->dataType) + 1)));
        /* status as text */
        result += (NQ_UINT32)(4 + (staticData->jobInfo.pStatus == NULL? 0:sizeof(NQ_WCHAR) * (cmRpcTcharAsUnicodeLength(staticData->jobInfo.pStatus) + 1)));
        /* data type */
        /* status as code */
        result += 4;
        /* priority */
        result += 4;
        /* position */
        result += 4;
        /* total pages */
        result += 4;
        /* pages printed */
        result += 4;
        /* submit time */
        result += 16;
        break;
    case 4:
        result += 4;    /* size high */
    case 2:
        /* job id */
        result += 4;
        /* printer name */
        result += (NQ_UINT32)(4 + sizeof(NQ_WCHAR) * (cmRpcTcharAsUnicodeLength(pShare->name) + 1));
        /* machine name */
        syStrcpy(staticData->txtBuffer, "\\\\");
        syStrcat(staticData->txtBuffer, serverIP ? serverIP : cmNetBiosGetHostNameZeroed());
        result += (NQ_UINT32)(4 + sizeof(NQ_WCHAR) * (syStrlen(staticData->txtBuffer) + 1));
        /* user name */
        result += 4;
        if (NULL != in->user)
        {
            result += (NQ_UINT32)(sizeof(NQ_WCHAR) * (syWStrlen (((CSUser*)in->user)->name) + 1));
        }
        /* document name */
        result += (NQ_UINT32)(4 + (staticData->jobInfo.documentName == NULL? 0:sizeof(NQ_WCHAR) * (cmRpcTcharAsUnicodeLength(staticData->jobInfo.documentName) + 1)));
        /* notify name */
        result += 4;
        if (NULL != staticData->jobInfo.user)
        {
            result += (NQ_UINT32)(sizeof(NQ_WCHAR) * (syWStrlen (((CSUser*)staticData->jobInfo.user)->name) + 1));
        }
        /* data type */
        result += (NQ_UINT32)(4 + (printInfo->dataType == NULL? 0:sizeof(NQ_WCHAR) * (cmRpcTcharAsUnicodeLength(printInfo->dataType) + 1)));
        /* print processor */
        result += (NQ_UINT32)(4 + (printInfo->printProcessor == NULL? 0:sizeof(NQ_WCHAR) * (cmRpcTcharAsUnicodeLength(printInfo->printProcessor) + 1)));
        /* parameters */
        result += (NQ_UINT32)(4 + (printInfo->parameters == NULL? 0:sizeof(NQ_WCHAR) * (cmRpcTcharAsUnicodeLength(printInfo->parameters) + 1)));
        /* driver name */
        result += (NQ_UINT32)(4 + (printInfo->driverName == NULL? 0:sizeof(NQ_WCHAR) * (cmRpcTcharAsUnicodeLength(printInfo->driverName) + 1)));
        /* devmode */
        result += 4;
        /* status as text */
        result += 4;
        /* security descriptor */
        result += 4  + secDescLen;
        /* status as code */
        result += 4;
        /* priority */
        result += 4;
        /* position */
        result += 4;
        /* start time */
        result += 4;
        /* until time */
        result += 4;
        /* total pages */
        result += 4;
        /* size */
        result += 4;
        /* submit time */
        result += 16;
        /* time */
        result += 4;
        /* pages printed */
        result += 4;
        /* ++ device mode */
        result += (NQ_UINT32)(ENUMPRINTERS_DEVMODESIZE + printInfo->devMode.driverExtraLength + 4);
        /* -- device mode */
        break;
    case 3:
        result = 4 * 4;
        break;
    default:
        TRCE();
        return 0;
    }

    TRCE();
    return result + 20;
}

/*
 *====================================================================
 * PURPOSE: create one entry for EnumJobs
 *--------------------------------------------------------------------
 * PARAMS:  IN incoming packet descriptor
 *          OUT outgoing packet descriptor
 *          IN pointer to share descriptor
 *          IN job ID
 *          IN printer handle
 *          IN printer information structure
 *          IN information level
 *          IN pointer to the buffer start
 *          IN/OUT running pointer for placing strings
 *          IN pointer to server IP
 * RETURNS: zero on success
 *          CM_RP_FAULTOBJECTNOTFOUND on no more entries or error code
 *          CM_RP_FAULTOTHER on an entry that this user does not have access
 *
 * NOTES:   a pipe function parses incoming packet and packs outgoing
 *          packet
 *====================================================================
 */

static NQ_UINT32
enumJobEntry(
    const CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out,
    const CSShare* pShare,
    NQ_UINT32 jobId,
    SYPrinterHandle printHandle,
    const SYPrinterInfo* printInfo,
    NQ_UINT32 infoLevel,
    NQ_BYTE* bufferStart,
    NQ_WCHAR** buffer,
    const NQ_CHAR* serverIp
    )
{
    NQ_BYTE* devModePtr;                /* pointer to the pointer on device mode structure */
    /*NQ_BYTE* secDescPtr; */           /* pointer to the pointer on security descriptor structure */
    NQ_BYTE* tempPtr;                   /* temporary pointer inside descriptor */
    NQ_UINT32 status;                   /* temporary status */

    TRCB();

    if (syGetPrintJobById(printHandle, jobId, &staticData->jobInfo) == NQ_FAIL)
    {
        TRCE();
        return CM_RP_FAULTOBJECTNOTFOUND;
    }

    /* check access to job */
    if (!checkAccessToJob(printHandle, jobId, in, SMB_DESIREDACCESS_JOBQUERY))
    {
        TRC("unable to access job");
        TRCE();
        return CM_RP_FAULTOTHER;
    }

    /* get job SD */
    if (NULL == staticData->jobInfo.securityDescriptor ||
        0 == staticData->jobInfo.securityDescriptorLength ||
        sizeof(staticData->sd.data) < staticData->jobInfo.securityDescriptorLength)
    {
        staticData->sd.length = syPrinterGetSecurityDescriptor(printHandle, staticData->sd.data, sizeof(staticData->sd.data));
        if (staticData->sd.length == 0)
        {
            TRCERR("Unable to get printer security descriptor");
            TRC1P(" printer: %s", cmWDump(pShare->map));
            TRCE();
            return CM_RP_FAULTINVALIDPRINTERNAME;
        }
    }
    else
    {
        staticData->sd.length = staticData->jobInfo.securityDescriptorLength;
        syMemcpy(staticData->sd.data, staticData->jobInfo.securityDescriptor, staticData->jobInfo.securityDescriptorLength);
    }

    /* place data */

    switch (infoLevel)
    {
    case 1:
        /* job id */
        cmRpcPackUint32(out, staticData->jobInfo.id);
        /* printer name */
        CS_RP_CALL(placeTcharAsUnicode(out, buffer, bufferStart,  pShare->name));
        /* machine name */
        syStrcpy(staticData->txtBuffer, "\\\\");
        syStrcat(staticData->txtBuffer, serverIp ? serverIp : cmNetBiosGetHostNameZeroed());
        CS_RP_CALL(placeAsciiAsUnicode(out, buffer, bufferStart, staticData->txtBuffer));
        /* user name */
        cmRpcPackUint32(out, 0);
        /* document name */
        CS_RP_CALL(placeTcharAsUnicode(out, buffer, bufferStart, staticData->jobInfo.documentName));
        /* data type */
        CS_RP_CALL(placeTcharAsUnicode(out, buffer, bufferStart, printInfo->dataType));
        /* status as text */
        CS_RP_CALL(placeTcharAsUnicode(out, buffer, bufferStart, staticData->jobInfo.pStatus));
        /* status as code */
        cmRpcPackUint32(out, staticData->jobInfo.status);
        /* priority */
        cmRpcPackUint32(out, staticData->jobInfo.priority);
        /* position */
        cmRpcPackUint32(out, staticData->jobInfo.position);
        /* total pages */
        cmRpcPackUint32(out, staticData->jobInfo.totalPages);
        /* pages printed */
        cmRpcPackUint32(out, staticData->jobInfo.pagesPrinted);
        /* submit time */
        packTimePortions(out, staticData->jobInfo.submitTime);
        break;
    case 4:
    case 2:
        /* job id */
        cmRpcPackUint32(out, staticData->jobInfo.id);
        /* printer name */
        CS_RP_CALL(placeTcharAsUnicode(out, buffer, bufferStart,  pShare->name));
        /* machine name */
        syStrcpy(staticData->txtBuffer, "\\\\");
        syStrcat(staticData->txtBuffer, serverIp ? serverIp : cmNetBiosGetHostNameZeroed());
        CS_RP_CALL(placeAsciiAsUnicode(out, buffer, bufferStart, staticData->txtBuffer));
        /* user name */
        if (NULL != staticData->jobInfo.user)
        {
            CS_RP_CALL(placeTcharAsUnicode(out, buffer, bufferStart,  ((CSUser*)staticData->jobInfo.user)->name));
        }
        else
        {
            cmRpcPackUint32(out, 0);
        }
        /* document name */
        CS_RP_CALL(placeTcharAsUnicode(out, buffer, bufferStart, staticData->jobInfo.documentName));
        /* notify name */
        if (NULL != in->user)
        {
            CS_RP_CALL(placeTcharAsUnicode(out, buffer, bufferStart,  ((CSUser*)in->user)->name));
        }
        else
        {
            cmRpcPackUint32(out, 0);
        }
        /* data type */
        CS_RP_CALL(placeTcharAsUnicode(out, buffer, bufferStart, printInfo->dataType));
        /* print processor */
        CS_RP_CALL(placeTcharAsUnicode(out, buffer, bufferStart, printInfo->printProcessor));
        /* parameters */
        CS_RP_CALL(placeTcharAsUnicode(out, buffer, bufferStart, printInfo->parameters));
        /* driver name */
        CS_RP_CALL(placeTcharAsUnicode(out, buffer, bufferStart, printInfo->driverName));
        /* devmode */
        devModePtr = out->current;
        cmRpcPackUint32(out, 0);
        /* status as text */
        cmRpcPackUint32(out, 0);
        /* security descriptor */
        /*secDescPtr = out->current;*/
        cmRpcPackUint32(out, 0);
        /* status as code */
        cmRpcPackUint32(out, staticData->jobInfo.status);
        /* priority */
        cmRpcPackUint32(out, staticData->jobInfo.priority);
        /* position */
        cmRpcPackUint32(out, staticData->jobInfo.position);
        /* start time */
        cmRpcPackUint32(out, staticData->jobInfo.startTime);
        /* until time */
        cmRpcPackUint32(out, staticData->jobInfo.untilTime);
        /* total pages */
        cmRpcPackUint32(out, staticData->jobInfo.totalPages);
        /* size */
        cmRpcPackUint32(out, staticData->jobInfo.size);
        /* submit time */
        packTimePortions(out, staticData->jobInfo.submitTime);
        /* time */
        cmRpcPackUint32(out, staticData->jobInfo.time);
        /* pages printed */
        cmRpcPackUint32(out, staticData->jobInfo.pagesPrinted);
        /* size high */
        if (infoLevel == 4)
            cmRpcPackUint32(out, 0);    /* not supported */

        /* ++ device mode */
        *buffer -= (NQ_UINT)(ENUMPRINTERS_DEVMODESIZE + printInfo->devMode.driverExtraLength + 4)/sizeof(NQ_WCHAR);
        tempPtr = out->current;
        out->current = devModePtr;
        cmRpcPackUint32(out, (NQ_UINT32)((NQ_BYTE*)*buffer - bufferStart));
        out->current = (NQ_BYTE*)*buffer;
        status = placeDevMode(out, &printInfo->devMode, pShare, serverIp);
        out->current = tempPtr;
        if (status != 0)
        {
            TRCE();
            return status;
        }
        /* -- device mode */

        /* ++ security descriptor */
/*        *buffer -= staticData->sd.length/sizeof(NQ_WCHAR);
        tempPtr = out->current;
        out->current = secDescPtr;
        cmRpcPackUint32(out, (NQ_BYTE*)*buffer - bufferStart);
        out->current = (NQ_BYTE*)*buffer;
        cmSdPackSecurityDescriptor(out, &staticData->sd, 0x0f);
        out->current = tempPtr;*/
        /* -- security descriptor */
        break;
    case 3:
    {
        NQ_INT32 jobIdx;      /* job index in the queue */

        cmRpcPackUint32(out, staticData->jobInfo.id);   /* job id */
        jobIdx = syGetPrintJobIndexById(printHandle, jobId);
        jobId = (NQ_UINT32)syGetPrintJobIdByIndex(printHandle, (NQ_INT)(jobIdx + 1));
        if (jobId == (NQ_UINT32)NQ_FAIL || syGetPrintJobById(printHandle, (NQ_UINT32)jobId, &staticData->jobInfo) == (NQ_STATUS)NQ_FAIL)
        {
            cmRpcPackUint32(out, 0xFFFFFFFF);
        }
        else
        {
            cmRpcPackUint32(out, staticData->jobInfo.id);   /* next job id */
        }
        cmRpcPackUint32(out, 0);
        break;
    }
    default:
        return CM_RP_FAULTUNSUPPORTED;
    }
    cmRpcAllignZero(out, 4);

    TRCE();
    return 0;
}

/*
 *====================================================================
 * PURPOSE: place one entry of EnumDrivers
 *--------------------------------------------------------------------
 * PARAMS:  IN incoming packet descriptor
 *          OUT outgoing packet descriptor
 *          IN name of required OS
 *          IN information level
 *          IN pointer to the share
 *          IN/OUT running pointer for placing strings
 * RETURNS: zero on success or error code
 *
 * NOTES:   a pipe function parses incoming packet and packs outgoing
 *          packet
 *====================================================================
 */

static NQ_UINT32
enumDriverEntry(
    const CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out,
    const NQ_WCHAR* requiredOS,
    NQ_UINT32 infoLevel,
    const CSShare* pShare,
    NQ_WCHAR** buffer,
    const NQ_CHAR* serverIp
    )
{
    static SYPrinterDriver driverInfo;  /* driver information structure */
    SYPrinterHandle printHandle;        /* internal printer handle */
    NQ_BYTE* bufferStart;               /* pointer to the buffer start */

    TRCB();

    /* check space according to the largest variant */

    CS_RP_CHECK(out, ENUMDRIVERS_ENTRYSIZE);

    /* get driver info */
    printHandle = syGetPrinterHandle(pShare->map);
    if (!syIsValidPrinter(printHandle))
    {
        TRCERR("Unable to find printer by handle");
        TRC1P(" printer: %s", cmWDump(pShare->map));
        TRCE();
        return CM_RP_FAULTINVALIDPRINTERNAME;
    }

    /* check access to printer */
    if (!checkAccessToPrinter(printHandle, in, SMB_DESIREDACCESS_PRINTERUSE))
    {
        TRCE();
        return CM_RP_FAULTLOGONFAILURE;
    }

    /* get driver information */
    if (NQ_FAIL == syGetPrinterDriver(printHandle, requiredOS, &driverInfo))
    {
        TRCERR("Unable to get driver information");
        TRC1P(" printer handle: %d", printHandle);
        TRCE();
        return SMB_STATUS_UNKNOWN_PRINTER_DRIVER;
    }

    bufferStart = out->current;

    /* place data */

    switch (infoLevel)
    {
    case 1:
        CS_RP_CALL(placeTcharAsUnicode(out, buffer, bufferStart, driverInfo.name));
        break;
    case 2:
        cmRpcPackUint32(out, driverInfo.osVersion);
        CS_RP_CALL(placeTcharAsUnicode(out, buffer, bufferStart, driverInfo.name));
        CS_RP_CALL(placeTcharAsUnicode(out, buffer, bufferStart, requiredOS));
        CS_RP_CALL(placePathAsUnicode(out, buffer, bufferStart, driverInfo.driverPath, serverIp));
        CS_RP_CALL(placePathAsUnicode(out, buffer, bufferStart, driverInfo.dataFile, serverIp));
        CS_RP_CALL(placePathAsUnicode(out, buffer, bufferStart, driverInfo.configFile, serverIp));
        break;
    case 3:
        cmRpcPackUint32(out, driverInfo.osVersion);
        CS_RP_CALL(placeTcharAsUnicode(out, buffer, bufferStart, driverInfo.name));
        CS_RP_CALL(placeTcharAsUnicode(out, buffer, bufferStart, requiredOS));
        CS_RP_CALL(placePathAsUnicode(out, buffer, bufferStart, driverInfo.driverPath, serverIp));
        CS_RP_CALL(placePathAsUnicode(out, buffer, bufferStart, driverInfo.dataFile, serverIp));
        CS_RP_CALL(placePathAsUnicode(out, buffer, bufferStart, driverInfo.configFile, serverIp));
        CS_RP_CALL(placePathAsUnicode(out, buffer, bufferStart, driverInfo.helpFile, serverIp));
        CS_RP_CALL(placePathListAsUnicode(out, buffer, bufferStart, driverInfo.dependentFiles, serverIp));
        CS_RP_CALL(placeTcharAsUnicode(out, buffer, bufferStart, driverInfo.monitorName));
        CS_RP_CALL(placeTcharAsUnicode(out, buffer, bufferStart, driverInfo.defaultDataType));
        break;
    case 4:
        cmRpcPackUint32(out, driverInfo.osVersion);
        CS_RP_CALL(placeTcharAsUnicode(out, buffer, bufferStart, driverInfo.name));
        CS_RP_CALL(placeTcharAsUnicode(out, buffer, bufferStart, requiredOS));
        CS_RP_CALL(placePathAsUnicode(out, buffer, bufferStart, driverInfo.driverPath, serverIp));
        CS_RP_CALL(placePathAsUnicode(out, buffer, bufferStart, driverInfo.dataFile, serverIp));
        CS_RP_CALL(placePathAsUnicode(out, buffer, bufferStart, driverInfo.configFile, serverIp));
        CS_RP_CALL(placePathAsUnicode(out, buffer, bufferStart, driverInfo.helpFile, serverIp));
        CS_RP_CALL(placePathListAsUnicode(out, buffer, bufferStart, driverInfo.dependentFiles, serverIp));
        CS_RP_CALL(placeTcharAsUnicode(out, buffer, bufferStart, driverInfo.monitorName));
        CS_RP_CALL(placeTcharAsUnicode(out, buffer, bufferStart, driverInfo.defaultDataType));
        CS_RP_CALL(placeListAsUnicode(out, buffer, bufferStart, driverInfo.previousNames));
        break;
    case 5:
        cmRpcPackUint32(out, driverInfo.osVersion);
        CS_RP_CALL(placeTcharAsUnicode(out, buffer, bufferStart, driverInfo.name));
        CS_RP_CALL(placeTcharAsUnicode(out, buffer, bufferStart, requiredOS));
        CS_RP_CALL(placePathAsUnicode(out, buffer, bufferStart, driverInfo.driverPath, serverIp));
        CS_RP_CALL(placePathAsUnicode(out, buffer, bufferStart, driverInfo.dataFile, serverIp));
        CS_RP_CALL(placePathAsUnicode(out, buffer, bufferStart, driverInfo.configFile, serverIp));
        cmRpcPackUint32(out, 0);
        cmRpcPackUint32(out, driverInfo.driverVersions[0]);
        cmRpcPackUint32(out, driverInfo.driverVersions[1]);
        break;
    case 6:
        cmRpcPackUint32(out, driverInfo.osVersion);
        CS_RP_CALL(placeTcharAsUnicode(out, buffer, bufferStart, driverInfo.name));
        CS_RP_CALL(placeTcharAsUnicode(out, buffer, bufferStart, requiredOS));
        CS_RP_CALL(placePathAsUnicode(out, buffer, bufferStart, driverInfo.driverPath, serverIp));
        CS_RP_CALL(placePathAsUnicode(out, buffer, bufferStart, driverInfo.dataFile, serverIp));
        CS_RP_CALL(placePathAsUnicode(out, buffer, bufferStart, driverInfo.configFile, serverIp));
        CS_RP_CALL(placePathAsUnicode(out, buffer, bufferStart, driverInfo.helpFile, serverIp));
        CS_RP_CALL(placePathListAsUnicode(out, buffer, bufferStart, driverInfo.dependentFiles, serverIp));
        CS_RP_CALL(placeTcharAsUnicode(out, buffer, bufferStart, driverInfo.monitorName));
        CS_RP_CALL(placeTcharAsUnicode(out, buffer, bufferStart, driverInfo.defaultDataType));
        CS_RP_CALL(placeListAsUnicode(out, buffer, bufferStart, driverInfo.previousNames));
        {
            NQ_UINT32 timeLow, timeHigh;

            if (driverInfo.driverDate == 0)
            {
                cmRpcPackUint32(out, 0);
                cmRpcPackUint32(out, 0);
            }
            else
            {
                cmCifsTimeToUTC(cmTimeConvertSecToMSec(driverInfo.driverDate), &timeLow, &timeHigh);
                cmRpcPackUint32(out, timeLow);
                cmRpcPackUint32(out, timeHigh);
            }
        }
        cmRpcPackUint32(out, 0);         /* undocumented ? */
        cmRpcPackUint32(out, driverInfo.driverVersions[0]);
        cmRpcPackUint32(out, driverInfo.driverVersions[1]);
        CS_RP_CALL(placeTcharAsUnicode(out, buffer, bufferStart, driverInfo.manufacturer));
        CS_RP_CALL(placeTcharAsUnicode(out, buffer, bufferStart, driverInfo.manufacturerURL));
        CS_RP_CALL(placeTcharAsUnicode(out, buffer, bufferStart, driverInfo.hardwareID));
        CS_RP_CALL(placeTcharAsUnicode(out, buffer, bufferStart, driverInfo.provider));
        break;
    default:
        return CM_RP_UNKNOWNLEVEL;
    }
    cmRpcAllignZero(out, 4);

    TRCE();
    return 0;
}

/*====================================================================
 * PURPOSE: Place ascii string as unicode backwards from the end of the buffer
 *--------------------------------------------------------------------
 * PARAMS:  IN packet descriptor for offsets
 *          IN/OUT running pointer for placing strings
 *          IN pointer to the start of the buffer
 *          IN string to place
 *
 * RETURNS: zero or error code
 *
 * NOTES:
 *====================================================================
 */

static NQ_UINT32
placeAsciiAsUnicode(
    CMRpcPacketDescriptor* out,
    NQ_WCHAR** buffer,
    NQ_BYTE* bufferStart,
    const NQ_CHAR* src
    )
{
    CMRpcPacketDescriptor temp;     /* for placing string */

    TRCB();

    *buffer -= syStrlen(src) + 1;
    if ((NQ_BYTE*)*buffer <= (out->current + 4))
    {
        TRCE();
        return CM_RP_INSUFFICIENTBUFFER;
    }
    if ((NQ_BYTE*)*buffer > out->current)
    {
        cmRpcCloneDescriptor(out, &temp);
        temp.current = (NQ_BYTE*)*buffer;
        CS_RP_CALL(cmRpcPackAsciiAsUnicode(&temp, src, CM_RP_NULLTERM));
        cmRpcPackUint32(out, (NQ_UINT32)((NQ_BYTE*)*buffer - bufferStart));
    }
    else
    {
        cmRpcParseSkip(out, 4);
    }

    TRCE();
    return 0;
}

/*====================================================================
 * PURPOSE: Place TCHAR string backwards from the end of the buffer
 *--------------------------------------------------------------------
 * PARAMS:  IN packet descriptor for offsets
 *          IN/OUT running pointer for placing strings
 *          IN pointer to the start of the buffer
 *          IN string to place
 *
 * RETURNS: zero or error code
 *
 * NOTES:
 *====================================================================
 */

static NQ_UINT32
placeTcharAsUnicode(
    CMRpcPacketDescriptor* out,
    NQ_WCHAR** buffer,
    NQ_BYTE* bufferStart,
    const NQ_WCHAR* src
    )
{
    CMRpcPacketDescriptor temp;     /* for placing string */

    TRCB();

    if (src == NULL)
    {
        cmRpcPackUint32(out, 0);
    }
    else
    {
        *buffer -= cmRpcTcharAsUnicodeLength(src) + 1;

        /* check space in the buffer */
        if ((NQ_BYTE*)*buffer <= (out->current + 4))
        {
            TRCE();
            return CM_RP_INSUFFICIENTBUFFER;
        }

        /* place string and pointer */
        if ((NQ_BYTE*)*buffer > out->current)
        {
            cmRpcCloneDescriptor(out, &temp);
            temp.current = (NQ_BYTE*)*buffer;
            CS_RP_CALL(cmRpcPackWcharAsUnicode(&temp, src, CM_RP_NULLTERM));
            cmRpcPackUint32(out, (NQ_UINT32)((NQ_BYTE*)*buffer - bufferStart));
        }
        else
        {
            cmRpcParseSkip(out, 4);
        }
    }

    TRCE();
    return 0;
}

/*====================================================================
 * PURPOSE: Place TCHAR string backwards from the end of the buffer
 *--------------------------------------------------------------------
 * PARAMS:  IN packet descriptor for offsets
 *          IN/OUT running pointer for placing strings
 *          IN pointer to the start of the buffer
 *          IN pointer to string array, the last name is empty
 *
 * RETURNS: zero or error code
 *
 * NOTES:
 *====================================================================
 */

static NQ_UINT32
placeListAsUnicode(
    CMRpcPacketDescriptor* out,
    NQ_WCHAR** buffer,
    NQ_BYTE* bufferStart,
    const NQ_WCHAR** src
    )
{
    CMRpcPacketDescriptor temp;         /* for placing string */
    const NQ_WCHAR** srcSaved = src;    /* saved calue */

    TRCB();

    while (*src != NULL)
    {
        *buffer -= syWStrlen(*src) + 1;
        src++;
    }
    *buffer -= 1;
    cmRpcCloneDescriptor(out, &temp);
    temp.current = (NQ_BYTE*)*buffer;
    src = srcSaved;
    while (*src != NULL)
    {
        CS_RP_CALL(cmRpcPackWcharAsUnicode(&temp, *src, CM_RP_NULLTERM));
        src++;
    }

    cmRpcPackUint16(&temp, 0);

    TRCE();
    return 0;
}

/*====================================================================
 * PURPOSE: Place TCHAR path string backwards from the end of the buffer
 *--------------------------------------------------------------------
 * PARAMS:  IN packet descriptor for offsets
 *          IN/OUT running pointer for placing strings
 *          IN pointer to the start of the buffer
 *          IN string to place
 *          IN pointer to server IP
 * RETURNS: zero or error code
 *
 * NOTES:   We prefix this string with host name
 *====================================================================
 */

static NQ_UINT32
placePathAsUnicode(
    CMRpcPacketDescriptor* out,
    NQ_WCHAR** buffer,
    NQ_BYTE* bufferStart,
    const NQ_WCHAR* src,
    const NQ_CHAR* serverIp
    )
{
    NQ_UINT32 result;

    if (NULL == src)
    {
        cmRpcPackUint32(out, 0);
        return 0;
    }
    syAnsiToUnicode(staticData->txtBufferW, "\\\\");
    syAnsiToUnicode(staticData->txtBufferW + syWStrlen(staticData->txtBufferW), serverIp ? serverIp : cmNetBiosGetHostNameZeroed());
    syWStrcat(staticData->txtBufferW, src);
    result = placeTcharAsUnicode(out, buffer, bufferStart, staticData->txtBufferW);
    return result;
}

/*====================================================================
 * PURPOSE: Place TCHAR path string backwards from the end of the buffer
 *--------------------------------------------------------------------
 * PARAMS:  IN packet descriptor for offsets
 *          IN/OUT running pointer for placing strings
 *          IN pointer to the start of the buffer
 *          IN pointer to string array, the last name is empty
 *          IN pointer to server IP
 * RETURNS: zero or error code
 *
 * NOTES:   We prefix this string with host name
 *====================================================================
 */

static NQ_UINT32
placePathListAsUnicode(
    CMRpcPacketDescriptor* out,
    NQ_WCHAR** buffer,
    NQ_BYTE* bufferStart,
    const NQ_WCHAR** src,
    const NQ_CHAR* serverIp
    )
{
    CMRpcPacketDescriptor temp;         /* for placing string */
    const NQ_WCHAR** srcSaved = src;    /* saved calue */

    TRCB();

    syAnsiToUnicode(staticData->txtBufferW, "\\\\");
    syAnsiToUnicode(staticData->txtBufferW + syWStrlen(staticData->txtBufferW), serverIp ? serverIp : cmNetBiosGetHostNameZeroed());
    while (*src != NULL)
    {
        *buffer -= syWStrlen(*src) + syWStrlen(staticData->txtBufferW) + 1;
        src++;
    }
    *buffer -= 1;
    cmRpcCloneDescriptor(out, &temp);
    temp.current = (NQ_BYTE*)*buffer;
    src = srcSaved;
    while (*src != NULL)
    {
        syAnsiToUnicode(staticData->txtBufferW, "\\\\");
        syAnsiToUnicode(staticData->txtBufferW + syWStrlen(staticData->txtBufferW), serverIp ? serverIp : cmNetBiosGetHostNameZeroed());
        syWStrcat(staticData->txtBufferW, *src);
        CS_RP_CALL(cmRpcPackWcharAsUnicode(&temp, staticData->txtBufferW, CM_RP_NULLTERM));
        src++;
    }
    cmRpcPackUint16(&temp, 0);

    TRCE();
    return 0;
}

/*====================================================================
 * PURPOSE: pack time in Windows portion format
 *--------------------------------------------------------------------
 * PARAMS:  IN packet descriptor for offsets
 *          IN time in UNIX format
 *
 * RETURNS: None
 *
 * NOTES:
 *====================================================================
 */

static void
packTimePortions(
    CMRpcPacketDescriptor* out,
    NQ_UINT32 time
    )
{
    SYTimeFragments fragTime;   /* system-independent time fragments */

    if (0L == time)
    {
        cmRpcPackUint16(out, 0);
        cmRpcPackUint16(out, 0);
        cmRpcPackUint16(out, 0);
        cmRpcPackUint16(out, 0);
        cmRpcPackUint16(out, 0);
        cmRpcPackUint16(out, 0);
        cmRpcPackUint16(out, 0);
        cmRpcPackUint16(out, 0);
    }
    else
    {
        syDecomposeTime(time, &fragTime);
        cmRpcPackUint16(out, fragTime.year);
        cmRpcPackUint16(out, fragTime.month);
        cmRpcPackUint16(out, 0);    /* day of week - not supported */
        cmRpcPackUint16(out, fragTime.day);
        cmRpcPackUint16(out, fragTime.hour);
        cmRpcPackUint16(out, fragTime.min);
        cmRpcPackUint16(out, fragTime.sec);
        cmRpcPackUint16(out, 0);    /* milliseconds - not supported */
    }
}

/*====================================================================
 * PURPOSE: place DevMode structure into the buffer
 *--------------------------------------------------------------------
 * PARAMS:  IN packet descriptor
 *          IN pointer to DevMode structure
 *          IN share pointer
 *          IN pointer to server IP
 *
 * RETURNS: zero or error code
 *
 * NOTES:
 *====================================================================
 */

static NQ_UINT32
placeDevMode(
    CMRpcPacketDescriptor* out,
    const SYDeviceMode* devMode,
    const CSShare* pShare,
    const NQ_CHAR* serverIp
    )
{
    NQ_BYTE* devModeSize;               /* pointer to the size of devmode structure */
    NQ_BYTE* devModeStart;              /* pointer to the devmode structure */
    NQ_BYTE* devModeEnd;                /* pointer after the end of devmode structure */
    NQ_BYTE* tempPtr;                   /* temporary pointer inside descriptor */

    devModeStart = out->current;
    syStrcpy(staticData->txtBuffer, "\\\\");
    syStrcat(staticData->txtBuffer, serverIp ? serverIp : cmNetBiosGetHostNameZeroed());
    syStrcat(staticData->txtBuffer, "\\");
    syAnsiToUnicode(staticData->txtBufferW, staticData->txtBuffer);
    syWStrcat(staticData->txtBufferW, pShare->name);
    staticData->txtBufferW[0x40/sizeof(NQ_WCHAR) - 1] = cmWChar('\0'); /* forced null-terminator */
    CS_RP_CALL(cmRpcPackWcharAsUnicode(out, staticData->txtBufferW, CM_RP_NULLTERM));
    out->current = devModeStart + 0x40;                       /* undocumented */
    cmRpcPackUint16(out, 0x0401 /*devMode->specVersion*/);
    cmRpcPackUint16(out, devMode->driverVersion);
    devModeSize = out->current;
    cmRpcPackUint16(out, 0);                                     /* size */
    cmRpcPackUint16(out, (NQ_UINT16)(NULL != devMode->driverExtraData? 0 : devMode->driverExtraLength));
    cmRpcPackUint32(out, devMode->fields);
    cmRpcPackUint16(out, devMode->orientation);
    cmRpcPackUint16(out, devMode->paperSize);
    cmRpcPackUint16(out, devMode->paperLength);
    cmRpcPackUint16(out, devMode->paperWidth);
    cmRpcPackUint16(out, devMode->scale);
    cmRpcPackUint16(out, devMode->copies);
    cmRpcPackUint16(out, devMode->defaultSource);
    cmRpcPackUint16(out, devMode->printQuality);
    cmRpcPackUint16(out, devMode->color);
    cmRpcPackUint16(out, devMode->duplex);
    cmRpcPackUint16(out, devMode->yResolution);
    cmRpcPackUint16(out, devMode->ttOption);
    cmRpcPackUint16(out, devMode->collate);
    tempPtr = out->current;
    CS_RP_CALL(cmRpcPackWcharAsUnicode(out, devMode->formName, CM_RP_NULLTERM));
    out->current = tempPtr + 0x40;                          /* undocumented */
    cmRpcPackUint16(out, devMode->logPixels);
    cmRpcPackUint32(out, devMode->bitsPerPel);
    cmRpcPackUint32(out, devMode->pelsWidth);
    cmRpcPackUint32(out, devMode->pelsHeight);
    cmRpcPackUint32(out, devMode->displayFlags);
    cmRpcPackUint32(out, devMode->displayFrequency);
    cmRpcPackUint32(out, devMode->icmMethod);
    cmRpcPackUint32(out, devMode->icmIntent);
    cmRpcPackUint32(out, devMode->mediaType);
    cmRpcPackUint32(out, devMode->ditherType);
    cmRpcPackUint32(out, devMode->reserved1);
    cmRpcPackUint32(out, devMode->reserved2);
    cmRpcPackUint32(out, devMode->panningWidth);
    cmRpcPackUint32(out, devMode->panningHeight);
    devModeEnd = out->current;
    tempPtr = out->current;
    out->current = devModeSize;
    cmRpcPackUint16(out, (NQ_UINT16)(devModeEnd - devModeStart));
    out->current = tempPtr;
    if (NULL != devMode->driverExtraData)
    {
        cmRpcPackBytes(out, devMode->driverExtraData, devMode->driverExtraLength);
    }
    return 0;
}

/*====================================================================
 * PURPOSE: parse device mode structure
 *--------------------------------------------------------------------
 * PARAMS:  IN packet descriptor
 *          IN data size
 *          OUT pointer to DevMode structure
 *
 * RETURNS: zero or error code
 *
 * NOTES:
 *====================================================================
 */

static NQ_UINT32
parseDevMode(
    CMRpcPacketDescriptor* in,
    NQ_UINT32 size,
    SYDeviceMode* devMode
    )
{
    NQ_BYTE* tempPtr;                   /* temporary pointer inside descriptor */

    in->current += 0x40;           /* skip device name - undocumented */
    cmRpcParseUint16(in, &devMode->specVersion);
    cmRpcParseUint16(in, &devMode->driverVersion);
    cmRpcParseSkip(in, 2);                                     /* size */
    cmRpcParseUint16(in, &devMode->driverExtraLength);
    cmRpcParseUint32(in, &devMode->fields);
    cmRpcParseUint16(in, &devMode->orientation);
    cmRpcParseUint16(in, &devMode->paperSize);
    cmRpcParseUint16(in, &devMode->paperLength);
    cmRpcParseUint16(in, &devMode->paperWidth);
    cmRpcParseUint16(in, &devMode->scale);
    cmRpcParseUint16(in, &devMode->copies);
    cmRpcParseUint16(in, &devMode->defaultSource);
    cmRpcParseUint16(in, &devMode->printQuality);
    cmRpcParseUint16(in, &devMode->color);
    cmRpcParseUint16(in, &devMode->duplex);
    cmRpcParseUint16(in, &devMode->yResolution);
    cmRpcParseUint16(in, &devMode->ttOption);
    cmRpcParseUint16(in, &devMode->collate);
    devMode->formName = (NQ_WCHAR*)in->current;
    tempPtr = in->current;
    syWStrncpy((NQ_WCHAR*)in->current, (NQ_WCHAR*)in->current, 0x40 / sizeof(NQ_WCHAR));
    in->current = tempPtr + 0x40;                          /* undocumented */
    cmRpcParseUint16(in, &devMode->logPixels);
    cmRpcParseUint32(in, &devMode->bitsPerPel);
    cmRpcParseUint32(in, &devMode->pelsWidth);
    cmRpcParseUint32(in, &devMode->pelsHeight);
    cmRpcParseUint32(in, &devMode->displayFlags);
    cmRpcParseUint32(in, &devMode->displayFrequency);
    cmRpcParseUint32(in, &devMode->icmMethod);
    cmRpcParseUint32(in, &devMode->icmIntent);
    cmRpcParseUint32(in, &devMode->mediaType);
    cmRpcParseUint32(in, &devMode->ditherType);
    cmRpcParseUint32(in, &devMode->reserved1);
    cmRpcParseUint32(in, &devMode->reserved2);
    cmRpcParseUint32(in, &devMode->panningWidth);
    cmRpcParseUint32(in, &devMode->panningHeight);
    devMode->driverExtraData = in->current;
    return 0;
}

/*====================================================================
 * PURPOSE: check access to printer
 *--------------------------------------------------------------------
 * PARAMS:  IN printer handle
 *          IN packet descriptor
 *          IN desired access bits
 *
 * RETURNS: TRUE when access is allowed
 *
 * NOTES:
 *====================================================================
 */

static NQ_BOOL
checkAccessToPrinter(
    SYPrinterHandle handle,
    const CMRpcPacketDescriptor* in,
    NQ_UINT32 desiredAccess
    )
{
#ifdef UD_CS_INCLUDESECURITYDESCRIPTORS
    NQ_BOOL res;        /* the result */
    static SYPrinterInfo info;  /* printer info */

    if (0 == desiredAccess)
        return TRUE;
    if (NQ_SUCCESS != syGetPrinterInfo(handle, &info) || NULL == in->token)
    {
        return FALSE;
    }
    res = cmSdHasAccess((CMSdAccessToken*)in->token, info.securityDescriptor, desiredAccess);
    return res;
#else /* UD_CS_INCLUDESECURITYDESCRIPTORS */
    return TRUE;
#endif /* UD_CS_INCLUDESECURITYDESCRIPTORS */
}

/*====================================================================
 * PURPOSE: check access to printer job
 *--------------------------------------------------------------------
 * PARAMS:  IN printer handle
 *          IN job index
 *          IN packet descriptor
 *          IN desired access bits
 *
 * RETURNS: TRUE when access is allowed
 *
 * NOTES:
 *====================================================================
 */

static NQ_BOOL
checkAccessToJob(
    SYPrinterHandle handle,
    NQ_UINT32 jobId,
    const CMRpcPacketDescriptor* in,
    NQ_UINT32 desiredAccess
    )
{
#ifdef UD_CS_INCLUDESECURITYDESCRIPTORS
    NQ_BOOL res;        /* the result */

    if (NQ_SUCCESS != syGetPrintJobById(handle, jobId, &staticData->jobInfo) || NULL == in->token)
    {
        return FALSE;
    }

    res = cmSdHasAccess((CMSdAccessToken*)in->token, staticData->jobInfo.securityDescriptor, desiredAccess);

    return res;
#else /* UD_CS_INCLUDESECURITYDESCRIPTORS */
    return TRUE;
#endif /* UD_CS_INCLUDESECURITYDESCRIPTORS */
}

/*====================================================================
 * PURPOSE: initialize entry table
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:
 *====================================================================
 */

static NQ_STATUS
initData(
    void
    )
{
    NQ_INT i;

    TRCB();

    /* allocate memory */
#ifdef SY_FORCEALLOCATION
    staticData = (StaticData *)syMalloc(sizeof(*staticData));
    if (NULL == staticData)
    {
        TRCERR("Unable to allocate SPOOLSS table");
        TRCE();
        return NQ_FAIL;
    }
#endif /* SY_FORCEALLOCATION */

    staticData->fakePrinterHandle = 1;
    staticData->changeId = 1;
    for (i = 0; i < UD_CS_SPOOLSS_MAXOPENPRINTERS; i++)
    {
        staticData->openEntries[i].isFree = TRUE;
    }

    TRCE();
    return NQ_SUCCESS;
}

/*====================================================================
 * PURPOSE: release entry table
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: None
 *
 * NOTES:
 *====================================================================
 */

static void
stopData(
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

/*====================================================================
 * PURPOSE: find printer share
 *--------------------------------------------------------------------
 * PARAMS:  IN incoming descriptor
 *          OUT buffer for resulting share pointer
 *          IN TRUE to fill the next parameter
 *          OUT buffer for printer handle
 *
 * RETURNS: NQ_SUCCESS or error code
 *
 * NOTES:
 *====================================================================
 */

static NQ_STATUS
getPrinterShare(
    CMRpcPacketDescriptor* in,
    NQ_INT16 *entry,
    CSShare **share,
    SYPrinterHandle *h,
    NQ_BOOL skipPolicyHandle
    )
{
    NQ_UINT16 ix;
    CSShare *s;

    TRCB();

    cmRpcParseSkip(in, 4);  /* flags */
    cmRpcParseUint16(in, &ix);

    if (entry != NULL)
        *entry = (NQ_INT16)ix;

    if (ix > UD_CS_SPOOLSS_MAXOPENPRINTERS)
    {
        TRCERR("Open entry index out of range");
        TRC1P(" index: %d", ix);
        TRCE();
        return CM_RP_FAULTCONTEXTMISMATCH;
    }

    if (staticData->openEntries[ix].isFree)
    {
        TRCERR("Open entry index designates a free entry");
        TRC1P(" index: %d", ix);
        TRCE();
        return CM_RP_FAULTCONTEXTMISMATCH;
    }

    if ((s = staticData->openEntries[ix].pShare) == NULL)
    {
        TRCERR("Illegal printer handle in request");
        TRC1P("  value: %d", ix);
        TRCE();
        return CM_RP_FAULTINVALIDPRINTERNAME;
    }

    if (share != NULL)
        *share = s;

    if (h != NULL)
    {
        *h = syGetPrinterHandle(s->map);

        if (!syIsValidPrinter(*h))
        {
            TRCERR("Unable to find printer by handle");
            TRC1P(" printer: %s", cmWDump(s->map));
            TRCE();
            return CM_RP_FAULTOTHER;
        }
    }

    if (skipPolicyHandle)
        cmRpcParseSkip(in, sizeof(CMRpcUuid) - 2);

    TRCE();
    return NQ_SUCCESS;
}

/*====================================================================
 * PURPOSE: clean up resources belonging to a user
 *--------------------------------------------------------------------
 * PARAMS:  IN User ID
 *
 * RETURNS: None
 *
 * NOTES:
 *====================================================================
 */

void csRpcSpoolssCleanupUser(
    const NQ_UINT16 uid
    )
{
    NQ_COUNT i;             /* just an index */
    const CSUser* pUser;    /* user pointer */

    if (NULL == (pUser = csGetUserByUid(uid)))
        return;

    for (i = 0;
         i < sizeof(staticData->openEntries)/sizeof(staticData->openEntries[0]);
         i++
        )
    {
        if (   !staticData->openEntries[i].isFree
             && staticData->openEntries[i].user == (NQ_BYTE*)pUser
           )
        {
            if (0 !=  staticData->openEntries[i].jobId)
            {
                syControlPrintJob(
                    staticData->openEntries[i].handle,
                    staticData->openEntries[i].jobId,
                    SY_PRINTJOBCOM_CANCEL
                    );
            };
            staticData->openEntries[i].isFree = TRUE;
        }
    }
}

#endif /* UD_CS_INCLUDERPC_SPOOLSS */

#endif /* UD_NQ_INCLUDECIFSSERVER */
