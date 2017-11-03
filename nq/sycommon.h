/*************************************************************************
 * Copyright 2014-2015 by Visuality Systems, Ltd.
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

#ifndef _SYCOMMON_H_
#define _SYCOMMON_H_

/*@@
   Description
   This structure is intended for composing/decomp0sing system
   time - contains a field for each time fraction.
   Note
   This structure is designated here for reference only and it
   must not be modified.                                       */
typedef struct
{
    NQ_UINT16 sec;      /*@@ Seconds (0 - 59). */
    NQ_UINT16 min;      /*@@ Minutes (0 - 59). */
    NQ_UINT16 hour;     /*@@ Hours of day (0 - 23). */
    NQ_UINT16 day;      /*@@ Day of the month (1-31). */
    NQ_UINT16 month;    /*@@ Month (1 - 12). */
    NQ_UINT16 year;     /*@@ Year in YYYY format. */
} SYTimeFragments;

/*@@
   Description
   \File information structure. It is used for querying
   information from the file system and modifying this
   information.
   Note
   This structure is designated here for reference only and it
   must not be modified.                                       */
typedef struct
{
    NQ_TIME creationTime;         	/*@@ Seconds in UNIX format. */
    NQ_TIME lastChangeTime;      	/*@@ Seconds in UNIX format. */
    NQ_TIME lastAccessTime;       	/*@@ Seconds in UNIX format. */
    NQ_TIME lastWriteTime;        	/*@@ Seconds in UNIX format. */
    NQ_UINT32 sizeLow;              /*@@ Low part of the file size. */
    NQ_UINT32 sizeHigh;             /*@@ High part of the file size. */
    NQ_UINT32 allocSizeLow;         /*@@ Low part of the file size. */
    NQ_UINT32 allocSizeHigh;        /*@@ High part of the file size. */
    NQ_UINT32 attributes;           /*@@ DOS FS format attributes. */
    NQ_UINT32 isDeleted;            /*@@ File is marked for deletion. */
    NQ_UINT32 numLinks;             /*@@ Number of hard links to the file. */
    NQ_UINT32 fileIdLow;            /*@@ Low part of file ID. */
    NQ_UINT32 fileIdHigh;           /*@@ High part of file ID. */
} SYFileInformation;

/*@@
 File attributes bits: the file is read-only.
 */
#define SY_ATTR_READONLY            0x001

/*@@
 File attributes bits: the file is hidden.
 */

#define SY_ATTR_HIDDEN              0x002
/*@@
 File attributes bits: the file is a system file.
 */
#define SY_ATTR_SYSTEM              0x004

/*@@
 File attributes bits: this is a voluem.
 */
#define SY_ATTR_VOLUME              0x008

/*@@
 File attributes bits: the file is a directory.
 */
#define SY_ATTR_DIRECTORY           0x010

/*@@
 File attributes bits: the file is archived.
 */
#define SY_ATTR_ARCHIVE             0x020

/*@@
 File attributes bits: this is a device.
 */
#define SY_ATTR_DEVICE              0x040

/*@@
 File attributes bits: the file is a regular file.
 */
#define SY_ATTR_NORMAL              0x080

/*@@
 File attributes bits: the file is temporary.
 */
#define SY_ATTR_TEMPORARY           0x100

/*@@
 File attributes bits: the file is distributed.
 */
#define SY_ATTR_SPARSE_FILE         0x200

/*@@
 File attributes bits: the file is a DFS reparse point.
 */
#define SY_ATTR_REPARSE_POINT       0x400

/*@@
 File attributes bits: the file is compressed.
 */
#define SY_ATTR_COMPRESSED          0x800

/*@@
 File attributes bits: the file is offline.
 */
#define SY_ATTR_OFFLINE             0x1000

/*@@
 File attributes bits: the file ahs indexed contents.
 */
#define SY_ATTR_NOT_CONTENT_INDEXED 0x2000

/*@@
 File attributes bits: the file is encrypted.
 */
#define SY_ATTR_ENCRYPTED           0x4000

/*@@
   Volume information structure. It is used for querying volume
   information from the file system.


   Note
   This structure is designated here for reference only and it
   must not be modified.                                        */
typedef struct
{
    NQ_UINT32 serialNumberLow;                /*@@ VolumeSerial number (low part). */
    NQ_UINT32 serialNumberHigh;               /*@@ VolumeSerial number (high part). */
    NQ_UINT32 creationTimeLow;                /*@@ Time of the volume creation (low part). */
    NQ_UINT32 creationTimeHigh;               /*@@ Time of the volume creation (high part). */
    NQ_UINT32 fileSystemIdLow;                /*@@ ID of the file system (low part). */
    NQ_UINT32 fileSystemIdHigh;               /*@@ ID of the file system (high part). */
    NQ_UINT32 blockSizeLow;                   /*@@ Block size in bytes (low part). */
    NQ_UINT32 blockSizeHigh;                  /*@@ Block size in bytes (high part). */
    NQ_UINT32 blocksPerUnitLow;               /*@@ Number of blocks in an allocation unit (low part). */
    NQ_UINT32 blocksPerUnitHigh;              /*@@ Number of blocks in an allocation unit (high part). */
    NQ_UINT32 totalUnitsLow;              	  /*@@ Number of units in volume (low part). */
    NQ_UINT32 totalUnitsHigh;              	  /*@@ Number of units in volume (high part). */
    NQ_UINT32 freeUnitsLow;                   /*@@ Number of free units in volume (low part). */
    NQ_UINT32 freeUnitsHigh;                  /*@@ Number of free units in volume (high part). */
} SYVolumeInformation;

/* printer information structures */

typedef struct
{
    NQ_UINT16 specVersion;
    NQ_UINT16 driverVersion;
    NQ_UINT16 size;
    NQ_UINT16 driverExtraLength;
    const NQ_BYTE* driverExtraData;
    NQ_UINT32 fields;
    NQ_UINT16 orientation;
    NQ_UINT16 paperSize;
    NQ_UINT16 paperLength;
    NQ_UINT16 paperWidth;
    NQ_UINT16 scale;
    NQ_UINT16 copies;
    NQ_UINT16 defaultSource;
    NQ_UINT16 printQuality;
    NQ_UINT16 color;
    NQ_UINT16 duplex;
    NQ_UINT16 yResolution;
    NQ_UINT16 ttOption;
    NQ_UINT16 collate;
    const NQ_WCHAR* formName;
    NQ_UINT16 logPixels;
    NQ_UINT32 bitsPerPel;
    NQ_UINT32 pelsWidth;
    NQ_UINT32 pelsHeight;
    NQ_UINT32 displayFlags;
    NQ_UINT32 displayFrequency;
    NQ_UINT32 icmMethod;
    NQ_UINT32 icmIntent;
    NQ_UINT32 mediaType;
    NQ_UINT32 ditherType;
    NQ_UINT32 reserved1;
    NQ_UINT32 reserved2;
    NQ_UINT32 panningWidth;
    NQ_UINT32 panningHeight;
} SYDeviceMode;

/* printer driver information structure */

#define SY_PRINTEROSVERSION_WIN 3

typedef struct
{
    NQ_UINT32 osVersion;
    const NQ_WCHAR* name;
    const NQ_WCHAR* driverPath;
    const NQ_WCHAR* dataFile;
    const NQ_WCHAR* configFile;
    const NQ_WCHAR* helpFile;
    const NQ_WCHAR** dependentFiles;
    const NQ_WCHAR* monitorName;
    const NQ_WCHAR* defaultDataType;
    const NQ_WCHAR** previousNames;
    NQ_UINT32 driverDate;
    NQ_UINT32 driverVersions[2];
    const NQ_WCHAR* manufacturer;
    const NQ_WCHAR* manufacturerURL;
    const NQ_WCHAR* hardwareID;
    const NQ_WCHAR* provider;
    NQ_UINT32 attributes;
    NQ_UINT32 configVersion;
    NQ_UINT32 driverVersion;
} SYPrinterDriver;

/* field flags in above */

#define SY_DEVICEMODE_ORIENTATION       0x00000001
#define SY_DEVICEMODE_PAPERSIZE         0x00000002
#define SY_DEVICEMODE_PAPERLENGTH       0x00000004
#define SY_DEVICEMODE_PAPERWIDTH        0x00000008
#define SY_DEVICEMODE_SCALE             0x00000010
#define SY_DEVICEMODE_POSITION          0x00000020
#define SY_DEVICEMODE_NUP               0x00000040
#define SY_DEVICEMODE_COPIES            0x00000080
#define SY_DEVICEMODE_DEFAULTSOURCE     0x00000100
#define SY_DEVICEMODE_PRINTQUALITY      0x00000400
#define SY_DEVICEMODE_COLOR             0x00000800
#define SY_DEVICEMODE_DUPLEX            0x00001000
#define SY_DEVICEMODE_YRESOLUTION       0x00002000
#define SY_DEVICEMODE_TTOPTION          0x00004000
#define SY_DEVICEMODE_COLLATE           0x00008000
#define SY_DEVICEMODE_FORMNAME          0x00010000
#define SY_DEVICEMODE_LOGPIXELS         0x00020000
#define SY_DEVICEMODE_BITSPERPEL        0x00040000
#define SY_DEVICEMODE_PELWIDTH          0x00080000
#define SY_DEVICEMODE_PELHEIGHT         0x00100000
#define SY_DEVICEMODE_DISPLAYFLAGS      0x00200000
#define SY_DEVICEMODE_DISPLAYFREQUENCY  0x00400000
#define SY_DEVICEMODE_ICMMETHOD         0x00800000
#define SY_DEVICEMODE_ICMINTENT         0x01000000
#define SY_DEVICEMODE_MEDIATYPE         0x02000000
#define SY_DEVICEMODE_DITHERTYPE        0x04000000
#define SY_DEVICEMODE_PANNINGWIDTH      0x08000000
#define SY_DEVICEMODE_PANNINGHEIGHT     0x10000000

/* united printer information structure */

typedef struct
{
    NQ_UINT32 flags;                /* printer flags */
    NQ_WCHAR* portName;
    NQ_WCHAR* driverName;
    NQ_WCHAR* comment;
    NQ_WCHAR* location;
    SYDeviceMode devMode;
    NQ_WCHAR* sepFile;
    NQ_WCHAR* printProcessor;
    NQ_WCHAR* dataType;
    NQ_WCHAR* parameters;
    NQ_UINT32 attributes;
    NQ_UINT32 priority;
    NQ_UINT32 defaultPriority;
    NQ_UINT32 startTime;
    NQ_UINT32 untilTime;
    NQ_UINT32 status;
    NQ_UINT32 cJobs;
    NQ_UINT32 totalJobs;
    NQ_UINT32 totalBytes;
    NQ_UINT32 globalCounter;
    NQ_UINT32 totalPages;
    NQ_UINT16 majorVersion;
    NQ_UINT16 buildVersion;
    NQ_UINT32 sessionCounter;
    NQ_UINT32 printerErrors;
    NQ_UINT32 cSetPrinter;
    NQ_UINT32 averagePpm;
    NQ_UINT32 deviceNotSelectedTimeout;
    NQ_UINT32 transmissionRetryTimeout;
    NQ_BYTE* securityDescriptor;
    NQ_UINT32 securityDescriptorLength;
}
SYPrinterInfo;

/* status flags */

#define SY_PRINTERSTATUS_PAUSED             0x00000001
#define SY_PRINTERSTATUS_ERROR              0x00000002
#define SY_PRINTERSTATUS_PENDINGDELETION    0x00000004
#define SY_PRINTERSTATUS_PAPERJAM           0x00000008
#define SY_PRINTERSTATUS_PAPEROUT           0x00000010
#define SY_PRINTERSTATUS_MANUALFEED         0x00000020
#define SY_PRINTERSTATUS_PAPERPROBLEM       0x00000040
#define SY_PRINTERSTATUS_OFFLINE            0x00000080
#define SY_PRINTERSTATUS_IOACTIVE           0x00000100
#define SY_PRINTERSTATUS_BUSY               0x00000200
#define SY_PRINTERSTATUS_PRINTING           0x00000400
#define SY_PRINTERSTATUS_OUTPUTBINFULL      0x00000800
#define SY_PRINTERSTATUS_NOTAVAILABLE       0x00001000
#define SY_PRINTERSTATUS_WAITING            0x00002000
#define SY_PRINTERSTATUS_PROCESSING         0x00004000
#define SY_PRINTERSTATUS_INITIALIZING       0x00008000
#define SY_PRINTERSTATUS_WARMINGUP          0x00010000
#define SY_PRINTERSTATUS_TONERLOW           0x00020000
#define SY_PRINTERSTATUS_NOTONER            0x00040000
#define SY_PRINTERSTATUS_PAGEPUNT           0x00080000
#define SY_PRINTERSTATUS_USERINTERVENTION   0x00100000
#define SY_PRINTERSTATUS_OUTOFMEMORY        0x00200000
#define SY_PRINTERSTATUS_DOOROPEN           0x00400000
#define SY_PRINTERSTATUS_SERVERUNKNOWN      0x00800000
#define SY_PRINTERSTATUS_POWERSAVE          0x01000000

/* attribute flags */

#define SY_PRINTERATTR_QUEUED       0x0001   /* spools first, then prints */
#define SY_PRINTERATTR_DIRECT       0x0002   /* jobs are printed directly, without spooling */
#define SY_PRINTERATTR_DEFAULT      0x0004   /* 9x/ME only - default printer */
#define SY_PRINTERATTR_SHARED       0x0008   /* shared printer */
#define SY_PRINTERATTR_NETWORK      0x0010   /* network printer */
#define SY_PRINTERATTR_RESERVED     0x0020   /* */
#define SY_PRINTERATTR_LOCAL        0x0040   /* local printer */
#define SY_PRINTERATTR_DEVQUERY     0x0080   /* enable DevQueryPrint */
#define SY_PRINTERATTR_KEEPJOBS     0x0100   /* do not delete jobs after printing */
#define SY_PRINTERATTR_LIFO         0x0200   /* jobs are printed in back order */
#define SY_PRINTERATTR_OFFLINE      0x0400   /* 9x/ME only */
#define SY_PRINTERATTR_BIDI         0x0800   /* 9x/ME only - bidirectional operations */
#define SY_PRINTERATTR_RAWONLY      0x1000   /* only raw data may be spooled */
#define SY_PRINTERATTR_PUBLISHED    0x2000   /* printer is published in the directory */
#define SY_PRINTERATTR_EXPAND       0x4000
#define SY_PRINTERATTR_CONTAINER    0x8000
#define SY_PRINTERATTR_ICON1        0x10000
#define SY_PRINTERATTR_ICON2        0x20000
#define SY_PRINTERATTR_ICON3        0x40000
#define SY_PRINTERATTR_ICON4        0x80000
#define SY_PRINTERATTR_ICON5        0x100000
#define SY_PRINTERATTR_ICON6        0x200000
#define SY_PRINTERATTR_ICON7        0x400000
#define SY_PRINTERATTR_ICON8        0x800000

/* united print job information structure */

typedef struct
{
    NQ_UINT32 id;                   /* job ID */
    const NQ_WCHAR* documentName;   /* name of the document being printed */
    const NQ_WCHAR* pStatus;        /* optional text description of the status */
    NQ_UINT32 status;               /* status code (when the above is null) - see below */
    NQ_UINT32 priority;             /* job priority - see below */
    NQ_UINT32 position;             /* job position in the print queue (0 - current) */
    NQ_UINT32 totalPages;           /* number of pages in the entire job */
    NQ_UINT32 pagesPrinted;         /* number of pages printed so far */
    NQ_UINT32 submitTime;           /* time this job was queued */
    NQ_UINT32 startTime;            /* the earliest time this job can be printed */
    NQ_UINT32 untilTime;            /* the latest time this job can be printed */
    NQ_UINT32 time;                 /* elapsed time since this job begun being printed */
    NQ_UINT32 size;                 /* job size in bytes */
    NQ_BYTE* securityDescriptor;           /* pointer to security descriptor */
    NQ_UINT32 securityDescriptorLength;    /* security desriptor length */
    const void* user;				/* user context */
}
SYPrintJobInfo;

/* values in the "status" field above */

#define SY_PRINTJOBSTATUS_PAUSED           0x00000001 /* Job is paused. */
#define SY_PRINTJOBSTATUS_ERROR            0x00000002 /* An error is associated with the job. */
#define SY_PRINTJOBSTATUS_DELETING         0x00000004 /* Job is being deleted. */
#define SY_PRINTJOBSTATUS_SPOOLING         0x00000008 /* Paper jam on printer. */
#define SY_PRINTJOBSTATUS_PRINTING         0x00000010 /* Job is being printed. */
#define SY_PRINTJOBSTATUS_OFFLINE          0x00000020 /* Printer is offline. */
#define SY_PRINTJOBSTATUS_PAPERPROBLEM     0x00000040 /* Paper jam or out of paper. */
#define SY_PRINTJOBSTATUS_PRINTED          0x00000080 /* Job has printed. */
#define SY_PRINTJOBSTATUS_DELETED          0x00000100 /* Job has been deleted. */
#define SY_PRINTJOBSTATUS_BLOCKED          0x00000200 /* The driver cannot print the job. */
#define SY_PRINTJOBSTATUS_USERINTERVENTION 0x00000400 /* User intervention required. */
#define SY_PRINTJOBSTATUS_RESTART          0x00000800 /* Job has been restarted. */

/* values in the "priority" field above */

#define SY_PRINTJOB_MINPRIORITY     1   /* Minimum priority. */
#define SY_PRINTJOB_MAXPRIORITY     99  /* Maximum priority. */
#define SY_PRINTJOB_DEFPRIORITY     1   /* Default priority. */

/* printer control commands */

#define SY_PRINTERCONTROL_PAUSE         1   /* Pause printer */
#define SY_PRINTERCONTROL_RESUME        2   /* Resume printer */
#define SY_PRINTERCONTROL_PURGE         3   /* Purge all jobs */
#define SY_PRINTERCONTROL_SETSTATUS     4   /* Force printer status */

/* job control commands */

#define SY_PRINTJOBCOM_PAUSE            1   /* Pause a job */
#define SY_PRINTJOBCOM_RESUME           2   /* Resume a paused job */
#define SY_PRINTJOBCOM_CANCEL           3   /* Cancel a job (NT4.0 and later only) */
#define SY_PRINTJOBCOM_RESTART          4   /* Restart the print job.
                                               A job can only be restarted if it was
                                               printing */
#define SY_PRINTJOBCOM_DELETE           5   /* Windows NT 4.0 and later:
                                               Delete the print job */
#define SY_PRINTJOBCOM_SENDTOPRINTER    6   /* Windows NT 4.0 and later:
                                               Used by port monitors to end the print job. */
#define SY_PRINTJOBCOM_LASTPAGEEJECTED  7   /* Windows NT 4.0 and later:
                                               Used by language monitors to end the print job. */

/* size structure */

typedef struct
{
    NQ_UINT32 width;            /* width in thousandths of millimeters */
    NQ_UINT32 height;           /* heighth in thousandths of millimeters */
}
SYPrintSize;

/* structure defining a rectangle area */

typedef struct
{
    NQ_UINT32 left;             /* horisontal shift to the left edge in thousandths of millimeters */
    NQ_UINT32 top;              /* vertical shift to the top edge in thousandths of millimeters */
    NQ_UINT32 right;            /* horisontal shift to the right edge in thousandths of millimeters */
    NQ_UINT32 bottom;           /* vertical shift to the bottom edge in thousandths of millimeters */
}
SYPrintRect;

/* form information structure */

typedef struct
{
    NQ_UINT32 id;                       /* form ID */
    const NQ_WCHAR* name;               /* form name */
    NQ_UINT32 flags;                    /* see below */
    SYPrintSize size;                   /* form size */
    SYPrintRect imageableArea;          /* form shape */
}
SYPrintFormInfo;

#define SY_PRINTFORMFLAG_USER       0x00000000  /* user-defined */
#define SY_PRINTFORMFLAG_BUILTIN    0x00000001  /* spooler level */
#define SY_PRINTFORMFLAG_PRINTER    0x00000002  /* printer level */

#endif  /* _SYCOMMON_H_ */
