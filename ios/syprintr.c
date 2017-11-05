/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : OS-dependent definitions for printing
 *                 This file is expected to be modified during porting
 *--------------------------------------------------------------------
 * MODULE        : SY - System-dependent
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 22-May-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "nqapi.h"
#include "syprintr.h"
#include "csdcerpc.h"

#ifdef UD_CS_INCLUDERPC_SPOOLSS

/* Simulating printer: uncomment SIMULATE_PRINTER_NNN and fill out the appropriate
   values in ID, VENDOR and PRODUCT */

#define SIMULATE_PRINTER_BROTHER

#ifdef SIMULATE_PRINTER_BROTHER
#define SIMULATION_MODE
#define SHOW_PRINTING_PROCESS
#define SIMULATED_PRINTER_ID      "MFG:Brother;CMD:PJL,HBP;MDL:HL-2030 series;CLS:PRINTER;"
#define SIMULATED_PRINTER_VENDOR  0x4F9
#define SIMULATED_PRINTER_PRODUCT 0x27
#endif

/* Table sizes */

#define MAX_PRINTERS 1
#define MAX_JOBS     10

#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))

/* ################################################################ */
/* ################################################################ */

#ifndef SIMULATION_MODE
#include <linux/lp.h>
#endif

static char deviceA[20];        /* for converting printer name to ANSI */ 

#ifndef SIMULATION_MODE
/* ioctl() constants */
#define IOCNR_GET_DEVICE_ID      1
#define IOCNR_GET_VID_PID        6
#define LPIOC_GET_DEVICE_ID(len) _IOC(_IOC_READ, 'P', IOCNR_GET_DEVICE_ID, len) /* get device_id string */
#define LPIOC_GET_VID_PID(len)   _IOC(_IOC_READ, 'P', IOCNR_GET_VID_PID, len)   /* get vendor and product IDs */
#define LPGETSTATUS              0x060b                                         /* same as in drivers/char/lp.c */
#endif

static NQ_BOOL
getDeviceStatusByFD(
    int device,
    NQ_UINT32 *status
)
{
    /* actual device is not accessed in simulation mode */
#ifndef SIMULATION_MODE
    int s;

    if (ioctl(device, LPGETSTATUS, &s) == -1)
        return FALSE;
#endif

    /* translate status */
    *status = 0;

#ifndef SIMULATION_MODE
    if (s != 0x18)
    {
        /* something wrong */
        if (s & LP_ERR)
            *status |= SY_PRINTERSTATUS_ERROR;
        if (s & LP_NOPA)
            *status |= SY_PRINTERSTATUS_PAPEROUT;
        if (s & LP_OFFL)
            *status |= SY_PRINTERSTATUS_OFFLINE;
    }
#endif

    return TRUE;
}

static NQ_BOOL
getDeviceStatusByName(
    const char *device,
    NQ_UINT32 *status
    )
{
#ifndef SIMULATION_MODE
    NQ_BOOL result;
    int fd = open(device, O_RDWR);

    if (fd < 0)
        return FALSE;

    result = getDeviceStatusByFD(fd, status);
    close(fd);

    return result;
#else
    /* fd does not matter in simulation mode */
    return getDeviceStatusByFD(0, status);
#endif
}

static NQ_BOOL
getDeviceInfo(
    const char *device,
    char *buffer,
    size_t limit,
    int *vendor,
    int *product,
    NQ_UINT32 *status
    )
{
#ifndef SIMULATION_MODE
    int pair[2] = {0, 0};
    int fd = open(device, O_RDONLY);

    if (fd < 0)
        return FALSE;

    /* reserve spare byte for null termination */
    syMemset(buffer, 0, limit--);

    /* get device ID string */
    if (ioctl(fd, LPIOC_GET_DEVICE_ID(limit), buffer) < 0)
    {
        close(fd);

        TRC("NQPR: ioctl() failed for get device ID string");
        return FALSE;
    }

    /* get device vendor and product */
    if (ioctl(fd, LPIOC_GET_VID_PID(sizeof(pair)), pair) < 0)
    {
        close(fd);

        TRC("NQPR: ioctl() failed for get device vendor and product IDs");
        return FALSE;
    }

    *vendor = pair[0];
    *product = pair[1];

    /* get device status */
    if (!getDeviceStatusByFD(fd, status))
    {
        close(fd);

        TRC("NQPR: ioctl() failed for get device status");
        return FALSE;
    }

    close(fd);
#else
    /* set hardcoded simulated printer information */
    syStrncpy(buffer, SIMULATED_PRINTER_ID, limit - 1);
    buffer[limit - 1] = 0;

    *vendor = SIMULATED_PRINTER_VENDOR;
    *product = SIMULATED_PRINTER_PRODUCT;
#endif

    return TRUE;
}

/* ################################################################ */
/* ################################################################ */

typedef struct
{
    /* runtime information */
    NQ_CHAR   device[16];         /* device name */
    int       fd;                 /* device file descriptor */
    NQ_UINT32 job;                /* current job ID or -1 if idle */
    NQ_UINT32 status;             /* actual device status */
    /* information structure */
    SYPrinterInfo info;
    /* buffers for actual info data */
    NQ_WCHAR  manufacturer[32];
    NQ_WCHAR  model[32];
    NQ_WCHAR  name[64];
    NQ_WCHAR  comment[100];
    NQ_WCHAR  location[100];
    NQ_WCHAR  parameters[100];
    NQ_WCHAR  portName[100];
    NQ_WCHAR  printProcessor[100];
    NQ_WCHAR  sepFile[100];
    NQ_WCHAR  dataType[100];
    NQ_WCHAR  formName[7];
    NQ_BYTE   sd[320];
    NQ_BYTE   extra[1000];
}
Printer;

/* Printer table */
static Printer _printers[MAX_PRINTERS];

static Printer*
getPrinter(
    int id
    )
{
    return (0 <= id && id < ARRAY_SIZE(_printers)) ? &_printers[id] : NULL;
}

static int
findPrinter(
    const NQ_WCHAR *device
    )
{
    int i;

    for (i = 0; i < ARRAY_SIZE(_printers); i++)
    {
        Printer *p = &_printers[i];

        syUnicodeToAnsi(deviceA, device);
        if (strcmp(deviceA, p->device) == 0)
            return i;
    }

    return -1;
}

static int
newPrinter(
    void
    )
{
    int i;

    for (i = 0; i < ARRAY_SIZE(_printers); i++)
    {
        Printer *p = &_printers[i];

        /* check if the slot is free */
        if (p->device[0] == '\0')
            return i;
    }

    return -1;
}

/* ################################################################ */
/* ################################################################ */

typedef struct
{
    NQ_BOOL used;
    SYPrinterHandle printer;
    SYPrintJobInfo info;
    NQ_WCHAR document[256];
    NQ_WCHAR status[32];
    NQ_BYTE sd[320];
    struct {
        NQ_BOOL flag;
        CSDcerpcResponseContext ctx;
        NQ_BYTE data[65536];
        NQ_UINT32 size;
    } delayed;
}
Job;

/* Job table */
Job _jobs[MAX_JOBS];

static void
initJobs(
    void
    )
{
    int i;

    for (i = 0; i < ARRAY_SIZE(_jobs); i++)
    {
        Job *j = &_jobs[i];

        j->used = FALSE;
        j->delayed.flag = FALSE;
        j->delayed.size = 0;
        j->info.documentName = j->document;
        j->info.pStatus = j->status;
        j->info.securityDescriptor = j->sd;
    }
}

static Job*
getJobByID(
    NQ_UINT32 id
    )
{
    int i;

    for (i = 0; i < ARRAY_SIZE(_jobs); i++)
    {
        Job *j = &_jobs[i];

        if (j->used && j->info.id == id)
            return j;
    }

    return NULL;
}

static Job*
getJobByPos(
    int pos
    )
{
    int i;

    for (i = 0; i < ARRAY_SIZE(_jobs); i++)
    {
        Job *j = &_jobs[i];

        if (j->used && j->info.position == pos)
            return j;
    }

    return NULL;
}

static Job*
newJob(
    void
    )
{
    static NQ_UINT32 id = 1;

    int i;

    for (i = 0; i < ARRAY_SIZE(_jobs); i++)
    {
        Job *j = &_jobs[i];

        if (!j->used)
        {
            /* unused slot found, assign new id */
            j->info.id = id++;

            j->info.pagesPrinted = 0;
            j->info.totalPages = 0;
            j->info.size = 0;
            j->info.status = 0;
            j->info.securityDescriptorLength = sizeof(j->sd);

            return j;
        }
    }

    return NULL;
}

static Job*
nextJob(
    NQ_INT printer,
    NQ_UINT32 position
    )
{
    int i;
    Job *next = NULL;

    /* shift job positions for this printer starting from "position+1" while searching */
    for (i = 0; i < ARRAY_SIZE(_jobs); i++)
    {
        Job *j = &_jobs[i];

        /* next job (if exists) will be in "position+1" */
        if (j->used && j->printer == printer)
        {
            if (j->info.position > position && --j->info.position == position)
                next = j;
        }
    }

    return next;
}

static NQ_BOOL
getJobAndPrinter(
    NQ_UINT32 job,
    NQ_BOOL current,
    Job **j,
    Printer **p,
    const char *function
    )
{
    *j = getJobByID(job);

    if (*j != NULL)
    {
        *p = getPrinter((*j)->printer);

        if (*p != NULL)
        {
            if (!current || (*p)->job == (*j)->info.id)
                return TRUE;
            else
                TRC3P("NQPR: job %d is not current on printer %d (%s)", job, (*j)->printer, function);
        }
        else
            TRC2P("NQPR: printer %d not found (%s)", (*j)->printer, function);
    }
    else
        TRC2P("NQPR: job %d not found (%s)", job, function);

    return FALSE;
}

static NQ_INT
writeToPrinter(
    Printer *p,
    Job *j,
    const NQ_BYTE *buffer,
    NQ_UINT32 size
    )
{
#ifndef SIMULATION_MODE
    /* actual writing to the printer */
    NQ_INT written = write(p->fd, buffer, size);
#else
    /* fake writing with sleep for 2 seconds */
    NQ_INT written = (NQ_INT)size;

#ifdef SHOW_PRINTING_PROCESS
    syPrintf("NQPR:  Job #%ld - printing %d bytes (total %d)...\n", j->info.id, size, j->info.size);
#endif
    sleep(2);
#endif

    p->info.totalBytes += ((written == -1) ? 0 : (NQ_UINT32)written);
    j->info.size += ((written == -1) ? 0 : (NQ_UINT32)written);

    TRC1P("      written %d bytes", written);

    return written;
}

static void
closePrinter(
    Printer *p
    )
{
    if (p->fd > -1)
    {
#ifndef SIMULATION_MODE
        close(p->fd);
#endif
        p->fd = -1;
    }
}

static NQ_BOOL
isPrinterReady(
    Printer *p,
    Job *j
    )
{
    return p->status == 0 &&
           p->info.status == SY_PRINTERSTATUS_PRINTING &&
           j->info.status == SY_PRINTJOBSTATUS_PRINTING;
}

static void
sendLateWriteResponse(
    Job *j,
    NQ_INT written
    )
{
    CMRpcPacketDescriptor out;

    if (j->delayed.flag)
    {
        j->delayed.flag = FALSE;

        csDcerpcPrepareLateResponse(&j->delayed.ctx);
        cmRpcSetDescriptor(&out, j->delayed.ctx.cifsContext.commandData, j->delayed.ctx.nbo);
        cmRpcPackUint32(&out, (NQ_UINT32)written);
        csDcerpcSendLateResponse(&j->delayed.ctx, 0, sizeof(NQ_UINT32));
    }
}

static void
onResumeJob(
    Printer *p,
    Job *j
    )
{
    /* check if this job is current and there is delayed data */
    if (j == NULL || p->job != j->info.id || !j->delayed.flag)
        return;

    TRC1P("NQPR: trying to resume job %ld... ", j->info.id);
#ifdef SHOW_PRINTING_PROCESS
    syPrintf("NQPR: trying to resume job %ld...\n", j->info.id);
#endif

    if (isPrinterReady(p, j))
    {
        /* write delayed data from the job buffer to the printer */
        NQ_INT written = writeToPrinter(p, j, j->delayed.data, j->delayed.size);

        sendLateWriteResponse(j, written);
    }
    else
    {
        TRCERR("NQPR:    printer not ready\n");
#ifdef SHOW_PRINTING_PROCESS
        syPrintf("NQPR:    printer not ready\n");
#endif
    }
}

static NQ_BOOL
startJob(
    Job *j,
    Printer *p
    )
{
#ifndef SIMULATION_MODE
    /* if printer fd is already open do not open it again */
    if (p->fd == -1 && ((p->fd = open(p->device, O_RDWR)) == -1))
    {
        TRC1P("NQPR: could not open printer device %s", p->device);

        return FALSE;
    }
#else
    /* set printer's file descriptor to 0 */
    p->fd = 0;
#endif

    if (getDeviceStatusByFD(p->fd, &p->status))
    {
        p->job = j->info.id;
        p->info.status |= SY_PRINTERSTATUS_PRINTING;

        /* start the job only if it is new or in "blocked" state */
        j->info.status &= (NQ_UINT32)(~SY_PRINTJOBSTATUS_BLOCKED);
        j->info.status |= SY_PRINTJOBSTATUS_PRINTING;
        syAnsiToUnicode(j->status, "Printing");

        onResumeJob(p, j);

        return TRUE;
    }
    else
        TRC1P("NQPR: could not obtain status for printer device %s", p->device);

    return FALSE;
}

static int
addJob(
    int printer,
    const NQ_WCHAR *document,
    const NQ_BYTE *sd,
    NQ_COUNT sdlen,
    const void *pUser
    )
{
    Job *j = newJob();

    if (j != NULL)
    {
        Printer *p = getPrinter(printer);

        if (p != NULL)
        {
            /* mark this slot as used */
            j->used = TRUE;

            /* initialize some job info */
            j->printer = printer;
            j->info.position = p->info.cJobs++;
            j->info.user = pUser;
                /* document name */
            cmTStrcpy(j->document, document);
                /* security descriptor and length */
            j->info.securityDescriptorLength = (NQ_UINT32)(sdlen < sizeof(j->sd) ? sdlen : sizeof(j->sd));
            syMemcpy(j->sd, sd, j->info.securityDescriptorLength);

            /* mark the new job as "blocked" by default */
            j->info.status |= SY_PRINTJOBSTATUS_BLOCKED;
            syAnsiToUnicode(j->status, "Blocked");

            if (p->job == -1)
            {
                /* printer is idle - start this job immediately */
                TRC1P("NQPR: starting new job %ld immediately", j->info.id);
#ifdef SHOW_PRINTING_PROCESS
                syPrintf("NQPR: starting new job %ld immediately\n", j->info.id);
#endif

                if (!startJob(j, p))
                    return -1;
            }
            else
            {
                TRC2P("NQPR: new job %ld added to the queue at position %ld", j->info.id, j->info.position);
#ifdef SHOW_PRINTING_PROCESS
                syPrintf("NQPR: new job %ld added to the queue at position %ld\n", j->info.id, j->info.position);
#endif
            }

            return (int)j->info.id;
        }
        else
            TRC1P("NQPR: printer %d not found", printer);
    }

    TRC1P("NQPR: job limit exceeded (%d)", ARRAY_SIZE(_jobs));
    return -1;
}

static NQ_BOOL
endJob(
    NQ_UINT32 job
    )
{
    Job *j, *next;
    Printer *p;

    /* do not check if the job is current here */
    if (!getJobAndPrinter(job, FALSE, &j, &p, "endJob()"))
        return FALSE;

    TRC1P("NQPR: ending job %ld", j->info.id);
#ifdef SHOW_PRINTING_PROCESS
    syPrintf("NQPR: ending job %ld\n", j->info.id);
#endif

    p->info.cJobs--;

    /* send delayed response (if any) */
    sendLateWriteResponse(j, 0);
    /* mark this slot as unused */
    j->used = FALSE;
    /* find next queued job starting from this job's position (and shift job positions down) */
    next = nextJob(j->printer, j->info.position);

    /* start next job only if this one was current otherwise just release postponed
       write response */
    if (p->job == job)
    {
        p->info.status &= (NQ_UINT32)(~SY_PRINTERSTATUS_PRINTING);
        p->info.totalJobs++;

        /* close printer device */
        closePrinter(p);

        if (next != NULL)
        {
            TRC3P("NQPR: starting next job %ld on printer %d (total jobs: %ld)",
                  next->info.id, j->printer, p->info.cJobs);
#ifdef SHOW_PRINTING_PROCESS
            syPrintf("NQPR: starting next job %ld on printer %d (total jobs: %ld)\n",
                  next->info.id, j->printer, p->info.cJobs);
#endif

            return startJob(next, p);
        }

        TRC1P("NQPR: no more jobs for printer %d", j->printer);
#ifdef SHOW_PRINTING_PROCESS
        syPrintf("NQPR: no more jobs for printer %d\n", j->printer);
#endif

        p->job = (NQ_UINT32)-1;
    }

    return TRUE;
}

/* ################################################################ */
/* ################################################################ */

static NQ_BOOL
getProperty(
    const char *source,
    const char *name,
    char *buffer,
    size_t limit
    )
{
    char tmp[16];
    const char *p, *end;

    /* add ':' to the supplied name */
    strcpy(tmp, name);
    strcat(tmp, ":");

    /* find first occurrence of "name:" in the string */
    if ((p = strstr(source, tmp)) == NULL)
        return FALSE;

    /* skip name characters until ':' */
    if ((p = strchr(p, ':')) == NULL)
        return FALSE;

    /* property value starts at the next character and ends with ';' */
    if ((end = strchr(++p, ';')) == NULL)
        return FALSE;

    /* preserve space in the buffer for null terminator and calculate value length for copying */
    if (--limit > end - p)
        limit = (size_t)(end - p);

    /* copy the value and set null terminator */
    syStrncpy(buffer, p, limit);
    buffer[limit] = '\0';

    return TRUE;
}

static NQ_BOOL
initPrinter(
    const NQ_WCHAR *device,
    Printer *p
    )
{
    /*NQ_WCHAR space[] = {cmTChar(' '), cmTChar('\0')};*/
    static char buffer[512];
    char property[64];
    int vendor, product;
#ifndef SIMULATION_MODE
    const char *ds = buffer + 2;
#else
    const char *ds = buffer;
#endif

    syUnicodeToAnsi(deviceA, device);
    if (!getDeviceInfo(deviceA, buffer, sizeof(buffer), &vendor, &product, &p->status))
        return FALSE;

    TRC1P("NQPR: device ID for %s is:", cmTDump(device));
    TRC1P("[%s]", ds);
    TRC3P("NQPR: vendor=%x, product=%x, device status 0x%lx", vendor, product, p->status);

    /* reset user controled status */
    p->info.status = 0;

    getProperty(ds, "MFG", property, sizeof(property));
    syAnsiToUnicode(p->manufacturer, property);
    getProperty(ds, "MDL", property, sizeof(property));
    syAnsiToUnicode(p->model, property);

    /* construct full printer name */
/*  cmTStrcpy(p->name, p->manufacturer);
    cmTStrcat(p->name, space);
    cmTStrcat(p->name, p->model);*/
    
    /* store the device name */
    syUnicodeToAnsi(p->device, device);

    return TRUE;
}

/* ################################################################ */
/* ################################################################ */

static void
setPrinterInfoPointers(
    Printer *p
    )
{
    p->info.driverName = /*NULL*/p->name;
    p->info.comment = p->comment;
    p->info.location = p->location;
    p->info.parameters = p->parameters;
    p->info.portName = p->portName;
    p->info.printProcessor = p->printProcessor;
    p->info.sepFile = p->sepFile;
    p->info.dataType = p->dataType;
    p->info.securityDescriptor = p->sd;
    p->info.devMode.formName = p->formName;
    p->info.devMode.driverExtraData = p->extra;
}

NQ_BOOL
syInitPrinters(
    void
    )
{
    NQ_INT i;

    /* initialize job table */
    initJobs();

    for (i = 0; i < ARRAY_SIZE(_printers); i++)
    {
        Printer *p = &_printers[i];

        /* NQ_CHAR buffer[32]; */

        p->device[0] = '\0';
        p->fd = -1;
        p->job = (NQ_UINT32)-1;
        p->status = SY_PRINTERSTATUS_NOTAVAILABLE;

        /* prepare data */
        syAnsiToUnicode(p->name, "");
        syAnsiToUnicode(p->comment, "");
        syAnsiToUnicode(p->location, "");
        syAnsiToUnicode(p->parameters, "");
        syAnsiToUnicode(p->portName, "NQ Printer Port");
        syAnsiToUnicode(p->printProcessor, "winprint");
        syAnsiToUnicode(p->sepFile, "");
        syAnsiToUnicode(p->dataType, "RAW");
        syAnsiToUnicode(p->formName, "A4");

        /* information */
        p->info.averagePpm = 0;        
        p->info.deviceNotSelectedTimeout = 0;
        p->info.flags = 0;
        p->info.priority = 0;
        p->info.startTime = 0;   
        p->info.transmissionRetryTimeout = 0;
        p->info.untilTime = 0;
        p->info.securityDescriptorLength = 0;
        p->info.attributes = SY_PRINTERATTR_SHARED | SY_PRINTERATTR_LOCAL;
        p->info.priority = 1;
        p->info.defaultPriority = 1;
        p->info.startTime = 0;
        p->info.untilTime = 0;
        p->info.cJobs = 0;
        p->info.totalJobs = 0;
        p->info.totalBytes = 0;
        p->info.globalCounter = 1;
        p->info.totalPages = 0;
        p->info.majorVersion = 0;
        p->info.buildVersion = 0;
        p->info.sessionCounter = 1;
        p->info.printerErrors = 0;
        p->info.cSetPrinter = 0;
        p->info.averagePpm = 0;

        /* dev mode */
        syMemset(&p->info.devMode, 0, sizeof(p->info.devMode));
        p->info.devMode.size = sizeof(p->info.devMode);
        p->info.devMode.fields = 0x10000;  /* form name field set */

        /* initialize pointers in the information structure */
        setPrinterInfoPointers(p);
    }

    return TRUE;
}

/* ################################################################ */
/* ################################################################ */

/*
 *====================================================================
 * PURPOSE: get printer handle by name
 *--------------------------------------------------------------------
 * PARAMS:  IN printer name
 *
 * RETURNS: printer handle or invalid printer handle
 *
 * NOTES:
 *====================================================================
 */

SYPrinterHandle
syGetPrinterHandle(
    const NQ_WCHAR* name
    )
{
    SYPrinterHandle h = findPrinter(name);
    Printer *p;

    /* if printer not found create and initialize it */
    if (h == -1)
    {
        TRC1P("NQPR: printer handle not found for '%s', allocating new one...", cmTDump(name));

        /* find new printer table entry (*note* this does not mark it as "used")*/
        if ((h = newPrinter()) == -1)
        {
            TRC1P("      (!) could not allocate new entry for printer %s", cmTDump(name));

            return -1;
        }

        TRC1P("      entry allocated at %d, initializing...", h);
    }

    p = getPrinter(h);

    /* initialize printer */
    if (p->status & SY_PRINTERSTATUS_NOTAVAILABLE)
        initPrinter(name, p);

    return h;
}

/*
 *====================================================================
 * PURPOSE: get printer info
 *--------------------------------------------------------------------
 * PARAMS:  IN printer handle
 *          OUT printer structure to fill in
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:
 *====================================================================
 */

NQ_STATUS
syGetPrinterInfo(
    SYPrinterHandle handle,
    SYPrinterInfo* info
    )
{
    Printer *p = getPrinter(handle);

    TRC1P("NQPR: get printer %d info ", handle);

    if (p != NULL)
    {
        /* get fresh printer status */
        NQ_BOOL result = (p->fd > -1) ? getDeviceStatusByFD(p->fd, &p->status) :
                                        getDeviceStatusByName(p->device, &p->status);

        if (result)
        {
            *info = p->info;
            /* combine device and user assigned status */
            info->status |= p->status;

            TRC2P("      (status d:0x%lx u:0x%lx)", p->status, p->info.status);

            return NQ_SUCCESS;
        }
        else
        {
            TRC1P("      (!) getting device status failed, p->fd=%d", p->fd);

            closePrinter(p);
            p->status = SY_PRINTERSTATUS_NOTAVAILABLE;
        }
    }
    else
        TRC("      (!) not found");

    return NQ_FAIL;
}

static void
safeTStrcpy(
    NQ_WCHAR *to,
    const NQ_WCHAR *from
    )
{
    if (from && to)
        cmTStrcpy(to, from);
}

/*
 *====================================================================
 * PURPOSE: set printer info
 *--------------------------------------------------------------------
 * PARAMS:  IN printer handle
 *          IN printer structure to store in
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:
 *====================================================================
 */

NQ_STATUS
sySetPrinterInfo(
    SYPrinterHandle idx,
    const SYPrinterInfo* info
    )
{
    Printer *p = getPrinter(idx);

    TRC1P("NQPR: setting printer %d info... ", idx);

    if (p == NULL)
    {
        TRC("      (!) not found");
        return NQ_FAIL;
    }

    p->info = *info;
    setPrinterInfoPointers(p);

    safeTStrcpy(p->comment, info->comment);
    safeTStrcpy(p->name, info->driverName);
    safeTStrcpy(p->location, info->location);
    safeTStrcpy(p->parameters, info->parameters);
    safeTStrcpy(p->portName, info->portName);
    safeTStrcpy(p->printProcessor, info->printProcessor);
    safeTStrcpy(p->sepFile, info->sepFile);
    safeTStrcpy(p->dataType, info->dataType);
    safeTStrcpy(p->formName, info->devMode.formName);

    return NQ_SUCCESS;
}

/*
 *====================================================================
 * PURPOSE: get printer driver info
 *--------------------------------------------------------------------
 * PARAMS:  IN printer handle
 *          IN required OS
 *          OUT driver structure to fill in
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:
 *====================================================================
 */

NQ_STATUS
syGetPrinterDriver(
    SYPrinterHandle handle,
    const NQ_WCHAR* os,
    SYPrinterDriver* info
    )
{
/*    static const NQ_WCHAR *list[] = {NULL, NULL};
    static const NQ_WCHAR empty[] = {(NQ_WCHAR)0};
    Printer *p = getPrinter(handle);

    TRC2P("NQPR: get printer %d driver, os='%s'", handle, cmTDump(os));

    if (p == NULL)
    {
        TRC("      (!) not found");
        return NQ_FAIL;
    }

    info->osVersion = SY_PRINTEROSVERSION_WIN;
    info->name = p->name;
    info->driverPath = empty;
    info->dataFile = empty;
    info->configFile = empty;
    info->helpFile = empty;
    info->dependentFiles = list;
    info->monitorName = empty;
    info->defaultDataType = 0;
    info->previousNames = list;
    info->driverDate = 0;
    info->manufacturer = p->manufacturer;
    info->manufacturerURL = empty;
    info->hardwareID = empty;
    info->provider = empty;
    info->attributes = 0;
    info->configVersion = 0;
    info->driverVersion = 0;
    info->driverVersions[0] = info->driverVersions[1] = 0;

    return NQ_SUCCESS;*/

    return NQ_FAIL;
}

/*
 *====================================================================
 * PURPOSE: set security descriptor for printer as raw data block
 *--------------------------------------------------------------------
 * PARAMS:  IN printer name
 *          IN pointer to descriptor
 *          IN descriptor length
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:
 *====================================================================
 */

NQ_STATUS
syPrinterSetSecurityDescriptor(
    SYPrinterHandle idx,
    const NQ_BYTE* descriptor,
    NQ_UINT32 length
    )
{
    Printer *p = getPrinter(idx);

    if (p != NULL)
    {
        memcpy(p->sd, descriptor, (size_t)length);
        p->info.securityDescriptorLength = length;

        return NQ_SUCCESS;
    }

    TRC2P("NQPR: (!) setting security descriptor for printer %d (length=%d) failed", idx, length);

    return NQ_FAIL;
}

/*
 *====================================================================
 * PURPOSE: get security descriptor for printer as raw data block
 *--------------------------------------------------------------------
 * PARAMS:  IN printer name
 *          OUT buffer for SD data
 *          IN buffer length
 *
 * RETURNS: SD length
 *
 * NOTES:
 *====================================================================
 */

NQ_COUNT
syPrinterGetSecurityDescriptor(
    SYPrinterHandle idx,
    NQ_BYTE* buffer,
    NQ_COUNT bufferLength
    )
{
    Printer *p = getPrinter(idx);

    if (p != NULL)
    {
        if (bufferLength < p->info.securityDescriptorLength)
            return 0;

        memcpy(buffer, p->sd, p->info.securityDescriptorLength);

        return (NQ_COUNT)p->info.securityDescriptorLength;
    }

    TRC1P("NQPR: getting security descriptor for printer %d failed", idx);

    return 0;
}

/*
 *====================================================================
 * PURPOSE: start new print job
 *--------------------------------------------------------------------
 * PARAMS:  IN printer handle
 *          IN document name
 *          IN file name
 *          IN data type or NULL
 *          IN poniter to job owner
 *
 * RETURNS: zero on error, job id on success
 *
 * NOTES:
 *====================================================================
 */

NQ_UINT32
syStartPrintJob(
    SYPrinterHandle handle,
    const NQ_WCHAR* name,
    const NQ_WCHAR* file,
    const NQ_WCHAR* type,
    const NQ_BYTE* sd,
    NQ_COUNT sdLen,
    const void *pUser
    )
{
    TRC1P("NQPR: +++ Job start requested (printer=%d)", handle);
#ifdef SHOW_PRINTING_PROCESS
    syPrintf("NQPR: +++ Job start requested (printer=%d)\n", handle);
#endif
 
    return (NQ_UINT32)addJob(handle, name, sd, sdLen, pUser);
}

/*
 *====================================================================
 * PURPOSE: End print job
 *--------------------------------------------------------------------
 * PARAMS:  IN printer handle
 *          IN job ID
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:
 *====================================================================
 */

NQ_STATUS
syEndPrintJob(
    SYPrinterHandle handle,
    NQ_UINT32 jobId
    )
{
    TRC2P("NQPR: --- Job end requested (printer=%d, job=%ld)", handle, jobId);
#ifdef SHOW_PRINTING_PROCESS
    syPrintf("NQPR: --- Job end requested (printer=%d, job=%ld)\n", handle, jobId);
#endif

    return endJob(jobId) ? NQ_SUCCESS : NQ_FAIL;
}

/*
 *====================================================================
 * PURPOSE: Start new page
 *--------------------------------------------------------------------
 * PARAMS:  IN printer handle
 *          IN job ID
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:
 *====================================================================
 */

NQ_STATUS
syStartPrintPage(
    SYPrinterHandle handle,
    NQ_UINT32 jobId
    )
{
    Job *j;
    Printer *p;

    TRC2P("NQPR: + new page (printer=%d, job=%ld)... ", handle, jobId);

    if (!getJobAndPrinter(jobId, FALSE, &j, &p, "syStartPrintPage()"))
        return NQ_FAIL;

    return NQ_SUCCESS;
}

/*
 *====================================================================
 * PURPOSE: End page
 *--------------------------------------------------------------------
 * PARAMS:  IN printer handle
 *          IN job ID
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:
 *====================================================================
 */

NQ_STATUS
syEndPrintPage(
    SYPrinterHandle handle,
    NQ_UINT32 jobId
    )
{
    Job *j;
    Printer *p;

    TRC2P("NQPR: - end page (printer=%d, job=%ld)", handle, jobId);

    if (!getJobAndPrinter(jobId, TRUE, &j, &p, "syEndPrintPage()"))
        return NQ_FAIL;

    /* note: j->info.pagesPrinted should always be zero */
    j->info.totalPages++;
    p->info.totalPages++;

    return NQ_SUCCESS;
}

/*
 *====================================================================
 * PURPOSE: Print data portion
 *--------------------------------------------------------------------
 * PARAMS:  IN printer handle
 *          IN job ID
 *          IN pointer to data
 *          IN data length
 *          IN/OUT place for response context pointer 
 *
 * RETURNS: number of bytes written or -1 on error
 *
 * NOTES:
 *====================================================================
 */

NQ_INT32
syWritePrintData(
    SYPrinterHandle handle,
    NQ_UINT32 jobId,
    const NQ_BYTE* data,
    NQ_UINT32 count,
    void **rctx
    )
{
    Job *j;
    Printer *p;
    CSDcerpcResponseContext **ctx = (CSDcerpcResponseContext **)rctx;

    TRC3P("NQPR: * print data (printer=%d, job=%ld, bytes=%ld)... ", handle, jobId, count);

    if (getJobAndPrinter(jobId, FALSE, &j, &p, "syWritePrintData()"))
    {
        if (p->job == jobId)
        {
            if (!getDeviceStatusByFD(p->fd, &p->status))
            {
                TRC("NQPR:      (!) failed to obtain device status");

                return -1;
            }

            TRC3P("NQPR:      d:0x%lx u:0x%lx j:0x%lx", p->status, p->info.status, j->info.status);

            if (isPrinterReady(p, j))
            {
                return writeToPrinter(p, j, data, count);
            }
            else
                TRC("NQPR:      wrong status");
        }
        else
            TRC("NQPR:      the job is not current");

        TRC("NQPR:      delaying response");
#ifdef SHOW_PRINTING_PROCESS
        printf("NQPR:      delaying response\n");
#endif
        /* save data to be written in the job buffer */
        memcpy(j->delayed.data, data, count);
        j->delayed.size = count;
        j->delayed.flag = TRUE;
        /* delay response */
        *ctx = &j->delayed.ctx;

        return 0;
    }

    return -1;
}

/*
 *====================================================================
 * PURPOSE: get job ID by its index in the queue
 *--------------------------------------------------------------------
 * PARAMS:  IN printer handle
 *          IN job index in the queue
 *
 * RETURNS: job ID or NQ_FAIL when no more jobs
 *
 * NOTES:   This call is issued continuously for each job, syEnumPrintJobStart()
 *          should precede.
 *====================================================================
 */

NQ_INT32
syGetPrintJobIdByIndex(
    SYPrinterHandle handle,
    NQ_INT jobIdx
    )
{
    Job *j = getJobByPos(jobIdx);

    if (j == NULL)
    {
        TRC2P("NQPR: (!) get job ID by index (printer=%d, job index=%d)... job not found", handle, jobIdx);

        return NQ_FAIL;
    }

    return (NQ_INT32)j->info.id;
}

/*
 *====================================================================
 * PURPOSE: get job index in the queue by its ID
 *--------------------------------------------------------------------
 * PARAMS:  IN printer handle
 *          IN job ID
 *
 * RETURNS: job index in the queue or NQ_FAIL when no more jobs
 *
 * NOTES:   This call is issued continuously for each job, syEnumPrintJobStart()
 *          should precede.
 *====================================================================
 */

NQ_INT32
syGetPrintJobIndexById(
    SYPrinterHandle handle,
    NQ_UINT32 jobId
    )
{
    Job *j = getJobByID(jobId);

    if (j == NULL)
    {
        TRC2P("NQPR: (!) get job index by ID (printer=%d, job ID=%ld)... job not found", handle, jobId);

        return NQ_FAIL;
    }

    return (NQ_INT32)j->info.position;
}

/*
 *====================================================================
 * PURPOSE: get job information by its ID
 *--------------------------------------------------------------------
 * PARAMS:  IN printer handle
 *          IN job ID
 *          OUT poiter to the structure to be filled with job info
 *
 * RETURNS: OK when next entry is avaialble or NQ_FAIL when no more jobs
 *
 * NOTES:   This call is issued continuously for each job, syEnumPrintJobStart()
 *          should precede.
 *====================================================================
 */

NQ_STATUS
syGetPrintJobById(
    SYPrinterHandle handle,
    NQ_UINT32 jobId,
    SYPrintJobInfo* info
    )
{
    Job *j = getJobByID(jobId);

    if (j == NULL)
    {
        TRC2P("NQPR: (!) get job by ID (printer=%d, job ID=%ld)... job not found", handle, jobId);

        return NQ_FAIL;
    }

    *info = j->info;

    return NQ_SUCCESS;
}

/*
 *====================================================================
 * PURPOSE: get form information
 *--------------------------------------------------------------------
 * PARAMS:  IN printer handle
 *          IN form index in the queue
 *          OUT poiter to the structure to be filled with form info
 *
 * RETURNS: OK when next entry is avaialble or NQ_FAIL when no more jobs
 *
 * NOTES:   This call is issued continuously for each job, syEnumPrintJobStart()
 *          should precede.
 *====================================================================
 */

NQ_STATUS
syGetPrintForm(
    SYPrinterHandle handle,
    NQ_UINT32 formIdx,
    SYPrintFormInfo* info
    )
{
    static NQ_WCHAR letter[16];
    static NQ_WCHAR a4[8];

    syAnsiToUnicode(letter, "Letter");
    syAnsiToUnicode(a4, "A4");

    info->id = formIdx;
    info->flags = SY_PRINTFORMFLAG_BUILTIN;
    info->imageableArea.top = 0;
    info->imageableArea.left = 0;

    switch (formIdx)
    {
        case 0:
            info->name = letter;
            info->size.width = info->imageableArea.right = 215900;
            info->size.height = info->imageableArea.bottom = 279400;

            return NQ_SUCCESS;

        case 1:
            info->name = a4;
            info->size.width = info->imageableArea.right = 210000;
            info->size.height = info->imageableArea.bottom = 297000;

            return NQ_SUCCESS;
    }

    return NQ_FAIL;
}

/*
 *====================================================================
 * PURPOSE: perform control command on printer
 *--------------------------------------------------------------------
 * PARAMS:  IN printer handle
 *          IN control command see sycommon.h
 *
 * RETURNS: OK when command was performed or NQ_FAIL on failure
 *
 * NOTES:   This call is issued continuously for each job, syEnumPrintJobStart()
 *          should precede.
 *====================================================================
 */

NQ_STATUS
syControlPrinter(
    SYPrinterHandle handle,
    NQ_UINT32 command
    )
{
    Printer *p = getPrinter(handle);

    TRC2P("NQPR: control printer %d, command=%ld", handle, command);

    if (p != NULL)
    {
        switch (command)
        {
            case SY_PRINTERCONTROL_PAUSE:
                TRC("      pause");
                p->info.status |= SY_PRINTERSTATUS_PAUSED;
                break;
            case SY_PRINTERCONTROL_RESUME:
                TRC("      resume");
                p->info.status &= (NQ_UINT32)(~SY_PRINTERSTATUS_PAUSED);
                onResumeJob(p, getJobByID(p->job));
                break;
            case SY_PRINTERCONTROL_PURGE:
                TRC("      purge");
                /* delete all jobs for this printer */
                while (p->job != -1)
                {
                    TRC1P("      Ending job %ld", p->job);
                    endJob(p->job);
                }
                break;
            default:
                TRC("      (!) unknown command");
                return NQ_FAIL;
        }

        return NQ_SUCCESS;
    }
    else
        TRC("      (!) printer not found");

    return NQ_FAIL;
}

/*
 *====================================================================
 * PURPOSE: perform control command on a job
 *--------------------------------------------------------------------
 * PARAMS:  IN printer handle
 *          IN job index in the queue
 *          IN control command see sycommon.h
 *
 * RETURNS: OK when command was performed or NQ_FAIL on failure
 *
 * NOTES:   This call is issued continuously for each job, syEnumPrintJobStart()
 *          should precede.
 *====================================================================
 */

NQ_STATUS
syControlPrintJob(
    SYPrinterHandle handle,
    NQ_UINT32 jobIdx,                /* id? */
    NQ_UINT32 command
    )
{
    Job *j;
    Printer *p;

    TRC3P("NQPR: control job (printer=%d, job index=%d, command=%ld)... ", handle, jobIdx, command);

    if (getJobAndPrinter(jobIdx, FALSE, &j, &p, "syControlPrintJob()"))
    {
        switch (command)
        {
            case SY_PRINTJOBCOM_PAUSE:
                TRC("      pause");
                j->info.status |= SY_PRINTJOBSTATUS_PAUSED;
                break;
            case SY_PRINTJOBCOM_RESUME:
                TRC("      resume");
                j->info.status &= (NQ_UINT32)(~SY_PRINTJOBSTATUS_PAUSED);
                onResumeJob(p, j);
                break;
            case SY_PRINTJOBCOM_CANCEL:
            case SY_PRINTJOBCOM_DELETE:
                TRC("      cancel/delete");
                return endJob(j->info.id) ? NQ_SUCCESS : NQ_FAIL;
                break;
            case SY_PRINTJOBCOM_RESTART:
                TRC("      restart not supported");
                return NQ_FAIL;
            default:
                TRC("      unknown command");
                return NQ_FAIL;
        }

        return NQ_SUCCESS;
    }

    return NQ_FAIL;
}

#endif  /* UD_CS_INCLUDERPC_SPOOLSS */
