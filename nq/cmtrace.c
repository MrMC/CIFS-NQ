/*********************************************************************
 *
 *           Copyright (c) 2008 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Trace common definitions
 *--------------------------------------------------------------------
 * MODULE        : CM - Common Library
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 08-Dec-2008
 * CREATED BY    : Lilia Wasserman
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "cmtrace.h"
#include "cmthread.h"

#ifdef UD_NQ_INCLUDETRACE

#define CM_DEBUG_DUMP_BLOCK_SIZE  16

/*  Format definition of an internal log message. */
typedef enum{
    
    TYPE_VERSION    = 'V',   /* Version record. This record is placed once at the very beginning of the log. */
    TYPE_START      = 'S',   /* Thread start. This record appears once on a thread start. It marks a new thread and contains its name. */    
    TYPE_STOP       = 'T',   /* Thread stop. This record appears once on a thread end. */    
    TYPE_ENTER      = 'F',   /* Function entrance. This record marks an entrance into a function execution. */    
    TYPE_LEAVE      = 'L',   /* Function exit. This record marks an exit from a function execution. */    
    TYPE_ERROR      = 'E',   /* Error message. This record contains error text and system error code. */    
    TYPE_INFO       = 'I'    /* Information message. This record contains general purpose text. */
}
CMRecordTypes;

typedef struct{
    NQ_UINT32  id;           /* Record ID. Used for sequencing. */
    NQ_CHAR    type;         /* Record type. See CMRecordTypes above. */
    NQ_INT     thread;       /* Thread ID. This number is provided by OS. */
    NQ_TIME    timestamp;    /* Record time. The system time when this record was created. */
    NQ_UINT    level;        /* Severity. Abstract record priority, used by viewer. */
    NQ_CHAR    file[64];     /* Source file. This should be supported by the OS. */    
    NQ_CHAR    function[64]; /* Called function. This should be supported by the OS. */ 
    NQ_UINT    line;         /* Source line. This should be supported by the OS. */    
    NQ_UINT32  error;        /* Error code. This should be supported by the OS. */
    NQ_CHAR    data[256];    /* Record information. Pointer to the variable argument list starting with format string and followed by format arguments. */
} 
CMLogRecord;    

typedef struct{
    CMLogRecord record;
    NQ_CHAR buffer[1460];
}
CMTrace;

static NQ_BOOL initialized = FALSE;
static NQ_BOOL shutdwn = FALSE;
static CMThread thread;
static SYSocketHandle sendSocket;
#ifdef SY_REMOTE_LOG
static NQ_IPADDRESS addr;
static SYSocketHandle remoteLogSocket;
#endif
static const NQ_IPADDRESS localHost = CM_IPADDR_LOCAL;
static SYMutex  endMutex;
#ifdef SY_FILE_LOG
static SYFile file = syInvalidFile();
#endif
static const NQ_CHAR *truncateFileName(const NQ_CHAR *path)
{
    NQ_CHAR *p = syStrrchr(path, SY_PATHSEPARATOR); 
    return (p == NULL ? path : p + 1);
}

static void traceHeader(CMLogRecord *record, NQ_CHAR mt, NQ_UINT level, const NQ_CHAR *file, const NQ_CHAR *function, NQ_UINT line)
{
    static NQ_UINT32 id = 0;
    char *parenthesis = "()";                               
    
    record->id = ++id;
    record->thread = (NQ_INT)syThreadGetCurrent();
    record->timestamp = (NQ_TIME)syGetTime();
    record->level = level;
    syStrcpy(record->file, truncateFileName(file));
    syStrcpy(record->function, function);
    syStrncat(record->function, parenthesis, syStrlen(parenthesis));
    record->line = line;
    record->type = mt;
}

#ifdef SY_REMOTE_LOG
static void writeToRemoteLog(const NQ_CHAR *buffer, NQ_UINT32 size)
{    
    NQ_INT res;  

    if (initialized && syIsValidSocket(remoteLogSocket))
    {
        res = sySendToSocket(remoteLogSocket, (const NQ_BYTE *)buffer, (NQ_COUNT)size, &addr, syHton16(SY_LOG_SRV_PORT));
        if (res != size)
        {
            syPrintf("sendto returned %d, error: %d\n", res, syGetLastError());
        }
    }
}
#endif /* SY_REMOTE_LOG */

#ifdef SY_FILE_LOG
static void writeToFileLog(const NQ_CHAR *buffer, NQ_UINT32 size)
{
    syWriteFile(file, (const NQ_BYTE *)buffer, size);
}
#endif /* SY_FILE_LOG */

static void writeTrace(CMTrace *trc)
{
    NQ_UINT32 size;
    CMLogRecord *record = &trc->record;

    size = (NQ_UINT32)sySnprintf(trc->buffer, sizeof(trc->buffer), "%c;%lu;%d;%lu;%d;%s;%s;%d", record->type, (unsigned long)record->id, record->thread, (unsigned long)record->timestamp, (NQ_UINT)record->level, record->file, record->function, record->line);
    switch (record->type)
    {
        case TYPE_ERROR:
            size += (NQ_UINT32)sySnprintf(trc->buffer + size, (NQ_UINT)(sizeof(trc->buffer) - size), ";%lu", (unsigned long)record->error);
        case TYPE_VERSION:
        case TYPE_START:
        case TYPE_STOP:
        case TYPE_INFO:
            size += (NQ_UINT32)sySnprintf(trc->buffer + size, sizeof(trc->buffer) - size, ";%s", record->data);  
        default:
            size += (NQ_UINT32)sySnprintf(trc->buffer + size, sizeof(trc->buffer) - size, "\n");
    }
    /* send datagram */
    if (initialized)
    {
        sySendToSocket(sendSocket, (NQ_BYTE *)trc->buffer, size, &localHost, syHton16(SY_LOG_SRV_PORT));
    }
}

static void threadBody(void)
{
    SYSocketHandle socket;  /* receiving socket */
    NQ_BOOL active = TRUE;  /* flag to execute the body */

    socket = syCreateSocket(FALSE, CM_IPADDR_IPV4);
    if (!syIsValidSocket(socket))
    {
        syPrintf("Unable to create trace socket - %d\n", syGetLastError());
        return;
    }
    if (NQ_SUCCESS != syBindSocket(socket, &localHost, syHton16(SY_LOG_SRV_PORT)))
    {
        syCloseSocket(socket);
        syPrintf("Unable to bind trace socket - %d\n", syGetLastError());
        return;
    }
    syMutexTake(&endMutex);
    while (active)
    {
        SYSocketSet set;    /* select argument */

        syClearSocketSet(&set);
        syAddSocketToSet(socket, &set);

        if (shutdwn)
        {
            syCloseSocket(socket);
#ifdef SY_FILE_LOG
            syCloseFile(file);
#endif /* SY_FILE_LOG */
            syMutexGive(&endMutex);
            break;
        }
        
        switch(sySelectSocket(&set, 1))
        {
        case 0:
            continue;   /* timeout */
        case 1:
            {
                NQ_CHAR buffer[1460];       /* full MTU */
                NQ_INT size;              /* message size */
                NQ_IPADDRESS ip;
                NQ_PORT port;

                size = syRecvFromSocket(socket, (NQ_BYTE *)buffer, sizeof(buffer), &ip, &port);
                if (size <= 0)
                    continue;
#ifdef SY_CONSOLE_LOG
                syPrintf("%s", buffer);
#endif
#ifdef SY_REMOTE_LOG
                writeToRemoteLog(buffer, (NQ_UINT32)size);
#endif
#ifdef SY_FILE_LOG 
                writeToFileLog(buffer, (NQ_UINT32)size);
#endif 
            }
            break;
        default:
            break;
        }
    }
}

void cmTraceInit(void)
{
    if (!initialized)
    {
    
#ifdef SY_FILE_LOG
        static NQ_TCHAR filename[CM_BUFFERLENGTH(NQ_TCHAR, UD_FS_MAXPATHLEN)];

        cmAnsiToTchar(filename, SY_LOG_FILENAME);
        syDeleteFile(filename);
        file = syCreateFile(filename, FALSE, FALSE, FALSE);
        if (!syIsValidFile(file))
        {
            syPrintf("Could not create log file, error: %d\n", syGetLastError());
            return;
        }
#endif /* SY_FILE_LOG */
       
        sendSocket = syCreateSocket(FALSE, CM_IPADDR_IPV4);    
        if (syIsValidSocket(sendSocket))
        {
            syMutexCreate(&endMutex);
            cmThreadCreateAndRun(&thread, threadBody, TRUE);
            initialized = TRUE;
        }
        else
        {
            syPrintf("Unable to start log - %d\n", syGetLastError());
        }
        
#ifdef SY_REMOTE_LOG
        cmAsciiToIp(SY_LOG_SRV_IP, &addr);
        remoteLogSocket = syCreateSocket(FALSE, CM_IPADDR_IPV4);
		if (!syIsValidSocket(remoteLogSocket))
		{
			syPrintf("Could not create socket for remote log, error: %d\n", syGetLastError());
		}
#ifdef SY_REMOTE_LOG_BROADCAST  
        if (syAllowBroadcastsSocket(remoteLogSocket) == NQ_FAIL) 
        {
            syCloseSocket(remoteLogSocket);
            syPrintf("Could not set socket option for remote log, error: %d\n", syGetLastError());
        }        
#endif /* SY_REMOTE_LOG_BROADCAST */
#endif /* SY_REMOTE_LOG */
    }
}

void cmTraceFinish(void)
{
    if (initialized)
    {
        shutdwn = TRUE;
#ifdef SY_REMOTE_LOG        
        syCloseSocket(remoteLogSocket);
#endif /* SY_REMOTE_LOG */     
        syCloseSocket(sendSocket);
        cmThreadStopAndDestroy(&thread);
		syMutexDelete(&endMutex);
        initialized = FALSE;
    }
}

void cmTraceMessage(const NQ_CHAR *file, const NQ_CHAR *function, NQ_UINT line, NQ_UINT level, const NQ_CHAR *format, ...)
{
    if (level <= CM_TRC_DEBUG_LEVEL && !shutdwn && initialized)
    {
        static CMTrace trace;
        va_list args;
        CMLogRecord *record = &trace.record;
		NQ_UINT32 lastError;

		lastError = syGetLastError();
        traceHeader(record, TYPE_INFO, level, file, function, line);

        va_start(args, format);
        syVsnprintf(record->data, sizeof(record->data), format, args);
        va_end(args);

        writeTrace(&trace);
		sySetLastError(lastError);	
    }
}

void cmTraceError(const NQ_CHAR *file, const NQ_CHAR *function, NQ_UINT line, NQ_UINT level, const NQ_CHAR *format, ...)
{
    if (level <= CM_TRC_DEBUG_LEVEL && !shutdwn && initialized)
    {
        static CMTrace trace;
        va_list args;
        CMLogRecord *record = &trace.record;
		NQ_UINT32 lastError;
        
		lastError = syGetLastError();
        traceHeader(record, TYPE_ERROR, level, file, function, line);
        record->error = ((NQ_UINT32)syGetLastError());

        va_start(args, format);
        syVsnprintf(record->data, sizeof(record->data), format, args);
        va_end(args);

        writeTrace(&trace);
		sySetLastError(lastError);	
    }
}

void cmTraceFuncEnter(const NQ_CHAR *file, const NQ_CHAR *function, NQ_UINT line, NQ_UINT level)
{
    if (level <= CM_TRC_DEBUG_LEVEL && !shutdwn && initialized)
    {
        static CMTrace trace;
        CMLogRecord *record = &trace.record;
        NQ_UINT32 lastError;

		lastError = syGetLastError();
        traceHeader(record, TYPE_ENTER, level, file, function, line);
        writeTrace(&trace);
		sySetLastError(lastError);	
    }
}

void cmTraceFuncLeave(const NQ_CHAR *file, const NQ_CHAR *function, NQ_UINT line, NQ_UINT level)
{
    if (level <= CM_TRC_DEBUG_LEVEL && !shutdwn && initialized)
    {
        static CMTrace trace;
        CMLogRecord *record = &trace.record;
		NQ_UINT32 lastError;
        
		lastError = syGetLastError();
        traceHeader(record, TYPE_LEAVE, level, file, function, line);
		record->error = lastError;
        writeTrace(&trace);
		sySetLastError(lastError);
    }
}

void cmTraceStart(const NQ_CHAR *file, const NQ_CHAR *function, NQ_UINT line, NQ_UINT level, const NQ_CHAR *name)
{
    if (level <= CM_TRC_DEBUG_LEVEL && !shutdwn && initialized)
    {
        static CMTrace trace;
        CMLogRecord *record = &trace.record;
        
        traceHeader(record, TYPE_START, level, file, function, line);
        syStrcpy(record->data, name); 
        writeTrace(&trace);
    }
}

void cmTraceStop(const NQ_CHAR *file, const NQ_CHAR *function, NQ_UINT line, NQ_UINT level, const NQ_CHAR *name)
{
    if (level <= CM_TRC_DEBUG_LEVEL && !shutdwn && initialized)
    {
        static CMTrace trace;
        CMLogRecord *record = &trace.record;
        
        traceHeader(record, TYPE_STOP, level, file, function, line);
        syStrcpy(record->data, name); 
        writeTrace(&trace);
    }
}

static NQ_CHAR c(NQ_BYTE p)
{
    return (NQ_CHAR)((p < 32 || p >= 127) ? '.' : p);
}

void cmTraceDump(const NQ_CHAR *file, const NQ_CHAR *function, NQ_UINT line, NQ_UINT level, const NQ_CHAR *str, const void *addr, NQ_UINT nBytes)
{
    if (level <= CM_TRC_DEBUG_LEVEL && !shutdwn && initialized)
    {
        NQ_INDEX i = 0;
        NQ_BYTE p[CM_DEBUG_DUMP_BLOCK_SIZE];
        NQ_BYTE * pAddr = (NQ_BYTE *)addr;

        cmTraceMessage(file, function, line, level, "%s (%d bytes):", str, nBytes);
        if (nBytes < 1)
            return;
        if (pAddr != NULL)
        {
            for (; nBytes > 0; i+= CM_DEBUG_DUMP_BLOCK_SIZE, pAddr += CM_DEBUG_DUMP_BLOCK_SIZE, nBytes = nBytes > CM_DEBUG_DUMP_BLOCK_SIZE? nBytes - CM_DEBUG_DUMP_BLOCK_SIZE : 0)
            {
                syMemset(p, 0, sizeof(p));
                syMemcpy(p, pAddr, nBytes > CM_DEBUG_DUMP_BLOCK_SIZE? CM_DEBUG_DUMP_BLOCK_SIZE : nBytes); 
                cmTraceMessage(file, function, line, level, "%03x: %02x %02x %02x %02x %02x %02x %02x %02x  %02x %02x %02x %02x %02x %02x %02x %02x | %c%c%c%c%c%c%c%c  %c%c%c%c%c%c%c%c |", 
                        i, 
                        p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15],
                        c(p[0]), c(p[1]), c(p[2]), c(p[3]), c(p[4]), c(p[5]), c(p[6]), c(p[7]), 
                        c(p[8]), c(p[9]), c(p[10]), c(p[11]), c(p[12]), c(p[13]), c(p[14]), c(p[15]));
            }
        }
        else
            cmTraceMessage(file, function, line, level, "Dump address is NULL");
    }
}

#endif /* UD_NQ_INCLUDETRACE */


