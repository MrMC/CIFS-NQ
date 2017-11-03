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

#ifndef _SYPRINTR_H_
#define _SYPRINTR_H_

#include "syapi.h"

/* printer handle */

#define SYPrinterHandle int
#define syIsValidPrinter(_handle)       (_handle != -1)
#define syInvalidatePrinter(_pHandle)   *_pHandle = -1;

/* get printer handle by name */

SYPrinterHandle             /* printer handle */
syGetPrinterHandle(
    const NQ_WCHAR* name    /* printer name */
);

/* get printer info */

NQ_STATUS                         /* NQ_SUCCESS or NQ_FAIL */
syGetPrinterInfo(
    SYPrinterHandle handle,       /* printer handle */
    SYPrinterInfo* info           /* pointer to the printer info */
);

/* set printer info */

NQ_STATUS                         /* NQ_SUCCESS or NQ_FAIL */
sySetPrinterInfo(
    SYPrinterHandle handle,       /* printer handle */
    const SYPrinterInfo* info     /* pointer to the printer info */
);

/* get printer driver info */

NQ_STATUS                   /* NQ_SUCCESS or NQ_FAIL */
syGetPrinterDriver(
    SYPrinterHandle handle, /* printer handle */
    const NQ_WCHAR* os,     /* required OS */
    SYPrinterDriver* info   /* pointer to the printer info */
);

/* set security descriptor for printer as raw data block */

NQ_STATUS                               /* NQ_SUCCESS or NQ_FAIL */
syPrinterSetSecurityDescriptor(
    SYPrinterHandle handle,             /* printer handle */
    const NQ_BYTE* descriptor,          /* pointer to descriptor */
    NQ_UINT32 length                    /* descriptor length */
);

/* get security descriptor for printer as raw data block */

NQ_COUNT                                   /* SD length */
syPrinterGetSecurityDescriptor(
    SYPrinterHandle handle,                /* printer handle */
    NQ_BYTE* buffer,                       /* buffer for SD */
    NQ_COUNT bufferLength                  /* buffer length */
);

/* start new print job */

NQ_UINT32                               /* job ID or zero for error */
syStartPrintJob(
    SYPrinterHandle handle,             /* printer handle */
    const NQ_WCHAR* name,               /* job (document) name */
    const NQ_WCHAR* file,               /* file name */
    const NQ_WCHAR* type,               /* data type or NULL */
    const NQ_BYTE* sd,                  /* security descriptor */
    NQ_COUNT sdLen,                     /* security descriptor length */
    const void *pUser                   /* job owner */
);

/* end print job */

NQ_STATUS                               /* NQ_SUCCESS or NQ_FAIL */
syEndPrintJob(
    SYPrinterHandle handle,             /* printer handle */
    NQ_UINT32 jobId                     /* job ID */
);

/* start new page */

NQ_STATUS                               /* NQ_SUCCESS or NQ_FAIL */
syStartPrintPage(
    SYPrinterHandle handle,             /* printer handle */
    NQ_UINT32 jobId                     /* job ID */
);

/* end page */

NQ_STATUS                               /* NQ_SUCCESS or NQ_FAIL */
syEndPrintPage(
    SYPrinterHandle handle,             /* printer handle */
    NQ_UINT32 jobId                     /* job ID */
);

/* print data portion */

NQ_INT32                                /* number of bytes written or negative number on error */
syWritePrintData(
    SYPrinterHandle handle,             /* printer handle */
    NQ_UINT32 jobId,                    /* job ID */
    const NQ_BYTE* data,                /* data to print */
    NQ_UINT32 count,                    /* number of bytes in the portion */
    void **rctx                         /* place for response context pointer */
);

/* get a job from the queue by its id */

NQ_STATUS                               /* NQ_SUCCESS or NQ_FAIL */
syGetPrintJobById(
    SYPrinterHandle handle,             /* printer handle */
    NQ_UINT32 jobId,                    /* job ID */
    SYPrintJobInfo* info                /* pointer to the structure to fill with job info */
);

/* get job ID by its index in the queue */

NQ_INT32                                /* ID or NQ_FAIL */
syGetPrintJobIdByIndex(
    SYPrinterHandle handle,             /* printer handle */
    NQ_INT jobIdx                       /* job index in the queue */
);

/* get job index in the queue by its ID */

NQ_INT32                                /* index or NQ_FAIL */
syGetPrintJobIndexById(
    SYPrinterHandle handle,             /* printer handle */
    NQ_UINT32 jobId                     /* job index in the queue */
);

/* enumerate forms */

NQ_STATUS                               /* NQ_SUCCESS or NQ_FAIL */
syGetPrintForm(
    SYPrinterHandle handle,             /* printer handle */
    NQ_UINT32 formIdx,                  /* form index in the queue */
    SYPrintFormInfo* info               /* pointer to the structure to fill with form info */
);

/* perform control command on printer */

NQ_STATUS                               /* NQ_SUCCESS or NQ_FAIL */
syControlPrinter(
    SYPrinterHandle handle,             /* printer handle */
    NQ_UINT32 command                   /* control command see sycommon.h */
);

/* perform control command on a job */

NQ_STATUS                               /* NQ_SUCCESS or NQ_FAIL */
syControlPrintJob(
    SYPrinterHandle handle,             /* printer handle */
    NQ_UINT32 jobIdx,                   /* job index in the queue */
    NQ_UINT32 command                   /* control command see sycommon.h */
);

#endif  /* _SYPRINTR_H_ */
