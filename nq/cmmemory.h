/*************************************************************************
 * Copyright 2011-2012 by Visuality Systems, Ltd.
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

#ifndef _CMMEMORY_H_ 
#define _CMMEMORY_H_

#include "cmapi.h"

/* -- Functions -- */

/* Description
   This function starts memory management module.
   Parameters
   maxBytes :  Maximum number of bytes that NQ is allowed to
               allocate in total. A zero value means unlimited
               memory usage.
   Returns
   TRUE on success, FALSE on failure.                          */
NQ_BOOL cmMemoryStart(NQ_COUNT maxBytes);

/* Description
   This function terminates memory management module.
   Returns
   None */
void cmMemoryShutdown(void);



void * cmMemoryAllocNonDebug(NQ_UINT size);
#if SY_DEBUGMODE
void * cmMemoryAllocDebug(NQ_UINT size, const NQ_CHAR *text, const NQ_UINT line);
#endif

#if SY_DEBUGMODE
#define cmMemoryAllocate(_size) cmMemoryAllocDebug(_size, SY_LOG_FUNCTION, SY_LOG_LINE) 
#else
#define cmMemoryAllocate(_size) cmMemoryAllocNonDebug(_size)
#endif


/* Description
   This function allocates a block of memory.
   Parameters
   size :  Number of bytes to allocate.
   Returns
   Pointer to the block or NULL on error.   */
/*void * cmMemoryAllocate(NQ_UINT size);*/


#if SY_DEBUGMODE
NQ_WCHAR * cmMemoryCloneWStringDebug(const NQ_WCHAR * str, const NQ_CHAR *function, const NQ_UINT line);
#endif
NQ_WCHAR * cmMemoryCloneWStringNonDebug(const NQ_WCHAR * str);

#if SY_DEBUGMODE
#define cmMemoryCloneWString(_str) cmMemoryCloneWStringDebug(_str, SY_LOG_FUNCTION, SY_LOG_LINE) 
#else
#define cmMemoryCloneWString(_str) cmMemoryCloneWStringNonDebug(_str)
#endif

/* Description
   This function creates a string in allocated memory with the
   same contents as the original string.
   
   It is caller's responsibility to release this string.
   Parameters
   str :  The original string.
   Returns
   Pointer to new string or NULL on error.                     */
/*NQ_WCHAR * cmMemoryCloneWString(const NQ_WCHAR * str);*/

#if SY_DEBUGMODE
NQ_WCHAR * cmMemoryCloneAStringDebug(const NQ_CHAR * str, const NQ_CHAR *function, const NQ_UINT line);
#endif
NQ_WCHAR * cmMemoryCloneAStringNonDebug(const NQ_CHAR * str);

#if SY_DEBUGMODE
#define cmMemoryCloneAString(_str) cmMemoryCloneAStringDebug(_str, SY_LOG_FUNCTION, SY_LOG_LINE) 
#else
#define cmMemoryCloneAString(_str) cmMemoryCloneAStringNonDebug(_str)
#endif


/* Description
   This function creates a string in allocated memory with the
   same contents as the original ASCII string after conversion.
   
   It is caller's responsibility to release this string.
   Parameters
   str :  The original string.
   Returns
   Pointer to new string or NULL on error.                      */
/*NQ_WCHAR * cmMemoryCloneAString(const NQ_CHAR * str);*/

/* Description
   This function creates an ASCII string in allocated memory
   with the same contents as the original string.
   
   It is caller's responsibility to release this string.
   Parameters
   str :  The original string.
   Returns
   Pointer to new string or NULL on error.                   */
/*NQ_CHAR * cmMemoryCloneWStringAsAscii(const NQ_WCHAR * str);*/
#if SY_DEBUGMODE
NQ_CHAR * cmMemoryCloneWStringAsAsciiDebug(const NQ_WCHAR * str, const NQ_CHAR *function, const NQ_UINT line);
#endif
NQ_CHAR * cmMemoryCloneWStringAsAsciiNonDebug(const NQ_WCHAR * str);

#if SY_DEBUGMODE
#define cmMemoryCloneWStringAsAscii(_str) cmMemoryCloneWStringAsAsciiDebug(_str, SY_LOG_FUNCTION, SY_LOG_LINE) 
#else
#define cmMemoryCloneWStringAsAscii(_str) cmMemoryCloneWStringAsAsciiNonDebug(_str)
#endif



/* Description
   This function creates a new blob and copies into it the contents of the original blob.
   
   It is caller's responsibility to release new blob data.
   Parameters
   origin :  The original blob.
   Returns
   New blob with allocated data or NULL data on error.                   */
/*CMBlob cmMemoryCloneBlob(const CMBlob * origin);*/

#if SY_DEBUGMODE
CMBlob cmMemoryCloneBlobDebug(const CMBlob * origin, const NQ_CHAR *function, const NQ_UINT line);
#endif
CMBlob cmMemoryCloneBlobNonDebug(const CMBlob * origin);

#if SY_DEBUGMODE
#define cmMemoryCloneBlob(_origin) cmMemoryCloneBlobDebug(_origin, SY_LOG_FUNCTION, SY_LOG_LINE) 
#else
#define cmMemoryCloneBlob(_origin) cmMemoryCloneBlobNonDebug(_origin)
#endif


/* Description
   This function disposes blob data and sets its pointer to NULL.
   
   Parameters
   blob :  The original blob.
   Returns
   None.                   */
/*void cmMemoryFreeBlob(CMBlob * blob);*/

#if SY_DEBUGMODE
void cmMemoryFreeBlobDebug(CMBlob * _blob, const NQ_CHAR *function, const NQ_UINT line);
#endif
void cmMemoryFreeBlobNonDebug(CMBlob * _blob);

#if SY_DEBUGMODE
#define cmMemoryFreeBlob(_blob) cmMemoryFreeBlobDebug(_blob, SY_LOG_FUNCTION, SY_LOG_LINE) 
#else
#define cmMemoryFreeBlob(_blob) cmMemoryFreeBlobNonDebug(_blob)
#endif



void cmMemoryFreeNonDebug(const void * block);
#if SY_DEBUGMODE
void cmMemoryFreeDebug(const void * block, const NQ_CHAR *function, const NQ_UINT line);
#endif

#if SY_DEBUGMODE
#define cmMemoryFree(_block) cmMemoryFreeDebug(_block, SY_LOG_FUNCTION, SY_LOG_LINE) 
#else
#define cmMemoryFree(_block) cmMemoryFreeNonDebug(_block)
#endif

/* Description
   This function disposes a block of memory.
   Parameters
   block :  Pointer to a block.
   Returns
   None                                      */
/*void cmMemoryFree(const void * block);*/

#if SY_DEBUGMODE

/* Description
   This function reports memory usage statistics.
   
   It is available in debug mode only.
   Parameters
   memAlloc :      Number of bytes allocated so far.
   memDedealloc :  Number of bytes deallocated so far.
   blockAlloc :    Number of blocks allocated so far.
   blockDealloc :  Number of blocks deallocated so far.
   Returns
   None.               */
void cmMemoryStatistics(NQ_UINT32 * memAlloc, NQ_UINT32 * memDealloc, NQ_UINT32 * blockAlloc, NQ_UINT32 * blockDealloc);

/* Description
   This function prints memory usage statistics.
   
   It is available in debug mode only.
   Returns
   None.               */
void cmMemoryDump(void);

#endif /* SY_DEBUGMODE */

#endif /* _CMMEMORY_H_ */
