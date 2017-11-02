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

#ifndef _CCINFO_H_
#define _CCINFO_H_

#include "cmapi.h"

/* Description
   This structure describes file information.
   
   It combines all possible file information fields that may be
   used in information calls. The file information class
   equivalent is <i>FileAllInformation</i>.                     */
typedef struct _ccfileinfo
{
	NQ_UINT64 creationTime;			/* File creation time. */
	NQ_UINT64 lastAccessTime;		/* File last access time. */
	NQ_UINT64 lastWriteTime;		/* File last write time. */
	NQ_UINT64 changeTime;			/* File change time. */
	NQ_UINT64 endOfFile;			/* File size. */
	NQ_UINT64 allocationSize;		/* File allocation size. */
	NQ_UINT32 attributes;			/* File attributes. */
    NQ_UINT32 numberOfLinks;        /* Number of hard links to this file. */
    NQ_UINT64 fileIndex;         	/* File index. */
} CCFileInfo; /* File information structure. */

/* Description
   This structure describes volume information.
   */
typedef struct _ccvolumeinfo
{
    NQ_UINT sectorsPerCluster;	/* Number of sectors per claster. */
    NQ_UINT bytesPerSector;		/* Number of bytes per sector. */
    NQ_UINT freeClusters;		/* Number of free clusters. */
    NQ_UINT totalClusters;		/* number of clusters on disk. */
    NQ_UINT fsType;				/* File system type as disk or DC. */
    NQ_UINT serialNumber;		/* Disk serial number. */
} CCVolumeInfo; /* Volume information structure. */

/* Description
   This function is called to check for path existance. 
   
   Parameters
   path :    File path.
   stripLast :   Whether to strip last path component.
   resolvedPath :  New path resolved through DFS.
   Returns
   This function returns TRUE if file path exists
   or FALSE otherwise. */
NQ_BOOL ccCheckPath(const NQ_WCHAR * path, NQ_BOOL stripLast, NQ_WCHAR **resolvedPath);

#endif  /* _CCINFO_H_ */

