/*********************************************************************
 *
 *           Copyright (c) 2011 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : FS Driver
 *--------------------------------------------------------------------
 * MODULE        :
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 04-Sep-2011
 * CREATED BY    : Lilia Wasserman
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

/* The following definition should match the appropriate compilation parameter in FUSE. In most cases it si 64 bit but it would be 
   a good idea to consult FUSE sources. */
#define _FILE_OFFSET_BITS 64

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#define FUSE_USE_VERSION 28 /* new api */    /*  21 for an old api (default) */

#include "udparams.h"

#ifdef UD_CC_INCLUDEFSDRIVER

#include <fuse.h>

#include "cmapi.h"
#include "ccapi.h"
#include "nsapi.h"
#include "nqapi.h"
#include "udapi.h"
#include "syapi.h"
#include "ccgen.h"
#include "fsdriver.h"

/* The following macro may be missing on some platforms */

#ifndef ENOATTR
#define ENOATTR         ENODATA
#endif

/*
    Static functions & data
    -----------------------
 */

typedef struct
{
    NQ_CHAR mntEntry[MNT_PATH_SIZE];                                /* mount entry */
    NQ_CHAR fullPath[CM_BUFFERLENGTH(NQ_CHAR, UD_FS_MAXPATHLEN)];   /* full path (starts with mount entry) */ 
    NQ_CHAR tempPath[CM_BUFFERLENGTH(NQ_CHAR, UD_FS_MAXPATHLEN)];   /* temp path (starts with mount entry) */ 
}
StaticData;


#ifdef SY_FORCEALLOCATION
static StaticData* staticData = NULL;
#else  /* SY_FORCEALLOCATION */
static StaticData staticDataSrc;
static StaticData* staticData = &staticDataSrc;
#endif /* SY_FORCEALLOCATION */


#define FSDRIVER_DATA       ((StaticData *)fuse_get_context()->private_data)

#define getLastError()      (-(int)udNqToSystemError((NQ_UINT32)syGetLastError()))

void udSetCredentials(const char* user, const char* pwd, const char* domain);
NQ_BOOL fsInit();
void fsStop();

static void *driverInit(struct fuse_conn_info *conn);
static void driverDestroy(void *userdata);

static int driverOpen(const char *path, struct fuse_file_info *fi);
static int driverReaddir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi);
static int driverMkdir(const char *path, mode_t mode);
static int driverGetattr(const char *path, struct stat *statbuf);
static int driverFlush(const char *path, struct fuse_file_info *fi);
static int driverRelease(const char *path, struct fuse_file_info *fi);
static int driverWrite(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi);
static int driverRead(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi);
static int driverUtime(const char *path, struct utimbuf *ubuf);
/*static int driverUtimens(const char *, const struct timespec tv[2]);*/
static int driverFtruncate(const char *path, off_t offset, struct fuse_file_info *fi);
static int driverFgetattr(const char *path, struct stat *statbuf, struct fuse_file_info *fi);
static int driverFsync(const char *path, int datasync, struct fuse_file_info *fi);
static int driverRmdir(const char *path);
static int driverOpendir(const char *path, struct fuse_file_info *fi);
static int driverReaddir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi);
static int driverReleasedir(const char *path, struct fuse_file_info *fi);
static int driverStatfs(const char *path, struct statvfs *statv);
static int driverUnlink(const char *path);
static int driverAccess(const char *path, int mask);
static int driverCreate(const char *path, mode_t mode, struct fuse_file_info *fi);
static int driverRename(const char *path, const char *newpath);
static int driverTruncate(const char *path, off_t newsize);
static int driverGetxattr(const char *path, const char *name, char *value, size_t size);
static int driverSetxattr(const char *path, const char *name, const char *value, size_t size, int flags);
static int driverListxattr(const char *path, char *list, size_t size);
static int driverRemovexattr(const char *path, const char *name);
static int driverSymlink(const char *path, const char *link);
static int driverLink(const char *path, const char *newpath);
static int driverChown(const char *path, uid_t uid, gid_t gid);
static int driverChmod(const char *path, mode_t mode);
static int driverFsyncdir(const char *path, int datasync, struct fuse_file_info *fi);

static int pathValid(const char *path);
static int pathExist(const char *path);
static char* getFullPath(const char* path, char* fullPath, int size);
static void getAttr(FileInfo_t *fileInfo, struct stat *statBuf);
static void convertPathDelimiters(char *path);
static int printUsage();


static struct fuse_operations driverOperations = 
{
   .init        = driverInit,
   .destroy     = driverDestroy,
   .getattr     = driverGetattr,
   .mkdir       = driverMkdir,
   .rmdir       = driverRmdir,
   .opendir     = driverOpendir,
   .readdir     = driverReaddir,
   .releasedir  = driverReleasedir,
   .statfs      = driverStatfs, 
   .open        = driverOpen,
   .create      = driverCreate,
   .read        = driverRead,
   .write       = driverWrite,
   .rename      = driverRename,
   .unlink      = driverUnlink,
   .access      = driverAccess,
   .truncate    = driverTruncate,
   .flush       = driverFlush,
   .release     = driverRelease,
   .utime       = driverUtime,
 /*.utimens     = driverUtimens*/
   .ftruncate   = driverFtruncate,
   .fgetattr    = driverFgetattr,
   .fsync       = driverFsync,
   .getxattr    = driverGetxattr,
   .setxattr    = driverSetxattr,
   .listxattr   = driverListxattr,
   .removexattr = driverRemovexattr,
   .chmod       = driverChmod,
   .symlink     = driverSymlink,
   .link        = driverLink,
   .chown       = driverChown,
   .fsyncdir    = driverFsyncdir
};


NQ_BOOL
fsInit(
    void
    )
{
    /* allocate memory */
#ifdef SY_FORCEALLOCATION
    staticData = syCalloc(1, sizeof(*staticData));
    if (staticData == NULL)
    {
        TRCE();
        return FALSE;
    }
#endif /* SY_FORCEALLOCATION */
    return TRUE;
}


void
fsStop(
    void
    )
{
    /* release memory */
#ifdef SY_FORCEALLOCATION
    if (staticData != NULL)
        syFree(staticData);
    staticData = NULL;
#endif /* SY_FORCEALLOCATION */
}


/*

./nqdrv -d mountpoint sharepath

*/
int 
fsDriverMain(
    int argc, 
    char *argv[]
    )
{
#define MOUNTPOINT "\\mnt"
    NQ_INT result, j, i = 1;
    const NQ_CHAR *user = NULL, *pwd = NULL, *domain = NULL, *mountPoint = NULL, *sharePath = NULL;
    NQ_INT authenticationLevel = 0;
    NQ_BOOL messageSigning = FALSE;
    NQ_BOOL fuseDebugOn = FALSE;
    NQ_COUNT setCredentialsCnt = 0, setSecurityCnt = 0;

    TRCB();  

    if (argc < 3)
    {       
        fprintf(stderr, "Invalid parameters.\n");
        TRCERR("Invalid parameters.");
        TRCE();
        return printUsage();
    }   

    if (syStrcmp(argv[1], "-d") == 0)
    {
        fuseDebugOn = TRUE;
        if (argc < 4)
        {       
            fprintf(stderr, "Invalid parameters.\n");
            TRCERR("Invalid parameters.");
            TRCE();
            return printUsage();
        }
        i = 2;   
    }
    
    /* set pointers */
    mountPoint = argv[i];
    sharePath = argv[++i];

    /* parse optional parameters */
    if ((++i < argc) && (syStrcmp(argv[i], "-o") == 0))
    {
        if (argc == i + 1)
        {
            fprintf(stderr, "Invalid parameters: missing optional parameters.\n");
            TRCERR("Invalid parameters: missing optional parameters.");
            TRCE();
            return printUsage();
        }

        for (j = i + 1; j < argc; j++)
        {
            if (argv[j][0] == '-' && (j + 1) != argc)
            {
                switch (argv[j][1])
                {
                    case 'u':   user = argv[++j];  setCredentialsCnt++;                     break;
                    case 'p':   pwd = argv[++j];   setCredentialsCnt++;                     break;
                    case 'd':   domain = argv[++j]; setCredentialsCnt++;                    break;
                    case 'a':   authenticationLevel = atoi(argv[++j]);  setSecurityCnt++; break;
                    case 's':   messageSigning = atoi(argv[++j]);       setSecurityCnt++; break;   
                    default:    
                    {
                        fprintf(stderr, "Invalid optional parameters: parameter unknown.\n");
                        TRCERR("Invalid optional parameters: parameter unknown.");
                        TRCE();
                        return printUsage();
                    }          
                }
            }
            else
            {
                fprintf(stderr, "Invalid parameters: missing optional parameters.\n");
                TRCERR("Invalid parameters: missing optional parameters.");
                TRCE();
                return printUsage();
            }
        }  
        if ((setCredentialsCnt > 0 && setCredentialsCnt < 3) || (setSecurityCnt > 0 && setSecurityCnt < 2))
        {
            fprintf(stderr, "Invalid optional parameters: some parameters are missing.\n");
            TRCERR("Invalid optional parameters: some parameters are missing.");
            TRCE();
            return printUsage();
        } 
    }

    if (pathValid(mountPoint) == -1)
    {
        fprintf(stderr, "Mountpoint folder path '%s' is not valid, use absolute path.\n", mountPoint);
        TRCERR("Mountpoint folder path '%s' is not valid, use absolute path.", mountPoint);
        TRCE();
        return -1;
    }

    /* check for existance of mountPoint folder*/
    if (pathExist(mountPoint) == -1)
    {
        fprintf(stderr, "Mountpoint folder '%s' does not exist.\n", mountPoint);
        TRCERR("Mountpoint folder '%s' does not exist.", mountPoint);
        TRCE();
        return -1;
    }

    /* init NQ Client and connect to sharePath */
    if (udInit() == 0)
    {
        nsInitGuard();

        if (ccInit(NULL))
        {
            if (setCredentialsCnt != 0)
                udSetCredentials(user, pwd, domain);
            if (setSecurityCnt != 0)
                nqSetSecurityParams(authenticationLevel, messageSigning);

           /* connect to sharePath */
            if (nqAddMountA(MOUNTPOINT, sharePath, 1) != 0)
            {
                fprintf(stderr, "Failed to connect to: %s (0x%X).\n", sharePath, errno);
                TRCERR("Failed to connect to: %s", sharePath);

                ccShutdown();
                nsExitGuard();
                udStop();

                TRCE();
                return -1;
            }      
        }
        else
        {
            fprintf(stderr, "Initialization failed (ccInit)\n");
            TRCERR("Initialization failed (ccInit).");

            nsExitGuard();
            udStop();

            TRCE();
            return -1;
        }
    }          

    fsInit();

    syStrcpy(staticData->mntEntry, MOUNTPOINT);

    TRC("about to call fuse_main");
    result = fuse_main(fuseDebugOn ? 3 : 2, argv, &driverOperations, staticData);
    TRC("fuse_main returned  %d", result);
    
    /* fs mount is unmounted at this point */
    /* now disconnect from remote share */
    if (nqRemoveMountA(MOUNTPOINT) != 0)
    {
        fprintf(stderr, "Failed to disconnect from '%s'.\n", sharePath);
        TRCERR("Failed to disconnect from '%s'.", sharePath);
    }

    fsStop();
    ccShutdown();
    nsExitGuard();
    udStop();

    TRCE();
    return 0;
}


void *driverInit(struct fuse_conn_info *conn)
{
    TRCB();
    TRCE();
    return FSDRIVER_DATA;
}


void driverDestroy(void *userdata)
{
    TRCB();
    TRCE();
}


static int driverUtime(const char *path, struct utimbuf *ubuf)
{
    NQ_CHAR *fullPath;
    NQ_HANDLE handle;
    FileTime_t lastAccessTime, lastWriteTime;

    TRCB();
    
    if (!(fullPath = getFullPath(path, FSDRIVER_DATA->fullPath, sizeof(FSDRIVER_DATA->fullPath))))
    {
        TRCERR("Failed to get full path for: %s", path);
        TRCE();
        return -1;
    }
    TRC("path: %s", path);
    TRC("full path: %s", fullPath);
    TRC("ubuf->actime: 0x%X, ubuf->modtime: 0x%X", ubuf->actime, ubuf->modtime);

    handle = ccCreateFileA(fullPath, FILE_AM_READ_WRITE, FILE_SM_COMPAT, FILE_LCL_UNKNOWN, FALSE, 0, FILE_CA_FAIL, FILE_OA_OPEN);
    if (handle == NULL)
    {
        TRCERR("Failed to open file: %s", fullPath);
        TRCE();
        return getLastError();
    }
    TRC("handle: 0x%X", (NQ_ULONG)handle);

    cmCifsTimeToUTC((NQ_UINT32)ubuf->actime, &lastAccessTime.timeLow, &lastAccessTime.timeHigh);
    cmCifsTimeToUTC((NQ_UINT32)ubuf->modtime, &lastWriteTime.timeLow, &lastWriteTime.timeHigh);

    if (!ccSetFileTime(handle, NULL, &lastAccessTime, &lastWriteTime))
    {
        ccCloseHandle(handle);
        TRCERR("Failed to set file time: %s", fullPath);
        TRCE();
        return getLastError();
    }
    ccCloseHandle(handle);
    TRCE();
    return 0;
}


int
driverMkdir(const char *path, mode_t mode)
{
    NQ_CHAR *fullPath;

    TRCB();
    
    if (!(fullPath = getFullPath(path, FSDRIVER_DATA->fullPath, sizeof(FSDRIVER_DATA->fullPath))))
    {
        TRCERR("Failed to get full path for: %s", path);
        TRCE();
        return -1;
    }
    TRC("path: %s", path);
    TRC("full path: %s", fullPath);

    if (!ccCreateDirectoryA((const NQ_CHAR *)fullPath))
    {
        TRCERR("Failed to create directory: %s", fullPath);
        TRCE();
        return getLastError();
    }
    TRCE();
    return 0;
}


static int 
driverRmdir(
    const char *path
    )
{
    NQ_CHAR *fullPath;

    TRCB();

    if (!(fullPath = getFullPath(path, FSDRIVER_DATA->fullPath, sizeof(FSDRIVER_DATA->fullPath))))
    {
        TRCERR("Failed to get full path for: %s", path);
        TRCE();
        return -1;
    }
    TRC("path: %s", path);
    TRC("full path: %s", fullPath);

    if (!ccRemoveDirectoryA((const NQ_CHAR *)fullPath))
    {
        TRCERR("Failed to delete directory: %s", fullPath);
        TRCE();
        return getLastError();
    }
    TRCE();
    return 0;
}


static
int 
driverGetattr(
    const char *path, 
    struct stat *statbuf
    )
{
    FileInfo_t fileInfo;
    NQ_CHAR *fullPath;

    TRCB();
    
    if (!(fullPath = getFullPath(path, FSDRIVER_DATA->fullPath, sizeof(FSDRIVER_DATA->fullPath))))
    {
        TRCERR("Failed to get full path for: %s", path);
        TRCE();
        return -1;
    }
    TRC("path: %s", path);
    TRC("full path: %s", fullPath);

    if (syStrcmp(path, "/") == 0)
    {
        /* special case - mount folder */
        NQ_HANDLE handle;
        
        handle = ccCreateFileA(fullPath, FILE_AM_READ, FILE_SM_COMPAT, FILE_LCL_UNKNOWN, FALSE, 0, FILE_CA_FAIL, FILE_OA_OPEN);
        if (handle == NULL)
        {
            TRCERR("Failed to open file: %s", fullPath);
            TRCE();
            return getLastError();
        }

        if (!ccGetFileInformationByHandle(handle, &fileInfo))
        {
            ccCloseHandle(handle);
            TRCERR("Failed to get file information for: %s", fullPath);
            TRCE();        
            return getLastError();
        }      
        ccCloseHandle(handle);      
    }
    else
    {
        if (!ccGetFileInformationByNameA(fullPath, &fileInfo))
        {
            TRCERR("Failed to get file information for: %s", path);
            TRCE();        
            return -ENOENT; //getLastError();
        }
    }

    getAttr(&fileInfo, statbuf);

    TRCE();
    return 0;
}

static inline NQ_HANDLE getFh(struct fuse_file_info *fi)
{
    return (NQ_HANDLE)(uintptr_t)fi->fh;
}

static int 
driverFgetattr(
    const char *path, 
    struct stat *statbuf, 
    struct fuse_file_info *fi
    )
{
    FileInfo_t fileInfo;

    TRCB();

    TRC("handle: 0x%X, path: %s", (NQ_ULONG)fi->fh, path);

    if (ccGetFileInformationByHandle(getFh(fi), &fileInfo) == FALSE)
    {
        TRCERR("Failed to get file information for: %s", path);
        TRCE();        
        return getLastError();
    }

    getAttr(&fileInfo, statbuf);

    TRCE();
    return 0;
}


static
int 
driverOpendir(
    const char *path, 
    struct fuse_file_info *fi
    )
{
    NQ_CHAR *fullPath;
    FindFileDataA_t findFileData;
    NQ_HANDLE dirHandle;

    TRCB();
    
    if (!(fullPath = getFullPath(path, FSDRIVER_DATA->fullPath, sizeof(FSDRIVER_DATA->fullPath))))
    {
        TRCERR("Failed to get full path for: %s", path);
        TRCE();
        return -1;
    }

    if (fullPath[syStrlen(fullPath) - 1] == '\\')
        syStrcat(fullPath, "*");
    else
        syStrcat(fullPath, "\\*");

    TRC("path: %s", path);
    TRC("full path: %s", fullPath);

    if ((dirHandle = ccFindFirstFileA(fullPath, &findFileData, FALSE)) == NULL)
    {
        if (syGetLastError() != NQ_ERR_BADFILE)
        {
            TRCERR("Failed to open: %s", path);
            TRCE();
            return getLastError();
        }
    }
    else
    {
        NQ_HANDLE *h = (NQ_HANDLE *)&fi->fh;        
        *h = dirHandle;
        TRC("handle: 0x%X", (NQ_ULONG)dirHandle);
    }

    TRCE();
    return 0;
}


static int 
driverReaddir(
    const char *path, 
    void *buf, 
    fuse_fill_dir_t filler,
    off_t offset, 
    struct fuse_file_info *fi
    )
{
    FindFileDataA_t findFileData;
    NQ_BOOL closeHandle = FALSE;

    TRCB();
    TRC("path: %s", path);

    if (fi == NULL)
    {
        struct fuse_file_info fuseFileInfo;

        if (driverOpendir(path, &fuseFileInfo) != 0)
        {
            TRCERR("Failed to open directory: %s", path);
            TRCE();
            return getLastError();
        }
        fi = &fuseFileInfo;
        closeHandle = (NULL != getFh(fi));
    }
    TRC("handle: 0x%X", (NQ_ULONG)fi->fh);

    if (NULL == getFh(fi))
    {
        return -ENOENT;
    }
    if (ccFindNextFileA(getFh(fi), &findFileData))
    {       
        do 
        {
            TRC("calling filler with name: %s", findFileData.fileName);
            if (filler(buf, findFileData.fileName, NULL, 0) != 0) 
            {
                if (closeHandle)
                    ccFindClose(getFh(fi));
                TRCERR("filler:  buffer full");
                TRCE();
                return -ENOMEM;
            }
        } while (ccFindNextFileA(getFh(fi), &findFileData));
    }
    else
    {
        TRCERR("Failed to get dir entry: %s", path);
        TRCE();
        return getLastError();
    }
    if (closeHandle)
        ccFindClose(getFh(fi));
    TRCE();
    return 0;
}


static int 
driverReleasedir(
    const char *path, 
    struct fuse_file_info *fi
    )
{
    TRCB();
    TRC("path: %s, handle: 0x%X", path, (NQ_ULONG)fi->fh);

    ccFindClose(getFh(fi));

    TRCE();
    return 0;
}


static int  
driverStatfs(
    const char *path, 
    struct statvfs *statv
    )
{
    NQ_CHAR *fullPath;
    NQ_UINT sectorsPerCluster;
    NQ_UINT bytesPerSector;
    NQ_UINT freeClusters;
    NQ_UINT totalClusters;

    TRCB();

    if (!(fullPath = getFullPath(path, FSDRIVER_DATA->fullPath, sizeof(FSDRIVER_DATA->fullPath))))
    {
        TRCERR("Failed to get full path for: %s", path);
        TRCE();
        return -1;
    }
    TRC("path: %s", path);
    TRC("full path: %s", fullPath);

    if (ccGetDiskFreeSpaceA(
                            fullPath,
                            &sectorsPerCluster,
                            &bytesPerSector,
                            &freeClusters,
                            &totalClusters,
                            NULL,
                            NULL
                            ))
    {
        statv->f_bsize = sectorsPerCluster * bytesPerSector;    /* file system block size */
        statv->f_blocks = totalClusters;                        /* size of fs in f_frsize units */
        statv->f_bfree = freeClusters;                          /* free blocks */
        statv->f_bavail = freeClusters;                         /* free blocks for non-root */
        statv->f_files = 0xFFFFFFFF;                            /* inodes */
        statv->f_ffree = 0xFFFFFFFF;                            /* free inodes */
        statv->f_namemax = UD_FS_FILENAMELEN;                   /* maximum filename length */
        /* 'f_frsize', 'f_favail', 'f_fsid' and 'f_flag' fields are ignored */
    }
    else
    {
        TRCERR("Failed to get volume information.");
        TRCE();
        return getLastError();
    }

    TRCE();
    return 0;
}


static int 
driverCreate(
    const char *path, 
    mode_t mode, 
    struct fuse_file_info *fi
    )
{
    NQ_CHAR *fullPath;
    NQ_HANDLE handle;
    NQ_INT access;

    TRCB();

    if (!(fullPath = getFullPath(path, FSDRIVER_DATA->fullPath, sizeof(FSDRIVER_DATA->fullPath))))
    {
        TRCERR("Failed to get full path for: %s", path);
        TRCE();
        return -1;
    }

    TRC("path: %s", path);
    TRC("full path: %s", fullPath);
    TRC("flags: 0x%X", fi->flags);

    switch (fi->flags & 0x3)
    {
        case O_RDWR:    access = FILE_AM_READ_WRITE;    break;
        case O_WRONLY:  access = FILE_AM_WRITE;         break;
        case O_RDONLY:            
        default:        access = FILE_AM_READ;
    }

    handle = ccCreateFileA(fullPath, access, FILE_SM_COMPAT, FILE_LCL_UNKNOWN, FALSE, 0, FILE_CA_CREATE, FILE_OA_FAIL);
    if (handle == NULL)
    {
        TRCERR("Failed to create file: %s", fullPath);
        TRCE();
        return getLastError();
    }
    else
    {
        NQ_HANDLE *h = (NQ_HANDLE *)&fi->fh;        
        *h = handle;
        TRC("handle: 0x%X", (NQ_ULONG)handle);
    }

    TRCE();
    return 0;
}


static int 
driverOpen(
    const char *path, 
    struct fuse_file_info *fi
    )
{
    NQ_CHAR *fullPath;
    NQ_HANDLE handle;
    NQ_INT access;

    TRCB();
    
    if (!(fullPath = getFullPath(path, FSDRIVER_DATA->fullPath, sizeof(FSDRIVER_DATA->fullPath))))
    {
        TRCERR("Failed to get full path for: %s", path);
        TRCE();
        return -1;
    }

    TRC("path: %s", path);
    TRC("full path: %s", fullPath);
    TRC("flags: 0x%X", fi->flags);

    switch (fi->flags & 0x3)
    {
        case O_RDWR:    access = FILE_AM_READ_WRITE;    break;
        case O_WRONLY:  access = FILE_AM_WRITE;         break;
        case O_RDONLY:            
        default:        access = FILE_AM_READ;
    }

    handle = ccCreateFileA(fullPath, access, FILE_SM_COMPAT, FILE_LCL_UNKNOWN, FALSE, 0, FILE_CA_FAIL, FILE_OA_OPEN);
    if (handle == NULL)
    {
        TRCERR("Failed to open file: %s", fullPath);
        TRCE();
        return getLastError();
    }
    else
    {
        NQ_HANDLE *h = (NQ_HANDLE *)&fi->fh;        
        *h = handle;
        TRC("handle: 0x%X", (NQ_ULONG)handle);
    }
    
    TRCE();
    return 0;
}


static int 
driverFlush(
    const char *path, 
    struct fuse_file_info *fi
    )
{
    TRCB();
    TRC("path: %s, handle: 0x%X", path, (NQ_ULONG)fi->fh);

    if (!ccFlushFile(getFh(fi)))
    {
        TRCERR("Failed to flush file: %s", path);
/*        TRCE();
        return getLastError();*/
    }
    TRCE();
    return 0;
}


static int 
driverFsync(
    const char *path, 
    int datasync, 
    struct fuse_file_info *fi
    )
{
    return driverFlush(path, fi);
}


static int 
driverRelease(
    const char *path, 
    struct fuse_file_info *fi
    )
{
    TRCB();
    TRC("path: %s, handle: 0x%X", path, (NQ_ULONG)fi->fh);
    
    if (!ccCloseHandle(getFh(fi)))
    {
        TRCERR("Failed to close file: %s", path);
        TRCE();
        return getLastError();
    }
    TRCE();
    return 0;
}


static int 
driverRead(
    const char *path, 
    char *buf, 
    size_t size, 
    off_t offset, 
    struct fuse_file_info *fi
    )
{
    NQ_UINT32   position;
    NQ_INT32    *highOffset = NULL;
    NQ_UINT     readSize;

    TRCB();
    
    TRC("path: %s", path);
    TRC("handle: 0x%X, size: %d, offset: %d", (NQ_ULONG)fi->fh, size, offset);
    
    position = ccSetFilePointer(getFh(fi), (NQ_INT32)offset, highOffset, SEEK_FILE_BEGIN);
    if (position == NQ_ERR_SEEKERROR)
    {
        TRCERR("Failed to set file pointer: %s", path);
        TRCE();
        return getLastError();
    }

    if (!ccReadFile(getFh(fi), (NQ_BYTE *)buf, (NQ_UINT)size, &readSize))
    {
        TRCERR("Failed to read: %s", path);
        TRCE();
        return getLastError();
    }
    TRC("Read %d bytes", readSize);
    TRCE();
    return (int)readSize;
}


static int 
driverWrite(
    const char *path, 
    const char *buf, 
    size_t size, 
    off_t offset, 
    struct fuse_file_info *fi
    )
{
    NQ_UINT32   position;
    NQ_INT32    *highOffset = NULL;
    NQ_UINT     writtenSize;
    NQ_BOOL     closeHandle = FALSE;

    TRCB();
    TRC("path: %s", path);
    TRC("fi: %p", fi);

/*
	
    if (fi == NULL)
    {
        struct fuse_file_info fuseFileInfo;

        if (driverOpen(path, &fuseFileInfo) != 0)
        {
            TRCERR("Failed to open file: %s", path);
            TRCE();
            return getLastError();
        }
        fi = &fuseFileInfo;
        closeHandle = TRUE;
    }
*/
    TRC("handle: 0x%X, size: %d, offset: %d", (NQ_ULONG)fi->fh, size, offset);
    
    position = ccSetFilePointer(getFh(fi), (NQ_INT32)offset, highOffset, SEEK_FILE_BEGIN);
    if (position == NQ_ERR_SEEKERROR)
    {
        if (closeHandle)
            ccCloseHandle(getFh(fi));
        TRCERR("Failed to set file pointer: %s", path);
        TRCE();
        return getLastError();
    }

    if (!ccWriteFile(getFh(fi), (NQ_BYTE *)buf, (NQ_UINT)size, &writtenSize))
    {
        if (closeHandle)
            ccCloseHandle(getFh(fi));
        TRCERR("Failed to write: %s", path);
        TRCE();
        return getLastError();
    }
    if (closeHandle)
        ccCloseHandle(getFh(fi));

    TRC("Written %d bytes", writtenSize);
    TRCE();
    return (int)writtenSize;
}


static int 
driverRename(
    const char *path, 
    const char *newpath
    )
{
    NQ_CHAR *fullPathOld;
    NQ_CHAR *fullPathNew;

    TRCB();
    TRC("path: %s", path);
    
    if (!(fullPathOld = getFullPath(path, FSDRIVER_DATA->fullPath, sizeof(FSDRIVER_DATA->fullPath))))
    {
        TRCERR("Failed to get full path for: %s", path);
        TRCE();
        return -1;
    }
    if (!(fullPathNew = getFullPath(newpath, FSDRIVER_DATA->tempPath, sizeof(FSDRIVER_DATA->tempPath))))
    {
        TRCERR("Failed to get full path for: %s", newpath);
        TRCE();
        return -1;
    }

    TRC("path: %s", fullPathOld);
    TRC("path: %s", fullPathNew);

    if (!ccMoveFileA(fullPathOld, fullPathNew))
    {
        TRCERR("Failed to rename: %s", path);
        TRCE();
        return getLastError();
    }
    TRCE();
    return 0;
}


static int 
driverUnlink(
    const char *path
    )
{
    NQ_CHAR *fullPath;

    TRCB();

    if (!(fullPath = getFullPath(path, FSDRIVER_DATA->fullPath, sizeof(FSDRIVER_DATA->fullPath))))
    {
        TRCERR("Failed to get full path for: %s", path);
        TRCE();
        return -1;
    }
    TRC("path: %s", path);
    TRC("full path: %s", fullPath);

    if (!ccDeleteFileA(fullPath))
    {
        TRCERR("Failed to delete file: %s", fullPath);
        TRCE();
        return getLastError();
    }   
    TRCE();
    return 0;
}


static
int 
driverAccess(
    const char *path, 
    int mask
    )
{
    NQ_CHAR *fullPath;
    FileInfo_t fileInfo;

    TRCB();

    if (!(fullPath = getFullPath(path, FSDRIVER_DATA->fullPath, sizeof(FSDRIVER_DATA->fullPath))))
    {
        TRCERR("Failed to get full path for: %s", path);
        TRCE();
        return -1;
    }
    TRC("path: %s", path);
    TRC("full path: %s", fullPath);
    TRC("mask: 0x%X", mask);

    if (!ccGetFileInformationByNameA(fullPath, &fileInfo))
    {
        TRCERR("Failed to get file information for: %s", fullPath);
        TRCE();        
        return -ENOENT;
    }

    if (mask == F_OK)    
    {
        TRCE();
        return 0;
    }

    if ((fileInfo.attributes & CIFS_ATTR_READONLY) && (mask & W_OK))
    {
        TRCE();        
        return -EACCES;
    }

    TRCE();
    return 0;
}


static int 
driverTruncate(
    const char *path, 
    off_t newsize
    )
{
    NQ_CHAR *fullPath;

    TRCB();

    if (!(fullPath = getFullPath(path, FSDRIVER_DATA->fullPath, sizeof(FSDRIVER_DATA->fullPath))))
    {
        TRCERR("Failed to get full path for: %s", path);
        TRCE();
        return -1;
    }
    TRC("path: %s", path);
    TRC("full path: %s", fullPath);
    TRC("truncate to size: %d", newsize);

    if (!ccSetFileSizeByNameA(fullPath, (NQ_UINT32)newsize, 0))
    {
        TRCERR("Failed to truncate file: %s", fullPath);
        TRCE();
        return getLastError();
    }

    TRCE();
    return (int)newsize;
}


static int 
driverFtruncate(
    const char *path, 
    off_t offset, 
    struct fuse_file_info *fi
    )
{
    TRCB();
    TRC("handle: 0x%X, size: %d", (NQ_ULONG)fi->fh, offset);

    if (!ccSetFileSizeByHandle(getFh(fi), (NQ_UINT32)offset, 0))
    {
        TRCERR("Failed to ftruncate file");
        TRCE();
        return getLastError();
    }

    TRCE();
    return (int)offset;
}


static int 
driverGetxattr(
    const char *path, 
    const char *name, 
    char *value, 
    size_t size
    )
{
    TRCB();
    TRCE();
    return -ENOATTR;
}


static int 
driverSetxattr(
    const char *path, 
    const char *name, 
    const char *value, 
    size_t size,
    int flags
    )
{
    TRCB();
    TRCE();
    return -ENOTSUP;
}


static int 
driverListxattr(
    const char *path, 
    char *list, 
    size_t size
    )
{
    TRCB();
    TRCE();
    return -ENOTSUP;
}


static int 
driverRemovexattr(
    const char *path, 
    const char *name
    )
{
    TRCB();
    TRCE();
    return -ENOTSUP;
}

static int 
driverSymlink(
    const char *path, 
    const char *link
    )
{
    TRCB();
    TRCE();
    return -ENOTSUP;
}


static int 
driverLink(
    const char *path, 
    const char *newpath
    )
{
    TRCB();
    TRCE();
    return -ENOTSUP;
}


static int 
driverChown(
    const char *path, 
    uid_t uid, 
    gid_t gid)
{
    TRCB();
    TRCE();
    return -ENOTSUP;
}


static int 
driverChmod(
    const char *path, 
    mode_t mode
    )
{
    NQ_CHAR *fullPath;

    TRCB();

    if (!(fullPath = getFullPath(path, FSDRIVER_DATA->fullPath, sizeof(FSDRIVER_DATA->fullPath))))
    {
        TRCERR("Failed to get full path for: %s", path);
        TRCE();
        return -1;
    }
    TRC("path: %s", path);
    TRC("full path: %s", fullPath);
    TRC("mode: 0x%X", mode);

    if (!ccSetFileAttributesA(fullPath, (NQ_UINT32)syUnixMode2DosAttr((int)mode)))
    {
        TRCERR("Failed to chmod file");
        TRCE();
        return getLastError();
    }
    TRCE();
    return 0;
}


static int 
driverFsyncdir(
    const char *path, 
    int datasync, 
    struct fuse_file_info *fi
    )
{
    TRCB();
    TRCE();
    return 0;
}


static
int
pathValid(
    const char *path 
    )
{
    return path[0] == '/' ? 0 : -1;
}


static
int
pathExist(
    const char *path
    )
{
    return access(path, F_OK);
}


static 
int
printUsage()
{
    fprintf(stderr, "usage:  ./nqdrv mountpoint sharepath\n");
    fprintf(stderr, "usage:  ./nqdrv mountpoint sharepath -o -u user -p password -d domain -a authenticationlevel -s signing\n");
    return 0;
}


static
void
convertPathDelimiters(
    char *path
    )
{
    for (  ; *path != '\0'; path++)
        if (*path == '/')
            *path = '\\';
}


/* create path of form \\<nqMountPoint>\\path */
static
char* 
getFullPath(
    const char* path,
    char* fullPath,
    int size
    )
{
    TRCB();

    if (syStrlen(path) + syStrlen(FSDRIVER_DATA->mntEntry) + 3 > size)
    {
        TRCERR("Path is too long");
        TRCE();
        return NULL;
    }
        
    syStrcpy(fullPath, FSDRIVER_DATA->mntEntry);
    syStrcat(fullPath, path);
    convertPathDelimiters(fullPath);
    
    TRCE();
    return fullPath;
}


static void 
getAttr(
    FileInfo_t *fileInfo, 
    struct stat *statBuf
    )
{
    syMemset(statBuf, 0, sizeof(*statBuf));

    /* set st_mode - important */
    if (fileInfo->attributes & CIFS_ATTR_DIR)
        statBuf->st_mode |= S_IFDIR;
    else
        statBuf->st_mode |= S_IFREG;

    statBuf->st_mode |= (S_IRWXU | S_IRWXG | S_IRWXO);
    if (fileInfo->attributes & CIFS_ATTR_READONLY)
        statBuf->st_mode &= ~(mode_t)(S_IWUSR | S_IWGRP | S_IWOTH);    

    statBuf->st_atime = (time_t)cmCifsUTCToTime(fileInfo->lastAccessTimeLow, fileInfo->lastAccessTimeHigh);
    statBuf->st_ctime = statBuf->st_mtime = (time_t)cmCifsUTCToTime(fileInfo->lastWriteTimeLow, fileInfo->lastWriteTimeHigh);

    statBuf->st_uid = fuse_get_context()->uid;
    statBuf->st_gid = fuse_get_context()->gid;

    statBuf->st_size = (off_t)((fileInfo->attributes & CIFS_ATTR_DIR) ? 4096 : fileInfo->fileSizeLow);
    statBuf->st_nlink = fileInfo->numberOfLinks;
    statBuf->st_blksize = 512;
    statBuf->st_blocks = (statBuf->st_size + 511)/512;

    /*statDump(statBuf);*/
}

#if 0
static void statDump(struct stat *buff)
{
    printf("\nstat dump:");
    printf("\nst_dev: %d - ignored", buff->st_dev);
    printf("\nst_ino: %d - ignored", buff->st_ino);
    printf("\nst_mode: 0x%X, %s", buff->st_mode, buff->st_mode & S_IFDIR ? "S_IFDIR" : "S_IFREG");
    printf("\nst_nlink: %d", buff->st_nlink);
    printf("\nst_uid: %d", buff->st_uid);
    printf("\nst_gid: %d", buff->st_gid);
    printf("\nst_rdev: %d", buff->st_rdev);
    printf("\nst_size: %d", buff->st_size);
    printf("\nst_blksize: %d - ignored", buff->st_blksize);
    printf("\nst_blocks: %d", buff->st_blocks);
    printf("\nst_atime: %d", buff->st_atime);
    printf("\nst_mtime: %d", buff->st_mtime);
    printf("\nst_ctime: %d\n", buff->st_ctime);
}
#endif

#endif /* UD_CC_INCLUDEFSDRIVER */
