/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : OS-dependent functions
 *--------------------------------------------------------------------
 * MODULE        : SY - System-dependent
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 01-Jul-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/
// add by ryu
#include <net/if.h>
#include <ifaddrs.h>
#include <arpa/inet.h>

#include "udparams.h"
#include "syapi.h"
#include "udapi.h"
#include "cmapi.h"

/* #define SYOPSYST_DEBUG */
#ifdef SYOPSYST_DEBUG
 #define syfPrintf(arg) fprintf arg
#else /* SYOPSYST_DEBUG */
 #define syfPrintf(arg)
#endif /* SYOPSYST_DEBUG */


#include <errno.h> 
//#include <sys/sendfile.h>
#include <sys/socket.h> // add by ryuu
#include <sys/param.h>
#include <sys/mount.h>

#ifdef UD_NQ_USETRANSPORTIPV6
/* IPv6 related includes here */
#endif /* UD_NQ_USETRANSPORTIPV6 */

#if (defined(SY_UNICODEFILESYSTEM) && defined(UD_CM_UNICODEAPPLICATION)) || defined(UD_CC_INCLUDELDAP) || defined(UD_NQ_CODEPAGEUTF8)
#include <iconv.h>
#endif

#if defined(SY_UNICODEFILESYSTEM) && defined(UD_CM_UNICODEAPPLICATION)
#define UNICODEFILENAMES
#endif

#ifdef UD_NQ_CODEPAGEUTF8
	 static iconv_t utf16LE_to_Utf8;
	 static iconv_t utf8_to_Utf16LE;
#endif /* UD_NQ_CODEPAGEUTF8 */ 


/* 64 bit offsets support */
#define LONG_FILES_SUPPORT
#ifdef LONG_FILES_SUPPORT
#define loff_t int64_t
#define stat64 stat
#define fstat64 fstat
#define lseek64 lseek
#define ftruncate64 ftruncate

#define OPEN_RDONLY          (O_RDONLY)
#define OPEN_WRONLY          (O_WRONLY)
#define OPEN_RDWR            (O_RDWR)
#define OPEN_RDWR_CREAT      (O_RDWR | O_CREAT)
#else
#define OPEN_RDONLY          (O_RDONLY)
#define OPEN_WRONLY          (O_WRONLY)
#define OPEN_RDWR            (O_RDWR)
#define OPEN_RDWR_CREAT      (O_RDWR | O_CREAT)
#endif /* LONG_FILES_SUPPORT */

#define S_IWUGO (S_IWUSR | S_IWGRP | S_IWOTH)
#define S_IRUGO (S_IRUSR | S_IRGRP | S_IROTH)

/*
    Static functions & data
    -----------------------
 */

typedef struct
{
  /* buffer for converting TCHAR to ASCII or UTF8 */
#ifdef UNICODEFILENAMES
    char utf8Name[4 * UD_FS_FILENAMELEN + 1];
    char newName[4 * UD_FS_FILENAMELEN + 1];
#else
    char asciiName[CM_BUFFERLENGTH(char, UD_FS_FILENAMELEN)];
    char newName[CM_BUFFERLENGTH(char, UD_FS_FILENAMELEN)];
#endif /* UNICODEFILENAMES */
#ifdef UD_CS_INCLUDEDIRECTTRANSFER
    int pipe[2];
#endif /* UD_CS_INCLUDEDIRECTTRANSFER */
}
StaticData;

#ifdef SY_FORCEALLOCATION
static StaticData* staticData = NULL;
#else  /* SY_FORCEALLOCATION */
static StaticData staticDataSrc;
static StaticData* staticData = &staticDataSrc;
#endif /* SY_FORCEALLOCATION */

/* check that file name is valid */
static int checkFileName(const NQ_WCHAR * name)
{
		return NULL == syWStrrchr(name, cmWChar(':'));
}

/* Convert file name from UTF-16 LE to UTF-8
 * Buffer should be twice as big as for UTF-16, since UTF-8 may
 * (theoretically) have up to 4 bytes for a symbol */

#ifdef UNICODEFILENAMES
void filenameToUtf8(
    const unsigned short* name   /* UTF-16 LE name buffer */
    )
{
    iconv_t convertor;
    size_t inbytesleft = (syWStrlen(name) + 1) * sizeof(unsigned short);
    size_t outbytesleft = sizeof(staticData->utf8Name);
    char *in = (char *)name;
    char *out = staticData->utf8Name;
    
    if ((convertor = iconv_open("UTF-8", "UTF-16LE")) == (iconv_t)-1)
    {
        printf("!! Unable to convert UTF-16LE to UTF-8 (iconv_open failed with errno %d)\n", errno);
        return;
    }

    if (iconv(convertor, &in, &inbytesleft, &out, &outbytesleft) == (size_t)-1)
    {
        printf("!! Unable to convert UTF-16LE to UTF-8 (iconv failed with errno %d)\n", errno);
        iconv_close(convertor);
        return;
    }
    iconv_close(convertor);
}

/* Convert file name from UTF-8 to UTF-16 LE */

void filenameFromUtf8(
    unsigned short* buffer, /* UTF-16 LE name buffer */
    int size                /* buffer size */
    )
{
    iconv_t convertor;
    size_t inbytesleft = strlen(staticData->utf8Name) + 1;
    size_t outbytesleft = size;
    char *in = staticData->utf8Name;
    char *out = (char*)buffer;

    if ((convertor = iconv_open("UTF-16LE", "UTF-8")) == (iconv_t)-1)
    {
        printf("!! Unable to convert UTF-8 to UTF-16LE (iconv_open failed with errno %d)\n", errno);
        return;
    }

    if (iconv(convertor, &in, &inbytesleft, &out, &outbytesleft) == (size_t)-1)
    {
        printf("!! Unable to convert UTF-8 to UTF-16LE (iconv failed with errno %d)\n", errno);
        iconv_close(convertor);
        return;
    }
    iconv_close(convertor);
}
#endif /* UNICODEFILENAMES */


#ifdef UD_NS_ASYNCSEND
static void (*bufferReleaseCallback)(const unsigned char *buf);      /* callback function for releasing a z-buffer */

/* release Z-buffer */

static
void
freeSocketBuffer(
    caddr_t buf,        /* buffer to release */
    int freeArg         /* argument */
    );
#endif /* UD_NS_ASYNCSEND */

static
NQ_BOOL
buildSockaddr(
    struct sockaddr* saddr,
    int *size,
    const NQ_IPADDRESS *ip,
    NQ_PORT port
        );

static
NQ_BOOL
parseSockaddr(
    struct sockaddr* saddr,
    NQ_IPADDRESS *ip,
    NQ_PORT *port
        );

/* convert file information from system to system-independent format */

static void
statToFileInformation(
    const struct stat* from,   
    SYFileInformation* to
    );
    
#if (0)  /* for Linux versions where ftruncate() doesn't support extending file */

/* extend file with a specified amount of bytes by writing zeros and positioning
 the file at the end */

static int              /* NQ_SUCCESS or NQ_FAIL */
extendFile(
    int file,           /* fd */
    int off,            /* number of bytes to add */
    int fSize           /* file size before */
);

static const unsigned char zeroArray[] =        /* array of zero bytes for extendFile() use */
    {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};
#endif    

/*====================================================================
 * PURPOSE: initialize resources
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:
 *====================================================================
 */

NQ_BOOL
syInit(
    void
    )
{
    /* allocate memory */
#ifdef SY_FORCEALLOCATION
    staticData = (StaticData*) syCalloc(1, sizeof(*staticData));
    if (staticData == NULL)
    {
        TRCE();
        return FALSE;
    }
#endif /* SY_FORCEALLOCATION */
#ifdef UD_CS_INCLUDEDIRECTTRANSFER
    if ( pipe(staticData->pipe) < 0 ) 
    {
        if (staticData != NULL)
            syFree(staticData);
        TRCE();
        return FALSE;
    }
#endif /* UD_CS_INCLUDEDIRECTTRANSFER */
    return TRUE;
}

/*====================================================================
 * PURPOSE: release resources
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: None
 *
 * NOTES:
 *====================================================================
 */

void
syStop(
    void
    )
{
#ifdef UD_CS_INCLUDEDIRECTTRANSFER
    close(staticData->pipe[0]);
    close(staticData->pipe[1]);
#endif /* UD_CS_INCLUDEDIRECTTRANSFER */
    /* release memory */
#ifdef SY_FORCEALLOCATION
    if (staticData != NULL)
        syFree(staticData);
    staticData = NULL;
#endif /* SY_FORCEALLOCATION */
}

/*
 *====================================================================
 * Convert UNIX file permissions to DOS file attributes
 *--------------------------------------------------------------------
 * NOTES: dos readonly is represented in unix by removing everyone's write bit
 *        dos archive is represented in unix by the user's execute bit
 *        dos system is represented in unix by the group's execute bit
 *        dos hidden is represented in unix by the other's execute bit
 *        dos directory is represented in unix by unix's dir bit
 *====================================================================
 */


int
syUnixMode2DosAttr(
    int mode
    )
{
    int attributes = 0;

    if ((mode & S_IFDIR) != 0)
        attributes = SY_ATTR_DIRECTORY;

    if ((mode & S_IWUGO) == 0)
        attributes |= SY_ATTR_READONLY;
/*	Note: the next attributes are incorrect
    if ((attributes & SY_ATTR_HIDDEN) != 0)
        mode |= S_IXOTH;
    if ((attributes & SY_ATTR_SYSTEM) != 0)
        mode |= S_IXGRP;*/
    if ((mode & S_IXUSR) != 0 && (mode & S_IFDIR) == 0)
        attributes |= SY_ATTR_ARCHIVE;

    return (attributes == 0 ? SY_ATTR_NORMAL : attributes);
}

/*
 *====================================================================
 * Convert DOS file attributes to UNIX file permissions
 *--------------------------------------------------------------------
 * NOTES: dos readonly is represented in unix by removing everyone's write bit
 *        dos archive is represented in unix by the user's execute bit
 *        dos system is represented in unix by the group's execute bit
 *        dos hidden is represented in unix by the other's execute bit
 *        dos directory is represented in unix by unix's dir bit
 *====================================================================
 */

static
int
dos2Unix(
    int attributes
    )
{
    int mode = S_IRUGO;

    if ((attributes & SY_ATTR_DIRECTORY) != 0)
        mode |= S_IFDIR;

    if ((attributes & SY_ATTR_READONLY) == 0)
        mode |= S_IWUGO;
/*	Note: the next attributes are incorrect
    if ((attributes & SY_ATTR_HIDDEN) != 0)
        mode |= S_IXOTH;
    if ((attributes & SY_ATTR_SYSTEM) != 0)
        mode |= S_IXGRP;*/
    if ((attributes & SY_ATTR_ARCHIVE) != 0)
        mode |= S_IXUSR;

    return mode;
}

/*
 *====================================================================
 * PURPOSE: Convert last system error into SMB error
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: SMB Error converted from system error
 *
 * NOTES:
 *
 *====================================================================
 */

NQ_UINT32
syGetLastSmbError(
    void
    )
{
    if (errno == 0)
        return 0;

    return udGetSmbError((NQ_UINT32)errno);
}

/*
 *====================================================================
 * PURPOSE: Set NQ error into system error
 *--------------------------------------------------------------------
 * PARAMS:  IN SMB error in NT format
 *
 * RETURNS: NONE
 *
 * NOTES:
 *
 *====================================================================
 */

void
sySetLastNqError(
    NQ_UINT32 nqErr
    )
{
    errno = (int)nqErr;
}

/*
 *====================================================================
 * PURPOSE: fill a static file information structure
 *--------------------------------------------------------------------
 * PARAMS:  IN file name
 *          OUT file information structure
 *
 * RETURNS: 0 on success, -1 on error
 *
 * NOTES:
 *
 *====================================================================
 */

int
syGetFileInformationByName(
    const NQ_WCHAR* fileName,
    SYFileInformation* fileInfo
    )
{
    struct stat tmp;

#ifdef UNICODEFILENAMES
    filenameToUtf8(fileName);
    if (stat(staticData->utf8Name, &tmp) == -1)
        return NQ_FAIL;
#else
    syUnicodeToAnsi(staticData->asciiName, fileName);
    cmAnsiToFs(staticData->asciiName, sizeof(staticData->asciiName));
    if (stat(staticData->asciiName, &tmp) == -1)
        return NQ_FAIL;
#endif /* UNICODEFILENAMES */

    statToFileInformation(&tmp, fileInfo);

    return NQ_SUCCESS;
}

/*
 *====================================================================
 * PURPOSE: fill a static file information structure
 *--------------------------------------------------------------------
 * PARAMS:  IN file handle
 *          IN file name (not used in VxWorks)
 *          OUT file information structure
 *
 * RETURNS: NONE
 *
 * NOTES:
 *
 *====================================================================
 */

int
syGetFileInformation(
    SYFile file,
    const NQ_WCHAR* fileName,
    SYFileInformation* fileInfo
    )
{
    struct stat tmp;

    if (fstat(file, &tmp) == -1)
        return NQ_FAIL;

    statToFileInformation(&tmp, fileInfo);

    return NQ_SUCCESS;
}

/*
 *====================================================================
 * PURPOSE: fill a static file information structure
 *--------------------------------------------------------------------
 * PARAMS:  IN file name
 *          IN file handle (use handle if it is valid)
 *          OUT file information structure
 *
 * RETURNS: 0 - success, -1 - error
 *
 * NOTES:
 *
 *====================================================================
 */

int
sySetFileInformation(
    const NQ_WCHAR* fileName,
    SYFile file,
    const SYFileInformation* fileInfo
    )
{
    struct utimbuf timeBuf; /* time buffer */
    struct stat statBuf;    /* file status info */
    int wasOpen;            /* file was opened */

    if (!(wasOpen = syIsValidFile(file)))
    {
#ifdef UNICODEFILENAMES
        filenameToUtf8(fileName);
        if ((file = open(staticData->utf8Name, OPEN_RDONLY, 0777)) == -1)
            return NQ_FAIL;
#else
        syUnicodeToAnsi(staticData->asciiName, fileName);
        cmAnsiToFs(staticData->asciiName, sizeof(staticData->asciiName));
        if ((file = open(staticData->asciiName, OPEN_RDONLY, 0777)) == -1)
            return NQ_FAIL;
#endif /* UNICODEFILENAMES */    
    }
    // ryuu 
    /* set attributes 
    if (fchmod(file, (__mode_t)dos2Unix((int)fileInfo->attributes)) == -1)
    {
        if (!wasOpen)
            close(file);
        return NQ_FAIL;
    }
     */

    /* read file statistics */
    if (fstat(file, &statBuf) == -1)
    {
        if (!wasOpen)
            close(file);
        return NQ_FAIL;
    }

    if (   (cmTimeConvertMSecToSec((NQ_TIME *)&fileInfo->lastAccessTime) != 0 && cmTimeConvertMSecToSec((NQ_TIME *)&fileInfo->lastAccessTime) != (NQ_UINT32)statBuf.st_atime)
        || (cmTimeConvertMSecToSec((NQ_TIME *)&fileInfo->lastWriteTime)  != 0 && cmTimeConvertMSecToSec((NQ_TIME *)&fileInfo->lastWriteTime)  != (NQ_UINT32)statBuf.st_mtime)
       )
    {
    	NQ_TIME zero = {0, 0};

        if (0 == cmU64Cmp((NQ_TIME *)&fileInfo->lastAccessTime, &zero))
            timeBuf.actime = statBuf.st_atime;
        else
            timeBuf.actime = (time_t)cmTimeConvertMSecToSec((NQ_TIME *)&fileInfo->lastAccessTime);
        if (0 == cmU64Cmp((NQ_TIME *)&fileInfo->lastWriteTime, &zero))
            timeBuf.modtime = statBuf.st_mtime;
        else
            timeBuf.modtime = (time_t)cmTimeConvertMSecToSec((NQ_TIME *)&fileInfo->lastWriteTime);
#ifdef UNICODEFILENAMES
        if (utime(staticData->utf8Name, &timeBuf) == -1)
        {
            if (!wasOpen)
                close(file);
            return NQ_FAIL;
        }
#else
        if (utime(staticData->asciiName, &timeBuf) == -1)
        {
            if (!wasOpen)
                close(file);
            return NQ_FAIL;
        }
#endif /* UNICODEFILENAMES */
    }

    if (!wasOpen)
        close(file);

    return NQ_SUCCESS;
}

/*
 *====================================================================
 * PURPOSE: query volume information
 *--------------------------------------------------------------------
 * PARAMS:  IN volume name
 *          OUT buffer for information
 *
 * RETURNS: 0 - success, -1 - error
 *
 * NOTES:
 *
 *====================================================================
 */

int
syGetVolumeInformation(
    const NQ_WCHAR* name,
    SYVolumeInformation *info
    )
{
    struct statfs tmp;

#ifdef UNICODEFILENAMES
    filenameToUtf8(name);
    if (statfs(staticData->utf8Name, &tmp) < 0)
        return NQ_FAIL;
#else
    syUnicodeToAnsi(staticData->asciiName, name);
    cmAnsiToFs(staticData->asciiName, sizeof(staticData->asciiName));
    if (statfs(staticData->asciiName, &tmp) < 0)
        return NQ_FAIL;
#endif /* UNICODEFILENAMES */

    info->fileSystemIdLow = UD_FS_FILESYSTEMID;
    info->creationTimeLow = 0L;                    /* simulate 1-1-1970 */
    info->serialNumberLow = 0L;                    /* we do not report serial number */
    info->blockSizeLow = (NQ_UINT32)tmp.f_bsize;
    info->blocksPerUnitLow = 1;
    info->totalUnitsLow = (NQ_UINT32)tmp.f_blocks;
    info->freeUnitsLow = (NQ_UINT32)tmp.f_bfree;
    info->totalUnitsHigh = 0L;
    info->freeUnitsHigh = 0L;

    return NQ_SUCCESS;
}

/*
 *====================================================================
 * PURPOSE: get MAC address by IP4
 *--------------------------------------------------------------------
 * PARAMS:  IN ip address
 *          OUT buffer for MAC address
 *
 * RETURNS: NONE
 *
 * NOTES:   if MAC address is not available - fill buffer by zeroes
 *
 *====================================================================
 */

void
syGetMacAddress(
    NQ_IPADDRESS4 ip4,
    NQ_BYTE* macBuffer
    )
{
    static const NQ_BYTE mac[6] = {0,0,0,0,0,0};
    syMemcpy(macBuffer, mac, sizeof(mac));
    return;
}

/*
 *====================================================================
 * PURPOSE: get next adapter information
 *--------------------------------------------------------------------
 * PARAMS:  IN adapter number (zero based)
 *          OUT buffer for adapter IP in NBO
 *          OUT buffer for subnet mask in NBO
 *          OUT buffer for wins IP in NBO (may be zero for a B-node)
 *
 * RETURNS: 0 when there is no adapter with the given index,
 *          1 when adapter information awailable
 *
 * NOTES:
 *
 *====================================================================
 */

/*static struct ifreq *next_ifr (struct ifreq *ifr)
{
    char *ptr = (char *)ifr;
    ptr += (sizeof (*ifr)  - sizeof (struct sockaddr) + ifr->ifr_ifru.ifru_addr.sa_len );
    return (struct ifreq *)ptr;
}*/

#define MAX_EXT_ADDRESSES (UD_NS_MAXADAPTERS + 5)

NQ_STATUS
syGetAdapter(
    NQ_INDEX adapterIdx,    /* adapter number (zero based) */
	NQ_INDEX * osIndex,     /* buffer for adapter index as defined by the OS */
    NQ_IPADDRESS4* pIp,     /* buffer for adapter IP in NBO */
    NQ_IPADDRESS6 *ip6,     /* buffer for adapter IPv6 in NBO */
    NQ_IPADDRESS4* pSubnet, /* buffer for subnet address in NBO */
	NQ_IPADDRESS4* pBcast, 	/* buffer for bcast address in NBO */
    NQ_IPADDRESS4* pWins    /* buffer for wins address in NBO (may be 0 for a B-node) */
    )
{
    unsigned int idx = 0;                    /* as counted by NQ */
    unsigned int osIdx = 0;            /* as counted by the OS */
    int status;
    unsigned long nelem;
    int ntSockFd;
    int result = NQ_FAIL;

    struct ifaddrs* pIfa;
    struct ifaddrs* saved = NULL;
#ifdef UD_NQ_USETRANSPORTIPV6
    struct in6_addr any6 = IN6ADDR_ANY_INIT;
#endif /* UD_NQ_USETRANSPORTIPV6 */

    /*
     * nelem is set to the maximum interfaces
     * on one machine here
     */
    nelem = 4*MAX_EXT_ADDRESSES;

    /* try to get the IP/Bcast from the system */

    ntSockFd = socket(AF_INET, SOCK_DGRAM, 0);

    /* check socket error */
    if (-1 == ntSockFd)
    {
       syfPrintf((stderr, "[%s:%d][%s()] %d %s\n", __FILE__, __LINE__, __func__, errno, strerror(errno)));
       goto Exit;
    }

    status = getifaddrs(&pIfa);
    if (status < 0)
    {
        syfPrintf((stderr, "[%s:%d][%s()] %d %s\n", __FILE__, __LINE__, __func__, errno, strerror(errno)));
        goto Exit;
    }

    if (0 == status)
    {
		saved = pIfa;
    	for (idx = 0; adapterIdx > 0 && idx <= *osIndex; pIfa = pIfa->ifa_next, ++idx )
    	{
    		/* do nothing */
    	}
    	*osIndex = idx;

		for (idx = 0 , osIdx = *osIndex; pIfa != NULL && osIdx < nelem ; pIfa = pIfa->ifa_next, ++osIdx)
		{
#ifdef UD_NQ_USETRANSPORTIPV6
			memset(ip6, 0, 16);
#endif /* UD_NQ_USETRANSPORTIPV6 */
			*pIp = CM_IPADDR_ZERO4;
			*pSubnet = CM_IPADDR_ZERO4;
			if (pIfa->ifa_addr && (pIfa->ifa_addr->sa_family == AF_INET || pIfa->ifa_addr->sa_family == AF_INET6))
			{
				/*
				 * Don't bother with interfaces that have been disabled
				 */
				if (!(pIfa->ifa_flags & IFF_UP))
				{
					continue;
				}

				/*
				 * Don't use the loop back interface
				 */
				if (pIfa->ifa_flags & IFF_LOOPBACK)
				{
					continue;
				}

				/*
				 * If its not an internet inteface then dont use it.
				 */

				if(0 && pIfa->ifa_addr->sa_family != AF_INET)
				{
					continue;
				}

				/*
				 * If this is an interface that supports
				 * broadcast fetch the broadcast address.
				 */
				if (!(pIfa->ifa_flags & IFF_BROADCAST))
				{
					continue;
				}

				*pWins = udGetWins();
				*osIndex = osIdx;
				if (pIfa->ifa_addr != NULL)
				{
					if (pIfa->ifa_addr->sa_family == AF_INET)
					{
						/* Get interface IP Address */
						*pIp = ((struct sockaddr_in*)pIfa->ifa_addr)->sin_addr.s_addr;
						/* Get interface mask Address */
						*pSubnet = ((struct sockaddr_in*)pIfa->ifa_netmask)->sin_addr.s_addr;
						/* Get interface broadcast Address */
						*pBcast = ((struct sockaddr_in*)pIfa->ifa_broadaddr)->sin_addr.s_addr;
					}
#ifdef UD_NQ_USETRANSPORTIPV6
					else if (pIfa->ifa_addr->sa_family == AF_INET6)
					{
						struct sockaddr_in6* p6 = (struct sockaddr_in6*)pIfa->ifa_addr;
						if (memcmp(p6->sin6_addr.s6_addr16, &any6, sizeof(any6)) == 0)
							continue;
						memcpy(ip6, p6->sin6_addr.s6_addr16, 16);
					}
#endif /* UD_NQ_USETRANSPORTIPV6 */
					result = NQ_SUCCESS;
					goto Exit;
				}
			}
		}
    }

Exit:
	if( NULL != saved )
		freeifaddrs(saved);

    if( -1 != ntSockFd )
    {
        close(ntSockFd);
    }

    return result;
}

#if (0)

int
syGetAdapter(
    int adapterIdx,         /* adapter number (zero based) */
    unsigned long* pIp,     /* buffer for adapter IP in NBO */
    NQ_IPADDRESS6 *ip6,     /* buffer for adapter IPv6 in NBO */
    unsigned long* pSubnet, /* buffer for subnet address in NBO */
    unsigned long* pWins    /* buffer for wins address in NBO (may be 0 for a B-node) */
    )
{
    int idx = 0;
    int i, fd ;
    struct in_addr ipAddr, ipMask, bCast;
    argOZIOGetSysInfoType arg;

    if ( (fd = socket(AF_XIPINET, SOCK_DGRAM, IPPROTO_UDP)) < 0 )
    {
        return ERROR;
    }

    for ( i = 0 ; i < 3 ; i++ )
    {
        memset( &arg, 0, sizeof(arg) ) ;

        arg.addr.hp_len = sizeof(struct sockaddr_hp);
        arg.addr.hp_family = AF_HP;
        arg.addr.hp_class = AC_IIO;
        arg.addr.hp_slot = i ;
        arg.operation = OZIO_SYS_INFO_OPERATION_GET;
        arg.objectId = OZIO_SYS_INFO_OID_IP_ADDR;
        arg.value = &ipAddr;
        arg.len = sizeof(ipAddr);

        if (ioctl(fd, OZIO_IOCTL_GET_SYS_INFO, &arg ) != 0)
        {
            continue;
        }

        memset( &arg, 0, sizeof(arg) ) ;
        arg.addr.hp_len = sizeof(struct sockaddr_hp);
        arg.addr.hp_family = AF_HP;
        arg.addr.hp_class = AC_IIO;
        arg.addr.hp_slot = i ;
        arg.operation = OZIO_SYS_INFO_OPERATION_GET;
        arg.objectId = OZIO_SYS_INFO_OID_SUBNET_MASK;
        arg.value = &ipMask;
        arg.len = sizeof(ipMask);
        if (ioctl(fd, OZIO_IOCTL_GET_SYS_INFO, &arg ) != 0)
        {
                continue;
        }

        bCast.s_addr = ipAddr.s_addr | ~(ipMask.s_addr);

        *pIp = ipAddr.s_addr;
        *pSubnet = ipMask.s_addr;
        *pWins = udGetWins();
        if (idx++ == adapterIdx)
        {
            close(fd);
            return OK;
        }
    }
    close(fd);
    return ERROR;
}

#endif

#ifdef UD_NQ_USETRANSPORTIPV6
/*
 *====================================================================
 * PURPOSE: get IPv6 scope ID
 *--------------------------------------------------------------------
 * PARAMS:  ip - the IPv6 address
 *
 * RETURNS: 0..n - the scope id to be used  
 *   
 * NOTES:  0 - unknown network interface
 *====================================================================
 */

NQ_UINT32
syGetIPv6ScopeId(
    const NQ_IPADDRESS6 ip
    )
{
    struct ifaddrs *ifaddr, *ifa;
    unsigned int scopeId = 0;

    /* only link-local ip addresses need scopeId */
    if ((ip[0] & SY_LINKLOCALIP) != SY_LINKLOCALIP)
        return 0;

    if (getifaddrs(&ifaddr) == -1) 
        return 0;

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) 
    {
       if (ifa->ifa_addr == NULL)
          continue;

       if (!(ifa->ifa_flags & IFF_UP) || (ifa->ifa_flags & IFF_LOOPBACK))
          continue;

       if (ifa->ifa_addr->sa_family == AF_INET6)
       {
           scopeId = if_nametoindex(ifa->ifa_name);
           if (scopeId != 0)
              break;
       }
    }

    freeifaddrs(ifaddr);
    return scopeId;
}

#endif /* UD_NQ_USETRANSPORTIPV6 */


NQ_TIME syGetTimeInMsec(void)
{
	NQ_TIME curTime;
	struct timeval tv;

	gettimeofday(&tv, NULL);
	cmU64MultU32U32(&curTime, (NQ_UINT32)tv.tv_sec, 1000);
	curTime.low += (NQ_UINT32)(tv.tv_usec/1000);

	return curTime;
}

/*
 *====================================================================
 * PURPOSE: Get time offset
 *--------------------------------------------------------------------
 * PARAMS:  IN system time
 *          OUT structure of file fragments
 *
 * RETURNS: The number of minutes to be added to the local time to
 *          get GMT. This number is negative for GMT+ and positive for
 *          GMT-
 *
 * NOTES:
 *
 *====================================================================
 */

int
syGetTimeZone(
    void
    )
{
  struct tm utc, local;
  time_t current;

  time ( &current );

  gmtime_r ( &current, &utc );
  localtime_r ( &current, &local );

  return (utc.tm_hour - local.tm_hour) * 60 + utc.tm_min - local.tm_min;
}

NQ_TIME syConvertTimeSpecToTimeInMsec(void * val)
{
	NQ_TIME curTime;
	struct timespec * tv = (struct timespec *)val;

	cmU64MultU32U32(&curTime, (NQ_UINT32)tv->tv_sec, 1000);
	curTime.low += (NQ_UINT32)(tv->tv_nsec/1000000);

	return curTime;
}

/*
 *====================================================================
 * PURPOSE: Decompose system time into fragments
 *--------------------------------------------------------------------
 * PARAMS:  IN system time
 *          OUT structure of file fragments
 *
 * RETURNS: NONE
 *
 * NOTES:
 *
 *====================================================================
 */

void
syDecomposeTime(
    NQ_UINT32 time,
    SYTimeFragments* decomposed
    )
{
    struct tm sysTime;
    time_t t = (time_t)time;

    localtime_r(&t, &sysTime);

    decomposed->year   = (NQ_UINT16)sysTime.tm_year;
    decomposed->day    = (NQ_UINT16)sysTime.tm_mday;
    decomposed->month  = (NQ_UINT16)sysTime.tm_mon;
    decomposed->hour   = (NQ_UINT16)sysTime.tm_hour;
    decomposed->min    = (NQ_UINT16)sysTime.tm_min;
    decomposed->sec    = (NQ_UINT16)sysTime.tm_sec;
}

/*
 *====================================================================
 * PURPOSE: compose system time from fragments
 *--------------------------------------------------------------------
 * PARAMS:  OUT structure of file fragments
 *
 * RETURNS: composed system time
 *
 * NOTES:
 *
 *====================================================================
 */

NQ_UINT32
syComposeTime(
    const SYTimeFragments* decomposed
    )
{
    struct tm time;

    time.tm_year   = decomposed->year;
    time.tm_mday   = decomposed->day;
    time.tm_mon    = decomposed->month;
    time.tm_hour   = decomposed->hour;
    time.tm_min    = decomposed->min;
    time.tm_sec    = decomposed->sec;

    return (NQ_UINT32)mktime(&time);
}

#ifdef UD_NQ_USETRANSPORTIPV6
#define MAX_SOCKADDR_SIZE sizeof(struct sockaddr_in6)
#else /* UD_NQ_USETRANSPORTIPV6 */
#define MAX_SOCKADDR_SIZE sizeof(struct sockaddr_in)
#endif /* UD_NQ_USETRANSPORTIPV6 */

static
NQ_BOOL
buildSockaddr(
    struct sockaddr* saddr,
    int *size,
    const NQ_IPADDRESS *ip,
    NQ_PORT port
        )
{
#if SY_DEBUGMODE
    if (!ip)
    {
        TRCERR("Invalid ip pointer: NULL");
        return FALSE;
    }
#endif /* SY_DEBUGMODE */

#ifdef UD_NQ_USETRANSPORTIPV6
    switch (ip->version)
    {
        case CM_IPADDR_IPV4:
#endif /* UD_NQ_USETRANSPORTIPV6 */

        {
            struct sockaddr_in *sin = (struct sockaddr_in*)saddr;

            memset(sin, 0, sizeof(struct sockaddr_in));
            sin->sin_family = AF_INET;
            sin->sin_port = port;
            sin->sin_addr.s_addr = (in_addr_t)CM_IPADDR_GET4(*ip);
            *size = sizeof(struct sockaddr_in);
            return TRUE;
        }

#ifdef UD_NQ_USETRANSPORTIPV6
        case CM_IPADDR_IPV6:
        {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)saddr;

            memset(sin6, 0, sizeof(struct sockaddr_in6));
            sin6->sin6_family = AF_INET6;
            sin6->sin6_port = port;
            syMemcpy(sin6->sin6_addr.s6_addr, CM_IPADDR_GET6(*ip), sizeof(NQ_IPADDRESS6));
            sin6->sin6_scope_id = (uint32_t)syGetIPv6ScopeId(ip->addr.v6);
            *size = sizeof(struct sockaddr_in6);
            return TRUE;
        }

        default:
            TRC1P("Invalid ip version: %d", ip->version);
            return FALSE;
    }
#endif /* UD_NQ_USETRANSPORTIPV6 */
}

static
NQ_BOOL
parseSockaddr(
    struct sockaddr* saddr,
    NQ_IPADDRESS *ip,
    NQ_PORT *port
        )
{
#ifdef UD_NQ_USETRANSPORTIPV6
    switch (saddr->sa_family)
    {
    case AF_INET:
#endif /* UD_NQ_USETRANSPORTIPV6 */

    {
        struct sockaddr_in *sin = (struct sockaddr_in*)saddr;
        *port = sin->sin_port;
        CM_IPADDR_ASSIGN4(*ip, sin->sin_addr.s_addr);
        return TRUE;
    }

#ifdef UD_NQ_USETRANSPORTIPV6
    case AF_INET6:
    {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)saddr;
        *port = sin6->sin6_port;
        CM_IPADDR_ASSIGN6(*ip, sin6->sin6_addr.s6_addr);
        return TRUE;
    }

    default:
    {
        NQ_IPADDRESS zero = CM_IPADDR_ZERO;
        TRC1P("Unknown address family: %d", saddr->sa_family);
        *port = 0;
        *ip = zero;
        return FALSE;
    }
    }
#endif /* UD_NQ_USETRANSPORTIPV6 */
}

/*
 *====================================================================
 * PURPOSE: Detecting whether a socket is still alive
 *--------------------------------------------------------------------
 * PARAMS:  IN socket id
 *
 * RETURNS: TRUE or FALSE
 *
 * NOTES:   this method is said to work on any BSD socket system: issue select()
 *          with a zero timeout. on dead socket this should return error instead of zero
 *====================================================================
 */

NQ_BOOL
syIsSocketAlive(
    SYSocketHandle sock
    )
{
    fd_set set;             /* temporary set for checking the socket */
    struct timeval tv;      /* timeout value */
    int ret;                /* the select result */

    tv.tv_sec = 0;
    tv.tv_usec = 0;

    FD_ZERO(&set);
    FD_SET(sock, &set);

    ret = select(FD_SETSIZE, &set, NULL, NULL, &tv);

    return (ret >= 0)? TRUE : FALSE;
}

/*
 *====================================================================
 * PURPOSE: Stop socket operations and disconnect the socket if it was connected
 *--------------------------------------------------------------------
 * PARAMS:  IN socket id
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:   this method is said to work on any BSD socket system
 *
 *====================================================================
 */

NQ_STATUS
syShutdownSocket(
    SYSocketHandle sock
    )
{
    return (shutdown(sock, 2)==ERROR)? NQ_FAIL : NQ_SUCCESS;
}

/*
 *====================================================================
 * PURPOSE: Close socket
 *--------------------------------------------------------------------
 * PARAMS:  IN socket id
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:
 *
 *====================================================================
 */
NQ_STATUS
syCloseSocket(
    SYSocketHandle sock
    )
{
    return (close(sock) == ERROR) ? NQ_FAIL : NQ_SUCCESS;
}

/*
 *====================================================================
 * PURPOSE: Listen on server socket
 *--------------------------------------------------------------------
 * PARAMS:  IN socket id
 *          IN max number of requests in queue
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:
 *
 *====================================================================
 */
NQ_STATUS
syListenSocket(
    SYSocketHandle sock,
    NQ_INT backlog
    )
{
    return (listen(sock, backlog) == OK) ? NQ_SUCCESS : NQ_FAIL;
}

/*
 *====================================================================
 * PURPOSE: Create new socket
 *--------------------------------------------------------------------
 * PARAMS:  OUT pointer to socket id
 *
 * RETURNS: None
 *
 * NOTES:
 *
 *====================================================================
 */
SYSocketHandle
syCreateSocket(
    NQ_INT stream,
    NQ_UINT family
    )
{
#ifdef UD_NQ_USETRANSPORTIPV6
    switch (family)
    {
        case CM_IPADDR_IPV4:
#endif /* UD_NQ_USETRANSPORTIPV6 */
            return socket(AF_INET, ((stream)? SOCK_STREAM : SOCK_DGRAM), 0);
#ifdef UD_NQ_USETRANSPORTIPV6
        case CM_IPADDR_IPV6:
            return socket(AF_INET6, ((stream)? SOCK_STREAM : SOCK_DGRAM), 0);
        default:
            TRC1P("Invalid socket family: %d", family);
            return ERROR;
    }
#endif /* UD_NQ_USETRANSPORTIPV6 */
}

/*
 *====================================================================
 * PURPOSE: Bind socket to IP and port
 *--------------------------------------------------------------------
 * PARAMS:  IN socket id
 *          IN IP address in NBO
 *          IN port number in NBO
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:
 *
 *====================================================================
 */

NQ_STATUS
syBindSocket(
    SYSocketHandle sock,
    const NQ_IPADDRESS *ip,
    NQ_PORT port
    )
{
    char buffer[MAX_SOCKADDR_SIZE];
    struct sockaddr *saddr = (struct sockaddr*)buffer;
    int size;
    int val1 = 1;               /* setting socket options */

#ifdef UD_NQ_USETRANSPORTIPV6
    if (ip->version == CM_IPADDR_IPV6)
    {
        setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&val1, sizeof(val1));
    }
#endif

    if (buildSockaddr(saddr, &size, ip, port) &&
        bind(sock, (struct sockaddr*)saddr, (socklen_t)size) == OK)
    {
        setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (char*)&val1, sizeof(val1));
        setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char*)&val1, sizeof(val1));
        setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (char*)&val1, sizeof(val1));

        return NQ_SUCCESS;
    }

    return NQ_FAIL;
}

/*
 *====================================================================
 * PURPOSE: Allow broadcasts on socket
 *--------------------------------------------------------------------
 * PARAMS:  IN socket id
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:
 *
 *====================================================================
 */

NQ_STATUS
syAllowBroadcastsSocket(
    SYSocketHandle sock
    )
{
    int on = 1;

    setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (char*)&on, sizeof(on));

    return NQ_SUCCESS;
}


/*
 *====================================================================
 * PURPOSE: Tune a new client socket
 *--------------------------------------------------------------------
 * PARAMS:  IN socket id
 *
 * RETURNS: None
 *
 * NOTES:
 *
 *====================================================================
 */

void
sySetClientSocketOptions(
    SYSocketHandle sock
    )
{
    struct linger l;    /* for setting linger options */
#if (UD_NS_BUFFERSIZE > 8192)
    int valBuf;         /* for setting buffer lengths */
#endif

    l.l_onoff = 0;
    l.l_linger = 1;
    setsockopt (sock, SOL_SOCKET, SO_LINGER, (char*)&l, sizeof (l));

#if (UD_NS_BUFFERSIZE > 8192)
    valBuf = UD_NS_BUFFERSIZE;
    setsockopt (sock, SOL_SOCKET, SO_SNDBUF, (char*)&valBuf, sizeof(valBuf));
    setsockopt (sock, SOL_SOCKET, SO_RCVBUF, (char*)&valBuf, sizeof(valBuf));
#endif
}

/*
 *====================================================================
 * PURPOSE: Get IP and port the socket is bound on
 *--------------------------------------------------------------------
 * PARAMS:  IN socket id
 *          OUT buffer for IP address in NBO
 *          OUT buffer for port number in NBO
 *
 * RETURNS: None
 *
 * NOTES:
 *
 *====================================================================
 */

void
syGetSocketPortAndIP(
    SYSocketHandle sock,
    NQ_IPADDRESS *ip,
    NQ_PORT *port
    )
{
    char buffer[MAX_SOCKADDR_SIZE];
    struct sockaddr *saddr = (struct sockaddr*)buffer;
    socklen_t size = sizeof(buffer);

    if (getsockname(sock, (struct sockaddr*)saddr, &size) == ERROR)
    {
        NQ_IPADDRESS zero = CM_IPADDR_ZERO;

        *port = 0;
        *ip = zero;
    }
    else
        parseSockaddr(saddr, ip, port);
}

/*
 *====================================================================
 * PURPOSE: Send a UDP message to a specific addressee
 *--------------------------------------------------------------------
 * PARAMS:  IN socket id
 *          IN buffer to send
 *          IN number of bytes to send
 *          IN IP address of the addressee in NBO
 *          IN port number of the addressee in NBO
 *
 * RETURNS: NQ_FAIL or number of bytes sent
 *
 * NOTES:
 *
 *====================================================================
 */

NQ_INT
sySendToSocket(
    SYSocketHandle sock,
    const NQ_BYTE *buf,
    NQ_COUNT len,
    const NQ_IPADDRESS *ip,
    NQ_PORT port
    )
{
    char buffer[MAX_SOCKADDR_SIZE];
    struct sockaddr *saddr = (struct sockaddr*)buffer;
    int size, res;

    if (!buildSockaddr(saddr, &size, ip, port))
        return NQ_FAIL;

    res = (int)sendto(sock, (char*)buf, (size_t)len, 0, saddr, (socklen_t)size);
    return (res == ERROR) ? NQ_FAIL : res;
}

/*
 *====================================================================
 * PURPOSE: Connect to a remote server port
 *--------------------------------------------------------------------
 * PARAMS:  IN socket id
 *          IN IP address of the server in NBO
 *          IN port number of the server in NBO
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:
 *
 *====================================================================
 */

NQ_STATUS
syConnectSocket(
    SYSocketHandle sock,
    const NQ_IPADDRESS *ip,
    NQ_PORT port
    )
{
    char buffer[MAX_SOCKADDR_SIZE];
    struct sockaddr *saddr = (struct sockaddr*)buffer;
    int size, val0 = 0, val1 = 1;

    if (!buildSockaddr(saddr, &size, ip, port))
        return NQ_FAIL;

    if (connect(sock, saddr, (socklen_t)size) != OK)
        return NQ_FAIL;

    setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (char*)&val0, sizeof(val0));
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char*)&val1, sizeof(val1));
    return NQ_SUCCESS;
}


/*
 *====================================================================
 * PURPOSE: Send bytes over a connected socket
 *--------------------------------------------------------------------
 * PARAMS:  IN socket id
 *          IN buffer to send
 *          IN number of bytes to send
 *
 * RETURNS: NQ_FAIL or number of bytes sent
 *
 * NOTES:
 *
 *====================================================================
 */

NQ_INT
sySendSocket(
    SYSocketHandle sock,
    const unsigned char* buf,
    unsigned int len
    )
{
    int res;                /* operation result */

    res = (int)send(sock, (const char*)buf, len, 0);

    return (res == ERROR)? NQ_FAIL : res;
}

#ifdef UD_NS_ASYNCSEND
#error Zero buffers are not supported (UD_NS_ASYNCSEND)
#endif /* UD_NS_ASYNCSEND */

/*
 *====================================================================
 * PURPOSE: Select on sockets
 *--------------------------------------------------------------------
 * PARAMS:  IN pointer to file set
 *          IN select timeout in seconds
 *
 * RETURNS: number of sockets with data pending, zero on timeout or
 *          NQ_FAIL on error
 *
 * NOTES:
 *
 *====================================================================
 */

NQ_INT
sySelectSocket(
    SYSocketSet* pSet,
    NQ_UINT32 timeout
    )
{
    struct timeval tv;      /* timeout */
    int num;                /* the result of select() */

    tv.tv_sec = (time_t)timeout;
    tv.tv_usec = 0;
    num = select (FD_SETSIZE, pSet, NULL, NULL, &tv);
    return (num == ERROR)? NQ_FAIL : num;
}

/*
 *====================================================================
 * PURPOSE: Receive a UDP message
 *--------------------------------------------------------------------
 * PARAMS:  IN socket id
 *          IN receive buffer
 *          IN buffer length
 *          OUT buffer for sender IP address in NBO
 *          OUT buffer for sender port number in NBO
 *
 * RETURNS: NQ_FAIL or number of bytes received
 *
 * NOTES:
 *
 *====================================================================
 */

NQ_INT
syRecvFromSocket(
    SYSocketHandle sock,
    NQ_BYTE* buf,
    NQ_COUNT len,
    NQ_IPADDRESS* ip,
    NQ_PORT* port
    )
{
    char buffer[MAX_SOCKADDR_SIZE];
    struct sockaddr *saddr = (struct sockaddr*)buffer;
    socklen_t size = sizeof(buffer);
    int res = (int)recvfrom(sock, (char*)buf, len, 0, saddr, &size);

    if (res == ERROR)
        return NQ_FAIL;

    if (!parseSockaddr(saddr, ip, port))
        return NQ_FAIL;

    return res;
}

/*
 *====================================================================
 * PURPOSE: Receive a UDP message from any sender
 *--------------------------------------------------------------------
 * PARAMS:  IN socket id
 *          IN receive buffer
 *          IN buffer length
 *
 * RETURNS: NQ_FAIL or number of bytes received
 *
 * NOTES:
 *
 *====================================================================
 */

NQ_INT
syRecvSocket(
    SYSocketHandle sock,
    unsigned char* buf,
    unsigned int len
    )
{
    int res;                        /* operation result */

    res = (int)recv(sock, (char*)buf, len, 0);
    return (res==ERROR)? NQ_FAIL : res;
}

/*
 *====================================================================
 * PURPOSE: Receive from a datagram or a TCP stream or time out
 *--------------------------------------------------------------------
 * PARAMS:  IN socket id
 *          OUT receive buffer
 *          IN buffer length
 *          IN timeout
 *
 * RETURNS: NQ_FAIL or number of bytes received
 *
 * NOTES:
 *
 *====================================================================
 */

NQ_INT
syRecvSocketWithTimeout(
    SYSocketHandle sock,
    unsigned char* buf,
    unsigned int len,
    unsigned int secs
    )
{
    int res;                         /* operation result */
    fd_set socketSet;                /* for select */
    struct timeval tv;               /* timeout */

    tv.tv_sec = (time_t)secs;
    tv.tv_usec = 0;

    FD_ZERO(&socketSet);
    FD_SET(sock, &socketSet);
    res = select (FD_SETSIZE, &socketSet, NULL, NULL, &tv);
#ifdef SYOPSYST_DEBUG
    if (NQ_FAIL == res)
        syfPrintf((stderr, "[%s:%d][%s()] %d %s\n", __FILE__, __LINE__, __func__, errno, strerror(errno)));
#endif /* SYOPSYST_DEBUG */

    if (res > 0)
    {
        res = (int)recv(sock, (char*)buf, len, 0);
#ifdef SYOPSYST_DEBUG
        if (NQ_FAIL == res)
            syfPrintf((stderr, "[%s:%d][%s()] %d %s\n", __FILE__, __LINE__, __func__, errno, strerror(errno)));
#endif /* SYOPSYST_DEBUG */
    }

    return res;
}


/*
 *====================================================================
 * PURPOSE: Accept client socket
 *--------------------------------------------------------------------
 * PARAMS:  IN server socket id
 *          OUT buffer for sender IP address in NBO
 *          OUT buffer for sender port number in NBO
 *
 * RETURNS: new socket ID or invalid handle
 *
 * NOTES:
 *
 *====================================================================
 */

SYSocketHandle
syAcceptSocket(
    SYSocketHandle sock,
    NQ_IPADDRESS* ip,
    NQ_PORT* port
    )
{
    char buffer[MAX_SOCKADDR_SIZE];
    struct sockaddr *saddr = (struct sockaddr*)buffer;
    socklen_t size = sizeof(buffer);
    SYSocketHandle newSock = accept(sock, saddr, &size);

    parseSockaddr(saddr, ip, port);

    return newSock;
}
#ifdef CM_NQ_STORAGE
/*
 *====================================================================
 * PURPOSE: Insert GMT time to strTime as string in fmt format.
 *--------------------------------------------------------------------
 * PARAMS:  OUT time string buffer
 *             IN  buffer size
 *             IN  time
 *             IN  string format
 *
 * RETURNS: TRUE on success ,FALSE on error
 *
 * NOTES:
 *====================================================================
 */
NQ_BOOL
syGmtToString(NQ_BYTE * strTime, NQ_COUNT size, NQ_UINT32 t, const NQ_CHAR * fmt)
{
    struct tm *tmp;
    char outstr[size];
    NQ_BOOL result = FALSE;
    time_t tt = (time_t)t;

    tmp = gmtime(&tt);
    if (NULL == tmp)
    {
        syfPrintf((stderr, "[%s:%d][%s()] %d %s\n", __FILE__, __LINE__, __func__, errno, strerror(errno)));
        goto Exit;
    }

    if(0 == strftime(outstr, sizeof(outstr), fmt, tmp))
    {
        syfPrintf((stderr, "[%s:%d][%s()] %d %s\n", __FILE__, __LINE__, __func__, errno, strerror(errno)));
        goto Exit;
    }
    syMemcpy(strTime, outstr, size);

    result = TRUE;

Exit:
    return result;
}
#endif
/*
 *====================================================================
 * PURPOSE: Open directory by name
 *--------------------------------------------------------------------
 * PARAMS:  IN directory name
 *
 * RETURNS: Directory handle or invalide handle
 *
 * NOTES:
 *
 *====================================================================
 */

SYDirectory
syOpenDirectory(
    const NQ_WCHAR* dirName
    )
{
    const NQ_WCHAR root[] = {cmWChar('/'), cmWChar('\0')};

    if (*dirName == cmWChar(0))
        dirName = root;
        
#ifdef UNICODEFILENAMES
    filenameToUtf8(dirName);
    return opendir(staticData->utf8Name);
#else
    syUnicodeToAnsi(staticData->asciiName, dirName);
    cmAnsiToFs(staticData->asciiName, sizeof(staticData->asciiName));
    return opendir(staticData->asciiName);
#endif /* UNICODEFILENAMES */
}

/*
 *====================================================================
 * PURPOSE: Open directory and read the first entry
 *--------------------------------------------------------------------
 * PARAMS:  IN directory name
 *          OUT buffer for directory handle
 *          OUT buffer for a pointer to the first file name
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:
 *
 *====================================================================
 */

NQ_STATUS
syFirstDirectoryFile(
    const NQ_WCHAR* dirName,
    SYDirectory* pDir,
    const NQ_WCHAR** fileName
    )
{
    const NQ_WCHAR root[] = {cmWChar('/'), cmWChar('\0')};

    if (*dirName == cmWChar(0))
        dirName = root;

 #ifdef UNICODEFILENAMES
    filenameToUtf8(dirName);
    *pDir = opendir(staticData->utf8Name);
#else
    syUnicodeToAnsi(staticData->asciiName, dirName);
    cmAnsiToFs(staticData->asciiName, sizeof(staticData->asciiName));
    *pDir = opendir(staticData->asciiName);
#endif /* UNICODEFILENAMES */

    return *pDir == NULL ? NQ_FAIL : syNextDirectoryFile(*pDir, fileName);
}

/*
 *====================================================================
 * PURPOSE: Read next directory entry
 *--------------------------------------------------------------------
 * PARAMS:  IN directory handle
 *          OUT buffer for a pointer to the next file name
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:
 *
 *====================================================================
 */

NQ_STATUS
syNextDirectoryFile(
    SYDirectory dir,
    const NQ_WCHAR** fileName
    )
{
    struct dirent* de;

    errno = OK;
    de = readdir(dir);
    if (de == NULL)
    {
        *fileName = NULL;
        return (errno == OK)? NQ_SUCCESS: NQ_FAIL;
    }
    else
    {
        static NQ_WCHAR tcharName[CM_BUFFERLENGTH(NQ_WCHAR, UD_FS_FILENAMELEN)];

#ifdef UNICODEFILENAMES
        strcpy(staticData->utf8Name, de->d_name);
        filenameFromUtf8(tcharName, sizeof(tcharName));
#else
        strcpy(staticData->asciiName, de->d_name);
        cmFsToAnsi(staticData->asciiName, sizeof(staticData->asciiName));
        syAnsiToUnicode(tcharName, staticData->asciiName);
#endif /* UNICODEFILENAMES */
        *fileName = tcharName;
        return NQ_SUCCESS;
    }
}

/*
 *====================================================================
 * PURPOSE: Open file for read
 *--------------------------------------------------------------------
 * PARAMS:  IN file name
 *          IN TRUE to deny further openings for read
 *          IN TRUE to deny further openings for execute
 *          IN TRUE to deny further openings for write
 *
 * RETURNS: file handle or invalid handle
 *
 * NOTES:
 *
 *====================================================================
 */

SYFile
syOpenFileForRead(
    const NQ_WCHAR* name,
    NQ_BOOL denyread,
    NQ_BOOL denyexecute,
    NQ_BOOL denywrite
    )
{
#ifdef UNICODEFILENAMES
    filenameToUtf8(name);
    return open(staticData->utf8Name, OPEN_RDONLY);
#else
    syUnicodeToAnsi(staticData->asciiName, name);
    cmAnsiToFs(staticData->asciiName, sizeof(staticData->asciiName));
    return open(staticData->asciiName, OPEN_RDONLY);
#endif /* UNICODEFILENAMES */
}

/*
 *====================================================================
 * PURPOSE: Open file for write
 *--------------------------------------------------------------------
 * PARAMS:  IN file name
 *          IN TRUE to deny further openings for read
 *          IN TRUE to deny further openings for execute
 *          IN TRUE to deny further openings for write
 *
 * RETURNS: file handle or invalid handle
 *
 * NOTES:
 *
 *====================================================================
 */

SYFile
syOpenFileForWrite(
    const NQ_WCHAR* name,
    NQ_BOOL denyread,
    NQ_BOOL denyexecute,
    NQ_BOOL denywrite
    )
{
#ifdef UNICODEFILENAMES
    filenameToUtf8(name);
    return open(staticData->utf8Name, OPEN_WRONLY);
#else
    syUnicodeToAnsi(staticData->asciiName, name);
    cmAnsiToFs(staticData->asciiName, sizeof(staticData->asciiName));
    return open(staticData->asciiName, OPEN_WRONLY);
#endif /* UNICODEFILENAMES */
}

/*
 *====================================================================
 * PURPOSE: Open file for read and write
 *--------------------------------------------------------------------
 * PARAMS:  IN file name
 *          IN TRUE to deny further openings for read
 *          IN TRUE to deny further openings for execute
 *          IN TRUE to deny further openings for write
 *
 * RETURNS: file handle or invalid handle
 *
 * NOTES:
 *
 *====================================================================
 */

SYFile
syOpenFileForReadWrite(
    const NQ_WCHAR* name,
    NQ_BOOL denyread,
    NQ_BOOL denyexecute,
    NQ_BOOL denywrite
    )
{
#ifdef UNICODEFILENAMES
    filenameToUtf8(name);
    return open(staticData->utf8Name, OPEN_RDWR);
#else
    syUnicodeToAnsi(staticData->asciiName, name);
    cmAnsiToFs(staticData->asciiName, sizeof(staticData->asciiName));
    return open(staticData->asciiName, OPEN_RDWR);
#endif /* UNICODEFILENAMES */
}

/*
 *====================================================================
 * PURPOSE: Delete directory
 *--------------------------------------------------------------------
 * PARAMS:  IN directory name
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:
 *
 *====================================================================
 */

NQ_STATUS
syDeleteDirectory(
    const NQ_WCHAR* name
    )
{
#ifdef UNICODEFILENAMES
    filenameToUtf8(name);
    return rmdir(staticData->utf8Name) == OK? NQ_SUCCESS : NQ_FAIL;
#else
    syUnicodeToAnsi(staticData->asciiName, name);
    cmAnsiToFs(staticData->asciiName, sizeof(staticData->asciiName));
    return rmdir(staticData->asciiName) == OK ? NQ_SUCCESS : NQ_FAIL;
#endif /* UNICODEFILENAMES */
}

/*
 *====================================================================
 * PURPOSE: Create new directory
 *--------------------------------------------------------------------
 * PARAMS:  IN directory name
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:
 *
 *====================================================================
 */

NQ_STATUS
syCreateDirectory(
    const NQ_WCHAR* name
    )
{
#ifdef UNICODEFILENAMES
    filenameToUtf8(name);
    return mkdir(staticData->utf8Name, 0766) == OK ? NQ_SUCCESS : NQ_FAIL;
#else
    syUnicodeToAnsi(staticData->asciiName, name);
    cmAnsiToFs(staticData->asciiName, sizeof(staticData->asciiName));
    return mkdir(staticData->asciiName, 0766) == OK ? NQ_SUCCESS : NQ_FAIL;
#endif /* UNICODEFILENAMES */
}

/*
 *====================================================================
 * PURPOSE: Rename a file
 *--------------------------------------------------------------------
 * PARAMS:  IN file name
 *          IN new file name
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:
 *
 *====================================================================
 */

NQ_STATUS
syRenameFile(
    const NQ_WCHAR* oldName,
    const NQ_WCHAR* newName
    )
{
#ifdef UNICODEFILENAMES
    filenameToUtf8(newName);
    strcpy(staticData->newName, staticData->utf8Name);
    filenameToUtf8(oldName);
    return rename(staticData->utf8Name, staticData->newName) == OK ? NQ_SUCCESS : NQ_FAIL;
#else
    syUnicodeToAnsi(staticData->asciiName, oldName);
    cmAnsiToFs(staticData->asciiName, sizeof(staticData->asciiName));
    syUnicodeToAnsi(staticData->newName, newName);
    cmAnsiToFs(staticData->newName, sizeof(staticData->newName));
    return rename(staticData->asciiName, staticData->newName) == OK ? NQ_SUCCESS : NQ_FAIL;
#endif /* UNICODEFILENAMES */
}

/*
 *====================================================================
 * PURPOSE: Create and open new file
 *--------------------------------------------------------------------
 * PARAMS:  IN file name
 *          IN TRUE to deny further openings for read
 *          IN TRUE to deny further openings for execute
 *          IN TRUE to deny further openings for write
 *
 * RETURNS: file handle or invalid handle
 *
 * NOTES:
 *
 *====================================================================
 */

SYFile
syCreateFile(
    const NQ_WCHAR* name,
    NQ_BOOL denyread,
    NQ_BOOL denyexecute,
    NQ_BOOL denywrite
    )
{
    if (!checkFileName(name))
    {
        errno = ENAMETOOLONG;
        return ERROR;
    }
#ifdef UNICODEFILENAMES
    filenameToUtf8(name);
    return open(staticData->utf8Name, OPEN_RDWR_CREAT, 0700);
#else
    syUnicodeToAnsi(staticData->asciiName, name);
    cmAnsiToFs(staticData->asciiName, sizeof(staticData->asciiName));
    return open(staticData->asciiName, OPEN_RDWR_CREAT, 0700);
#endif /* UNICODEFILENAMES */
}

/*
 *====================================================================
 * PURPOSE: Read bytes from file
 *--------------------------------------------------------------------
 * PARAMS:  IN file handle
 *          OUT buffer for data
 *          IN number of bytes to read
 *
 * RETURNS: number of bytes read, zero on end of file, NQ_FAIL on error
 *
 * NOTES:
 *
 *====================================================================
 */

NQ_INT
syReadFile(
    SYFile file,
    NQ_BYTE* buf,
    NQ_COUNT len
    )
{
    int res = (int)read(file, (char*)buf, len);
    return (res == ERROR)? NQ_FAIL : res;
}

/*
 *====================================================================
 * PURPOSE: Write bytes into file
 *--------------------------------------------------------------------
 * PARAMS:  IN file handle
 *          IN data to write
 *          IN number of bytes to write
 *
 * RETURNS: number of bytes written, NQ_FAIL on error
 *
 * NOTES:
 *
 *====================================================================
 */

NQ_INT
syWriteFile(
    SYFile file,
    const NQ_BYTE* buf,
    NQ_COUNT len
    )
{
    int res = (int)write(file, (char*)buf, len);
    return (res == ERROR)? NQ_FAIL : res;
}

#if (0) /* for Linux versions where ftruncate() doesn't support extending file */
/*
 *====================================================================
 * PURPOSE: Extend file
 *--------------------------------------------------------------------
 * PARAMS:  IN file id
 *          IN number of bytes to add
 *          IN file length before
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:   write zeros and position the file at the end
 *
 *====================================================================
 */

static int
extendFile(
    int file,
    int off,
    int fSize
)
{
    off_t status;          /* operation result */
    long int fillAmount;    /* number of bytes to add at once */

    /* seek to the end of the file first */

    errno = 0;
    status = lseek(file, fSize, SEEK_SET);
    if (status != fSize)
        return NQ_FAIL;

    /* fill file with zeroes to bring length up to 'offset' */

    while (off > 0)
    {
        if (off > (int)sizeof(zeroArray))
            fillAmount = sizeof(zeroArray);
        else
            fillAmount = off;

        errno = 0;
        status = write(file, (char*)zeroArray, fillAmount);
        if (status != fillAmount)
            return NQ_FAIL;

        off -= fillAmount;
    }
    
    return NQ_SUCCESS;
}
#endif
/*
 *====================================================================
 * PURPOSE: Position file relatively from the current position
 *--------------------------------------------------------------------
 * PARAMS:  IN file handle
 *          IN low 32 bits of the offset
 *          IN high 32 bits of the offset
 *
 * RETURNS: new file position or NQ_FAIL
 *
 * NOTES:
 *====================================================================
 */

NQ_UINT32
sySeekFileCurrent(
    SYFile file,
    NQ_INT32 off,
    NQ_INT32 offHigh
    )
{
#ifdef LONG_FILES_SUPPORT
    loff_t pos = (loff_t)off + ((loff_t)offHigh * ((loff_t)1 << 32));
    pos = lseek64(file, (loff_t)pos, SEEK_CUR);
#else
    off_t pos;
    pos = lseek(file, (off_t)off, SEEK_CUR);
#endif
    return (pos == ERROR) ? (NQ_UINT32)NQ_FAIL : (NQ_UINT32)pos;
}

/*
 *====================================================================
 * PURPOSE: Position file from the beginning
 *--------------------------------------------------------------------
 * PARAMS:  IN file handle
 *          IN low 32 bits of the offset
 *          IN high 32 bits of the offset
 *
 * RETURNS: new file position or NQ_FAIL
 *
 * NOTES:
 *====================================================================
 */

NQ_UINT32
sySeekFileStart(
    SYFile file,
    NQ_UINT32 off,
    NQ_UINT32 offHigh
    )
{
#ifdef LONG_FILES_SUPPORT
    loff_t pos = (loff_t)off + ((loff_t)offHigh * ((loff_t)1 << 32));
    pos = lseek64(file, (loff_t)pos, SEEK_SET);
#else
    off_t pos;
    pos = lseek(file, (off_t)off, SEEK_SET);
#endif
    return (pos == ERROR) ? (NQ_UINT32)NQ_FAIL : (NQ_UINT32)pos;
}

/*
 *====================================================================
 * PURPOSE: Position file from the end
 *--------------------------------------------------------------------
 * PARAMS:  IN file handle
 *          IN low 32 bits of the offset
 *          IN high 32 bits of the offset
 *
 * RETURNS: new file position or NQ_FAIL
 *
 * NOTES:
 *====================================================================
 */

NQ_UINT32
sySeekFileEnd(
    SYFile file,
    NQ_INT32 off,
    NQ_INT32 offHigh
    )
{
    struct stat s;

    if (fstat(file, &s) != 0)
        return (NQ_UINT32)NQ_FAIL;

#ifdef LONG_FILES_SUPPORT
    {
        /* avoid negative resulting file offset */
    	loff_t pos;

    	pos = s.st_size + (loff_t)off + ((loff_t)offHigh * ((loff_t)1 << 32));
		if (pos < 0)
			pos = 0;

		pos = lseek64(file, (loff_t)pos, SEEK_SET);
		return (pos == ERROR) ? (NQ_UINT32)NQ_FAIL : (NQ_UINT32)pos;
    }
#else
    /* avoid negative resulting file offset */
    off += (NQ_INT32)s.st_size;
    if (off < 0)
        off = 0;
    {
		off_t pos;
		pos = lseek(file, (off_t)off, SEEK_SET);
		return (pos == ERROR) ? (NQ_UINT32)NQ_FAIL : (NQ_UINT32)pos;
    }
#endif
}

/*====================================================================
 * PURPOSE: Truncate file
 *--------------------------------------------------------------------
 * PARAMS:  IN file handle 
 *          IN low 32 bits of the offset
 *          IN high 32 bits of the offset
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:
 *====================================================================
 */  

NQ_STATUS 
syTruncateFile(
    SYFile file,
    NQ_UINT32 offLow,
    NQ_UINT32 offHigh 
    )
{
    struct stat fileStat;
#ifdef LONG_FILES_SUPPORT
    loff_t len = (loff_t)offLow + ((loff_t)offHigh * ((loff_t)1 << 32));
#endif
    
    if (fstat(file, &fileStat) == ERROR)
        return NQ_FAIL;

#ifdef LONG_FILES_SUPPORT
    if (ftruncate(file, (loff_t)len) == ERROR)
#else
    if (ftruncate(file, (off_t)offLow) == ERROR)
#endif
    {

        if (errno == EIO)
            return NQ_FAIL;
         
        /*  if ftruncate() doesn't support extending file, 
            file can be extended by writing zeros */
#if (0)
        extendFile(file, offLow - fileStat.st_size, fileStat.st_size);
#endif
    }
    return NQ_SUCCESS;
}


/*
 *====================================================================
 * PURPOSE: find host IP by its name
 *--------------------------------------------------------------------
 * PARAMS:  IN host name
 *
 * RETURNS: host IP
 *
 * NOTES:   this function is used by client when UD_NB_INCLUDENAMESERVICE
 *          is not defined. This implementation uses DNS which is a temporary solution
 *          for vxWorks
 *====================================================================
 */

NQ_IPADDRESS4
syGetHostByName(
    const char* name
    )
{
    struct hostent* h = gethostbyname(name);
    return h != NULL ? ((struct sockaddr_in*)h->h_addr)->sin_addr.s_addr : 0;
}

#if defined(UD_NQ_USETRANSPORTIPV4) || defined(UD_NQ_USETRANSPORTIPV6)
/*
 *====================================================================
 * PURPOSE: get DNS initialization parameters
 *--------------------------------------------------------------------
 * PARAMS:  OUT buffer for the default domain target belongs to
 *          OUT The DNS server address: IPv4 or IPv6
 *
 * RETURNS: None
 *
 * NOTES:
 *====================================================================
 */

void
syGetDnsParams(
    NQ_CHAR *domain,           /* The default domain target belongs to */
    NQ_IPADDRESS *server       /* The DNS server IP address */
    )
{
    NQ_WCHAR DomainW[CM_NQ_HOSTNAMESIZE];
    NQ_WCHAR ServerW[CM_IPADDR_MAXLEN];
    NQ_CHAR  aServer[CM_IPADDR_MAXLEN];

    udGetDnsParams(DomainW, ServerW);
    syUnicodeToAnsi(domain, DomainW);
    syUnicodeToAnsi(aServer, ServerW);
    cmAsciiToIp(aServer, server);
}
#endif /* defined(UD_NQ_USETRANSPORTIPV4) || defined(UD_NQ_USETRANSPORTIPV6) */

/*
 *====================================================================
 * PURPOSE: copy system file information into system-independent structure
 *--------------------------------------------------------------------
 * PARAMS:  IN system structure
 *          OUT independent structure
 *
 * RETURNS: NONE
 *
 * NOTES:
 *
 *====================================================================
 */

static void
statToFileInformation(
    const struct stat* from,
    SYFileInformation* to
    )
{
	NQ_TIME mTime = syConvertTimeSpecToTimeInMsec((void *)&from->st_mtime);
	NQ_TIME aTime = syConvertTimeSpecToTimeInMsec((void *)&from->st_atime);
	NQ_TIME cTime = syConvertTimeSpecToTimeInMsec((void *)&from->st_ctime);

    to->lastAccessTime = aTime;
    to->lastChangeTime = to->lastWriteTime = mTime;

    /* since POSIX does not support creation time, we set it to the least of the three file
       times */
    to->creationTime   = cTime;
    if (cmU64Cmp(&mTime, &to->creationTime) < 0)
        to->creationTime = mTime;
    if (cmU64Cmp(&aTime, &to->creationTime) < 0)
        to->creationTime = aTime;

    to->attributes = (NQ_UINT32)syUnixMode2DosAttr((int)from->st_mode);
    to->isDeleted = 0;
#ifdef LONG_FILES_SUPPORT
    to->fileIdHigh     = (NQ_UINT32)(from->st_ino >> 32);
    to->fileIdLow      = (NQ_UINT32)(from->st_ino & 0xFFFFFFFF);
#else
    to->fileIdHigh     = 0;
    to->fileIdLow      = (NQ_UINT32)from->st_ino;
#endif /* LONG_FILES_SUPPORT */

    if ((to->attributes & SY_ATTR_DIRECTORY) != 0)
    {
        to->sizeHigh       = 0;
        to->sizeLow        = 0;
        to->allocSizeHigh  = 0;
        to->allocSizeLow   = 0;
        to->numLinks       = 1;
    }
    else
    {
        to->numLinks       = 0;
#ifdef LONG_FILES_SUPPORT
        to->sizeHigh       = (NQ_UINT32)(from->st_size >> 32);
        to->sizeLow        = (NQ_UINT32)(from->st_size & 0xFFFFFFFF);
        to->allocSizeHigh  = (NQ_UINT32)((from->st_blocks * 512) >> 32);        /* standard block size for UNIX file system */
        to->allocSizeLow   = (NQ_UINT32)((from->st_blocks * 512) & 0xFFFFFFFF); /* standard block size for UNIX file system */
#else
        to->sizeHigh       = 0;
        to->sizeLow        = (NQ_UINT32)from->st_size;
        to->allocSizeHigh  = 0;
        to->allocSizeLow   = (NQ_UINT32)(from->st_blocks * 512); /* standard block size for UNIX file system */
#endif /* LONG_FILES_SUPPORT */
    }
}

/*
 *====================================================================
 * PURPOSE: Close file
 *--------------------------------------------------------------------
 * PARAMS:  IN file handle
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:
 *
 *====================================================================
 */
 
NQ_STATUS
syCloseFile(
    SYFile fd
    )
{
    return close(fd) != ERROR ? NQ_SUCCESS : NQ_FAIL;
}

/*
 *====================================================================
 * PURPOSE: Close directory
 *--------------------------------------------------------------------
 * PARAMS:  IN directory handle
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:
 *
 *====================================================================
 */
 
NQ_STATUS
syCloseDirectory(
    SYDirectory dir
    )
{
    return closedir(dir) != ERROR ? NQ_SUCCESS : NQ_FAIL;
}

/*
 *====================================================================
 * PURPOSE: Delete file
 *--------------------------------------------------------------------
 * PARAMS:  IN file name
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:
 *
 *====================================================================
 */

NQ_STATUS
syDeleteFile(
    const NQ_WCHAR* name
    )
{
#ifdef UNICODEFILENAMES
    filenameToUtf8(name);
    return unlink(staticData->utf8Name) == OK ? NQ_SUCCESS : NQ_FAIL;
#else
    syUnicodeToAnsi(staticData->asciiName, name);
    cmAnsiToFs(staticData->asciiName, sizeof(staticData->asciiName));
    return unlink(staticData->asciiName) == OK ? NQ_SUCCESS : NQ_FAIL;
#endif /* UNICODEFILENAMES */
}

#ifdef UD_CS_INCLUDEDIRECTTRANSFER

/*
 *====================================================================
 * PURPOSE: Start fragmented packet
 *--------------------------------------------------------------------
 * PARAMS:  IN socket handle
 *
 * RETURNS: NQ_FAIL when this operation is not avaiiable 
 *           NQ_SUCCESS when operation succeeded 
 *
 * NOTES:   This function removes TCP_NODELAY on socket
 *
 *====================================================================
 */

NQ_STATUS              
syDtStartPacket(
    SYSocketHandle sock
    )
{
    int opt = 0;
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char*)&opt, sizeof(opt));

    return NQ_SUCCESS;
}

/*
 *====================================================================
 * PURPOSE: End fragmented packet
 *--------------------------------------------------------------------
 * PARAMS:  IN socket handle
 *
 * RETURNS: NQ_FAIL when this operation is not avaiiable 
 *           NQ_SUCCESS when operation succeeded 
 *
 * NOTES:   This function sets TCP_NODELAY on socket
 *
 *====================================================================
 */

void
syDtEndPacket(
    SYSocketHandle sock 
    )
{
    int opt = 1;
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char*)&opt, sizeof(opt));
}

/*
    DT setup:
    The following code is a sample implementation. Real implementation may vary from platform to
    platform. 
    For Z-copy we can use 1) sndfile() 2) revcfile() 3) splice() and 4) something proprietary
    Since recvfile() is not available in most linux platforms, this eample uses splice() and sendfile(). 
    Notice that some 2.6.x kernels (2.6.31 in particular) have a buggy splice() that hangs up on heavy load.
    Notice also that on most 2.6.x platforms sendfile() works for reads only. 
*/

#define USE_DT_READ         /* use DT for reads, otherwise - simulate */
/*#define USE_DT_WRITE*/    /* use DT for writes, otherwise - simulate */
#define SPLICE_AVAILABLE    /* splice() function is available on the target platform */
#define SENDFILE_AVAILABLE  /* sendfile() function is available on the target platform */

/* 
++
    Fedora does not properly export "splice" 
    remove this on a clean platform 
*/
#define SPLICE_F_MOVE        1       /* Move pages instead of copying.  */
#define SPLICE_F_NONBLOCK    2       /* Don't block on the pipe splicing */
#define SPLICE_F_MORE        4       /* Expect more data.  */
#define SPLICE_F_GIFT        8       /* Pages passed in are a gift.  */
/*long splice(int fd_in, loff_t *off_in, int fd_out, loff_t *off_out, size_t len, unsigned int flags);*/
/*
--
*/

#if defined(USE_DT_WRITE) && defined(SPLICE_AVAILABLE)

static size_t nqSplice(int from, int to, size_t len)
{
    size_t bytes, sent, in_pipe;
    size_t total_sent = 0;

    while (total_sent < len) 
    {
/*printf("nqSplice: total=%d len=%d\n", total_sent, len);*/
        if ((sent = splice(from, NULL, staticData->pipe[1], NULL, (len - total_sent) < 16384? len - total_sent: 16384, SPLICE_F_MORE | SPLICE_F_MOVE)) <= 0) 
        {
/*printf("nqSplice: error=%d\n", errno);*/
            if (errno == EINTR || errno == EAGAIN) 
            {
                continue;
            }
            return NQ_FAIL;
        }
/*printf("nqSplice: sent=%d\n", sent);*/
        in_pipe = sent;
        while (in_pipe > 0) 
        {
            if ((bytes = splice(staticData->pipe[0], NULL, to, NULL, in_pipe, SPLICE_F_MORE | SPLICE_F_MOVE)) <= 0) 
            {
/*printf("nqSplice: error=%d\n", errno);*/
                if (errno == EINTR || errno == EAGAIN) 
                {
                    continue;
                }
                return -1;
            }
            in_pipe -= bytes;
/*printf("nqSplice: bytes=%d\n", bytes);*/
        }
        total_sent += sent;
    }
    return total_sent;
}

#endif /* defined(USE_DT_WRITE) && defined(SPLICE_AVAILABLE) */

#ifdef SENDFILE_AVAILABLE

static size_t nqSendFile(int from, int to, size_t len)
{
    return (size_t)sendfile(to, from, NULL, len);
}

#endif /* SENDFILE_AVAILABLE */

/*
 *====================================================================
 * PURPOSE: Transfer bytes from socket to file
 *--------------------------------------------------------------------
 * PARAMS:  IN socket handle
 *          IN file handle
 *          IN/OUT number of bytes to transfer/number of bytes transferred
 *
 * RETURNS: NQ_FAIL on error or NQ_SUCCESS when operation succeeded 
 *
 * NOTES:   Since VxWorks does not support direct transfer, this function 
 *          simulates direct transfer through a buffer
 *
 *====================================================================
 */

NQ_STATUS                     
syDtFromSocket(
    SYSocketHandle sock,
    SYFile file,    
    NQ_COUNT * len    
    )
{
#if defined(USE_DT_WRITE) && defined(SPLICE_AVAILABLE)
    *len = nqSplice(sock, file, *len);
    return ERROR == *len? NQ_FAIL : NQ_SUCCESS;
#else /* defined(USE_DT_WRITE) && defined(SPLICE_AVAILABLE) */
    static NQ_BYTE buf[65700];
    NQ_COUNT cnt1, cnt2, total = 0;
  
		while (*len > 0)
		{
            cnt1 = (NQ_COUNT)recv(sock, (char*)buf, *len, 0);
				if (cnt1==ERROR)
				  	return NQ_FAIL;
                cnt2 = (NQ_COUNT)write(file, (char*)buf, cnt1);
				if (cnt2 == ERROR || cnt2 != cnt1)
				  	return NQ_FAIL;
				*len -= cnt2;
				total += cnt2;
		}
		*len = total;
		return NQ_SUCCESS;
#endif /* defined(USE_DT_WRITE) && defined(SPLICE_AVAILABLE) */
}

/*
 *====================================================================
 * PURPOSE: Transfer bytes from file to socket
 *--------------------------------------------------------------------
 * PARAMS:  IN socket handle
 *          IN file handle
 *          IN/OUT number of bytes to transfer/number of bytes transferred
 *
 * RETURNS: NQ_FAIL on error or NQ_SUCCESS when operation succeeded 
 *
 * NOTES:   Since VxWorks does not support direct transfer, this function 
 *          simulates direct transfer through a buffer
 *
 *====================================================================
 */

NQ_STATUS              		/* NQ_FAIL on error or NQ_SUCCESS when operation succeeded */
syDtToSocket(
    SYSocketHandle sock,  /* socket handle */
    SYFile file,      		/* file handle */
    NQ_COUNT * len      	/* IN number of bytes to transfer, OUT bytes transferred */
    )
{
#if defined(USE_DT_READ) && defined(SENDFILE_AVAILABLE)
    *len = (NQ_COUNT)nqSendFile(file, sock, *len);
    return ERROR == *len? NQ_FAIL : NQ_SUCCESS;
#else /* defined(USE_DT_READ) && defined(SENDFILE_AVAILABLE) */
    static NQ_BYTE buf[65700];

    *len = read(file, (char*)buf, *len);
    if (*len==ERROR)
    	return NQ_FAIL;
    *len = send(sock, (char*)buf, *len, 0);
    return (*len == ERROR)? NQ_FAIL : NQ_SUCCESS;
#endif /* defined(USE_DT_READ) && defined(SENDFILE_AVAILABLE) */
}

#endif /* UD_CS_INCLUDEDIRECTTRANSFER */

#ifdef UD_CC_INCLUDELDAP

/* Convert Unicode UTF-16LE string to UTF8 */
void
syUnicodeToUTF8N(
    NQ_CHAR *u,  
    const NQ_WCHAR *w,  
    NQ_COUNT size 
    )
{
    iconv_t convertor;
    size_t inbytesleft = (syWStrlen(w) + 1) * sizeof(unsigned short);
    size_t outbytesleft = size;
    char *in = (char *)w;
    char *out = u;
    
    TRCB();

    if ((convertor = iconv_open("UTF-8", "UTF-16LE")) == (iconv_t)-1)
    {
        TRCERR("Unable to open converter (UTF-16LE to UTF-8)");
        TRCE();
        return;
    }
    TRC("opened converter");
    if (iconv(convertor, &in, &inbytesleft, &out, &outbytesleft) == (size_t)-1)
    {
        iconv_close(convertor);
        TRCERR("Unable to convert UTF-16LE to UTF-8");
        TRCE();
        return;
    }
    iconv_close(convertor);

    TRC("Remain unconverted %d symbols", outbytesleft);
    TRCE();
}

void
syUTF8ToUnicodeN(
    NQ_WCHAR *w, 
    const NQ_CHAR *u,
    NQ_COUNT size 
    )
{
    iconv_t convertor;
    size_t inbytesleft = strlen(u) + 1;
    size_t outbytesleft = size;
    char *in = (char *)u;
    char *out = (char*)w;

    TRCB();

    if ((convertor = iconv_open("UTF-16LE", "UTF-8")) == (iconv_t)-1)
    {
        TRCERR("Unable to open converter (UTF-8 to UTF-16LE)");
        TRCE();
        return;
    }

    if (iconv(convertor, &in, &inbytesleft, &out, &outbytesleft) == (size_t)-1)
    {
        iconv_close(convertor);
        TRCERR("Unable to convert UTF-8 to UTF-16LE");
        TRCE();
        return;
    }
    iconv_close(convertor);

    TRC("Remain unconverted %d symbols", outbytesleft);
    TRCE();
}
#endif /* UD_CC_INCLUDELDAP */

#ifdef MUTEX_DEBUG /* debug mutex issues. */
void
syMutexDelete(SYMutex* _m)
{
    int ret = pthread_mutex_destroy(_m);
    if( 0 != ret )
    {
    	LOGERR(CM_TRC_LEVEL_MESS_NORMAL,"Trying to delete a mutex that is taken: %d, ret: %d, err: %s", _m, ret, strerror(ret));
    }
}
void
syMutexTake(SYMutex* _m)
{
    pthread_mutex_lock(_m);

    LOGERR(CM_TRC_LEVEL_MESS_NORMAL,"Lock mutex: %p", _m);
}
void
syMutexGive(SYMutex* _m)
{
    pthread_mutex_unlock(_m);

    LOGERR(CM_TRC_LEVEL_MESS_NORMAL,"Unlock mutex: %p", _m);
}

#endif /* MUTEX_DEBUG */

void
syMutexCreate(SYMutex* _m)
{

    pthread_mutexattr_t attr; 

#ifdef MUTEX_DEBUG
    LOGERR(CM_TRC_LEVEL_MESS_NORMAL,"Create mutex: %p", _m);
#endif

    pthread_mutexattr_init(&attr); 
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE); 
    pthread_mutex_init(_m, &attr); 
    pthread_mutexattr_destroy(&attr);

}

NQ_STATUS sySendMulticast(
    SYSocketHandle socket, 
    const NQ_BYTE * buffer, 
    NQ_COUNT length, 
    const NQ_IPADDRESS *ip,
    NQ_PORT port)
{   
    NQ_STATUS res;          /* operation result */
    struct ip_mreq mreg;

    mreg.imr_multiaddr.s_addr = (in_addr_t)CM_IPADDR_GET4(*ip);
    mreg.imr_interface.s_addr = INADDR_ANY;
    setsockopt (socket, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreg, sizeof(mreg));
    res = sySendToSocket(socket, buffer, length, ip, port);
    setsockopt (socket, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mreg, sizeof(mreg));
    return res;
}

void sySubscribeToMulticast(SYSocketHandle socket,
		const NQ_IPADDRESS *ip
		)
{
	struct ip_mreq mreg;

	mreg.imr_multiaddr.s_addr = (in_addr_t)CM_IPADDR_GET4(*ip);
	mreg.imr_interface.s_addr = INADDR_ANY;
	setsockopt (socket, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreg, sizeof(mreg));
}

#ifdef SY_SEMAPHORE_AVAILABLE
NQ_INT
sySemaphoreTimedTake(SYSemaphore *sem , NQ_INT timeout)
{
	struct timespec semTimeout;

	semTimeout.tv_sec = (time_t)syGetTimeInSec();
	semTimeout.tv_sec += timeout;
	semTimeout.tv_nsec = 0;

	if (sem_timedwait( sem , &semTimeout))
	{
		NQ_INT semErr = errno;
		if (ETIMEDOUT != semErr)
		{
			LOGERR(CM_TRC_LEVEL_ERROR, "semaphore error: %d. %s", semErr, strerror(semErr));
		}
		return NQ_FAIL;
	}
	return NQ_SUCCESS;
}
#endif /* SY_SEMAPHORE_AVAILABLE */


void syThreadStart(SYThread *taskIdPtr, void (*startpoint)(void), NQ_BOOL background)
{
	pthread_attr_t attr;

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	pthread_create(taskIdPtr, &attr, (void * (*)(void *))startpoint, NULL);
	pthread_attr_destroy(&attr);
}

#ifdef UD_NQ_CODEPAGEUTF8
	
void initCodePageUTF8()
{
	utf16LE_to_Utf8 = iconv_open("UTF-8", "UTF-16LE");
	utf8_to_Utf16LE = iconv_open("UTF-16LE", "UTF-8");
}

NQ_UINT32 convertCodePageUTF8toUtf16LE(NQ_CHAR **inBuf, NQ_UINT32 *inBytesLeft, NQ_CHAR **outBuf, NQ_UINT32 *outBytesLeft)
{
	NQ_UINT32 size;
	
	size = (NQ_UINT32)iconv(utf8_to_Utf16LE, inBuf, (size_t*)inBytesLeft, outBuf, (size_t*)outBytesLeft);
#ifdef SY_DEBUGMODE
	if (size == -1)
	{
		int errsv = errno;
		LOGERR(CM_TRC_LEVEL_ERROR, "failed conversion utf8_to_Utf16LE, error: %d %s\n", errsv, strerror(errsv));
	}	
#endif

	return size;
}
NQ_UINT32 convertCodePageUtf16LEtoUTF8(NQ_CHAR **inBuf, NQ_UINT32 *inBytesLeft, NQ_CHAR **outBuf, NQ_UINT32 *outBytesLeft)
{
	NQ_UINT32 size;
	
	size = (NQ_UINT32)iconv(utf16LE_to_Utf8, inBuf, (size_t*)inBytesLeft, outBuf, (size_t*)outBytesLeft);
#ifdef SY_DEBUGMODE
	if (size == -1)
	{
		int errsv = errno;
		LOGERR(CM_TRC_LEVEL_ERROR, "failed conversion utf16LE_to_Utf8, error: %d %s", errsv, strerror(errsv));
	}
#endif
	return size;
}
					
#endif /* UD_NQ_CODEPAGEUTF8 */



