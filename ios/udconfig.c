/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Configuration management
 *--------------------------------------------------------------------
 * MODULE        : UD - user defined
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 6-Jun-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : Felix Tener (December 2009)
 ********************************************************************/

#include "syinclud.h"
#include "udparams.h"
#include "sycompil.h"
#include "udapi.h"
#include "udconfig.h"
#include "udparser.h"
#include "cmapi.h"
#include "cmcrypt.h"
/*#include "nqapi.h"  */

/*
  This file contains a sample implementation of UD configuration functions.

  Configuration parameters reside in several files. Each file has a format described in
  "udparser.c"

  Functions in this file are not reenterant. This is appropriate since for each of them
  there is exactly one caller.

  The following configuration files are used:
    1) COMMON configuration file defines network parameters common for both server
       and client.

    2) CIFS Server configuration file defines shared directories on target (shares)

    3) CIFS Client configuration file defines mounted remote filesystems that CIFS
       client provides access to

    4) User (password) list for CIFS Client

 */

 /*
    NQ Parameters
    ----------------
  */

/* default values for NQ parameters */

#define NQ_CONFIGPATH           "./"
#define NQ_TASKPRIORITY         1
#define NQ_DOMAIN               "WORKGROUP" 
#define NQ_ISWORKGROUP          TRUE
#define NQ_SERVERCOMMENT        "NQ CIFS Server"   /* server comment is how the server is
                                                      litteraly described */
#define NQ_CCDRVNAME            "/net"
#define NQ_CCUSERNAME           "guest"
#define NQ_CCPASSWORD           ""


#ifndef NQ_DNSDOMAIN
  #define NQ_DNSDOMAIN NQ_DOMAIN
#endif
#ifndef NQ_DNSADDRESS         /* max number of DNS servers should not exceed UD_NQ_MAXDNSSERVERS */
  #define NQ_DNSADDRESS       ""

#endif

typedef struct
{
/* buffers in the user space. The deafult implementation uses static buffers. */
    unsigned char staticBuffers[5*UD_NS_BUFFERSIZE];
/* data for access to the configuration files. Some of them are read only once. */
    int fileNamesReady;      /* will be set to 1 when full passes will set for
                                       configuration files (only once) */
    int netBiosConfigFlag;   /* will be set to 1 after the NB config file will be read
                                       (only once) */
    int readingShares;       /* will be set to 1 while reading shares */
    int defaultShareReported;/* if the default share was already reported */
    int hiddenShareReported;     /* if the hidden share was already reported */
    int readingMounts;       /* will be set to 1 while reading mounts */
    const char* scopeIdPtr;     /* will be set after the scope id will be read
                                               from the NB configuration (only once) */
    int isSecretFileLoaded;      /* will be set to 1 after loading secret from file */
    int isSecretAvailable;       /* will be set to 1 if secret is available */
    char secret[16];             /* buffer for domain computer account secret */ 
    char scopeId[100];       /* buffer for scope id */
    ParseContext mountParser;/* parser for reading the mount table */
    ParseContext shareParser;/* parser for reading the share table */
/* storage for configuration parameters */
    char netbiosFile[250];   /* full path to netbios config file name */
    char cifsFile[250];      /* full path to CIFS config file name */
    char passwordFile[250];  /* full path to password file name */
    char shareSdFile[250];   /* full path to file for share SD */
    char tempFileName[250];  /* full path to a temporary file */
    char secretFile[250];        /* full path to a secret file */
#ifdef UD_NQ_INCLUDEEVENTLOG
    char logFile[250];       /* full path to file for event log */
#endif /* UD_NQ_INCLUDEEVENTLOG */
    char mountFile[250];     /* full path to client monut table file name */
    /* char userName[CM_USERNAMELENGTH]; */
    /* char password[65]; */
    char domainNameOfClient[CM_NQ_HOSTNAMESIZE];
    int  isWorkgroupName;        /* TRUE if the domain name is a workgroup */
    unsigned long winsAddress;   /* WINS IP address */
    FILE* logHandle;             /* event log file */
    int logHandleFlag;           /* open flag for event log file */
    char userName[CM_USERNAMELENGTH];     /* buffer for user's name - set in udSetCredentials*/
    char password[UD_NQ_MAXPWDLEN];       /* buffer for user's password - set in udSetCredentials*/
    char domainNameOfServer[CM_NQ_HOSTNAMESIZE];  /* buffer for domain name with which the client conects to the server */
}
StaticData;

#ifdef SY_FORCEALLOCATION
static StaticData* staticData = NULL;
#else  /* SY_FORCEALLOCATION */
static StaticData staticDataSrc;
static StaticData* staticData = &staticDataSrc;
#endif /* SY_FORCEALLOCATION */

/* Format of Share SD file:
 *      fix size records of
 *          - 256 bytes - share name padded by zeroes
 *          - 2 bytes ";;"
 *          - 600 bytes of SD padded by zeroes (2 bytes of ascii per 1byte of binary)
 *          - '\n\r'
 *      total: 860 bytes per record
 */

#define SD_SHARENAMELEN 256
#define SD_SDLEN 300
#define SD_RECLEN (SD_SHARENAMELEN + 2 + SD_SDLEN * 2 + 2)

/* parsing confurations and storing parameters */

static NQ_BOOL
parseNetBiosConfig(
    void
    );

static void
setFileNames(
    void
    );

static NQ_BOOL
convertHex2Ascii(
    char* text
    );

#ifdef UD_CS_INCLUDELOCALUSERMANAGEMENT
static void
convertPasswordToText(
    const NQ_BYTE* password,
    NQ_CHAR* buffer
    );
#endif /* UD_CS_INCLUDELOCALUSERMANAGEMENT */

#ifdef UD_NQ_INCLUDEEVENTLOG
static void
saveEvent(
    char* format,
    ...
    );
#endif /* UD_NQ_INCLUDEEVENTLOG */

#if 0

/*====================================================================
 * PURPOSE: set new client credentials
 *--------------------------------------------------------------------
 * PARAMS:  IN user name for client login
 *          IN password for client login
 *          IN domain name
 *
 * RETURNS: NONE
 *
 * NOTES:   Domain name is used only for
 *====================================================================
 */
void
udSetCredentials(
    const char* user,
    const char* pwd,
    const char* domain
    )
{
    strncpy(staticData->userName, user, sizeof(staticData->userName));
    strncpy(staticData->password, pwd, sizeof(staticData->password));
    strncpy(staticData->domainNameOfClient, domain, sizeof(staticData->domainNameOfClient));
}
#endif

/*
 *========================================================================
 * Note about domainName and domainNameOfClient.
 * There are 3 possible cases:
 * 1. domainName was never changed -> the domainNameOfClient is NQ_DOMAIN 
 * 2. domainName was changed, and domain was not received from the 
 *    command line -> domainNameOfClient and domainNameOfServer are the same.
 * 3. domain was received from command line -> domainNameOfClient and 
 *    domainNameOfServer could be different.
 *========================================================================
 */
void
udSetCredentials(
    const char* user,
    const char* pwd,
    const char* domain
    )
{
    if ( user == NULL && pwd == NULL && domain == NULL ){
        /* Printing brief help about the function */
        syPrintf ("/=========================================================================\n");
        syPrintf ("In order to use this function properly, the format should be as follows:\n\n");
        syPrintf ("udSetCredentials \"username\",\"password\", \"domain\"\n\n");
        syPrintf ("It is possible to omit the fields, then, the default hardcoded fields\nwill be used\n");
        syPrintf ("=========================================================================/\n\n/");
        return;
    }

    /* First one should check if the enterd pointers are not NULL */
    if ( user == NULL ){
        syPrintf ("You have entered wrong user name. Please try again...\n");
        return;
    }
    if ( pwd == NULL ){
        syPrintf ("You have entered wrong password. Please try again...\n");
        return;
    }
    if ( domain == NULL ){
        syPrintf ("Using predefined value (the domain of the client).\n");
        /* The default value of domainNameOfServer is the value in domainName */
        syStrncpy(staticData->domainNameOfClient,staticData->domainNameOfServer, sizeof(staticData->domainNameOfClient));
    } else {
    /* If we here the entered string for 'domain' is not NULL */
        syStrncpy(staticData->domainNameOfClient, domain, sizeof(staticData->domainNameOfClient));
        /* capitalize domain name */
        { 
            char *s = staticData->domainNameOfClient;

            while ((*s = syToupper(*s)) != 0)
                s++;
        }
    }
    /* If we here the entered strings for 'use' and 'pwd' are not NULL */
    syStrncpy(staticData->userName, user, sizeof(staticData->userName));
    syStrncpy(staticData->password, pwd, sizeof(staticData->password));

    #if SY_DEBUGMODE
    syPrintf ("udSetCredentials: the parameters that were set are:\n");
    syPrintf ("                  User name is: %s\n",staticData->userName );
/*  syPrintf ("                  Password is: %s\n",staticData->password );*/
    syPrintf ("                  Domain name of the client: %s\n",staticData->domainNameOfClient );
    syPrintf ("                  Domain name of the server is: %s\n",staticData->domainNameOfServer  );
    #endif 

}

/*====================================================================
 * PURPOSE: initialize the configuration
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: NQ_SUCCESS on success
 *          NQ_FAIL on error
 *
 * NOTES:   Inits this module
 *====================================================================
 */

NQ_STATUS
udDefInit(
    void
    )
{
    /* allocate memory */
#ifdef SY_FORCEALLOCATION
    staticData = (StaticData *)syCalloc(1, sizeof(StaticData));
    if (NULL == staticData)
    {
        TRCERR("Unable to allocate adapter table");
        TRCE();
        return NQ_FAIL;
    }
#endif /* SY_FORCEALLOCATION */

    staticData->fileNamesReady = 0;
    staticData->readingShares = 0;
    staticData->readingMounts = 0;
    staticData->scopeIdPtr = NULL;
    strcpy(staticData->userName, NQ_CCUSERNAME);
    strcpy(staticData->password, NQ_CCPASSWORD);
    strcpy(staticData->domainNameOfClient, NQ_DOMAIN);
    strcpy(staticData->domainNameOfServer, NQ_DOMAIN);
    staticData->isWorkgroupName = NQ_ISWORKGROUP;
    staticData->winsAddress = 0L;
    staticData->defaultShareReported = 0;
    staticData->netBiosConfigFlag = 0;
    staticData->logHandleFlag = 0;
    staticData->isSecretFileLoaded = 0;
    staticData->isSecretAvailable = 0;

    return NQ_SUCCESS;
}

/*
 *====================================================================
 * PURPOSE: stop the CIFS configuration
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: None
 *
 * NOTES:
 *====================================================================
 */

void
udDefStop(
    void
    )

{
    /* release memory */
#ifdef SY_FORCEALLOCATION
    if (NULL != staticData)
        syFree(staticData);
    staticData = NULL;
#endif /* SY_FORCEALLOCATION */
}

/*
 *====================================================================
 * PURPOSE: get scope id
 *--------------------------------------------------------------------
 * PARAMS:  OUT buffer for the result
 *
 * RETURNS: None
 *
 * NOTES:
 *====================================================================
 */

void
udDefGetScopeID(
    NQ_WCHAR* buffer
    )
{
    if (!staticData->netBiosConfigFlag)
        parseNetBiosConfig();
    if (staticData->scopeIdPtr != 0)
    {
        syAnsiToUnicode(buffer, staticData->scopeIdPtr);
    }
    else
    {
        syAnsiToUnicode(buffer, "");
    }
}

/*
 *====================================================================
 * PURPOSE: get WINS address
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: WINS address or 0
 *
 * NOTES:
 *====================================================================
 */

NQ_IPADDRESS4
udDefGetWins(
    void
    )
{

    if (!staticData->netBiosConfigFlag)
    {
        parseNetBiosConfig();
    }

    return (NQ_IPADDRESS4)staticData->winsAddress;
}

/*
 *====================================================================
 * PURPOSE: get domain name
 *--------------------------------------------------------------------
 * PARAMS:  OUT buffer for the result
 *
 * RETURNS: None
 *
 * NOTES:
 *====================================================================
 */
#if 0
void
udDefGetDomain(
    NQ_WCHAR *buffer,
    NQ_BOOL  *isWorkgroup
    )
{
    if (!staticData->netBiosConfigFlag)
    {
        parseNetBiosConfig();
    }

    syAnsiToUnicode(buffer, staticData->domainNameOfServer);
    *isWorkgroup = staticData->isWorkgroupName;
}
#endif

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
udDefGetDnsParams(
    NQ_WCHAR *domain,
    NQ_WCHAR *server
    )
{
    /*syAnsiToUnicode(domain, NQ_DNSDOMAIN);*/
    if (!staticData->netBiosConfigFlag)
    {
        parseNetBiosConfig();
    }
    syAnsiToUnicode(domain, staticData->domainNameOfServer);

    syAnsiToUnicode(server, NQ_DNSADDRESS);
}

#endif /* defined(UD_NQ_USETRANSPORTIPV4) || defined(UD_NQ_USETRANSPORTIPV6) */

/*
 *====================================================================
 * PURPOSE: get authentication parameters
 *--------------------------------------------------------------------
 * PARAMS:  IN: URI about to connect to
 *          OUT buffer for user name
 *          OUT buffer for password
 *          OUT buffer for domain name
 *
 * RETURNS: TRUE - success
 *          FALSE - fail
 *
 * NOTES:   Not implemented yet
 *====================================================================
 */

NQ_BOOL
udDefGetCredentials(
    const void* resource,
    NQ_WCHAR* userName,
    NQ_WCHAR* password,
    NQ_WCHAR* domain
    )
{
    syAnsiToUnicode(userName, staticData->userName);
    syAnsiToUnicode(password, staticData->password);
    syAnsiToUnicode(domain, staticData->domainNameOfClient);

    return TRUE;
}

/*
 *====================================================================
 * PURPOSE: get next share in the list of shares for CIFS Server
 *--------------------------------------------------------------------
 * PARAMS:  OUT buffer for share name
 *          OUT buffer for the map path
 *          OUT pointer to variable getting 0 for file system share and 1 for a print queue
 *          OUT buffer for the share description
 *
 * RETURNS: TRUE - next share read
 *          FALSE - no more shares
 *
 * NOTES:   Concenquently parses the CIFS configuration file for shares
 *          if there is no configuration file, this function returns on its first call:
 *          "Root", NQ_CONFIGPATH, "Default root (no configuration file provided)"
 *====================================================================
 */
#if 0
NQ_BOOL
udDefGetNextShare(
    NQ_WCHAR* name,
    NQ_WCHAR* map,
    NQ_BOOL* printQueue,
    NQ_WCHAR* description
    )
{
    NQ_STATIC char nameA[256];
    NQ_STATIC char mapA[256];
    NQ_STATIC char descriptionA[256];

    if (!staticData->readingShares)
    {
        staticData->readingShares = 1;      /* start reading shares */
        setFileNames();
        if (!parseInit(&staticData->shareParser, staticData->cifsFile)) /* start parsing */
        {
            parseStop(&staticData->shareParser);
            staticData->readingShares = 0;

            if (staticData->defaultShareReported)
            {
                return FALSE;      /* no share read */
            }
            else
            {
                staticData->defaultShareReported = 1;
                syAnsiToUnicode(name, "Root");
                syAnsiToUnicode(map, NQ_CONFIGPATH);
                syAnsiToUnicode(description, "Default root (no configuration file provided)");
                *printQueue = FALSE;
                return TRUE;
            }
        }
    }

    /* cycle by lines of the parameter file */

    while (1)
    {
        char ch;                        /* next character */

        if (parseAtFileEnd(&staticData->shareParser))    /* EOF */
        {
            if (!staticData->hiddenShareReported)
            {
                /*  return default hidden C$ share */
                syAnsiToUnicode(name, "C$");
                syAnsiToUnicode(map, NQ_CONFIGPATH);
                syAnsiToUnicode(description, "Default share");
                *printQueue = FALSE;
                staticData->hiddenShareReported = 1;
                return TRUE;
            }         
            staticData->readingShares = 0;
            return FALSE;                   /* no share read */
        }

        parseSkipSpaces(&staticData->shareParser);
        if (!parseAtLineEnd(&staticData->shareParser) && (ch = parseGet(&staticData->shareParser)) != '#')    /* comment  line? */
        {
            parseUnget(&staticData->shareParser, ch);
            parseSkipSpaces(&staticData->shareParser);
            parseValue(&staticData->shareParser, nameA, 100, ';');      /* share name */
            if (parseDelimiter(&staticData->shareParser, ';'))
            {
                parseValue(&staticData->shareParser, mapA, 256, ';');  /* share map */
                if (parseDelimiter(&staticData->shareParser, ';'))
                {
                    parseValue(&staticData->shareParser, descriptionA, 256, (char)0);  /* share description */
                    syAnsiToUnicode(name, nameA);
                    syAnsiToUnicode(map, mapA);
                    syAnsiToUnicode(description, descriptionA);
                    *printQueue = 0;
                    return TRUE;   /* a share read */
                }
            }
        }
        parseSkipLine(&staticData->shareParser);
    }
}

/*
 *====================================================================
 * PURPOSE: get next mount in the list of mounted filesystems for CIFS
 *          Client
 *--------------------------------------------------------------------
 * PARAMS:  OUT buffer for volume name
 *          OUT buffer for the map path
 *
 * RETURNS: TRUE - a mount read FALSE - no more mounts
 *
 * NOTES:   Concenquently parses the mount file
 *====================================================================
 */

NQ_BOOL
udDefGetNextMount(
    NQ_WCHAR* name,
    NQ_WCHAR* map
    )
{
    NQ_STATIC char nameA[256];
    NQ_STATIC char mapA[256];

    if (!staticData->readingMounts)
    {
        staticData->readingMounts = 1;      /* start reading shares */
        setFileNames();
        if (!parseInit(&staticData->mountParser, staticData->mountFile)) /* start parsing */
        {
            staticData->readingMounts = 0;
            return FALSE;      /* no mount read */
        }
    }

    /* cycle by lines of the parameter file */

    while (1)
    {
        char ch;                        /* next character */

        if (parseAtFileEnd(&staticData->mountParser))    /* EOF */
        {
            staticData->readingMounts = 0;
            return FALSE;                   /* no mount read */
        }

        parseSkipSpaces(&staticData->mountParser);
        if ((ch = parseGet(&staticData->mountParser)) != '#')    /* comment  line? */
        {
            parseUnget(&staticData->mountParser, ch);
            parseSkipSpaces(&staticData->mountParser);
            parseValue(&staticData->mountParser, nameA, 256, ';');      /* share name */
            if (parseDelimiter(&staticData->mountParser, ';'))
            {
                parseValue(&staticData->mountParser, mapA, 256, ';');   /* share path */
                parseSkipLine(&staticData->mountParser);
                syAnsiToUnicode(name, nameA);
                syAnsiToUnicode(map, mapA);
                return TRUE;
            }
        }
        parseSkipLine(&staticData->mountParser);
    }
}
#endif
/*
 *====================================================================
 * PURPOSE: get task priorities
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: task priority
 *
 * NOTES:
 *====================================================================
 */

NQ_INT
udDefGetTaskPriorities(
    void
    )
{
    return NQ_TASKPRIORITY;
}

/*
 *====================================================================
 * PURPOSE: get server comment string
 *--------------------------------------------------------------------
 * PARAMS:  OUT buffer for the result
 *
 * RETURNS: None
 *
 * NOTES:
 *
 *====================================================================
 */

void
udDefGetServerComment(
    NQ_WCHAR* buffer
    )
{
    syAnsiToUnicode(buffer, NQ_SERVERCOMMENT);
}

/*
 *====================================================================
 * PURPOSE: get next user name and password from the list of passwords
 *--------------------------------------------------------------------
 * PARAMS:  IN login name
 *          OUT buffer for password
 *          OUT TRUE if the password is hashed, FALSE - otherwise
 *          OUT user number while administrative users have numbers < 0
 *
 * RETURNS: NQ_CS_PWDFOUND - user found equivalent to 3 (deprecated)
 *          NQ_CS_PWDNOAUTH - authentication is not required
 *          NQ_CS_PWDNOUSER - no such user
 *          NQ_CS_PWDLMHASH - user found and password is LM hash (*pwdIsHashed value has to
 *              be TRUE in this case)
 *          NQ_CS_PWDANY - user found and password is either LM and NTLM hash or plain
 *              text depending on the *pwdIsHashed value
 *
 * NOTES:   Opens the file, parses it and stores parameter values if
 *          those parameters were found. User number is returned as ID from
 *             the pwd file
 *====================================================================
 */
#if 0
NQ_INT
udDefGetPassword(
    const NQ_WCHAR* userName,
    NQ_CHAR* password,
    NQ_BOOL* pwdIsHashed,
    NQ_UINT32* userNumber
    )
{
    ParseContext userParser;    /* parser for reading the password list */
    char name[50];              /* next user name */
    char userNameA[256];        /* user name in ASCII */
    NQ_UINT i;
    char userNumText[12];

    /* start parsing passwords */

    syUnicodeToAnsi(userNameA, userName);

    for (i = 0; i < strlen(userNameA); i++)
    {
        userNameA[i] = (char)tolower(((int)userNameA[i]));
    }

    if (syStrcmp(userNameA , "anonymous") == 0)
	{
		*userNumber = 666;
		return NQ_CS_PWDNOAUTH;
	}

    setFileNames();
    if (!parseInit(&userParser, staticData->passwordFile)) /* start parsing */
    {
        return NQ_CS_PWDNOAUTH;           /* proceed without authentication */
    }

    /* cycle by lines of the parameter file */

    while (1)
    {
        char ch;                        /* next character */

        if (parseAtFileEnd(&userParser))    /* EOF */
        {
            parseStop(&userParser);
            return NQ_CS_PWDNOUSER;                   /* user not found */
        }

        parseSkipSpaces(&userParser);
        if (parseAtLineEnd(&userParser))            /* empty line? */
        {
            parseSkipLine(&userParser);
            continue;
        }
        if ((ch = parseGet(&userParser)) == '#')    /* comment  line? */
        {
            parseSkipLine(&userParser);
            continue;
        }
        parseUnget(&userParser, ch);
        parseSkipSpaces(&userParser);
        parseName(&userParser, name, 50);      /* user name */
        for (i = 0; i < strlen(name); i++)
        {
            name[i] = (char)tolower(((int)name[i]));
        }
        if (parseDelimiter(&userParser, ':'))
        {
            parseValue(&userParser, password, 64, ':');  /* password */
        }
        if (parseDelimiter(&userParser, ':'))
        {
            parseValue(&userParser, userNumText, sizeof(userNumText) - 1, ':');  /* ID */
        }
        parseSkipLine(&userParser);

        if (strcmp(userNameA, name) == 0)
        {
            int pwdlen = (int)strlen(password);

            *userNumber = (NQ_UINT32)atol(userNumText);
            *pwdIsHashed = (pwdlen == 32 || pwdlen == 64);

            parseStop(&userParser);

            /* if the password is hashed convert it to a binary form */
            if (*pwdIsHashed)
            {
                if (!convertHex2Ascii(password))
                    return NQ_CS_PWDNOUSER;   /* report user not found  */

                /* password is LM and NTLM hash if its length equals to 64, otherwise consider it LM hash */
                return (pwdlen == 64)? NQ_CS_PWDANY : NQ_CS_PWDLMHASH;
            }

            return NQ_CS_PWDANY; /* the password is plain text */
        }
    }
}
#endif
#ifdef UD_NQ_INCLUDECODEPAGE

/*
 *====================================================================
 * PURPOSE: get default code page
 *--------------------------------------------------------------------
 * PARAMS:
 *
 * RETURNS: default code page
 *
 * NOTES:
 *====================================================================
 */

NQ_INT
udDefGetCodePage(
    void
    )
{
    return UD_NQ_CODEPAGE437;
}

#endif /* UD_NQ_INCLUDECODEPAGE */

/*
 *====================================================================
 * PURPOSE: allocate buffer in the user space
 *--------------------------------------------------------------------
 * PARAMS:  IN buffer index zero based
 *          IN total number of buffers
 *          IN buffer size in bytes
 *
 * RETURNS: pointer to the buffer
 *
 * NOTES:   Include any project-level processing here
 *====================================================================
 */

NQ_BYTE*
udDefAllocateBuffer(
    NQ_INT idx,
    NQ_COUNT numBufs,
    NQ_UINT bufferSize
    )
{
    return staticData->staticBuffers + (NQ_UINT)idx*(bufferSize);
}

/*
 *====================================================================
 * PURPOSE: Return CIFS driver name
 *--------------------------------------------------------------------
 * PARAMS:  OUT buffer for the result
 *
 * RETURNS: None
 *
 * NOTES:
 *====================================================================
 */

void
udDefGetDriverName(
    NQ_CHAR* buffer
    )
{
    strcpy(buffer, NQ_CCDRVNAME);
}

#if defined(UD_CS_INCLUDESECURITYDESCRIPTORS) || defined(UD_CC_INCLUDESECURITYDESCRIPTORS) || defined (UD_CC_INCLUDEDOMAINMEMBERSHIP) || defined(UD_CS_INCLUDEPASSTHROUGH)

/*
 *====================================================================
 * PURPOSE: get unique ID for the current machine
 *--------------------------------------------------------------------
 * PARAMS:  OUT buffer of 12 bytes length
 *
 * RETURNS: None
 *
 * NOTES:   The returned 12-byte value should be:
 *              - "statistically unique" for the given machine
 *              - persistently the same for each call
 *             Recommended methods are:
 *              - MAC address of the default adapter
 *              - product serial number when available
 *             This reference implementation returns the same number for
 *             each computer
 *====================================================================
 */

void
udDefGetComputerId(
    NQ_BYTE* buf
    )
{
    NQ_INT i;

    for (i = 0; i < 12 ; i++)
    {
        *buf++ = 0xA5;
    }
}

/*
 *====================================================================
 * PURPOSE: Get persistent security descriptor for share
 *--------------------------------------------------------------------
 * PARAMS:  IN share name
 *          OUT buffer for SD
 *          IN buffer length
 *
 * RETURNS: SD length or zero on error
 *
 * NOTES:
 *====================================================================
 */

NQ_COUNT
udDefLoadShareSecurityDescriptor(
    const NQ_WCHAR* shareName,
    NQ_BYTE* buffer,
    NQ_COUNT bufferLen
    )
{
#define isHex(_a)   isxdigit((int)_a)
#define ascToHex(_a) ((_a) > '9'? tolower((int)_a) - 'a' + 10 : (int)(_a) - '0')
    NQ_STATIC char nameA[256];
    int file;
    NQ_COUNT res = 0;

    syUnicodeToAnsi(nameA, shareName);

    file = open(staticData->shareSdFile, O_RDONLY, 0777); /* start parsing */
    if (ERROR == file)
        return 0;      /* no share read */

    /* cycle by lines of the SD file */

    while (1)
    {
        static char in[SD_RECLEN];                        /* next record */

        if (read(file, in, SD_RECLEN) != SD_RECLEN)
        {
            res = 0;
            break;
        }
        if (0 == strcmp(nameA, in))     /* share name match */
        {
            char* pc = in + SD_SHARENAMELEN + 2;

            while (0 != *pc)
            {
                int val;

                if (bufferLen <=0)
                {
                    printf("UDCONFIG - Buffer overflow while loading share SD\n");
                    res = 0;
                    break;
                }
                if (!isHex(*pc))
                {
                    printf("UDCONFIG - Non-hexadecimal character found in Share SD file: %s\n", pc);
                    res = 0;
                    break;
                }
                val = ascToHex(*pc);
                pc++;
                if (!isHex(*pc))
                {
                    printf("UDCONFIG - Non-hexadecimal character found in Share SD file: %s\n", pc);
                    res = 0;
                    break;
                }
                val = 16 * val + ascToHex(*pc);
                pc++;
                *buffer++ = (NQ_BYTE)val;
                res++;
                bufferLen--;
            }
            break;
        }
    }
    close(file);

    return res;
}

/*
 *====================================================================
 * PURPOSE: Save persistent security descriptor for share
 *--------------------------------------------------------------------
 * PARAMS:  IN share name
 *          IN pointer to SD
 *          IN SD length
 *
 * RETURNS: None
 *
 * NOTES:
 *====================================================================
 */

void
udDefSaveShareSecurityDescriptor(
    const NQ_WCHAR* shareName,
    const NQ_BYTE* sd,
    NQ_COUNT sdLen
    )
{
    NQ_STATIC char nameA[UD_FS_MAXSHARELEN];
    int file;
    int recNum;

    syUnicodeToAnsi(nameA, shareName);

    if (sdLen > SD_SDLEN)
        return;
    file = open(staticData->shareSdFile, O_CREAT , 0777); /* start parsing */
    if (file == ERROR)
        return;
    close(file);
    file = open(staticData->shareSdFile, O_RDWR , 0777); /* start parsing */
    if (file == ERROR)
        return;

    /* cycle by lines of the SD file */

    for (recNum = 0; ; recNum++)
    {
        NQ_STATIC char in[SD_RECLEN];                        /* next record */

        if (read(file, in, SD_RECLEN) != SD_RECLEN)
        {
            break;
        }
        if (0 == strcmp(nameA, in))     /* share name match */
        {
            int i;

            close (file);
            file = open(staticData->shareSdFile, O_RDWR , 0777); /* start parsing again */

            for (i = recNum; i > 0; i--)
                read(file, in, SD_RECLEN);

            break;
        }
    }

    /* update record (either old or new) */
    {
        NQ_STATIC char temp[SD_SDLEN * 2];
        NQ_STATIC char name[SD_SHARENAMELEN];
        char* pc = temp;

        memset(name, 0, sizeof(name));
        strncpy(name, nameA, sizeof(name));
        write(file, name, sizeof(name));
        write(file, ";;", 2);
        memset(temp, 0, sizeof(temp));
        while (sdLen > 0)
        {
            sprintf(pc, "%02x", *sd++);
            sdLen--;
            pc += 2;
        }
        write(file, temp, sizeof(temp));
        write(file, "\n\r", 2);
    }

    close(file);
}

#ifdef UD_CS_INCLUDELOCALUSERMANAGEMENT

/*
 *====================================================================
 * PURPOSE: get number of local users
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: Number of local users
 *
 * NOTES:
 *====================================================================
 */

NQ_COUNT
udDefGetUserCount(
    void
    )
{
    ParseContext userParser;    /* parser for reading the password list */
    NQ_COUNT count = 0;

    setFileNames();
    if (!parseInit(&userParser, staticData->passwordFile)) /* start parsing */
    {
        return 0;    /* no users */
    }

    /* cycle by lines of the parameter file */

    while (1)
    {
        char ch;                        /* next character */

        if (parseAtFileEnd(&userParser))    /* EOF */
        {
            parseStop(&userParser);
            return count;
        }

        parseSkipSpaces(&userParser);
        if (parseAtLineEnd(&userParser))            /* empty line? */
        {
            parseSkipLine(&userParser);
            continue;
        }
        if ((ch = parseGet(&userParser)) == '#')    /* comment  line? */
        {
            parseSkipLine(&userParser);
            continue;
        }
        parseUnget(&userParser, ch);
        parseSkipLine(&userParser);
        count++;
    }
}

/*
 *====================================================================
 * PURPOSE: get user ID by name
 *--------------------------------------------------------------------
 * PARAMS:  IN user name
 *          OUT buffer for user ID
 *
 * RETURNS: TRUE when user was found
 *
 * NOTES:
 *====================================================================
 */

NQ_BOOL
udDefGetUserRidByName(
    const NQ_WCHAR* name,
    NQ_UINT32* rid
    )
{
    ParseContext userParser;    /* parser for reading the password list */
    NQ_STATIC char nextName[50];       /* next user name */
    NQ_STATIC char userNameA[256];     /* user name in ASCII */
    NQ_STATIC char password[256];     /* password in ASCII */
    int i;
    char userNumText[12];

    /* start parsing passwords */

    syUnicodeToAnsi(userNameA, name);

    for (i = 0; i < strlen(userNameA); i++)
    {
        userNameA[i] = (char)tolower(((int)userNameA[i]));
    }

    setFileNames();
    if (!parseInit(&userParser, staticData->passwordFile)) /* start parsing */
    {
        return FALSE;           /* proceed without authentication */
    }

    /* cycle by lines of the parameter file */

    while (1)
    {
        char ch;                        /* next character */

        if (parseAtFileEnd(&userParser))    /* EOF */
        {
            parseStop(&userParser);
            return FALSE;                   /* user not found */
        }

        parseSkipSpaces(&userParser);
        if (parseAtLineEnd(&userParser))            /* empty line? */
        {
            parseSkipLine(&userParser);
            continue;
        }
        if ((ch = parseGet(&userParser)) == '#')    /* comment  line? */
        {
            parseSkipLine(&userParser);
            continue;
        }
        parseUnget(&userParser, ch);
        parseSkipSpaces(&userParser);
        parseName(&userParser, nextName, 50);      /* user name */
        for (i = 0; i < strlen(nextName); i++)
        {
            nextName[i] = (char)tolower(((int)nextName[i]));
        }
        if (parseDelimiter(&userParser, ':'))
        {
            parseValue(&userParser, password, 70, ':');  /* password */
        }
        if (parseDelimiter(&userParser, ':'))
        {
            parseValue(&userParser, userNumText, sizeof(userNumText) - 1, ':');  /* ID */
        }
        parseSkipLine(&userParser);

        if (strcmp(userNameA, nextName) == 0)
        {
            *rid = (NQ_UINT32)atol(userNumText);
            parseStop(&userParser);
            return TRUE; /* user found */
        }
    }
}

/*
 *====================================================================
 * PURPOSE: get user name by ID
 *--------------------------------------------------------------------
 * PARAMS:  IN user ID
 *          OUT buffer for user name
 *          OUT buffer for user name
 *
 * RETURNS: TRUE when user was found
 *
 * NOTES:
 *====================================================================
 */

NQ_BOOL
udDefGetUserNameByRid(
    NQ_UINT32 rid,
    NQ_WCHAR* nameBuffer,
    NQ_WCHAR* fullNameBuffer
    )
{
    ParseContext userParser;    /* parser for reading the password list */
    char name[50];              /* next user name */
    char userNumText[12];
    NQ_STATIC char password[256];     /* password in ASCII */

    setFileNames();
    if (!parseInit(&userParser, staticData->passwordFile)) /* start parsing */
    {
        return FALSE;           /* proceed without authentication */
    }

    /* cycle by lines of the parameter file */

    while (1)
    {
        char ch;                        /* next character */

        if (parseAtFileEnd(&userParser))    /* EOF */
        {
            parseStop(&userParser);
            return FALSE;                   /* user not found */
        }

        parseSkipSpaces(&userParser);
        if (parseAtLineEnd(&userParser))            /* empty line? */
        {
            parseSkipLine(&userParser);
            continue;
        }
        if ((ch = parseGet(&userParser)) == '#')    /* comment  line? */
        {
            parseSkipLine(&userParser);
            continue;
        }
        parseUnget(&userParser, ch);
        parseSkipSpaces(&userParser);
        parseName(&userParser, name, 50);      /* user name */
        if (parseDelimiter(&userParser, ':'))
        {
            parseValue(&userParser, password, 70, ':');  /* password */
        }
        if (parseDelimiter(&userParser, ':'))
        {
            parseValue(&userParser, userNumText, sizeof(userNumText) - 1, ':');  /* ID */
        }
        parseSkipLine(&userParser);

        if ((NQ_INT)rid == (NQ_INT)atol(userNumText))
        {
            syAnsiToUnicode(nameBuffer, name);
            syAnsiToUnicode(fullNameBuffer, name);
            parseStop(&userParser);
            return TRUE; /* user found */
        }
    }
}

/*
 *====================================================================
 * PURPOSE: enumerate users
 *--------------------------------------------------------------------
 * PARAMS:  IN user index (zero based)
 *          OUT buffer for user id
 *          OUT buffer for user name
 *          OUT buffer for user's full name
 *          OUT buffer for user description
 *
 * RETURNS: TRUE when user was found
 *
 * NOTES:
 *====================================================================
 */

NQ_BOOL
udDefGetUserInfo(
    NQ_UINT index,
    NQ_UINT32* rid,
    NQ_WCHAR* shortName,
    NQ_WCHAR* fullName,
    NQ_WCHAR* description
    )
{
    ParseContext userParser;    /* parser for reading the password list */
    char name[50];              /* next user name */
    char userNumText[12];
    NQ_STATIC char password[256];     /* password in ASCII */

    setFileNames();
    if (!parseInit(&userParser, staticData->passwordFile)) /* start parsing */
    {
        return FALSE;           /* proceed without authentication */
    }

    /* cycle by lines of the parameter file */

    while (1)
    {
        char ch;                        /* next character */

        if (parseAtFileEnd(&userParser))    /* EOF */
        {
            parseStop(&userParser);
            return FALSE;                   /* user not found */
        }

        parseSkipSpaces(&userParser);
        if (parseAtLineEnd(&userParser))            /* empty line? */
        {
            parseSkipLine(&userParser);
            continue;
        }
        if ((ch = parseGet(&userParser)) == '#')    /* comment  line? */
        {
            parseSkipLine(&userParser);
            continue;
        }
        parseUnget(&userParser, ch);
        parseSkipSpaces(&userParser);
        parseName(&userParser, name, 50);      /* user name */
        if (parseDelimiter(&userParser, ':'))
        {
            parseValue(&userParser, password, 70, ':');  /* password */
        }
        if (parseDelimiter(&userParser, ':'))
        {
            parseValue(&userParser, userNumText, sizeof(userNumText) - 1, ':');  /* ID */
        }
        parseSkipLine(&userParser);

        if (index-- <= 0)
        {
            *rid = (NQ_UINT32)atol(userNumText);
            syAnsiToUnicode(shortName, name);
            syAnsiToUnicode(fullName, name);
            syAnsiToUnicode(description, ((NQ_INT)*rid) < 0? "Administrator":"Ordinary user");
            parseStop(&userParser);
            return TRUE; /* user found */
        }
    }
}

/*
 *====================================================================
 * PURPOSE: modify user
 *--------------------------------------------------------------------
 * PARAMS:  IN user RID
 *          IN user name
 *          IN full user name
 *          IN user description
 *          IN Unicode text password or NULL
 *
 * RETURNS: TRUE when user was found
 *
 * NOTES:
 *====================================================================
 */

NQ_BOOL
udDefSetUserInfo
(
    NQ_UINT32 rid,
    const NQ_WCHAR* name,
    const NQ_WCHAR* fullName,
    const NQ_WCHAR* description,
    const NQ_WCHAR* password
    )
{
    ParseContext userParser;            /* parser for reading the password list */
    NQ_STATIC char nextName[50];        /* next user name */
    NQ_STATIC char userNameA[256];      /* user name in ASCII */
    char userNumText[12];               /* next RID */
    char matchUserNumText[12];          /* required user RID */
    NQ_STATIC char oldPassword[256];    /* password in ASCII hex pairs */
    NQ_STATIC char matchPassword[256];  /* required user password in ASCII */
    FILE* tempFile;                     /* temporary file fd */
    int oldUser = 0;                    /* user exists */
    NQ_INT nextRid;

    syUnicodeToAnsi(userNameA, name);

    /* create temporary file */
    tempFile = fopen((const char*)staticData->tempFileName, "a+");
    if (NULL == tempFile)
        return FALSE;

    /* parse existing file */
    setFileNames();
    if (parseInit(&userParser, staticData->passwordFile)) /* start parsing */
    {
        /* cycle by lines of the parameter file */
        while (1)
        {
            char ch;                        /* next character */

            if (parseAtFileEnd(&userParser))    /* EOF */
            {
                parseStop(&userParser);
                break;
            }

            parseSkipSpaces(&userParser);
            if (parseAtLineEnd(&userParser))            /* empty line? */
            {
                parseSkipLine(&userParser);
                continue;
            }
            if ((ch = parseGet(&userParser)) == '#')    /* comment  line? */
            {
                parseSkipLine(&userParser);
                continue;
            }
            parseUnget(&userParser, ch);
            parseSkipSpaces(&userParser);
            parseName(&userParser, nextName, 50);      /* user name */
            if (parseDelimiter(&userParser, ':'))
            {
                parseValue(&userParser, oldPassword, 70, ':');  /* password */
            }
            if (parseDelimiter(&userParser, ':'))
            {
                parseValue(&userParser, userNumText, sizeof(userNumText) - 1, ':');  /* ID */
            }
            parseSkipLine(&userParser);

            nextRid = (NQ_INT)atol(userNumText);

            if ((NQ_INT)rid == nextRid)
            {
                oldUser = 1;
                syStrcpy(matchPassword, oldPassword);
                syStrcpy(matchUserNumText, userNumText);
            }
            else
            {
                fprintf(tempFile, "%s:%s:%s\n", nextName, oldPassword, userNumText);
            }
            }
        }
    if (NULL != password)
    {
        NQ_STATIC NQ_BYTE encryptedPassword[32];
        NQ_STATIC NQ_BYTE asciiPassword[256];

        cmUnicodeToAnsi((NQ_CHAR *)asciiPassword, password);
        cmHashPassword(asciiPassword, encryptedPassword);    /* LM */
        cmMD4(
            encryptedPassword + 16,
            (NQ_BYTE*)password,
            (NQ_UINT)(cmWStrlen(password) * sizeof(NQ_WCHAR))
            );                                                 /* NTLM */
        convertPasswordToText(encryptedPassword, matchPassword);
    }
    matchPassword[64] = '\0';
    if (oldUser)
    {
         fprintf(tempFile, "%s:%s:%s\n", userNameA, matchPassword, matchUserNumText);
         fclose(tempFile);
        unlink(staticData->passwordFile);
         rename((const char*)staticData->tempFileName, staticData->passwordFile);
        return TRUE;
    }
    else
    {
         fclose(tempFile);
        unlink(staticData->tempFileName);
        return FALSE;
    }
}

/*
 *====================================================================
 * PURPOSE: add user
 *--------------------------------------------------------------------
 * PARAMS:  IN user name
 *          IN full user name
 *          IN user description
 *
 * RETURNS: TRUE when user was found
 *
 * NOTES:   This function either creates a new user or modifies an existing one.
 *====================================================================
 */

NQ_BOOL
udDefCreateUser(
    const NQ_WCHAR* name,
    const NQ_WCHAR* fullName,
    const NQ_WCHAR* description
    )
{
    ParseContext userParser;            /* parser for reading the password list */
    NQ_STATIC char nextName[50];        /* next user name */
    NQ_STATIC char userNameA[256];      /* user name in ASCII */
    NQ_STATIC char userNumText[12];     /* next RID */
    NQ_STATIC char password[256];       /* password in ASCII */
    FILE* tempFile;                     /* temporary file fd */
    long maxRid = 0;
    long nextRid;

    syUnicodeToAnsi(userNameA, name);

    /* create temporary file */
    tempFile = fopen((const char*)staticData->tempFileName, "a+");
    if (NULL == tempFile)
        return FALSE;

    /* parse existing file */
    setFileNames();
    if (parseInit(&userParser, staticData->passwordFile)) /* start parsing */
    {
        /* cycle by lines of the parameter file */
        while (1)
        {
            char ch;                        /* next character */

            if (parseAtFileEnd(&userParser))    /* EOF */
            {
                parseStop(&userParser);
                break;
            }

            parseSkipSpaces(&userParser);
            if (parseAtLineEnd(&userParser))            /* empty line? */
            {
                parseSkipLine(&userParser);
                continue;
            }
            if ((ch = parseGet(&userParser)) == '#')    /* comment  line? */
            {
                parseSkipLine(&userParser);
                continue;
            }
            parseUnget(&userParser, ch);
            parseSkipSpaces(&userParser);
            parseName(&userParser, nextName, 50);      /* user name */
            if (parseDelimiter(&userParser, ':'))
            {
                parseValue(&userParser, password, 70, ':');  /* password */
            }
            if (parseDelimiter(&userParser, ':'))
            {
                parseValue(&userParser, userNumText, sizeof(userNumText) - 1, ':');  /* ID */
            }
            parseSkipLine(&userParser);

            nextRid = atol(userNumText);
            if ((nextRid > 0 && nextRid > maxRid) || (nextRid < 0 && -nextRid > maxRid))
                maxRid = nextRid > 0? nextRid : -nextRid;

            if (0 == syStrcmp(userNameA, nextName))
            {
                 fclose(tempFile);
                unlink(staticData->tempFileName);
                return FALSE;
            }
            else
            {
                fprintf(tempFile, "%s:%s:%s\n", nextName, password, userNumText);
            }
        }
    }
     fprintf(tempFile, "%s:%s:%ld\n", userNameA, "", maxRid + 1);
     fclose(tempFile);
    unlink(staticData->passwordFile);
     rename((const char*)staticData->tempFileName, staticData->passwordFile);
    return TRUE;
}

/*
 *====================================================================
 * PURPOSE: set user administrative rights
 *--------------------------------------------------------------------
 * PARAMS:  IN user RID
 *          IN TRUE to make user an administrator
 *
 * RETURNS: TRUE when user was found
 *
 * NOTES:
 *====================================================================
 */

NQ_BOOL
udDefSetUserAsAdministrator(
    NQ_UINT32 rid,
    NQ_BOOL    isAdmin
    )
{
    ParseContext userParser;            /* parser for reading the password list */
    NQ_STATIC char nextName[50];        /* next user name */
    NQ_STATIC char matchName[50];       /* required user name */
    char userNumText[12];               /* next RID */
    char matchUserNumText[12];          /* required user RID */
    NQ_STATIC char password[256];       /* password in ASCII */
    NQ_STATIC char matchPassword[256];  /* required user password in ASCII */
    FILE* tempFile;                     /* temporary file fd */
    int oldUser = 0;                    /* user exists */
    NQ_INT nextRid;

    if (((int)rid < 0) && isAdmin) return TRUE;   /* nothing to do */
    if (((int)rid > 0) && !isAdmin) return TRUE;   /* nothing to do */

    /* create temporary file */
    tempFile = fopen((const char*)staticData->tempFileName, "a+");
    if (NULL == tempFile)
        return FALSE;

    /* parse existing file */
    setFileNames();
    if (parseInit(&userParser, staticData->passwordFile)) /* start parsing */
    {
        /* cycle by lines of the parameter file */
        while (1)
        {
            char ch;                        /* next character */

            if (parseAtFileEnd(&userParser))    /* EOF */
            {
                parseStop(&userParser);
                break;
            }

            parseSkipSpaces(&userParser);
            if (parseAtLineEnd(&userParser))            /* empty line? */
            {
                parseSkipLine(&userParser);
                continue;
            }
            if ((ch = parseGet(&userParser)) == '#')    /* comment  line? */
            {
                parseSkipLine(&userParser);
                continue;
            }
            parseUnget(&userParser, ch);
            parseSkipSpaces(&userParser);
            parseName(&userParser, nextName, 50);      /* user name */
            if (parseDelimiter(&userParser, ':'))
            {
                parseValue(&userParser, password, 70, ':');  /* password */
            }
            if (parseDelimiter(&userParser, ':'))
            {
                parseValue(&userParser, userNumText, sizeof(userNumText) - 1, ':');  /* ID */
            }
            parseSkipLine(&userParser);

            nextRid = (NQ_INT)atol(userNumText);

            if ((NQ_INT)rid == nextRid)
            {
                oldUser = 1;
                syStrcpy(matchName, nextName);
                syStrcpy(matchPassword, password);
                syStrcpy(matchUserNumText, userNumText);
            }
            else
            {
                fprintf(tempFile, "%s:%s:%s\n", nextName, password, userNumText);
            }
        }
    }
    if (!oldUser)
    {
         fclose(tempFile);
        unlink(staticData->tempFileName);
         return FALSE;
    }
    else
    {
        rid  = -rid;
         fprintf(tempFile, "%s:%s:%d\n", matchName, matchPassword, rid);
    }
     fclose(tempFile);
    unlink(staticData->passwordFile);
     rename((const char*)staticData->tempFileName, staticData->passwordFile);
    return TRUE;
}

/*
 *====================================================================
 * PURPOSE: remove user
 *--------------------------------------------------------------------
 * PARAMS:  IN user RID
 *
 * RETURNS: TRUE when user was deleted
 *
 * NOTES:
 *====================================================================
 */

NQ_BOOL
udDefDeleteUserByRid(
    NQ_UINT32 rid
    )
{
    ParseContext userParser;            /* parser for reading the password list */
    NQ_STATIC char nextName[50];        /* next user name */
    char userNumText[12];               /* next RID */
    NQ_STATIC char password[256];       /* password in ASCII */
    FILE* tempFile;                     /* temporary file fd */
    int userDeleted = 0;                /* user exists */
    NQ_INT nextRid;

    /* create temporary file */
    tempFile = fopen((const char*)staticData->tempFileName, "a+");
    if (NULL == tempFile)
        return FALSE;

    /* parse existing file */
    setFileNames();
    if (parseInit(&userParser, staticData->passwordFile)) /* start parsing */
    {
        /* cycle by lines of the parameter file */
        while (1)
        {
            char ch;                        /* next character */

            if (parseAtFileEnd(&userParser))    /* EOF */
            {
                parseStop(&userParser);
                break;
            }

            parseSkipSpaces(&userParser);
            if (parseAtLineEnd(&userParser))            /* empty line? */
            {
                parseSkipLine(&userParser);
                continue;
            }
            if ((ch = parseGet(&userParser)) == '#')    /* comment  line? */
            {
                parseSkipLine(&userParser);
                continue;
            }
            parseUnget(&userParser, ch);
            parseSkipSpaces(&userParser);
            parseName(&userParser, nextName, 50);      /* user name */
            if (parseDelimiter(&userParser, ':'))
            {
                parseValue(&userParser, password, 70, ':');  /* password */
            }
            if (parseDelimiter(&userParser, ':'))
            {
                parseValue(&userParser, userNumText, sizeof(userNumText) - 1, ':');  /* ID */
            }
            parseSkipLine(&userParser);

            nextRid = (NQ_INT)atol(userNumText);

            if ((NQ_INT)rid == nextRid)
            {
                userDeleted = 1;
            }
            else
            {
                fprintf(tempFile, "%s:%s:%s\n", nextName, password, userNumText);
            }
        }
    }
    fclose(tempFile);
    unlink(staticData->passwordFile);
    rename((const char*)staticData->tempFileName, staticData->passwordFile);
    return userDeleted? TRUE : FALSE;
}

#endif /* UD_CS_INCLUDELOCALUSERMANAGEMENT */

#endif /* defined(UD_CS_INCLUDESECURITYDESCRIPTORS) || defined(UD_CC_INCLUDESECURITYDESCRIPTORS) || defined (UD_CC_INCLUDEDOMAINMEMBERSHIP) || defined(UD_CS_INCLUDEPASSTHROUGH)*/

#ifdef UD_CS_INCLUDERPC_SRVSVC_EXTENSION

/*
 *====================================================================
 * PURPOSE: modify/create share information in a persistent store
 *--------------------------------------------------------------------
 * PARAMS:  IN share name to change or NULL for a new share
 *          IN share name
 *          IN share path
 *          IN share descriptor
 *
 * RETURNS: TRUE on success, FALSE on failure
 *
 * NOTES:   user-level should return TRUE in the following cases:
 *          1) new share was perisistently stored
 *          2) existing share was peristently modified
 *          3) new share was not persistently stored but it should
 *             be exposed until server shutdown
 *          4) share was not persistently modified but this modification
 *             should be exposed until server shutdown
 *          user-level should return FALSE when a new share should not \
 *          be created or an existing share should not be modified
 *
 *          This sample implementation always returns TRUE
 *====================================================================
 */

NQ_BOOL
udDefSaveShareInformation(
    const NQ_WCHAR* name,
    const NQ_WCHAR* newName,
    const NQ_WCHAR* newMap,
    const NQ_WCHAR* newDescription
    )
{
    NQ_STATIC char nameA[UD_FS_MAXSHARELEN];
    NQ_STATIC char newNameA[UD_FS_MAXSHARELEN];
    NQ_STATIC char mapA[UD_FS_MAXPATHLEN];
    NQ_STATIC char descriptionA[UD_FS_MAXDESCRIPTIONLEN];
    FILE* defFile;
    FILE* tempFile;
    NQ_STATIC char buffer[256];

    if (staticData->readingShares)
    {
        return FALSE;
    }

    unlink((const char*)staticData->tempFileName);
    if (NULL != name)
    {
        syUnicodeToAnsi(nameA, name);

        defFile = fopen((const char*)staticData->cifsFile, "r");
        if (NULL != defFile)
        {
            tempFile = fopen((const char*)staticData->tempFileName, "w+");
            if (NULL == tempFile)
            {
                fclose(defFile);
                return TRUE;
            }

            /* cycle by lines of the parameter file */
            while (NULL != fgets(buffer, sizeof(buffer), defFile))
            {
                if (0 != strncmp(nameA, buffer, strlen(nameA)))
                    fputs(buffer, tempFile);
            }

            fclose(defFile);
            fclose(tempFile);
        }
    }
    else
    {
        if (OK != rename((const char*)staticData->cifsFile, (const char*)staticData->tempFileName))
        {
            return TRUE;
        }
    }

    tempFile = fopen((const char*)staticData->tempFileName, "a+");
    if (NULL == tempFile)
    {
        return TRUE;
    }
    syUnicodeToAnsi(newNameA, newName);
    syUnicodeToAnsi(mapA, newMap);
    syUnicodeToAnsi(descriptionA, newDescription);
    fprintf(tempFile, "%s;%s;%s\n", newNameA, mapA, descriptionA);
    fclose(tempFile);
    unlink((const char*)staticData->cifsFile);
    rename((const char*)staticData->tempFileName, (const char*)staticData->cifsFile);
    return TRUE;
}

/*
 *====================================================================
 * PURPOSE: remove share from the persistent store
 *--------------------------------------------------------------------
 * PARAMS:  IN share name
 *
 * RETURNS: TRUE on success, FALSE on failure
 *
 * NOTES:   this implementation always returns TRUE
 *====================================================================
 */

NQ_BOOL
udDefRemoveShare(
    const NQ_WCHAR* name
    )
{
    NQ_STATIC char nameA[UD_FS_MAXSHARELEN];
    FILE* defFile;
    FILE* tempFile;
    NQ_STATIC char buffer[256];

    if (staticData->readingShares)
    {
        return FALSE;
    }

    unlink((const char*)staticData->tempFileName);
    syUnicodeToAnsi(nameA, name);

    defFile = fopen((const char*)staticData->cifsFile, "r");
    if (NULL == defFile)
        return TRUE;
    tempFile = fopen((const char*)staticData->tempFileName, "w");
    if (NULL == tempFile)
	{
	    fclose(defFile);
        return TRUE;
	}

    /* cycle by lines of the parameter file */
    while (NULL != fgets(buffer, sizeof(buffer), defFile))
    {
        if (0 != strncmp(nameA, buffer, strlen(nameA)))
            fputs(buffer, tempFile);
    }

    fclose(defFile);
    fclose(tempFile);
    unlink((const char*)staticData->cifsFile);
    rename((const char*)staticData->tempFileName, (const char*)staticData->cifsFile);

    return TRUE;
}

#endif /* UD_CS_INCLUDERPC_SRVSVC_EXTENSION */

#ifdef UD_NQ_INCLUDEEVENTLOG

/*
 *====================================================================
 * PURPOSE: event log function
 *--------------------------------------------------------------------
 * PARAMS:  IN code of NQ module that originated this event
 *          IN event class code
 *          IN event type
 *          IN pointer to the user name string
 *          IN IP address on the second side of the connection
 *          IN zero if the operation has succeeded or error code on failure
 *             for server event this code is the same that will be transmitted
 *             to the client
 *             for an NQ CIFS client event this value is the same that will be
 *             installed as system error
 *          IN pointer to a structure that is filled with event data
 *             actual structure depends on event type
 *
 * RETURNS: None
 *
 * NOTES:   Sample implementation
 *====================================================================
 */

void
udDefEventLog (
    NQ_UINT module,
    NQ_UINT eventClass,
    NQ_UINT type,
    const NQ_WCHAR* userName,
    const NQ_IPADDRESS* pIp,
    NQ_UINT32 status,
    const NQ_BYTE* parameters
    )
{

#define UNIQUECLASS(_mod, _class)  (_mod * 100 + _class)
#define UNIQUEEVENT(_mod, _class, _type)  (_mod * 10000 + _class * 100 + _type)
    const char* modName;
    const char* className;
    const char* typeName;
    NQ_CHAR    ip[CM_IPADDR_MAXLEN];
    NQ_BOOL   isUnicode = FALSE;
    NQ_CHAR * tempName = NULL;

#ifdef UD_CM_UNICODEAPPLICATION
    isUnicode = TRUE;
    if (userName != NULL)
    	tempName = cmMemoryCloneWStringAsAscii(userName);
#endif /*UD_CM_UNICODEAPPLICATION*/

    if (pIp != NULL)
        cmIpToAscii(ip, pIp); 
    else
        syStrcpy(ip, "<NULL>");

    switch (module)
    {
    case UD_LOG_MODULE_CS:
        modName = "SERVER";
        break;
    case UD_LOG_MODULE_CC:
        modName = "CLIENT";
        break;
    default:
        modName = "UNKNOWN";
    }

    switch (UNIQUECLASS(module, eventClass))
    {
    case UNIQUECLASS(UD_LOG_MODULE_CS, UD_LOG_CLASS_GEN):
        className = "GENERIC   ";
        break;
    case UNIQUECLASS(UD_LOG_MODULE_CS, UD_LOG_CLASS_FILE):
        className = "FILE      ";
        break;
    case UNIQUECLASS(UD_LOG_MODULE_CS, UD_LOG_CLASS_SHARE):
        className = "SHARE     ";
        break;
    case UNIQUECLASS(UD_LOG_MODULE_CS, UD_LOG_CLASS_USER):
        className = "USER      ";
        break;
    case UNIQUECLASS(UD_LOG_MODULE_CS, UD_LOG_CLASS_CONNECTION):
        className = "CONNECTION";
        break;
    default:
        className = "UNKNOWN   ";
    }

    switch (UNIQUEEVENT(module, eventClass, type))
    {
    case UNIQUEEVENT(UD_LOG_MODULE_CS, UD_LOG_CLASS_GEN, UD_LOG_GEN_START):
        typeName = "START     ";
        break;
    case UNIQUEEVENT(UD_LOG_MODULE_CS, UD_LOG_CLASS_GEN, UD_LOG_GEN_STOP):
        typeName = "STOP      ";
        break;
    case UNIQUEEVENT(UD_LOG_MODULE_CS, UD_LOG_CLASS_GEN, UD_LOG_GEN_NAMECONFLICT):
		typeName = "NAME CONF ";
		break;
    case UNIQUEEVENT(UD_LOG_MODULE_CS, UD_LOG_CLASS_FILE, UD_LOG_FILE_CREATE):
        typeName = "CREATE    ";
        break;
    case UNIQUEEVENT(UD_LOG_MODULE_CS, UD_LOG_CLASS_FILE, UD_LOG_FILE_OPEN):
        typeName = "OPEN      ";
        break;
    case UNIQUEEVENT(UD_LOG_MODULE_CS, UD_LOG_CLASS_FILE, UD_LOG_FILE_CLOSE):
        typeName = "CLOSE     ";
        break;
    case UNIQUEEVENT(UD_LOG_MODULE_CS, UD_LOG_CLASS_FILE, UD_LOG_FILE_DELETE):
        typeName = "DELETE    ";
        break;
    case UNIQUEEVENT(UD_LOG_MODULE_CS, UD_LOG_CLASS_FILE, UD_LOG_FILE_RENAME):
        typeName = "RENAME    ";
        break;
    case UNIQUEEVENT(UD_LOG_MODULE_CS, UD_LOG_CLASS_FILE, UD_LOG_FILE_ATTRIBSET):
        typeName = "ATTRIB SET";
        break;
    case UNIQUEEVENT(UD_LOG_MODULE_CS, UD_LOG_CLASS_FILE, UD_LOG_FILE_ATTRIBGET):
     	typeName = "ATTRIB GET";
     	break;
    case UNIQUEEVENT(UD_LOG_MODULE_CS, UD_LOG_CLASS_FILE, UD_LOG_FILE_SIZESET):
		typeName = "SIZE SET  ";
		break;
    case UNIQUEEVENT(UD_LOG_MODULE_CS, UD_LOG_CLASS_FILE, UD_LOG_FILE_VOLUMEINFO):
		typeName = "VOLUMEINFO";
		break;
    case UNIQUEEVENT(UD_LOG_MODULE_CS, UD_LOG_CLASS_FILE, UD_LOG_FILE_QUERYDIRECTORY):
		typeName = "QUERYDIR  ";
		break;
    case UNIQUEEVENT(UD_LOG_MODULE_CS, UD_LOG_CLASS_FILE, UD_LOG_FILE_SEEK):
		typeName = "SEEK      ";
		break;
    case UNIQUEEVENT(UD_LOG_MODULE_CS, UD_LOG_CLASS_FILE, UD_LOG_FILE_LOCK):
		typeName = "LOCK      ";
		break;
    case UNIQUEEVENT(UD_LOG_MODULE_CS, UD_LOG_CLASS_FILE, UD_LOG_FILE_UNLOCK):
		typeName = "UNLOCK    ";
		break;
    case UNIQUEEVENT(UD_LOG_MODULE_CS, UD_LOG_CLASS_SHARE, UD_LOG_SHARE_CONNECT):
        typeName = "CONNECT   ";
        break;
    case UNIQUEEVENT(UD_LOG_MODULE_CS, UD_LOG_CLASS_SHARE, UD_LOG_SHARE_DISCONNECT):
        typeName = "DISCONNECT";
        break;
    case UNIQUEEVENT(UD_LOG_MODULE_CS, UD_LOG_CLASS_USER, UD_LOG_USER_LOGON):
        typeName = "LOGON     ";
        break;
    case UNIQUEEVENT(UD_LOG_MODULE_CS, UD_LOG_CLASS_USER, UD_LOG_USER_LOGOFF):
        typeName = "LOGOFF    ";
        break;
    case UNIQUEEVENT(UD_LOG_MODULE_CS, UD_LOG_CLASS_CONNECTION, UD_LOG_CONNECTION_CONNECT):
        typeName = "CONNECT   ";
        break;
    case UNIQUEEVENT(UD_LOG_MODULE_CS, UD_LOG_CLASS_CONNECTION, UD_LOG_CONNECTION_DISCONNECT):
        typeName = "DISCONNECT";
        break;
    default:
        typeName = "UNKNOWN   ";
    }

    /*saveEvent(
        "#NQ event in %s class %s type %s user %s IP 0x%08lx error %ld",
        modName,
        className,
        typeName,
        NULL == userName? "<NONE>" : cmTDump(userName),
        NULL == pIp? 0 : CM_IPADDR_GET4(*pIp),
        status
        );*/
    saveEvent(
        "#NQ Event in: %s Class: %s Type: %s User: %s IP: %s",
        modName,
        className,
        typeName,
        NULL == userName? "<NONE>" : isUnicode ? tempName :(NQ_CHAR *)userName,
        ip
        );
    if (status != NQ_SUCCESS)
    	saveEvent(" ERROR: %x" , status);
    switch(status)
    {
    case (SMB_STATUS_USER_SESSION_DELETED):
    		saveEvent(" UNEXPECTED DISCONNECT");
    		break;
    case (NQ_ERR_NORESOURCE):
    		saveEvent(" OVERFLOW");
    		break;
    default:
    	if (status != NQ_SUCCESS)
    	    	saveEvent(" ERROR: %x" , status);
    	break;
    }

    switch (UNIQUECLASS(module, eventClass))
    {
    case UNIQUECLASS(UD_LOG_MODULE_CS, UD_LOG_CLASS_FILE):
        {
            UDFileAccessEvent* event = (UDFileAccessEvent*)parameters;
            NQ_CHAR * tempFileName = NULL;

            if (event == NULL)
                break;

#ifdef UD_CM_UNICODEAPPLICATION
            if (event->fileName != NULL)
                tempFileName = cmMemoryCloneWStringAsAscii(event->fileName);
#endif /*UD_CM_UNICODEAPPLICATION*/
            saveEvent(" TID: %d" , event->tid == (NQ_UINT32)(-1) ? (NQ_UINT32)(-1) : event->tid);
            saveEvent("  File: %s", NULL == event->fileName? "<NONE>" : isUnicode ? tempFileName : (NQ_CHAR *)event->fileName);
#ifdef UD_CM_UNICODEAPPLICATION
            cmMemoryFree(tempFileName);
#endif /*UD_CM_UNICODEAPPLICATION*/
            event->before ? saveEvent(" BEFORE") : saveEvent(" AFTER");
            switch(type)
            {
            case UD_LOG_FILE_CREATE:
                saveEvent(" CREATE");
                saveEvent(" RID: '%d' ", event->rid);
                break;
            case UD_LOG_FILE_DELETE:
                saveEvent(" DELETE");
                saveEvent(" RID: '%d' ", event->rid);
                break;
            case UD_LOG_FILE_OPEN:
            {
                const char* access;

                switch (event->access & 0xF)
                {
                case 0:
                    access = "READ";
                    break;
                case 1:
                    access = "WRITE";
                    break;
                case 2:
                    access = "READ/WRITE";
                    break;
                case 3:
                    access = "EXECUTE";
                    break;
                case 0xF:
                    access = "READ";
                    break;
                default:
                    access = "UNKNOWN";
                }
                saveEvent(" Access: %s", access);
                saveEvent(" RID: '%d' ", event->rid);
            }
            break;
            case UD_LOG_FILE_CLOSE:
            {
                const char* access;

                switch (event->access & 0xF)
                {
                case 0:
                    access = "READ";
                    break;
                case 1:
                    access = "WRITE";
                    break;
                case 2:
                    access = "READ/WRITE";
                    break;
                case 3:
                    access = "EXECUTE";
                    break;
                case 0xF:
                    access = "READ";
                    break;
                default:
                    access = "UNKNOWN";
                }
                saveEvent(" Access: %s", access);
                saveEvent(" RID: '%d' ", event->rid);
            }
            break;
           case UD_LOG_FILE_RENAME:
#ifdef UD_CM_UNICODEAPPLICATION
               if (event->newName != NULL)
        	        tempFileName = cmMemoryCloneWStringAsAscii(event->newName);
#endif /*UD_CM_UNICODEAPPLICATION*/
               saveEvent(" New: %s", isUnicode ? tempFileName : (NQ_CHAR *)event->newName);
               saveEvent(" RID: '%d' ", event->rid);
#ifdef UD_CM_UNICODEAPPLICATION
               cmMemoryFree(tempFileName);
#endif /*UD_CM_UNICODEAPPLICATION*/
               break;
           case UD_LOG_FILE_ATTRIBSET:
               {
                   saveEvent(" Mode: %08lx", event->access);
                   saveEvent(" RID: '%d' ", event->rid);
               }
               break;
           default:
                saveEvent(" RID: '%d' ", event->rid);
                break;
            }
        }
        break;
    case UNIQUECLASS(UD_LOG_MODULE_CS, UD_LOG_CLASS_SHARE):
        {
            UDShareAccessEvent* event = (UDShareAccessEvent*)parameters;
            NQ_CHAR * tempShareName = NULL;

            if (event == NULL)
                break;

#ifdef UD_CM_UNICODEAPPLICATION
            tempShareName = cmMemoryCloneWStringAsAscii(event->shareName);
#endif /*UD_CM_UNICODEAPPLICATION*/

            saveEvent(" Share: '%s'", isUnicode ? tempShareName : (NQ_CHAR *)event->shareName);
            saveEvent(" Tid: %d" , event->tid );
#ifdef UD_CM_UNICODEAPPLICATION
            cmMemoryFree(tempShareName);
#endif /*UD_CM_UNICODEAPPLICATION*/
            if (event->ipc)
            {
                saveEvent(" IPC");
            }
            if (event->printQueue)
            {
                saveEvent(" PRINT QUEUE");
            }
            saveEvent(" RID: '%d' ", event->rid);
        }
        break;
    case UNIQUECLASS(UD_LOG_MODULE_CS, UD_LOG_CLASS_USER):
    {
        UDUserAccessEvent * event = (UDUserAccessEvent *)parameters;

        if (event == NULL)
            break;

        saveEvent(" RID: '%d' ", event->rid);
    }
    default:
        className = "UNKNOWN";
    }
    saveEvent("\n");
    if (UNIQUEEVENT(UD_LOG_MODULE_CS, UD_LOG_CLASS_GEN, UD_LOG_GEN_STOP) ==
        UNIQUEEVENT(module, eventClass, type)
       )
       saveEvent(NULL);
}

#endif /* UD_NQ_INCLUDEEVENTLOG */

/*
 *====================================================================
 * PURPOSE: read and parse the NetBIOS configuration file
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: TRUE on success,
 *          FALSE on error
 *
 * NOTES:   Opens the file, parses it and stores parameter values if
 *          those parameters were found
 *====================================================================
 */

static NQ_BOOL
parseNetBiosConfig(
    void
    )
{
    ParseContext parser;            /* parser context */

    setFileNames();
    if (!parseInit(&parser, staticData->netbiosFile)) /* start parsing */
        return FALSE;

    /* cycle by lines of the parameter file */

    while (1)
    {
        char ch;                        /* next character */

        if (parseAtFileEnd(&parser))      /* EOF */
        {
            staticData->netBiosConfigFlag = 1;
            return TRUE;
        }

        parseSkipSpaces(&parser);

        if ((ch = parseGet(&parser)) != '#')    /* comment  line? */
        {
            char name[100];    /* buffer for name */
            char value[100];  /* buffer for value */

            parseUnget(&parser, ch);
            parseSkipSpaces(&parser);
            parseName(&parser, name, sizeof(name));              /* parameter name */

            parseSkipSpaces(&parser);

            if (parseDelimiter(&parser, '='))
            {
                parseSkipSpaces(&parser);
                parseValue(&parser, value, sizeof(value), ':');  /* parameter value - no delimiter */

                if (!strncmp(name, "WINS", strlen("WINS")))
                {
                    staticData->winsAddress = inet_addr(value);
                }
                else
                    if (!strncmp(name, "SCOPE_ID", strlen("SCOPE_ID")))
                    {
                        strcpy(staticData->scopeId, value);
                        staticData->scopeIdPtr = staticData->scopeId;
                    }

                if (!strncmp(name, "DOMAIN", strlen("DOMAIN")))
                {
                    /* value of type DOMAIN_NAME[:D] */
                    strcpy(staticData->domainNameOfServer, value);

                    parseSkipSpaces(&parser);
                    staticData->isWorkgroupName = TRUE;

                    if (parseDelimiter(&parser, ':'))
                    {
                        parseSkipSpaces(&parser);
                        parseValue(&parser, value, 1, (char)0);
                        staticData->isWorkgroupName = (value[0] != 'D');
                    }
                }
            }
        }

        parseSkipLine(&parser);
    }
}

/*
 *====================================================================
 * PURPOSE: Prepare file names for futher use
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: NONE
 *
 * NOTES:   This function does its work only once by using a singleton
 *====================================================================
 */

static void
setFileNames(
    void
    )
{
    if (!staticData->fileNamesReady)
    {
        strcpy(staticData->netbiosFile, NQ_CONFIGPATH);
        if (*(staticData->netbiosFile + strlen(staticData->netbiosFile) - 1) != '/')
        {
            strcat(staticData->netbiosFile, "/");
        }
        strcat(staticData->netbiosFile, "cm_cfg.txt");
        strcpy(staticData->cifsFile, NQ_CONFIGPATH);
        if (*(staticData->cifsFile + strlen(staticData->cifsFile) - 1) != '/')
        {
            strcat(staticData->cifsFile, "/");
        }
        strcat(staticData->cifsFile, "cs_cfg.txt");
        strcpy(staticData->mountFile, NQ_CONFIGPATH);
        if (*(staticData->mountFile + strlen(staticData->mountFile) - 1) != '/')
        {
            strcat(staticData->mountFile, "/");
        }
        strcat(staticData->mountFile, "cc_cfg.txt");
        strcpy(staticData->passwordFile, NQ_CONFIGPATH);
        if (*(staticData->passwordFile + strlen(staticData->passwordFile) - 1) != '/')
        {
            strcat(staticData->passwordFile, "/");
        }
        strcat(staticData->passwordFile, "pwd_list.txt");
        strcpy(staticData->shareSdFile, NQ_CONFIGPATH);
        if (*(staticData->shareSdFile + strlen(staticData->shareSdFile) - 1) != '/')
        {
            strcat(staticData->shareSdFile, "/");
        }
        strcat(staticData->shareSdFile, "share_sd.txt");
        strcpy(staticData->tempFileName, NQ_CONFIGPATH);
        if (*(staticData->tempFileName + strlen(staticData->tempFileName) - 1) != '/')
        {
            strcat(staticData->tempFileName, "/");
        }
        strcat(staticData->tempFileName, "__temp__");
#ifdef UD_NQ_INCLUDEEVENTLOG
        strcpy(staticData->logFile, NQ_CONFIGPATH);
        if (*(staticData->logFile + strlen(staticData->logFile) - 1) != '/')
        {
            strcat(staticData->logFile, "/");
        }
        strcat(staticData->logFile, "event_log.txt");
#endif /* UD_NQ_INCLUDEEVENTLOG */
        strcpy(staticData->secretFile, NQ_CONFIGPATH);
        if (*(staticData->secretFile + strlen(staticData->secretFile) - 1) != '/')
        {
            strcat(staticData->secretFile, "/");
        }
        strcat(staticData->secretFile, "secret.txt");

        staticData->fileNamesReady = 1;
    }
}

/*
 *====================================================================
 * PURPOSE: Save/print logged event
 *--------------------------------------------------------------------
 * PARAMS:  IN print format
 *          VARARG parameters
 *
 * RETURNS: None
 *
 * NOTES:
 *====================================================================
 */

#ifdef UD_NQ_INCLUDEEVENTLOG

static void
saveEvent(
    char* format,
    ...
    )
{
    va_list va;                         /* parameter list */

    if (!staticData->logHandleFlag)
    {
        staticData->logHandle = fopen(staticData->logFile, "w");
        staticData->logHandleFlag = 1;
    }

    if (staticData->logHandle == NULL)
        return;

    if (NULL == format)
    {
        staticData->logHandleFlag = 0;
        fclose(staticData->logHandle);
        return;
    }

    va_start(va, format);
    vfprintf(staticData->logHandle, format, va);
    fflush(staticData->logHandle);
}
#endif /* UD_NQ_INCLUDEEVENTLOG */

/*
 *====================================================================
 * PURPOSE: Convert HEX representation of a password string to text
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT HEX string. This buffer is used for conversion
 *
 * RETURNS: TRUE for success FALSE for error
 *
 * NOTES:   HEX representation is an ASCII representation where each ACSII character
 *          is represented as its HEX equivalent
 *====================================================================
 */

static NQ_BOOL
convertHex2Ascii(
    char* text
    )
{
    int  src;           /* index in the source (hex) string */
    int  dst;           /* index in the target (ascii) string*/
    unsigned char tmp;           /* temporary holds the half-character being converted */


    /* we use the same buffer for the destination string
       the size password in HEX should be of exact length */

    for ( src = 0, dst = 0; text[src] > 0 && dst < 32; dst++ )
    {
        /* check if next character is a hex numbers */

        tmp = (unsigned char)toupper((int)text[src]);
        src++;

        if ( !(   ((tmp >= '0') && (tmp <= '9') )
               || ((tmp >= 'A') && (tmp <= 'F') )
              )
           )
        {
            return FALSE;
        }

        /* get the real number of the high hex character */

        tmp = (unsigned char)(tmp - (unsigned char)((tmp < 'A')? 0x30: 0x37));
        text[dst] = (char)(tmp << 4);   /* high half-octet */

        /* check if the second character is a hex numbers */

        tmp = (unsigned char)toupper((int)text[src]);
        src++;

        if ( !(   ((tmp >= '0') && (tmp <= '9') )
               || ((tmp >= 'A') && (tmp <= 'F') )
              )
           )
        {
            return FALSE;
        }

        /* get the real number of the high hex character */

        tmp = (unsigned char)(tmp - (unsigned char)((tmp < 'A')? 0x30: 0x37));
        text[dst] = (char)(text[dst] + tmp);       /* low half-octet */
    }

    text[dst] = '\0';

    return TRUE;
}

#ifdef UD_CS_INCLUDELOCALUSERMANAGEMENT

/*
 *====================================================================
 * PURPOSE: Convert binary representation of a password to text
 *--------------------------------------------------------------------
 * PARAMS:  IN 32-byte binary password
 *             OUT 64-byte buffer
 *
 * RETURNS: None
 *
 * NOTES:
 *====================================================================
 */

static void
convertPasswordToText(
    const NQ_BYTE* password,
    NQ_CHAR* buffer
    )
{
    int i;

    for (i = 0; i < 32; i++)
    {
        *buffer = (NQ_CHAR)((((*password)/16) < 10)? (char)((*password)/16 + '0') : (char)((*password)/16 - 10 + 'a'));
        buffer++;
        *buffer = (NQ_CHAR)((((*password)%16) < 10)? (char)((*password)%16 + '0') : (char)((*password)%16 - 10 + 'a'));
        buffer++;
        password++;
    }
}

#endif /* UD_CS_INCLUDELOCALUSERMANAGEMENT */

#ifdef UD_CS_INCLUDEDOMAINMEMBERSHIP

NQ_BOOL
udDefGetComputerSecret(
    NQ_BYTE **secret
    )
{
    TRCB();

    if (!staticData->isSecretFileLoaded && !staticData->isSecretAvailable)
    {
        int file;

        /* load secret file once only */
        staticData->isSecretFileLoaded = TRUE;
        setFileNames();
        file = open(staticData->secretFile, O_RDWR, 0777);
        if (file == ERROR)
        {
            TRCERR("Failed to open secret file");
            TRCE();
            return FALSE;
        }
        if (read(file, staticData->secret, sizeof(staticData->secret)) != sizeof(staticData->secret))
        {
            close(file);
            TRCERR("Failed to read secret file");
            TRCE();
            return FALSE;
        }
        close(file);
        TRC("Secret loaded from file");
        staticData->isSecretAvailable = TRUE;
        TRCDUMP("secret", staticData->secret, 16);
    }

    if (staticData->isSecretAvailable && secret)
    {
        *secret = (NQ_BYTE *)&staticData->secret;
        TRCDUMP("secret", *secret, 16);
    }
    TRCE();
    return staticData->isSecretAvailable;
}


void
udDefSetComputerSecret(
    NQ_BYTE *secret
    )
{
    int file;

    TRCB();

    syMemcpy(staticData->secret, secret, sizeof(staticData->secret));

    file = open(staticData->secretFile, O_RDWR | O_CREAT, 0777);
    if (file == ERROR)
    {
        TRCERR("Failed to open secret file");
        TRCE();
        return;
    }
    write(file, staticData->secret, sizeof(staticData->secret));
    close(file);
    staticData->isSecretAvailable = TRUE;
    TRCE();
}

#endif /* UD_CS_INCLUDEDOMAINMEMBERSHIP */
