
#import "INQServiceManager.h"

#import "udconfig.h"
#import "nsapi.h"
#import "ndapi.h"
#import "csapi.h"


#pragma mark -
#pragma mark CIFS Service Implementation.

#ifdef UD_CS_INCLUDEDOMAINMEMBERSHIP
void joinDomain(void);
#endif

void udCifsServerStarted(void) {

    static NQ_CHAR *result = "no printer";

#ifdef UD_CS_INCLUDEDOMAINMEMBERSHIP
    joinDomain();
#endif
    printf("\n===== NQCS: server is ready (%s)\n", result);

    dispatch_async(dispatch_get_main_queue(), ^{
        NSNotification *n = [NSNotification notificationWithName:CIFS_SERVER_STARTED object:nil];
        [[NSNotificationCenter defaultCenter] postNotification:n];
    });
}

int count;

NQ_BOOL
udDefGetNextShare(
                  NQ_WCHAR* name,
                  NQ_WCHAR* map,
                  NQ_BOOL* printQueue,
                  NQ_WCHAR* description
                  ) {
    
    NSMutableDictionary *savedData = [[NSUserDefaults standardUserDefaults]objectForKey:SHARE_FOLDERS];
    NSEnumerator *enm = [savedData keyEnumerator];
    
    
    int i = 0;
    while (TRUE) {
        NSString *key = [enm nextObject];
        i++;
        if (i < count) {
            continue;
        }

        if (key == nil) {
#if 0
            // デバッグ用処理としてサーバー機能を有効時に自端末のrootフォルダを共有設定にする設定を無効
#if DEBUG
            syAnsiToUnicode(name, "Root");
            syAnsiToUnicode(map, "./");
            syAnsiToUnicode(description, "Default root (no configuration file provided)");
            *printQueue = FALSE;
            return TRUE;              
#endif
#endif
            break;
        }

        
        NSMutableDictionary *dic = [savedData objectForKey:key];

        NSString *folderName = [dic objectForKey:FOLDER_NAME];

        DLog(@"Initial Shared Folder:%@",folderName);        

#if 1 // ITA - debug
        NSString* documents = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) objectAtIndex:0];
        DLog(@"documents Folder:%@",documents);
        NSString* documentpath = [documents stringByAppendingPathComponent:folderName];
        DLog(@"document path:%@",documentpath);
#endif // ITA - debug
        cmWStrcpy(name, (NQ_WCHAR *)[[NSString stringWithFormat:@"%@",folderName]
                                     cStringUsingEncoding:NSUTF16StringEncoding]);
        cmAnsiToUnicode(map, [documentpath UTF8String]);
        cmWStrcpy(description, (NQ_WCHAR *)[[NSString stringWithFormat:@"%@",folderName]
                                    cStringUsingEncoding:NSUTF16StringEncoding]);
        *printQueue = FALSE;
        count++;
        return TRUE;
        
    }
    
    return FALSE;

}

void
udDefGetDomain(
               NQ_WCHAR *buffer,
               NQ_BOOL  *isWorkgroup
               )
{
   // if (!staticData->netBiosConfigFlag)
   // {
   //     parseNetBiosConfig();
   // }
    
   // syAnsiToUnicode(buffer, staticData->domainNameOfServer);
   // *isWorkgroup = staticData->isWorkgroupName;
    NSString *workgroup = [[NSUserDefaults standardUserDefaults] objectForKey:@"WORKGROUP"];
    if (workgroup != nil) {
        syAnsiToUnicode(buffer,[workgroup UTF8String]);
    } else {
        syAnsiToUnicode(buffer,"WORKGROUP");
    }
    *isWorkgroup = TRUE;    
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
    
 
    syAnsiToUnicode(name, nameA);
    syAnsiToUnicode(map, mapA);
    return FALSE;

}

void udCifsServerClosed(void) {
    NSLog(@"\nCIFS SERVER CLOSED\n");
    NSNotification *n = [NSNotification notificationWithName:CIFS_SERVER_CLOSED object:nil];
    [[NSNotificationCenter defaultCenter] postNotification:n];
  
}

void udNetBiosDaemonStarted(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        NSLog(@"\n NETBIOS STARTED\n");
        [[NSNotificationCenter defaultCenter] postNotification:[NSNotification notificationWithName:NETBIOS_DAEMON_STARTED object:nil]];
        
    });

    
}

void udNetBiosDaemonClosed(void) {
    NSLog(@"\n NETBISO CLOSED\n");
    NSNotification *n = [NSNotification notificationWithName:NETBIOS_DAEMON_CLOSED object:nil];
    [[NSNotificationCenter defaultCenter] postNotification:n];
    
}

@implementation INQServiceManager
@synthesize serverStated;

#pragma mark -
#pragma mark  ServiceManager implementation.

+ (id)sharedManager {
    static dispatch_once_t once;
    static INQServiceManager *singleton = nil;
    dispatch_once(&once, ^ { singleton = [[INQServiceManager alloc] init]; });
    return singleton;    
}

- (id)init {
    self = [super init];
    if (self) {  
        serverStated = NO;
        udInit();
        syInit();
        nsInitGuard();
        
    }
    return self;
}


- (void)initClient {
    [self client];
}

- (void)startNetBios {
    DLog(@"StartNetBios");
    [self performSelectorInBackground:@selector(ndstart) withObject:nil];
}

- (void)stopNetBios {
    [self performSelectorInBackground:@selector(ndstop) withObject:nil];      
}

- (void)startCifsServer {

    DLog(@"StartCIFSServer");
    [self csstart];
    [self performSelectorInBackground:@selector(csstart) withObject:nil];

}

- (void)stopCifsServer {

    DLog(@"StopCIFSServer");
    [self performSelectorInBackground:@selector(csstop) withObject:nil]; 
}

#pragma mark -
#pragma mark Native Command.

- (void)client {
#ifdef UD_NQ_INCLUDECIFSCLIENT
    ccInit(NULL);
#endif

}

-(void)ndstart {
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];    
#ifdef UD_ND_INCLUDENBDAEMON
    cmInit();
    /* main function */
    ndStart(NULL);
    
    /* cleanup */
    cmExit();
    //udStop();
#endif  
    [pool release];
}

- (void)ndstop {
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];        
#ifdef UD_ND_INCLUDENBDAEMON
    ndStop();
    nsExitGuard();
#endif  
    [pool release];
}



- (void)csstart {
  
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
    //udInit();           /* new UD */
    //syInit();
    //nsInitGuard();      /* prepare for using NS */
    
    ccInit(NULL);
#ifdef UD_NQ_INCLUDECIFSSERVER
    csStart();
#endif  
    [pool release];
}

- (void)csstop {
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];    
    csStop();  
    [pool release];
}

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

NQ_INT
udDefGetPassword(
                 const NQ_WCHAR* userName,
                 NQ_CHAR* password,
                 NQ_BOOL* pwdIsHashed,
                 NQ_UINT32* userNumber
                 )
{
    printf("***************** udDefGetPassword *********");
    char userNameA[256];        
    *userNumber = 501;
    *pwdIsHashed = 0;

    syUnicodeToAnsi(userNameA, userName);
    printf("USER NAME %s",userNameA);
    
    NSString *inqUserName = [[NSUserDefaults standardUserDefaults] objectForKey:@"USERID"];
    NSString *inqPassword = [[NSUserDefaults standardUserDefaults] objectForKey:@"PASSWORD"];  
    if (inqUserName == NULL || inqPassword == NULL) {
        return NQ_CS_PWDNOAUTH;
    }
    
    if (inqUserName != NULL) {
        return NQ_CS_PWDNOUSER;                
    }


    if (strcasecmp(userNameA, [inqUserName UTF8String]) != 0) {
        return NQ_CS_PWDNOUSER;        
    }

    strcpy(password,[inqPassword UTF8String]);
    
    return NQ_CS_PWDANY; 

}

@end
