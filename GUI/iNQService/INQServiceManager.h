
#import <Foundation/Foundation.h>

#import "INQ.h"
#import "INQSharedFolderDataSource.h"

#include "cmapi.h"
#include "cscontrl.h"

static NSString *const CIFS_SERVER_STARTED = @"cifsServerStarted";
static NSString *const CIFS_SERVER_CLOSED = @"cifsServerClosed";
static NSString *const NETBIOS_DAEMON_STARTED = @"netBiosDaemonStarted";
static NSString *const NETBIOS_DAEMON_CLOSED = @"netBiosDaemonClosed";
static NSString *const BROWSER_DAEMON_STARTED = @"browserDaemonStarted";
static NSString *const BROWSER_DAEMON_CLOSED = @"browserDaemonClosed";

static NSString *const IS_AUTO_START_SERVER = @"isAutoStartServer";

@interface INQServiceManager : NSObject {
    BOOL serverStated;

}

@property (nonatomic,getter = isServerStated) BOOL serverStated;


+ (id)sharedManager;

- (void)startNetBios;
- (void)stopNetBios;
- (void)startCifsServer;
- (void)stopCifsServer;
- (void)startBrowser;
- (void)stopBrowser;
- (void)initClient;

@end
