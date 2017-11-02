
#import "INQAppDelegate.h"

static void uncaughtExceptionHandler(NSException *exception)
{
    NSLog(@"CRASH: %@", exception);
    NSLog(@"Stack Trace: %@", [exception callStackSymbols]);
}

@implementation INQAppDelegate

@synthesize window = _window;
@synthesize viewController = _viewController;
@synthesize naviController = _naviController;
@synthesize wifi;
@synthesize inqStatusWindow;
@synthesize typeAddWorkGroupView;
@synthesize typeSelectedView;
@synthesize isUpdateComputerInfo;
@synthesize backupComputerName;

- (void)dealloc {
    [_window release];
    [_viewController release];
    [_naviController release];
    
    [super dealloc];
}

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    DLog(@"Start NQ Application");
#if DEBUG    
    NSSetUncaughtExceptionHandler(&uncaughtExceptionHandler);
#endif
        
    _naviController = [[UINavigationController alloc] init];
    
    [UIApplication sharedApplication].statusBarHidden = NO;    

    //self.naviController.navigationBar.tintColor = [UIColor colorWithRed:14.0f/255.f green:133.f/255.f blue:175.f/255.f alpha:0.5];
    
    
    self.window = [[[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]] autorelease];
    
    // Override point for customization after application launch.
    if ([[UIDevice currentDevice] userInterfaceIdiom] == UIUserInterfaceIdiomPhone) {
        _viewController = [[INQSplashViewController alloc]init];
        DLog(@"User Inteface iPhone.");
    } else {
        DLog(@"User Inteface iPad.");        
        //self.viewController = [[[INQSplashViewController alloc] initWithNibName:@"NQViewController_iPad" bundle:nil] autorelease];
        _viewController = [[INQSplashViewController alloc]init];        
    }
    
    [self initDocumentDirectory];        
    [self performSelectorInBackground:@selector(startAllService) withObject:nil];
    [self registerNotification];
    
    [self.naviController pushViewController:self.viewController animated:YES];

    NSDictionary *attributes = [NSDictionary dictionaryWithObjectsAndKeys: 
                                [UIColor whiteColor], 
                                UITextAttributeTextColor, 
                                [UIColor clearColor], 
                                UITextAttributeTextShadowColor, nil];
    
    [[UIBarButtonItem appearance] setTitleTextAttributes: attributes
                                                forState: UIControlStateNormal];
    
    [self.window setRootViewController:self.naviController];
    [self.window makeKeyAndVisible];

    DLog(@"Wifi LOCAL IP ADDRESS:%@",[self getIPAddress]);
    return YES;    
}

- (void)applicationWillResignActive:(UIApplication *)application {
    DLog(@"Application will resing active.");	

}

- (void)applicationDidEnterBackground:(UIApplication *)application {
    DLog(@"Application did enter background.");
    
    /**
     * バックグラウンドに遷移したらアプリケーションを終了させる様にする処理を追加.
     */
    [self stopAllService];
    exit(1);
}

- (void)applicationWillEnterForeground:(UIApplication *)application {
    DLog(@"Application will enter foreground.");
    
}

- (void)applicationDidBecomeActive:(UIApplication *)application {
    DLog(@"Application did become active.");
}

- (void)applicationWillTerminate:(UIApplication *)application {
    DLog(@"Application will terminate.");
    
    [self stopAllService];
}

- (void)startAllService {
    // INQ service 
    [[INQServiceManager sharedManager] startNetBios];
    sleep(5);

    // check for internet connection
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(checkNetworkStatus:) name:kReachabilityChangedNotification object:nil];
    
    internetReachable = [[Reachability reachabilityForInternetConnection] retain];
    [internetReachable startNotifier];
    
    Reachability *reach = [Reachability reachabilityForLocalWiFi];
    [reach startNotifier];
    
    NetworkStatus stat = [reach currentReachabilityStatus];
    wifi = NO;
    
    // init client
    [[INQServiceManager sharedManager] initClient];
    
    if(stat & ReachableViaWiFi) {
        wifi = YES;
        BOOL isLoginStartServer = [[NSUserDefaults standardUserDefaults] boolForKey:IS_AUTO_START_SERVER];
        if (isLoginStartServer && ![[INQServiceManager sharedManager]isServerStated]) {
            DLog(@"The internet is working via WIFI. Start CIFS Server.");                 
            [[INQServiceManager sharedManager] startCifsServer];        
        }        
    }
    //[[INQServiceManager sharedManager] startBrowser];
}

- (void)stopAllService {
    //[[INQServiceManager sharedManager] stopBrowser];
    [[INQServiceManager sharedManager] stopCifsServer];
    [[INQServiceManager sharedManager] stopNetBios];    
}

/**
 * @brief イメージファイルのリサイズ処理
 */
- (UIImage *)resizeImage: (NSString *)imageFilePath image_size:(NSInteger)length
{
    UIImage *img_before = [UIImage imageNamed:imageFilePath];
    UIImage *img_after;
    UIGraphicsBeginImageContextWithOptions(CGSizeMake(length, length), NO, 0.0);
    [img_before drawInRect:CGRectMake(0, 0, length, length)];
    img_after = UIGraphicsGetImageFromCurrentImageContext();
    UIGraphicsEndImageContext();
    
    return img_after;
}

/**
 * @brief 背景色共通設定処理(ナビゲーションバー、ツールバー用)
 */
-(UIColor *)setBarColor
{
    return [UIColor colorWithRed:49.0f/255.f green:99.f/255.f blue:149.f/255.f alpha:1.0];
}

#pragma mark -
#pragma mark - init document directory 

- (void)initDocumentDirectory {
    BOOL isFirst = [[NSUserDefaults standardUserDefaults] boolForKey:@"First"];
    if (isFirst) {
        return;
    }
    DLog(@"Initialize data.")
    // Initialize Document Folder
    
    NSString* documentsDirectory = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];    
    NSString *publicPath = [documentsDirectory stringByAppendingPathComponent:NSLocalizedString(@"Public",@"Public folder")];
    NSString *dataPath = [documentsDirectory stringByAppendingPathComponent:NSLocalizedString(@"Doc",@"Document folder")];

    NSString *imagePath = [documentsDirectory stringByAppendingPathComponent:NSLocalizedString(@"Image",@"Image Folder")];

    
    if (![[NSFileManager defaultManager] fileExistsAtPath:publicPath])
        [[NSFileManager defaultManager] createDirectoryAtPath:publicPath withIntermediateDirectories:NO attributes:nil error:nil]; 
    
    if (![[NSFileManager defaultManager] fileExistsAtPath:dataPath])
        [[NSFileManager defaultManager] createDirectoryAtPath:dataPath withIntermediateDirectories:NO attributes:nil error:nil]; 

    if (![[NSFileManager defaultManager] fileExistsAtPath:imagePath])
        [[NSFileManager defaultManager] createDirectoryAtPath:imagePath withIntermediateDirectories:NO attributes:nil error:nil];

    
    // auto start server.
    [[NSUserDefaults standardUserDefaults]setBool:NO forKey:IS_AUTO_START_SERVER];
    [[NSUserDefaults standardUserDefaults]setBool:YES forKey:@"First"];
    
    // default share folder.
    INQShareFolder *folderObj = [[INQShareFolder alloc]init];
    
    [folderObj setFolderId:publicPath];
    [folderObj setPath:documentsDirectory];
    [folderObj setFolderName:NSLocalizedString(@"Public",@"Public folder.")];
    [folderObj setSecurity:NO];
    [folderObj setGuest:YES];
    [folderObj setShare:YES];
    [folderObj setUserName:@"guest"];
    [folderObj setPassword:@"guest"];
    [INQSharedFolderDataSource saveData:folderObj];
    [folderObj release];
    
  
}


#pragma mark -
#pragma mark register notification.
- (void)registerNotification {
    DLog(@"Register Notification.");
    [[NSNotificationCenter defaultCenter] addObserver:self.viewController selector:@selector(netBiosDaemonStarted) name:NETBIOS_DAEMON_STARTED object:nil];
    
    [[NSNotificationCenter defaultCenter] addObserver:self.viewController selector:@selector(cifsServerStarted) name:CIFS_SERVER_STARTED object:nil];
    [[NSNotificationCenter defaultCenter] addObserver:self.viewController selector:@selector(cifsServerClosed) name:CIFS_SERVER_CLOSED object:nil];
    [[NSNotificationCenter defaultCenter] addObserver:self.viewController selector:@selector(browserDaemonStarted) name:BROWSER_DAEMON_STARTED object:nil];
    [[NSNotificationCenter defaultCenter] addObserver:self.viewController selector:@selector(browserDaemonClosed) name:BROWSER_DAEMON_CLOSED object:nil];
    
    [[NSNotificationCenter defaultCenter] addObserver:self.viewController selector:@selector(netBiosDaemonStarted) name:NETBIOS_DAEMON_STARTED object:nil];
    
    [[NSNotificationCenter defaultCenter] addObserver:self.viewController selector:@selector(netBiosDaemonClosed) name:NETBIOS_DAEMON_CLOSED object:nil];     
}

#pragma mark -
#pragma mark Reachability

- (void)checkNetworkStatus:(NSNotification *)notice {
    // called after network status changes
    
    NetworkStatus internetStatus = [internetReachable currentReachabilityStatus];
    
    switch (internetStatus) {
        case NotReachable: {
            wifi = NO;
            DLog(@"The internet is down."); 
            break;
        }
        case ReachableViaWiFi: {
            wifi = YES;
            BOOL isLoginStartServer = [[NSUserDefaults standardUserDefaults] boolForKey:IS_AUTO_START_SERVER];
            if (isLoginStartServer && ![[INQServiceManager sharedManager]isServerStated]) {
                DLog(@"The internet is working via WIFI. Start CIFS Server.");                 
                // [[INQServiceManager sharedManager] startCifsServer];        
            }
            break;
        }
        case ReachableViaWWAN: {
            wifi = NO;
            if ([[INQServiceManager sharedManager]isServerStated]) {
                DLog(@"The internet is working via WWAN. Stop CIFS Server.");                  
                
                //  [[INQServiceManager sharedManager] stopCifsServer];        
            }
            break;
        }
    }
    
}


#pragma mark -
#pragma mark wifi ipaddress.

- (NSString *)getIPAddress {
    NSString *address = @"0.0.0.0";
    struct ifaddrs *interfaces = NULL;
    struct ifaddrs *temp_addr = NULL;
    int success = 0;
    
    // retrieve the current interfaces - returns 0 on success
    success = getifaddrs(&interfaces);
    if (success == 0) {
        // Loop through linked list of interfaces
        temp_addr = interfaces;
        while(temp_addr != NULL) {
            if(temp_addr->ifa_addr->sa_family == AF_INET) {
                // Check if interface is en0 which is the wifi connection on the iPhone
                if([[NSString stringWithUTF8String:temp_addr->ifa_name] isEqualToString:@"en0"]) {
                    // Get NSString from C String
                    address = [NSString stringWithUTF8String:inet_ntoa(((struct sockaddr_in *)temp_addr->ifa_addr)->sin_addr)];
                }
            }
            
            temp_addr = temp_addr->ifa_next;
        }
    }
    
    // Free memory
    freeifaddrs(interfaces);
    
    return address;
}



- (BOOL)application:(UIApplication *)application openURL:(NSURL*)url sourceApplication:(NSString *)sourceApplication annotation:(id)annotation {
    DLog(@"URL Schema:%@",[url path]);
    NSAssert(url != nil,@"URLSchema url is null.");
    if ([[url scheme] isEqualToString:@"inq"]) {
        NSString *computerId = nil;
        NSString *computerName = [url host];
        // NSArray *arr = [computerName componentsSeparatedByString:@"//"];
        // computerName = [arr objectAtIndex:0];
        NSInteger key = [[NSUserDefaults standardUserDefaults] integerForKey:@"KEY"];
        key++;        
        
        computerId = [NSString stringWithFormat:@"%d",(int)key];
        [[NSUserDefaults standardUserDefaults] setInteger:key forKey:@"KEY"];
        
        NSMutableDictionary *data = [[NSMutableDictionary alloc]init];
        
        [data setValue:computerId forKey:COMPUTER_ID];
        [data setValue:computerName forKey:DISPLAY_NAME];
        [data setValue:@"guest" forKey:USER_NAME];
        [data setValue:@"" forKey:PASSWORD];
        [data setValue:computerName forKey:COMPUTER];
        [data setValue:@"workgroup" forKey:WORKGROUP];
        
        NSMutableDictionary *org = [[NSUserDefaults standardUserDefaults] objectForKey:COMPUTERS];
        
        if (org == nil) {
            org = [[[NSMutableDictionary alloc]init]autorelease];
        }
        NSMutableDictionary *orgdic = [NSMutableDictionary dictionaryWithDictionary:org];
        [orgdic setValue:data forKey:computerId];
        
        [[NSUserDefaults standardUserDefaults] setObject:orgdic forKey:COMPUTERS];
        [[NSUserDefaults standardUserDefaults] synchronize];        
        
        INQWorkgroupViewController *controller = [[INQWorkgroupViewController alloc]init];
        [self.naviController pushViewController:controller animated:YES];
        [controller release];       
        [data release];
        return YES;
    }
    
    INQLocalViewController *controller = [[INQLocalViewController alloc]initWithStyle:UITableViewStyleGrouped];
    [self.naviController pushViewController:controller animated:YES];
    //  [controller loadDataFromServer:NO];
    [controller release];
    
    
    return YES;
}



@end
