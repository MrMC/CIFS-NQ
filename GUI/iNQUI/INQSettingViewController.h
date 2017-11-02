
#import <UIKit/UIKit.h>
#import "Reachability.h"
#import "INQ.h"
#import "INQServiceManager.h"
#import "INQAppDelegate.h"
#import "INQSetUserPasswordViewController.h"
#import "INQHelpViewController.h"
#import "INQSetWorkgroupViewController.h"

@interface INQSettingViewController : UITableViewController {
    Reachability *internetReachable;   
    BOOL isWifi;
    BOOL startBegin;
    BOOL startEnd;
    NSString *serverStatus;
}

@end
