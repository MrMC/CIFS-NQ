
#include <ifaddrs.h>
#include <arpa/inet.h>

#import <UIKit/UIKit.h>
#import "Reachability.h"

#import "INQ.h"
#import "INQHomeViewController.h"
#import "INQServiceManager.h"
#import "INQSplashViewController.h"
#import "INQStatusWindow.h"
#import "INQNavigationBar.h"

@class INQSplashViewController;

@interface INQAppDelegate : UIResponder <UIApplicationDelegate> {
    INQStatusWindow *_inqStatusWindow;
    Reachability *internetReachable;
    UIBackgroundTaskIdentifier bgTask;
    BOOL wifi;
    BOOL typeAddWorkGroupView;      // ワークグループの新規追加画面 呼び出し元識別子
    NSInteger typeSelectedView;     // 選択画面識別子(DEF_VIEW_TYPE)
    BOOL isUpdateComputerInfo;
    NSString *backupComputerName;
}

@property (nonatomic,getter = isWifi) BOOL wifi;
@property (nonatomic,strong) UIWindow *window;
@property (nonatomic,strong) INQSplashViewController *viewController;
@property (nonatomic,strong) UINavigationController *naviController;
@property (nonatomic,strong) INQStatusWindow *inqStatusWindow;
@property (nonatomic) BOOL typeAddWorkGroupView;
@property (nonatomic) NSInteger typeSelectedView;
@property (nonatomic) BOOL isUpdateComputerInfo;
@property (nonatomic, retain)NSString *backupComputerName;
- (NSString *)getIPAddress;

- (UIImage *)resizeImage: (NSString *)imageFilePath image_size:(NSInteger)length;
- (UIColor *)setBarColor;
@end

typedef enum                        /* <列挙子定義> Main View Type */
{
    DEF_VIEW_UNDEFINE = 0,
    DEF_VIEW_LOCAL,
    DEF_VIEW_WORKGROUP,
    DEF_VIEW_SETTING,
    DEF_VIEW_HELP,
} DEF_VIEW_TYPE;
