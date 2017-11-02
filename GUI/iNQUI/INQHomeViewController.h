
#import <UIKit/UIKit.h>
#import "INQ.h"
#import "INQWorkgroupViewController.h"
#import "INQImagePickerController.h"
#import "INQServiceManager.h"
#import "Reachability.h"
#import "INQLocalViewController.h"
#import "INQFileListViewController.h"
#import "INQLocalViewController.h"
#import "INQAlbumPickerController.h"
#import "INQAppDelegate.h"
#import "INQSettingViewController.h"
#import "INQBookMarkViewController.h"

#import "INQRemoteTargetsViewController.h"


#import <MessageUI/MessageUI.h>
#import <MessageUI/MFMessageComposeViewController.h>


#include "cmapi.h"

@interface INQHomeViewController : UIViewController<MFMessageComposeViewControllerDelegate,UIActionSheetDelegate,MFMailComposeViewControllerDelegate> {
    Reachability *internetReachable;    
    UILabel *ipAddress;
    UIImageView *onOffImageView_;
}


@property (nonatomic,retain) IBOutlet UILabel *ipAddress;
@property (nonatomic,retain) UIImageView *onOffImageView;
@property (nonatomic,retain) IBOutlet UIButton *smsButton;

- (IBAction)localFile:(id)sender;
- (IBAction)workgroup:(id)sender;
- (IBAction)favorites:(id)sender;
- (IBAction)help:(id)sender;
- (IBAction)startServer:(id)sender;
- (IBAction)setting:(id)sender;

- (void) checkNetworkStatus:(NSNotification *)notice;

- (IBAction)displaySMSComposerSheet;

- (IBAction)openURL:(id)sender;

@end
