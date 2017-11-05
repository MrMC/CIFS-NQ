
#import "INQHomeViewController.h"

@interface INQHomeViewController ()

@end

@implementation INQHomeViewController

@synthesize ipAddress;
@synthesize onOffImageView = onOffImageView_;
@synthesize smsButton;

- (id)initWithNibName:(NSString *)nibNameOrNil bundle:(NSBundle *)nibBundleOrNil {
    self = [super initWithNibName:nibNameOrNil bundle:nibBundleOrNil];
    if (self) {
        
    }
    return self;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor colorWithRed:238.0f/255.f 
                                                green:238.f/255.f 
                                                 blue:238.f/255.f 
                                                alpha:1.0];    
    self.ipAddress.userInteractionEnabled = YES;
 
    [[UIApplication sharedApplication] setStatusBarHidden:NO];    
    [self.navigationController setToolbarHidden:YES];  
    
    UIBarButtonItem *settingButtonItem = [[UIBarButtonItem alloc]
                                          initWithImage:[UIImage imageNamed:@"icon_setting.png"] 
                                          style:UIBarButtonItemStylePlain
                                          target:self 
                                          action:@selector(setting:)];
                                          
    self.navigationItem.rightBarButtonItem = settingButtonItem;
    [settingButtonItem release];


    // check for internet connection
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(checkNetworkStatus:) name:kReachabilityChangedNotification object:nil];
    
    internetReachable = [[Reachability reachabilityForInternetConnection] retain];
    [internetReachable startNotifier];
    
    onOffImageView_ = [[UIImageView alloc]init];
    self.onOffImageView.frame = CGRectMake(ipAddress.frame.origin.x - 30 , ipAddress.frame.origin.y, 24, 24);
#if 0
    // サーバー機能無効時はホーム画面上に特に表示無し
    [self.onOffImageView setImage:[UIImage imageNamed:@"on_icon&24.png"]];
#endif
    [self.view addSubview:self.onOffImageView];
    [smsButton setHidden:YES];
  //  DLog(@"HOST NAME: %@",[NSString stringWithUTF8String:hostname]);
    
    
}


- (void)dealloc {
#if 1
    // 'viewDidUnload' is deprecated: first deprecated in iOS6.0対応
    [onOffImageView_ release];
    onOffImageView_ = nil;
    [ipAddress release];
    ipAddress = nil;
#else
    [self viewDidUnload];
#endif
    [super dealloc];
}

- (void)viewDidUnload {
    [onOffImageView_ release];
    onOffImageView_ = nil;
    [ipAddress release];  
    ipAddress = nil;
    [super viewDidUnload];
}

- (BOOL)shouldAutorotateToInterfaceOrientation:(UIInterfaceOrientation)interfaceOrientation {
    return (interfaceOrientation == UIInterfaceOrientationPortrait);
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    self.navigationController.navigationBar.hidden = YES;   
    [self.navigationController setToolbarHidden:YES];    
    
    if (![[INQServiceManager sharedManager] isServerStated]) {

#if 1
        // サーバー機能無効時はホーム画面上に特に表示無し
        self.ipAddress.text = @"";
#else
        [self.onOffImageView setImage:[UIImage imageNamed:@"off_icon&24.png"]];
        self.ipAddress.text = @"0.0.0.0";
#endif

#if 1
        // 設定画面に遷移後の戻るボタンの配置を統一化する変更に関連する変更
        // イメージの非表示
        self.onOffImageView.image = nil;
#endif
        
        [smsButton setHidden:YES];
    } else {
        [self.onOffImageView setImage:[UIImage imageNamed:@"on_icon&24.png"]];
        INQAppDelegate *app = (INQAppDelegate*)[[UIApplication sharedApplication] delegate];
        [self.ipAddress setText:[NSString stringWithFormat:@"%@ (%s)", [app getIPAddress] ,cmGetFullHostName()]];  
        UITapGestureRecognizer *tapGesuture = [[UITapGestureRecognizer alloc]initWithTarget:self action:@selector(displaySMSComposerSheet)];
        tapGesuture.numberOfTapsRequired = 1;
        [self.ipAddress addGestureRecognizer:tapGesuture];
        [tapGesuture release];
        [smsButton setHidden:NO];        
    }
    DLog(@"Controller Count:[%d]",(int)[self.navigationController.childViewControllers count]);
}

#pragma mark -
#pragma mark IB Actions.

- (IBAction)localFile:(id)sender {
    INQLocalViewController *controller = [[INQLocalViewController alloc]initWithStyle:UITableViewStyleGrouped];

#if 1
    // ナビゲーションバーのタイトル識別子設定
    INQAppDelegate *app = (INQAppDelegate *)[[UIApplication sharedApplication] delegate];
    app.typeSelectedView = DEF_VIEW_LOCAL;
#endif

#if 1
    // Transition is adopted as screen changes.
    [UIView transitionFromView:self.view toView:controller.view
                      duration:0.5
                       options:UIViewAnimationOptionTransitionFlipFromRight
                    completion:nil];
    [self.navigationController pushViewController:controller animated:NO];
#else
    [self.navigationController pushViewController:controller animated:YES];
#endif
  //  [controller loadDataFromServer:NO];
    [controller release];
}

- (IBAction)workgroup:(id)sender {

    INQRemoteTargetsViewController *controller = [[INQRemoteTargetsViewController alloc]initWithStyle:UITableViewStyleGrouped];
    
    INQAppDelegate *app = (INQAppDelegate *)[[UIApplication sharedApplication] delegate];
    app.typeSelectedView = DEF_VIEW_WORKGROUP;
    
    // Transition is adopted as screen changes.
    [UIView transitionFromView:self.view toView:controller.view
                      duration:0.5
                       options:UIViewAnimationOptionTransitionFlipFromLeft
                    completion:nil];
    [self.navigationController pushViewController:controller animated:NO];
    
    
    [controller release];
    
    /*
    INQWorkgroupViewController *controller = [[INQWorkgroupViewController alloc]initWithStyle:UITableViewStyleGrouped];

    // ナビゲーションバーのタイトル識別子設定
    INQAppDelegate *app = (INQAppDelegate *)[[UIApplication sharedApplication] delegate];
    app.typeSelectedView = DEF_VIEW_WORKGROUP;

    // Transition is adopted as screen changes.
    [UIView transitionFromView:self.view toView:controller.view
                      duration:0.5
                       options:UIViewAnimationOptionTransitionFlipFromLeft
                    completion:nil];
    [self.navigationController pushViewController:controller animated:NO];
    [controller release];*/
}


- (IBAction)favorites:(id)sender {
    INQWorkgroupViewController *controller = [[INQWorkgroupViewController alloc]initWithStyle:UITableViewStyleGrouped];
    controller.isBookMark = YES;
    [self.navigationController pushViewController:controller animated:YES];
    [controller release]; 
}

- (IBAction)setting:(id)sender {
    INQAppDelegate *app = (INQAppDelegate *)[[UIApplication sharedApplication] delegate];
    
#if 1
    // ナビゲーションバーのタイトル識別子設定
    app.typeSelectedView = DEF_VIEW_SETTING;
#endif
    
    INQSettingViewController *controller = [[INQSettingViewController alloc]initWithStyle:UITableViewStyleGrouped];
#if 1
    // 設定画面に遷移後の戻るボタンの配置を統一化する変更に関連する変更
    // Transition is adopted as screen changes.
    [UIView transitionFromView:self.view toView:controller.view
                      duration:0.5
                       options:UIViewAnimationOptionTransitionCrossDissolve
                    completion:nil];
    [self.navigationController pushViewController:controller animated:NO];
    
    [controller release];
#else
    UINavigationController *navi = [[UINavigationController alloc]initWithRootViewController:controller];
    [app.viewController presentViewController:navi animated:YES completion:NULL];

    [controller release];
    [navi release];
#endif
}

- (IBAction)help:(id)sender {
    
#if 1
    // ヘルプ画面処理(暫定対応としてcifsのページを開く)
    NSURL *url = [NSURL URLWithString:@"http://www.visualitynq.com/index.php?option=com_content&task=view&id=51&itemid=43"];
    [[UIApplication sharedApplication] openURL:url];
#else
    INQAlbumPickerController *albumController = [[INQAlbumPickerController alloc] initWithNibName:@"INQAlbumPickerController" bundle:[NSBundle mainBundle]];    
    
    INQImagePickerController *inqPicker = [[INQImagePickerController alloc] initWithRootViewController:albumController];
    [albumController setParent:inqPicker];
    [inqPicker setDelegate:self];
    
    INQAppDelegate *app = (INQAppDelegate *)[[UIApplication sharedApplication] delegate];
    [app.viewController presentModalViewController:inqPicker animated:YES];
    [inqPicker release];
    [albumController release];
#endif
}

- (IBAction)startServer:(id)sender {
    //[self disableButton];
}


#pragma mark -
#pragma mark Reachability

-(void) checkNetworkStatus:(NSNotification *)notice {
    // called after network status changes
    
    NetworkStatus internetStatus = [internetReachable currentReachabilityStatus];
    
    switch (internetStatus) {
        case NotReachable: {
            DLog(@"The internet is down.");                       
            break;
        }
        case ReachableViaWiFi: {
            INQAppDelegate *app = (INQAppDelegate*)[[UIApplication sharedApplication] delegate];             
            [self.ipAddress setText:[NSString stringWithFormat:@"%@ (%s)", [app getIPAddress] ,cmGetFullHostName()]];  
            break;
        }
        case ReachableViaWWAN: {    
            break;
        }
    }
    
}

- (IBAction)displaySMSComposerSheet {
    UIActionSheet *as = [[UIActionSheet alloc] init];
    as.delegate = self;
    as.title = NSLocalizedString(@"Sahre", @"Sahre");
    [as addButtonWithTitle:NSLocalizedString(@"Email", @"Email")];
    [as addButtonWithTitle:NSLocalizedString(@"SMS", @"SMS")];
    [as addButtonWithTitle:NSLocalizedString(@"Cancel", @"Cancel")];
    as.cancelButtonIndex = 2;
    as.destructiveButtonIndex = 0;
    [as showInView:self.view];
    
}


-(void)actionSheet:(UIActionSheet*)actionSheet clickedButtonAtIndex:(NSInteger)buttonIndex {
    INQAppDelegate *app = (INQAppDelegate *)[[UIApplication sharedApplication] delegate]; 
    NSString *body = NSLocalizedString(@"SahreBody", @"Share folder message body");
    switch (buttonIndex) {
        case 0:
            if(![MFMailComposeViewController canSendMail]) {
                return;
            }
            MFMailComposeViewController *mailCont = [[MFMailComposeViewController alloc] init];
            mailCont.mailComposeDelegate = self;
            NSString *title = NSLocalizedString(@"ShareTitle", @"email share title.");
            [mailCont setSubject:title];
        //    [mailCont setToRecipients:[NSArray arrayWithObject:@"onkeyi@gmail.com"]];
            [mailCont setMessageBody:[NSString stringWithUTF8String:[[NSString stringWithFormat:@"%@\n inq://%@",body,[app getIPAddress]] UTF8String]] isHTML:NO];
            
            [self presentViewController:mailCont animated:YES completion:NULL];
            [mailCont release];
            
            break;
        case 1:
            if(![MFMessageComposeViewController canSendText]) {
                return;
            }
            
   
            MFMessageComposeViewController *picker = [[MFMessageComposeViewController alloc] init];
            picker.messageComposeDelegate = self;
            
            picker.body = [NSString stringWithUTF8String:[[NSString stringWithFormat:@"%@\n inq://%@",body,[app getIPAddress]] UTF8String]];
            
            //    picker.recipients = [NSArray arrayWithObjects:@"08054191688", nil];
            
            [self presentViewController:picker animated:YES completion:NULL];
            [picker release];
            break;
        case 2:

            break;
    }
    
}
- (void)mailComposeController:(MFMailComposeViewController*)controller didFinishWithResult:(MFMailComposeResult)result error:(NSError*)error {
    [self dismissViewControllerAnimated:YES completion:NULL];
}

- (void)messageComposeViewController:(MFMessageComposeViewController*)controller 
				 didFinishWithResult:(MessageComposeResult)result {
    [self dismissViewControllerAnimated:YES completion:NULL];
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    float mem = [self memory];
    if (mem < 4.0f) {
        //UIAlertView *alert = [[UIAlertView alloc]initWithTitle:@"MemoryWarning" message:@"close other app." delegate:nil cancelButtonTitle:@"OK" otherButtonTitles:nil, nil];
        //[alert show];
        UIAlertController * alert = [UIAlertController
                alertControllerWithTitle:@"MemoryWarning"
                                 message:@"close other app."
                          preferredStyle:UIAlertControllerStyleAlert];
        UIAlertAction* defaultAction = [UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault
                               handler:^(UIAlertAction * action) {}];

        [alert addAction:defaultAction];
        [self presentViewController:alert animated:YES completion:nil];
        [alert release];
    }
}

- (IBAction)openURL:(id)sender {
    NSURL *url = [NSURL URLWithString:@"http://www.visualitynq.com/index.php?option=com_content&task=view&id=51&itemid=43"];
    [[UIApplication sharedApplication] openURL:url];
}

#import <mach/mach.h>

#define kTimerInterval 1.0
#define tval2msec(tval) ((tval.seconds * 1000) + (tval.microseconds / 1000))

- (float)memory {
    struct vm_statistics a_vm_info;
    
    mach_msg_type_number_t a_count = HOST_VM_INFO_COUNT;
    
    host_statistics( mach_host_self(), HOST_VM_INFO, (host_info_t)&a_vm_info ,&a_count);
    
    return ((a_vm_info.free_count * vm_page_size)/1024.0)/1024.0;
    
}
@end
