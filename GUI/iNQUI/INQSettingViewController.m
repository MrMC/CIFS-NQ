
#import "INQSettingViewController.h"

@interface INQSettingViewController ()

@end

@implementation INQSettingViewController

/**
 * @brief 色定義関数(ナビゲーションバー、ツールバー用) 画面個別設定用
 */
-(UIColor *)COLOR_BAR
{
    return [UIColor colorWithRed:112.0f/255.f green:186.f/255.f blue:36.f/255.f alpha:0.8];
}

- (id)initWithStyle:(UITableViewStyle)style {
    self = [super initWithStyle:style];
    if (self) {
        // Custom initialization
    }
    return self;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.navigationController.navigationBar.hidden = NO;   
#if 1
    // 画面のスクロールを有効
    [self.tableView setScrollEnabled:YES];
#else
    [self.tableView setScrollEnabled:NO];
#endif
    self.title = NSLocalizedString(@"Setting", @"Setting");
    // check for internet connection
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(checkNetworkStatus:) name:kReachabilityChangedNotification object:nil];
    
    internetReachable = [[Reachability reachabilityForInternetConnection] retain];
    [internetReachable startNotifier];
    INQAppDelegate *app = (INQAppDelegate*)[[UIApplication sharedApplication]delegate];
    isWifi = app.isWifi;
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(cifsServerStarted) name:CIFS_SERVER_STARTED object:nil];
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(cifsServerClosed) name:CIFS_SERVER_CLOSED object:nil]; 
    BOOL isAuto = [[NSUserDefaults standardUserDefaults] boolForKey:IS_AUTO_START_SERVER];
    if (isAuto) {
        startBegin = YES;
    }
    
#if 0
    // 設定画面に遷移後の戻るボタンの配置を統一化する為の変更
#if 1
    // 完了ボタンの文言変更
    UIBarButtonItem *doneButtonItem = [[UIBarButtonItem alloc]
                                       initWithTitle:NSLocalizedString(@"Back", @"Back")
                                       style:UIBarButtonItemStyleDone
                                       target:self
                                       action:@selector(done)];
#else
    UIBarButtonItem *doneButtonItem = [[UIBarButtonItem alloc]
                                       initWithBarButtonSystemItem:UIBarButtonSystemItemDone 
                                       target:self 
                                       action:@selector(done)];
#endif
    doneButtonItem.tag = 100;
    self.navigationItem.rightBarButtonItem = doneButtonItem;
    [doneButtonItem release];    
#endif
    
    if ([[INQServiceManager sharedManager] isServerStated]) {
        serverStatus = NSLocalizedString(@"ServerStatus:ON", @"server status");        
    } else {
        serverStatus = NSLocalizedString(@"ServerStatus:OFF", @"server status");        
    }
    
#if 1
    // ナビゲーションバーの背景色設定
    self.navigationController.navigationBar.tintColor = [app setBarColor];
#endif

    // ---------------------------------------------------------------------
    // iOS7以降対応 : UINavigationBarとStatusBarをUIViewに上被せで表示させない処理
    if ([[[[UIDevice currentDevice] systemVersion] componentsSeparatedByString:@"."][0] intValue] >= 7)
    {
        self.edgesForExtendedLayout = UIRectEdgeNone;
    }
}

/**
 * @brief Viewが表示される直前に呼び出される処理
 */
- (void)viewWillAppear:(BOOL)animated
{
    [super viewWillAppear:animated];

    // ナビゲーションバー 表示設定(有効)
    self.navigationController.navigationBar.hidden = NO;
    // ツールバー 表示設定(有効)
    self.navigationController.toolbarHidden = YES;
    
    INQAppDelegate *app = (INQAppDelegate*)[[UIApplication sharedApplication]delegate];
    // current iOS version is after 7
    if ([[[[UIDevice currentDevice] systemVersion] componentsSeparatedByString:@"."][0] intValue] >= 7)
    {
        // set navigation bar color
        [self.navigationController.navigationBar setBarTintColor:[app setBarColor]];
        
        // set navigation title color
        [self.navigationController.navigationBar setTitleTextAttributes:[NSDictionary dictionaryWithObject:[UIColor whiteColor] forKey:UITextAttributeTextColor]];
        
        // set navigation bar button arrow color
        self.navigationController.navigationBar.tintColor = [UIColor whiteColor];

        // set navigation bar button color
        [[UIBarButtonItem appearanceWhenContainedIn:[UINavigationBar class], nil]
         setTitleTextAttributes:[NSDictionary dictionaryWithObjectsAndKeys:[UIColor whiteColor],
                                 UITextAttributeTextColor, nil] forState:UIControlStateNormal];
    }
    else
    {
        // 画面遷移にトランジションを適応した場合、iOS6以前でもtintColorの設定が必要
        self.navigationController.navigationBar.tintColor = [app setBarColor];
        self.navigationController.toolbar.tintColor = [app setBarColor];
    }
}

- (void)done {
	[self dismissViewControllerAnimated:YES completion:NULL];
}

- (void)viewDidUnload {
    [super viewDidUnload];

}
- (void)dealloc {
    [internetReachable release];
    [super dealloc];
}

- (BOOL)shouldAutorotateToInterfaceOrientation:(UIInterfaceOrientation)interfaceOrientation {
    return (interfaceOrientation == UIInterfaceOrientationPortrait);
}

#pragma mark - Table view data source

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView
{
    return 4;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    
#if 1
    if ((section == 2) || (section == 3))
    {
        return 1;
    }
    
    return 2;
#else
    if (section == 0) {
        return 3;
    } else if(section == 1 || section == 2) {
        return 1;
    }
    return 2;
#endif
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    static NSString *CellIdentifier = @"Cell";
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:CellIdentifier];
    if(cell == nil) {
        cell = [[[UITableViewCell alloc]
                initWithStyle:UITableViewCellStyleDefault reuseIdentifier:CellIdentifier]autorelease];
        [cell.detailTextLabel setTextAlignment:NSTextAlignmentRight];
        cell.selectionStyle = UITableViewCellSelectionStyleNone;
    }

    if (indexPath.section == 0) {
        if (indexPath.row == 0) {
                    
            [cell.textLabel setText:NSLocalizedString(@"ServerController",@"Server switch controller.")];
            UISwitch *serverSwitch = [[UISwitch alloc]initWithFrame:CGRectZero];
            [serverSwitch addTarget:self action:@selector(serverController:) forControlEvents:UIControlEventValueChanged];
            cell.accessoryView = serverSwitch;
            BOOL started = [[INQServiceManager sharedManager]isServerStated];
            [serverSwitch setOn:started];
#if 0
            // アイコン非表示化
            [cell.imageView setImage:[UIImage imageNamed:@"connect_icon&24.png"]];
#endif
            BOOL isAuto = [[NSUserDefaults standardUserDefaults] boolForKey:IS_AUTO_START_SERVER];
            
            // NO1
            
            if (isAuto) {
                [serverSwitch setEnabled:NO];
            } else {       
                [serverSwitch setEnabled:YES];
            }
            
            if ((startBegin && startEnd) || (!startBegin && !startEnd)) {
                [serverSwitch setEnabled:YES];
            } 
            
            // NO2
            
            // NO3
            if (!isWifi) {
                serverSwitch.enabled = NO;
            } 
            [serverSwitch release];            
        }
        
#if 1
        // テーブルの構成変更
        if (indexPath.row == 1) {
            [cell.textLabel setText:NSLocalizedString(@"AutoStartServer",@"AutoStartServer")];
            UISwitch *serverStartSwitch = [[UISwitch alloc]initWithFrame:CGRectZero];
            [serverStartSwitch addTarget:self action:@selector(serverAutoStartController:) forControlEvents:UIControlEventValueChanged];
            serverStartSwitch.tag = 100;
            cell.accessoryView = serverStartSwitch;
            
            BOOL isAuto = [[NSUserDefaults standardUserDefaults] boolForKey:IS_AUTO_START_SERVER];
            [serverStartSwitch setOn:isAuto];
#if 0
            // アイコン非表示化
            [cell.imageView setImage:[UIImage imageNamed:@"on-off_icon&24.png"]];
#endif
            [serverStartSwitch release];
        }
#else
        if (indexPath.row == 1) {
            cell.textLabel.text = NSLocalizedString(@"SharedFolderPassword", @"SET Shared Folder Password");
            [cell setAccessoryType:UITableViewCellAccessoryDisclosureIndicator];
        }
        
        if (indexPath.row == 2) {
            cell.textLabel.text = NSLocalizedString(@"EditWorkgroupName", @"EditWorkgroupName");
            [cell setAccessoryType:UITableViewCellAccessoryDisclosureIndicator];
        }        
#endif
    }

    
    if (indexPath.section == 1) {
#if 1
        // テーブルの構成変更
        if (indexPath.row == 0) {
            cell.textLabel.text = NSLocalizedString(@"EditWorkgroupName", @"EditWorkgroupName");
            [cell setAccessoryType:UITableViewCellAccessoryDisclosureIndicator];
        }
        
        if (indexPath.row == 1) {
            cell.textLabel.text = NSLocalizedString(@"SharedFolderPassword", @"SET Shared Folder Password");
            [cell setAccessoryType:UITableViewCellAccessoryDisclosureIndicator];
        }
#else
        [cell.textLabel setText:NSLocalizedString(@"AutoStartServer",@"AutoStartServer")];
        UISwitch *serverStartSwitch = [[UISwitch alloc]initWithFrame:CGRectZero];
        [serverStartSwitch addTarget:self action:@selector(serverAutoStartController:) forControlEvents:UIControlEventValueChanged];
        serverStartSwitch.tag = 100;
        cell.accessoryView = serverStartSwitch;	
                                       
        BOOL isAuto = [[NSUserDefaults standardUserDefaults] boolForKey:IS_AUTO_START_SERVER];
        [serverStartSwitch setOn:isAuto];
#if 0
        // アイコン非表示化
        [cell.imageView setImage:[UIImage imageNamed:@"on-off_icon&24.png"]];
#endif
        [serverStartSwitch release];        
#endif
    }
    
    if (indexPath.section == 2) {
        [cell.textLabel setText:NSLocalizedString(@"ThumnailPreview",@"ThumnailPreview")];
        UISwitch *thumnailSwitch = [[UISwitch alloc]initWithFrame:CGRectZero];
        [thumnailSwitch addTarget:self action:@selector(thumbnailSwitch:) forControlEvents:UIControlEventValueChanged];
        thumnailSwitch.tag = 200;
        cell.accessoryView = thumnailSwitch;	
        
        BOOL isAuto = [[NSUserDefaults standardUserDefaults] boolForKey:@"THUMNAIL_PREVIEW"];
        [thumnailSwitch setOn:isAuto];
        //[cell.imageView setImage:[UIImage imageNamed:@"on-off_icon&24.png"]];
        [thumnailSwitch release];         
    }
    
    if (indexPath.section == 3) {
#if 1
        // セクション3はバージョンを表示
        if (indexPath.row == 0)
        {
            [cell.textLabel setText:[[NSBundle mainBundle] objectForInfoDictionaryKey: @"CFBundleVersion"]];
        }
#else
        if (indexPath.row == 0) {
            [cell.textLabel setText:NSLocalizedString(@"Help", @"Help")];
            [cell setAccessoryType:UITableViewCellAccessoryDisclosureIndicator];
        }
        if (indexPath.row == 1) {
            
            [cell.textLabel setText:NSLocalizedString(@"Version",@"Version")];
            [cell.detailTextLabel setText:[[NSBundle mainBundle]
                                            objectForInfoDictionaryKey: @"CFBundleVersion"]];
            UILabel *version = [[UILabel alloc]init];
            version.text = [[NSBundle mainBundle]
                            objectForInfoDictionaryKey: @"CFBundleVersion"];
            version.frame = CGRectMake(0, 0, 50, 40);
            version.backgroundColor = [UIColor clearColor];
            cell.accessoryView = (UIView *)[NSString stringWithFormat:@"%@ Build:%@", version,BUILD];
            [version release];
        }
#endif
    }    
    return cell;
}

- (void)serverController:(id)sender {
    UISwitch *sw = (UISwitch*)sender;
    DLog(@"started %d",sw.isOn);
    if (sw.isOn) {
        UITableViewCell *cell = [self.tableView cellForRowAtIndexPath:[NSIndexPath indexPathForRow:0 inSection:0]];
        UIActivityIndicatorView *loadingView = [[UIActivityIndicatorView alloc]initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleGray];
        cell.accessoryView = loadingView;
        [loadingView startAnimating];
        [loadingView release];
        
        serverStatus = NSLocalizedString(@"Start Server...", @"server status");
        self.title = serverStatus;
        [[INQServiceManager sharedManager] startCifsServer];
       // [sw setOn:YES];      
        startBegin = YES;
        //[sw setEnabled:NO];
        for (UIView *v in [self.navigationController.view subviews]) {
            [v setUserInteractionEnabled:NO];
        }
        for (UIView *v in [self.view subviews]) {
            [v setUserInteractionEnabled:NO];
        }  

        
    } else if (!sw.isOn && [[INQServiceManager sharedManager] isServerStated]) {
        
        startBegin = NO;
        startEnd = NO;
        
        [[INQServiceManager sharedManager] stopCifsServer];        
        [sw setOn:NO];
        [sw setEnabled:NO];
    }

}

- (void)thumbnailSwitch:(id)sender {
    UISwitch *sw = (UISwitch*)sender;
    BOOL isAuto = [[NSUserDefaults standardUserDefaults] boolForKey:@"THUMNAIL_PREVIEW"];
    [sw setOn:!isAuto];
    [[NSUserDefaults standardUserDefaults]setBool:!isAuto forKey:@"THUMNAIL_PREVIEW"];

    [[NSUserDefaults standardUserDefaults] synchronize];
}

- (void)serverAutoStartController:(id)sender {
    UISwitch *sw = (UISwitch*)sender;
    BOOL isAuto = [[NSUserDefaults standardUserDefaults] boolForKey:IS_AUTO_START_SERVER];
    [sw setOn:!isAuto];
    [[NSUserDefaults standardUserDefaults]setBool:!isAuto forKey:IS_AUTO_START_SERVER];

    [[NSUserDefaults standardUserDefaults] synchronize];
}

- (UIView *)tableView:(UITableView *)tableView viewForHeaderInSection:(NSInteger)section
{
    UIView *sectionView;
    UILabel *textLabel;
    if ([[[[UIDevice currentDevice] systemVersion] componentsSeparatedByString:@"."][0] intValue] >= 7)
    {
        sectionView = [[[UIView alloc]initWithFrame:CGRectMake(0, 0, [UIScreen mainScreen].bounds.size.width, 50)]autorelease];
        textLabel = [[[UILabel alloc]initWithFrame:CGRectMake(10, 20, [UIScreen mainScreen].bounds.size.width, 30)]autorelease];
    }
    else
    {
        sectionView = [[[UIView alloc]initWithFrame:CGRectMake(0, 0, [UIScreen mainScreen].bounds.size.width, 40)]autorelease];
        textLabel = [[[UILabel alloc]initWithFrame:CGRectMake(10, 15, [UIScreen mainScreen].bounds.size.width, 20)]autorelease];
    }
    
    sectionView.backgroundColor = [UIColor clearColor];
    
    textLabel.backgroundColor = [UIColor clearColor];
    textLabel.textColor = [UIColor darkGrayColor];
    textLabel.font = [UIFont boldSystemFontOfSize:16.0f];
    textLabel.shadowColor = [UIColor whiteColor];
    textLabel.shadowOffset = CGSizeMake(0, 1);

    switch(section) {
        case 0:
            textLabel.text = serverStatus;
            break;
        case 1:
            textLabel.text = NSLocalizedString(@"AutoStart", @"AutoStart");
            break;
        case 2:
            textLabel.text = NSLocalizedString(@"PreviewSettingTitle", @"PreviewSettingTitle");
             break;
        case 3:
            textLabel.text = NSLocalizedString(@"Version",@"Version");
            break;
        default:
            break;
    }
    
    [sectionView addSubview:textLabel];
    
    return sectionView;
}

- (CGFloat)tableView:(UITableView *)tableView heightForHeaderInSection:(NSInteger)section
{
    CGFloat heightSection;
    if ([[[[UIDevice currentDevice] systemVersion] componentsSeparatedByString:@"."][0] intValue] >= 7)
    {
        heightSection = 50.0f;
    }
    else
    {
        heightSection = 40.0f;
    }
    
    return heightSection;
}

- (NSString*)tableView:(UITableView *)tableView titleForFooterInSection:(NSInteger)section {
    switch (section) {
        case 0: {
            INQAppDelegate *app = (INQAppDelegate*)[[UIApplication sharedApplication]delegate]; 
            return [NSString stringWithFormat:@"%@:%@", NSLocalizedString(@"AccessIP(WIFI ONLY)", @"AccessIP") ,[app getIPAddress]];
            break;
        }
#if 0
        case 1:
            return [NSString stringWithFormat:@"%@", NSLocalizedString(@"AutoStart<iNQServer>",@"AutoStartNQServer")];
#endif
        default:
            break;
    }
    return nil;
}


#pragma mark - Table view delegate

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {

#if 1
    // テーブルの構成変更
    if (indexPath.section == 1) {
        if (indexPath.row == 1) {
#else
    if (indexPath.section == 0) {
        if (indexPath.row == 1) {
#endif
#if 1
            // UserID Passwrod 設定をアラート画面にて実施する様に変更
            NSString* message = nil;
            NSString* buttonTitleCancel = @"Cancel";
            NSString* buttonTitleOK = @"OK";
            
            UIAlertView* alert = [[UIAlertView alloc] initWithTitle:NSLocalizedString(@"SharedFolderPassword", @"SharedFolderPassword")
                                                            message:message
                                                           delegate:self
                                                  cancelButtonTitle:buttonTitleCancel
                                                  otherButtonTitles:buttonTitleOK,nil];
            
            alert.alertViewStyle = UIAlertViewStyleLoginAndPasswordInput;
            
            [[alert textFieldAtIndex:0] setPlaceholder:NSLocalizedString(@"UserID", @"UserID")];
            
            UITextField *textFieldLocal = [alert textFieldAtIndex:0];
            UITextField *textFieldLocal2 = [alert textFieldAtIndex:1];
            
            // alertView識別用タグの設定
            alert.tag = 1003;
            
            // init a text field in a UIAlertView
            [textFieldLocal setAutocorrectionType:UITextAutocorrectionTypeNo];
            [textFieldLocal2 setAutocorrectionType:UITextAutocorrectionTypeNo];

            [textFieldLocal setText:[[NSUserDefaults standardUserDefaults] objectForKey:@"USERID"]];
            [textFieldLocal2 setText:[[NSUserDefaults standardUserDefaults] objectForKey:@"PASSWORD"]];

            [alert show];
            [alert release];

#else
            INQSetUserPasswordViewController *controller = [[INQSetUserPasswordViewController alloc]init];
            [self.navigationController pushViewController:controller animated:YES];
            [controller release];
#endif
        }
        
#if 1
        // テーブルの構成変更
        if (indexPath.row == 0) {
#else
        if (indexPath.row == 2) {
#endif
#if 1
            // Workgroup名設定をアラート画面にて実施する様に変更
            NSString* message = Nil;
            NSString* buttonTitleCancel = @"Cancel";
            NSString* buttonTitleOK = @"OK";
            
            UIAlertView* alert = [[UIAlertView alloc] initWithTitle:NSLocalizedString(@"EditWorkgroupName", @"EditWorkgroupName")
                                                            message:message
                                                           delegate:self
                                                  cancelButtonTitle:buttonTitleCancel
                                                  otherButtonTitles:buttonTitleOK,nil];
            
            alert.alertViewStyle = UIAlertViewStylePlainTextInput;
            UITextField *textFieldLocal = [alert textFieldAtIndex:0];
            
            // alertView識別用タグの設定
            alert.tag = 1002;
            
            // init a text field in a UIAlertView
            [textFieldLocal setAutocorrectionType:UITextAutocorrectionTypeNo];
            // 保存済みワークグループ名を初期表示として設定
            [textFieldLocal setText:[[NSUserDefaults standardUserDefaults] objectForKey:@"WORKGROUP"]];
            [alert show];
            [alert release];
#else
            INQSetWorkgroupViewController *controller = [[INQSetWorkgroupViewController alloc]init];
            [self.navigationController pushViewController:controller animated:YES];
            [controller release];
#endif
        }        
    }
    
    if (indexPath.section == 2) {
        if (indexPath.row == 1) {
            // help
            INQHelpViewController *controller = [[INQHelpViewController alloc]init];
            [self.navigationController pushViewController:controller animated:YES];
            [controller release];
        }
    }
}

/**
 * @brief Alert用 ボタンクリックイベントハンドラ
 * @param [in] alertView Alert Viewオブジェクト
 * @param [in] buttonIndex ボタン用インデックス
 */
- (void)alertView:(UIAlertView *)alertView clickedButtonAtIndex:(NSInteger)buttonIndex
{
	if (buttonIndex == 1)
    {
        if(alertView.tag == 1002)
        {
            // textFieldの入力内容を取得
            NSString *inputText =
            [[[alertView textFieldAtIndex:0] text] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
            
            if ((inputText != nil) && (inputText.length > 0))
            {
                [[NSUserDefaults standardUserDefaults] setObject:inputText forKey:@"WORKGROUP"];

                [[NSUserDefaults standardUserDefaults] synchronize];
            }
        }
        else if(alertView.tag == 1003)
        {
            // textFieldの入力内容を取得
            NSString *inputUserId =
            [[[alertView textFieldAtIndex:0] text]
             stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
            NSString *inputPassword =
            [[[alertView textFieldAtIndex:1] text]
             stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];

            if ((inputUserId != nil) && (inputUserId.length > 0))

            {
                [[NSUserDefaults standardUserDefaults] setObject:[inputUserId uppercaseString] forKey:@"USERID"];
                
                [[NSUserDefaults standardUserDefaults] synchronize];
            }
            if ((inputPassword != nil) && (inputPassword.length > 0))
            {
                [[NSUserDefaults standardUserDefaults] setObject:inputPassword forKey:@"PASSWORD"];
                
                [[NSUserDefaults standardUserDefaults] synchronize];
            }
        }
	}
    else if( buttonIndex == 0)
    {
        /* DO NOTHING */
    }
}

#pragma mark -
#pragma mark Reachability

-(void) checkNetworkStatus:(NSNotification *)notice {
    // called after network status changes
    
    NetworkStatus internetStatus = [internetReachable currentReachabilityStatus];
    
    switch (internetStatus) {
        case NotReachable: {
            DLog(@"The internet is down."); 
            isWifi = NO;
            break;
        }
        case ReachableViaWiFi: {
            isWifi = YES;
            [self.tableView reloadData];
            break;
        }
        case ReachableViaWWAN: {
            isWifi = NO;
            [self.tableView reloadData];
            break;
        }
    }
    [self.tableView reloadData];    
}

#pragma mark - 
#pragma mark Server Status Notification

- (void)cifsServerStarted {
    for (UIView *v in [self.navigationController.view subviews]) {
        [v setUserInteractionEnabled:YES];
    }
    for (UIView *v in [self.view subviews]) {
        [v setUserInteractionEnabled:YES];
    }   

    startEnd = YES;
    serverStatus = NSLocalizedString(@"ServerStatus:ON", @"server status");
    self.title = serverStatus;
    [self.tableView reloadData];
}

- (void)cifsServerClosed {
    for (UIView *v in [self.navigationController.view subviews]) {
        [v setUserInteractionEnabled:YES];
    }
    for (UIView *v in [self.view subviews]) {
        [v setUserInteractionEnabled:YES];
    }      
    serverStatus = NSLocalizedString(@"ServerStatus:OFF", @"server status");
    self.title = serverStatus;    
    [self.tableView reloadData];
}


@end
