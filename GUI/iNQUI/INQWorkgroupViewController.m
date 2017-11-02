
#import "INQWorkgroupViewController.h"

#import "udconfig.h"
#import "INQAppDelegate.h"

@interface INQWorkgroupViewController()
{
    NSMutableArray          *data_;             // 保存データ用
    NSMutableArray          *dataTmp_;          // 検索データ用
    INQComputerDataSource   *dataSource;        //
    UITextField             *textField;         // エラー表示用テキスト領域
    NSString                *workgroupName;     // ワークグループ名格納先
    BOOL                    loadedDomains;
    BOOL                    pressedDomain;
}

@end

@implementation INQWorkgroupViewController
@synthesize data = data_;
@synthesize dataTmp = dataTmp_;
@synthesize domainList;
@synthesize isBookMark;

@synthesize loadingView;
@synthesize indicator;
@synthesize loadingMessageLabel;
@synthesize backupDataTmpIndex;

/**
 * @brief 色定義関数(ナビゲーションバー、ツールバー用) 画面個別設定用
 */
-(UIColor *)COLOR_BAR
{
    return [UIColor colorWithRed:82.0f/255.f green:158.f/255.f blue:255.f/255.f alpha:0.8];
}

- (id)initWithNibName:(NSString *)nibNameOrNil bundle:(NSBundle *)nibBundleOrNil
{
    self = [super initWithNibName:nibNameOrNil bundle:nibBundleOrNil];
    if (self)
    {
        // Custom initialization
        data_ = [[NSMutableArray alloc]init];             

        dataTmp_ = [[NSMutableArray alloc]init];
        domainList = [[NSMutableArray alloc]init];
        
        dataSource = [[INQComputerDataSource alloc]init];
        [dataSource loadData:NO];
        dataSource.delegate = self;
        /*dispatch_async(dispatch_get_main_queue(), ^{
            [dataSource getWorkgroups];});*/
        loadedDomains = NO;
        pressedDomain = NO;
    }
    return self;
}

/**
 * @brief Viewが初めて呼び出される時に実行される処理(1回だけ)
 */
- (void)viewDidLoad
{
    [super viewDidLoad];
    // ナビゲーションバー 非表示設定：無効
    self.navigationController.navigationBarHidden = NO;
    // ナビゲーションバー タイトル設定
    self.title = NSLocalizedString(@"WorkGroup",@"workgroup title");
    // テーブルビュー 背景色設定
    self.tableView.backgroundColor = [UIColor colorWithRed:238.0f/255.f
                                                     green:238.f/255.f
                                                      blue:238.f/255.f
                                                     alpha:1.0];
    [self done:self];

    //dataSource = [[INQComputerDataSource alloc]init];
    //self.tableView.dataSource = dataSource;
    
    //[dataSource setDelegate:self];
    //self.tableView.delegate = self;
    
    //[dataSource getWorkgroups];
    

    INQAppDelegate *app = (INQAppDelegate *)[[UIApplication sharedApplication] delegate];
    
    // ナビゲーションバー 背景色
    self.navigationController.navigationBar.tintColor = [app setBarColor];

    // ツールバー(タブバー) 背景色
    self.navigationController.toolbar.tintColor = [app setBarColor];

    // テーブルビュー セル仕切り色
    self.tableView.separatorColor = [UIColor colorWithRed:153.0f/255.f 
                                                    green:51.f/255.f 
                                                     blue:0.f/255.f 
                                                    alpha:0.5];
    
    self.tableView.separatorStyle = UITableViewCellSeparatorStyleSingleLine;

    CGRect screen = [[UIScreen mainScreen] bounds];
    
    self.tableView.frame = CGRectMake(0, 0, screen.size.width, screen.size.height - 100);

    // Image of bar button
    /*UIBarButtonItem *newFolderButton;
    if ([[[[UIDevice currentDevice] systemVersion] componentsSeparatedByString:@"."][0] intValue] >= 7)
    {
        UIButton *barBtnNewComputer = [[[UIButton alloc]initWithFrame:CGRectMake(0, 0, 32, 32)]autorelease];
        [barBtnNewComputer setBackgroundImage:[app resizeImage:@"icon_newhost.png" image_size:32] forState:UIControlStateNormal];
        [barBtnNewComputer addTarget:self action:@selector(addWorkgroup) forControlEvents:UIControlEventTouchUpInside];
        barBtnNewComputer.showsTouchWhenHighlighted = YES;
        
        newFolderButton = [[UIBarButtonItem alloc]initWithCustomView:barBtnNewComputer];
    }
    else
    {
        newFolderButton = [[UIBarButtonItem alloc]initWithImage:[app resizeImage:@"icon_newhost.png" image_size:32]
                                                          style:UIBarButtonItemStylePlain
                                                         target:self
                                                         action:@selector(addWorkgroup)];
    }
    */
    // タブバーボタン(余白)
    UIBarButtonItem *spaceButton =
            [[UIBarButtonItem alloc]initWithBarButtonSystemItem:UIBarButtonSystemItemFlexibleSpace
                                                         target:nil
                                                         action:nil];
    
    // タブバーボタン(ホーム)
    // Image of bar button
    /*UIBarButtonItem *homeButton;
    if ([[[[UIDevice currentDevice] systemVersion] componentsSeparatedByString:@"."][0] intValue] >= 7)
    {
        UIButton *barBtnHome = [[[UIButton alloc]initWithFrame:CGRectMake(0, 0, 32, 32)]autorelease];
        [barBtnHome setBackgroundImage:[app resizeImage:@"icon_home.png" image_size:32] forState:UIControlStateNormal];
        [barBtnHome addTarget:self action:@selector(backToHome) forControlEvents:UIControlEventTouchUpInside];
        barBtnHome.showsTouchWhenHighlighted = YES;

        homeButton = [[UIBarButtonItem alloc]initWithCustomView:barBtnHome];
    }
    else
    {
        homeButton = [[UIBarButtonItem alloc]initWithImage:[app resizeImage:@"icon_home.png" image_size:32]
                                                     style:UIBarButtonItemStylePlain
                                                    target:self
                                                    action:@selector(backToHome)];
    }
    
    homeButton.tag = 5;*/
    
    NSArray *items = [NSArray arrayWithObjects:spaceButton,nil];
//  NSArray *items = [NSArray arrayWithObjects:newFolderButton,spaceButton,homeButton, nil];
    self.toolbarItems = items;  
    [self.tableView setEditing:NO animated:YES];     
    //[newFolderButton release];
    [spaceButton release];
    //[homeButton release];
    
    // ---------------------------------------------------------------------
    // iOS7以降対応 : UINavigationBarとStatusBarをUIViewに上被せで表示させない処理
    if ([[[[UIDevice currentDevice] systemVersion] componentsSeparatedByString:@"."][0] intValue] >= 7)
    {
        self.edgesForExtendedLayout = UIRectEdgeNone;
    }
}

/*
- (NSString *)stringFromWchar:(const wchar_t *)charText
{
    //used ARC
    return [[NSString alloc] initWithBytes:charText length:wcslen(charText) * sizeof(*charText) encoding:NSUTF32LittleEndianStringEncoding];
}
 */



- (void)dealloc
{
    [loadingView release];
    [indicator release];
    
    [dataSource release];
    [data_ release];

    [dataTmp_ release];
    self.dataTmp = nil;
    
    [domainList release];
    self.domainList = nil;
    
    [textField release];
    textField = nil;
    self.data = nil;
    dataSource = nil;    
    [super dealloc];
}

/**
 * @brief ナビゲーションバーボタン"編集" クリックイベントハンドラ
 */

- (void)loadWorkgroups
{
    [dataSource getWorkgroups];
}

- (void)editWorkgroup:(id)selector
{
    UIBarButtonItem *editButton =
    [[UIBarButtonItem alloc]initWithBarButtonSystemItem:UIBarButtonSystemItemDone
                                                 target:self
                                                 action:@selector(done:)];
    
	[self.navigationItem setRightBarButtonItem:editButton animated:NO];
    
    [self.tableView setEditing:YES animated:YES];
    
    [self.tableView reloadData];
    [editButton release];
}

/**
 * @brief ナビゲーションバーボタン"完了" クリックイベントハンドラ
 */
- (void)done:(id)sender
{
    UIBarButtonItem *doneButton =
    [[UIBarButtonItem alloc]initWithBarButtonSystemItem:UIBarButtonSystemItemEdit 
                                                 target:self 
                                                 action:@selector(editWorkgroup:)];

	[self.navigationItem setRightBarButtonItem:doneButton animated:NO];
    
    [self.tableView setEditing:NO animated:YES];
    
    [self.tableView reloadData];   
    [doneButton release];
}


- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section
{
    if (!pressedDomain)
        return [self.domainList count];
    else
        return [self.data count];
}

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView
{
    return 1;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath
{
    if (!loadedDomains)
    {
        UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:@"DomainCell"];
        
        if (!cell)
        {
            cell = [[[UITableViewCell alloc]initWithStyle:UITableViewCellStyleDefault reuseIdentifier:@"DomainCell"]autorelease];
            cell.imageView.contentMode = UIViewContentModeScaleAspectFill;
            cell.textLabel.font = [UIFont systemFontOfSize:15.0];
        }
        
        
        INQDomain *domain = [self.domainList objectAtIndex:indexPath.row];
        [[cell textLabel]setText:[NSString stringWithFormat:@"%@", domain.domainName]];
        
        if (indexPath.row == [self.domainList count] - 1)
            loadedDomains = YES;

        return cell;
    }
    else
    {
        UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:@"ComputerCell"];
        
        if (!cell)
        {
            cell = [[[UITableViewCell alloc]initWithStyle:UITableViewCellStyleDefault reuseIdentifier:@"ComputerCell"]autorelease];
            cell.imageView.contentMode = UIViewContentModeScaleAspectFill;
            cell.textLabel.font = [UIFont systemFontOfSize:15.0];
        }
        
        INQComputer *computer = [self.data objectAtIndex:indexPath.row];
        [[cell textLabel]setText:[NSString stringWithFormat:@"%@  / %@", computer.displayName,computer.computerNameIP]];
        INQAppDelegate *app = (INQAppDelegate *)[[UIApplication sharedApplication] delegate];
        UIImage *imgResize = [app resizeImage:@"icon_pc_scan.png" image_size:36];
        [cell.imageView setImage:imgResize];
        
        return cell;
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
    self.navigationController.toolbarHidden = NO;
    //
    //[dataSource loadData:self.isBookMark];
    // テーブルビュー 再描画
    //[self.tableView reloadData];
    
    // ナビゲーションバーのタイトル設定(ワークグループ画面とブックマーク画面を共用利用の為)
    if(self.isBookMark == YES)
    {
        self.title = NSLocalizedString(@"BookMark",@"bookmark title");
    }
    else
    {
        self.title = NSLocalizedString(@"WorkGroup",@"workgroup title");
    }
    
    INQAppDelegate *app = (INQAppDelegate *)[[UIApplication sharedApplication] delegate];
    
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
        
        // set navigation toolbar color
        [self.navigationController.toolbar setBarTintColor:[app setBarColor]];
    }
    else
    {
        // 画面遷移にトランジションを適応した場合、iOS6以前でもtintColorの設定が必要
        self.navigationController.navigationBar.tintColor = [app setBarColor];
        self.navigationController.toolbar.tintColor = [app setBarColor];
    }
}

/**
 * @brief Viewが表示された直後に呼び出される処理
 */
- (void)viewDidAppear:(BOOL)animated
{
    [super viewDidAppear:animated];
}

/**
 * @brief alertのタイマーによる非表示処理
 */
-(void) performDissmiss:(NSTimer *)timer
{
    UIAlertView *alertView = [timer userInfo];
    [alertView dismissWithClickedButtonIndex:0 animated:YES];
}

/**
 * @brief ワークグループ検索 コールバック処理
 */

- (void)loadedDataSourceCallBack:(NSArray*)dt info:(NSString *)info option:(NSInteger)type {

    if (info != nil)
    {
        dispatch_async(dispatch_get_main_queue(), ^{

            // ロード中表示の終了
            [self stopLoadingView];

            // エラー表示をアラートビューにて実行

            UIAlertView *alertView = [[UIAlertView alloc] initWithTitle:NSLocalizedString(@"ErrMsgNFWorkgroup", @"error message")
                                                                message:nil
                                                               delegate:nil
                                                      cancelButtonTitle:NSLocalizedString(@"AlertClose", @"alert close")
                                                      otherButtonTitles:nil, nil];

            [alertView show];
            [alertView release];

            if(type == 0)
            {
                [self.data removeAllObjects];
                [self.data addObjectsFromArray:dt];
            }
            else if(type == 1)
            {
                [dataSource.dataTmp removeAllObjects];
                
                [self.dataTmp removeAllObjects];
            }

            [self.tableView reloadData];
        });
    }
    else
    {
        dispatch_async(dispatch_get_main_queue(), ^{

            
            // ロード中表示の終了
            [self stopLoadingView];


            if(type == 0)
            {
                [self.data removeAllObjects];
                [self.data addObjectsFromArray:dt];
            }
            else if(type == 1)
            {
                [self.dataTmp removeAllObjects];
                [self.dataTmp addObjectsFromArray:dt];
            }
            else if(type == 3)
            {
                [self.domainList removeAllObjects];
                [self.domainList addObjectsFromArray:dt];
            }

            
            [self.tableView reloadData];
        });
    }


}

/**
 * @brief 新しいコンピューター追加ボタン イベントハンドラ
 */
- (void)addWorkgroup
{
    INQAddWorkgroupViewController *controller = [[INQAddWorkgroupViewController alloc]init];

    // ナビゲーションバーのタイトル識別子設定
    INQAppDelegate *app = (INQAppDelegate *)[[UIApplication sharedApplication] delegate];
    app.typeAddWorkGroupView = TRUE;

    // ナビゲーションバーの戻るボタンのタイトルを設定
    UIBarButtonItem *backButton = [[UIBarButtonItem alloc]initWithTitle:NSLocalizedString(@"Back",@"Back")
                                                                  style:UIBarButtonItemStylePlain
                                                                 target:nil
                                                                 action:nil];
    [self.navigationItem setBackBarButtonItem:backButton];
    [backButton release];
    
    [self.navigationController pushViewController:controller animated:YES];
    [controller release];    
}

- (void)viewDidUnload
{
    [super viewDidUnload];
    [dataSource release];
    [data_ release];

    [dataTmp_ release];
    self.dataTmp = nil;

    [textField release];
    textField = nil;
    self.data = nil;
    dataSource = nil;  
}

- (BOOL)shouldAutorotateToInterfaceOrientation:(UIInterfaceOrientation)interfaceOrientation {
    return (interfaceOrientation == UIInterfaceOrientationPortrait);
}

/**
 * @brief Alert表示処理(テキスト入力処理付き)
 */
/*- (void)showWithTitle:(NSString *)title text:(NSString *)text
{
    // text field付きアラート表示の処理変更
    NSString* message = Nil;
    NSString* buttonTitleCancel = @"Cancel";
    NSString* buttonTitleOK = @"OK";
    
    UIAlertView* alert = [[UIAlertView alloc] initWithTitle:title
                                                    message:message
                                                   delegate:self
                                          cancelButtonTitle:buttonTitleCancel
                                          otherButtonTitles:buttonTitleOK,nil];
    
    alert.alertViewStyle = UIAlertViewStylePlainTextInput;
    UITextField *textFieldLocal = [alert textFieldAtIndex:0];
    
    // alertView識別用タグの設定
    alert.tag = 1000;
    
    // init a text field in a UIAlertView
    [textFieldLocal setAutocorrectionType:UITextAutocorrectionTypeNo];
    // 保存済みワークグループ名を初期表示として設定
    [textFieldLocal setText:[self getSerachWorkgroupName]];
    [alert show];
    [alert release];
}*/

/**
 * @brief Alert表示処理(ユーザーID、パスワード入力欄付き)
 */
- (void)showAlertWithInputUserIdAndPassWord:(NSString *)title
{
    // text field付きアラート表示の処理変更
    NSString* message = nil;
    NSString* buttonTitleCancel = @"Cancel";
    NSString* buttonTitleOK = @"OK";
    
    UIAlertView* alert = [[UIAlertView alloc] initWithTitle:title
                                                    message:message
                                                   delegate:self
                                          cancelButtonTitle:buttonTitleCancel
                                          otherButtonTitles:buttonTitleOK,nil];
    
    alert.alertViewStyle = UIAlertViewStyleLoginAndPasswordInput;
    
    [[alert textFieldAtIndex:0] setPlaceholder:NSLocalizedString(@"UserID", @"UserID")];
    
    UITextField *textFieldLocal = [alert textFieldAtIndex:0];
    UITextField *textFieldLocal2 = [alert textFieldAtIndex:1];
    
    // alertView識別用タグの設定
    alert.tag = 1001;
    
    // init a text field in a UIAlertView
    [textFieldLocal setAutocorrectionType:UITextAutocorrectionTypeNo];
    [textFieldLocal2 setAutocorrectionType:UITextAutocorrectionTypeNo];
    [alert show];
    [alert release];
}

/**
 * @brief インジケータ表示開始処理
 */
- (void)startLoadingView:(NSString *)workgroup
{
    //loadingView = [[UIView alloc] initWithFrame:self.navigationController.view.bounds];
    loadingView = [[UIView alloc] initWithFrame:self.view.bounds];
    [loadingView setBackgroundColor:[UIColor blackColor]];
    [loadingView setAlpha:0.5];
    
    indicator = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleWhiteLarge];
    
    [self.view addSubview:loadingView];
    [self.navigationController.view addSubview:loadingView];
    [loadingView addSubview:indicator];
    
    CGRect rect = [[UIScreen mainScreen] bounds];
    [indicator setFrame:CGRectMake (rect.size.width / 2 - 20 , rect.size.height / 2 - 40, 40, 40)];
    [indicator startAnimating];

    loadingMessageLabel = [[UILabel alloc]initWithFrame:CGRectMake( 0, indicator.frame.origin.y + 30, rect.size.width, 50)];
    loadingMessageLabel.backgroundColor = [UIColor clearColor];
    loadingMessageLabel.textColor = [UIColor colorWithRed:255.f/255.f green:255.f/255.f blue:255.f/255.f alpha:0.5];
    loadingMessageLabel.font = [UIFont fontWithName:@"AppleGothic" size:12];
    loadingMessageLabel.numberOfLines = 2;
    loadingMessageLabel.minimumScaleFactor = 8.f/12.f;
    loadingMessageLabel.textAlignment = NSTextAlignmentCenter;
    [self.navigationController.view addSubview:loadingMessageLabel];
    
    NSString *labelText = [[NSLocalizedString(@"Searching...",@"Searching...") stringByAppendingString:@"\n"] stringByAppendingString:workgroup];
    [loadingMessageLabel setText:labelText];
}

/**
 * @brief インジケータ表示停止処理
 */
- (void)stopLoadingView
{
    [indicator stopAnimating];
    [loadingView removeFromSuperview];
    [loadingMessageLabel removeFromSuperview];
}

/**
 * @brief 検索用ワークグループ(保存済み) 取得処理
 */
- (NSString *)getSerachWorkgroupName
{
    NSString *workgroup = [[NSUserDefaults standardUserDefaults] objectForKey:@"SERACH_WORKGROUP"];
    if( workgroup == nil )
    {
        workgroup = @"WORKGROUP";
        // 更新
        [self updateSerachWorkgroupName:workgroup];
    }
    
    return workgroup;
}

/**
 * @brief 検索用ワークグループ 更新処理
 */
- (void)updateSerachWorkgroupName:(NSString *)workgroup
{
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    [defaults setObject:workgroup forKey:@"SERACH_WORKGROUP"];
    [defaults synchronize];
}

#pragma mark -
#pragma mark UIAlertView delegate method.

/**
 * @brief Alert用 ボタンクリックイベントハンドラ
 * @param [in] alertView Alert Viewオブジェクト
 * @param [in] buttonIndex ボタン用インデックス
 */
- (void)alertView:(UIAlertView *)alertView clickedButtonAtIndex:(NSInteger)buttonIndex
{
    

	if (buttonIndex == 1)
    {
        if(alertView.tag == 1001)
        {
            
            INQSharedFolderViewController *controller = [[INQSharedFolderViewController alloc]init];
            controller.computerInfo = [self.data objectAtIndex:self.backupDataTmpIndex];
            controller.isBookMark = self.isBookMark;
            
            // コンピュータ情報の更新(有効)
            INQAppDelegate *app = (INQAppDelegate *)[[UIApplication sharedApplication] delegate];
            app.isUpdateComputerInfo = TRUE;
            
            // ナビゲーションバーのタイトルにコンピュータの表示名を設定
            controller.navigationItem.title = controller.computerInfo.displayName;
            
            controller.computerInfo.userName =
            [[[alertView textFieldAtIndex:0] text]
             stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
            controller.computerInfo.password =
            [[[alertView textFieldAtIndex:1] text]
             stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
            
            [self.navigationController pushViewController:controller animated:NO];
            [controller release];
        }
        /*
        if(alertView.tag == 1000)
        {
            // text field付きアラート表示の処理変更
            // textFieldの入力内容を取得
            NSString *inputText =
                [[[alertView textFieldAtIndex:0] text] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];

            if (inputText == nil || [inputText length] == 0)
            {
                // テーブルビューの選択状態を解除
                [self.tableView reloadData];

                return;
            }
            
            // 入力されたワークグループ名を保存
            [self updateSerachWorkgroupName:inputText];
            
            // ロード中表示の開始
            [self startLoadingView:inputText];
            [self.addWorkgroupController startLoadingView:inputText];

            dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                [dataSource getComputers:inputText];
            });
        }
        else if(alertView.tag == 1001)
        {

            INQSharedFolderViewController *controller = [[INQSharedFolderViewController alloc]init];
            controller.computerInfo = [self.data objectAtIndex:self.backupDataTmpIndex];
            controller.isBookMark = self.isBookMark;
            
            // コンピュータ情報の更新(有効)
            INQAppDelegate *app = (INQAppDelegate *)[[UIApplication sharedApplication] delegate];
            app.isUpdateComputerInfo = TRUE;
            
            // ナビゲーションバーのタイトルにコンピュータの表示名を設定
            controller.navigationItem.title = controller.computerInfo.displayName;
                
            controller.computerInfo.userName =
                [[[alertView textFieldAtIndex:0] text]
                 stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
            controller.computerInfo.password =
                [[[alertView textFieldAtIndex:1] text]
                 stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
            
            [self.navigationController pushViewController:controller animated:NO];
            [controller release];
        } */
	}
    
    

    else if( buttonIndex == 0)
    {
        // テーブルビューの選択状態を解除
        [self.tableView reloadData];
    }
}

#pragma mark -
#pragma mark  UITableViewDelegate method

/**
 * @brief Table View用 セルクリックイベントハンドラ
 * @param [in] tableView Table Viewオブジェクト
 * @param [in] indexPath セル用インデックスパス
 */
- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath
{
#if 0
    {
    INQAppDelegate *delegate = (INQAppDelegate*)[[UIApplication sharedApplication] delegate];

    // search workgroup

    // wifi check
    if (!delegate.isWifi)
    {
        [self alertMessage:NSLocalizedString(@"WifiOnly", @"wifi is off")];
        return;
    }

    // セクション数が 1 の場合で且つ検索データ件数とセルの位置が一致する場合はワークグループ入力
    if(([tableView numberOfSections] == 1) && (indexPath.row == [self.dataTmp count]))
    {
        [self showWithTitle:NSLocalizedString(@"InputWorkgroup", @"Input Workgroup") text:@"WORKGROUP"];
        return;
    }
    else if ([tableView numberOfSections] == 1)
    {
        self.backupDataTmpIndex = indexPath.row;
        // ユーザID、パスワードを入力用Alert表示
        [self showAlertWithInputUserIdAndPassWord:NSLocalizedString(@"InputLoginInfo", @"Input UserID and Password")];
        return;
    }
    
    if (indexPath.section == 1 && (indexPath.row == [self.dataTmp count]))
    {
        [self showWithTitle:NSLocalizedString(@"InputWorkgroup", @"Input Workgroup") text:@"WORKGROUP"];
        return;
    }
    
    if(indexPath.section == 0)
    {
        // 共有フォルダ用View初期化
        INQSharedFolderViewController *controller = [[INQSharedFolderViewController alloc]init];
        controller.computerInfo = [self.data objectAtIndex:indexPath.row];
        controller.isBookMark = self.isBookMark;
        
        // コンピュータ情報の更新(無効)
        INQAppDelegate *app = (INQAppDelegate *)[[UIApplication sharedApplication] delegate];
        app.isUpdateComputerInfo = FALSE;
        
        // ナビゲーションバーのタイトルにコンピュータの表示名を設定
        controller.navigationItem.title = controller.computerInfo.displayName;
        
        [self.navigationController pushViewController:controller animated:NO];
        [controller release];
        return;
    }
    if(indexPath.section == 1)
    {
        self.backupDataTmpIndex = indexPath.row;
        // ユーザID、パスワードを入力用Alert表示
        [self showAlertWithInputUserIdAndPassWord:NSLocalizedString(@"InputLoginInfo", @"Input UserID and Password")];
        return;
    }
    }
#else
    if (!pressedDomain)
    {
        INQDomain *domain;
        domain = [self.domainList objectAtIndex:indexPath.row];
        //[self startLoadingView:domain.domainName];
        //DLog(" About to start computers loading view");
        [self.addWorkgroupController startLoadingView:domain.domainName];
        dispatch_async(dispatch_get_main_queue(), ^{
            [dataSource getComputers:domain.domainName];
            //[self stopLoadingView];
            [self.addWorkgroupController stopLoadingView];
        });
        
        pressedDomain = YES;
        [self.tableView reloadData];
    }
    else
    {
        self.backupDataTmpIndex = indexPath.row;
        [self showAlertWithInputUserIdAndPassWord:NSLocalizedString(@"InputLoginInfo", @"Input UserID and Password")];
        
        INQSharedFolderViewController *controller = [[INQSharedFolderViewController alloc]init];
        DLog(" computer in row = %ld \n", (long)indexPath.row);
        controller.computerInfo = [self.data objectAtIndex:indexPath.row];
        //controller.isBookMark = self.isBookMark;
        
        // コンピュータ情報の更新(無効)
        INQAppDelegate *app = (INQAppDelegate *)[[UIApplication sharedApplication] delegate];
        app.isUpdateComputerInfo = FALSE;
        
        // ナビゲーションバーのタイトルにコンピュータの表示名を設定
        controller.navigationItem.title = controller.computerInfo.displayName;
        //[self.navigationController pushViewController:controller animated:NO];
        
        [controller release];
        return;
    }
    
#endif
}

/**
 * @brief Table View用 セル付属ボタン クリックイベントハンドラ
 * @param [in] tableView Table Viewオブジェクト
 * @param [in] indexPath セル用インデックスパス
 * @note  共有先情報の編集用
 */
- (void)tableView:(UITableView *)tableView accessoryButtonTappedForRowWithIndexPath:(NSIndexPath *)indexPath
{
    INQAddWorkgroupViewController *controller = [[INQAddWorkgroupViewController alloc]init];

    // ナビゲーションバーのタイトル識別子設定
    INQAppDelegate *app = (INQAppDelegate *)[[UIApplication sharedApplication] delegate];
    app.typeAddWorkGroupView = FALSE;

    // ナビゲーションバーの戻るボタンのタイトルを設定
    UIBarButtonItem *backButton = [[UIBarButtonItem alloc]initWithTitle:NSLocalizedString(@"Back",@"Back")
                                                                  style:UIBarButtonItemStylePlain
                                                                 target:nil
                                                                 action:nil];
    [self.navigationItem setBackBarButtonItem:backButton];
    [backButton release];

    [self.navigationController pushViewController:controller animated:YES];
    
    if([tableView numberOfSections] == 1)
    {
        // セクション数が 1 の場合は検索データ側を適応
        if (self.dataTmp != nil)
        {
            controller.data = [self.dataTmp objectAtIndex:indexPath.row];
        }
    }
    else
    {
        // セクションに応じて保存データか検索データかを切り分ける処理を追加
        // セクション0:保存データ
        if( indexPath.section == 0 )
        {
            if (self.data != nil)
            {
                controller.data = [self.data objectAtIndex:indexPath.row];
            }
        }
        // セクション1:検索データ
        else if( indexPath.section == 1 )
        {
            if (self.dataTmp != nil)
            {
                controller.data = [self.dataTmp objectAtIndex:indexPath.row];
            }
        }
    }
    [controller release];
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
    
    // セクション数が 1 の場合は検索データ側が該当
    if([tableView numberOfSections] == 1)
    {
        textLabel.text = NSLocalizedString(@"SearchWorkGroup",@"SearchWorkGroup");
    }
    else
    {
        if (section == 0) {
            textLabel.text = NSLocalizedString(@"SavedWorkGroup",@"SavedWorkGroup");
        }
        
        if (section == 1) {
            textLabel.text = NSLocalizedString(@"SearchWorkGroup",@"SearchWorkGroup");
        }
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

- (void)setEditing:(BOOL)editing animated:(BOOL)animated
{
    [super setEditing:editing animated:animated];
    [self.tableView setEditing:editing animated:YES];
    
    if (editing)
    {
        UIBarButtonItem *doneButton =
                    [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemDone
                                                                  target:self
                                                                  action:@selector(done:)];

        [self.navigationItem setRightBarButtonItem:doneButton animated:YES];
        [doneButton release];
    }
    else
    {
        UIBarButtonItem *editButtonItem =
                [[UIBarButtonItem alloc]initWithBarButtonSystemItem:UIBarButtonSystemItemEdit
                                                             target:self
                                                             action:@selector(editWorkgroup:)];

        self.navigationItem.rightBarButtonItem = editButtonItem;
        [editButtonItem release]; 
    }
}

/**
 * @brief Alert表示処理(メッセージのみ)
 * @param [in] msg 表示メッセージ
 */
- (void)alertMessage:(NSString*)msg
{

    UIAlertView *alertView = [[UIAlertView alloc]initWithTitle:msg
                                                       message:nil
                                                      delegate:self
                                             cancelButtonTitle:NSLocalizedString(@"AlertClose",@"alert window close button")
                                             otherButtonTitles:nil, nil];
    [alertView show];
    [alertView release];
}

#pragma mark - HOME Button.
- (void)backToHome {
    [self.navigationController popToViewController:[self.navigationController.viewControllers objectAtIndex:1] animated:YES];
    
}


@end
