
#import "INQLocalViewController.h"
#import "INQAppDelegate.h"


@interface INQLocalViewController ()

@end

@implementation INQLocalViewController
@synthesize data = data_,selectMode,downloadMode,uploadServer,uploadPath,delegate;

/**
 * @brief 色定義関数(ナビゲーションバー、ツールバー用) 画面個別設定用
 */
-(UIColor *)COLOR_BAR
{
    return [UIColor colorWithRed:245.0f/255.f green:184.f/255.f blue:20.f/255.f alpha:0.8];
}

- (id)initWithStyle:(UITableViewStyle)style
{
    self = [super initWithStyle:style];
    if (self) {
        [[UIApplication sharedApplication] setStatusBarHidden:NO];    


        // Custom initialization
    }
    return self;
}

- (void)viewDidLoad{    
    [super viewDidLoad];
    
    self.title = NSLocalizedString(@"LocalFolder", @"LocalFolder");
    
    data_ = [[NSMutableArray alloc]init];
    self.tableView.backgroundColor = [UIColor colorWithRed:238.0f/255.f green:238.f/255.f blue:238.f/255.f alpha:1.0];

    INQAppDelegate *app = (INQAppDelegate *)[[UIApplication sharedApplication] delegate];
#if 1
    self.navigationController.navigationBar.tintColor = [app setBarColor];
    self.navigationController.toolbar.tintColor = [app setBarColor];
#else
    self.navigationController.navigationBar.tintColor = [UIColor colorWithRed:14.0f/255.f green:133.f/255.f blue:175.f/255.f alpha:0.5];
    self.navigationController.toolbar.tintColor = [UIColor colorWithRed:14.0f/255.f green:133.f/255.f blue:175.f/255.f alpha:0.5];
#endif
    
    self.tableView.separatorColor = [UIColor colorWithRed:14.0f/255.f green:133.f/255.f blue:175.f/255.f alpha:0.5];
    self.tableView.separatorStyle = UITableViewCellSeparatorStyleSingleLine;

    if (self.isSelectMode || self.isDownloadMode) {
        [self end:self];
        return;
    } 
    [self done:self]; 
    

#if 1
    
    // Image of bar button
    UIBarButtonItem *newFolderButton;
    if ([[[[UIDevice currentDevice] systemVersion] componentsSeparatedByString:@"."][0] intValue] >= 7)
    {
        UIButton *barBtnNewComputer = [[[UIButton alloc]initWithFrame:CGRectMake(0, 0, 32, 32)]autorelease];
        [barBtnNewComputer setBackgroundImage:[app resizeImage:@"icon_newfolder.png" image_size:32] forState:UIControlStateNormal];
        [barBtnNewComputer addTarget:self action:@selector(newFolder) forControlEvents:UIControlEventTouchUpInside];
        barBtnNewComputer.showsTouchWhenHighlighted = YES;
        
        newFolderButton = [[UIBarButtonItem alloc]initWithCustomView:barBtnNewComputer];
    }
    else
    {
        newFolderButton = [[UIBarButtonItem alloc]initWithImage:[app resizeImage:@"icon_newfolder.png" image_size:32]
                                                          style:UIBarButtonItemStylePlain
                                                         target:self
                                                         action:@selector(newFolder)];
    }
#else
    // Text of bar button
    UIBarButtonItem *newFolderButton = [[UIBarButtonItem alloc]initWithTitle:NSLocalizedString(@"NewFolder",@"New Folder")
                                                                       style:UIBarButtonItemStyleBordered 
                                                                      target:self 
                                                                      action:@selector(newFolder)];
#endif
    
    // self.navigationItem.rightBarButtonItem = actionButton;
    
    UIBarButtonItem *spaceButton = [[UIBarButtonItem alloc]initWithBarButtonSystemItem:UIBarButtonSystemItemFlexibleSpace 
                                                                                target:nil 
                                                                                action:nil];
    
    
#if 1
    // Image of bar button
    UIBarButtonItem *homeButton;
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
#else
    // Text of bar button
    UIBarButtonItem *homeButton = [[UIBarButtonItem alloc]initWithTitle:NSLocalizedString(@"Home",@"Home") style:UIBarButtonItemStyleBordered target:self action:@selector(backToHome)];
#endif
    homeButton.tag = 5;
    
    NSArray *items = [NSArray arrayWithObjects:newFolderButton,spaceButton,homeButton,nil];
#if 0
    // Analyze対応 [Value stored to 'items' during its initialization is never read]
    items = [NSArray arrayWithObjects:newFolderButton,spaceButton,homeButton, nil];
#endif
    [self.tableView setEditing:NO animated:YES]; 

    self.toolbarItems = items;  
    
    [newFolderButton release];
    [spaceButton release];
    [homeButton release];
    
    
}

#pragma mark - HOME Button.
- (void)backToHome {
    [self.navigationController popToViewController:[self.navigationController.viewControllers objectAtIndex:1] animated:YES];
    
}

- (void)editFolder:(id)selector {
    UIBarButtonItem *editButton =
    [[UIBarButtonItem alloc]
     initWithBarButtonSystemItem:UIBarButtonSystemItemDone target:self action:@selector(done:)];
	[self.navigationItem setRightBarButtonItem:editButton animated:NO];
    
    [self.tableView setEditing:YES animated:YES];
    
    [self.tableView reloadData];
    [editButton release];
    
}

- (void)end:(id)sender {
    UIBarButtonItem *endButton =
    [[UIBarButtonItem alloc]
     initWithBarButtonSystemItem:UIBarButtonSystemItemCancel target:self action:@selector(endUpload)];
    
	[self.navigationItem setRightBarButtonItem:endButton animated:NO];

    [endButton release];
}

- (void)endUpload {
	[self dismissViewControllerAnimated:YES completion:NULL];
}

- (void)done:(id)sender {
    UIBarButtonItem *doneButton =
    [[UIBarButtonItem alloc]
     initWithBarButtonSystemItem:UIBarButtonSystemItemEdit target:self action:@selector(editFolder:)];
    
	[self.navigationItem setRightBarButtonItem:doneButton animated:NO];
    
    [self.tableView setEditing:NO animated:YES];
    
    [self.tableView reloadData];   
    [doneButton release];
}

- (void)setEditing:(BOOL)editing animated:(BOOL)animated {
    [super setEditing:editing animated:animated];

    if (editing) {
        UIBarButtonItem *doneButton = [[UIBarButtonItem alloc] 
                                       initWithBarButtonSystemItem:UIBarButtonSystemItemDone
                                                            target:self 
                                                            action:@selector(done:)];
        
        [self.navigationItem setRightBarButtonItem:doneButton animated:YES];
        [doneButton release];
    } else { 
#if 0
        // (参考) ワークグループ画面からの遷移の場合にセルの編集を許可した場合は本処理を有効とすることで編集後のキャンセルが可能.
        //       現状、editingStyleForRowAtIndexPathにてワークグループからの遷移の場合はセルの編集を実行出来ない様に設定済み.
        INQAppDelegate *app = (INQAppDelegate *)[[UIApplication sharedApplication] delegate];
        UIBarButtonItem *editButtonItem;
        if(app.typeSelectedView == DEF_VIEW_LOCAL)
        {
            editButtonItem = [[UIBarButtonItem alloc]initWithBarButtonSystemItem:UIBarButtonSystemItemEdit target:self action:@selector(editWorkgroup:)];
        }
        else
        {
            editButtonItem = [[UIBarButtonItem alloc]initWithBarButtonSystemItem:UIBarButtonSystemItemCancel target:self action:@selector(endUpload)];
        }
#else
        UIBarButtonItem *editButtonItem = [[UIBarButtonItem alloc]initWithBarButtonSystemItem:UIBarButtonSystemItemEdit target:self action:@selector(editWorkgroup:)];
#endif
        self.navigationItem.rightBarButtonItem = editButtonItem;
        [editButtonItem release]; 
    }
}

- (void)viewDidUnload {
    [super viewDidUnload];
    self.data = nil;
    self.uploadServer = nil;
    self.uploadPath = nil;
    self.delegate = nil;
}

- (BOOL)shouldAutorotateToInterfaceOrientation:(UIInterfaceOrientation)interfaceOrientation {
    return (interfaceOrientation == UIInterfaceOrientationPortrait);
}

/**
 * @brief Viewが表示される直前に呼び出される処理
 */
- (void)viewWillAppear:(BOOL)animated
{
    DLog(@"viewWillApper:LocalView");

    [super viewWillAppear:animated];

    // ナビゲーションバー 表示設定(有効)
    self.navigationController.navigationBar.hidden = NO;

    INQAppDelegate *app = (INQAppDelegate *)[[UIApplication sharedApplication] delegate];
    // ツールバー 表示設定
    if(app.typeSelectedView == DEF_VIEW_WORKGROUP)
    {
        [self.navigationController setToolbarHidden:YES];
    }
    else if(app.typeSelectedView == DEF_VIEW_LOCAL)
    {
        [self.navigationController setToolbarHidden:NO];
    }
    else if(app.typeSelectedView == DEF_VIEW_UNDEFINE)
    {
        // (暫定対応)
        // 他アプリから"ファイルを開く"の操作で本アプリが起動するケースでいきなりローカルフォルダ画面が開く挙動への対応
        [self.navigationController popViewControllerAnimated:YES];
    }

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

    [self reload];
}

- (void)reload {
    NSString* documentsDirectory = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];        
    [self.data removeAllObjects];
    
    NSArray *contents = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:documentsDirectory error:nil];    
    @autoreleasepool {
        for (NSString *name in contents) {
            INQFile *file = [[INQFile alloc]init];
            BOOL isDir;
            NSString *ph = [documentsDirectory stringByAppendingPathComponent:name];
            if ([[NSFileManager defaultManager] fileExistsAtPath:ph isDirectory:&isDir] &&isDir) {
                file.fullPath = ph;
                file.dir = YES;
                file.fileName = name;
                file.subFolderFileCount = [[[NSFileManager defaultManager] contentsOfDirectoryAtPath:ph error:nil] count];
                [self.data addObject:file];
            }
            [file release];        
        } 
    }
    [self.tableView reloadData];    
}

- (void)dealloc {
    [data_ release];
    [textField release];
    delegate = nil;
    [super dealloc];
}

/**
 * @brief ナビゲーションバーボタン"編集" クリックイベントハンドラ
 */
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

#pragma mark - 
#pragma mark Table view data source

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    return 1;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
#if 1
    // 新規フォルダーの追加はセル上からは実行しない様に変更に伴う変更
    return [self.data count];
#else
    if (tableView.isEditing || self.isSelectMode) {
        return [self.data count];
    }
    return ([self.data count] + 1);
#endif
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    static NSString *CellIdentifier = @"Cell";
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:CellIdentifier];
    if (cell == nil) {
        cell = [[[UITableViewCell alloc]initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:CellIdentifier]autorelease];        
    }

#if 1
    
#if 1
    [cell setSelectionStyle:UITableViewCellSelectionStyleNone];
    
    if (indexPath.row != ([self.data count]))
    {
        // ホーム画面からの遷移時のみスイッチを表示
        INQAppDelegate *app = (INQAppDelegate *)[[UIApplication sharedApplication] delegate];
        if(app.typeSelectedView == DEF_VIEW_LOCAL)
        {
            /**
             * アクセサリーボタンで遷移後の画面での設定処理からスイッチで切り替える処理に変更
             */
            UISwitch *sw = [[UISwitch alloc]initWithFrame:CGRectZero];
            cell.accessoryView = sw;

            // インデックスをタグに格納(イベントハンドラ側で意図した実装が出来なかった為の代替案)
            sw.tag = indexPath.row;
            
            NSString* documentsDirectory = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
            INQFile *file = (INQFile*)[self.data objectAtIndex:indexPath.row];
            NSString *folderId = [documentsDirectory stringByAppendingPathComponent:file.fileName];
            
            INQShareFolder *folderObj =[INQSharedFolderDataSource getSharedFolderById:folderId];
            if (folderObj == nil)
            {
                folderObj = [[[INQShareFolder alloc]init]autorelease];
                [folderObj setFolderId:folderId];
                [folderObj setPath:documentsDirectory];
                [folderObj setFolderName:file.fileName];
                [folderObj setSecurity:NO];
                [folderObj setGuest:YES];
                [folderObj setShare:NO];
                
                folderObj.share = NO;
            }
            else
            {
                // 保存済みの内容をスイッチに反映
                sw.on = folderObj.share;
            }
            
            [sw addTarget:self action:@selector(onShare:) forControlEvents:UIControlEventValueChanged];
            [sw release];
        }
    }

#else
    // セルの記号設定
    if ([[[[UIDevice currentDevice] systemVersion] componentsSeparatedByString:@"."][0] intValue] >= 7)
    {
        // iOS7では従来指定していたDetailDisclosureButtonだとイメージが２つ表示されるので変更
        [cell setAccessoryType:UITableViewCellAccessoryDetailButton];
    }
    else
    {
        [cell setAccessoryType:UITableViewCellAccessoryDetailDisclosureButton];
    }
#endif
    
#else
    [cell setAccessoryType:UITableViewCellAccessoryDetailDisclosureButton];
#endif
    if (self.isSelectMode || self.isDownloadMode) {
        [cell setAccessoryType:UITableViewCellAccessoryNone];          
    }

#if 0
    // 新規フォルダーの追加はセル上からは実行しない様に変更
    if (indexPath.row == ([self.data count])) {
        [cell setAccessoryType:UITableViewCellAccessoryDisclosureIndicator];
        [cell.textLabel setText:NSLocalizedString(@"AddNewFolder", @"Add New Folder")];

#if 1
        INQAppDelegate *app = (INQAppDelegate *)[[UIApplication sharedApplication] delegate];
        UIImage *imgResize = [app resizeImage:@"icon_newfolder_color.png" image_size:30];
        [cell.imageView setImage:imgResize];
#else
        [cell.imageView setImage:[UIImage imageNamed:@"import_icon&24.png"]];
#endif
        return cell;
    }
#endif
    
    INQFile *file = (INQFile*)[self.data objectAtIndex:indexPath.row];
#if 0
    // 共有設定有効時の詳細表示(2行)はセクションに移行の為、非表示に
    [cell.detailTextLabel setText:@""];    
    if ([INQSharedFolderDataSource getSharedFolderById:file.fullPath]) {
        [cell.detailTextLabel setText:NSLocalizedString(@"Share",@@"Share")];
    }
#endif

#if 1
    // 言語設定に応じてフォルダ名の表示を変更する処理を無効化
    [cell.textLabel setText:[NSString stringWithFormat:@"%@ (%d)", file.fileName,(int)file.subFolderFileCount]];
#else
    [cell.textLabel setText:[NSString stringWithFormat:@"%@ (%d)", NSLocalizedString(file.fileName,@"folder name"),file.subFolderFileCount]];
#endif
    
    if (file.isDir) {
#if 1
        INQAppDelegate *app = (INQAppDelegate *)[[UIApplication sharedApplication] delegate];
        UIImage *imgResize = [app resizeImage:@"icon_folder.png" image_size:30];
        [cell.imageView setImage:imgResize];
#else
        [cell.imageView setImage:[UIImage imageNamed:@"folder_icon&24.png"]];
#endif
        
    } else {
#if 1
        INQAppDelegate *app = (INQAppDelegate *)[[UIApplication sharedApplication] delegate];
        UIImage *imgResize = [app resizeImage:@"file.png" image_size:30];
        [cell.imageView setImage:imgResize];
#else
        [cell.imageView setImage:[UIImage imageNamed:@"doc_lines_icon&24.png"]];
#endif
    }
    
    return cell;
}

/**
 * @brief セルに配置のスイッチ操作イベントハンドラ(未完成)
 */
- (void)onShare:(id)sender
{
    // スイッチの状態取得
    BOOL changed = [(UISwitch*)sender isOn];
    
    UISwitch *sw = sender;
    NSString* documentsDirectory = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    INQFile *file = (INQFile*)[self.data objectAtIndex:sw.tag];
    NSString *folderId = [documentsDirectory stringByAppendingPathComponent:file.fileName];
    
    INQShareFolder *folderObj =[INQSharedFolderDataSource getSharedFolderById:folderId];
    DLog(@"load shared folder:%@",folderObj);
    if (folderObj == nil)
    {
        folderObj = [[[INQShareFolder alloc]init]autorelease];
        [folderObj setFolderId:folderId];
        [folderObj setPath:documentsDirectory];
        [folderObj setFolderName:file.fileName];
        [folderObj setSecurity:NO];
        [folderObj setGuest:YES];
        [folderObj setShare:NO];
    }
    
    // スイッチの状態を保存用領域に更新
    folderObj.share = changed;
    
    if (folderObj.userName == nil)
    {
        folderObj.userName = @"guest";
    }
    
    if (folderObj.password == nil)
    {
        folderObj.password = @"guest";
    }
    
    // スイッチの状態を含め更新保存
    [INQSharedFolderDataSource saveData:folderObj];
}

- (UIView *)tableView:(UITableView *)tableView viewForHeaderInSection:(NSInteger)section
{
    if([self.data count] == 0)
    {
        return nil;
    }
    
    UIView *sectionView;
    UILabel *textLabel;
    UILabel *textLabelRight;
    if ([[[[UIDevice currentDevice] systemVersion] componentsSeparatedByString:@"."][0] intValue] >= 7)
    {
        sectionView = [[[UIView alloc]initWithFrame:CGRectMake(0, 0, [UIScreen mainScreen].bounds.size.width, 50)]autorelease];
        textLabel = [[[UILabel alloc]initWithFrame:CGRectMake(10, 20, [UIScreen mainScreen].bounds.size.width, 30)]autorelease];
        textLabelRight = [[[UILabel alloc]initWithFrame:CGRectMake( [UIScreen mainScreen].bounds.size.width - 80, 20, 80, 30)]autorelease];
    }
    else
    {
        sectionView = [[[UIView alloc]initWithFrame:CGRectMake(0, 0, [UIScreen mainScreen].bounds.size.width, 40)]autorelease];
        textLabel = [[[UILabel alloc]initWithFrame:CGRectMake(10, 15, [UIScreen mainScreen].bounds.size.width, 20)]autorelease];
        textLabelRight = [[[UILabel alloc]initWithFrame:CGRectMake( [UIScreen mainScreen].bounds.size.width - 115, 15, 115, 20)]autorelease];
    }
    
    sectionView.backgroundColor = [UIColor clearColor];
    
    textLabel.backgroundColor = [UIColor clearColor];
    textLabel.textColor = [UIColor darkGrayColor];
    textLabel.font = [UIFont boldSystemFontOfSize:16.0f];
    textLabel.shadowColor = [UIColor whiteColor];
    textLabel.shadowOffset = CGSizeMake(0, 1);
    
    textLabel.text = NSLocalizedString(@"LocalFolder",@"LocalFolder");

    textLabelRight.backgroundColor = [UIColor clearColor];
    textLabelRight.textColor = [UIColor darkGrayColor];
    textLabelRight.font = [UIFont boldSystemFontOfSize:14.0f];
    textLabelRight.shadowColor = [UIColor whiteColor];
    textLabelRight.shadowOffset = CGSizeMake(0, 1);
    textLabelRight.textAlignment = NSTextAlignmentCenter;
    
    textLabelRight.text = NSLocalizedString(@"Share",@"Share");
    
    [sectionView addSubview:textLabel];

#if 1
    // ホーム画面からの遷移時のみスイッチ用のセクションヘッダー文字列を表示
    INQAppDelegate *app = (INQAppDelegate *)[[UIApplication sharedApplication] delegate];
    if(app.typeSelectedView == DEF_VIEW_LOCAL)
    {
        [sectionView addSubview:textLabelRight];
    }
#else
    [sectionView addSubview:textLabelRight];
#endif
    
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

#pragma mark -
#pragma mark  Table view delegate

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    DLog(@"Select mode %d",self.selectMode);
    DLog(@"Download mode %d",self.downloadMode);    
    if (indexPath.row == [self.data count]) {
        [self newFolder];
        return;
    }
    INQFileListViewController *controller = [[INQFileListViewController alloc]initWithStyle:UITableViewStylePlain];
    [controller setSelectMode:self.isSelectMode];  
    [controller setDownloadMode:self.isDownloadMode];
    [controller setDelegate:self.delegate];
    
    [self.navigationController pushViewController:controller animated:YES];

#if 1
    // dispatch処理で実行しないとiOS7で期待動作にならない
    dispatch_async(dispatch_get_main_queue(), ^{
        
        INQFile *file = (INQFile*)[self.data objectAtIndex:indexPath.row];
        controller.title = file.fileName;
        [controller loadDataFromLocalPath:file.fileName];
      
        [controller release];
    });
#else
    INQFile *file = (INQFile*)[self.data objectAtIndex:indexPath.row];
    controller.title = file.fileName;
    [controller loadDataFromLocalPath:file.fileName];
    
    [controller release];
#endif
}


- (void)tableView:(UITableView *)tableView accessoryButtonTappedForRowWithIndexPath:(NSIndexPath *)indexPath {
    NSString* documentsDirectory = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];    
    INQFile *file = (INQFile*)[self.data objectAtIndex:indexPath.row];
    NSString *folderId = [documentsDirectory stringByAppendingPathComponent:file.fileName];
    

    INQShareFolder *folderObj =[INQSharedFolderDataSource getSharedFolderById:folderId];
    DLog(@"load shared folder:%@",folderObj);
    if (folderObj == nil) {
        folderObj = [[[INQShareFolder alloc]init]autorelease];
        [folderObj setFolderId:folderId];
        [folderObj setPath:documentsDirectory];
        [folderObj setFolderName:file.fileName];
        [folderObj setSecurity:NO];
        [folderObj setGuest:YES];
        [folderObj setShare:NO];
    }

    INQFolderSettingViewController *controller = [[INQFolderSettingViewController alloc]initWithStyle:UITableViewStyleGrouped];
    controller.folderObj = folderObj;
    
#if 1
    // ナビゲーションバータイトルをローカルフォルダー名を適応
    controller.navigationItem.title = file.fileName;
#endif

    [self.navigationController pushViewController:controller animated:YES];
    [controller release];
}

- (BOOL)tableView:(UITableView *)tableView canEditRowAtIndexPath:(NSIndexPath *)indexPath {
    if (indexPath.section == 0) {
        return YES;
    }
    return NO;
}

- (void)tableView:(UITableView *)tableView commitEditingStyle:(UITableViewCellEditingStyle)editingStyle forRowAtIndexPath:(NSIndexPath *)indexPath {
    
    if (editingStyle == UITableViewCellEditingStyleDelete) {
        INQFile *file = [self.data objectAtIndex:indexPath.row];
        if (file.subFolderFileCount > 0) {
#if 1
            // アラートの表示形態を統一
            UIAlertView *deleteFaildView = [[UIAlertView alloc]
                                            initWithTitle:NSLocalizedString(@"SubFolderHaveFile", @"sub folder have file.")
                                            message:nil
                                            delegate:nil
                                            cancelButtonTitle:NSLocalizedString(@"OK",@"OK")
                                            otherButtonTitles:nil, nil];
            [deleteFaildView show];
            [deleteFaildView release];
            [tableView reloadData];
#else
            UIAlertView *deleteFaildView = [[UIAlertView alloc]
                                            initWithTitle:NSLocalizedString(@"Info", @"Info") 
                                            message:NSLocalizedString(@"SubFolderHaveFile", @"sub folder have file.")
                                            delegate:nil 
                                            cancelButtonTitle:NSLocalizedString(@"OK",@"OK") 
                                            otherButtonTitles:nil, nil];
            [deleteFaildView show];
            [deleteFaildView release];            
#endif
            return;
        }
        NSError *error = nil;
        [[NSFileManager defaultManager] removeItemAtPath:file.fullPath error:&error];
        if (error) {
#if 1
            // フォルダ削除に失敗した場合のAlert上に表示する文言を変更.
            // (注意) Inboxフォルダは権限の都合で削除が出来ないので削除を実行するとエラーとなる.
            UIAlertView *deleteFaildView = [[UIAlertView alloc]
                                            initWithTitle:NSLocalizedString(@"DeleteFolderFailed", @"delete folder failed")
                                            message:nil
                                            delegate:nil
                                            cancelButtonTitle:NSLocalizedString(@"OK",@"OK")
                                            otherButtonTitles:nil, nil];
#else
            UIAlertView *deleteFaildView = [[UIAlertView alloc]
                                            initWithTitle:NSLocalizedString(@"Info", @"Info") 
                                            message:[error description]
                                            delegate:nil 
                                            cancelButtonTitle:NSLocalizedString(@"OK",@"OK") 
                                            otherButtonTitles:nil, nil];
#endif
            [deleteFaildView show];
            [deleteFaildView release];
            
#if 1
            // フォルダの選択状態を解除
            [tableView reloadData];
#endif
            return;
        }
        [INQSharedFolderDataSource sharedFolderRemoveById:file.fullPath];
        [self.data removeObjectAtIndex:indexPath.row];
        [tableView deleteRowsAtIndexPaths:[NSArray arrayWithObject:indexPath] withRowAnimation:UITableViewRowAnimationFade];

#if 1
        // ローカルのフォルダーを全て削除した際にセクション表示も消去する為に再描画処理を追加
        [tableView reloadData];
#endif
    }
}

- (void)showWithTitle:(NSString *)title text:(NSString *)text {

#if 1
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
    
    // init a text field in a UIAlertView
    [textFieldLocal setAutocorrectionType:UITextAutocorrectionTypeNo];
    [alert show];
    [alert release];

#else
	UIAlertView *alert = [[UIAlertView alloc] initWithTitle:title
                                                    message:@" "
                                                   delegate:self
                                          cancelButtonTitle:@"Cancel"
                                          otherButtonTitles:@"OK", nil];
    if (textField == nil) {
        textField = [[UITextField alloc] initWithFrame:CGRectMake(12, 45, 260, 25)];        
    }
	textField.text = text;
	CGAffineTransform myTransform = CGAffineTransformMakeTranslation(0, 60);
	[alert setTransform:myTransform];
	[textField setBackgroundColor:[UIColor whiteColor]];
	[alert addSubview:textField];
	[alert show];
	[alert release];
    [textField becomeFirstResponder];
#endif
}

/**
 * @brief テーブルビュー セルの編集スタイルの設定処理
 * @note  本Viewは共通で利用される為、遷移元に応じてスワイプ操作によるセルの"削除"を有効/無効の設定を本関数にて実施
 */
- (UITableViewCellEditingStyle)tableView:(UITableView*)tableView editingStyleForRowAtIndexPath:(NSIndexPath*)indexPath
{
    UITableViewCellEditingStyle style;
    INQAppDelegate *app = (INQAppDelegate *)[[UIApplication sharedApplication] delegate];
    if(app.typeSelectedView == DEF_VIEW_LOCAL)
        
    {
        // deleteを許可
        style = UITableViewCellEditingStyleDelete;
    }
    
    else if(app.typeSelectedView == DEF_VIEW_WORKGROUP)
    {
        style = UITableViewCellEditingStyleNone;
    }
    else
    {
        style = UITableViewCellEditingStyleDelete;
    }
    
    return style;
}

#pragma mark -
#pragma mark UIAlertView delegate method.

- (void)alertView:(UIAlertView *)alertView clickedButtonAtIndex:(NSInteger)buttonIndex {
	
#if 0
    // text field付きアラート表示の処理変更に伴う削除
//  [textField resignFirstResponder];
#endif

    // create directory.
	if (buttonIndex == 1) {
#if 1
        // text field付きアラート表示の処理変更
        // textFieldの入力内容を取得
        NSString *inputText = [[alertView textFieldAtIndex:0] text];
#else
        NSString *inputText = textField.text;
        inputText = [inputText stringByReplacingOccurrencesOfString:@"" withString:@" "];
#endif
        if (inputText == nil || [inputText length] == 0) {
            return;
        }
        
        if([self createDirectory:inputText]) {
            [self reload];            
        }

	}
    else
    {
        // キャンセルボタン押下後のテーブルビューの再描画(選択状態の解除)
        [self reload];
    }
}

- (void)newFolder {
        [self showWithTitle:NSLocalizedString(@"NewFolder",@"Input Folder Name") text:@""];
}

- (BOOL)createDirectory:(NSString*)directory {
    NSString *documentsDirectory = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];   
    NSString *path = [documentsDirectory stringByAppendingPathComponent:directory];
    NSError *error = nil;
    [[NSFileManager defaultManager] createDirectoryAtPath:path withIntermediateDirectories:YES attributes:nil error:&error];
    if (error) {
        DLog(@"Create Document Directory Error:%@",error);
        return NO;
    } 
    return YES;
}
@end
