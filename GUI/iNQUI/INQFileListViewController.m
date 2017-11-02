
#import "INQFileListViewController.h"


@interface INQFileListViewController ()

@end

@implementation INQFileListViewController
@synthesize documents = documents_,dataSource = dataSource_;
@synthesize savedPath,selectMode,downloadMode,delegate;
@synthesize loadingView;
@synthesize previewFilePath;

- (id)initWithNibName:(NSString *)nibNameOrNil bundle:(NSBundle *)nibBundleOrNil {
    self = [super initWithNibName:nibNameOrNil bundle:nibBundleOrNil];
    
    if (self) {
        imageArray = [[NSMutableArray alloc]init];
    }
    
    return self;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    //self.title = NSLocalizedString(@"FileList",@"File list title");   
    dataSource_ = [[INQFileDataSource alloc]init];   
    CGRect screen = [[UIScreen mainScreen] bounds];
    self.tableView.frame = CGRectMake(0, 0, screen.size.width, screen.size.height - 100);
    [self.tableView setDelegate:self];
#if 0
    UISegmentedControl* segment = [[[UISegmentedControl alloc] initWithItems:[[NSArray alloc]initWithObjects:@"L",@"T", nil]] autorelease];
    

    segment.momentary = YES;
    segment.frame = CGRectMake(0, 0, 100, 30);
    
    [segment addTarget:self action:@selector(changeView) forControlEvents:UIControlEventValueChanged];
    
    //self.navigationItem.titleView = segment;
    [segment release];
#endif
    
    // ---------------------------------------------------------------------
    // iOS7以降対応 : UINavigationBarとStatusBarをUIViewに上被せで表示させない処理
    if ([[[[UIDevice currentDevice] systemVersion] componentsSeparatedByString:@"."][0] intValue] >= 7)
    {
        self.edgesForExtendedLayout = UIRectEdgeNone;
    }    
}

- (void)changeView {
    
}

#if 0
- (UIBarButtonItem*)createSegmentedButton: (NSArray*)titles target:(id)target selector:(SEL)selector {
    
    UISegmentedControl* segment = [[[UISegmentedControl alloc] initWithItems:titles]autorelease];
    // この設定で状態を残さない
    segment.momentary = YES;
    segment.frame = CGRectMake(0, 0, 100, 30);
    
    [segment addTarget:target action:selector forControlEvents:UIControlEventValueChanged];
    UIBarButtonItem* button = [[[UIBarButtonItem alloc]initWithCustomView:segment]autorelease];
    return button;
    
}
#endif

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    self.navigationController.toolbarHidden = NO;
    
    if (savedPath && savedPath) {
       // [self loadDataFromServer:savedComputer path:savedPath];
    }
    
    if (self.isSelectMode) {
   //     [self.navigationController setToolbarHidden:YES];
        return;
    }
    [self.loadingView startAnimating];       
}

- (void)dealloc {
#if 1
    // 'viewDidUnload' is deprecated: first deprecated in iOS6.0対応
    [loadingView release];
    loadingView = nil;
    [savedPath release];
    savedPath = nil;
    [savedComputer release];
    savedComputer = nil;
    [dataSource_ release];
    dataSource_ = nil;
    [documents_ release];
    documents_ = nil;
    [textField release];
    textField = nil;
#else
    [self viewDidUnload];
#endif
    [super dealloc];
}

- (void)viewDidUnload {
    [loadingView release];
    loadingView = nil;
    [savedPath release];
    savedPath = nil;
    [savedComputer release];
    savedComputer = nil;
    [dataSource_ release];
    dataSource_ = nil;
    [documents_ release];
    documents_ = nil;
    [textField release];    
    textField = nil;
    [super viewDidUnload];
}

- (BOOL)shouldAutorotateToInterfaceOrientation:(UIInterfaceOrientation)interfaceOrientation {
    return (interfaceOrientation == UIInterfaceOrientationPortrait);
}

- (void)loadDataFromLocalPath:(NSString *)path {
    isServer = NO;
    self.tableView.separatorColor = [UIColor colorWithRed:14.0f/255.f 
                                                    green:133.f/255.f 
                                                     blue:175.f/255.f 
                                                    alpha:0.1];
    self.tableView.separatorStyle = UITableViewCellSeparatorStyleSingleLine;
    if (self.savedPath == nil) {
        self.savedPath = path;
    }
    
    self.tableView.dataSource = self.dataSource;
    self.dataSource.delegate = self;

    if (self.isSelectMode) {
        [self upload:self];
    } else if (self.isDownloadMode) {
        [self download:self];
    } else {
        [self done:self];           
    }
    [self startLoading];
}	

- (void)loadDataFromServer:(NSString*)server path:(NSString*)path {
    isServer = YES;
    self.tableView.separatorColor = [UIColor colorWithRed:153.0f/255.f 
                                                    green:51.f/255.f 
                                                     blue:0.f/255.f 
                                                    alpha:0.1];
    self.tableView.separatorStyle = UITableViewCellSeparatorStyleSingleLine;
    if (self.savedPath == nil) {
        self.savedPath = path;
       
    }
    
    savedComputer = server; 
    self.tableView.dataSource = self.dataSource;
    self.dataSource.delegate = self;
    [self done:self]; 
    [self startLoading];
   
}


#pragma mark -
#pragma mark - INQDataSourceCallBack

#if 1
- (void)loadedDataSourceCallBack:(NSArray*)data info:(NSString *)info option:(NSInteger)type {
#else
- (void)loadedDataSourceCallBack:(NSArray*)data info:(NSString *)info {
#endif
    [self stopLoading];
    [self.loadingView stopAnimating];
    [self.loadingView setHidden:YES];
    
    self.messageLabel.hidden = YES;
    if (info != nil) {
        self.messageLabel.text = info;
        self.messageLabel.hidden = NO;
    }
    
    if (self.documents == nil) {
        documents_ = [[NSMutableArray alloc]initWithArray:data];        
    } else {
        [self.documents removeAllObjects];
        [self.documents addObjectsFromArray:data];
    }

   // [self.loadingView setHidden:YES];
    if ([self.documents count] > 0 ) {
        [self.tableView reloadData];        
    }
    
    NSAssert(imageArray != NULL,@"Image Array is NULL.");
   
    [imageArray removeAllObjects];
    
    for(INQFile *inqFile in self.documents) {
#if 1
        // jpgの拡張子(jpeg,jpe)を追加
        if ([inqFile.fileExt isEqualToString:@"PNG"] ||
            [inqFile.fileExt isEqualToString:@"JPG"] ||
            [inqFile.fileExt isEqualToString:@"JPEG"] ||
            [inqFile.fileExt isEqualToString:@"JPE"]) {
#else
        if ([inqFile.fileExt isEqualToString:@"PNG"] || [inqFile.fileExt isEqualToString:@"JPG"]) {
#endif
            [imageArray addObject:inqFile];
        }
    }
}

- (void)needDisplay {
    [self.tableView performSelectorOnMainThread:@selector(reloadData) withObject:nil waitUntilDone:NO];
}

#pragma mark -
#pragma mark QLPreviewControllerDelegate methods

- (BOOL)previewController:(QLPreviewController *)controller shouldOpenURL:(NSURL *)url forPreviewItem:(id <QLPreviewItem>)item {
	return YES;
}


#pragma mark -
#pragma mark QLPreviewControllerDataSource methods

/**
 * @brief [QLPreviewControllerDataSource]用関数 プレビューするファイル数を設定する処理
 * @note  元々の処理ではプレビュー画面に遷移後、スワイプ操作にて前後のファイルを表示する機能として
 *        実装されていたが、諸々(※)の理由によりプレビューするファイル数を1つに限定する.
 *        ※. 表示を行う為に一旦、ローカルの領域にコピーする為、時間が掛かるのフォルダとの混在時に
 *           意図した実装がすぐに出来ないと判断した為.
 */
- (NSInteger) numberOfPreviewItemsInPreviewController: (QLPreviewController *) controller
{
#if 1
    // プレビューを許可するファイル数は１つに限定
    return 1;
#else
    int count = 0;
    for (int i = 0; i <[self.documents count]; i++) {
        INQFile *inqFile = (INQFile*)[self.documents objectAtIndex:i];
        if (!inqFile.isDir) {
            if ([self.dataSource.supportFiles objectForKey:[inqFile.fileExt uppercaseString]]) {
                count++;                
            }
        }
    }
    
	return [self.documents count];
#endif
}

/**
 * @brief [QLPreviewControllerDataSource]用関数 プレビューするファイルのパスを設定する処理
 */
- (id <QLPreviewItem>) previewController: (QLPreviewController *) controller previewItemAtIndex: (NSInteger) index
{

#if 1
    if(self.previewFilePath == nil)
    {
        /**
         * プレビュー対象のファイルのコピーが未完了だとファイルパスにnilがセットされているのでここでreturn.
         * 挙動としてはnilを返却するとリトライして本関数がコールされる様なので本処理を実装.
         */
        return nil;
    }
    NSString *tmpFilePath = self.previewFilePath;
    self.previewFilePath = nil;
    return [NSURL fileURLWithPath:tmpFilePath];

#else
    if (index >= [self.documents count])
    {
        return nil;
    }
    INQFile *inqFile = (INQFile*)[self.documents objectAtIndex:index];
    
    if (inqFile.isDir)
    {
        return  nil;
    }
    
#if 0
//*********************************************************************************
    /**
     * 以下の処理はプレビュー画面からスワイプ操作にて次のファイルを開く場合にファイルを
     * 先読みする処理として参考までに実装したもの.
     * 結果としてはプレビュー画面への遷移にて表示するファイルを１つに限定し、スワイプによる
     * 次ファイル表示への遷移は無効とすることで対応.
     * プレビューにて開くファイルを制限する方法はnumberOfPreviewItemsInPreviewController の
     * 戻り値にて指定.
     */
    NSFileManager *filemanager = [NSFileManager defaultManager];
    BOOL fileExist = [filemanager fileExistsAtPath:inqFile.fullPath];
    NSLog(@"### file : %@(%d)",inqFile.fullPath,fileExist);

    // ファイルの先読み処理(インデックスが一つ前のファイル)
    if((index - 1) > 0)
    {
        INQFile *preFile = (INQFile *)[self.documents objectAtIndex:index - 1];
        BOOL fileExist = [filemanager fileExistsAtPath:preFile.fullPath];
        if((!preFile.isDir) && (!fileExist))
        {
            dispatch_async(dispatch_get_main_queue(), ^{
                [self.dataSource copyFile:preFile];
                
            });
        }
    }
    // ファイルの先読み処理(インデックスが一つ後のファイル)
    if((index + 1) < [self.documents count])
    {
        INQFile *preFile = (INQFile *)[self.documents objectAtIndex:index + 1];
        BOOL fileExist = [filemanager fileExistsAtPath:preFile.fullPath];
        if((!preFile.isDir) && (!fileExist))
        {
            dispatch_async(dispatch_get_main_queue(), ^{
                [self.dataSource copyFile:preFile];
                
            });
        }
    }
//*********************************************************************************
#endif

	return [NSURL fileURLWithPath:inqFile.fullPath];
#endif
}


#pragma mark -
#pragma mark Table view delegate

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    INQFile *inqFile = (INQFile*)[self.documents objectAtIndex:indexPath.row];
    NSAssert(inqFile,@"INQFile isnull");
    
    if ((self.isSelectMode || self.isDownloadMode) && (inqFile != nil && !inqFile.isDir)) {
        UITableViewCell *cell = [self.tableView cellForRowAtIndexPath:indexPath];        
    
        if ([self.dataSource.selectedRow objectForKey:[NSString stringWithFormat:@"%d",(int)indexPath.row]]) {
            [self.dataSource.selectedRow removeObjectForKey:[NSString stringWithFormat:@"%d",(int)indexPath.row]];

            [cell setAccessoryType:UITableViewCellAccessoryNone];
        
            return;
        }
        [self.dataSource.selectedRow setObject:@"YES" forKey:[NSString stringWithFormat:@"%d",(int)indexPath.row]];

        [cell setAccessoryType:UITableViewCellAccessoryCheckmark];

       // [self.tableView reloadData];
        return;
    }
    

    if (inqFile != nil && inqFile.isDir) {
        INQFileListViewController *controller = [[INQFileListViewController alloc]init];       
        [self.navigationController pushViewController:controller animated:YES];

#if 1
        // dispatch処理で実行しないとiOS7で期待動作にならない
        dispatch_async(dispatch_get_main_queue(), ^{
            
            controller.navigationController.title = inqFile.fileName;
            controller.title = inqFile.fileName;
            controller.mountPoint = self.mountPoint;
            controller.selectMode = self.isSelectMode;
            controller.downloadMode = self.isDownloadMode;
            controller.delegate = self.delegate;
            // controller.selectedRow = self.selectedRow;
            NSString *_path = [self.savedPath stringByAppendingPathComponent:inqFile.fileName];
            
            if (savedComputer) {
                _path = [_path stringByReplacingOccurrencesOfString:@"/" withString:@"\\"];
                [controller loadDataFromServer:savedComputer path:_path];
            } else {
                [controller loadDataFromLocalPath:_path];
            }
            [controller release];
        });
#else
        controller.navigationController.title = inqFile.fileName;
        controller.title = inqFile.fileName;
        controller.selectMode = self.isSelectMode;
        controller.downloadMode = self.isDownloadMode;
        controller.delegate = self.delegate;
       // controller.selectedRow = self.selectedRow;
        NSString *_path = [self.savedPath stringByAppendingPathComponent:inqFile.fileName];
     
        if (savedComputer) {
            _path = [_path stringByReplacingOccurrencesOfString:@"/" withString:@"\\"];            
            [controller loadDataFromServer:savedComputer path:_path];            
        } else {
            [controller loadDataFromLocalPath:_path];
        }
        [controller release];
#endif
        return;
    }

    if (self.isDownloadMode) {
        return;
    }    
    
    if (![self.dataSource.supportFiles objectForKey:[inqFile.fileExt uppercaseString]]) {
        DLog(@"Not suport file:%@",inqFile.fileName);
        return;
    }
    /*
    if ([inqFile.fileExt isEqualToString:@"PNG"] || [inqFile.fileExt isEqualToString:@"JPG"]) {
        INQImageSlideViewController *controller = [[INQImageSlideViewController alloc]init];
        controller.imageArray = imageArray;
        controller.currentFileName = inqFile.fileName;
        [self.navigationController pushViewController:controller animated:YES];
        controller.navigationController.toolbarHidden = YES;
        controller.navigationController.navigationBarHidden = YES;
        [controller release];
        return;        
    }
`   */
    //TODO : Add loading View
    
//  dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
    dispatch_async(dispatch_get_main_queue(), ^{
        loadingView.hidden = NO;
        [loadingView startAnimating];
        [self.dataSource copyFile:inqFile];
        
        dispatch_async(dispatch_get_main_queue(), ^{        
            [loadingView stopAnimating];            
            [loadingView setHidden:YES];
            QLPreviewController * preview = [[QLPreviewController alloc] init];
            preview.dataSource = self;
            
            preview.currentPreviewItemIndex = indexPath.row;
            [self.navigationController pushViewController:preview animated:YES];
            preview.title = inqFile.fileName;
            
            // プレビュー用ファイルのパスを退避(プレビュー対象のファイルを一つに限定する為の処理)
            self.previewFilePath = inqFile.fullPath;

#if 0
            // ツールバー(タブバー)を非表示
            preview.navigationController.toolbarHidden = YES;
#endif
            
            [preview release];
        });
    });
}


- (CGFloat)tableView:(UITableView *)tableView heightForRowAtIndexPath:(NSIndexPath *)indexPath {	
	return 60;
}

 
#pragma mark - 
#pragma mark UIActionSheet Delegate Method

- (void)actionSheet:(UIActionSheet *)actionSheet clickedButtonAtIndex:(NSInteger)buttonIndex {

    INQAppDelegate *app = (INQAppDelegate *)[[UIApplication sharedApplication] delegate];
    
    //Photo Album.
    if (buttonIndex == 0) {
        INQAlbumPickerController *albumController = [[INQAlbumPickerController alloc] initWithNibName:@"INQAlbumPickerController"
                                                                                               bundle:[NSBundle mainBundle]];    
        
        INQImagePickerController *inqPicker = [[INQImagePickerController alloc] initWithRootViewController:albumController];
        [albumController setParent:inqPicker];
        [inqPicker setDelegate:self];
        
        [app.viewController presentViewController:inqPicker animated:YES completion:NULL];
        [inqPicker release];
        [albumController release];    
    }
    
    // Local file
    if (buttonIndex == 1) {
#if 1
        // ローカル画面のViewの呼び出し方法を変更(表示形態の統一化の為)
        INQLocalViewController *controller = [[INQLocalViewController alloc]initWithStyle:UITableViewStyleGrouped];
#else
        INQLocalViewController *controller = [[INQLocalViewController alloc]init];
#endif
        controller.selectMode = YES;
        controller.downloadMode = NO;
        controller.delegate = self;
        UINavigationController *navigation = [[UINavigationController alloc]init];
        [navigation addChildViewController:controller];
        
        [app.viewController presentViewController:navigation animated:YES completion:NULL];
        [controller release];
        [navigation release];
    }
}

- (void)inqImagePickerControllerDidCancel:(INQImagePickerController *)picker {
    
	[self dismissViewControllerAnimated:YES completion:NULL];
}

- (void)editFile:(id)selector {
    
    selectMode = YES;
    isEdit = YES;
    UIBarButtonItem *editButton = [[UIBarButtonItem alloc]
                                   initWithBarButtonSystemItem:UIBarButtonSystemItemDone 
                                                        target:self 
                                                        action:@selector(done:)];
    
	[self.navigationItem setRightBarButtonItem:editButton animated:NO];
    if (!isServer) {
        [self.tableView setEditing:YES animated:YES];
        [editButton release];
        return;
    }    
    
    [self.tableView reloadData];  
    [editButton release];    
    

    // Server 
    // upload action
#if 1
    INQAppDelegate *app = (INQAppDelegate *)[[UIApplication sharedApplication] delegate];
    
    // Image of bar button
    UIBarButtonItem *downloadButton;
    if ([[[[UIDevice currentDevice] systemVersion] componentsSeparatedByString:@"."][0] intValue] >= 7)
    {
        UIButton *barBtnDownload = [[[UIButton alloc]initWithFrame:CGRectMake(0, 0, 32, 32)]autorelease];
        [barBtnDownload setBackgroundImage:[app resizeImage:@"icon_download.png" image_size:32] forState:UIControlStateNormal];
        [barBtnDownload addTarget:self action:@selector(fileAction:) forControlEvents:UIControlEventTouchUpInside];
        barBtnDownload.showsTouchWhenHighlighted = YES;
        barBtnDownload.tag = 1;
        
        downloadButton = [[UIBarButtonItem alloc]initWithCustomView:barBtnDownload];
    }
    else
    {
        downloadButton = [[UIBarButtonItem alloc]initWithImage:[app resizeImage:@"icon_download.png" image_size:32]
                                                       style:UIBarButtonItemStylePlain
                                                      target:self
                                                      action:@selector(fileAction:)];
        downloadButton.tag = 1;
    }
#else
    // Text of bar button
    UIBarButtonItem *downloadButton = [[UIBarButtonItem alloc]initWithTitle:NSLocalizedString(@"Download",@"Download")
                                                                      style:UIBarButtonItemStyleBordered target:self 
                                                                     action:@selector(fileAction:)];
    downloadButton.tag = 1;
#endif
    UIBarButtonItem *copydButton = [[UIBarButtonItem alloc]initWithTitle:NSLocalizedString(@"Copy",@"Copy")
                                                                   style:UIBarButtonItemStyleBordered target:self 
                                                                  action:@selector(fileAction:)];
    copydButton.tag = 2;
    UIBarButtonItem *moveButton = [[UIBarButtonItem alloc]initWithTitle:NSLocalizedString(@"Move",@"Move") 
                                                                  style:UIBarButtonItemStyleBordered target:self 
                                                                 action:@selector(fileAction:)];
    moveButton.tag = 3;
#if 1
    // Image of bar button
    UIBarButtonItem *deleteButton;
    if ([[[[UIDevice currentDevice] systemVersion] componentsSeparatedByString:@"."][0] intValue] >= 7)
    {
        UIButton *barBtnDelete = [[[UIButton alloc]initWithFrame:CGRectMake(0, 0, 32, 32)]autorelease];
        [barBtnDelete setBackgroundImage:[app resizeImage:@"icon_delete.png" image_size:32] forState:UIControlStateNormal];
        [barBtnDelete addTarget:self action:@selector(fileAction:) forControlEvents:UIControlEventTouchUpInside];
        barBtnDelete.showsTouchWhenHighlighted = YES;
        barBtnDelete.tag = 4;
        
        deleteButton = [[UIBarButtonItem alloc]initWithCustomView:barBtnDelete];
    }
    else
    {
        deleteButton = [[UIBarButtonItem alloc]initWithImage:[app resizeImage:@"icon_delete.png" image_size:32]
                                                       style:UIBarButtonItemStylePlain
                                                      target:self
                                                      action:@selector(fileAction:)];
        deleteButton.tag = 4;
    }
#else
    // Text of bar button
    UIBarButtonItem *deleteButton = [[UIBarButtonItem alloc]initWithTitle:NSLocalizedString(@"Delete",@"Delete")
                                                                    style:UIBarButtonItemStyleBordered target:self 
                                                                   action:@selector(fileAction:)];
    deleteButton.tag = 4;
#endif
    
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
        barBtnHome.tag = 5;
        
        homeButton = [[UIBarButtonItem alloc]initWithCustomView:barBtnHome];
    }
    else
    {
        homeButton = [[UIBarButtonItem alloc]initWithImage:[app resizeImage:@"icon_home.png" image_size:32]
                                                     style:UIBarButtonItemStylePlain
                                                    target:self
                                                    action:@selector(backToHome)];
        homeButton.tag = 5;
    }
#else
    // Text of bar button
    UIBarButtonItem *homeButton = [[UIBarButtonItem alloc]initWithTitle:NSLocalizedString(@"Home",@"Home")
                                                                  style:UIBarButtonItemStyleBordered 
                                                                 target:self 
                                                                 action:@selector(fileAction:)];
    homeButton.tag = 5;
#endif
    
    // self.navigationItem.rightBarButtonItem = actionButton;
#if 1
    // ツールバーボタンの配置変更
    NSArray *items = [NSArray arrayWithObjects:downloadButton,spaceButton,deleteButton,spaceButton,homeButton,nil];
#else
    NSArray *items = [NSArray arrayWithObjects:downloadButton,deleteButton,spaceButton,homeButton,nil];
#endif
    self.toolbarItems = items;
    
    [downloadButton release];
    [copydButton release];
    [moveButton release];
    [deleteButton release];
    [spaceButton release];
    [homeButton release];

}

#pragma mark -
#pragma mark  download,delete action

- (void)fileAction:(id)sender {
    INQAppDelegate *app = (INQAppDelegate *)[[UIApplication sharedApplication] delegate];    
    UIBarButtonItem *button = (UIBarButtonItem*)sender;
    NSInteger tag = button.tag;
    switch (tag) {
        case 1: // download
        {
       
            if ([self.dataSource.selectedRow count] == 0) {
                [self alertMessage:NSLocalizedString(@"SelectFile", @"select download file")];
                return;
            }
#if 1
            // ローカルフォルダ画面を開く際のスタイルをグループに設定
            INQLocalViewController *controller = [[INQLocalViewController alloc]initWithStyle:UITableViewStyleGrouped];
#else
            INQLocalViewController *controller = [[INQLocalViewController alloc]init];
#endif
            UINavigationController *navigation = [[UINavigationController alloc]init];
            [navigation addChildViewController:controller];
            controller.downloadMode = YES;
            controller.selectMode = NO;
            controller.delegate = self;
            [app.viewController presentViewController:navigation animated:YES completion:NULL];
            [controller release];
            [navigation release];

        }
            break;
        case 2: //copy
            
            break;
        case 3: //move{
            //document dir
        {
            __block NSString *docPath = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
            docPath = [docPath stringByAppendingPathComponent:savedPath];

            dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                [self.dataSource.selectedRow enumerateKeysAndObjectsUsingBlock:^(id key, id obj, BOOL *stop) {
                    int row = [(NSString*)key intValue];                    
                    INQFile *inqFile = [self.documents objectAtIndex:row];
#if 1
                    // warning対応
                    docPath = [docPath stringByAppendingFormat:@"%@",inqFile.fileName];
#else
                    docPath = [docPath stringByAppendingFormat:inqFile.fileName];
#endif
                    if(![INQRemoteFileManager moveFile:[NSString stringWithFormat:@"\\\\%@\\%@\\%@",savedComputer,savedPath,inqFile.fileName] to:docPath]) {
                        [self alertMessage:NSLocalizedString(@"MoveFileFailed", @"Move file failed")];
                        return;
                    }
                    
                }];  
                dispatch_async(dispatch_get_main_queue(), ^{
                    [self.dataSource.selectedRow removeAllObjects];
                    [self loadDataFromServer:savedComputer path:savedPath];                                    
                });
                
            });               
            break;
        }
        case 4: {//delete 
            UIAlertView *deleteNowView = [[UIAlertView alloc]initWithTitle:NSLocalizedString(@"Warning",@"Warning") 
                                                                   message:NSLocalizedString(@"AreYouSureDelete",@"are you sure delete file ?") 
                                                                  delegate:self 
                                                         cancelButtonTitle:NSLocalizedString(@"YES",@"YES") 
                                                         otherButtonTitles:NSLocalizedString(@"NO", @"NO"), nil];
            deleteNowView.tag = 100;
            [deleteNowView show];
            [deleteNowView release];
                 
            break;            
        }
        case 5: //backToHome
            [self backToHome];
            break;            
        default:
            break;
    }
}

#pragma mark - 
#pragma mark upload download action

- (void)upload:(id)sender {
    
    self.navigationController.toolbarHidden = NO;
    UIBarButtonItem *spaceButton = [[UIBarButtonItem alloc]initWithBarButtonSystemItem:UIBarButtonSystemItemFlexibleSpace 
                                                                                target:nil 
                                                                                action:nil];
        
    UIBarButtonItem *uploadButton = [[UIBarButtonItem alloc]initWithTitle:NSLocalizedString(@"UploadSelectFiles",@"Upload Selecte Files") 
                                                                    style:UIBarButtonItemStyleBordered 
                                                                   target:self 
                                                                   action:@selector(endUpload)];  
    
    self.toolbarItems = [NSArray arrayWithObjects:spaceButton,uploadButton,spaceButton,nil];
    [spaceButton release];
    [uploadButton release];
    
}

- (void)download:(id)sender {
    UIBarButtonItem *endButton = [[UIBarButtonItem alloc]initWithBarButtonSystemItem:UIBarButtonSystemItemAdd 
                                                                              target:self 
                                                                              action:@selector(createFolder)];
    
	[self.navigationItem setRightBarButtonItem:endButton animated:NO];
    
    [endButton release];
    
    self.navigationController.toolbarHidden = NO;
    UIBarButtonItem *spaceButton = [[UIBarButtonItem alloc]initWithBarButtonSystemItem:UIBarButtonSystemItemFlexibleSpace
                                                                                 target:nil 
                                                                                 action:nil];
    
    UIBarButtonItem *uploadButton = [[UIBarButtonItem alloc]initWithTitle:NSLocalizedString(@"DownloadHear",@"Download Selecte Files") style:UIBarButtonItemStyleBordered target:self action:@selector(endDownload)];  
    
    self.toolbarItems = [NSArray arrayWithObjects:spaceButton,uploadButton,spaceButton,nil];    
    [spaceButton release];
    [uploadButton release];
}

- (void)endUpload {
    [self dismissViewControllerAnimated:YES completion:NULL];
    
    NSMutableArray *array = [[NSMutableArray alloc]init];
    [self.dataSource.selectedRow enumerateKeysAndObjectsUsingBlock:^(id key, id obj, BOOL *stop) {
        int row = [(NSString*)key intValue];
        INQFile *inqFile = [self.documents objectAtIndex:row];
        [array addObject:inqFile];

    }];  
    
    [self.delegate didEndUploadCallBack:array];   
    [array release];
}


- (void)endDownload {

    [self dismissViewControllerAnimated:YES completion:NULL];
    
    //document dir
    NSString *docPath=[NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    docPath = [docPath stringByAppendingPathComponent:savedPath];
    DLog(@"Dwonload Path:%@",docPath);
    [self.delegate didEndDownloadCallBack:docPath];   

}

- (void)done:(id)sender {
    isEdit = NO;
    UIBarButtonItem *doneButton =
    [[UIBarButtonItem alloc]
     initWithBarButtonSystemItem:UIBarButtonSystemItemEdit target:self action:@selector(editFile:)];
    
	[self.navigationItem setRightBarButtonItem:doneButton animated:NO];
    
    [doneButton release];
    
    [self.dataSource.selectedRow enumerateKeysAndObjectsUsingBlock:^(id key, id obj, BOOL *stop) {
        int row = [(NSString*)key intValue];
        UITableViewCell *cell = [self.tableView cellForRowAtIndexPath:[NSIndexPath indexPathForRow:row inSection:0]];        

        if ([self.dataSource.selectedRow objectForKey:[NSString stringWithFormat:@"%d",row]]) {
#if 1
            // iOS6では以下の行を有効にすると落ちるのでiOS7以降でのみ有効とする様に対応(暫定対応)
            if ([[[[UIDevice currentDevice] systemVersion] componentsSeparatedByString:@"."][0] intValue] >= 7)
            {
                [self.dataSource.selectedRow removeObjectForKey:[NSString stringWithFormat:@"%d",row]];
            }
#else
            [self.dataSource.selectedRow removeObjectForKey:[NSString stringWithFormat:@"%d",row]];
#endif
            
            [cell setAccessoryType:UITableViewCellAccessoryNone];
        }        
        
    }]; 
    
    [self.dataSource.selectedRow removeAllObjects];
    self.selectMode = NO;
    self.downloadMode = NO;
    [self.tableView reloadData];       
  
    // upload action
#if 1
    INQAppDelegate *app = (INQAppDelegate *)[[UIApplication sharedApplication] delegate];

    // Image of bar button
    UIBarButtonItem *uploadButton;
    if ([[[[UIDevice currentDevice] systemVersion] componentsSeparatedByString:@"."][0] intValue] >= 7)
    {
        UIButton *btnImageUpload = [[[UIButton alloc]initWithFrame:CGRectMake(0, 0, 32, 32)]autorelease];
        [btnImageUpload setBackgroundImage:[app resizeImage:@"icon_upload.png" image_size:32] forState:UIControlStateNormal];
        [btnImageUpload addTarget:self action:@selector(upload) forControlEvents:UIControlEventTouchUpInside];
        btnImageUpload.showsTouchWhenHighlighted = YES;
        
        uploadButton = [[UIBarButtonItem alloc]initWithCustomView:btnImageUpload];
    }
    else
    {
        uploadButton = [[UIBarButtonItem alloc]initWithImage:[app resizeImage:@"icon_upload.png" image_size:32]
                                                       style:UIBarButtonItemStylePlain
                                                      target:self
                                                      action:@selector(upload)];
    }
#else
    // Text of bar button
    UIBarButtonItem *uploadButton = [[UIBarButtonItem alloc]initWithTitle:NSLocalizedString(@"Upload",@"Upload")
                                                                    style:UIBarButtonItemStyleBordered 
                                                                   target:self 
                                                                   action:@selector(upload)];
#endif

#if 1
    // Image of bar button
    UIBarButtonItem *newFolderButton;
    if ([[[[UIDevice currentDevice] systemVersion] componentsSeparatedByString:@"."][0] intValue] >= 7)
    {
        UIButton *btnImageNewFolder = [[[UIButton alloc]initWithFrame:CGRectMake(0, 0, 32, 32)]autorelease];
        [btnImageNewFolder setBackgroundImage:[app resizeImage:@"icon_newfolder.png" image_size:32] forState:UIControlStateNormal];
        [btnImageNewFolder addTarget:self action:@selector(createFolder) forControlEvents:UIControlEventTouchUpInside];
        btnImageNewFolder.showsTouchWhenHighlighted = YES;
        
        newFolderButton = [[UIBarButtonItem alloc]initWithCustomView:btnImageNewFolder];
    }
    else
    {
        newFolderButton = [[UIBarButtonItem alloc]initWithImage:[app resizeImage:@"icon_newfolder.png" image_size:32]
                                                                           style:UIBarButtonItemStylePlain
                                                                          target:self
                                                                          action:@selector(createFolder)];
    }
#else
    // Text of bar button
    UIBarButtonItem *newFolderButton = [[UIBarButtonItem alloc]initWithTitle:NSLocalizedString(@"NewFolder",@"New Folder")
                                                                       style:UIBarButtonItemStyleBordered 
                                                                      target:self 
                                                                      action:@selector(createFolder)];
#endif
    
#if 0
    // Analyze対応 [Value stored to 'bookMarkButton' during its initialization is never read]
    UIBarButtonItem *bookMarkButton = [[UIBarButtonItem alloc]initWithTitle:NSLocalizedString(@"BookMark",@"BookMark Folder")
                                                                       style:UIBarButtonItemStyleBordered 
                                                                      target:self 
                                                                      action:@selector(bookMark)];
#endif
    
#if 1
    // Image of bar button
    UIBarButtonItem *newPhotoButton;
    if ([[[[UIDevice currentDevice] systemVersion] componentsSeparatedByString:@"."][0] intValue] >= 7)
    {
        UIButton *btnImageSharePhoto = [[[UIButton alloc]initWithFrame:CGRectMake(0, 0, 32, 32)]autorelease];
        [btnImageSharePhoto setBackgroundImage:[app resizeImage:@"icon_photoshare.png" image_size:32] forState:UIControlStateNormal];
        [btnImageSharePhoto addTarget:self action:@selector(addPhoto) forControlEvents:UIControlEventTouchUpInside];
        btnImageSharePhoto.showsTouchWhenHighlighted = YES;
        
        newPhotoButton = [[[UIBarButtonItem alloc]initWithCustomView:btnImageSharePhoto]autorelease];
    }
    else
    {
        newPhotoButton = [[[UIBarButtonItem alloc]initWithImage:[app resizeImage:@"icon_photoshare.png" image_size:32]
                                                          style:UIBarButtonItemStylePlain
                                                         target:self
                                                         action:@selector(addPhoto)]autorelease];
    }
#else
    // Text of bar button
    UIBarButtonItem *newPhotoButton = [[UIBarButtonItem alloc]initWithTitle:NSLocalizedString(@"SharePhoto",@"SharePhoto")
                                                                      style:UIBarButtonItemStyleBordered 
                                                                     target:self 
                                                                     action:@selector(addPhoto)];
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
        UIButton *btnImageHome = [[[UIButton alloc]initWithFrame:CGRectMake(0, 0, 32, 32)]autorelease];
        [btnImageHome setBackgroundImage:[app resizeImage:@"icon_home.png" image_size:32] forState:UIControlStateNormal];
        [btnImageHome addTarget:self action:@selector(backToHome) forControlEvents:UIControlEventTouchUpInside];
        btnImageHome.showsTouchWhenHighlighted = YES;
        
        homeButton = [[UIBarButtonItem alloc]initWithCustomView:btnImageHome];
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
    UIBarButtonItem *homeButton = [[UIBarButtonItem alloc]initWithTitle:NSLocalizedString(@"Home",@"Home") style:UIBarButtonItemStyleBordered target:self action:@selector(fileAction:)];
#endif
    homeButton.tag = 5;
    
#if 1
    // ツールバーボタンの配置変更
    NSArray *items = [NSArray arrayWithObjects:uploadButton,spaceButton,newFolderButton,spaceButton,homeButton,nil];
#else
    NSArray *items = [NSArray arrayWithObjects:uploadButton,newFolderButton,spaceButton,homeButton,nil];
#endif
    
    if (!isServer) {
#if 1
        // ツールバーボタンの配置変更
        items = [NSArray arrayWithObjects:newFolderButton,spaceButton,newPhotoButton,spaceButton,homeButton, nil];
#else
        items = [NSArray arrayWithObjects:newFolderButton,newPhotoButton,spaceButton,homeButton, nil];
#endif
        [self.tableView setEditing:NO animated:YES];
    }     
    self.toolbarItems = items;  
    
    [uploadButton release];
    [newFolderButton release];
    [spaceButton release];
    [homeButton release];

}

- (void)addPhoto {
    INQAppDelegate *app = (INQAppDelegate *)[[UIApplication sharedApplication] delegate];
    
    INQAlbumPickerController *albumController = [[INQAlbumPickerController alloc] initWithNibName:@"INQAlbumPickerController"
                                                                                           bundle:[NSBundle mainBundle]];    
    
    INQImagePickerController *inqPicker = [[INQImagePickerController alloc] initWithRootViewController:albumController];
    [albumController setParent:inqPicker];
    [inqPicker setDelegate:self];
    
    [app.viewController presentViewController:inqPicker animated:YES completion:NULL];
    [inqPicker release];
    [albumController release];    
    
}

- (void)bookMark {
    
#if 1
    // Analyze対応 [Potential leak of an object stored into 'bookMark']
    INQBookMark *bookMark = [[[INQBookMark alloc]init]autorelease];
#else
    INQBookMark *bookMark = [[INQBookMark alloc]init];
#endif
    bookMark.bookMarkId = [INQBookMarkDataSource getKey];
    bookMark.bookMarkName = savedPath;
    bookMark.computer = savedComputer;
    bookMark.fullPath = savedPath;
    [INQBookMarkDataSource saveBookMark:bookMark];
    [self alertMessage:NSLocalizedString(@"SaveBookMarkOK", @"save book mark ")];
    
}

- (void)remoteShareNameFromPath:(NSMutableString *)mountPath from:(NSString *)orgPath{

    NSMutableString *original = [NSMutableString stringWithString:orgPath];
    
    //[mountPath appendString:@"\\"];
    [original appendString:@"\\"];
    [original deleteCharactersInRange:  NSMakeRange(0,[original rangeOfString: @"\\"].location)];
    [mountPath appendString: original];

}

- (void)setEditing:(BOOL)editing animated:(BOOL)animated {
    [super setEditing:editing animated:animated];
  //  [self.tableView setEditing:editing animated:YES];
    if (editing) {
        UIBarButtonItem *doneButton = [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemDone
                                                                                     target:self 
                                                                                    action:@selector(done)];
        [self.navigationItem setRightBarButtonItem:doneButton animated:YES];
        [doneButton release];        
    } else { 
        UIBarButtonItem *editButtonItem = [[UIBarButtonItem alloc]initWithBarButtonSystemItem:UIBarButtonSystemItemEdit 
                                                                                       target:self 
                                                                                       action:@selector(editWorkgroup)];
        self.navigationItem.rightBarButtonItem = editButtonItem;
        [editButtonItem release]; 
    }
}

- (void)upload {
    UIActionSheet *actionSheet = [[UIActionSheet alloc]initWithTitle:NSLocalizedString(@"Upload", @"Upload") 
                                                            delegate:self 
                                                   cancelButtonTitle:NSLocalizedString(@"Cancel", @"Cancel") 
                                              destructiveButtonTitle:NSLocalizedString(@"PhotoAlbum", @"Photo Album") otherButtonTitles:NSLocalizedString(@"LocalFile", @"LocalFile"), nil];
    [actionSheet showInView:self.tableView];
    [actionSheet release];
}

/**
 * @brief ”新しいフォルダー”ボタン イベントハンドラ
 */
- (void)createFolder
{
    [self showWithTitle:NSLocalizedString(@"NewFolder",@"NewFolder") text:nil]; 
}

#pragma mark - HOME Button.
- (void)backToHome {
    [self.navigationController popToViewController:[self.navigationController.viewControllers objectAtIndex:1] animated:YES];
    
}

#pragma mark -
#pragma mark INQImagePickerControllerDelegate Methods

- (void)inqImagePickerController:(INQImagePickerController *)picker didFinishPickingMediaWithInfo:(NSArray *)info {
    [self dismissViewControllerAnimated:YES completion:NULL];
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        
        for (int i = 0; i < [info count]; i++) {
            NSMutableDictionary *pic = [info objectAtIndex:i];
            DLog(@"select picture : %@",pic);     
            UIImage *img = (UIImage*)[pic objectForKey:UIImagePickerControllerOriginalImage];
            NSString *filePaht = [[pic objectForKey:UIImagePickerControllerReferenceURL]absoluteString];
            NSArray *arr = [filePaht componentsSeparatedByString:@"="];
            NSString *fileName = [[[arr objectAtIndex:1] componentsSeparatedByString:@"&"] objectAtIndex:0];
            NSArray *fa = [fileName componentsSeparatedByString:@"-"];
            fileName = [fa objectAtIndex:([fa count] -1)];
            NSString *fileType = [[arr objectAtIndex:2] uppercaseString];
            //NSMutableString *relativePath = [NSMutableString stringWithString: self.mountPoint];
            NSMutableString *relativePath;
            if (isServer){
                relativePath = [NSMutableString stringWithString: self.mountPoint];
                [self remoteShareNameFromPath:relativePath from:savedPath];
            }
            if (isServer) {
                            
                //if(![INQRemoteFileManager uploadImage:img imageType:fileType toRemotePath:[NSString stringWithFormat:@"\\\\%@\\%@\\%@.%@",savedComputer,savedPath,fileName,fileType]]) {
                if(![INQRemoteFileManager uploadImage:img imageType:fileType toRemotePath: [NSString stringWithFormat: @"\\%@%@.%@" , relativePath , fileName , fileType]]) {
                    [self alertMessage:NSLocalizedString(@"UploadFailed", @"Upload file failed.")];
                    return;
                }
            } else {
                //local share album.
                NSString *docPath=[NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
                docPath = [[docPath stringByAppendingPathComponent:savedPath] stringByAppendingPathComponent:fileName];
                
                if ([fileType isEqualToString:@"JPG"]) {
                    [UIImageJPEGRepresentation(img, 1.0) writeToFile:[NSString stringWithFormat:@"%@.JPG",docPath] atomically:YES];                
                }
                
                if ([fileType isEqualToString:@"PNG"]) {
                    // Write image to PNG
                    [UIImagePNGRepresentation(img) writeToFile:[NSString stringWithFormat:@"%@.PNG",docPath] atomically:YES];                
                }  
                DLog(@"Copy file to:%@",docPath);
            }
        } 
        
        dispatch_async(dispatch_get_main_queue(), ^{
            [self startLoading];

        });
    });
     
}

- (void)endUploadTask {
    [self loadDataFromServer:savedComputer path:savedPath];
}

- (void)didEndUploadCallBack:(NSArray *)inqFiles {
    
    dispatch_sync(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        [self.loadingView setHidden:NO];
        [self.loadingView startAnimating];   
        for (INQFile *inqFile in inqFiles) {
            DLog(@"Upload File:%@",[NSString stringWithFormat:@"\\\\%@\\%@\\%@",savedComputer,savedPath,inqFile.fileName]);
            if(![INQRemoteFileManager uploadFileFromLocalPath:inqFile.fullPath toRemotepath:[NSString stringWithFormat:@"\\\\%@\\%@\\%@",savedComputer,savedPath,inqFile.fileName]]) {
                [self alertMessage:NSLocalizedString(@"UploadFailed", @"Upload file failed.")];
                return;
            }
        }
        
        dispatch_async(dispatch_get_main_queue(), ^{
            //[self loadDataFromServer:savedComputer path:savedPath];
            [self startLoading];
        });
    });     
}


- (void)didEndDownloadCallBack:(NSString*)downloadTo {
    
    dispatch_sync(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        [self.loadingView setHidden:NO];
        [self.loadingView startAnimating];  
        [self.dataSource.selectedRow enumerateKeysAndObjectsUsingBlock:^(id key, id obj, BOOL *stop) {
            int row = [(NSString*)key intValue];
            INQFile *inqFile = [self.documents objectAtIndex:row];
            NSString *downloadFileName = [downloadTo stringByAppendingPathComponent:inqFile.fileName];
            if(![INQRemoteFileManager copyFile:[NSString stringWithFormat:@"\\\\%@\\%@\\%@",savedComputer,savedPath,inqFile.fileName] to:downloadFileName]) {
                [self alertMessage:NSLocalizedString(@"CopyFailed", @"Copy file failed.")];                
                return;
            }
        
        }];  
        [self.loadingView setHidden:YES];
        [self.loadingView stopAnimating];  
    });    
}

#pragma mark -
#pragma mark AlertView

- (void)alertMessage:(NSString*)msg {
    // アラートの表示形態を統一
    UIAlertView *alertView = [[UIAlertView alloc]initWithTitle:msg
                                                       message:nil
                                                      delegate:nil
                                             cancelButtonTitle:NSLocalizedString(@"OK",@"OK Button")
                                             otherButtonTitles:nil, nil];
     [alertView show];
     [alertView release];
}

/**
 * @brief Alert表示処理(テキスト入力処理付き)
 */
- (void)showWithTitle:(NSString *)title text:(NSString *)text
{
#if 1
    // text field付きアラート表示の処理変更
    NSString* message = Nil;
    NSString* buttonTitleCancel = NSLocalizedString(@"Cancel",@"Cancel Button");
    NSString* buttonTitleOK = NSLocalizedString(@"OK",@"OK Button");
    
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
                                          cancelButtonTitle:NSLocalizedString(@"Cancel",@"Cancel Button")
                                          otherButtonTitles:NSLocalizedString(@"OK",@"OK Button"), nil];
	textField = [[UITextField alloc] initWithFrame:CGRectMake(12, 45, 260, 25)];
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

#pragma mark -
#pragma mark UIAlertView delegate method.

- (void)alertView:(UIAlertView *)alertView clickedButtonAtIndex:(NSInteger)buttonIndex {
    
	if (alertView.tag == 100) {
        //delete 
        if (buttonIndex == 0) {
            dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                [self.dataSource.selectedRow enumerateKeysAndObjectsUsingBlock:^(id key, id obj, BOOL *stop) {
                    int row = [(NSString*)key intValue];                    
                    INQFile *inqFile = [self.documents objectAtIndex:row];
                    //NSString *remoteFile = [NSString stringWithFormat:@"\\\\%@\\%@\\%@",savedComputer,savedPath,inqFile.fileName];
                    NSMutableString *relativePath = [NSMutableString stringWithString: self.mountPoint];
                    [self remoteShareNameFromPath:relativePath from:savedPath];
                    NSString *remoteFile = [NSString stringWithFormat:@"\\%@%@",relativePath,inqFile.fileName];
                    if(![INQRemoteFileManager deleteFile:remoteFile]) {
                        DLog(@"Delete failed:%@",remoteFile);
                        [self alertMessage:NSLocalizedString(@"DeleteFailed",@"Delete file filed.")];
                        return;
                    }
                    
                }];  
                dispatch_async(dispatch_get_main_queue(), ^{
                    [self.dataSource.selectedRow removeAllObjects];
                    //[self loadDataFromServer:savedComputer path:savedPath];
                    [self startLoading];
                    [self done:self];
                });
                
            });  
        }
        return;
    }
    
    [textField resignFirstResponder];

    // create new folder.
	if (buttonIndex == 1)
    {
#if 1
        // text field付きアラート表示の処理変更
        // textFieldの入力内容を取得
        //NSMutableString    *mntPtPath = [[NSMutableString alloc] initWithString:savedPath]; // search path relevant to mount point
        //NSMutableString    *mntPtPath = [[NSMutableString alloc] initWithString:self.mountPoint]; // search path relevant to mount point
        NSMutableString    *mntPtPath;
        if (isServer)
            mntPtPath = [[NSMutableString alloc] initWithString:self.mountPoint]; // search path relevant to mount point
        NSString *inputText =
        [[[alertView textFieldAtIndex:0] text] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
        
        //[mntPtPath appendString:@"\\"];
        //[mntPtPath deleteCharactersInRange:  NSMakeRange(0,[mntPtPath rangeOfString: @"\\"].location)];
        [self remoteShareNameFromPath:mntPtPath from:savedPath];
        
#else
        NSString *inputText = textField.text;
        inputText = [inputText stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
#endif
        NQ_TCHAR uDirectory[1000];
#ifdef UD_CM_UNICODEAPPLICATION /* mizuguchi UTF-8 <-> UTF-16 */
        //cmWStrcpy(uDirectory, (NQ_TCHAR *)[[NSString stringWithFormat:@"\\\\%@\\%@\\%@",savedComputer,savedPath,inputText]
        //                                    cStringUsingEncoding:NSUTF16StringEncoding]);
        cmWStrcpy(uDirectory, (NQ_TCHAR *)[[NSString stringWithFormat:@"\\%@%@" , mntPtPath,inputText]
                                          cStringUsingEncoding:NSUTF16StringEncoding]);
        DLog(@"Directory(UTF-16):%S", (const NQ_TCHAR *)uDirectory);
#else
        const char *directory;
        directory = [[NSString stringWithFormat:@"\\\\%@\\%@\\%@",savedComputer,savedPath,inputText] UTF8String];
 
        
        cmAnsiToTchar(uDirectory,directory);
#endif
        if (isServer) {
            if(!ccCreateDirectory(uDirectory)) {
                [self alertMessage:NSLocalizedString(@"CreateFolderFailed", @"CreateFolderFailed")];
                return;
            }
            [self startLoading];              
            return;
        }
        
        NSString *documentsDirectory = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];   
        NSString *path = [documentsDirectory stringByAppendingPathComponent:savedPath];
        path = [path stringByAppendingPathComponent:inputText];        
        NSError *error = nil;
        if ([[NSFileManager defaultManager] isReadableFileAtPath:path]) {
            DLog(@"Directory Found in path : %@",path);
            return;
        }
        [[NSFileManager defaultManager] createDirectoryAtPath:path withIntermediateDirectories:YES attributes:nil error:&error];
        if (error) {
            DLog(@"Create Document Directory Error:%@",error);
            [self alertMessage:NSLocalizedString(@"CreateFolderFailed", @"CreateFolderFailed")];
            return;
        }  
        //[self loadDataFromLocalPath:savedPath];
        [self startLoading];
	}
}

#pragma mark -
#pragma makr override refresh.

- (void)refresh {
    if (savedComputer) {
        [self.dataSource loadDataFromServer:savedComputer path:self.savedPath];   
    } else {
        [self.dataSource loadDataFromLocalPath:self.savedPath];        
    }
}

@end
