
#import "INQSharedFolderViewController.h"
#import "INQAppDelegate.h"

@interface INQSharedFolderViewController ()

@end

@implementation INQSharedFolderViewController
@synthesize data = data_;
@synthesize computerInfo;
@synthesize isBookMark;
- (id)initWithNibName:(NSString *)nibNameOrNil bundle:(NSBundle *)nibBundleOrNil {
    self = [super initWithNibName:nibNameOrNil bundle:nibBundleOrNil];
    if (self) {
        // Custom initialization
    }
    return self;
}

- (void)viewDidLoad {
    [super viewDidLoad];  
    [self.tableView setDelegate:self];
    
    dataSource = [[INQSharedFolderDataSource alloc]init];;
    
    [self.tableView setDataSource:dataSource];
    [dataSource setDelegate:self];
    //[dataSource setComputerInfo:computerInfo];

    [self.tableView setHidden:NO];
    
    UIBarButtonItem *spaceButton =
        [[UIBarButtonItem alloc]initWithBarButtonSystemItem:UIBarButtonSystemItemFlexibleSpace
                                                     target:nil
                                                     action:nil];
    
    INQAppDelegate *app = (INQAppDelegate *)[[UIApplication sharedApplication] delegate];

    // Image of bar button
    UIBarButtonItem *homeButton;
    if ([[[[UIDevice currentDevice] systemVersion] componentsSeparatedByString:@"."][0] intValue] >= 7)
    {
        UIButton *barBtnHome = [[[UIButton alloc]initWithFrame:CGRectMake(0, 0, 32, 32)]autorelease];
        [barBtnHome setBackgroundImage:[app resizeImage:@"icon_home.png" image_size:32] forState:UIControlStateNormal];
        [barBtnHome addTarget:self action:@selector(backToHome) forControlEvents:UIControlEventTouchUpInside];
        barBtnHome.showsTouchWhenHighlighted = YES;
        
        homeButton = [[[UIBarButtonItem alloc]initWithCustomView:barBtnHome]autorelease];
    }
    else
    {
        homeButton = [[[UIBarButtonItem alloc]initWithImage:[app resizeImage:@"icon_home.png" image_size:32]
                                                       style:UIBarButtonItemStylePlain
                                                      target:self
                                                      action:@selector(backToHome)]autorelease];
    }

    homeButton.tag = 5;
    
    // お気に入り設定ボタンを非表示対応
    NSArray *items = [NSArray arrayWithObjects:spaceButton,homeButton,nil];

    // Analyze対応 [Potential leak of an object stored into 'spaceButton']
    [spaceButton release];
    
    self.toolbarItems = items;
    CGRect frame = self.tableView.frame;
    frame.size.height -= 20 + (2 * self.navigationController.toolbar.frame.size.height);
    self.tableView.frame = frame;
    
    // ---------------------------------------------------------------------
    // iOS7以降対応 : UINavigationBarとStatusBarをUIViewに上被せで表示させない処理
    if ([[[[UIDevice currentDevice] systemVersion] componentsSeparatedByString:@"."][0] intValue] >= 7)
    {
        self.edgesForExtendedLayout = UIRectEdgeNone;
    }

    [self startLoading];
}

- (void)dealloc {

    // 'viewDidUnload' is deprecated: first deprecated in iOS6.0対応
    [data_ release];
    data_ = nil;
    [computerInfo release];
    computerInfo = nil;
    [dataSource release];
    dataSource = nil;
    [super dealloc];    
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    self.navigationController.navigationBar.hidden = NO;    
    self.navigationController.toolbarHidden = NO;      
}

- (void)viewDidAppear:(BOOL)animated {
    [super viewDidAppear:animated];
    //[self.tableView reloadData];
}

-(void)viewWillLayoutSubviews
{
  [super viewDidLayoutSubviews];
  CGRect rect = self.navigationController.navigationBar.frame;
  float y = -rect.origin.y;
  rect = self.navigationController.toolbar.frame;
  float b = -rect.size.height;
  self.tableView.contentInset = UIEdgeInsetsMake(y, 0, b, 0);
}

#if 1
- (void)loadedDataSourceCallBack:(NSArray*)dt info:(NSString *)info option:(NSInteger)type {
#else
- (void)loadedDataSourceCallBack:(NSArray*)dt info:(NSString *)info {
#endif
    [self stopLoading];
    self.messageLabel.hidden = YES;

#if 0
    // (暫定対応) infoがnil以外の場合は基本的にはエラーだが、詳細が不明につきエラー表示は行わない様に対応.
    //           以下の処理を有効にするとView上のラベルに表示されてしまうのでコメントアウト.
    if (info != nil) {
        self.messageLabel.text = info;
        self.messageLabel.hidden = NO;
    }
#endif
    
    if (self.data == nil) {
        data_ = [[NSMutableArray alloc]initWithArray:dt];
    } else {
        [self.data removeAllObjects];
        [self.data addObjectsFromArray:dt];        
    }

    [self.tableView reloadData];    
}

- (void)viewDidUnload {

    [data_ release];
    data_ = nil;
    [computerInfo release];
    computerInfo = nil;
    [dataSource release];    
    dataSource = nil;
    [super viewDidUnload];

}

- (void)bookMark {
    NSMutableDictionary *org = [[NSUserDefaults standardUserDefaults] objectForKey:BOOKMARK];
    
    if (org == nil) {
        org = [[[NSMutableDictionary alloc]init]autorelease];
    }
    
    NSMutableDictionary *orgdic = [NSMutableDictionary dictionaryWithDictionary:org];
    NSDictionary *dic = [[NSMutableDictionary alloc]init]; 
    [dic setValue:computerInfo.computerNameIP forKey:COMPUTER];
    [dic setValue:computerInfo.displayName forKey:DISPLAY_NAME];
    [dic setValue:computerInfo.workGroup forKey:WORKGROUP];
    [dic setValue:computerInfo.userName forKey:USER_NAME];
    [dic setValue:computerInfo.password forKey:PASSWORD];
  
    [orgdic setValue:dic forKey:computerInfo.computerId];

    [[NSUserDefaults standardUserDefaults] setObject:orgdic forKey:BOOKMARK];
    [[NSUserDefaults standardUserDefaults] synchronize];
    [self alertMessage:NSLocalizedString(@"SaveBookMarkOK", @"save book mark ")];
    [dic release];
    
}

#pragma mark -
#pragma mark AlertView

- (void)alertMessage:(NSString*)msg {
    UIAlertView *alertView = [[UIAlertView alloc]initWithTitle:@"" 
                                                       message:msg 
                                                      delegate:nil 
                                             cancelButtonTitle:NSLocalizedString(@"OK",@"OK Button") 
                                             otherButtonTitles:nil, nil];
    [alertView show];
    [alertView release];
}
- (BOOL)shouldAutorotateToInterfaceOrientation:(UIInterfaceOrientation)interfaceOrientation {
    return (interfaceOrientation == UIInterfaceOrientationPortrait);
}

#pragma mark - HOME Button.
- (void)backToHome {
    [self.navigationController popToViewController:[self.navigationController.viewControllers objectAtIndex:1] animated:YES];
    
}

#pragma mark -
#pragma mark UITableViewDelegate method

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {

    INQShareFolder *folder = (INQShareFolder*)[self.data objectAtIndex:indexPath.row];
   
    if (!folder.isMounted) {
        return;
    }
    
    INQFileListViewController *controller = [[INQFileListViewController alloc]initWithStyle:UITableViewStylePlain];       
    [self.navigationController pushViewController:controller animated:YES];

    // dispatch処理で実行しないとiOS7で期待動作にならない
    dispatch_async(dispatch_get_main_queue(), ^{
        controller.title = folder.folderName;
        controller.mountPoint = folder.mountPoint;
        [controller loadDataFromServer:computerInfo.computerNameIP path:folder.folderName];
        [controller release];
    });
    
    // テーブル再描画処理(選択したテーブルの行の状態が選択色のままになるのを回避)
    [self.tableView reloadData];
}

- (UIView *)tableView:(UITableView *)tableView viewForHeaderInSection:(NSInteger)section
{
    UIView *sectionView = [[[UIView alloc]initWithFrame:CGRectMake(0, 0, [UIScreen mainScreen].bounds.size.width, 20)]autorelease];
    UILabel *textLabel = [[[UILabel alloc]initWithFrame:CGRectMake(10, 0, [UIScreen mainScreen].bounds.size.width, 20)]autorelease];
    
    sectionView.backgroundColor = [UIColor colorWithRed:191.f/255.f green:191.f/255.f blue:191.f/255.f alpha:0.8];
    
    textLabel.backgroundColor = [UIColor clearColor];
    textLabel.textColor = [UIColor darkGrayColor];
    textLabel.font = [UIFont boldSystemFontOfSize:16.0f];
    textLabel.shadowColor = [UIColor whiteColor];
    textLabel.shadowOffset = CGSizeMake(0, 1);
    
    switch(section) {
        case 0:
            textLabel.text = NSLocalizedString(@"SharedFolder", @"Shared Folder");
            break;
    }
    
    [sectionView addSubview:textLabel];
    
    return sectionView;
}

- (CGFloat)tableView:(UITableView *)tableView heightForHeaderInSection:(NSInteger)section
{
    CGFloat heightSection = 20.0f;
    
    return heightSection;
}

- (void)refresh {
    [dataSource setComputerInfo:computerInfo];    
}

@end
