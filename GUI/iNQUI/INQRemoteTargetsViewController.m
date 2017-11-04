//
//  INQRemoteTargetsViewController.m
//  iNQ
//
//  Created by Tanya Golberg on 3/20/14.
//  Copyright (c) 2014 ryuu@hotit.co.jp. All rights reserved.
//

#import "INQRemoteTargetsViewController.h"

@interface INQRemoteTargetsViewController ()
{
    NSMutableArray          *data_;
    //NSMutableArray          *dataTmp_;
    INQComputerDataSource   *dataSource;
    BOOL                    dataLoaded;
}

@end

@implementation INQRemoteTargetsViewController
@synthesize data = data_;
//@synthesize dataTmp = dataTmp_;

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
        //data_ = [[NSMutableArray alloc]init];
        
        //dataTmp_ = [[NSMutableArray alloc]init];
    }
    return self;
}

- (id)initWithStyle:(UITableViewStyle)style
{
    self = [super initWithStyle:style];
    if (self) {
        data_ = [[NSMutableArray alloc]init];
        // Custom initialization
        dataLoaded = NO;
    }
    return self;
}


- (void)loadView
{
    [super loadView];
    
    [dataSource loadData:NO];
    
    //Set the view up.
    /*UIView *theView = [[UIView alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
     self.view = theView;
     [theView release];*/
    
    
    //tableView_ = [[UITableView alloc] initWithFrame:[[UIScreen mainScreen] bounds] style:UITableViewStyleGrouped];
    
    
    //tableView_.delegate = self;
    //tableView_.dataSource = self;
    
    //[self.view addSubview:self.tableView];
    //    [theTableView release];
    
    
    //Background for a grouped tableview
    self.view.backgroundColor = [UIColor groupTableViewBackgroundColor];
}

- (void)viewDidLoad
{
    [super viewDidLoad];
    
    self.tableView.backgroundColor = [UIColor colorWithRed:238.0f/255.f
                                                     green:238.f/255.f
                                                      blue:238.f/255.f
                                                     alpha:1.0];
    [self done:self];
    
    dataSource = [[INQComputerDataSource alloc]init];
    //self.tableView.dataSource = dataSource;
    self.tableView.dataSource = self;
    
    [dataSource setDelegate:self];
    self.tableView.delegate = self;
    
    INQAppDelegate *app = (INQAppDelegate *)[[UIApplication sharedApplication] delegate];
    
    self.navigationController.navigationBar.tintColor = [app setBarColor];
    
    self.navigationController.toolbar.tintColor = [app setBarColor];
    
    self.tableView.separatorColor = [UIColor colorWithRed:153.0f/255.f
                                                    green:51.f/255.f
                                                     blue:0.f/255.f
                                                    alpha:0.5];
    
    self.tableView.separatorStyle = UITableViewCellSeparatorStyleSingleLine;
    
    CGRect screen = [[UIScreen mainScreen] bounds];
    
    self.tableView.frame = CGRectMake(0, 0, screen.size.width, screen.size.height - 100);
    
    // Image of bar button
    UIBarButtonItem *newFolderButton;
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
    
    UIBarButtonItem *spaceButton =
    [[UIBarButtonItem alloc]initWithBarButtonSystemItem:UIBarButtonSystemItemFlexibleSpace
                                                 target:nil
                                                 action:nil];
    
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
    
    
    homeButton.tag = 5;
    
    NSArray *items = [NSArray arrayWithObjects:newFolderButton,spaceButton, homeButton,nil];
    //  items = [NSArray arrayWithObjects:newFolderButton,spaceButton,homeButton, nil];
    self.toolbarItems = items;
    [self.tableView setEditing:NO animated:YES];
    [newFolderButton release];
    [spaceButton release];
    [homeButton release];
    
    // Uncomment the following line to display an Edit button in the navigation bar for this view controller.
    // self.navigationItem.rightBarButtonItem = self.editButtonItem;
    
    [self.tableView setEditing:NO animated:YES];
    
    if ([[[[UIDevice currentDevice] systemVersion] componentsSeparatedByString:@"."][0] intValue] >= 7)
    {
        self.edgesForExtendedLayout = UIRectEdgeNone;
    }
}

- (void)viewWillAppear:(BOOL)animated
{
    [super viewWillAppear:animated];
    
    
    self.navigationController.navigationBar.hidden = NO;
    self.navigationController.toolbarHidden = NO;
    
    [dataSource loadData:NO];
    dataLoaded = YES;
    //[self.tableView reloadData];
    
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
    DLog("number of sections in table %ld " , (long)[self.tableView numberOfSections]);
}

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView
{
    return 1;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    if ([self.data count] == 0 && dataLoaded)
    {
        return 1;
    }
    else
    {
        return [self.data count];
    }
}

- (void)dealloc
{
    
    [dataSource release];
    [data_ release];
    
    self.data = nil;
    dataSource = nil;
    [super dealloc];
}

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
    [controller removeSegmentedControlFromView];
    
    [self.navigationController pushViewController:controller animated:YES];
    
    if (self.data != nil)
    {
        controller.data = [self.data objectAtIndex:indexPath.row];
    }
    [controller release];
}

- (CGFloat)tableView:(UITableView *)tableView heightForHeaderInSection:(NSInteger)section
{
    return 60;
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
    
    if (section == 0)
    {
        textLabel.text = NSLocalizedString(@"SavedWorkGroup",@"SavedWorkGroup");
    }
    
    [sectionView addSubview:textLabel];
    
    return sectionView;
}

- (void)setEditing:(BOOL)editing animated:(BOOL)animated
{
    [super setEditing:editing animated:animated];
    [self.tableView setEditing:editing animated:YES];
    /*
     if (editing)
     {
     UIBarButtonItem *doneButton =
     [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemDone
     target:self
     action:@selector(done:)];
     
     //[self.navigationItem setRightBarButtonItem:doneButton animated:YES];
     [doneButton release];
     }
     else
     {
     UIBarButtonItem *editButtonItem =
     [[UIBarButtonItem alloc]initWithBarButtonSystemItem:UIBarButtonSystemItemEdit
     target:self
     action:@selector(editWorkgroup:)];
     
     //self.navigationItem.rightBarButtonItem = editButtonItem;
     [editButtonItem release];
     }*/
}

- (void)done:(id)sender
{
    UIBarButtonItem *doneButton =
    [[UIBarButtonItem alloc]initWithBarButtonSystemItem:UIBarButtonSystemItemEdit
                                                 target:self
                                                 action:@selector(editWorkgroup:)];
    
	//[self.navigationItem setRightBarButtonItem:doneButton animated:NO];
    
    [self.tableView setEditing:NO animated:YES];
    
    [self.tableView reloadData];
    [doneButton release];
}

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

- (void)editWorkgroup:(id)selector
{
    /*UIBarButtonItem *editButton =
     [[UIBarButtonItem alloc]initWithBarButtonSystemItem:UIBarButtonSystemItemDone
     target:self
     action:@selector(done:)];
     
     [self.navigationItem setRightBarButtonItem:editButton animated:NO];
     */
    [self.tableView setEditing:YES animated:YES];
    
    [self.tableView reloadData];
    //[editButton release];
}

#pragma mark - HOME Button.
- (void)backToHome {
    [self.navigationController popToViewController:[self.navigationController.viewControllers objectAtIndex:1] animated:YES];
    
}


- (void)tableView:(UITableView *)tableView commitEditingStyle:(UITableViewCellEditingStyle)editingStyle forRowAtIndexPath:(NSIndexPath *)indexPath
{
    if (editingStyle == UITableViewCellEditingStyleDelete)
    {
        // セルの編集開始
        [tableView beginUpdates];
        
        // 該当セルの削除
        [self.data removeObjectAtIndex:[indexPath row]];
        [dataSource.data removeObjectAtIndex:[indexPath row]];
        // セクション１側のデータが全て削除された場合はセクションの削除を実行
        [tableView deleteRowsAtIndexPaths:@[indexPath] withRowAnimation:UITableViewRowAnimationFade];
        
        if ([self.data count] == 0 && dataLoaded)
        {
            [tableView insertRowsAtIndexPaths:@[indexPath] withRowAnimation:UITableViewRowAnimationFade];
        }
        // セルの編集終了
        [tableView endUpdates];
        
        [dataSource performSelector:@selector(save)];
        
        // スワイプ操作による削除実行時に行数が複数あった場合に仕切り線が再描画されない症状への対応
        [tableView reloadData];
        
        // INQWorkgroupViewController側のデータを更新(保存データ)
        //[delegate loadedDataSourceCallBack:self.data info:nil option:0];
    }
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath
{
    
    if ([self.data count] > 0)
    {
        
        UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:@"MyCell"];
        
        if (!cell)
        {
            cell = [[[UITableViewCell alloc]initWithStyle:UITableViewCellStyleDefault reuseIdentifier:@"MyCell"]autorelease];
            cell.imageView.contentMode = UIViewContentModeScaleAspectFill;
            cell.textLabel.font = [UIFont systemFontOfSize:15.0];
        }
    
        if ([[[[UIDevice currentDevice] systemVersion] componentsSeparatedByString:@"."][0] intValue] >= 7)
        {
            [cell setAccessoryType:UITableViewCellAccessoryDetailButton];
        }
        else
        {
            [cell setAccessoryType:UITableViewCellAccessoryDetailDisclosureButton];
        }
        
        INQComputer *computer = [self.data objectAtIndex:indexPath.row];
        [[cell textLabel]setText:[NSString stringWithFormat:@"%@  / %@", computer.displayName,computer.computerNameIP]];
        INQAppDelegate *app = (INQAppDelegate *)[[UIApplication sharedApplication] delegate];
        UIImage *imgResize = [app resizeImage:@"icon_pc_save.png" image_size:36];
        [cell.imageView setImage:imgResize];
        return cell;
    }
    else if ([self.data count] == 0 && dataLoaded)
    {
        UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:@"AddComputerCell"];
        
        if (!cell)
        {
            cell = [[[UITableViewCell alloc]initWithStyle:UITableViewCellStyleDefault reuseIdentifier:@"AddComputerCell"]autorelease];
            cell.imageView.contentMode = UIViewContentModeScaleAspectFill;
            cell.textLabel.font = [UIFont systemFontOfSize:15.0];
        }
        
        [[cell textLabel]setText:[NSString stringWithString:NSLocalizedString(@"AddNewComputer", @"Add New Computer")]];
        return cell;
    }
    
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:@"MyCell"];
    
    if (!cell)
    {
        cell = [[[UITableViewCell alloc]initWithStyle:UITableViewCellStyleDefault reuseIdentifier:@"MyCell"]autorelease];
        cell.imageView.contentMode = UIViewContentModeScaleAspectFill;
        cell.textLabel.font = [UIFont systemFontOfSize:15.0];
    }
    return cell;
}


- (void)loadedDataSourceCallBack:(NSArray*)dt info:(NSString *)info option:(NSInteger)type {
    
    if (info != nil)
    {
        dispatch_async(dispatch_get_main_queue(), ^{
            
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
            
            //[self.tableView reloadData];
        });
    }
    else
    {
        dispatch_async(dispatch_get_main_queue(), ^{
            
            //[self stopLoadingView];
            
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
            [self.tableView reloadData];
        });
    }
    
}


// Override to support conditional editing of the table view.
- (BOOL)tableView:(UITableView *)tableView canEditRowAtIndexPath:(NSIndexPath *)indexPath
{
    // Return NO if you do not want the specified item to be editable.
    return YES;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath
{
    
    // 共有フォルダ用View初期化
    if ([self.data count] == 0)
    {
        [self addWorkgroup];
    }
    else
    {
        INQSharedFolderViewController *controller = [[INQSharedFolderViewController alloc]init];
        controller.computerInfo = [self.data objectAtIndex:indexPath.row];
        //controller.isBookMark = self.isBookMark;
        
        // コンピュータ情報の更新(無効)
        INQAppDelegate *app = (INQAppDelegate *)[[UIApplication sharedApplication] delegate];
        app.isUpdateComputerInfo = FALSE;
        
        // ナビゲーションバーのタイトルにコンピュータの表示名を設定
        controller.navigationItem.title = controller.computerInfo.displayName;
        
        [self.navigationController pushViewController:controller animated:NO];
        [controller release];
        return;
    }
}

/**
 * @brief Table View用 セル付属ボタン クリックイベントハンドラ
 * @param [in] tableView Table Viewオブジェクト
 * @param [in] indexPath セル用インデックスパス
 * @note  共有先情報の編集用
 */
/*
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
 */

/*
 // Override to support editing the table view.
 - (void)tableView:(UITableView *)tableView commitEditingStyle:(UITableViewCellEditingStyle)editingStyle forRowAtIndexPath:(NSIndexPath *)indexPath
 {
 if (editingStyle == UITableViewCellEditingStyleDelete) {
 // Delete the row from the data source
 [tableView deleteRowsAtIndexPaths:@[indexPath] withRowAnimation:UITableViewRowAnimationFade];
 }
 else if (editingStyle == UITableViewCellEditingStyleInsert) {
 // Create a new instance of the appropriate class, insert it into the array, and add a new row to the table view
 }
 }
 */

/*
 // Override to support rearranging the table view.
 - (void)tableView:(UITableView *)tableView moveRowAtIndexPath:(NSIndexPath *)fromIndexPath toIndexPath:(NSIndexPath *)toIndexPath
 {
 }
 */

/*
 // Override to support conditional rearranging of the table view.
 - (BOOL)tableView:(UITableView *)tableView canMoveRowAtIndexPath:(NSIndexPath *)indexPath
 {
 // Return NO if you do not want the item to be re-orderable.
 return YES;
 }
 */

/*
 #pragma mark - Navigation
 
 // In a story board-based application, you will often want to do a little preparation before navigation
 - (void)prepareForSegue:(UIStoryboardSegue *)segue sender:(id)sender
 {
 // Get the new view controller using [segue destinationViewController].
 // Pass the selected object to the new view controller.
 }
 
 */

@end
