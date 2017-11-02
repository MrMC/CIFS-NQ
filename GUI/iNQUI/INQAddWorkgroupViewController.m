
#import "INQAddWorkgroupViewController.h"
#import "INQComputerDataSource.h"
#import "INQAppDelegate.h"

@interface INQAddWorkgroupViewController (){
    NSString *computerId;
    UITextField *displayField;
    UITextField *computerField;
    UITextField *userField;  
    UITextField *passwordField;
    UITextField *workgroupField;
    INQComputer *data_;
    UITextField *hiddenTextField;
    UISegmentedControl  *segmentControl;
    //UITableView *browseTableView_;
    UITableView *tableView_;
    INQWorkgroupViewController  *wgController;
    BOOL        removeSegmentedControl;
    UITextField *activeText;
}
@property (nonatomic,retain) UITableView *tableView;
@end

@implementation INQAddWorkgroupViewController
@synthesize data = data_,tableView = tableView_;
@synthesize loadingView;
@synthesize indicator;
@synthesize loadingMessageLabel;

- (id)initWithNibName:(NSString *)nibNameOrNil bundle:(NSBundle *)nibBundleOrNil {
    self = [super initWithNibName:nibNameOrNil bundle:nibBundleOrNil];
    if (self) {
        // Custom initialization
    }
    return self;
}

- (void)loadView
{
    [super loadView];

    //Set the view up.
    UIView *theView = [[UIView alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    self.view = theView;
    [theView release];
    
    //Create an negatively sized or offscreen textfield
    /*UITextField *hiddenField = [[UITextField alloc] initWithFrame:CGRectMake(0, 0, -10, -10)];
    hiddenTextField = hiddenField;
    [self.view addSubview:hiddenTextField];
    [hiddenField release];*/

    //Create the tableview
    
    tableView_ = [[UITableView alloc] initWithFrame:[[UIScreen mainScreen] bounds] style:UITableViewStyleGrouped];
    tableView_.delegate = self;
    tableView_.dataSource = self;
    
    if (!removeSegmentedControl)
    {
        [self addSergmentedControl];
        [self.view addSubview:segmentControl];
    }
    // show "manual" form
    [self.view addSubview:tableView_];
    
    wgController = [[INQWorkgroupViewController alloc] init];

    wgController.addWorkgroupController = self;
    
    //Set the hiddenTextField to become first responder
    //[hiddenTextField becomeFirstResponder];
    
    //Background for a grouped tableview
    self.view.backgroundColor = [UIColor groupTableViewBackgroundColor];
}

-(void)removeSegmentedControlFromView{
    //[segmentControl removeFromSuperview];
    removeSegmentedControl = YES;
}


- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = NSLocalizedString(@"NewComputer",@"add workgroup title");
    
    UIBarButtonItem *saveButtonItem = [[UIBarButtonItem alloc]
                                          initWithBarButtonSystemItem:UIBarButtonSystemItemSave 
                                                                target:self 
                                                                action:@selector(save)];
    self.navigationItem.rightBarButtonItem = saveButtonItem;
    [saveButtonItem release];

    // ---------------------------------------------------------------------
    // iOS7以降対応 : UINavigationBarとStatusBarをUIViewに上被せで表示させない処理
    if ([[[[UIDevice currentDevice] systemVersion] componentsSeparatedByString:@"."][0] intValue] >= 7)
    {
        self.edgesForExtendedLayout = UIRectEdgeNone;
    }
    
    
}

- (void)viewDidUnload {
    [super viewDidUnload];   
    self.data = nil;
    self.tableView = nil;
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    //INQAppDelegate *app = (INQAppDelegate *)[[UIApplication sharedApplication] delegate];
    [self.navigationItem setTitle:NSLocalizedString(@"Edit", @"Edit")];
    /*if(app.typeAddWorkGroupView == TRUE)
    {
        [self.navigationItem setTitle:NSLocalizedString(@"NewAddition", @"new addition")];
    }
    else
    {
        [self.navigationItem setTitle:NSLocalizedString(@"Edit", @"Edit")];
    }*/
    
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(keyboardWillShow:)
                                                 name:UIKeyboardWillShowNotification object:nil];
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(keyboardWillHide:)
                                                 name:UIKeyboardWillHideNotification object:nil];
}

- (void) addSergmentedControl{
    NSArray * segmentedItems = [NSArray arrayWithObjects: @"Manual" , @"Find in network" , nil];
    segmentControl = [[[UISegmentedControl alloc] initWithItems:segmentedItems]retain];
    segmentControl.selectedSegmentIndex = 0;
    [segmentControl addTarget: self
                    action:@selector(segmentControlChange:)
                    forControlEvents: UIControlEventValueChanged];
    self.navigationItem.titleView = segmentControl;
}

- (void) segmentControlChange: (UISegmentedControl *) sender{

    //[self.subview add ];
    
    if (sender.selectedSegmentIndex == 0)
    {
        //[self.view addSubview:hiddenTextField];
        [wgController willMoveToParentViewController:nil];
        [wgController.view removeFromSuperview];
        [wgController removeFromParentViewController];
        
        self.navigationItem.rightBarButtonItem = nil;
        UIBarButtonItem *saveButtonItem = [[UIBarButtonItem alloc]
                                           initWithBarButtonSystemItem:UIBarButtonSystemItemSave
                                           target:self
                                           action:@selector(save)];
        self.navigationItem.rightBarButtonItem = saveButtonItem;
        [saveButtonItem release];
        [self.view addSubview:tableView_];
    }
    else if (sender.selectedSegmentIndex == 1)
    {
        [tableView_ removeFromSuperview];
        //[hiddenTextField removeFromSuperview];
        self.navigationItem.rightBarButtonItem = nil;
        
        //[self.navigationController pushViewController:wgController animated:NO];
        [self addChildViewController:wgController];

        [self.view addSubview:wgController.view];
        [wgController didMoveToParentViewController:self];
        [self startLoadingView:@"Network For Domains"];
        //dispatch_async(dispatch_get_main_queue(), ^{
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            [wgController loadWorkgroups];
            [self stopLoadingView];
         });

        
    }
}

- (void)startLoadingView:(NSString *)workgroup
{
    //DLog("starting loading view from add workgroup controller self.view = %p" , self.view);
    loadingView = [[UIView alloc] initWithFrame:self.navigationController.view.bounds];
    //loadingView = [[UIView alloc] initWithFrame:self.view.bounds];
    //DLog(" self view H %f W %f\n" , self.view.bounds.size.height, self.view.bounds.size.width);
    //DLog(" navigation controller H %f W %f\n" , self.navigationController.view.bounds.size.height , self.navigationController.view.bounds.size.width);
    [loadingView setBackgroundColor:[UIColor blackColor]];
    [loadingView setAlpha:0.5];
    
    indicator = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleWhiteLarge];
    //DLog(" self is %p view %p\n" , self , self.view);
    //DLog(" navigation controller is %p view %p\n" , self.navigationController , self.navigationController.view);
    //DLog(" loading view = %p" , loadingView);
    [self.view addSubview:loadingView];
    [self.navigationController.view addSubview:loadingView];
    [loadingView addSubview:indicator];
    
    //[self.view bringSubviewToFront:loadingView];
    //[self.navigationController.view bringSubviewToFront:loadingView];
    
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
    dispatch_sync(dispatch_get_main_queue(),^{
      [indicator stopAnimating];
      [loadingView removeFromSuperview];
      [loadingMessageLabel removeFromSuperview];
      [indicator release];
      [loadingView release];
      [loadingMessageLabel release];
    });
    ////[loadingView removeFromSuperview];
    //[loadingView performSelectorOnMainThread:@selector(removeFromSuperview) withObject:nil waitUntilDone:NO];
    ////[loadingMessageLabel removeFromSuperview];
    //[loadingMessageLabel performSelectorOnMainThread:@selector(removeFromSuperview) withObject:nil waitUntilDone:NO];
    ////[indicator release];
    ////[loadingView release];
    ////[loadingMessageLabel release];
}


-(void) keyboardWillShow:(NSNotification *)note
{
    // Get the keyboard size
    CGRect keyboardBounds;
    [[note.userInfo valueForKey:UIKeyboardFrameBeginUserInfoKey] getValue: &keyboardBounds];
    
    // Detect orientation
    UIInterfaceOrientation orientation = [[UIApplication sharedApplication] statusBarOrientation];
    CGRect frame = self.tableView.frame;
    
    // Start animation
    [UIView beginAnimations:nil context:NULL];
    [UIView setAnimationBeginsFromCurrentState:YES];
    [UIView setAnimationDuration:0.3f];
    
    // Reduce size of the Table view
    if (orientation == UIInterfaceOrientationPortrait || orientation == UIInterfaceOrientationPortraitUpsideDown)
        frame.size.height -= keyboardBounds.size.height + (self->passwordField.frame.size.height * 2);
    
    // Apply new size of table view
    self.tableView.frame = frame;
    
    [UIView commitAnimations];
}

- (void)textFieldDidBeginEditing:(UITextField *)textField
{
    self->activeText = textField;
}

-(void) keyboardWillHide:(NSNotification *)note
{
    // Get the keyboard size
    CGRect keyboardBounds;
    [[note.userInfo valueForKey:UIKeyboardFrameBeginUserInfoKey] getValue: &keyboardBounds];
    
    // Detect orientation
    UIInterfaceOrientation orientation = [[UIApplication sharedApplication] statusBarOrientation];
    CGRect frame = self.tableView.frame;
    
    [UIView beginAnimations:nil context:NULL];
    [UIView setAnimationBeginsFromCurrentState:YES];
    [UIView setAnimationDuration:0.3f];
    
    // Reduce size of the Table view
    if (orientation == UIInterfaceOrientationPortrait || orientation == UIInterfaceOrientationPortraitUpsideDown)
        frame.size.height += keyboardBounds.size.height;
    else 
        frame.size.height += keyboardBounds.size.width;
    
    // Apply new size of table view
    self.tableView.frame = frame;
    
    [UIView commitAnimations];
}

- (void)save {


    // 入力文字列の空白文字除去を追加
    NSString *displayName = [[displayField text] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
    NSString *computer = [[computerField text] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
    NSString *workGroup = [[workgroupField text] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
    NSString *userName = [[[userField text] uppercaseString] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
    NSString *password = [[passwordField text] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];

    
    DLog(@" display name:%@",displayName);
    // 条件に文字列長を追加
    if((displayName.length == 0) || (displayName == nil))
    {
        [self alertMessage:NSLocalizedString(@"InputDisplayName",@"input display name")];
        return;
    }
    
    if((computer.length == 0) || (computer == nil))
    {
        [self alertMessage:NSLocalizedString(@"InputComputerName",@"input computer name")];
        return;
    }
    
    if (computerId == nil) {
        int key = [[NSUserDefaults standardUserDefaults] integerForKey:@"KEY"];
        key++;

        computerId = [NSString stringWithFormat:@"%d",key];
        [[NSUserDefaults standardUserDefaults] setInteger:key forKey:@"KEY"];
    }
    
    if (workGroup == nil) {
        workGroup = @"WORKGROUP";
    }

    // Analyze [Potential leak of an object stored into 'dic']
    NSMutableDictionary *dic = [[[NSMutableDictionary alloc]init]autorelease];
    [dic setValue:computerId forKey:COMPUTER_ID];
    [dic setValue:displayName forKey:DISPLAY_NAME];
    [dic setValue:userName == nil?@"guest":userName forKey:USER_NAME];
    [dic setValue:password == nil?@"":password forKey:PASSWORD];
    [dic setValue:computer forKey:COMPUTER];
    [dic setValue:workGroup forKey:WORKGROUP];
    
    INQComputerDataSource *dataSource = [[INQComputerDataSource alloc]init];
    [dataSource saveData:dic forKey:computerId];
    [self.navigationController popViewControllerAnimated:YES];
    [dataSource release];
     
}

- (void)alertMessage:(NSString*)msg
{
    // Alertの表示書式を変更
    UIAlertView *alertView = [[UIAlertView alloc]initWithTitle:msg
                                                       message:nil
                                                      delegate:nil
                                             cancelButtonTitle:NSLocalizedString(@"AlertClose", @"alert close")
                                             otherButtonTitles:nil, nil];
    [alertView show];
    [alertView release];
}

#pragma mark - Table view data source
- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    return 1;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    if (section == 0) {
        return 5;
    }
    return 2;
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
        case 1:
            textLabel.text = NSLocalizedString(@"UserInfo", @"User Info");
            break;
    }
    
    [sectionView addSubview:textLabel];
    
    return sectionView;
}

- (CGFloat)tableView:(UITableView *)tableView heightForHeaderInSection:(NSInteger)section
{
    CGFloat heightSection = 0.0f;
    
    return heightSection;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    static NSString *CellIdentifier = @"Cell";
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:CellIdentifier];
    if (cell == nil) {
        // セルの文字列を２行表示を可能にする設定
        cell = [[[UITableViewCell alloc]initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:CellIdentifier]autorelease];
        [cell setSelectionStyle:UITableViewCellEditingStyleNone];
        [cell.textLabel setFont:[UIFont boldSystemFontOfSize:14.0f]];

        if (indexPath.section == 0) {
            if (indexPath.row == 0) {
                [cell.textLabel setText:NSLocalizedString(@"DisplayName", @"DisplayName")];
                
                displayField = [[UITextField alloc]initWithFrame:CGRectMake(0, 0,  130, 20)];
                [displayField setFont:[UIFont systemFontOfSize:14.0f]];

                displayField.placeholder = NSLocalizedString(@"DisplayName", @"please input computer name or ip");
                displayField.tag = 1;
                displayField.clearButtonMode = UITextFieldViewModeAlways;
                displayField.delegate = self;
                [displayField setTextAlignment:NSTextAlignmentLeft];
                
                // 自動校正動作を無効化
                displayField.autocorrectionType = UITextAutocorrectionTypeNo;

                cell.accessoryView = displayField;
                
            }
            if (indexPath.row == 1) {
                [cell.textLabel setText:NSLocalizedString(@"ComputerNameOrIP", @"ComputerName/IP")];

                // 2行表示対応
                cell.detailTextLabel.text = NSLocalizedString(@"ComputerNameOrIPSub", @"ComputerNameOrIPSub");

                computerField = [[UITextField alloc]initWithFrame:CGRectMake(0, 0, 130, 20)];
                [computerField setFont:[UIFont systemFontOfSize:14.0f]];
                computerField.clearButtonMode = UITextFieldViewModeAlways;
                computerField.placeholder = @"0.0.0.0";
                computerField.tag = 2;
                computerField.delegate = self;
                [computerField setTextAlignment:NSTextAlignmentLeft];

                // 自動校正動作を無効化
                computerField.autocorrectionType = UITextAutocorrectionTypeNo;

                cell.accessoryView = computerField;
            }
            
            if (indexPath.row == 2) {
                [cell.textLabel setText:NSLocalizedString(@"WorkGroup", @"WorkGroupName")];            
                workgroupField = [[UITextField alloc]initWithFrame:CGRectMake(0, 0,  130, 20)];
                [workgroupField setFont:[UIFont systemFontOfSize:14.0f]];
                workgroupField.clearButtonMode = UITextFieldViewModeAlways;
                //[cell addSubview:computerField];
                workgroupField.placeholder = @"WORKGROUP";
                workgroupField.tag = 3;
                workgroupField.delegate = self;
                [workgroupField setTextAlignment:NSTextAlignmentLeft];
                workgroupField.text = @"WORKGROUP";
                cell.accessoryView = workgroupField;
            }            
       // } else if (indexPath.section == 1) {
                    
            if (indexPath.row == 3) {
                [cell.textLabel setText:NSLocalizedString(@"UserID", @"UserID")];              
                userField = [[UITextField alloc]initWithFrame:CGRectMake(0, 0, 130, 20)];
                [userField setFont:[UIFont systemFontOfSize:14.0f]];
                //[cell addSubview:userField];
                userField.tag = 4;
                userField.placeholder = NSLocalizedString(@"UserID", @"please input user ID");
                userField.delegate = self;
                [userField setTextAlignment:NSTextAlignmentLeft];
                userField.clearButtonMode = UITextFieldViewModeAlways;
                
                // 自動校正動作を無効化
                userField.autocorrectionType = UITextAutocorrectionTypeNo;
                
                // 自動大文字入力を無効化
                userField.autocapitalizationType = UITextAutocapitalizationTypeNone;
                
                cell.accessoryView = userField;
                
            }
            
            if (indexPath.row == 4) {
                [cell.textLabel setText:NSLocalizedString(@"Password", @"Password")];              
                passwordField = [[UITextField alloc]initWithFrame:CGRectMake(0, 0, 130, 20)];
                [passwordField setFont:[UIFont systemFontOfSize:14.0f]];
                [passwordField setSecureTextEntry:YES];
                passwordField.clearButtonMode = UITextFieldViewModeAlways;
                passwordField.tag = 5;
                passwordField.delegate = self;
                passwordField.placeholder = NSLocalizedString(@"Password", @"please input password");

                [passwordField setTextAlignment:NSTextAlignmentLeft];
                cell.accessoryView = passwordField;
            }   
        }
    } 
    
    if (self.data != nil) {
        computerId = self.data.computerId;
        [displayField setText:self.data.displayName];
        [computerField setText:self.data.computerNameIP];
        [userField setText:self.data.userName];
        [passwordField setText:self.data.password];
        [workgroupField setText:self.data.workGroup];
    }
    
    return cell;
}

- (BOOL)shouldAutorotateToInterfaceOrientation:(UIInterfaceOrientation)interfaceOrientation {
    return (interfaceOrientation == UIInterfaceOrientationPortrait);
}

/**
 * @brief テキストフィールドへの入力終了時にコールされる処理
 */
- (void)textFieldDidEndEditing:(UITextField *)textField
{
    // 現在、入力が完了したフィールドが"パスワード"ならreturn
    if(textField.tag == 5)
    {
        return;
    }
    // 入力内容を大文字に変換
    [textField setText:[textField.text uppercaseString]];
    self->activeText = nil;
}

#pragma mark - HOME Button.
- (void)backToHome {
    [self.navigationController popToViewController:[self.navigationController.viewControllers objectAtIndex:1] animated:YES];
    
}

- (void)dealloc {
    
    [displayField release];
    [computerField release];
    [userField release];
    [passwordField release];
    [workgroupField release];
    [data_ release]; 
    [tableView_ release];

    //[wgController release];
    [super dealloc];
    
}

@end
