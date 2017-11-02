
#import "INQFolderSettingViewController.h"
#import "INQSharedFolderDataSource.h"
#import "INQShareFolder.h"

@interface INQFolderSettingViewController ()

@end

@implementation INQFolderSettingViewController

@synthesize folderObj;

- (id)initWithStyle:(UITableViewStyle)style {
    self = [super initWithStyle:style];
    if (self) {
        // Custom initialization
    }
    return self;
}

- (void)viewDidLoad {
    [super viewDidLoad];
#if 0
    // ナビゲーションバータイトルをローカルフォルダー名を適応する為、コメントアウト
    self.title = NSLocalizedString(@"FolderShare", @"FolderSahre");
#endif
    // ツールバー 表示設定(無効)
    [self.navigationController setToolbarHidden:YES];
    
    // Uncomment the following line to preserve selection between presentations.
    self.clearsSelectionOnViewWillAppear = NO;
    UIBarButtonItem *saveButtonItem = [[UIBarButtonItem alloc]
                                       initWithBarButtonSystemItem:UIBarButtonSystemItemDone 
                                       target:self 
                                       action:@selector(save)];
   // self.navigationItem.leftBarButtonItem = saveButtonItem;
    [saveButtonItem release];
    DLog(@"FolderID:%@ : %d : %@/%@" ,self.folderObj.folderId,folderObj.isShare,folderObj.userName,folderObj.password);
}


- (void)save {

    if (folderObj.userName == nil) {
        folderObj.userName = @"guest";
    }
    
    if (folderObj.password == nil) {
        folderObj.password = @"guest";
    }            

    [INQSharedFolderDataSource saveData:self.folderObj];
   // [self.navigationController popViewControllerAnimated:YES];
        
}


- (void)alertMessage:(NSString*)msg {
    UIAlertView *alertView = [[UIAlertView alloc]initWithTitle:@"" message:msg delegate:nil cancelButtonTitle:@"OK" otherButtonTitles:nil, nil];
    [alertView show];
    [alertView release];
}

- (void)viewDidUnload {
    [folderObj release];
    folderObj = nil;
    [super viewDidUnload];
}

- (void)dealloc {
#if 1
    // 'viewDidUnload' is deprecated: first deprecated in iOS6.0対応
    [folderObj release];
    folderObj = nil;
#else
    [self viewDidUnload];
#endif
    [super dealloc];
}

- (BOOL)shouldAutorotateToInterfaceOrientation:(UIInterfaceOrientation)interfaceOrientation
{
    return (interfaceOrientation == UIInterfaceOrientationPortrait);
}


#pragma mark - Table view data source
- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    return 1;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {

    return 1;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath
{
    static NSString *CellIdentifier = @"Cell";
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:CellIdentifier];
    if (!cell) {
        cell = [[[UITableViewCell alloc]initWithStyle:UITableViewCellStyleDefault reuseIdentifier:CellIdentifier]autorelease];        
        
        if (indexPath.row == 0) {
            [cell setSelectionStyle:UITableViewCellSelectionStyleNone];
            
#if 1
            [cell.textLabel setText:NSLocalizedString(@"PublicSetting", @"public setting")];
#else
            [cell.textLabel setText:NSLocalizedString(@"Share", @"Share")];
#endif
            UISwitch *sw = [[UISwitch alloc]initWithFrame:CGRectZero];
            sw.tag = 100;
            cell.accessoryView = sw;
            
            [sw addTarget:self action:@selector(onShare:) forControlEvents:UIControlEventValueChanged];
            [sw release];
        }

        if (indexPath.row == 1) {
            [cell setSelectionStyle:UITableViewCellSelectionStyleNone];
            [cell.textLabel setText:NSLocalizedString(@"DefaultGuest", @"Guest")];
            UISwitch *sw = [[UISwitch alloc]initWithFrame:CGRectZero];
            sw.tag = 200;
            [sw setOn:YES];
            cell.accessoryView = sw;
            [sw addTarget:self action:@selector(onSecurity:) forControlEvents:UIControlEventValueChanged];
            [sw release];
        }
            
        if (indexPath.row == 2) {
            [cell setSelectionStyle:UITableViewCellSelectionStyleNone];
            [cell.textLabel setText:NSLocalizedString(@"UserID", @"UserID")];
            UITextField *userNameTextField = [[UITextField alloc]initWithFrame:CGRectMake(0, 0, 180, 30)];
            userNameTextField.textAlignment = NSTextAlignmentLeft;
            userNameTextField.backgroundColor = [UIColor clearColor];
            userNameTextField.tag = 300;
            userNameTextField.delegate = self;
            userNameTextField.clearButtonMode = UITextFieldViewModeAlways;
            cell.accessoryView = userNameTextField;
            [userNameTextField release];

        }
        
        if (indexPath.row == 3) {
            [cell setSelectionStyle:UITableViewCellSelectionStyleNone];
            [cell.textLabel setText:NSLocalizedString(@"Password", @"Password")];
            UITextField *passwordTextField = [[UITextField alloc]initWithFrame:CGRectMake(0, 0, 180, 30)];
            passwordTextField.textAlignment = NSTextAlignmentLeft;
            passwordTextField.backgroundColor = [UIColor clearColor];
            passwordTextField.tag = 400;
            passwordTextField.delegate = self;
            passwordTextField.secureTextEntry = YES;
            passwordTextField.clearButtonMode = UITextFieldViewModeAlways;
            cell.accessoryView = passwordTextField;
            [passwordTextField release];
            
        }
    }
    
    UIView *view = cell.accessoryView;
    DLog(@"switch %@",view);
    if (view.tag == 100) {
        [(UISwitch*)view setOn:folderObj.isShare];        
    }
    
    if (view.tag == 200) {
        [(UISwitch*)view setOn:folderObj.isGuest];        
    }

    if (view.tag == 300) {
        ((UITextField*)view).text = folderObj.userName;        
    }
            
    if (view.tag == 400) {
        ((UITextField*)view).text = folderObj.password;        
    }
        
    return cell;
}

- (void)onShare:(id)sender {
    BOOL changed = [(UISwitch*)sender isOn];
    folderObj.share = changed;
    [self save];    
}

- (void)onSecurity:(id)sender {
    BOOL changed = [(UISwitch*)sender isOn];
    folderObj.guest = changed;
    [self save];    
}


#pragma mark - Table view delegate

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {

}

/**
 * @brief テーブルビューのセクションヘッダーの設定
 */
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
    
    textLabel.text = NSLocalizedString(@"SharedFolder",@"SharedFolder");
    
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

#pragma mark -
#pragma mark - UITextFieldDelegate Method.
- (void)textFieldDidEndEditing:(UITextField *)textField{
    int tag = textField.tag;
    if (tag == 100) {
        folderObj.userName = textField.text;
    }
    
    if (tag == 200) {
        folderObj.password = textField.text;
    }
    
}
@end
