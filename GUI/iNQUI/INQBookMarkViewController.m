

#import "INQBookMarkViewController.h"

@interface INQBookMarkViewController (){
    NSMutableArray *data_; 
    INQBookMarkDataSource *dataSource;

}

@end

@implementation INQBookMarkViewController
@synthesize data = data_;

- (id)initWithNibName:(NSString *)nibNameOrNil bundle:(NSBundle *)nibBundleOrNil
{
    self = [super initWithNibName:nibNameOrNil bundle:nibBundleOrNil];
    if (self) {
        // Custom initialization
    }
    return self;
}

- (void)viewDidLoad
{
    [super viewDidLoad];
    self.title = NSLocalizedString(@"BookMark",@"BookMark title");
    self.tableView.backgroundColor = [UIColor whiteColor];
    [self done:self];
    dataSource = [[INQBookMarkDataSource alloc]init];
    self.tableView.dataSource = dataSource;
    [dataSource setDelegate:self];
    self.tableView.delegate = self;
    
    self.navigationController.navigationBar.tintColor = [UIColor blackColor];    
    self.navigationController.toolbar.tintColor = [UIColor blackColor];
    self.tableView.separatorColor = [UIColor blackColor];
    self.tableView.separatorStyle = UITableViewCellSeparatorStyleSingleLine;
    CGRect screen = [[UIScreen mainScreen] bounds];
    self.tableView.frame = CGRectMake(0, 0, screen.size.width, screen.size.height - 100);

   
    // self.navigationItem.rightBarButtonItem = actionButton;
    
    UIBarButtonItem *spaceButton = [[UIBarButtonItem alloc]initWithBarButtonSystemItem:UIBarButtonSystemItemFlexibleSpace 
                                                                                target:nil 
                                                                                action:nil];
    
    
    UIBarButtonItem *homeButton = [[UIBarButtonItem alloc]initWithTitle:NSLocalizedString(@"Home",@"Home") style:UIBarButtonItemStylePlain target:self action:@selector(backToHome)];    
    homeButton.tag = 5;
    
    NSArray *items = [NSArray arrayWithObjects:spaceButton,homeButton,nil];
#if 0
    // Analyze対応 [Value stored to 'items' during its initialization is never read]
    items = [NSArray arrayWithObjects:spaceButton,homeButton, nil];
#endif
    self.toolbarItems = items;  
    [self.tableView setEditing:NO animated:YES];     

    [spaceButton release];
    [homeButton release];    
    [self startLoading];

}

- (void)viewWillAppear:(BOOL)animated {
    DLog(@"viewWillApper:LocalView");
    [super viewWillAppear:animated];
    [self.navigationController setToolbarHidden:NO]; 
    self.navigationController.navigationBar.hidden = NO;      
 
}
- (void)editBookMark:(id)selector {
    UIBarButtonItem *editButton =
    [[UIBarButtonItem alloc]
     initWithBarButtonSystemItem:UIBarButtonSystemItemDone target:self action:@selector(done:)];
	[self.navigationItem setRightBarButtonItem:editButton animated:NO];
    
    [self.tableView setEditing:YES animated:YES];
    
    [self.tableView reloadData];
    [editButton release];
    
}

- (void)done:(id)sender {
    UIBarButtonItem *doneButton =
    [[UIBarButtonItem alloc]initWithBarButtonSystemItem:UIBarButtonSystemItemEdit 
                                                 target:self 
                                                 action:@selector(editBookMark:)];
    
	[self.navigationItem setRightBarButtonItem:doneButton animated:NO];
    
    [self.tableView setEditing:NO animated:YES];
    
    [self.tableView reloadData];   
    [doneButton release];
}

- (void)viewDidUnload {
    [super viewDidUnload];
}

- (BOOL)shouldAutorotateToInterfaceOrientation:(UIInterfaceOrientation)interfaceOrientation {
    return (interfaceOrientation == UIInterfaceOrientationPortrait);
}

#if 1
- (void)loadedDataSourceCallBack:(NSArray*)dt info:(NSString *)info option:(NSInteger)type{
#else
- (void)loadedDataSourceCallBack:(NSArray*)dt info:(NSString *)info {
#endif
    [self stopLoading];
    if (self.data == nil) {
        data_ = [[NSMutableArray alloc]initWithArray:dt];
    } else {
        [self.data removeAllObjects];
        [self.data addObjectsFromArray:dt];        
    }
    
    [self.tableView reloadData];    
}

#pragma mark -
#pragma mark  UITableViewDelegate method

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    
    NQ_WCHAR uMountPoint[256];
    NQ_WCHAR uRemotePath[256];
    
    
    INQFileListViewController *controller = [[[INQFileListViewController alloc]init]autorelease];
    INQBookMark *bookmark = [self.data objectAtIndex:indexPath.row];
#if 1
    // Analyze対応 [Argument in message expression is an uninitialized value]
    NSString *fullPath = [NSString stringWithFormat:@"\\\\%@\\%@",bookmark.computer,bookmark];
#else
    NSString *fullPath = [NSString stringWithFormat:@"\\\\%@\\%@",bookmark.computer,bookmark,fullPath];
#endif
    
#if 1//def UD_CM_UNICODEAPPLICATION /* mizuguchi UTF-8 <-> UTF-16 */
    cmWStrcpy(uRemotePath, (NQ_WCHAR *)[fullPath
                                        cStringUsingEncoding:NSUTF16StringEncoding]);
    cmWStrcpy(uMountPoint, (NQ_WCHAR *)[[NSString stringWithFormat:@"\\mountPoint"]
                                        cStringUsingEncoding:NSUTF16StringEncoding]);
#else
    syAnsiToUnicode(uRemotePath,[fullPath cStringUsingEncoding:NSUTF8StringEncoding]);
    syAnsiToUnicode(uMountPoint,"mountPoint");
#endif
    
    int res = nqAddMount(uMountPoint,uRemotePath, TRUE);
    
    if (res == 0) {
        DLog(@"-----computer :%@",bookmark.computer);
        DLog(@"----full path : %@",bookmark.fullPath);
        [self.navigationController pushViewController:controller animated:NO];   
        [controller loadDataFromServer:bookmark.computer path:bookmark.fullPath];  
#if 0
        // Analyze対応 [Object autoreleased too many times]
      [controller release];
#endif
        return;        
    }
    
    nqRemoveMount(uMountPoint);    
    
}


- (void)setEditing:(BOOL)editing animated:(BOOL)animated {
    [super setEditing:editing animated:animated];
    
    if (editing) {
        UIBarButtonItem *doneButton = [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemDone
                                                                                    target:self action:@selector(done:)];
        [self.navigationItem setRightBarButtonItem:doneButton animated:YES];
        [doneButton release];
    } else { 
        UIBarButtonItem *editButtonItem = [[UIBarButtonItem alloc]initWithBarButtonSystemItem:UIBarButtonSystemItemEdit target:self action:@selector(editBookMark:)];
        self.navigationItem.rightBarButtonItem = editButtonItem;
        [editButtonItem release]; 
    }
}


- (void)alertMessage:(NSString*)msg {
    UIAlertView *alertView = [[UIAlertView alloc]initWithTitle:@"" message:msg delegate:nil cancelButtonTitle:@"OK" otherButtonTitles:nil, nil];
    [alertView show];
    [alertView release];
}

#pragma mark - HOME Button.
- (void)backToHome {
    [self.navigationController popToViewController:[self.navigationController.viewControllers objectAtIndex:1] animated:YES];
    
}

// Override 
- (void)refresh {
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{        
        [dataSource loadData];                  
    });      
}
@end
