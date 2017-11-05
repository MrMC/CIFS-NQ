
#import "INQAlbumPickerController.h"
#import "INQAppDelegate.h"

#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
@implementation INQAlbumPickerController

@synthesize parent, assetGroups;

#pragma mark -
#pragma mark View lifecycle

- (void)viewDidLoad {
    [super viewDidLoad];
	
	[self.navigationItem setTitle:NSLocalizedString(@"Loading...",@"Loading...")];
    self.navigationController.navigationBar.tintColor = [UIColor colorWithRed:14.0f/255.f green:133.f/255.f blue:175.f/255.f alpha:0.5];
    self.navigationController.toolbar.tintColor = [UIColor colorWithRed:14.0f/255.f green:133.f/255.f blue:175.f/255.f alpha:0.5];
    UIBarButtonItem *cancelButton = [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemCancel target:self.parent action:@selector(cancelImagePicker)];
	[self.navigationItem setRightBarButtonItem:cancelButton];
	[cancelButton release];

    NSMutableArray *tempArray = [[NSMutableArray alloc] init];
	self.assetGroups = tempArray;
    [tempArray release];
    
    library = [[ALAssetsLibrary alloc] init];      


    dispatch_async(dispatch_get_main_queue(), ^ {

        @autoreleasepool {
            // Group enumerator Block
            void (^assetGroupEnumerator)(ALAssetsGroup *, BOOL *) = ^(ALAssetsGroup *group, BOOL *stop) {
                if (group == nil) {
                    return;
                }
                
                [self.assetGroups addObject:group];

                // Reload albums
                [self performSelectorOnMainThread:@selector(reloadTableView) withObject:nil waitUntilDone:YES];
            };
            
            // Group Enumerator Failure Block
            void (^assetGroupEnumberatorFailure)(NSError *) = ^(NSError *error) {
                
                UIAlertView * alert = [[UIAlertView alloc] initWithTitle:@"Error" message:[NSString stringWithFormat:@"Album Error: %@ - %@", [error localizedDescription], [error localizedRecoverySuggestion]] delegate:nil cancelButtonTitle:@"OK" otherButtonTitles:nil];
                [alert show];
                [alert release];
                
                DLog(@"A problem occured %@", [error description]);	                                 
            };	
                    
            // Enumerate Albums
            [library enumerateGroupsWithTypes:ALAssetsGroupAll
                                   usingBlock:assetGroupEnumerator 
                                 failureBlock:assetGroupEnumberatorFailure];
        
        }
    });    
}

-(void)reloadTableView {
	
	[self.tableView reloadData];
	[self.navigationItem setTitle:NSLocalizedString(@"SelectAlbum",@"Select an Album")];
}

-(void)selectedAssets:(NSArray*)_assets {
	[(INQImagePickerController*)parent selectedAssets:_assets];
}

/**
 * @brief Viewが表示される直前に呼び出される処理
 */
-(void)viewWillAppear:(BOOL)animated
{
    [super viewWillAppear:animated];
    INQAppDelegate *app = (INQAppDelegate *)[[UIApplication sharedApplication] delegate];
    
    // ツールバー 表示設定(無効)
    [self.navigationController setToolbarHidden:YES];
    
    // current iOS version is after 7
    if ([[[[UIDevice currentDevice] systemVersion] componentsSeparatedByString:@"."][0] intValue] >= 7)
    {
        // set navigation bar color
        [self.navigationController.navigationBar setBarTintColor:[app setBarColor]];
        
        // set navigation title color
        [self.navigationController.navigationBar setTitleTextAttributes:[NSDictionary dictionaryWithObject:[UIColor whiteColor] forKey:NSForegroundColorAttributeName]];
        
        // set navigation bar button arrow color
        self.navigationController.navigationBar.tintColor = [UIColor whiteColor];
        
        // set navigation bar button color
        [[UIBarButtonItem appearanceWhenContainedIn:[UINavigationBar class], nil]
         setTitleTextAttributes:[NSDictionary dictionaryWithObjectsAndKeys:[UIColor whiteColor],
                                 NSForegroundColorAttributeName, nil] forState:UIControlStateNormal];
        
        // set navigation toolbar color
        [self.navigationController.toolbar setBarTintColor:[app setBarColor]];
    }
    else
    {
        self.navigationController.navigationBar.tintColor = [app setBarColor];
        self.navigationController.toolbar.tintColor = [app setBarColor];
    }
}

/**
 * @brief 色定義関数(ナビゲーションバー、ツールバー用) 画面個別設定用
 */
-(UIColor *)COLOR_BAR_WITH_TYPE:(NSInteger)color_type
{
    UIColor *barColor;
    if(color_type == DEF_VIEW_LOCAL)
    {
        barColor = [UIColor colorWithRed:245.0f/255.f green:184.f/255.f blue:20.f/255.f alpha:0.8];
    }
    else
    {
        barColor = [UIColor colorWithRed:82.0f/255.f green:158.f/255.f blue:255.f/255.f alpha:0.8];
    }
    
    return barColor;
}

#pragma mark -
#pragma mark Table view data source

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    return 1;
}


- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    return [assetGroups count];
}


// Customize the appearance of table view cells.
- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    
    static NSString *CellIdentifier = @"Cell";
    
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:CellIdentifier];
    if (cell == nil) {
        cell = [[[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:CellIdentifier] autorelease];
    }
    
    // Get count
    ALAssetsGroup *g = (ALAssetsGroup*)[assetGroups objectAtIndex:indexPath.row];
    [g setAssetsFilter:[ALAssetsFilter allPhotos]];
    NSInteger gCount = [g numberOfAssets];
    
    cell.textLabel.text = [NSString stringWithFormat:@"%@ (%d)",[g valueForProperty:ALAssetsGroupPropertyName], (int)gCount];
    [cell.imageView setImage:[UIImage imageWithCGImage:[(ALAssetsGroup*)[assetGroups objectAtIndex:indexPath.row] posterImage]]];
	[cell setAccessoryType:UITableViewCellAccessoryDisclosureIndicator];
	
    return cell;
}

#pragma mark -
#pragma mark Table view delegate

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
	
	INQAssetTablePicker *picker = [[INQAssetTablePicker alloc] initWithNibName:@"INQAssetTablePicker" bundle:[NSBundle mainBundle]];
	picker.parent = self;

    // Move me    
    picker.assetGroup = [assetGroups objectAtIndex:indexPath.row];
    [picker.assetGroup setAssetsFilter:[ALAssetsFilter allPhotos]];
    
	[self.navigationController pushViewController:picker animated:YES];
	[picker release];
}

- (CGFloat)tableView:(UITableView *)tableView heightForRowAtIndexPath:(NSIndexPath *)indexPath {
	
	return 57;
}

#pragma mark -
#pragma mark Memory management

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
}


- (void)viewDidUnload {
    [assetGroups release];
    assetGroups = nil;
    [library release];
    library = nil;
    [super viewDidUnload];
}


- (void)dealloc {	
#if 1
    // 'viewDidUnload' is deprecated: first deprecated in iOS6.0対応
    [assetGroups release];
    assetGroups = nil;
    [library release];
    library = nil;
#else
    [self viewDidUnload];
#endif
    [super dealloc];
}

@end

