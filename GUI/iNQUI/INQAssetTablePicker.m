
#import "INQAssetTablePicker.h"
#import "INQAppDelegate.h"

@implementation INQAssetTablePicker

@synthesize parent;
@synthesize selectedAssetsLabel;
@synthesize assetGroup, elcAssets;

- (void)viewDidLoad {
        
	[self.tableView setSeparatorColor:[UIColor clearColor]];
	[self.tableView setAllowsSelection:NO];

    NSMutableArray *tempArray = [[NSMutableArray alloc] init];
    self.elcAssets = tempArray;
    [tempArray release];
	
    self.navigationController.toolbarHidden = NO;
    UIBarButtonItem *spaceButton = [[[UIBarButtonItem alloc]initWithBarButtonSystemItem:UIBarButtonSystemItemFlexibleSpace target:nil action:nil]autorelease];

#if 1
    INQAppDelegate *app = (INQAppDelegate *)[[UIApplication sharedApplication] delegate];
    UIBarButtonItem *uploadButton;
    if (app.typeSelectedView == DEF_VIEW_WORKGROUP)
    {
        uploadButton = [[[UIBarButtonItem alloc]initWithTitle:NSLocalizedString(@"UploadSelectFiles",@"Upload Select Files") style:UIBarButtonItemStylePlain target:self action:@selector(doneAction:)]autorelease];
    }
    else
    {
        uploadButton = [[[UIBarButtonItem alloc]initWithTitle:NSLocalizedString(@"CopySelectFiles",@"Copy Select Files") style:UIBarButtonItemStylePlain target:self action:@selector(doneAction:)]autorelease];
    }
#else
    UIBarButtonItem *uploadButton = [[[UIBarButtonItem alloc]initWithTitle:NSLocalizedString(@"UploadSelectFiles",@"Upload Selecte Files") style:UIBarButtonItemStylePlain target:self action:@selector(doneAction:)]autorelease];
#endif
    
    self.toolbarItems = [NSArray arrayWithObjects:spaceButton,uploadButton,spaceButton,nil];

	[self.navigationItem setTitle:NSLocalizedString(@"Loading...",@"Loading...")];

#if 1
    // iOS7の場合に元の記述だと本画面に一度遷移後は画面遷移時のアニメーションが効かなくなるので変更
    [self preparePhotos];
#else
	[self performSelectorInBackground:@selector(preparePhotos) withObject:nil];
    
	[self.tableView performSelector:@selector(reloadData) withObject:nil afterDelay:.5];
#endif
}

- (void)preparePhotos {
    
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];

	
    DLog(@"Enumerating photos");
    [self.assetGroup enumerateAssetsUsingBlock:^(ALAsset *result, NSUInteger index, BOOL *stop) {         
         if(result == nil) {
             return;
         }
         
         INQAsset *inqAsset = [[[INQAsset alloc] initWithAsset:result] autorelease];
         [inqAsset setParent:self];
         [self.elcAssets addObject:inqAsset];
     }];    
    DLog(@"Done enumerating photos");
	
	[self.tableView reloadData];
	[self.navigationItem setTitle:NSLocalizedString(@"PickPhotos",@"Pick Photos")];
    
    [pool release];

}

- (void) doneAction:(id)sender {
	
	NSMutableArray *selectedAssetsImages = [[[NSMutableArray alloc] init] autorelease];
	    
	for(INQAsset *elcAsset in self.elcAssets) {		
		if([elcAsset selected]) {
			[selectedAssetsImages addObject:[elcAsset asset]];
		}
	}
        
    [(INQAlbumPickerController*)self.parent selectedAssets:selectedAssetsImages];
}

#pragma mark -
#pragma mark UITableViewDataSource Delegate Methods

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    return 1;
}


- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    return ceil([self.assetGroup numberOfAssets] / 4.0);
}

- (NSArray*)assetsForIndexPath:(NSIndexPath*)_indexPath {
    
	NSInteger index = (_indexPath.row*4);
	NSInteger maxIndex = (_indexPath.row*4+3);
    
	if(maxIndex < [self.elcAssets count]) {
        
		return [NSArray arrayWithObjects:[self.elcAssets objectAtIndex:index],
				[self.elcAssets objectAtIndex:index + 1],
				[self.elcAssets objectAtIndex:index + 2],
				[self.elcAssets objectAtIndex:index + 3],
				nil];
	} else if(maxIndex - 1 < [self.elcAssets count]) {
        
		return [NSArray arrayWithObjects:[self.elcAssets objectAtIndex:index],
				[self.elcAssets objectAtIndex:index + 1],
				[self.elcAssets objectAtIndex:index + 2],
				nil];
	} else if(maxIndex - 2 < [self.elcAssets count]) {
        
		return [NSArray arrayWithObjects:[self.elcAssets objectAtIndex:index],
				[self.elcAssets objectAtIndex:index + 1],
				nil];
	} else if(maxIndex - 3 < [self.elcAssets count]) {
        
		return [NSArray arrayWithObject:[self.elcAssets objectAtIndex:index]];
	}
    
	return nil;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    
    static NSString *CellIdentifier = @"Cell";
        
    INQAssetCell *cell = (INQAssetCell*)[tableView dequeueReusableCellWithIdentifier:CellIdentifier];

    if (cell == nil) {		        
        cell = [[[INQAssetCell alloc] initWithAssets:[self assetsForIndexPath:indexPath] reuseIdentifier:CellIdentifier] autorelease];
    } else {		
#if 1
        // iOS7だとスクロールするとイメージが消える症状への対応(暫定対応)
        if ([[[[UIDevice currentDevice] systemVersion] componentsSeparatedByString:@"."][0] intValue] >= 7)
        {
            cell = [[[INQAssetCell alloc] initWithAssets:[self assetsForIndexPath:indexPath] reuseIdentifier:CellIdentifier] autorelease];
        }
        else
        {
            [cell setAssets:[self assetsForIndexPath:indexPath]];
        }
#else
		[cell setAssets:[self assetsForIndexPath:indexPath]];
#endif
	}
    
    return cell;
}

- (CGFloat)tableView:(UITableView *)tableView heightForRowAtIndexPath:(NSIndexPath *)indexPath {
    
	return 79;
}

- (int)totalSelectedAssets {
    
    int count = 0;
    
    for(INQAsset *asset in self.elcAssets)  {
		if([asset selected]) {            
            count++;	
		}
	}
    
    return count;
}

- (void)dealloc {
    [elcAssets release];
    [selectedAssetsLabel release];
    [super dealloc];    
}

@end
