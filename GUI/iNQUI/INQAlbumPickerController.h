
#import <UIKit/UIKit.h>
#import <AssetsLibrary/AssetsLibrary.h>
#import "INQ.h"
#import "INQImagePickerController.h"

@interface INQAlbumPickerController : UITableViewController {
	
	NSMutableArray *assetGroups;
	NSOperationQueue *queue;
	id parent;
    
    ALAssetsLibrary *library;
}

@property (nonatomic, assign) id parent;
@property (nonatomic, retain) NSMutableArray *assetGroups;

-(void)selectedAssets:(NSArray*)_assets;

@end

