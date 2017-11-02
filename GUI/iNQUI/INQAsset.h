
#import <UIKit/UIKit.h>
#import <AssetsLibrary/AssetsLibrary.h>
#import "INQAssetTablePicker.h"

@interface INQAsset : UIView {
	ALAsset *asset;
	UIImageView *overlayView;
	BOOL selected;
	id parent;
}

@property (nonatomic, retain) ALAsset *asset;
@property (nonatomic, assign) id parent;

-(id)initWithAsset:(ALAsset*)_asset;
-(BOOL)selected;

@end