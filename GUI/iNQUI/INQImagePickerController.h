
#import <UIKit/UIKit.h>
#import "INQImagePickerController.h"
#import "INQAssetTablePicker.h"

@interface INQImagePickerController : UINavigationController {

	id delegate;
}

@property (nonatomic, assign) id delegate;

-(void)selectedAssets:(NSArray*)_assets;
-(void)cancelImagePicker;

@end

@protocol INQImagePickerControllerDelegate

- (void)inqImagePickerController:(INQImagePickerController *)picker didFinishPickingMediaWithInfo:(NSArray *)info;
- (void)inqImagePickerControllerDidCancel:(INQImagePickerController *)picker;

@end

