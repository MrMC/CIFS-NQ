
#import <UIKit/UIKit.h>
#import "INQImagePickerController.h"
#import "INQImagePickerController.h"
#import "INQAlbumPickerController.h"
#import "INQAppDelegate.h"
#import "INQFolderSettingViewController.h"

#import "INQRemoteFileManager.h"
#import "INQShareFolder.h"
#import "INQSharedFolderDataSource.h"
#import "INQFileListViewController.h"

@interface INQLocalViewController : UITableViewController<UIAlertViewDelegate>  {
    NSMutableArray *data_;
    UITextField *textField;
    //select mode.
    BOOL selectMode;
    BOOL downloadMode;
    id delegate;
}


@property (nonatomic,getter = isSelectMode) BOOL selectMode;
@property (nonatomic,getter = isDownloadMode) BOOL downloadMode;
@property (nonatomic,retain) NSString *uploadServer;
@property (nonatomic,retain) NSString *uploadPath;
@property (nonatomic,retain) id delegate;

@property (nonatomic,retain) NSMutableArray *data;

@end


