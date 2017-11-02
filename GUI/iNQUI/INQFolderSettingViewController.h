
#import <UIKit/UIKit.h>
#import "INQShareFolder.h"

@interface INQFolderSettingViewController : UITableViewController<UITextFieldDelegate> {    
    INQShareFolder *folderObj;
}

@property (nonatomic,retain) INQShareFolder *folderObj;

- (void)alertMessage:(NSString*)msg;
@end
