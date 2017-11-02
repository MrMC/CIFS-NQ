
#import <Foundation/Foundation.h>
#import "INQDataSource.h"
#import "INQComputer.h"
#import "INQShareFolder.h"
#import "INQ.h"
#import "INQShareFolder.h"
#import "INQServiceManager.h"
#import "INQRemoteFileManager.h"


#import "ccapi.h"

#define SHARE_FOLDERS @"SHARE_FOLDERS"


@interface INQSharedFolderDataSource : NSObject<INQDataSource,UITextFieldDelegate> {
    NSMutableArray *data_;
    id <INQDataSourceCallBack>delegate; 
    NSString *computer_;
    UITextField *userIdTextField;
    UITextField *passwordTextField;
    INQComputer *comInfo;
}

@property (nonatomic,retain) NSMutableArray *data;
@property (nonatomic,retain) id <INQDataSourceCallBack>delegate;
@property (nonatomic,retain) NSString* computer;

- (void)setComputerInfo:(INQComputer*)comInfo;
+ (void)sharedFolderRemoveById:(NSString*)folderId;
+ (id)getSharedFolderById:(NSString*)folderId;
+ (void)saveData:(INQShareFolder*)folderObj;

@end
