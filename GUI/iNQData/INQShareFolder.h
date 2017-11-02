
#import <Foundation/Foundation.h>

#define USER_NAME @"USER_NAME"
#define PASSWORD @"PASSWORD"
#define GUEST @"GUEST"
#define FOLDER_NAME @"FOLDER_NAME"
#define FOLDER_PATH @"FOLDER_PATH"
#define SHARE @"SHARE"

@interface INQShareFolder : NSObject {
    NSString *folderId;
    NSString *path;
    NSString *folderName;
    NSString *userName;
    NSString *password;
    NSString *mountPoint;
    BOOL mounted;
    BOOL security;
    BOOL guest;
    BOOL share;
}

@property (nonatomic,retain) NSString *folderId;
@property (nonatomic,retain) NSString *path;
@property (nonatomic,retain) NSString *mountPoint;
@property (nonatomic,retain) NSString *folderName;
@property (nonatomic,retain)NSString *userName;
@property (nonatomic,retain)NSString *password;
@property (nonatomic,getter = isMounted) BOOL mounted;
@property (nonatomic,getter = isSecurity)BOOL security;
@property (nonatomic,getter = isGuest) BOOL guest;
@property (nonatomic,getter = isShare) BOOL share;
@end
