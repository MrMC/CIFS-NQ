
#import <UIKit/UIKit.h>
#import <QuickLook/QuickLook.h>

#import "INQFileDataSource.h"
#import "INQ.h"
#import "INQRemoteFileManager.h"
#import "INQAlbumPickerController.h"
#import "INQImagePickerController.h"
#import "INQAppDelegate.h"
#import "INQTableViewController.h"
#import "INQImageSlideViewController.h"

#import "ccapi.h"

@protocol INQLocalFileDelegate;
@protocol INQLocalFileDelegate <NSObject>

- (void)didEndUploadCallBack:(NSArray*)inqFiles;

- (void)didEndDownloadCallBack:(NSString*)downloadTo;

@end

@interface INQFileListViewController : INQTableViewController<UITableViewDelegate,INQDataSourceCallBack,QLPreviewControllerDataSource,QLPreviewControllerDelegate,UIActionSheetDelegate,INQImagePickerControllerDelegate,INQLocalFileDelegate,UIAlertViewDelegate> {
      
    NSMutableArray *documents_;
    INQFileDataSource *dataSource_;
    
    NSString *savedComputer;
    NSString *savedPath;
    BOOL isRootDir;
    BOOL isServer;
    BOOL isEdit;
    UITextField *textField;
    
    // selectmode
    BOOL selectMode;
    BOOL downloadMode;
    id<INQLocalFileDelegate> delegate;  
    
    // imageArray;
    NSMutableArray *imageArray;
    
    // preview file path
    NSString *previewFilePath;
    
}

@property (nonatomic,retain) IBOutlet UIActivityIndicatorView *loadingView;
@property (nonatomic,getter = isSelectMode) BOOL selectMode;
@property (nonatomic,getter = isDownloadMode) BOOL downloadMode;

@property (nonatomic,retain) id<INQLocalFileDelegate> delegate;

@property (nonatomic,retain) NSString *savedPath;
@property (nonatomic,retain) NSString *mountPoint;
@property (nonatomic,retain) INQFileDataSource *dataSource;
@property (nonatomic,retain) NSMutableArray *documents;

@property (nonatomic,retain) NSString *previewFilePath;

- (void)remoteShareNameFromPath:(NSMutableString *)shortPath from:(NSString *)orgPath;
- (void)loadDataFromLocalPath:(NSString*)path;
- (void)loadDataFromServer:(NSString*)server path:(NSString*)path;
- (void)endUploadTask;
@end
