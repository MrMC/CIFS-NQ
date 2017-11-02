
#import <UIKit/UIKit.h>

#import "INQFileListViewController.h"
#import "INQShareFolder.h"
#import "INQSharedFolderDataSource.h"
#import "INQComputer.h"
#import "INQ.h"
#import "INQTableViewController.h"
#import "INQComputer.h"

@interface INQSharedFolderViewController : INQTableViewController <INQDataSourceCallBack,UITableViewDelegate> {
    
    NSMutableArray *data_;
    
    INQSharedFolderDataSource *dataSource;
    INQComputer *computerInfo;
}
@property (nonatomic,retain) NSMutableArray *data;
@property (nonatomic,retain) INQComputer *computerInfo;
@property (nonatomic) BOOL isBookMark;
@end
