
#import "INQTableViewController.h"
#import "INQDataSource.h"
#import "INQBookMarkDataSource.h"
#import "INQFileListViewController.h"

@interface INQBookMarkViewController : INQTableViewController<INQDataSourceCallBack,UITableViewDelegate>

@property (nonatomic,retain) NSMutableArray *data;

@end
