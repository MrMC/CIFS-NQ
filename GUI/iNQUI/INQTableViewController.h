
#import <UIKit/UIKit.h>
#import "INQ.h"

@interface INQTableViewController : UIViewController

@property (nonatomic,retain)    UITableView *tableView;
@property (nonatomic,copy)      NSString *textLoading;
@property (nonatomic,retain)    UILabel *messageLabel;

- (id)initWithStyle:(UITableViewStyle)style;
- (void)startLoading;
- (void)stopLoading;
- (void)refresh;

@end
