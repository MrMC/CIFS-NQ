
#import <UIKit/UIKit.h>
#import "INQ.h"
#import "INQComputer.h"

@interface INQAddWorkgroupViewController : UIViewController<UITableViewDataSource,UITableViewDelegate, UITextFieldDelegate,UITextFieldDelegate> 

@property (nonatomic,retain) INQComputer *data;

-(void)removeSegmentedControlFromView;
- (void)startLoadingView:(NSString *)workgroup;
- (void)stopLoadingView;
@property (nonatomic, retain) UIView *loadingView;
@property (nonatomic, retain) UIActivityIndicatorView *indicator;
@property (nonatomic, retain) UILabel *loadingMessageLabel;

@end
