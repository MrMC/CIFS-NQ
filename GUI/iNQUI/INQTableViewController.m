
#import <QuartzCore/QuartzCore.h>
#import "INQTableViewController.h"

@interface INQTableViewController () {
    UITableView *tableView_;
    UIView *refreshHeaderView_;
    UILabel *refreshLabel_;
    UIImageView *refreshArrow_;
    UIActivityIndicatorView *refreshSpinner_;
    BOOL isDragging;
    BOOL isLoading;
    NSString *textPull_;
    NSString *textRelease_;
    NSString *textLoading_;
    UILabel *messageLabel_;
}

@property (nonatomic,retain) UIView *refreshHeaderView;
@property (nonatomic,retain) UILabel *refreshLabel;
@property (nonatomic,retain) UIImageView *refreshArrow;
@property (nonatomic,retain) UIActivityIndicatorView *refreshSpinner;
@property (nonatomic,copy) NSString *textPull;
@property (nonatomic,copy) NSString *textRelease;


- (void)setupStrings;
- (void)addPullToRefreshHeader;

@end

#define REFRESH_HEADER_HEIGHT 52.0f

@implementation INQTableViewController
@synthesize tableView = tableView_;
@synthesize textPull = textPull_;
@synthesize textRelease = textRelease_;
@synthesize textLoading = textLoading_;
@synthesize refreshHeaderView = refreshHeaderView_;
@synthesize refreshLabel = refreshLabel_;
@synthesize refreshArrow = refreshArrow_;
@synthesize refreshSpinner = refreshSpinner_;
@synthesize messageLabel = messageLabel_;

- (id)initWithStyle:(UITableViewStyle)style {
    self = [super init];
    
    if (self != nil) {
        CGRect rect = [[UIScreen mainScreen] bounds]; 
        tableView_ = [[UITableView alloc]initWithFrame:rect style:style];

        //[self setupStrings];
    }
    
    return self;
}

- (id)initWithCoder:(NSCoder *)aDecoder {
    self = [super initWithCoder:aDecoder];
    
    if (self != nil) {
        CGRect rect = [[UIScreen mainScreen] bounds]; 

        tableView_ = [[UITableView alloc]initWithFrame:rect];   
        //[self setupStrings];
    }
    
    return self;
}

- (id)initWithNibName:(NSString *)nibNameOrNil bundle:(NSBundle *)nibBundleOrNil {
    self = [super initWithNibName:nibNameOrNil bundle:nibBundleOrNil];
    
    if (self != nil) {
        CGRect rect = [[UIScreen mainScreen] bounds];
        tableView_ = [[UITableView alloc]initWithFrame:rect];     
        //[self setupStrings];
    }
    
    return self;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    [self.view addSubview:self.tableView];
    self.tableView.scrollEnabled = YES;
    [self addPullToRefreshHeader];
    CGRect rect = [[UIScreen mainScreen]bounds];
    messageLabel_ = [[UILabel alloc]initWithFrame:CGRectMake(0, rect.size.height / 3, rect.size.width, 50)];
    messageLabel_.backgroundColor = [UIColor clearColor];
    messageLabel_.textAlignment = NSTextAlignmentCenter;
    messageLabel_.font = [UIFont boldSystemFontOfSize:15.0f];
    messageLabel_.textColor = [UIColor grayColor];
    [self.view addSubview:messageLabel_];
    messageLabel_.hidden = YES;
}

- (void)setupStrings{
    textPull_ = NSLocalizedString(@"PullDownToRefresh",@"Pull down to refresh..");
    textRelease_ = NSLocalizedString(@"ReleaseToRefresh",@"Release to refresh...");
    self.textLoading = NSLocalizedString(@"Loading...",@"Loading...");
}

- (void)addPullToRefreshHeader {
    refreshHeaderView_ = [[UIView alloc] initWithFrame:CGRectMake(0,0 - REFRESH_HEADER_HEIGHT,320,REFRESH_HEADER_HEIGHT)];
    self.refreshHeaderView.backgroundColor = [UIColor clearColor];
    
    refreshLabel_ = [[UILabel alloc] initWithFrame:CGRectMake(0,0,320,REFRESH_HEADER_HEIGHT)];
    self.refreshLabel.backgroundColor = [UIColor clearColor];
    self.refreshLabel.font = [UIFont boldSystemFontOfSize:12.0];
    self.refreshLabel.textAlignment = NSTextAlignmentCenter;
    
    refreshArrow_ = [[UIImageView alloc] initWithImage:[UIImage imageNamed:@"arrow.png"]];
    self.refreshArrow.frame = CGRectMake(floorf((REFRESH_HEADER_HEIGHT - 27) / 2),
                                    (floorf(REFRESH_HEADER_HEIGHT - 44) / 2),
                                    27,44);
    
    refreshSpinner_ = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleGray];
    self.refreshSpinner.frame = CGRectMake(floorf(floorf(REFRESH_HEADER_HEIGHT - 20) / 2),floorf((REFRESH_HEADER_HEIGHT - 20) / 2),20,20);
    self.refreshSpinner.hidesWhenStopped = YES;
    
    [self.refreshHeaderView addSubview:self.refreshLabel];
    [self.refreshHeaderView addSubview:self.refreshArrow];
    [self.refreshHeaderView addSubview:self.refreshSpinner];
    [self.tableView addSubview:self.refreshHeaderView];
}

- (void)scrollViewWillBeginDragging:(UIScrollView *)scrollView {
    
    if (isLoading) return;
    
    isDragging = YES;
}

- (void)scrollViewDidScroll:(UIScrollView *)scrollView {
    
    if (isLoading) {

        if (scrollView.contentOffset.y > 0)
            self.tableView.contentInset = UIEdgeInsetsZero;
        else if (scrollView.contentOffset.y >= -REFRESH_HEADER_HEIGHT)
            self.tableView.contentInset = UIEdgeInsetsMake(-scrollView.contentOffset.y,0,0,0);
    } else if (isDragging && scrollView.contentOffset.y < 0) {

        [UIView animateWithDuration:0.25 animations:^{
            if (scrollView.contentOffset.y < -REFRESH_HEADER_HEIGHT) {

                self.refreshLabel.text = self.textRelease;
                [self.refreshArrow layer].transform = CATransform3DMakeRotation(M_PI,0,0,1);
            } else { 

                self.refreshLabel.text = self.textPull;
                [self.refreshArrow layer].transform = CATransform3DMakeRotation(M_PI * 2,0,0,1);
            }
        }];
    }
}

- (void)scrollViewDidEndDragging:(UIScrollView *)scrollView willDecelerate:(BOOL)decelerate {
    
    if (isLoading) return;
    isDragging = NO;
    
    if (scrollView.contentOffset.y <= -REFRESH_HEADER_HEIGHT) {
        [self startLoading];
    }
}

- (void)startLoading {
    isLoading = YES;
    
    [UIView animateWithDuration:0.3 animations:^{
        self.tableView.contentInset = UIEdgeInsetsMake(REFRESH_HEADER_HEIGHT,0,0,0);
        self.refreshLabel.text = self.textLoading;
        self.refreshArrow.hidden = YES;
        [self.refreshSpinner startAnimating];
    }];

    [self refresh];
}

- (void)stopLoading {
    isLoading = NO;
    
    [UIView animateWithDuration:0.3 animations:^{
        self.tableView.contentInset = UIEdgeInsetsZero;
        [self.refreshArrow layer].transform = CATransform3DMakeRotation(M_PI * 2,0,0,1);
    } 
                     completion:^(BOOL finished) {
                         [self performSelector:@selector(stopLoadingComplete)];
                     }];
}

- (void)stopLoadingComplete {

    self.refreshLabel.text = self.textPull;
    self.refreshArrow.hidden = NO;
    [self.refreshSpinner stopAnimating];
}

// Override this.
- (void)refresh {

}

- (void)viewDidUnload {
    [super viewDidUnload];
    self.tableView = nil;
    self.refreshHeaderView = nil;
    self.refreshLabel = nil;
    self.refreshArrow = nil;
    self.refreshSpinner = nil;
}

- (void)dealloc {
    [tableView_ release];
    [refreshHeaderView_ release];
    [refreshLabel_ release];
    [refreshArrow_ release];
    [refreshSpinner_ release];
    self.textPull = nil;
    self.textRelease = nil;
    self.textLoading = nil;
    self.tableView = nil;
    self.refreshHeaderView = nil;
    self.refreshLabel = nil;
    self.refreshArrow = nil;
    self.refreshSpinner = nil;
    
    [super dealloc];
}

@end
