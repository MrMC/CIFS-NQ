
#import <mach/mach.h>
#import "INQStatusWindow.h"

@implementation INQStatusWindow

- (id)initWithFrame:(CGRect)frame {
    if ((self = [super initWithFrame:frame])) {
        // Place the window on the correct level and position
        self.windowLevel = UIWindowLevelStatusBar + 1.0f;
        
        self.frame = [[UIApplication sharedApplication] statusBarFrame];
        
        // Create an image view with an image to make it look like a status bar.
        UIView *backView = [[UIView alloc]initWithFrame:CGRectMake(200, 0, 220,self.frame.size.height)];
        backView.backgroundColor = [UIColor blackColor];
        backView.alpha = 0.9;
        backgroundImageView = [[UIImageView alloc] initWithFrame:self.frame];
        backgroundImageView.image = [[UIImage imageNamed:@"statusBarBackgroundGrey.png"] stretchableImageWithLeftCapWidth:2.0f topCapHeight:0.0f];
        [self addSubview:backView];

        loadingLabel = [[UILabel alloc]initWithFrame:CGRectMake(0, 0, 200, 20)];

        loadingLabel.backgroundColor = [UIColor clearColor];
        loadingLabel.font = [UIFont boldSystemFontOfSize:14.0f];
        loadingLabel.textColor = [UIColor whiteColor];
        [backView addSubview:loadingLabel];
        
        loadingView = [[UIActivityIndicatorView alloc]initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleWhite];
        loadingView.frame = CGRectMake(backView.frame.size.width - 22  , 2, 15, 15);
        [backView addSubview:loadingView];
        
#if 1   
        // Analyze対応 [Potential leak of an object stored into 'backView']
        [backView release];
#endif
        
        loadingView.hidden = YES;
      //  [loadingView startAnimating];
        [NSTimer scheduledTimerWithTimeInterval:1.0f target:self selector:@selector(memoryStatus) userInfo:NO repeats:YES];
        
    }
    return self;
}

- (void)memoryStatus {
    float m = [self memory];
    loadingLabel.textColor = [UIColor whiteColor];
    if (m < 20.0) {
        loadingLabel.textColor = [UIColor redColor];
    }
    loadingLabel.text = [NSString stringWithFormat:@"%4.1fMB Free",[self memory]];   
    
}

/*
// Only override drawRect: if you perform custom drawing.
// An empty implementation adversely affects performance during animation.
- (void)drawRect:(CGRect)rect
{
    // Drawing code
}
*/

- (void)startLoading {
    loadingView.hidden = NO;
    [loadingView startAnimating];
}

- (void)endLoading {
    loadingView.hidden = YES;
    [loadingView stopAnimating];
}

#define kTimerInterval 1.0
#define tval2msec(tval) ((tval.seconds * 1000) + (tval.microseconds / 1000))

- (float)memory {
    struct vm_statistics a_vm_info;
    
    mach_msg_type_number_t a_count = HOST_VM_INFO_COUNT;
    
    host_statistics( mach_host_self(), HOST_VM_INFO, (host_info_t)&a_vm_info ,&a_count);
    
    return ((a_vm_info.free_count * vm_page_size)/1024.0)/1024.0;

}
@end
