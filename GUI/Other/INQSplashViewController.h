
#import <UIKit/UIKit.h>
#import "INQHomeViewController.h"

@interface INQSplashViewController : UIViewController {
    UIActivityIndicatorView *loadingView;
    UILabel *loadingMessage;
    NSString *loadingText;
    NSTimer *timer;
    BOOL end;
}

@end
