
#import <UIKit/UIKit.h>

@interface INQStatusWindow : UIWindow {
    UIImageView *backgroundImageView;
    UILabel *loadingLabel;
    UIActivityIndicatorView *loadingView;
}

- (void)startLoading;
- (void)endLoading;

@end
