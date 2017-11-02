
#import <UIKit/UIKit.h>
#import "INQFile.h"

@interface INQImageSlideViewController : UIViewController<UIScrollViewDelegate> {
    UIScrollView *scrollView;
    NSMutableArray *imageArray_;
    int currentImageIndex;
    int view2Index;
    UIImageView *view1;
    UIImageView *view2;
    
}

@property (nonatomic,retain) NSString *currentFileName;
@property (nonatomic,retain) NSMutableArray *imageArray;
@end
