

#import "INQNavigationBar.h"

@implementation INQNavigationBar

- (id)initWithFrame:(CGRect)frame
{
    self = [super initWithFrame:frame];
    if (self) {
        UIView *backView = [[[UIView alloc]initWithFrame:self.frame]autorelease];
        backView.backgroundColor = [UIColor redColor];
        [self addSubview:backView];
        // Initialization code
    }
    return self;
}


// Only override drawRect: if you perform custom drawing.
// An empty implementation adversely affects performance during animation.
- (void)drawRect:(CGRect)rect {
    UIImage *imageBackground = [UIImage imageNamed: @"statusBarBackgroundGrey.png"];
    [imageBackground drawInRect: CGRectMake(0, 0, self.frame.size.width, self.frame.size.height) ];
}


@end
