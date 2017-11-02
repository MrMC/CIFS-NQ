
#import "INQImageSlideViewController.h"

@interface INQImageSlideViewController ()
    
@end

@implementation INQImageSlideViewController
@synthesize imageArray = imageArray_;
@synthesize currentFileName;

- (id)initWithNibName:(NSString *)nibNameOrNil bundle:(NSBundle *)nibBundleOrNil {
    self = [super initWithNibName:nibNameOrNil bundle:nibBundleOrNil];
    if (self) {
        // Custom initialization
    }
    return self;
}

- (void)dealloc {
#if 1
    // 'viewDidUnload' is deprecated: first deprecated in iOS6.0対応
    [scrollView release];
    scrollView = nil;
    [view1 release];
    view1 = nil;
    [view2 release];
    view2 = nil;
#else
    [self viewDidUnload];
#endif
    [imageArray_ release];
    [super dealloc];
}

- (void)viewDidLoad {
    [super viewDidLoad];
	// Do any additional setup after loading the view.
    CGRect rect = [[UIScreen mainScreen] bounds];
    scrollView = [[UIScrollView alloc]initWithFrame:rect];
    [self.view addSubview:scrollView];
    scrollView.scrollEnabled = YES;
    scrollView.showsHorizontalScrollIndicator = NO;
    scrollView.showsVerticalScrollIndicator = NO;
    scrollView.pagingEnabled = YES;
    
    UITapGestureRecognizer *gesture = [[UITapGestureRecognizer alloc]initWithTarget:self action:@selector(tapScreen)];
    gesture.numberOfTapsRequired = 1;
    [scrollView addGestureRecognizer:gesture];
    [gesture release];

    
    view1 = [[UIImageView alloc] initWithFrame:rect];
    [view1 setContentMode:UIViewContentModeScaleAspectFit];
    [scrollView addSubview:view1];
    
    view2 = [[UIImageView alloc] initWithFrame:rect];
    [view2 setContentMode:UIViewContentModeScaleAspectFit];    
    [scrollView addSubview:view2];

    int width = [self.imageArray count] * rect.size.width;
    if (width == 0) {
        width = rect.size.width;
    }    
    scrollView.contentSize = CGSizeMake(width, rect.size.height);
    
    int i = 0;
    for (INQFile *inqFile in self.imageArray) {
        if ([currentFileName isEqualToString:inqFile.fileName]) {
            currentImageIndex = i;
        }
        i++;
    }
        
    [UIApplication sharedApplication].statusBarHidden = YES;
    INQFile *currentFile = [self.imageArray objectAtIndex:currentImageIndex];
    [view1 setImage:[UIImage imageWithContentsOfFile:currentFile.fullPath]];
    CGRect imageFrame = CGRectMake(currentImageIndex * rect.size.width,0, rect.size.width, rect.size.height);
    view1.frame = imageFrame;
    
    [scrollView setContentOffset:CGPointMake(currentImageIndex * rect.size.width, 0) animated:NO];    
    
    if (currentImageIndex == ([self.imageArray count] -1)) {
        view2Index = currentImageIndex - 1;
    } else {
        view2Index = currentImageIndex + 1;
    }
    
    INQFile *nextFile = [self.imageArray objectAtIndex:view2Index];
    [view2 setImage:[UIImage imageWithContentsOfFile:nextFile.fullPath]];
    view2.frame = CGRectMake(view2Index * rect.size.width,0, rect.size.width, rect.size.height);
    
}

- (void)viewDidUnload {
    [scrollView release];
    scrollView = nil;
    [view1 release];
    view1 = nil;
    [view2 release];
    view2 = nil;
    [super viewDidUnload];
}

- (void)tapScreen {
    [UIView animateWithDuration:0.3 animations:^{
        [UIApplication sharedApplication].statusBarHidden = ![UIApplication sharedApplication].statusBarHidden ;        
        self.navigationController.navigationBarHidden = !self.navigationController.navigationBarHidden;  
        
    }];    
      
}

- (void) scrollViewDidScroll:(UIScrollView *) scrollView {	
	[self update];
}



- (void) update {
    CGRect rect = [[UIScreen mainScreen] bounds];    
	CGFloat pageWidth = rect.size.width;
	float currPos = scrollView.contentOffset.x;
	
	int selectedPage = roundf(currPos / pageWidth);
	
	float truePosition = selectedPage * pageWidth;
	
	int zone = selectedPage % 2;
	
	BOOL view1Active = zone == 0;
	
	UIImageView *nextView = view1Active ? view2 : view1;
	
	int nextpage = truePosition > currPos ? selectedPage - 1 : selectedPage + 1;
	
	if(nextpage >= 0 && nextpage < [self.imageArray count]) {
		
        if((view1Active && nextpage == currentImageIndex) || (!view1Active && nextpage == view2Index)) return;
		
		nextView.frame = CGRectMake(nextpage * rect.size.width,0,rect.size.width,rect.size.height);
        INQFile *file = [self.imageArray objectAtIndex:nextpage];
		nextView.image = [UIImage imageWithContentsOfFile:file.fullPath];
		
		if(view1Active) 
            currentImageIndex = nextpage;
		else 
            view2Index = nextpage;
	}
}


- (BOOL)shouldAutorotateToInterfaceOrientation:(UIInterfaceOrientation)interfaceOrientation {
    return (interfaceOrientation == UIInterfaceOrientationPortrait);
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    NSLog(@"DidReceive Memory Warning....");
}
@end
