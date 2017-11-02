
#import "INQImagePickerController.h"

@implementation INQImagePickerController

@synthesize delegate;

-(void)cancelImagePicker {
	if([delegate respondsToSelector:@selector(inqImagePickerControllerDidCancel:)]) {
		[delegate performSelector:@selector(inqImagePickerControllerDidCancel:) withObject:self];
	}
}

-(void)selectedAssets:(NSArray*)_assets {
    
    UIActivityIndicatorView *loadView = [[UIActivityIndicatorView alloc]initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleWhiteLarge];
    CGRect rect = [[UIScreen mainScreen] bounds];
    loadView.frame = CGRectMake(rect.size.width / 2 - 25 , rect.size.height / 2 , 50, 50);
    self.view.alpha = 0.4;
    [self.view addSubview:loadView];
    [loadView startAnimating];
    [loadView release];    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSMutableArray *returnArray = [[[NSMutableArray alloc] init] autorelease];
        [self popToRootViewControllerAnimated:NO];
        for(ALAsset *asset in _assets) {

            NSMutableDictionary *workingDictionary = [[NSMutableDictionary alloc] init];
            [workingDictionary setObject:[asset valueForProperty:ALAssetPropertyType] forKey:@"UIImagePickerControllerMediaType"];
            
            ALAssetRepresentation *representation = [asset defaultRepresentation];
            UIImage *img = [UIImage imageWithCGImage:[representation fullResolutionImage]
                                               scale:[representation scale]
                                         orientation:[representation orientation]];

            [workingDictionary setObject:img forKey:@"UIImagePickerControllerOriginalImage"];
            [workingDictionary setObject:[[asset valueForProperty:ALAssetPropertyURLs] valueForKey:[[[asset valueForProperty:ALAssetPropertyURLs] allKeys] objectAtIndex:0]] forKey:@"UIImagePickerControllerReferenceURL"];
            
            [returnArray addObject:workingDictionary];
            
            [workingDictionary release];	
        }
        
        if([delegate respondsToSelector:@selector(inqImagePickerController:didFinishPickingMediaWithInfo:)]) {
            [delegate performSelector:@selector(inqImagePickerController:didFinishPickingMediaWithInfo:) withObject:self withObject:[NSArray arrayWithArray:returnArray]];
        }
        
        dispatch_async(dispatch_get_main_queue(), ^{
            [[self parentViewController] dismissViewControllerAnimated:YES completion:NULL];
        });
    });


}

#pragma mark -
#pragma mark Memory management

- (void)didReceiveMemoryWarning {        
    [super didReceiveMemoryWarning];
}

- (void)viewDidUnload {
    [super viewDidUnload];
}


- (void)dealloc {
    [super dealloc];
}

@end
