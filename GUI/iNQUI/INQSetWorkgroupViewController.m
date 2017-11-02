

#import "INQSetWorkgroupViewController.h"

@interface INQSetWorkgroupViewController ()

@end

@implementation INQSetWorkgroupViewController
@synthesize workgroupName;

- (id)initWithNibName:(NSString *)nibNameOrNil bundle:(NSBundle *)nibBundleOrNil
{
    self = [super initWithNibName:nibNameOrNil bundle:nibBundleOrNil];
    if (self) {
        // Custom initialization
    }
    return self;
}

- (void)viewDidLoad
{
    [super viewDidLoad];
    self.title = NSLocalizedString(@"Workgropu", @"Workgroup");
    
    UIBarButtonItem *saveButtonItem = [[UIBarButtonItem alloc] 
                                       initWithTitle:NSLocalizedString(@"Save",@"Save Button")
                                       style:UIBarButtonItemStylePlain 
                                       target:self 
                                       action:@selector(save)];
    
    self.navigationItem.rightBarButtonItem = saveButtonItem;
    [saveButtonItem release];    

    [workgroupName setText:[[NSUserDefaults standardUserDefaults] objectForKey:@"WORKGROUP"]];
}

- (void)save {
    if (workgroupName.text != nil) {
        DLog(@"WORKGROPU:%@",workgroupName.text);
        [[NSUserDefaults standardUserDefaults] setObject:[workgroupName.text uppercaseString] forKey:@"WORKGROUP"];
    }

    [self.navigationController popViewControllerAnimated:YES];  
}

- (void)viewDidUnload
{
    [super viewDidUnload];
    
}

- (BOOL)shouldAutorotateToInterfaceOrientation:(UIInterfaceOrientation)interfaceOrientation
{
    return (interfaceOrientation == UIInterfaceOrientationPortrait);
}

@end
