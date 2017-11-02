
#import "INQSetUserPasswordViewController.h"

@interface INQSetUserPasswordViewController ()

@end

@implementation INQSetUserPasswordViewController
@synthesize userIdTextField,passwordlabel,userIdLabel,passwordTextField;

- (id)initWithNibName:(NSString *)nibNameOrNil bundle:(NSBundle *)nibBundleOrNil {
    self = [super initWithNibName:nibNameOrNil bundle:nibBundleOrNil];
    if (self) {
        // Custom initialization
    }
    return self;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = NSLocalizedString(@"Setting", @"Setting");

    UIBarButtonItem *saveButtonItem = [[UIBarButtonItem alloc] 
                                       initWithTitle:NSLocalizedString(@"Save",@"Save Button")
                                       style:UIBarButtonItemStylePlain 
                                       target:self 
                                       action:@selector(save)];

     self.navigationItem.rightBarButtonItem = saveButtonItem;
    [saveButtonItem release];    
    [userIdLabel setText:NSLocalizedString(@"UserID", @"User ID")];
    [passwordlabel setText:NSLocalizedString(@"Password", @"Password")];  
    [userIdTextField becomeFirstResponder];
    
    [userIdTextField setText:[[NSUserDefaults standardUserDefaults] objectForKey:@"USERID"]];
    [passwordTextField setText:[[NSUserDefaults standardUserDefaults] objectForKey:@"PASSWORD"]];
}

- (void)viewDidUnload {
    [super viewDidUnload];

}


- (void)textFieldDidEndEditing:(UITextField *)textField {
    [textField setText:[textField.text uppercaseString]];
}

- (void)save {
    if (userIdTextField.text != nil) {
        DLog(@"USERID:%@",userIdTextField.text);
        [[NSUserDefaults standardUserDefaults] setObject:[userIdTextField.text uppercaseString] forKey:@"USERID"];
    }
    if (passwordTextField.text != nil) {
        DLog(@"PASSWORD:%@",passwordTextField.text);
        [[NSUserDefaults standardUserDefaults] setObject:passwordTextField.text forKey:@"PASSWORD"];
    }
    
    [self.navigationController popViewControllerAnimated:YES];  
}

- (BOOL)shouldAutorotateToInterfaceOrientation:(UIInterfaceOrientation)interfaceOrientation {
    return (interfaceOrientation == UIInterfaceOrientationPortrait);
}

@end
