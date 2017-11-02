
#import <UIKit/UIKit.h>
#import "INQ.h"

@interface INQSetUserPasswordViewController : UIViewController<UITextFieldDelegate> {
    UILabel *userIdLabel;
    UILabel *passwordlabel;
    UITextField *userIdTextField;
    UITextField *passwordTextField;
}

@property (nonatomic,retain) IBOutlet UILabel *userIdLabel;
@property (nonatomic,retain) IBOutlet UILabel *passwordlabel;
@property (nonatomic,retain) IBOutlet UITextField *userIdTextField;
@property (nonatomic,retain) IBOutlet UITextField *passwordTextField;

@end
