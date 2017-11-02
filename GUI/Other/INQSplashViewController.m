
#import "INQSplashViewController.h"

@interface INQSplashViewController ()
{
    BOOL    isStartup;
}
@end

@implementation INQSplashViewController

- (id)initWithNibName:(NSString *)nibNameOrNil bundle:(NSBundle *)nibBundleOrNil {
    self = [super initWithNibName:nibNameOrNil bundle:nibBundleOrNil];
    if (self) {
        // Custom initialization
        isStartup = NO;
    }
    return self;
}

- (void)viewDidLoad
{
    [super viewDidLoad];
    // タイトル画面を表示後、本SplashView画面に遷移した際に背景に表示する画像を各条件に応じて設定する処理
    UIImageView *backgroundView = nil;
    // current iOS version is after 7
    if ([[[[UIDevice currentDevice] systemVersion] componentsSeparatedByString:@"."][0] intValue] >= 7)
    {
        if (([UIScreen mainScreen].bounds.size.height == 480) || ([UIScreen mainScreen].bounds.size.height == 460))
        {
            backgroundView = [[UIImageView alloc]initWithImage:[UIImage imageNamed:@"Default@2x.png"]];
        }
        else
        {
            backgroundView = [[UIImageView alloc]initWithImage:[UIImage imageNamed:@"Default-568h@2x.png"]];
        }
    }
    else
    {
        if (([UIScreen mainScreen].bounds.size.height == 480) || ([UIScreen mainScreen].bounds.size.height == 460))
        {
            backgroundView = [[UIImageView alloc]initWithImage:[UIImage imageNamed:@"splashView_480.png"]];
        }
        else
        {
            backgroundView = [[UIImageView alloc]initWithImage:[UIImage imageNamed:@"splashView_568.png"]];
        }
    }
    
    backgroundView.frame = [[UIScreen mainScreen] bounds];
    [self.view addSubview:backgroundView];
    
    // Analyze対応 [Potential leak of an object stored into 'backgroundView']
    [backgroundView release];
    
    [[UIApplication sharedApplication] setStatusBarHidden:NO];
    self.navigationController.navigationBar.hidden = YES;
    
    //[self.view addSubview:backgroundView];
    self.view.backgroundColor = [UIColor groupTableViewBackgroundColor];
    
    loadingView = [[UIActivityIndicatorView alloc]initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleWhiteLarge];
    
    CGRect orgRect = loadingView.frame;
    
    orgRect.origin.x = 0.5 * (self.view.frame.size.width - orgRect.size.width);
    // インジケーターの表示位置を変更(背景画像に合わせて下げた)
    orgRect.origin.y = 0.8 * (self.view.frame.size.height - orgRect.size.height);
    loadingView.frame = orgRect;
    
    [self.view addSubview:loadingView];    
    float sleepTime = 7.5f;
    [loadingView startAnimating];
    
    INQAppDelegate *delegate = [[UIApplication sharedApplication] delegate]; 
    BOOL isAuto = [[NSUserDefaults standardUserDefaults] boolForKey:IS_AUTO_START_SERVER];
    if (!delegate.isWifi || !isAuto) {
        // 初期化時間を若干延長(共有先への接続性向上を目的として[暫定対応])
        sleepTime = 2.5f;
    }
    
    if (isAuto)
    {
        isStartup = YES;
    }
    
    timer = [NSTimer scheduledTimerWithTimeInterval:sleepTime target:self selector:@selector(endLoading) userInfo:nil repeats:NO];

    // ローディングメッセージの位置微調整
    loadingMessage = [[UILabel alloc]initWithFrame:CGRectMake(0, orgRect.origin.y + 25, backgroundView.frame.size.width, 50)];
    // ローディングメッセージのフォント・文字サイズ設定
    loadingMessage.font = [UIFont fontWithName:@"AppleGothic" size:12];
    [self.view addSubview:loadingMessage];
    loadingMessage.backgroundColor = [UIColor clearColor];
    loadingMessage.textColor = [UIColor whiteColor];
    loadingMessage.textAlignment = NSTextAlignmentCenter;
    loadingText = NSLocalizedString(@"Loading...",@"Loading...");
    [loadingMessage setText:loadingText];
    
}

/**
 * @brief Viewが表示された直後に呼び出される処理
 * @note  iOS7以降で標準で実装されているスワイプ操作にて戻る機能より起動時以降に本画面に戻るケースがあることへの対応.
 */
- (void)viewDidAppear:(BOOL)animated
{
    static int count = 0;
    
    if(count > 0)
    {
        INQHomeViewController *controller;
        if(([UIScreen mainScreen].bounds.size.height == 480) || ([UIScreen mainScreen].bounds.size.height == 460))
        {
            controller = [[INQHomeViewController alloc]initWithNibName:@"INQHomeViewController_480" bundle:[NSBundle mainBundle]];
        }
        else
        {
            controller = [[INQHomeViewController alloc]initWithNibName:@"INQHomeViewController" bundle:[NSBundle mainBundle]];
        }

        [UIView transitionFromView:self.view toView:controller.view
                          duration:1.5
                           options:UIViewAnimationOptionTransitionCrossDissolve
                        completion:nil];
        [self.navigationController pushViewController:controller animated:NO];
        [controller release];
    }
    else
    {
        count++;
    }
}

/**
 * @brief Viewが表示される直前に呼び出される処理
 */
-(void)viewWillAppear:(BOOL)animated
{
    [super viewWillAppear:animated];
    
    // ツールバー 表示設定(無効)
    [self.navigationController setToolbarHidden:YES];
}

- (void)endLoading {
    DLog(@"time end...");
    [self goHome:NO];
}

- (void)goHome:(BOOL)serverStarted {
    
    [loadingView stopAnimating];
    // インジケーターの停止と合わせて"Loading..."のラベル表示もクリア
    loadingText = @"";
    [loadingMessage setText:loadingText];
    
    INQHomeViewController *controller;
    if ([[UIDevice currentDevice] userInterfaceIdiom] == UIUserInterfaceIdiomPhone)
    {
        /**
         * ホーム画面に対して3.5inch用と4inch用でxibファイルを切り替える対応
         */
        if ([UIScreen mainScreen].bounds.size.height == 480)
        {
            controller = [[INQHomeViewController alloc]initWithNibName:@"INQHomeViewController_480" bundle:[NSBundle mainBundle]];
        }
        else
        {
            controller = [[INQHomeViewController alloc]initWithNibName:@"INQHomeViewController" bundle:[NSBundle mainBundle]];
        }
    }
    else
    {
        controller = [[INQHomeViewController alloc]initWithNibName:@"INQHomeViewController_iPad" bundle:[NSBundle mainBundle]];
    }

    // ホーム画面に遷移する際のトランジションを設定
    [UIView transitionFromView:self.view toView:controller.view
                      duration:1.0
                       options:UIViewAnimationOptionTransitionCrossDissolve
                    completion:nil];
    [self.navigationController pushViewController:controller animated:NO];

    [controller release];
}

- (void)viewDidUnload {
    [super viewDidUnload];
}

- (BOOL)shouldAutorotateToInterfaceOrientation:(UIInterfaceOrientation)interfaceOrientation {
    return (interfaceOrientation == UIInterfaceOrientationPortrait);
}

#pragma mark -
#pragma mark NotificationCenter call Methods.

- (void)browserDaemonStarted {
}

- (void)browserDaemonClosed {
    
}

- (void)netBiosDaemonStarted {
    
}

- (void)netBiosDaemonClosed {
    
}

- (void)cifsServerStarted {
    DLog(@"start server ...");    
    [[INQServiceManager sharedManager] setServerStated:YES];
    //end = YES;
    
    if (isStartup)
    {
        [self endLoading];
        isStartup = NO;
    }
    
    
}

- (void)cifsServerClosed {
    DLog(@"close server ...");    
    [[INQServiceManager sharedManager] setServerStated:NO];
    //end = YES;
    
    if (isStartup)
    {
        [self endLoading];
        
        UIAlertView *alertView = [[UIAlertView alloc]initWithTitle:@" Auto-Start of server failed, please start manualy"
                                                           message:nil
                                                          delegate:nil
                                                 cancelButtonTitle:NSLocalizedString(@"OK",@"OK Button")
                                                 otherButtonTitles:nil, nil];
        [alertView show];
        [alertView release];
        isStartup = NO;
    }
    
    
}

@end
