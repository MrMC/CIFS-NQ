
#import <UIKit/UIKit.h>
#import "INQDataSource.h"
#import "INQServiceManager.h"
#import "INQComputerDataSource.h"
#import "INQAddWorkgroupViewController.h"
#import "INQComputerDataSource.h"
#import "INQSharedFolderViewController.h"
#import "INQAddWorkgroupViewController.h"
#import "INQTableViewController.h"

#if 1
// プルダウン操作によるワークグループ検索機能を無効に伴うコメントアウト
@interface INQWorkgroupViewController :  UITableViewController <INQDataSourceCallBack,UITableViewDelegate,UITextFieldDelegate> {
#else
@interface INQWorkgroupViewController : INQTableViewController <INQDataSourceCallBack,UITableViewDelegate,UITextFieldDelegate> {
#endif
    BOOL isBookMark;

    UIView                  *loadingView;	// 処理中インジケータ画面
    UIActivityIndicatorView *indicator;     // 処理中インジケータ
    UILabel                 *loadingMessageLabel;// 処理中ラベル
    NSInteger               backupDataTmpIndex;
    INQAddWorkgroupViewController * addWorkgroupController;
}

@property (nonatomic,retain) NSMutableArray *data;
@property (nonatomic,retain) NSMutableArray *dataTmp;
@property (nonatomic,retain) NSMutableArray *domainList;
@property (nonatomic) BOOL isBookMark;

@property (nonatomic, retain) INQAddWorkgroupViewController * addWorkgroupController;
@property (nonatomic, retain) UIView *loadingView;
@property (nonatomic, retain) UIActivityIndicatorView *indicator;
@property (nonatomic, retain) UILabel *loadingMessageLabel;
@property (nonatomic) NSInteger backupDataTmpIndex;
    
- (void)loadWorkgroups;

@end
