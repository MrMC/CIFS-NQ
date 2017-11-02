//
//  INQRemoteTargetsViewController.h
//  iNQ
//
//  Created by Tanya Golberg on 3/20/14.
//  Copyright (c) 2014 ryuu@hotit.co.jp. All rights reserved.
//

#import <UIKit/UIKit.h>
#import "INQDataSource.h"
#import "INQServiceManager.h"
#import "INQComputerDataSource.h"
#import "INQAddWorkgroupViewController.h"
#import "INQComputerDataSource.h"
#import "INQSharedFolderViewController.h"
#import "INQAddWorkgroupViewController.h"
#import "INQTableViewController.h"

@interface INQRemoteTargetsViewController : UITableViewController <INQDataSourceCallBack,UITableViewDelegate,UITextFieldDelegate>

@property (nonatomic,retain) NSMutableArray *data;
@property (nonatomic,retain) NSMutableArray *dataTmp;

@end

