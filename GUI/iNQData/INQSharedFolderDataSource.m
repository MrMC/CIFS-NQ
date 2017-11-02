
#import "INQSharedFolderDataSource.h"
#import "INQAppDelegate.h"

#import "udconfig.h"
#import "nsapi.h"

@implementation INQSharedFolderDataSource
@synthesize data = data_,delegate,computer = computer_;

- (id)init {
    if (self = [super init]) {
        data_ = [[NSMutableArray alloc]init]; 
        
    }
    return self;
}

- (void)dealloc {
    [data_ release];
    data_ = nil;
    [computer_ release];
    computer_ = nil;
    [userIdTextField release];
    userIdTextField = nil;
    [passwordTextField release];
    passwordTextField = nil;
    [super dealloc];
    
}

- (void)setComputerInfo:(INQComputer*)aComInfo {
    NSArray *arr = [aComInfo.computerNameIP componentsSeparatedByString:@"."];
    
    // set ip by hostname.
    if ([arr count] != 4) {
        NSString *ip = [[NSString stringWithUTF8String:[self getIpByHostName:(char *)[aComInfo.computerNameIP UTF8String]]] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
        if (ip != NULL && ![ip isEqualToString:@""]) {
            aComInfo.computerNameIP = ip;            
        }
    }
    
    computer_ = aComInfo.computerNameIP;
    comInfo = aComInfo;
//    INQAppDelegate *app = (INQAppDelegate*)[[UIApplication sharedApplication] delegate];
    //[app.inqStatusWindow startLoading];
    [self performSelectorInBackground:@selector(getFolder:) withObject:aComInfo];
}

- (char*)getIpByHostName:(char*)hostName {
    static NQ_CHAR temp[CM_IPADDR_MAXLEN];
    CMNetBiosNameInfo nbName;
    NQ_IPADDRESS ipAddr;
//  NQ_STATUS res;
    syMemset(&nbName.name, 0, sizeof(nbName.name));    
    cmNetBiosNameCreate(nbName.name, hostName, CM_NB_POSTFIX_WORKSTATION);    
    /* res =  */ nsGetHostByName(&ipAddr, &nbName);
    
    if(cmIpToAscii(temp, &ipAddr) != NQ_ERR_OK) {
        return hostName;
    }    
    return temp;
}


/**
 * @brief 共有フォルダ情報取得
 */
- (void)getFolder:(INQComputer*)aComInfo
{
    @autoreleasepool {
        
//      INQAppDelegate *app = (INQAppDelegate*)[[UIApplication sharedApplication] delegate];
        
        [self.data removeAllObjects];
        
//      static char buffer[16000];
//      NQ_TCHAR b[16000];
        unsigned int num;    
        char *name;    
        const char *uid;
        const char *p;
        const char *work;
        
        name = (char *)[aComInfo.computerNameIP UTF8String];
        uid = [aComInfo.userName UTF8String];
        p = [aComInfo.password UTF8String];
        work = [aComInfo.workGroup UTF8String];
        
        DLog(@"IP:%s",name);
        NQ_TCHAR uHost[256];
        NQ_TCHAR uBuffer[16000];
        NQ_TCHAR *s;
        
        cmAnsiToTchar(uHost, name);
        DLog(@"%@/%@/%@/%@",aComInfo.computerNameIP,aComInfo.userName,aComInfo.password,aComInfo.workGroup);
        
        udSetCredentials(uid,p,work); 
        
        if (!nqGetSharesOnHost(uHost, uBuffer, CM_ARRAY_SIZE(uBuffer), (int *)&num))
        {
            dispatch_async( dispatch_get_main_queue(), ^{
                
                // [self showAuthorAlert:NSLocalizedString(@"Authorization",@"Authorization title") message:nil];
                int status = (NQ_UINT32)syGetLastSmbError();
                NSString *msg = [NSString stringWithFormat:@"%@ code:0x%x",NSLocalizedString(@"GetShareOnHostError", @"Get shares on host error."),status];

                DLog(@"Unable to retrieve shares for %s error code:0x%x", name, status );
                
                if (status == NQ_ERR_LOGONFAILURE)
                {
                    msg = [NSString stringWithFormat:@"%@ code:0x%x",NSLocalizedString(@"LOGONFAILURE", @"LOGONFAILURE."),status];
                }
                
                /**
                 * エラー表示をアラートビューにて実行
                 */
                
#if 1
                UIAlertView *alertView = [[UIAlertView alloc] initWithTitle:NSLocalizedString(@"ErrMsgConnectFaild", @"error message")
                                                                    message:nil
                                                                   delegate:nil
                                                          cancelButtonTitle:NSLocalizedString(@"AlertClose", @"alert close")
                                                          otherButtonTitles:nil, nil];
#else
                UIAlertView *alertView = [[UIAlertView alloc] initWithTitle:@""
                                                                    message:msg
                                                                   delegate:nil
                                                          cancelButtonTitle:@"Close"
                                                          otherButtonTitles:nil, nil];
#endif
                // アラートビューをタイマーにて自動的に消す対応
                [NSTimer scheduledTimerWithTimeInterval:3.0f
                                                 target:self
                                               selector:@selector(performDissmiss:)
                                               userInfo:alertView
                                                repeats:NO];
                [alertView show];
                [alertView release];

#if 1
#if 1
                // loadedDataSourceCallBack関数の引数追加に伴う変更(optionは不使用)
                [delegate loadedDataSourceCallBack:self.data info:nil option:-1];
#else
                [delegate loadedDataSourceCallBack:self.data info:nil];
#endif
#else
                [delegate loadedDataSourceCallBack:self.data info:msg];
#endif
            });
            
            //[app.inqStatusWindow endLoading];
            return;            
        }
        
#if 1
        INQAppDelegate *app = (INQAppDelegate *)[[UIApplication sharedApplication] delegate];
        if(app.isUpdateComputerInfo == TRUE)
        {
            // 共有フォルダへのアクセスに成功につき、共有先情報を保存する処理を追加
            [self saveSharedComputerInfo:aComInfo];
        }
#endif
        
        if (num == 0)
        {
            //[app.inqStatusWindow endLoading];
#if 1
            // loadedDataSourceCallBack関数の引数追加に伴う変更(optionは不使用)
            [delegate loadedDataSourceCallBack:self.data info:NSLocalizedString(@"NoData", @"NoData") option:-1];
#else
            [delegate loadedDataSourceCallBack:self.data info:NSLocalizedString(@"NoData", @"NoData")];
#endif
            return;
        }
        
        int i;
        
        INQShareFolder *firstFolder = [[INQShareFolder alloc]init];
        
        firstFolder.folderName = [NSString stringWithFormat:@"%S",(const unichar *)uBuffer];
        
        firstFolder.userName = aComInfo.userName;
        firstFolder.password = aComInfo.password;
        //NSString *mp = [NSString stringWithFormat:@"%u%u", [self.computer hash],[firstFolder.folderName hash]];
        NSString *mp = [NSString stringWithFormat:@"%@%u",self.computer , syRand() % 100];
        firstFolder.mountPoint = mp;    
        NSRange range = [firstFolder.folderName rangeOfString:@"$"];
        if (range.length <= 0) {
            [self.data addObject:firstFolder];
        }
        
        [firstFolder release];
        
        for (i = 1, s = uBuffer; i < num; i++) {
            s += cmTStrlen(s) + 1;
            
            
#warning change this.
            char toChar[16000];
            //        NSString *folderName = [NSString stringWithFormat:@"%S",s];
            cmTcharToAnsi(toChar, s);
            NSString *folderName = [NSString stringWithUTF8String:toChar];
            if (folderName == nil) {
                folderName = [NSString stringWithFormat:@"%S",(const unichar *)s];
            }
            
            DLog(@"SHARED FOLDER:%@",folderName);
            
            if (folderName == nil) {
                continue;
            }
            
            NSRange range = [folderName rangeOfString:@"$"];
            
            if (range.length > 0) {
                continue;
            }
            
            INQShareFolder *folder = [[INQShareFolder alloc]init];
            folder.folderName = folderName;
            folder.userName = aComInfo.userName;
            folder.password = aComInfo.password;
            mp = [NSString stringWithFormat:@"%@_%u", folderName , syRand() % 100];
            folder.mountPoint = mp;
            
            [self.data addObject:folder];
            [folder release];
        }
        
        dispatch_async(dispatch_get_main_queue(), ^{
#if 1
            // loadedDataSourceCallBack関数の引数追加に伴う変更(optionは不使用)
            [delegate loadedDataSourceCallBack:self.data info:nil option:-1];
#else
            [delegate loadedDataSourceCallBack:self.data info:nil];
#endif
            //[app.inqStatusWindow endLoading];
        });
    }
    
}

/**
 * @brief アラート表示のタイムアップによる非表示処理
 */
-(void) performDissmiss:(NSTimer *)timer
{
    UIAlertView *alertView = [timer userInfo];
    [alertView dismissWithClickedButtonIndex:0 animated:YES];
}

- (BOOL)mountFolder:(INQShareFolder*)folder error:(NSError**)error {
    
    int res = 0;
    char remotePath[256]; 
//  char mountPoint[256];
    NQ_TCHAR uMountPoint[256];
    NQ_TCHAR uRemotePath[256];
//  const char *folderName;

#ifdef UD_CM_UNICODEAPPLICATION /* mizuguchi UTF-8 <-> UTF-16 */
    cmWStrcpy(uRemotePath, (NQ_TCHAR *)[[NSString stringWithFormat:@"\\\\%@\\%@",self.computer,folder.folderName]
                                        cStringUsingEncoding:NSUTF16StringEncoding]);
    cmWStrcpy(uMountPoint, (NQ_TCHAR *)[[NSString stringWithFormat:@"\\%@",folder.mountPoint]
                                        cStringUsingEncoding:NSUTF16StringEncoding]);
    DLog(@"MountPoint(UTF-16):%S", (const NQ_TCHAR *)uMountPoint);
    DLog(@"RemotePath(UTF-16):%S", (const NQ_TCHAR *)uRemotePath);
#else
    folderName = [folder.folderName cStringUsingEncoding:NSUnicodeStringEncoding];
    DLog(@"Mount folder Name %S",folderName);
    
    NSString *f = [NSString stringWithFormat:@"\\\\%@\\%S",self.computer,folderName];
    
    strcpy(remotePath, "\\\\");
    strcat(remotePath,[self.computer cStringUsingEncoding:NSUTF8StringEncoding]);
    strcat(remotePath,"\\");
    
    strcat(remotePath,folderName);
    DLog(@"remote path:%S",remotePath);
    strcpy(mountPoint, "\\");
    strcat(mountPoint,[folder.mountPoint cStringUsingEncoding:NSUTF8StringEncoding]);
    
    cmAnsiToTchar(uRemotePath,[f cStringUsingEncoding:NSUTF8StringEncoding]);
    cmAnsiToTchar(uMountPoint,mountPoint);
#endif
    
    nqRemoveMount(uMountPoint);
    
    res = nqAddMount(uMountPoint,uRemotePath, TRUE);        
    
    if (res != 0) {
        nqRemoveMount(uMountPoint);
        
        printf("\nUnable to mount '%S', error code: %d\n", (wchar_t *)uRemotePath, res);

        NSMutableDictionary *errorDetail = [NSMutableDictionary dictionary];
        [errorDetail setValue:@"Unable to mount" forKey:@"MSG"];
        [errorDetail setValue:[NSString stringWithFormat:@"%s",remotePath] forKey:@"REMOTE_PATH"];
        
#if 1   // Analyze対応 [Potential null dereference. Accordning to coding standards in ‘Creating and Returning NSError Objects’ the parameter maybe null]
        if(error)
        {
#endif
            *error = [NSError errorWithDomain:@"INQ" code:-1 userInfo:errorDetail];
#if 1
        }
#endif

        return NO;
    }
    return YES;
}

/**
 * @brief 共有先情報の保存
 */
- (void)saveSharedComputerInfo:(INQComputer*)aComInfo
{
    NSString *displayName = aComInfo.displayName;
    NSString *computer = aComInfo.computerNameIP;
    NSString *workGroup = aComInfo.workGroup;
    NSString *userName = aComInfo.userName;
    NSString *password = aComInfo.password;
    
    DLog(@" display name:%@",displayName);

    NSMutableDictionary *dic = [[[NSMutableDictionary alloc]init]autorelease];

    [dic setValue:aComInfo.computerId forKey:COMPUTER_ID];
    [dic setValue:displayName forKey:DISPLAY_NAME];
    [dic setValue:userName == nil?@"guest":userName forKey:USER_NAME];
    [dic setValue:password == nil?@"guset":password forKey:PASSWORD];
    [dic setValue:computer forKey:COMPUTER];
    [dic setValue:workGroup forKey:WORKGROUP];
    
    INQComputerDataSource *dataSource = [[INQComputerDataSource alloc]init];
    [dataSource saveData:dic forKey:aComInfo.computerId];
    [dataSource release];
}

#pragma mark  Table view data source delegate.

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    return 1;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    return [self.data count];
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    static NSString *CellIdentifier = @"Cell";
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:CellIdentifier];
    
    if (cell == nil) {
        cell = [[[UITableViewCell alloc]initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:CellIdentifier]autorelease];
        [cell setAccessoryType:UITableViewCellAccessoryDisclosureIndicator];
    }
    
    cell.detailTextLabel.textColor = [UIColor blackColor];
    [cell setAccessoryType:UITableViewCellAccessoryDisclosureIndicator];  
    
    INQShareFolder *folderObj = (INQShareFolder*)[self.data objectAtIndex:indexPath.row];
    
    NSString *folder = folderObj.folderName;
    
    NSError *error = nil;
    
    if (!folderObj.isMounted) {
        ;        
        
        if (![self mountFolder:folderObj error:&error]) {
            cell.detailTextLabel.text = NSLocalizedString(@"UnableToMount", @"Unable To Mount");
            cell.detailTextLabel.textColor = [UIColor redColor];
            [cell setAccessoryType:UITableViewCellAccessoryNone];
        } else {
            cell.detailTextLabel.text = NSLocalizedString(@"Mounted", @"Mounted");    
            folderObj.mounted = YES;
            [self.data replaceObjectAtIndex:indexPath.row withObject:folderObj];
        }        
    }
    
    [cell.textLabel setText:folder];
#if 1
    // アイコン変更
    INQAppDelegate *app = (INQAppDelegate *)[[UIApplication sharedApplication] delegate];
    UIImage *imgResize = [app resizeImage:@"icon_sharefolder.png" image_size:30];
    [cell.imageView setImage:imgResize];
#else
    [cell.imageView setImage:[UIImage imageNamed:@"share_icon&24.png"]];
#endif
    return cell;
}

+ (void)sharedFolderRemoveById:(NSString*)folderId {
    NSDictionary *savedData = [[NSUserDefaults standardUserDefaults]objectForKey:SHARE_FOLDERS];
    NSMutableDictionary *dic = [NSMutableDictionary dictionaryWithDictionary:savedData];
    [dic removeObjectForKey:folderId];
    [[NSUserDefaults standardUserDefaults] setObject:dic forKey:SHARE_FOLDERS];
    [[NSUserDefaults standardUserDefaults] synchronize];
}


+ (id)getSharedFolderById:(NSString*)folderId {
    NSMutableDictionary *savedData = [[NSUserDefaults standardUserDefaults]objectForKey:SHARE_FOLDERS];
    
    
    NSMutableDictionary *dic = (NSMutableDictionary*)[savedData objectForKey:folderId]; 
    
    if (dic) {
        INQShareFolder *folder = [[INQShareFolder alloc]init];
        folder.folderId = folderId;
        folder.folderName = [dic objectForKey:FOLDER_NAME];
        folder.path = [dic objectForKey:FOLDER_PATH];
        folder.userName = [dic objectForKey:USER_NAME];
        folder.password = [dic objectForKey:PASSWORD];
        folder.guest = [[dic objectForKey:GUEST] isEqual:@"YES"]?YES:NO;
        folder.share = [[dic objectForKey:SHARE] isEqual:@"YES"]?YES:NO;
        return [folder autorelease];
    }
    
    return nil;
}


+ (void)saveData:(INQShareFolder*)folderObj {
    
    NSMutableDictionary *org = (NSMutableDictionary*)[[NSUserDefaults standardUserDefaults] objectForKey:SHARE_FOLDERS];
    
    if (org == nil) {
        org = [[[NSMutableDictionary alloc]init]autorelease];
    }
    
    NSMutableDictionary *orgdic = [NSMutableDictionary dictionaryWithDictionary:org];
    
    if (!folderObj.isShare) {
        [orgdic removeObjectForKey:folderObj.folderId];
        [[NSUserDefaults standardUserDefaults] setObject:orgdic forKey:SHARE_FOLDERS];
        [[NSUserDefaults standardUserDefaults] synchronize];
        
        if ([[INQServiceManager sharedManager] isServerStated]) {
#if 1
            // サーバー機能時の文字化け対策
            NQ_TCHAR uFolderName[256] = {0};
            cmWStrcpy(uFolderName, (NQ_TCHAR *)[[NSString stringWithFormat:@"%@",folderObj.folderName]
                                                cStringUsingEncoding:NSUTF16StringEncoding]);

            // (注意) 以下の関数を使用することで期待動作をするが、ヘッダーファイルに定義の無い関数につき対応を要確認.(関数名に文字"q"が付与されている)
            csCtrlRemoveShareW(uFolderName);
#else
            csCtrlRemoveShareA([folderObj.folderName UTF8String]);
#endif
        }
        
        return;
    }    
    
    NSMutableDictionary *folderDetail = [NSMutableDictionary dictionaryWithDictionary:[orgdic objectForKey:folderObj.folderId]];
    
    if (folderDetail == nil)
    {
#if 1   // Analyze対応 [Potential leak of an object stored into 'folderDetail']
        folderDetail = [[[NSMutableDictionary alloc]init]autorelease];
#else
        folderDetail = [[NSMutableDictionary alloc]init];
#endif
    }
    
    [folderDetail setObject:folderObj.userName forKey:USER_NAME];
    [folderDetail setObject:folderObj.password forKey:PASSWORD];
    [folderDetail setObject:[NSNumber numberWithBool:folderObj.guest] forKey:GUEST];
    [folderDetail setObject:@"YES" forKey:SHARE];
    [folderDetail setObject:folderObj.folderName forKey:FOLDER_NAME];
    [folderDetail setObject:folderObj.path forKey:FOLDER_PATH];    
    [orgdic setValue:folderDetail forKey:folderObj.folderId];
    
    [[NSUserDefaults standardUserDefaults] setObject:orgdic forKey:SHARE_FOLDERS];
    [[NSUserDefaults standardUserDefaults] synchronize];
    
    if ([[INQServiceManager sharedManager] isServerStated]) {
        
        /*
         const NQ_CHAR* name,  
         const NQ_CHAR* fullName, 
         const NQ_CHAR* description,
         const NQ_CHAR* password,    
         NQ_BOOL isAdmin    
         */
        
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
#ifdef UD_CS_INCLUDELOCALUSERMANAGEMENT     
            csCtrlRemoveUserA("guest");
            csCtrlAddUserA([folderObj.userName UTF8String], [folderObj.userName UTF8String], [folderObj.userName UTF8String], [folderObj.password UTF8String], FALSE);
#endif  

#if 1
            // サーバー機能時の文字化け対策
            NQ_TCHAR uFolderName[256] = {0};
            NQ_TCHAR uFolderID[256] = {0};
            
            cmWStrcpy(uFolderName, (NQ_TCHAR *)[[NSString stringWithFormat:@"%@",folderObj.folderName]
                                                cStringUsingEncoding:NSUTF16StringEncoding]);
            cmAnsiToUnicode(uFolderID, [folderObj.folderId UTF8String]);
            
            // (注意) 以下の関数を使用することで期待動作をするが、ヘッダーファイルに定義の無い関数につき対応を要確認.(関数名に文字"q"が付与されている)
            csCtrlAddShareW(uFolderName,uFolderID,false,uFolderName);

            DLog(@"share folder name:%@",folderObj.folderName);

#else
            csCtrlAddShareA([folderObj.folderName UTF8String],[folderObj.folderId UTF8String],false,"share document folder");
#endif
            
        });        
    }
}


#pragma mark -
#pragma mark UIAlertView delegate method.

- (void)alertView:(UIAlertView *)alertView clickedButtonAtIndex:(NSInteger)buttonIndex {
	
    [userIdTextField resignFirstResponder];
    
	if (buttonIndex == 1) {
        NSString *userId = [userIdTextField.text stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
        NSString *password = [passwordTextField.text stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
        
        if (userId == nil || [userId length] == 0) {
            return;
        }
        if (password == nil || [password length] == 0) {
            return;
        } 
        NSAssert(comInfo,@"Compute info is null.");
        comInfo.userName = userId;
        comInfo.password = password;
        [self performSelectorInBackground:@selector(getFolder:) withObject:comInfo];        
	}
}

- (void)showAuthorAlert:(NSString*)title message:(NSString*)message {
    
    UIAlertView *prompt = [[UIAlertView alloc] 
                           initWithTitle:title               
                           message:message            
                           delegate:nil              
                           cancelButtonTitle:NSLocalizedString(@"Cancel",@"Cancel button")              
                           otherButtonTitles:NSLocalizedString(@"OK",@"OK Button"), nil];
    
    userIdTextField = [[UITextField alloc] initWithFrame:CGRectMake(12.0, 50.0, 260.0, 25.0)];  
    [userIdTextField setBackgroundColor:[UIColor whiteColor]]; 
    [userIdTextField setPlaceholder:@"username"]; 
    [prompt addSubview:userIdTextField];
    
    passwordTextField = [[UITextField alloc] initWithFrame:CGRectMake(12.0, 85.0, 260.0, 25.0)];  
    [passwordTextField setBackgroundColor:[UIColor whiteColor]]; 
    [passwordTextField setPlaceholder:@"password"]; 
    [passwordTextField setSecureTextEntry:YES]; 
    [prompt addSubview:passwordTextField];
    
    [prompt setTransform:CGAffineTransformMakeTranslation(0.0, 110.0)];
    [prompt show];
    [prompt release];
    
}

@end
