
#import "INQWorkgroupViewController.h"
#import "INQComputerDataSource.h"
#include "ccapi.h"
#import "nsapi.h"

@implementation INQComputerDataSource
@synthesize data = data_,delegate;
@synthesize dataTmp = dataTmp_;
@synthesize dataDomain = dataDomain_;

- (id)init {
    self = [super init];
    if (self) {
        data_ = [[NSMutableArray alloc]init];
        dataTmp_ = [[NSMutableArray alloc]init];
        dataDomain_ = [[NSMutableArray alloc]init];
        DLog(@"INQComputerDataSource Init ...");
    }
    return self;
}

- (void)dealloc {
    [data_ release]; 
    data_ = nil;

    [dataTmp_ release];
    dataTmp_ = nil;
    
    [dataDomain_ release];
    dataDomain_ = nil;
    
    delegate = nil;
    self.delegate = nil;
    [super dealloc];    
}

- (void)getWorkgroups
{
    static char buffer[16000];
    int num = 0;
    
    if (!nqGetWorkgroupsByWgA( "WORKGROUP", buffer, sizeof(buffer), &num))
    {
        DLog(@"Get Workgroups Failed");
        int status = (NQ_UINT32)syGetLastSmbError();
        
        NSString *msg = [NSString stringWithFormat:@"%@ code:0x%x",NSLocalizedString(@"GetShareOnHostError", @"Get shares on host error."),status];
        [delegate loadedDataSourceCallBack:self.data info:msg option:3];
        
        return;
    }
    
    if (num == 0) {
        DLog(@"No Workgroups Found");
        
        // コールバック関数の引数追加に伴う変更(保存済みデータか検索結果データかの判定)
        [delegate loadedDataSourceCallBack:self.data info:NSLocalizedString(@"NoData", @"NoData") option:1];
        
        return;
    }
    
    [self.dataDomain removeAllObjects];
    
    DLog(" Domains [found = %d] = %s \n" , num ,buffer);
    
    
    int i;
    char* s;
    for (i = 0, s = buffer; i < num; i++)
    {
        NSString *domainName = [NSString stringWithUTF8String:s];
        if (domainName == nil)
        {
            continue;
        }
        INQDomain  *domain= [[INQDomain alloc]init];
        domain.domainName = domainName;

        if (![self savedDomain:domainName])
        {
            [self.dataDomain addObject:domain];
            
        }
        [domain release];
        s += strlen(s) + 1;
    }
    [delegate loadedDataSourceCallBack:self.dataDomain info:nil option:3];
    
    
}
/**
 * @brief ワークグループ内のコンピュータ検索
 */
- (void)getComputers:(NSString*)workgroup
{

    static char buffer[16000];
    unsigned int num;    
//  const char *name;
//  name = [workgroup UTF8String];
   
//  unsigned short dName[256];
//  bool *isWorkgroup;
//  static char domainBuffer[16000];
    static char domain[256];    
//  static NQ_TCHAR domainT[256];
    
    // ワークグループ名を固定で"WORKGROUP"とする処理を可変できる様に変更.
    char *pDomain;
    memset( domain, 0x00, sizeof(domain) );
    pDomain = (char *)[workgroup UTF8String];
    strcpy( domain, pDomain );

    
    DLog(@"WORK Group: %s",domain);

    if (!nqGetHostsInWorkgroupByWgA(domain, buffer, sizeof(buffer), (int *)&num))
    {
        DLog(@"Get workgroup null :%@",workgroup);
        int status = (NQ_UINT32)syGetLastSmbError();
        
        NSString *msg = [NSString stringWithFormat:@"%@ code:0x%x",NSLocalizedString(@"GetShareOnHostError", @"Get shares on host error."),status];

        // コールバック関数の引数追加に伴う変更(保存済みデータか検索結果データかの判定)
        [delegate loadedDataSourceCallBack:self.data info:msg option:1];


        return;
    }
    
    if (num == 0) {     
        DLog(@"Get workgroup num = 0 :%@",workgroup);

        // コールバック関数の引数追加に伴う変更(保存済みデータか検索結果データかの判定)
        [delegate loadedDataSourceCallBack:self.data info:NSLocalizedString(@"NoData", @"NoData") option:1];

        return;
    }

    // 検索結果データを追加の際は全てクリア
    [self.dataTmp removeAllObjects];
    
    DLog(@"HOST : %s",buffer);   
    int i;
    char* s;
    
    INQComputer *computer = [[INQComputer alloc]init];
    computer.computerId = [self computerId];
    computer.computerNameIP = [NSString stringWithUTF8String:[self getIpByHostName:buffer]];
    computer.displayName = [NSString stringWithUTF8String:buffer];
    computer.workGroup = [NSString stringWithFormat:@"%s",domain];
    computer.userName = @"GUEST";
    computer.password = @"";
    
    if (![self savedComputer:computer.computerNameIP])
    {
        // 検索データオブジェクトに追加
        [self.dataTmp addObject:computer];
    }
    
    [computer release];
    
    for (i = 1, s = buffer; i < num; i++) {
        s += strlen(s) + 1;
        
        NSString *computerName = [NSString stringWithUTF8String:s];
        DLog(@"get workgroup = :%@",computerName);
        if (computerName == nil) {
            continue;
        }

        INQComputer *computer = [[INQComputer alloc]init];
        computer.computerId = [self computerId];
        computer.computerNameIP = [NSString stringWithUTF8String:[self getIpByHostName:s]];
        computer.displayName = computerName;
        computer.workGroup = [NSString stringWithUTF8String:domain];
        computer.userName = @"GUEST";
        computer.password = @"";
        
        if (![self savedComputer:computer.computerNameIP])
        {
            // 検索データオブジェクトに追加
            [self.dataTmp addObject:computer];
        }
        
        [computer release];
    }
    [self save];

    // コールバック関数の引数追加に伴う変更(保存済みデータか検索結果データかの判定)
    //[delegate loadedDataSourceCallBack:self.dataTmp info:nil option:1];
    [delegate loadedDataSourceCallBack:self.dataTmp info:nil option:0];

}

- (NSString*)computerId {
    NSString *computerId;
    NSInteger key = [[NSUserDefaults standardUserDefaults] integerForKey:@"KEY"];
    key++;
        
    computerId = [NSString stringWithFormat:@"%d",(int)key];
    [[NSUserDefaults standardUserDefaults] setInteger:key forKey:@"KEY"];
    return computerId;

}


- (char*)getIpByHostName:(char*)hostName
{
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

- (BOOL)savedComputer:(NSString*)computerName {
    for (INQComputer *com in self.data) {
        if ([com.computerNameIP isEqualToString:computerName]) {
            return YES;
        }
    }
    return NO;
}

- (BOOL)savedDomain:(NSString*)domainName
{
    for (INQDomain *dom in self.dataDomain)
    {
        if ([dom.domainName isEqualToString:domainName])
        {
            return YES;
        }
    }
    return NO;
}

- (void)loadData:(BOOL)aIsBookMark {
    isBookMark = aIsBookMark;
    
    // data stracture.
    // computers -> com dictoynary object [key = <com name> ,value = <com detail dictionary>] .
    // dic -->dic
    
    /*
     
     <computers>
        <com>
            <key/>
            <value/>
        </com>
     </computers>
    
     */
    [self.data removeAllObjects];
    NSMutableDictionary *savedData = [[NSUserDefaults standardUserDefaults]objectForKey:COMPUTERS];
    /*if (isBookMark) {
        savedData = [[NSUserDefaults standardUserDefaults]objectForKey:BOOKMARK];
    }*/
    DLog(@"== save data:%@ \n%d",savedData,isBookMark);
    NSEnumerator *enm = [savedData keyEnumerator];
    
    while (YES && enm != nil) {
        NSString *key = [enm nextObject];
        
        if (key == nil) {
            break;
        }
        INQComputer *computer = [[INQComputer alloc]init];
        NSDictionary *dic = [savedData objectForKey:key]; 
        computer.computerId = key;
        computer.computerNameIP = [dic objectForKey:COMPUTER];
        computer.displayName = [dic objectForKey:DISPLAY_NAME];
        computer.workGroup = [dic objectForKey:WORKGROUP];
        computer.userName = [dic objectForKey:USER_NAME];
        computer.password = [dic objectForKey:PASSWORD];
        computer.workGroup = [dic objectForKey:WORKGROUP];
        [self.data addObject:computer];
        [computer release];
        //[self.data addObject:[savedData objectForKey:key]];
        
    }
    DLog(@"count:%lu",(unsigned long)[self.data count]);

    // コールバック関数の引数追加に伴う変更(保存済みデータか検索結果データかの判定)
    [delegate loadedDataSourceCallBack:self.data info:nil option:0];
}


- (void)saveData:(NSDictionary*)dt forKey:(NSString*)computerId {
    NSMutableDictionary *org = [[NSUserDefaults standardUserDefaults] objectForKey:COMPUTERS];
    if (isBookMark) {
        org = [[NSUserDefaults standardUserDefaults] objectForKey:BOOKMARK];        
    }
    if (org == nil) {
        org = [[[NSMutableDictionary alloc]init]autorelease];
    }
    
    NSMutableDictionary *orgdic = [NSMutableDictionary dictionaryWithDictionary:org];
    [orgdic setValue:dt forKey:computerId];
    if (isBookMark) {
        [[NSUserDefaults standardUserDefaults] setObject:orgdic forKey:BOOKMARK];        
    } else {
        [[NSUserDefaults standardUserDefaults] setObject:orgdic forKey:COMPUTERS];        
    }

    [[NSUserDefaults standardUserDefaults] synchronize];
}


#pragma mark - UITableViewDataSource delegate.

/**
 * @brief テーブルのロード時に呼び出されるセクションに含まれるセル数を返す処理
 */
- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section
{
    // セクション数が 1 の場合は検索データ件数+1がセル数
    if([tableView numberOfSections] == 1)
    {
        return ([self.dataTmp count] + 1);
    }

    // ----------- //
    // Section : 0 //
    // ----------- //
    if (section == 0)
    {
        if (tableView.isEditing)
        {
            return [self.data count];
        }
        if (isBookMark)
        {
            return [self.data count];
        }
        // ”新しいコンピュータ追加”のセルを削除(ツールバーに一本化対応)
        return [self.data count];
    }

    // セクション１はcanEditRowAtIndexPathで編集不可にしているので非表示対応は行わない
    if(section == 1)
    {
        // セクション1側にワークグループ検索の結果を挿入し、"検索"のセル分1を追加
        return ([self.dataTmp count] + 1);
    }
    return 1;
}

/**
 * @brief テーブルのロード時に呼び出されるセクション数を返す処理
 */
- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView
{
    NSInteger sectionCount = 0;
    // 保存データの件数が 0 件の場合はセクション数を 1 として扱う
    if([self.data count] == 0)
    {
        sectionCount = 1;
    }
    else
    {
        // セクション数２
        sectionCount = 2;
    }
    //sectionCount = 1;
    return sectionCount;
}

/**
 * @brief テーブルのロード時に呼び出される各セルの内容を返す処理
 */
- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath
{
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:@"MyCell"];
    
    if (!cell)
    {
        cell = [[[UITableViewCell alloc]initWithStyle:UITableViewCellStyleDefault reuseIdentifier:@"MyCell"]autorelease];
        //     cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
       // cell.selectionStyle = UITableViewCellSelectionStyleNone;
        cell.imageView.contentMode = UIViewContentModeScaleAspectFill;
        cell.textLabel.font = [UIFont systemFontOfSize:15.0];
        //cell.selectionStyle = UITableViewCellSelectionStyleBlue;
    }
    
    // セルの記号設定
    if ([[[[UIDevice currentDevice] systemVersion] componentsSeparatedByString:@"."][0] intValue] >= 7)
    {
        // iOS7では従来指定していたDetailDisclosureButtonだとイメージが２つ表示されるので変更
        [cell setAccessoryType:UITableViewCellAccessoryDetailButton];
    }
    else
    {
        [cell setAccessoryType:UITableViewCellAccessoryDetailDisclosureButton];
    }
    
    // セクション数が 1 の場合の処理
    if([tableView numberOfSections] == 1)
    {
        INQAppDelegate *app = (INQAppDelegate *)[[UIApplication sharedApplication] delegate];
        if (indexPath.row == [self.dataTmp count])
        {
            // テーブルのデータ数とインデックスパスの行数が一致する場合
            // セクションが１で且つブックマーク画面以外なら"検索"
            [cell setAccessoryType:UITableViewCellAccessoryNone];
            [cell.textLabel setText:NSLocalizedString(@"Search",@"Search")];
            // 検索アイコンの新規作成及び配置
            [cell.imageView setImage:[app resizeImage:@"icon_workgroupsearch.png" image_size:36]];
        }
        else
        {
            // 登録済みの共有先コンピューター情報
            INQComputer *computer = [self.dataTmp objectAtIndex:indexPath.row];
            [[cell textLabel]setText:[NSString stringWithFormat:@"%@  / %@", computer.displayName,computer.computerNameIP]];

            // アイコン変更
            UIImage *imgResize = [app resizeImage:@"icon_pc_scan.png" image_size:36];
            [cell.imageView setImage:imgResize];

        }
        return cell;
    }
    
    // ----------- //
    // Section : 0 //
    // ----------- //
    if (indexPath.section == 0)
    {

        // ”新しいコンピュータ追加”のセルを削除(ツールバーに一本化対応)
        // 登録済みの共有先コンピューター情報
        INQComputer *computer = [self.data objectAtIndex:indexPath.row];
        [[cell textLabel]setText:[NSString stringWithFormat:@"%@  / %@", computer.displayName,computer.computerNameIP]];
        // アイコン変更
        INQAppDelegate *app = (INQAppDelegate *)[[UIApplication sharedApplication] delegate];
        UIImage *imgResize = [app resizeImage:@"icon_pc_save.png" image_size:36];
        [cell.imageView setImage:imgResize];

    
    }
    
    // ----------- //
    // Section : 1 //
    // ----------- //
    if (indexPath.section == 1 && !isBookMark)
    {
        INQAppDelegate *app = (INQAppDelegate *)[[UIApplication sharedApplication] delegate];
        if (indexPath.row == [self.dataTmp count])
        {
            // テーブルのデータ数とインデックスパスの行数が一致する場合
            // セクションが１で且つブックマーク画面以外なら"検索"
            [cell setAccessoryType:UITableViewCellAccessoryNone];
            [cell.textLabel setText:NSLocalizedString(@"Search",@"Search")];
            // 検索アイコンの新規作成及び配置
            [cell.imageView setImage:[app resizeImage:@"icon_workgroupsearch.png" image_size:36]];
        }
        else
        {
            // 登録済みの共有先コンピューター情報
            INQComputer *computer = [self.dataTmp objectAtIndex:indexPath.row];
            [[cell textLabel]setText:[NSString stringWithFormat:@"%@  / %@", computer.displayName,computer.computerNameIP]];
            // アイコン変更
            UIImage *imgResize = [app resizeImage:@"icon_pc_scan.png" image_size:36];
            [cell.imageView setImage:imgResize];
        }
    }
    return cell;
}

/**
 * @brief テーブルが編集モード時で"Delete"もしくは"Insert"が選択された時に呼び出される処理
 */
- (void)tableView:(UITableView *)tableView commitEditingStyle:(UITableViewCellEditingStyle)editingStyle forRowAtIndexPath:(NSIndexPath *)indexPath
{
    if (editingStyle == UITableViewCellEditingStyleDelete)
    {
        // セルの編集開始
        [tableView beginUpdates];
        
        // 該当セルの削除
        [self.data removeObjectAtIndex:[indexPath row]];
        
        // セクション１側のデータが全て削除された場合はセクションの削除を実行
        if (([self.data count] == 0) && ([tableView numberOfSections] == 2))
        {
            [tableView deleteSections:[NSIndexSet indexSetWithIndex:[indexPath section]] withRowAnimation:YES];
        }
        [tableView deleteRowsAtIndexPaths:@[indexPath] withRowAnimation:UITableViewRowAnimationFade];
        
        // セルの編集終了
        [tableView endUpdates];

        [self save];
        
        // スワイプ操作による削除実行時に行数が複数あった場合に仕切り線が再描画されない症状への対応
        [tableView reloadData];

        // INQWorkgroupViewController側のデータを更新(保存データ)
        [delegate loadedDataSourceCallBack:self.data info:nil option:0];
    }
}

/**
 * @brief テーブルの行の編集を許可/禁止を設定する処理
 * @note 編集 (移動も含む) を許可する行だったら YES を返却
 */
- (BOOL)tableView:(UITableView *)tableView canEditRowAtIndexPath:(NSIndexPath *)indexPath {

    
    // セクション数が 1 の場合は検索データ側の為、編集禁止
    if([tableView numberOfSections] == 1)
    {
        return NO;
    }
    
    if (indexPath.section == 0)
    {
        return YES;
    }
    
    return NO;
}

-(NSString *)tableView:(UITableView *)tableView titleForFooterInSection:(NSInteger)section {
    return nil;
    
}

/**
 * @brief コンピュータデータ保存処理
 */
- (void)save
{
    NSMutableDictionary *dic = [[NSMutableDictionary alloc]init];
    NSInteger dataCount = [self.data count];
    DLog(@"Save Computer Data:%ld",dataCount);

    for (int i = 0; i < dataCount; i++)
    {
        INQComputer *com = [self.data objectAtIndex:i];
        NSMutableDictionary *comDic = [[NSMutableDictionary alloc]init];
        [comDic setObject:com.computerId forKey:COMPUTER_ID];
        [comDic setObject:com.computerNameIP forKey:COMPUTER];
        [comDic setObject:com.displayName forKey:DISPLAY_NAME];
        [comDic setObject:com.workGroup forKey:WORKGROUP];
        [comDic setObject:com.userName forKey:USER_NAME];
        [comDic setObject:com.password forKey:PASSWORD];
        [dic setObject:comDic forKey:com.computerId];
        [comDic release];
    }
    
    /*if (isBookMark)
    {
        [[NSUserDefaults standardUserDefaults] setObject:dic forKey:BOOKMARK];        
    }
    else*/
    {
        [[NSUserDefaults standardUserDefaults] setObject:dic forKey:COMPUTERS];
    }
    [[NSUserDefaults standardUserDefaults] synchronize];    
    [dic release];
}

@end
