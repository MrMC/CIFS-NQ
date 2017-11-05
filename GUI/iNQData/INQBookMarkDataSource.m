
#import "INQBookMarkDataSource.h"

@implementation INQBookMarkDataSource
@synthesize data = data_;
@synthesize delegate = delegate_;

- (id)init {
    self = [super init];
    if (self) {
        data_ = [[NSMutableArray alloc]init];   
    }
    return self;
}

- (void)dealloc {
    [data_ release]; 
    data_ = nil;
    delegate_ = nil;
    self.delegate = nil;
    [super dealloc];    
}

- (void)loadData {

    [self.data removeAllObjects];
    NSMutableDictionary *savedData = [[NSUserDefaults standardUserDefaults]objectForKey:BOOKMARK];
    NSEnumerator *enm = [savedData keyEnumerator];
    
    while (YES) {
        NSString *key = [enm nextObject];
        
        if (key == nil) {
            break;
        }
        INQBookMark *bookMark = [[INQBookMark alloc]init];
        NSDictionary *dic = [savedData objectForKey:key]; 
        bookMark.bookMarkId = key;
        bookMark.bookMarkName = [dic objectForKey:BOOKMARK_NAME];
        bookMark.computer = [dic objectForKey:BOOKMARK_COMPUTER];
        bookMark.fullPath = [dic objectForKey:BOOKMARK_FULLPATH];

        [self.data addObject:bookMark];
        [bookMark release];
        
    }

#if 1
    // loadedDataSourceCallBack関数の引数追加に伴う変更(optionは不使用)
    [self.delegate loadedDataSourceCallBack:self.data info:nil option:-1];
#else
    [self.delegate loadedDataSourceCallBack:self.data info:nil];
#endif
}

- (void)save {
    NSMutableDictionary *dic = [[NSMutableDictionary alloc]init];
    
    for (int i = 0; i < [self.data count]; i++) {
        INQBookMark *bookMark = [self.data objectAtIndex:i];
        NSMutableDictionary *bookMarkDic = [[NSMutableDictionary alloc]init];
        [bookMarkDic setObject:bookMark.bookMarkId forKey:BOOKMARK_ID];
        [bookMarkDic setObject:bookMark.bookMarkName forKey:BOOKMARK_NAME];
        [bookMarkDic setObject:bookMark.computer forKey:BOOKMARK_COMPUTER];
        [bookMarkDic setObject:bookMark.fullPath forKey:BOOKMARK_FULLPATH];
        
        [dic setObject:bookMarkDic forKey:bookMark.bookMarkId];
        [bookMarkDic release];
    }
    
    [[NSUserDefaults standardUserDefaults] setObject:dic forKey:BOOKMARK];
    [[NSUserDefaults standardUserDefaults] synchronize];    
    [dic release];
}

+ (void)saveBookMark:(INQBookMark*)bookMark {
    NSMutableDictionary *org = [[NSUserDefaults standardUserDefaults] objectForKey:BOOKMARK];
    
    if (org == nil) {
        org = [[[NSMutableDictionary alloc]init]autorelease];
    }
    
    NSMutableDictionary *orgdic = [NSMutableDictionary dictionaryWithDictionary:org];
    NSMutableDictionary *bookMarkDic = [[NSMutableDictionary alloc]init];
    [bookMarkDic setValue:bookMark.bookMarkId forKey:BOOKMARK_ID];
    [bookMarkDic setValue:bookMark.bookMarkName forKey:BOOKMARK_NAME];
    [bookMarkDic setValue:bookMark.computer forKey:BOOKMARK_COMPUTER];
    [bookMarkDic setValue:bookMark.fullPath forKey:BOOKMARK_FULLPATH];
    
    [orgdic setValue:bookMarkDic forKey:bookMark.bookMarkId];
    
    [[NSUserDefaults standardUserDefaults] setObject:orgdic forKey:BOOKMARK];
    [[NSUserDefaults standardUserDefaults] synchronize];   
    [bookMarkDic release];
}

+ (NSString*)getKey {
    NSString *computerId;
    NSInteger key = [[NSUserDefaults standardUserDefaults] integerForKey:@"KEY"];
    key++;
    
  computerId = [NSString stringWithFormat:@"%ld",(long)key];
    [[NSUserDefaults standardUserDefaults] setInteger:key forKey:@"KEY"];
    [[NSUserDefaults standardUserDefaults] synchronize];
    return computerId;
    
}


#pragma mark - UITableViewDataSource delegate.

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
        
    return [self.data count];
}

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    return 1;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:@"MyCell"];
    
    if (!cell) {
        cell = [[[UITableViewCell alloc]initWithStyle:UITableViewCellStyleDefault reuseIdentifier:@"MyCell"]autorelease];
        //     cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
        // cell.selectionStyle = UITableViewCellSelectionStyleNone;
        cell.imageView.contentMode = UIViewContentModeScaleAspectFill;
        cell.textLabel.font = [UIFont systemFontOfSize:15.0];
        //cell.selectionStyle = UITableViewCellSelectionStyleBlue;
        
    }
    
  //  [cell setAccessoryType:UITableViewCellAccessoryDetailDisclosureButton];    
    
    if ([self.data count] > 0) {
            
        INQBookMark *bookMakr = [self.data objectAtIndex:indexPath.row];        
        [[cell textLabel]setText:[NSString stringWithFormat:@" < %@ > %@", bookMakr.bookMarkName,bookMakr.computer]]; 
        [cell.imageView setImage:[UIImage imageNamed:@"monitor_icon&24.png"]];
        
    }

    return cell;
}


- (void)tableView:(UITableView *)tableView commitEditingStyle:(UITableViewCellEditingStyle)editingStyle forRowAtIndexPath:(NSIndexPath *)indexPath {
    
    if (editingStyle == UITableViewCellEditingStyleDelete) {
        [self.data removeObjectAtIndex:indexPath.row]; 
        [self save];
        [tableView reloadData];
         
    }
}

- (BOOL)tableView:(UITableView *)tableView canEditRowAtIndexPath:(NSIndexPath *)indexPath {
    return YES;
}


- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section {
    return NSLocalizedString(@"BookMark",@"BookMark");        

}

-(NSString *)tableView:(UITableView *)tableView titleForFooterInSection:(NSInteger)section {
    return nil;
    
}

@end
