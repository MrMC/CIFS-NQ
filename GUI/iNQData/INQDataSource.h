@protocol INQDataSource <UITableViewDataSource>
- (void)loadData;
@end

@protocol INQDataSourceCallBack <NSObject>
#if 1
- (void)loadedDataSourceCallBack:(NSArray*)data info:(NSString*)info option:(NSInteger)type;
#else
- (void)loadedDataSourceCallBack:(NSArray*)data info:(NSString*)info;
#endif
- (void)needDisplay;
@end
