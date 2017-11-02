
#import <UIKit/UIKit.h>
#import "INQDataSource.h"
#import "INQBookMark.h"

@interface INQBookMarkDataSource : NSObject<INQDataSource> {
    NSMutableArray *data_;
    id <INQDataSourceCallBack>delegate_;    
}

@property (nonatomic,retain) NSMutableArray *data;
@property (nonatomic,retain) id <INQDataSourceCallBack>delegate;

- (void)save;
+ (NSString*)getKey;
+ (void)saveBookMark:(INQBookMark*)bookMark;

@end
