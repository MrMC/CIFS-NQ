
#import <Foundation/Foundation.h>
#import "INQDataSource.h"
#import "INQ.h"
#import "INQComputer.h"
#import "INQBookMark.h"
#import "INQDomain.h"

@interface INQComputerDataSource : NSObject<INQDataSource> {
    NSMutableArray *data_;
    NSMutableArray *dataTmp_;
    NSMutableArray *dataDomain_;
    id <INQDataSourceCallBack>delegate;
    BOOL isBookMark;
}

@property (nonatomic,retain) NSMutableArray *data;
@property (nonatomic,retain) NSMutableArray *dataTmp;
@property (nonatomic,retain) NSMutableArray *dataDomain;
@property (nonatomic,retain) id <INQDataSourceCallBack>delegate;

- (void)saveData:(NSDictionary*)data forKey:(NSString*)computer;
- (void)getComputers:(NSString*)workgroup;
- (void)getWorkgroups;
- (void)loadData:(BOOL)isBookMark;

@end
