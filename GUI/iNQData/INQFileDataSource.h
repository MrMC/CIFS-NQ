
#import "ccapi.h"

#import <Foundation/Foundation.h>
#import "INQDataSource.h"
#import "INQFile.h"
#import "INQ.h"
#import "INQBookMark.h"
#import "INQRemoteFileManager.h"
#import <ImageIO/ImageIO.h>

@interface INQFileDataSource :NSObject<INQDataSource> {
    NSMutableArray *data_;
    id <INQDataSourceCallBack>delegate;
     NSMutableDictionary *supportFiles_;  
    
    // select mode
    NSString *server;
    NSMutableDictionary *selectedRow_;
}
@property (nonatomic,retain) NSMutableDictionary *supportFiles;  
@property (nonatomic,retain) NSMutableArray *data;
@property (nonatomic,retain) id <INQDataSourceCallBack>delegate;
@property (nonatomic,retain) NSMutableDictionary *selectedRow;

- (NSArray*)mountFrom:(NSString *)computer remotePath:(NSString *)rp;

- (void)loadDataFromServer:(NSString*)server path:(NSString*)path;
- (void)loadDataFromLocalPath:(NSString*)path;
- (void)copyFile:(INQFile*)file;
@end
