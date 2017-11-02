
#import <Foundation/Foundation.h>

@interface INQFile : NSObject {
    NSString *fileName;
    NSString *fullPath;
    NSString *relativePath;
    NSDate *createDateTime;
    NSDate *updateTime;
    BOOL dir;
    BOOL hidden;
    long fileSize;
    NSInteger subFolderFileCount;
    NSString *fileExt;
    long lastWriteTimeHigh;
}

typedef enum{
    INQImageFile,
    INQDocFile,
    INQPDFFile,
} INQFileType;

@property (nonatomic,retain) NSString *fileExt;
@property (nonatomic,retain) NSString *fileName;
@property (nonatomic,retain) NSString *fullPath;
@property (nonatomic,retain) NSDate *createDateTime;
@property (nonatomic,retain) NSDate *updateTime;
@property (nonatomic,getter = isDir) BOOL dir;
@property (nonatomic,getter = isHidden) BOOL hidden;
@property (nonatomic) long fileSize;
@property (nonatomic) NSInteger subFolderFileCount;
@property (nonatomic) long lastWriteTimeHigh;
@property (nonatomic,retain) NSString *relativePath;


@end
