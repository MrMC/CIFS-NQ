
#import <Foundation/Foundation.h>

#define BOOKMARK @"BOOKMARK"
#define BOOKMARK_ID @"BOOKMARKID"
#define BOOKMARK_NAME @"BOOKMARKNAME"
#define BOOKMARK_COMPUTER @"BOOKMARKCOMPUTER"
#define BOOKMARK_FULLPATH @"BOOKMARKFULLPATH"

@interface INQBookMark : NSObject {
    NSString *bookMarkId;
    NSString *bookMarkName;
    NSString *computer;
    NSString *fullPath;
}

@property (nonatomic,retain) NSString *bookMarkId;
@property (nonatomic,retain) NSString *bookMarkName;
@property (nonatomic,retain) NSString *computer;
@property (nonatomic,retain) NSString *fullPath;
@end
