

#import <UIKit/UIKit.h>

@interface INQRemoteFileManager : NSObject {
    
}

+ (BOOL)uploadImage:(UIImage*)image imageType:(NSString*)imageType toRemotePath:(NSString*)remotePath;
+ (BOOL)uploadFileFromLocalPath:(NSString*)localPath toRemotepath:(NSString*)toRemotePath;
+ (BOOL)copyFile:(NSString*)fromPath to:(NSString*)to;
+ (BOOL)deleteFile:(NSString*)fileName;
+ (BOOL)moveFile:(NSString*)fullPath to:(NSString*)to;

//+ (NSString*)getCharCodeUTF16:(NSString*)input;
//+ (NSString*)getCharCodeUTF8:(NSString*)input;
//+ (NSString*)stringToHex:(NSString*)string;
@end
