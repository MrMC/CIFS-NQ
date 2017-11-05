#include "ccapi.h"
#import "INQ.h"
#import "INQRemoteFileManager.h"
#import "INQFileListViewController.h"

@implementation INQRemoteFileManager

#define BUFFER_SIZE 102400

+ (BOOL)copyFile:(NSString*)fromPath to:(NSString*)to {
    
    NSAssert(fromPath != nil,@"copy file from path is null.");
    NSAssert(to != nil,@"copy file to path is null.");    
    
    NQ_HANDLE file;
    DLog(@"FromPath:%@",fromPath);
    DLog(@"ToPath:%@",to);    
   // strcpy(fullPath,[fromPath UTF8String]);
    NQ_WCHAR uFromPath[255];
#ifdef UD_CM_UNICODEAPPLICATION /* mizuguchi UTF-8 <-> UTF-16 */
    cmWStrcpy(uFromPath, (NQ_WCHAR *)[fromPath cStringUsingEncoding:NSUTF16StringEncoding]);
    DLog(@"FromPath(UTF-16):%S", (const NQ_WCHAR *)uFromPath);
#else
    syAnsiToUnicode(uFromPath,[fromPath UTF8String]);
#endif
    file = ccCreateFile(
                         uFromPath, 
                         FILE_AM_READ, 
                         FILE_SM_COMPAT, 
                         FILE_LCL_UNKNOWN, 
                         FALSE, 
                         0, 
                         FILE_CA_FAIL, 
                         FILE_OA_OPEN);    
    
    
    int docLen;      
    NQ_BYTE *data[BUFFER_SIZE];
    NSMutableData *dt = [[NSMutableData alloc]init];
    docLen = 0;
    while (true) {
        unsigned int resultLen;
        
        if (!ccReadFile(file, (NQ_BYTE *)data, (NQ_UINT)(BUFFER_SIZE), &resultLen) && resultLen == 0) {
            break;
        }
        [dt appendBytes:(const void *)data length:resultLen];
        docLen += (int)resultLen;
        resultLen = 0;
    }
    
    if (file == NULL) {
#if 1
        // Analyze対応 [Potential leak of an object stored into 'dt']
        [dt release];
#endif
        return NO;
    }
    ccCloseHandle(file);          
    
    if(![dt writeToFile:to atomically:YES]) {
        [dt release];
        return NO;
    }
    
    [dt release];
    return YES;
}


+ (BOOL)uploadImage:(UIImage*)image imageType:(NSString*)imageType toRemotePath:(NSString*)toRemotePath {
    
    NSData *data;
    
    if ([imageType isEqualToString:@"PNG"]) {
        data = UIImagePNGRepresentation(image);        
    } else if ([imageType isEqualToString:@"JPG"]) {
        data = UIImageJPEGRepresentation(image,0);
    } else {
        DLog(@"Unknown File Type:%@",imageType);
        return NO;
    }        
    return [INQRemoteFileManager writeFileFromData:data toRemotePath:toRemotePath];
      
}


+ (BOOL)uploadFileFromLocalPath:(NSString*)localPath toRemotepath:(NSString*)toRemotePath {

    NSData *fileData = [NSData dataWithContentsOfFile:localPath];
    return [INQRemoteFileManager writeFileFromData:fileData toRemotePath:toRemotePath];    

}


+ (BOOL)writeFileFromData:(NSData*)fileData toRemotePath:(NSString*)toRemotePath {

    NSAssert(fileData != nil,@"write file data is null.");   
    NSAssert(toRemotePath != nil,@"write file path is null.");  
    
    NSInteger docLen;  
    unsigned char* data;
    
    static char filePath[255];  
    
    strcpy(filePath,[toRemotePath UTF8String]);
    
    data = (unsigned char*)[fileData bytes];
    docLen = [fileData length] / sizeof(unsigned char);

    NQ_HANDLE file;
    NQ_WCHAR uFilePath[255];
#ifdef UD_CM_UNICODEAPPLICATION /* mizuguchi UTF-8 <-> UTF-16 */
    cmWStrcpy(uFilePath, (NQ_WCHAR *)[toRemotePath cStringUsingEncoding:NSUTF16StringEncoding]);
    DLog(@"FilePath(UTF-16):%S", (const NQ_WCHAR *)uFilePath);
#else
    syAnsiToUnicode(uFilePath,[toRemotePath UTF8String]);
#endif
    file = ccCreateFile(
                         uFilePath,
                         FILE_AM_WRITE,
                         FILE_SM_EXCLUSIVE,
                         FILE_LCL_UNKNOWN,
                         FALSE,
                         0,
                         FILE_CA_CREATE,
                         FILE_OA_FAIL
                         );
    if (file == NULL) {
        printf("Unable to create %S\n", (wchar_t *)uFilePath);
        return NO;
    }
    
    while (docLen > 0) {
        unsigned int resultLen;
        
        if (!ccWriteFile(file, data, (NQ_UINT)(docLen), &resultLen)) {
            break;
        }
        
        docLen -= (int)resultLen;
    }
    if (file == NULL) {
        return NO;
    }
    ccCloseHandle(file);   
    
    return YES;

}

+ (BOOL)deleteFile:(NSString*)fullPath {
    NSAssert(fullPath != nil,@"delete file path is null.");    
    NQ_WCHAR uFullPath[255];
#ifdef UD_CM_UNICODEAPPLICATION /* mizuguchi UTF-8 <-> UTF-16 */
    cmWStrcpy(uFullPath, (NQ_WCHAR *)[fullPath cStringUsingEncoding:NSUTF16StringEncoding]);
    DLog(@"FullPath(UTF-16):%S", (const NQ_WCHAR *)uFullPath);
#else
    syAnsiToUnicode(uFullPath,[fullPath UTF8String]);
#endif
    return ccDeleteFile(uFullPath);
}


+ (BOOL)moveFile:(NSString*)fullPath to:(NSString*)to {
    NSAssert(fullPath != nil,@"move file path is null.");  
    NSAssert(to != nil,@"move file toPath is null.");      
    
    NQ_WCHAR uFullPath[255];
    NQ_WCHAR uToPath[255];
#if 1//def UD_CM_UNICODEAPPLICATION /* mizuguchi UTF-8 <-> UTF-16 */
    cmWStrcpy(uToPath, (NQ_WCHAR *)[to cStringUsingEncoding:NSUTF16StringEncoding]);
    DLog(@"ToPath(UTF-16):%S", (const NQ_WCHAR *)uToPath);
    cmWStrcpy(uFullPath, (NQ_WCHAR *)[fullPath cStringUsingEncoding:NSUTF16StringEncoding]);
    DLog(@"FullPath(UTF-16):%S", (const NQ_WCHAR *)uFullPath);
#else
    syAnsiToUnicode(uToPath,[to UTF8String]);
    syAnsiToUnicode(uFullPath,[fullPath UTF8String]);         
#endif
    return ccMoveFile(uFullPath,uToPath);
}


@end
