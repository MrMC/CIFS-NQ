
#import "NSString+CString.h"

@implementation NSString(CString)

- (const char*)getMultiByteString {
    return [self cStringUsingEncoding:NSUTF8StringEncoding];
}

- (wchar_t*)getWideString {
    NSLog(@"self :%@",self);
    const char* temp = [self cStringUsingEncoding:NSUTF8StringEncoding];
    int buflen = strlen(temp) + 1; //including NULL terminating char
    NSLog(@"BUffer len:%d",buflen);
    wchar_t* buffer = malloc(buflen * sizeof(wchar_t));
    mbstowcs(buffer, temp, buflen);
    return buffer;
}

- (char*)wideToAscill {
    wchar_t* wstr = [self getWideString];
    char* ascii[512];
    wcstombs( ascii, wstr, 512);
    return ascii;
}

+ (NSString*)stringWithWideString:(const wchar_t*)ws {
    // Destination char array must allocate more than just wcslen(ws)
    // since unicode chars may consume more than 1 byte
    // we do not yet know how many bytes the created array may consume, so assume the max.
    int bufflen = 8 * wcslen(ws) + 1;
    char* temp = malloc(bufflen);
    wcstombs(temp, ws, bufflen);
    NSString* retVal = [self stringWithUTF8String:temp];
    free(temp);
    return retVal;
}
@end
