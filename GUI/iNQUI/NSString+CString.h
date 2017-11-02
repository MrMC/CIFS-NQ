
#import <Foundation/Foundation.h>
#include <wchar.h>

@interface NSString(CString)

- (wchar_t*)getWideString;
+ (NSString*)stringWithWideString:(const wchar_t*)ws;
- (char*)wideToAscill;
@end
