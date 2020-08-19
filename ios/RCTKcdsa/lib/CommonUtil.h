//
//  CommonUtil.h
//
//
//  TaeHeun Lee (nixstory@gmail.com)

#import <Foundation/Foundation.h>

@interface CommonUtil : NSObject
+ (NSString *) toHex: (NSData *)nsdata;
+ (NSString *) randomKey: (NSInteger)length;
@end
