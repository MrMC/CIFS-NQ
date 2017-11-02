//
//  INQDomain.h
//  iNQ
//
//  Created by Tanya Golberg on 3/26/14.
//  Copyright (c) 2014 ryuu@hotit.co.jp. All rights reserved.
//

#import <Foundation/Foundation.h>

#define DOMAIN_NAME @"DOMAINNAME"

@interface INQDomain : NSObject{
    NSString    *domainName;
}
@property (nonatomic,retain) NSString *domainName;
@end



/*
#define COMPUTER_ID @"COMPUTERID"
#define COMPUTERS @"COMPUTERS"
#define DISPLAY_NAME @"DICPLAYNAME"
#define COMPUTER @"COMPUTER"
#define WORKGROUP @"WORKGROUP"
#define USER_NAME @"USER_NAME"
#define PASSWORD @"PASSWORD"



@interface INQComputer : NSObject {
    NSString *computerId;
    NSString *computerNameIP;
    NSString *domainSuffix;
    NSString *workGroup;
    NSString *displayName;
    NSString *userName;
    NSString *password;
}

@property (nonatomic,retain) NSString *computerId;
@property (nonatomic,retain) NSString *computerNameIP;
@property (nonatomic,retain) NSString *displayName;
@property (nonatomic,retain) NSString *workGroup;
@property (nonatomic,retain) NSString *domainSuffix;
@property (nonatomic,retain) NSString *userName;
@property (nonatomic,retain) NSString *password;

@end
 */
