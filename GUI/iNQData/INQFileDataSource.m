

#import "INQFileDataSource.h"
#import "UIImage+Thumbnail.h"
#import "INQAppDelegate.h"

@implementation INQFileDataSource
@synthesize data = data_ ,delegate;
@synthesize selectedRow = selectedRow_;
@synthesize supportFiles = supportFiles_;
- (id)init {
    self = [super init];
    if (self) {
        selectedRow_ = [[NSMutableDictionary alloc]init];
        data_ = [[NSMutableArray alloc]init];
        
        supportFiles_ = [[NSMutableDictionary alloc]init];
        [self.supportFiles setObject:[NSNumber numberWithBool:YES] forKey:@"JPG"];
#if 1
        // jpgの拡張子(jpeg,jpe)を追加
        [self.supportFiles setObject:[NSNumber numberWithBool:YES] forKey:@"JPEG"];
        [self.supportFiles setObject:[NSNumber numberWithBool:YES] forKey:@"JPE"];
#endif
        [self.supportFiles setObject:[NSNumber numberWithBool:YES] forKey:@"PNG"];
        [self.supportFiles setObject:[NSNumber numberWithBool:YES] forKey:@"PDF"];
        [self.supportFiles setObject:[NSNumber numberWithBool:YES] forKey:@"DOC"];        
        [self.supportFiles setObject:[NSNumber numberWithBool:YES] forKey:@"PPT"];        
        [self.supportFiles setObject:[NSNumber numberWithBool:YES] forKey:@"XLS"];        
        [self.supportFiles setObject:[NSNumber numberWithBool:YES] forKey:@"DOCX"];        
        [self.supportFiles setObject:[NSNumber numberWithBool:YES] forKey:@"PPTX"];        
        [self.supportFiles setObject:[NSNumber numberWithBool:YES] forKey:@"XLSX"];        
        [self.supportFiles setObject:[NSNumber numberWithBool:YES] forKey:@"TXT"];        
    }
    return self;
}

- (void)dealloc {
    
    [server release];
    server = nil;
    [data_ release];
    data_ = nil;
    [supportFiles_ release];
    supportFiles_ = nil;
    [selectedRow_ release];
    selectedRow_ = nil;
    [super dealloc];    
}

#pragma mark -
#pragma mark INQDataSource delegate

- (void)loadData {
    data_ = [[NSMutableArray alloc]initWithArray:[INQFileDataSource fileNames:@""]];
#if 1
    // loadedDataSourceCallBack関数の引数追加に伴う変更(optionは不使用)
    [delegate loadedDataSourceCallBack:self.data info:nil option:-1];
#else
    [delegate loadedDataSourceCallBack:self.data info:nil];
#endif
}

- (void)loadDataFromLocalPath:(NSString*)path {
    [self.data removeAllObjects];
    [self.data addObjectsFromArray:[INQFileDataSource fileNames:path]];
    DLog(@"File count:%d",[self.data count]);
#if 1
    // loadedDataSourceCallBack関数の引数追加に伴う変更(optionは不使用)
    [delegate loadedDataSourceCallBack:self.data info:nil option:-1];
#else
    [delegate loadedDataSourceCallBack:self.data info:nil];
#endif
}


- (void)loadDataFromServer:(NSString*)_server path:(NSString*)path {
    server = _server;
    [self.data removeAllObjects];
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        [self.data addObjectsFromArray:[self mountFrom:server remotePath:path]];
        BOOL isThumnailPreview =  [[NSUserDefaults standardUserDefaults] boolForKey:THUMNAIL_PREVIEW];
        
        dispatch_async(dispatch_get_main_queue(), ^{
            if (isThumnailPreview) {
                // [self copyFiles:self.data];     
                [self performSelectorInBackground:@selector(copyFiles:) withObject:self.data];
            }
#if 1
            // loadedDataSourceCallBack関数の引数追加に伴う変更(optionは不使用)
            [delegate loadedDataSourceCallBack:self.data info:nil option:-1];
#else
            [delegate loadedDataSourceCallBack:self.data info:nil];
#endif
        });
    });

}


- (void)sharedFolderList:(NSArray*)fileList {
    [self.data removeAllObjects];
    [self.data addObjectsFromArray:fileList];
#if 1
    // loadedDataSourceCallBack関数の引数追加に伴う変更(optionは不使用)
    [delegate loadedDataSourceCallBack:self.data info:nil option:-1];
#else
    [delegate loadedDataSourceCallBack:self.data info:nil];
#endif
}

#pragma mark -
#pragma mark operation remote file

- (NSArray*)mountFrom:(NSString *)computer remotePath:(NSString *)rp {
    
//  static NSString *unit = @"KB";
//  float size;
    
    // create cache folder.
    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSCachesDirectory, NSUserDomainMask, YES);
    NSString *cachePath = [paths objectAtIndex:0];        
    cachePath = [cachePath stringByAppendingPathComponent:@"Downloads"];
    cachePath = [cachePath stringByAppendingPathComponent:rp];
    
    if(![[NSFileManager defaultManager] isReadableFileAtPath:cachePath]) {
        [[NSFileManager defaultManager] createDirectoryAtPath:cachePath 
                                  withIntermediateDirectories:YES 
                                                   attributes:nil 
                                                        error:nil];
    }
    
    NQ_TCHAR uSearchPath[1000];
    NQ_TCHAR uFilePath[1000];

#ifndef UD_CM_UNICODEAPPLICATION
    NQ_TCHAR uBuffer[1000];
    unsigned int num;
#endif
    
    NSMutableArray *arr = [[NSMutableArray alloc]init];
#if 1
    // ファイルとフォルダの表示順をフォルダ(アルファベット順)→ファイル(アルファベット順)とする対応
    NSMutableArray *arrFile = [[NSMutableArray alloc]init];
#endif
    
#if 1
    // コンピューター名をバックアップ(削除処理用)
    INQAppDelegate *app = (INQAppDelegate *)[[UIApplication sharedApplication] delegate];
    app.backupComputerName = computer;
#endif
    
    while(TRUE) {
        
        NQ_HANDLE dir;
        INQFileListViewController *  controller = (INQFileListViewController *)self.delegate;  // to get mount point name
        NSMutableString    *mntPtPath = [NSMutableString stringWithString: controller.mountPoint]; // search path relevant to mount point
        static FindFileDataW_t fData;
//      static const char *searchPath;
        
        //[mntPtPath appendString:@"\\"];
        //[mntPtPath deleteCharactersInRange:  NSMakeRange(0,[mntPtPath rangeOfString: @"\\"].location)];
        [controller remoteShareNameFromPath:mntPtPath from:rp];
        
#ifndef UD_CM_UNICODEAPPLICATION
        NQ_TCHAR *s;
#endif
        
#ifdef UD_CM_UNICODEAPPLICATION /* mizuguchi UTF-8 <-> UTF-16 */
        
        //cmWStrcpy(uSearchPath, (NQ_TCHAR *)[[NSString stringWithFormat:@"\\\\%@\\%@\\*",computer,rp]
        //                                    cStringUsingEncoding:NSUTF16StringEncoding]);
        /*if ([mntPtPath length] > 1)
            cmWStrcpy(uSearchPath, (NQ_TCHAR *)[[NSString stringWithFormat:@"\\%@%@*", controller.mountPoint , mntPtPath]
                                            cStringUsingEncoding:NSUTF16StringEncoding]);
        else
            cmWStrcpy(uSearchPath, (NQ_TCHAR *)[[NSString stringWithFormat:@"\\%@\\*", controller.mountPoint]*/

        cmWStrcpy(uSearchPath, (NQ_TCHAR *)[[NSString stringWithFormat:@"\\%@*",  mntPtPath]
                                            cStringUsingEncoding:NSUTF16StringEncoding]);

        DLog(@"SearchPath(UTF-16):%S",(const NQ_TCHAR *)uSearchPath);
#else
        searchPath = [[NSString stringWithFormat:@"\\\\%@\\%@\\*",computer,rp] UTF8String];
        DLog(@"Search Path:%s",searchPath);
        cmAnsiToTchar(uSearchPath,searchPath);
#endif
        
        dir = ccFindFirstFile(uSearchPath, &fData, 0);

        if (dir ==  NULL) {
            if (errno == 0) {
                break;
            }
            
#if 1
            // ファイルとフォルダの表示順をフォルダ(アルファベット順)→ファイル(アルファベット順)とする対応
            [arr addObjectsFromArray:arrFile];
            [arrFile release];
#endif
            
            DLog(@"^^Unable to list files in '%S'\n", (const unichar *)uSearchPath);
            return [arr autorelease];
        }

#ifdef UD_CM_UNICODEAPPLICATION
        for ( /*s = uBuffer, num = 1*/; ccFindNextFileW(dir, &fData); ) {
#else
        for (s = uBuffer, num = 1; ccFindNextFileW(dir, &fData); ) {
#endif
            INQFile *file = [[INQFile alloc]init];

#ifdef UD_CM_UNICODEAPPLICATION /* mizuguchi UTF-8 <-> UTF-16 */
            //cmWStrcpy(uFilePath, (NQ_TCHAR *)[[NSString stringWithFormat:@"\\\\%@\\%@\\",computer,rp]
            //                                  cStringUsingEncoding:NSUTF16StringEncoding]);
            cmWStrcpy(uFilePath, (NQ_TCHAR *)[[NSString stringWithFormat:@"\\%@", mntPtPath]
                                                cStringUsingEncoding:NSUTF16StringEncoding]);
            cmWStrcat(uFilePath, fData.fileName);
            DLog(@"FullPath(UTF-16):%S", (const NQ_TCHAR *)uFilePath);
#else
            char toFile[256];
            cmTcharToAnsi(toFile,fData.fileName);
            
            NSString *fn = [NSString stringWithUTF8String:toFile];
            NSString *filePath = [NSString stringWithFormat:@"\\\\%@\\%@\\%@",computer,rp,fn];
            DLog(@"Next FilePath:%@",filePath);
            cmAnsiToTchar(uFilePath,[filePath UTF8String]);
#endif
            
            if (fData.fileAttributes & CIFS_ATTR_DIR) {
#ifdef UD_CM_UNICODEAPPLICATION /* mizuguchi UTF-8 <-> UTF-16 */
                file.fileName = [NSString stringWithFormat:@"%S", (const NQ_TCHAR *)fData.fileName];
#else
                s += cmTStrlen(s) + 1;
                cmTStrcpy(s, fData.fileName);
                num++;
                char foldername[256];
                cmTcharToAnsi(foldername,s);
                
                file.fileName = [NSString stringWithUTF8String:foldername];
#endif
                file.dir = YES;
                //file.relativePath = rp;
                file.relativePath = [NSString stringWithFormat:@"\\%@%@", mntPtPath , file.fileName];
                [arr addObject:file];
                
#if 0
                // 共有フォルダ側のサブフォルダ情報の取得処理(参考)
                NSString *remotePath = [[[[[[@"\\\\" stringByAppendingString:computer]
                                                     stringByAppendingString:@"\\"]
                                                     stringByAppendingString:rp]
                                                     stringByAppendingString:@"\\"]
                                                     stringByAppendingString:file.fileName]
                                                     stringByAppendingString:@"\\"];
                file.subFolderFileCount = [self getCountFileAndSubFolderAtRemote:remotePath];
#endif
                
               // DLog("\t\t%S\t DIR\n", file.fileName);
            } else {
                FileInfo_t fi;
                
                fi.allocationSizeLow = 0;
                
                if (!ccGetFileInformationByNameW(uFilePath, &fi))
#ifdef UD_CM_UNICODEAPPLICATION /* mizuguchi UTF-8 <-> UTF-16 */
                    DLog(@"Unable to perform ccGetFileInformationByName() for file [%S]\n", (const NQ_TCHAR *)uFilePath);
#else
                    DLog(@"Unable to perform ccGetFileInformationByName() for file [%@]\n", filePath);
#endif
                
#ifdef UD_CM_UNICODEAPPLICATION /* mizuguchi UTF-8 <-> UTF-16 */
                file.fileName = [NSString stringWithFormat:@"%S", (const NQ_TCHAR *)fData.fileName];
#else
                char filename[256];
                cmTcharToAnsi(filename,fData.fileName);
                
                file.fileName = [NSString stringWithUTF8String:filename];
#endif
                
                NSArray *fileSplit = [file.fileName componentsSeparatedByString:@"."];
                NSString *fileExt = @"";
                if (fileSplit != nil && [fileSplit count] > 0) {
                    fileExt = [fileSplit objectAtIndex:([fileSplit count] -1)];                    
                } 

                file.fileExt = [fileExt uppercaseString];
                file.dir = NO;
#if 1
                /**
                 * 共有先からファイルをコピーする際のパス生成にて従来処理ではファイル名の前に接頭辞として
                 * lastWriteTimeHighを付与していたが、プレビュー画面のタイトル表示の際に接頭辞が付与された
                 * 状態で表示されてしまう為、接頭辞の付与を中止。（接頭辞を付与している理由は不明）
                 */
                NSString *_tp = [cachePath stringByAppendingPathComponent:[NSString stringWithFormat:@"%@",file.fileName]];
#else
                // file name is lastwritetime_orgfilename
                NSString *_tp = [cachePath stringByAppendingPathComponent:[NSString stringWithFormat:@"%lu_%@",fData.lastWriteTimeHigh,file.fileName]];
#endif
                //file.relativePath = rp;
                file.relativePath = [NSString stringWithFormat:@"\\%@%@", mntPtPath,file.fileName];

                // cache file full path.
                file.fullPath = _tp;

               
                file.fileSize = fData.fileSizeLow;//[NSString stringWithFormat:@"%1.f %@",size,unit];
                long createTime = cmCifsUTCToTime(fData.lastWriteTimeLow,fData.lastWriteTimeHigh);

                file.createDateTime = [[[NSDate alloc]initWithTimeIntervalSince1970:createTime]autorelease];
                file.lastWriteTimeHigh = createTime;
                
#if 1
                // ファイルとフォルダの表示順をフォルダ(アルファベット順)→ファイル(アルファベット順)とする対応
                [arrFile addObject:file];
#else
                [arr addObject:file];              
#endif
            }
            [file release];
        }

        ccFindClose(dir);
        break;
    }
    
#if 1
        // ファイルとフォルダの表示順をフォルダ(アルファベット順)→ファイル(アルファベット順)とする対応
        [arr addObjectsFromArray:arrFile];
        [arrFile release];
#endif

    return [arr autorelease];
}

// save file to cache folder.
- (void)copyFiles:(NSArray*)files {
    
#if 1
    // ファイルのコピー中に落ちる現象を確認した為、暫定処理としてtry〜catchを追加(暫定対応)
    @try{
        for (INQFile *file in files)
        {
            if ([self.supportFiles objectForKey:[file.fileExt uppercaseString]])
            {
                [self copyFile:file];
            }
        }
    }
    @catch (NSException *exception) {
        NSLog(@"INQFileDataSource: copyFiles %@:%@", [exception name], [exception reason]);
    }
    @finally {
        /* DO NOTHING */
    }
#else
    for (INQFile *file in files) {
        
        if ([self.supportFiles objectForKey:[file.fileExt uppercaseString]]) {
            [self copyFile:file];        
        }
        
    }
#endif
}

- (void)copyFile:(INQFile*)file {
    
    if (![[NSFileManager defaultManager] isReadableFileAtPath:file.fullPath]) {
        //NSString *orgFile = [NSString stringWithFormat:@"\\\\%@\\%@\\%@",server,file.relativePath,file.fileName];
        NSString *orgFile = [NSString stringWithFormat:@"%@",file.relativePath];
        //NSString *toFile = [file.fullPath stringByReplacingOccurrencesOfString:@"\\" withString:@"/"];
        if([INQRemoteFileManager copyFile:orgFile to:file.fullPath]) {
            [delegate needDisplay];
        }
    }  
}

#pragma mark -
#pragma mark get file list array

+ (NSArray*)fileNames:(NSString*)filePath {
    //document dir
    NSString *docPath=[NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];

    
	NSString *path = [docPath stringByAppendingPathComponent:filePath]; 

    NSArray *files = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:path error:nil];
    NSMutableArray *arr = [[NSMutableArray alloc]init];
#if 1
    // ファイルとフォルダの表示順をフォルダ(アルファベット順)→ファイル(アルファベット順)とする対応
    NSMutableArray *arrFile = [[NSMutableArray alloc]init];
#endif
    if (files != nil) {

        for (int i = 0; i < [files count]; i++) {
            
            NSString *fileName = [files objectAtIndex:i];
            NSArray *fileSplit = [fileName componentsSeparatedByString:@"."];
            NSString *fileExt = @"";
            if (fileSplit != nil && [fileSplit count] > 0) {
                fileExt = [fileSplit objectAtIndex:([fileSplit count] -1)];                
            }

            NSString *fullPath = [path stringByAppendingPathComponent:fileName];
            NSDictionary *dic = [[NSFileManager defaultManager] attributesOfItemAtPath:fullPath error:nil];
            INQFile *f = [[INQFile alloc]init];

            if ([[dic objectForKey:NSFileType] isEqualToString:NSFileTypeDirectory]) {
                [f setDir:YES];
            }
            
            if ([[dic objectForKey:NSFileType] isEqualToString:NSFileExtensionHidden]) {
                [f setHidden:YES];
            }

            [f setRelativePath:filePath];
            [f setFileSize:[[dic objectForKey:NSFileSize] longValue]];
            [f setCreateDateTime:[dic objectForKey:NSFileCreationDate]];
            [f setUpdateTime:[dic objectForKey:NSFileModificationDate]];
            [f setFileName:fileName];
            [f setFullPath:fullPath];
            [f setFileExt:[fileExt uppercaseString]];
#if 1
            // サブフォルダの情報(フォルダ及びファイル数)をセット
            if(f.isDir)
            {
                [f setSubFolderFileCount:[[[NSFileManager defaultManager] contentsOfDirectoryAtPath:fullPath error:nil] count]];
            }
#endif
            
#if 1
            // ファイルとフォルダの表示順をフォルダ(アルファベット順)→ファイル(アルファベット順)とする対応
            if(f.isDir == YES)
            {
                [arr addObject:f];
            }
            else
            {
                [arrFile addObject:f];
            }
#else
            [arr addObject:f];
#endif
            [f release];
        }
    }

#if 1
    // ファイルとフォルダの表示順をフォルダ(アルファベット順)→ファイル(アルファベット順)とする対応
    [arr addObjectsFromArray:arrFile];
    [arrFile release];
#endif
    
    return [arr autorelease];
}


#pragma mark -
#pragma mark check exit file with name.

+ (BOOL)existsFileWithName:(NSString*)fileName {
    
    NSString* path = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
	path = [path stringByAppendingPathComponent:fileName]; 
    
	return [[NSFileManager defaultManager] fileExistsAtPath:path];
}


+ (void)makeDir:(NSString*)fileName {
    
    if ([INQFileDataSource existsFileWithName:fileName]) return;
    
    NSString* path = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
	path = [path stringByAppendingPathComponent:fileName];

    [[NSFileManager defaultManager] createDirectoryAtPath:path withIntermediateDirectories:NO attributes:nil error:nil];

}


+ (void)removeFileWithName:(NSString*)fileName {
    
    if (![INQFileDataSource existsFileWithName:fileName]) return;
    
    NSString* path = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
	path = [path stringByAppendingPathComponent:fileName]; 
	[[NSFileManager defaultManager] removeItemAtPath:path error:nil];
}

#pragma mark -
#pragma mark UITableViewDataSource delegate.

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    return [self.data count];
}


- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {

    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:@"MyCell"];
    
    if (!cell) {
        cell = [[[UITableViewCell alloc]initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:@"MyCell"]autorelease];
        //     cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
        cell.selectionStyle = UITableViewCellSelectionStyleNone;
        cell.imageView.contentMode = UIViewContentModeScaleAspectFit;
        cell.textLabel.font = [UIFont systemFontOfSize:15.0];
        //cell.selectionStyle = UITableViewCellSelectionStyleBlue;
        cell.imageView.frame = CGRectMake(5, 5, 30, 30);        
    }
    
    [cell setAccessoryType:UITableViewCellAccessoryNone];
    
    if ([self.data count] == 0) {
        return cell;
    }
    
    NSString *error = [NSString stringWithFormat:@"index:%d > arry:%d",indexPath.row,[self.data count]];
    NSAssert(indexPath.row < [self.data count],error);
    
    INQFile *file = [self.data objectAtIndex:indexPath.row];

    if (file.isDir) {
#if 1
        // フォルダ名に付与されていた括弧"<"(folder name)">"を削除
        [cell.textLabel setText:[NSString stringWithFormat:@"%@", file.fileName]];
        // アイコン変更
        INQAppDelegate *app = (INQAppDelegate *)[[UIApplication sharedApplication] delegate];
        UIImage *imgResize = [app resizeImage:@"icon_folder.png" image_size:30];
        [cell.imageView setImage:imgResize];
#else
        [cell.textLabel setText:[NSString stringWithFormat:@"<%@>", file.fileName]];
        [cell.imageView setImage:[UIImage imageNamed:@"folder_icon&24.png"]];
#endif
        [cell.detailTextLabel setText:@""];
    } else {
        NSDateFormatter *formater = [[NSDateFormatter alloc]init];
        
        [formater setTimeZone:[NSTimeZone timeZoneWithName:@"GMT"]];
        [formater setDateFormat:@"yyyy/MM/dd HH:mm:ss"];
        
        BOOL isReady = [[NSFileManager defaultManager] isReadableFileAtPath:file.fullPath];
        BOOL isThumnailPreview =  [[NSUserDefaults standardUserDefaults] boolForKey:THUMNAIL_PREVIEW];
        
#if 1
        // jpgの拡張子(jpeg,jpe)を追加
        if (([[file.fileExt uppercaseString] isEqualToString:@"PNG"] ||
             [[file.fileExt uppercaseString] isEqualToString:@"JPG"] ||
             [[file.fileExt uppercaseString] isEqualToString:@"JPEG"] ||
             [[file.fileExt uppercaseString] isEqualToString:@"JPE"]) && isReady && isThumnailPreview) {
#else
        if (([[file.fileExt uppercaseString] isEqualToString:@"PNG"] || [[file.fileExt uppercaseString] isEqualToString:@"JPG"]) && isReady && isThumnailPreview) {
#endif
            @autoreleasepool {

                CGImageSourceRef src = CGImageSourceCreateWithURL((CFURLRef)[NSURL fileURLWithPath:file.fullPath], NULL);
                CFDictionaryRef options = (CFDictionaryRef)[[NSDictionary alloc] 
                                                            initWithObjectsAndKeys:(id)kCFBooleanTrue, 
                                                            (id)kCGImageSourceCreateThumbnailWithTransform, 
                                                            (id)kCFBooleanTrue, 
                                                            (id)kCGImageSourceCreateThumbnailFromImageIfAbsent, 
                                                            (id)[NSNumber numberWithDouble:100.0], 
                                                            (id)kCGImageSourceThumbnailMaxPixelSize, nil];
                
                CGImageRef thumbnail = CGImageSourceCreateThumbnailAtIndex(src, 0, options); // Create scaled image
                UIImage* img = [[UIImage alloc] initWithCGImage:thumbnail];
                [cell.imageView setImage:[img makeThumbnailOfSize:CGSizeMake(50, 50)]];

                CFRelease(options);

#if 1           // Analyze対応 [Potential leak of an object stored into 'thumbnail']
                if( src )
                {
                    CFRelease(src);
                }
                if( thumbnail )
                {
                    CGImageRelease(thumbnail);
                }
#else
                if (src) {
                    CFRelease(src);                    
                    CGImageRelease(thumbnail);                                
                }
#endif

                [img release];

            }
        } else {
#if 1
            INQAppDelegate *app = (INQAppDelegate *)[[UIApplication sharedApplication] delegate];

            // ファイルのフォーマットに応じてリストに表示するアイコンファイルを変更する処理
            if([[file.fileExt uppercaseString] isEqualToString:@"PNG"])
            {
                UIImage *imgResize = [app resizeImage:@"file_png.png" image_size:30];
                [cell.imageView setImage:imgResize];
            }
            else if([[file.fileExt uppercaseString] isEqualToString:@"JPG"] ||
                    [[file.fileExt uppercaseString] isEqualToString:@"JPEG"] ||
                    [[file.fileExt uppercaseString] isEqualToString:@"JPE"])
            {
                UIImage *imgResize = [app resizeImage:@"file_jpg.png" image_size:30];
                [cell.imageView setImage:imgResize];
            }
            else if([[file.fileExt uppercaseString] isEqualToString:@"PDF"])
            {
                UIImage *imgResize = [app resizeImage:@"file_pdf.png" image_size:30];
                [cell.imageView setImage:imgResize];
            }
            else if([[file.fileExt uppercaseString] isEqualToString:@"TXT"])
            {
                UIImage *imgResize = [app resizeImage:@"file_txt.png" image_size:30];
                [cell.imageView setImage:imgResize];
            }
            else if([[file.fileExt uppercaseString] isEqualToString:@"DOC"] ||
                    [[file.fileExt uppercaseString] isEqualToString:@"DOCX"])
            {
                UIImage *imgResize = [app resizeImage:@"file_doc.png" image_size:30];
                [cell.imageView setImage:imgResize];
            }
            else if([[file.fileExt uppercaseString] isEqualToString:@"XLS"] ||
                    [[file.fileExt uppercaseString] isEqualToString:@"XLSX"])
            {
                UIImage *imgResize = [app resizeImage:@"file_xls.png" image_size:30];
                [cell.imageView setImage:imgResize];
            }
            else if([[file.fileExt uppercaseString] isEqualToString:@"PPT"] ||
                    [[file.fileExt uppercaseString] isEqualToString:@"PPTX"])
            {
                UIImage *imgResize = [app resizeImage:@"file_ppt.png" image_size:30];
                [cell.imageView setImage:imgResize];
            }
            else
            {
                UIImage *imgResize = [app resizeImage:@"file.png" image_size:30];
                [cell.imageView setImage:imgResize];
            }
#else
            [cell.imageView setImage:[UIImage imageNamed:@"doc_lines_icon&24.png"]];
#endif
        }

        [cell.textLabel setText:file.fileName];
        float size = (float)file.fileSize / 1023.0f;// / 1000.0f;
        NSString *unit = @"KB";
        
        if (size > 1024.0f * 1024.0f) {
            size = size / 1024.f / 1024.0f ;
            unit = @"MB";
        }
        
        [cell.detailTextLabel setText:[NSString stringWithFormat:@"%@ - %@",[NSString stringWithFormat:@"%d%@",(int)size,unit],[formater stringFromDate:file.createDateTime]]];
        [formater release];
    }

    if ([self.supportFiles objectForKey:[file.fileExt uppercaseString]]){
        [cell setAccessoryType:UITableViewCellAccessoryDisclosureIndicator];    
    }    
    
    [self.selectedRow enumerateKeysAndObjectsUsingBlock:^(id key, id obj, BOOL *stop) {
        int row = [(NSString*)key intValue];
        if (row == indexPath.row) {
            [cell setAccessoryType:UITableViewCellAccessoryCheckmark];
        }
        
    }];
    

    return cell;
}
    
- (void)tableView:(UITableView *)tableView commitEditingStyle:(UITableViewCellEditingStyle)editingStyle forRowAtIndexPath:(NSIndexPath *)indexPath {
    
    if (editingStyle == UITableViewCellEditingStyleDelete) {
        INQFile *file = [self.data objectAtIndex:indexPath.row];

#if 1
        /**
         * 元々の処理ではファイル及びフォルダの削除をローカルのファイルと同じ扱いで操作しようとし失敗していた為修正.
         */
        INQAppDelegate *app = (INQAppDelegate *)[[UIApplication sharedApplication] delegate];

        if( app.typeSelectedView == DEF_VIEW_WORKGROUP )
        {
            
            //NSString * tmpFullPath = [NSString stringWithFormat:@"\\\\%@\\%@\\%@",app.backupComputerName,file.relativePath,file.fileName];
            NSString * tmpFullPath = file.relativePath;
            
            if(file.isDir == YES)
            {
                // directory path
                tmpFullPath = [tmpFullPath stringByAppendingString:@"\\"];
            }
            
            if((file.isDir == YES) && ([self getCountFileAndSubFolderAtRemote:tmpFullPath] > 0))
            {
                [self showAlertNotExecDeleteFolder];
                [tableView reloadData];
                return;
            }
            
            if(![INQRemoteFileManager deleteFile:tmpFullPath])
            {
                DLog(@"Delete failed:%@",tmpFullPath);
                return;
            }
        }
        else /* if( app.typeSelectedView == DEF_VIEW_LOCAL ) */
        {
            DLog(@"Delete File:%@",file.fullPath);
            if(file.isDir && [self getCountFileAndSubFolderAtLocal:file.fullPath] > 0)
            {
                [self showAlertNotExecDeleteFolder];
                [tableView reloadData];
                return;
            }
            
            NSError *error = nil;
            [[NSFileManager defaultManager] removeItemAtPath:file.fullPath error:&error];
            
            if (error) {
                DLog(@"Delete File(%@) Error:%@",file.fullPath,error);
            }            
        }
#else
        DLog(@"Delete File:%@",file.fullPath);
        if (file.isDir && file.subFolderFileCount > 0) {
            return;
        }

        NSError *error = nil;
        [[NSFileManager defaultManager] removeItemAtPath:file.fullPath error:&error];
        
        if (error) {
            DLog(@"Delete File(%@) Error:%@",file.fullPath,error);
        }
#endif
        [self.data removeObjectAtIndex:indexPath.row]; 
        [tableView deleteRowsAtIndexPaths:[NSArray arrayWithObject:indexPath] withRowAnimation:UITableViewRowAnimationFade];
        
    }
}

/**
 * @brief アラート表示処理(フォルダ内にファイルもしくはサブフォルダが存在する)
 */
-(void)showAlertNotExecDeleteFolder
{
    UIAlertView *deleteFaildView = [[UIAlertView alloc]
                                    initWithTitle:NSLocalizedString(@"SubFolderHaveFile", @"sub folder have file.")
                                    message:nil
                                    delegate:nil
                                    cancelButtonTitle:NSLocalizedString(@"OK",@"OK")
                                    otherButtonTitles:nil, nil];
    [deleteFaildView show];
    [deleteFaildView release];
}
    
/**
 * @brief 共有フォルダ内のファイル及びサブフォルダ数取得処理
 */
-(int)getCountFileAndSubFolderAtRemote:(NSString *)remotoPath
{
    NQ_HANDLE dir;
    NQ_TCHAR uSearchPath[1000]={0};
    FindFileDataW_t fData;
    NSInteger subFileFolderCount = 0;

    cmWStrcpy( uSearchPath, (NQ_TCHAR *)[[NSString stringWithFormat:@"%@",remotoPath]
                                         cStringUsingEncoding:NSUTF16StringEncoding]);
    
    dir = ccFindFirstFile( uSearchPath, &fData, 0 );
    if (dir != NULL)
    {
        for (;ccFindNextFileW( dir, &fData ); )
        {
            subFileFolderCount++;
        }
    }
    
    ccFindClose(dir);
    
    return subFileFolderCount;
}

/**
 * @brief ローカルフォルダ内のファイル及びサブフォルダ数取得処理
 */
-(int)getCountFileAndSubFolderAtLocal:(NSString *)filePath
{
    NSArray *files = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:filePath error:nil];
    NSInteger subFileFolderCount = 0;

    if (files != nil)
    {
        subFileFolderCount = [files count];
    }

    return subFileFolderCount;
}

@end
