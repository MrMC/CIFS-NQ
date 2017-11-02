
#import <UIKit/UIKit.h>


@interface INQAssetCell : UITableViewCell {
	NSArray *rowAssets;
}

- (id)initWithAssets:(NSArray*)_assets reuseIdentifier:(NSString*)_identifier;
- (void)setAssets:(NSArray*)_assets;

@property (nonatomic,retain) NSArray *rowAssets;

@end
