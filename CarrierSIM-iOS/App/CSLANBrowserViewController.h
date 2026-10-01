#import <UIKit/UIKit.h>

@interface CSLANBrowserViewController : UITableViewController
@property (nonatomic, copy) void (^onSelect)(NSString *host, NSInteger port);
@end
