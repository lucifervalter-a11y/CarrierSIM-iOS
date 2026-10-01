#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN
/// Owner-assisted peer control. Pairing keys and backups never leave the target.
/// Both entry points and completions must run on the main queue.
@interface CSNearbyViewController : UITableViewController
@property (nonatomic, copy) BOOL (^canReceive)(void);
@property (nonatomic, copy) void (^executeRequest)(NSDictionary *request, BOOL (^stillAuthorized)(void), void (^completion)(NSDictionary *safeResult));
@end
NS_ASSUME_NONNULL_END
