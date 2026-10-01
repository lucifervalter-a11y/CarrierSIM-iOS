#import <UIKit/UIKit.h>

@interface CSDeveloperModeViewController : UITableViewController
- (instancetype)initWithPairingPath:(NSString *)pairingPath workDirectory:(NSURL *)work
                             target:(NSDictionary *)target operationQueue:(dispatch_queue_t)queue;
@property (nonatomic, copy) void (^onState)(NSDictionary *result, BOOL busy, BOOL waiting);
@property (nonatomic, copy) void (^onLog)(NSString *message);
+ (BOOL)hasPendingAtDirectory:(NSURL *)work;
@end
