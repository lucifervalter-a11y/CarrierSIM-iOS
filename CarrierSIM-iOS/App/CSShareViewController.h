#import <UIKit/UIKit.h>

@interface CSShareViewController : UITableViewController
- (instancetype)initWithPairingPath:(NSString *)pairingPath workDirectory:(NSURL *)work
                             target:(NSDictionary *)target device:(NSDictionary *)device operationQueue:(dispatch_queue_t)queue;
@property (nonatomic, copy) void (^onBusy)(BOOL busy);
@property (nonatomic, copy) void (^onLog)(NSString *message);
@property (nonatomic, copy) void (^onFinished)(NSDictionary *result);
@end
