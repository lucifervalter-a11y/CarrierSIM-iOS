#import <UIKit/UIKit.h>
#import "CSMainViewController.h"

@interface CSAppDelegate : UIResponder <UIApplicationDelegate>
@property (nonatomic, strong) UIWindow *window;
@property (nonatomic, strong) CSMainViewController *controller;
@end

@implementation CSAppDelegate
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)options {
    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    self.controller = [[CSMainViewController alloc] initWithStyle:UITableViewStyleInsetGrouped];
    UINavigationController *navigation = [[UINavigationController alloc] initWithRootViewController:self.controller];
    navigation.navigationBar.prefersLargeTitles = YES;
    self.window.rootViewController = navigation;
    self.window.tintColor = [UIColor colorWithRed:0.02 green:0.54 blue:0.48 alpha:1.0];
    [self.window makeKeyAndVisible];
    NSURL *url = options[UIApplicationLaunchOptionsURLKey];
    if (url) dispatch_async(dispatch_get_main_queue(), ^{ [self.controller handleIncomingURL:url]; });
    return YES;
}
- (BOOL)application:(UIApplication *)application openURL:(NSURL *)url options:(NSDictionary *)options {
    [self.controller handleIncomingURL:url];
    return YES;
}
@end

int main(int argc, char *argv[]) {
    @autoreleasepool { return UIApplicationMain(argc, argv, nil, NSStringFromClass(CSAppDelegate.class)); }
}
