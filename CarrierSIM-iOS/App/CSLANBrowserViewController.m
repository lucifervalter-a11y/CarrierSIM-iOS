#import "CSLANBrowserViewController.h"
#import <arpa/inet.h>

@interface CSLANBrowserViewController () <NSNetServiceBrowserDelegate, NSNetServiceDelegate>
@property (nonatomic, strong) NSMutableArray<NSNetServiceBrowser *> *browsers;
@property (nonatomic, strong) NSMutableArray<NSNetService *> *services;
@property (nonatomic, strong) NSMutableDictionary<NSString *, NSDictionary *> *devices;
@end

@implementation CSLANBrowserViewController
- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"iPhone в Wi-Fi";
    self.services = NSMutableArray.new; self.browsers = NSMutableArray.new; self.devices = NSMutableDictionary.new;
    self.tableView.rowHeight = UITableViewAutomaticDimension; self.tableView.estimatedRowHeight = 70;
    for (NSString *type in @[@"_remoted._tcp.", @"_remotepairing._tcp.", @"_apple-mobdev2._tcp."]) {
        NSNetServiceBrowser *browser = NSNetServiceBrowser.new; browser.delegate = self; [self.browsers addObject:browser];
        [browser searchForServicesOfType:type inDomain:@"local."];
    }
}
- (void)viewWillDisappear:(BOOL)animated {
    [super viewWillDisappear:animated];
    for (NSNetServiceBrowser *browser in self.browsers) [browser stop];
    for (NSNetService *service in self.services) [service stop];
}
- (NSString *)key:(NSNetService *)service { return [NSString stringWithFormat:@"%@|%@|%@",service.name,service.type,service.domain]; }
- (NSArray *)keys { return [self.devices.allKeys sortedArrayUsingSelector:@selector(compare:)]; }
- (void)netServiceBrowser:(NSNetServiceBrowser *)browser didFindService:(NSNetService *)service moreComing:(BOOL)more {
    [self.services addObject:service]; service.delegate = self; [service resolveWithTimeout:8];
}
- (void)netServiceBrowser:(NSNetServiceBrowser *)browser didRemoveService:(NSNetService *)service moreComing:(BOOL)more {
    NSString *key = [self key:service]; [self.devices removeObjectForKey:key];
    for (NSNetService *known in self.services.copy) { if ([[self key:known] isEqualToString:key]) { [known stop]; [self.services removeObject:known]; } }
    [self.tableView reloadData];
}
- (void)netServiceDidResolveAddress:(NSNetService *)service {
    if (service.port < 1 || service.port > 65535) return;
    for (NSData *address in service.addresses) {
        if (address.length < sizeof(struct sockaddr_in)) continue;
        const struct sockaddr_in *v4 = address.bytes;
        if (v4->sin_family != AF_INET) continue;
        char host[INET_ADDRSTRLEN];
        if (!inet_ntop(AF_INET, &v4->sin_addr, host, sizeof(host))) continue;
        self.devices[[self key:service]] = @{@"name":service.name, @"host":[NSString stringWithUTF8String:host], @"port":@(service.port), @"lockdown":@([service.type isEqualToString:@"_apple-mobdev2._tcp."])};
        [self.tableView reloadData]; break;
    }
}
- (void)netServiceBrowser:(NSNetServiceBrowser *)browser didNotSearch:(NSDictionary *)error {
    [self.tableView reloadData];
}
- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section { return self.devices.count; }
- (NSString *)tableView:(UITableView *)tableView titleForFooterInSection:(NSInteger)section {
    return @"Оба iPhone должны быть в одной Wi-Fi-сети. Разреши CarrierSIM локальную сеть и разблокируй телефон друга. Lockdown использует готовое доверенное сопряжение; Remote Pairing требует свой файл и доступную службу. При выключенном режиме разработчика нужные службы могут быть недоступны. Если список пуст, укажи адрес вручную. Выбор из списка ещё не подтверждает доступ к телефону.";
}
- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)path {
    NSDictionary *device = self.devices[[self keys][path.row]];
    UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:nil];
    cell.textLabel.text = device[@"name"]; cell.detailTextLabel.text = [NSString stringWithFormat:@"%@:%@ · %@",device[@"host"],device[@"port"],[device[@"lockdown"] boolValue] ? @"Lockdown: нужен его pairing-файл" : @"Remote Pairing"];
    cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator; return cell;
}
- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)path {
    NSDictionary *device = self.devices[[self keys][path.row]];
    void (^callback)(NSString *, NSInteger) = self.onSelect;
    [self.navigationController popViewControllerAnimated:YES];
    // The Lockdown port must not be used as an RSD port. The pairing file
    // selects Lockdown, which connects to its fixed port 62078 independently.
    if (callback) dispatch_async(dispatch_get_main_queue(), ^{ callback(device[@"host"], [device[@"lockdown"] boolValue] ? 49152 : [device[@"port"] integerValue]); });
}
@end
