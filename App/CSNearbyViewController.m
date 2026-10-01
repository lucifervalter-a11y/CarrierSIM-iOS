// CarrierSIM-iOS nearby assistance, original integration for this port.
// Apple MultipeerConnectivity: https://developer.apple.com/documentation/multipeerconnectivity
// The local carrier engine derives from ios-bundles/CarrierSIM; see CREDITS.md.
#import "CSNearbyViewController.h"
#import <MultipeerConnectivity/MultipeerConnectivity.h>

static NSString *const CSNearbyService = @"carriersim-help";
static const NSUInteger CSNearbyMessageLimit = 4096;
static BOOL CSString(id value, NSUInteger max) {
    return [value isKindOfClass:NSString.class] && [value length] > 0 && [value length] <= max;
}
static BOOL CSBundle(id value) {
    if (!CSString(value, 80)) return NO;
    NSCharacterSet *allowed = [NSCharacterSet characterSetWithCharactersInString:@"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"];
    return [(NSString *)value rangeOfCharacterFromSet:allowed.invertedSet].location == NSNotFound;
}
static BOOL CSInteger(id value, NSInteger low, NSInteger high) {
    return [value isKindOfClass:NSNumber.class] && CFGetTypeID((__bridge CFTypeRef)value) != CFBooleanGetTypeID() &&
        [value doubleValue] == [value integerValue] && [value integerValue] >= low && [value integerValue] <= high;
}
static BOOL CSKeys(NSDictionary *value, NSArray *keys) {
    return [[NSSet setWithArray:value.allKeys] isEqualToSet:[NSSet setWithArray:keys]];
}
static NSDictionary *CSDecode(NSData *data) {
    if (!data.length || data.length > CSNearbyMessageLimit) return nil;
    id value = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
    if (![value isKindOfClass:NSDictionary.class] || !CSInteger(value[@"v"], 1, 1) || !CSString(value[@"id"], 36) ||
        ![[NSUUID alloc] initWithUUIDString:value[@"id"]]) return nil;
    if ([value[@"type"] isEqual:@"request"]) {
        if (!CSKeys(value, @[@"v", @"id", @"type", @"action", @"bundle", @"sim"]) ||
            ![@[@"status", @"apply", @"restore"] containsObject:value[@"action"]] || !CSBundle(value[@"bundle"]) ||
            !CSInteger(value[@"sim"], 0, 2)) return nil;
    } else if ([value[@"type"] isEqual:@"result"]) {
        if (!CSKeys(value, @[@"v", @"id", @"type", @"state", @"catalog", @"confirmed", @"recovery", @"sims"]) ||
            ![@[@"done", @"failed", @"declined", @"not_ready", @"busy"] containsObject:value[@"state"]] ||
            !CSInteger(value[@"sims"], 0, 8)) return nil;
        for (NSString *key in @[@"catalog", @"confirmed", @"recovery"]) {
            if (![value[key] isKindOfClass:NSNumber.class] || CFGetTypeID((__bridge CFTypeRef)value[key]) != CFBooleanGetTypeID()) return nil;
        }
    } else return nil;
    return value;
}

@interface CSNearbyViewController () <MCSessionDelegate, MCNearbyServiceBrowserDelegate, MCNearbyServiceAdvertiserDelegate>
@property (nonatomic, strong) MCPeerID *identity;
@property (nonatomic, strong) MCPeerID *partner;
@property (nonatomic, strong) MCSession *session;
@property (nonatomic, strong) MCNearbyServiceBrowser *browser;
@property (nonatomic, strong) MCNearbyServiceAdvertiser *advertiser;
@property (nonatomic, strong) NSMutableArray<MCPeerID *> *peers;
@property (nonatomic, strong) NSMutableSet<NSString *> *seenRequests;
@property (nonatomic, copy) NSString *status;
@property (nonatomic, copy) NSString *code;
@property (nonatomic, copy) NSString *bundle;
@property (nonatomic, copy) NSString *outgoingID;
@property (nonatomic, copy) NSString *incomingID;
@property (nonatomic) NSInteger SIMSelection;
@property (nonatomic) NSInteger mode; // 0 off, 1 controller, 2 owner/receiver
@property (nonatomic) NSUInteger epoch;
@property (nonatomic) BOOL executing;
@property (nonatomic, copy) void (^invitationReply)(BOOL, MCSession *);
@end

@implementation CSNearbyViewController
- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"Другой iPhone";
    self.tableView.rowHeight = UITableViewAutomaticDimension;
    self.tableView.estimatedRowHeight = 70;
    self.peers = NSMutableArray.array;
    self.seenRequests = NSMutableSet.set;
    self.bundle = @"Vodafone_hu";
    self.status = @"Открой CarrierSIM на обоих iPhone. На изменяемом выбери «Принимать помощь», на другом — «Найти iPhone».";
    self.navigationItem.leftBarButtonItem = [[UIBarButtonItem alloc] initWithTitle:@"Закрыть" style:UIBarButtonItemStylePlain target:self action:@selector(close)];
    [NSNotificationCenter.defaultCenter addObserver:self selector:@selector(background) name:UIApplicationDidEnterBackgroundNotification object:nil];
}
- (void)dealloc { [NSNotificationCenter.defaultCenter removeObserver:self]; }
- (BOOL)connected { return self.partner && [self.session.connectedPeers containsObject:self.partner]; }
- (void)refresh { [self.tableView reloadData]; }
- (void)stop {
    self.epoch++;
    if (self.invitationReply) { self.invitationReply(NO, nil); self.invitationReply = nil; }
    self.browser.delegate = nil; [self.browser stopBrowsingForPeers]; self.browser = nil;
    self.advertiser.delegate = nil; [self.advertiser stopAdvertisingPeer]; self.advertiser = nil;
    self.session.delegate = nil; [self.session disconnect]; self.session = nil;
    self.identity = nil; self.partner = nil; self.mode = 0;
    self.incomingID = nil; self.outgoingID = nil; self.code = nil;
    [self.peers removeAllObjects]; [self.seenRequests removeAllObjects];
    [self refresh];
}
- (void)background {
    [self stop];
    if (self.presentedViewController) [self dismissViewControllerAnimated:NO completion:nil];
    self.status = self.executing ? @"Соединение закрыто. Уже начатая операция продолжается на этом iPhone; проверь её результат здесь." : @"Режим помощи выключен при сворачивании. Для нового подключения запусти поиск снова.";
    [self refresh];
}
- (void)close {
    if (self.executing) { [self notice:@"Операция идёт" text:@"Не закрывай CarrierSIM до результата. Отключение другого iPhone не отменяет начатую запись."]; return; }
    [self stop]; [self dismissViewControllerAnimated:YES completion:nil];
}
- (void)notice:(NSString *)title text:(NSString *)text {
    self.status = text; [self refresh];
    if (self.presentedViewController) return;
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:title message:text preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"Понятно" style:UIAlertActionStyleCancel handler:nil]];
    [self presentViewController:alert animated:YES completion:nil];
}
- (void)start:(NSInteger)mode {
    if (self.executing) return;
    if (mode == 2 && (!self.canReceive || !self.canReceive())) {
        [self notice:@"Сначала подготовь этот iPhone" text:@"На главном экране один раз создай сопряжение и включи локальный VPN. Затем вернись сюда и выбери «Принимать помощь»."]; return;
    }
    [self stop]; self.mode = mode;
    self.identity = [[MCPeerID alloc] initWithDisplayName:[@"iPhone-" stringByAppendingString:[NSUUID.UUID.UUIDString substringToIndex:4]]];
    self.session = [[MCSession alloc] initWithPeer:self.identity securityIdentity:nil encryptionPreference:MCEncryptionRequired];
    self.session.delegate = self;
    if (mode == 1) {
        self.browser = [[MCNearbyServiceBrowser alloc] initWithPeer:self.identity serviceType:CSNearbyService];
        self.browser.delegate = self; [self.browser startBrowsingForPeers];
        self.status = @"Ищу iPhone, на котором включено «Принимать помощь». Разреши локальную сеть. Используй общую Wi-Fi сеть либо включи Wi-Fi и Bluetooth на обоих устройствах.";
    } else {
        self.advertiser = [[MCNearbyServiceAdvertiser alloc] initWithPeer:self.identity discoveryInfo:@{@"v":@"1"} serviceType:CSNearbyService];
        self.advertiser.delegate = self; [self.advertiser startAdvertisingPeer];
        self.status = [NSString stringWithFormat:@"Этот телефон виден как %@. Подключение и каждое действие нужно подтвердить здесь. Ключи и копии остаются на этом телефоне.", self.identity.displayName];
    }
    [self refresh];
}
- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView { return 3; }
- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section { return section == 0 ? 3 : section == 1 ? MAX((NSUInteger)1, self.peers.count) : 6; }
- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section { return @[@"Режим", @"Доступные iPhone", @"Запрос к другому iPhone"][section]; }
- (NSString *)tableView:(UITableView *)tableView titleForFooterInSection:(NSInteger)section {
    if (section == 0) return self.status;
    if (section == 1) return @"Имя и код помогают не перепутать телефоны. Не принимай незнакомые запросы. Оба приложения должны оставаться открытыми.";
    return @"Изменение выполняется принимающим iPhone после согласия владельца. Обнаружение по сети само по себе не даёт доступа к системе. Проверка на реальных устройствах пока не выполнена.";
}
- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)path {
    UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:nil];
    cell.textLabel.numberOfLines = 0; cell.detailTextLabel.numberOfLines = 0;
    cell.detailTextLabel.textColor = UIColor.secondaryLabelColor;
    BOOL enabled = !self.executing;
    if (path.section == 0) {
        cell.textLabel.text = @[@"Найти iPhone", @"Принимать помощь на этом iPhone", @"Отключить помощь"][path.row];
        enabled = enabled && !self.outgoingID;
    } else if (path.section == 1) {
        cell.textLabel.text = self.peers.count ? self.peers[path.row].displayName : @"Нет найденных устройств";
        enabled = self.mode == 1 && self.peers.count && !self.partner;
    } else {
        cell.textLabel.text = @[@"Профиль", @"SIM", @"Проверить iPhone", @"Запросить применение", @"Запросить штатные профили", @"Соединение"][path.row];
        if (path.row == 0) cell.detailTextLabel.text = self.bundle;
        if (path.row == 1) cell.detailTextLabel.text = @[@"Все SIM", @"SIM 1", @"SIM 2"][self.SIMSelection];
        if (path.row == 5) cell.detailTextLabel.text = [NSString stringWithFormat:@"%@%@", self.connected ? self.partner.displayName : @"Не подключено", self.code ? [@" · Код: " stringByAppendingString:self.code] : @""];
        enabled = enabled && self.mode == 1 && self.connected && !self.outgoingID && path.row != 5;
    }
    cell.userInteractionEnabled = enabled;
    cell.textLabel.textColor = enabled ? UIColor.labelColor : UIColor.secondaryLabelColor;
    return cell;
}
- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)path {
    [tableView deselectRowAtIndexPath:path animated:YES];
    if (self.executing || self.outgoingID) return;
    if (path.section == 0) {
        if (path.row < 2) [self start:path.row + 1]; else { [self stop]; self.status = @"Помощь выключена."; [self refresh]; }
    } else if (path.section == 1 && self.mode == 1 && path.row < self.peers.count && !self.partner) {
        self.partner = self.peers[path.row]; self.code = [NSString stringWithFormat:@"%06u", arc4random_uniform(1000000)];
        NSData *context = [NSJSONSerialization dataWithJSONObject:@{@"v":@1, @"code":self.code} options:0 error:nil];
        [self.browser invitePeer:self.partner toSession:self.session withContext:context timeout:60];
        NSUInteger epoch = self.epoch;
        self.status = [NSString stringWithFormat:@"На %@ нужно подтвердить код %@. Не принимайте другой код.", self.partner.displayName, self.code]; [self refresh];
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 65 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
            if (self.epoch == epoch && !self.connected) { [self stop]; self.status = @"Приглашение истекло. Запусти поиск заново."; [self refresh]; }
        });
    } else if (path.section == 2 && self.mode == 1 && self.connected) {
        if (path.row == 0) [self editBundle];
        else if (path.row == 1) { self.SIMSelection = (self.SIMSelection + 1) % 3; [self refresh]; }
        else if (path.row >= 2 && path.row <= 4) [self sendAction:@[@"status", @"apply", @"restore"][path.row-2]];
    }
}
- (void)editBundle {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Имя профиля" message:@"Например, Vodafone_hu. Только буквы, цифры и подчёркивание; без .bundle." preferredStyle:UIAlertControllerStyleAlert];
    [alert addTextFieldWithConfigurationHandler:^(UITextField *field) { field.text = self.bundle; field.autocorrectionType = UITextAutocorrectionTypeNo; field.autocapitalizationType = UITextAutocapitalizationTypeNone; }];
    [alert addAction:[UIAlertAction actionWithTitle:@"Отмена" style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"Сохранить" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        NSString *value = alert.textFields.firstObject.text;
        if (CSBundle(value)) self.bundle = value; else self.status = @"Недопустимое имя профиля. Прежний выбор сохранён.";
        [self refresh];
    }]];
    [self presentViewController:alert animated:YES completion:nil];
}
- (BOOL)send:(NSDictionary *)message {
    if (!self.connected) return NO;
    NSData *data = [NSJSONSerialization dataWithJSONObject:message options:0 error:nil];
    if (!data || data.length > CSNearbyMessageLimit) return NO;
    NSError *error = nil;
    return [self.session sendData:data toPeers:@[self.partner] withMode:MCSessionSendDataReliable error:&error];
}
- (void)sendAction:(NSString *)action {
    if (self.mode != 1 || !self.connected || self.outgoingID) return;
    NSString *identifier = NSUUID.UUID.UUIDString;
    NSDictionary *request = @{@"v":@1, @"id":identifier, @"type":@"request", @"action":action, @"bundle":self.bundle, @"sim":@(self.SIMSelection)};
    if (![self send:request]) { [self notice:@"Запрос не отправлен" text:@"Проверь соединение. Автоматического повторения записи нет."]; return; }
    self.outgoingID = identifier;
    self.status = @"Ожидаю согласия владельца и результат. Не повторяй запрос: запись на другом телефоне может продолжаться даже после обрыва связи."; [self refresh];
}
- (void)reply:(NSString *)identifier state:(NSString *)state result:(NSDictionary *)result {
    // Deliberately rebuild an allow-listed response, never forward engine JSON or logs.
    [self send:@{@"v":@1, @"id":identifier, @"type":@"result", @"state":state,
                 @"catalog":@([result[@"catalog"] boolValue]), @"confirmed":@([result[@"confirmed"] boolValue]),
                 @"recovery":@([result[@"recovery"] boolValue]), @"sims":@(MIN(8, MAX(0, [result[@"sims"] integerValue])))}];
}
- (void)handleRequest:(NSDictionary *)request {
    if (self.mode != 2) return;
    NSString *identifier = request[@"id"];
    if ([self.seenRequests containsObject:identifier]) return;
    if (self.seenRequests.count >= 128) { [self stop]; return; }
    [self.seenRequests addObject:identifier];
    if (self.executing || self.incomingID || self.presentedViewController) { [self reply:identifier state:@"busy" result:nil]; return; }
    if (UIApplication.sharedApplication.applicationState != UIApplicationStateActive || !self.canReceive || !self.canReceive()) {
        [self reply:identifier state:@"not_ready" result:nil]; return;
    }
    self.incomingID = identifier;
    NSUInteger epoch = self.epoch;
    NSString *verb = [@{@"status":@"Проверить доступ и SIM без изменения профиля", @"apply":@"Изменить профиль на ЭТОМ iPhone", @"restore":@"Убрать IMSI-ссылки для ВСЕХ SIM на ЭТОМ iPhone"} objectForKey:request[@"action"]];
    NSString *body = [NSString stringWithFormat:@"От: %@\n%@\nПрофиль: %@\nSIM: %@\n\nКопии сохраняются на этом телефоне. Связь может временно пропасть. Подтверждай только ожидаемый запрос.", self.partner.displayName, verb, request[@"bundle"], @[@"все", @"SIM 1", @"SIM 2"][[request[@"sim"] integerValue]]];
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Разрешить действие?" message:body preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"Отклонить" style:UIAlertActionStyleCancel handler:^(UIAlertAction *a) {
        if (self.epoch != epoch || ![self.incomingID isEqual:identifier]) return;
        self.incomingID = nil; [self reply:identifier state:@"declined" result:nil];
    }]];
    [alert addAction:[UIAlertAction actionWithTitle:@"Разрешить на этом iPhone" style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
        if (self.epoch != epoch || !self.connected || ![self.incomingID isEqual:identifier]) return;
        self.incomingID = nil;
        if (!self.canReceive || !self.canReceive() || !self.executeRequest || UIApplication.sharedApplication.applicationState != UIApplicationStateActive) { [self reply:identifier state:@"not_ready" result:nil]; return; }
        self.executing = YES; self.modalInPresentation = YES;
        self.status = @"Действие выполняется на этом iPhone. Не закрывай приложение. Копии не передаются другому устройству."; [self refresh];
        self.executeRequest(request, ^BOOL{ return self.epoch == epoch && self.connected && self.mode == 2 && UIApplication.sharedApplication.applicationState == UIApplicationStateActive; }, ^(NSDictionary *result) {
            self.executing = NO; self.modalInPresentation = NO;
            self.status = [result[@"ok"] boolValue] ? @"Действие завершено. Результат проверки профиля и журнал — на главном экране этого iPhone." : @"Действие не завершено. Проверь журнал на главном экране; при необходимости запусти восстановление здесь.";
            if (self.epoch == epoch) [self reply:identifier state:[result[@"ok"] boolValue] ? @"done" : @"failed" result:result];
            [self refresh];
        });
    }]];
    [self presentViewController:alert animated:YES completion:nil];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 60 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        if (self.epoch != epoch || ![self.incomingID isEqual:identifier]) return;
        self.incomingID = nil; [alert dismissViewControllerAnimated:YES completion:nil];
        [self reply:identifier state:@"declined" result:nil];
    });
}
- (void)session:(MCSession *)session peer:(MCPeerID *)peer didChangeState:(MCSessionState)state {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (session != self.session || ![peer isEqual:self.partner]) return;
        if (state == MCSessionStateConnected) {
            [self.browser stopBrowsingForPeers]; [self.advertiser stopAdvertisingPeer];
            self.status = [NSString stringWithFormat:@"Соединено с %@. Каждое действие подтверждается владельцем принимающего iPhone.", peer.displayName];
        } else if (state == MCSessionStateNotConnected) {
            [self stop];
            if (self.presentedViewController) [self dismissViewControllerAnimated:YES completion:nil];
            self.status = @"Соединение разорвано. Это НЕ отмена и НЕ подтверждение результата. Перед повтором проверь принимающий iPhone.";
        }
        [self refresh];
    });
}
- (void)session:(MCSession *)session didReceiveData:(NSData *)data fromPeer:(MCPeerID *)peer {
    // Reject an oversized frame before dispatching or parsing it.
    if (data.length > CSNearbyMessageLimit) return;
    dispatch_async(dispatch_get_main_queue(), ^{
        if (session != self.session || ![peer isEqual:self.partner] || !self.connected) return;
        NSDictionary *message = CSDecode(data); if (!message) return;
        if ([message[@"type"] isEqual:@"request"]) { [self handleRequest:message]; return; }
        if (self.mode != 1 || ![message[@"id"] isEqual:self.outgoingID]) return;
        self.outgoingID = nil;
        NSString *state = message[@"state"];
        if ([state isEqual:@"done"]) {
            self.status = [NSString stringWithFormat:@"Действие завершено. SIM: %@. Каталог: %@. Выбор профиля iOS: %@. Это не гарантия VoWiFi/5G.", message[@"sims"], [message[@"catalog"] boolValue] ? @"проверен" : @"не подтверждён / не менялся", [message[@"confirmed"] boolValue] ? @"подтверждён" : @"не подтверждён / не проверялся"];
        } else self.status = [@{@"failed":@"Действие не завершено. Проверь журнал на принимающем iPhone.", @"declined":@"Владелец отклонил запрос либо время подтверждения истекло.", @"not_ready":@"Принимающий iPhone не готов. Проверь его сопряжение и локальный VPN.", @"busy":@"Принимающий iPhone занят. Дождись результата на нём."} objectForKey:state];
        if ([message[@"recovery"] boolValue]) self.status = [self.status stringByAppendingString:@" Требуется локальное восстановление на принимающем iPhone."];
        [self refresh];
    });
}
- (void)browser:(MCNearbyServiceBrowser *)browser foundPeer:(MCPeerID *)peer withDiscoveryInfo:(NSDictionary<NSString *,NSString *> *)info {
    dispatch_async(dispatch_get_main_queue(), ^{ if (browser != self.browser || ![info[@"v"] isEqual:@"1"] || [self.peers containsObject:peer] || self.peers.count >= 32) return; [self.peers addObject:peer]; [self refresh]; });
}
- (void)browser:(MCNearbyServiceBrowser *)browser lostPeer:(MCPeerID *)peer {
    dispatch_async(dispatch_get_main_queue(), ^{ if (browser == self.browser) { [self.peers removeObject:peer]; [self refresh]; } });
}
- (void)browser:(MCNearbyServiceBrowser *)browser didNotStartBrowsingForPeers:(NSError *)error {
    dispatch_async(dispatch_get_main_queue(), ^{ if (browser != self.browser) return; [self stop]; [self notice:@"Поиск не запущен" text:@"Проверь разрешение «Локальная сеть» для CarrierSIM и включи Wi-Fi/Bluetooth. Гостевая Wi-Fi сеть может изолировать устройства."]; });
}
- (void)advertiser:(MCNearbyServiceAdvertiser *)advertiser didNotStartAdvertisingPeer:(NSError *)error {
    dispatch_async(dispatch_get_main_queue(), ^{ if (advertiser != self.advertiser) return; [self stop]; [self notice:@"Телефон не виден" text:@"Разреши CarrierSIM доступ к локальной сети и повтори включение приёма помощи."]; });
}
- (void)advertiser:(MCNearbyServiceAdvertiser *)advertiser didReceiveInvitationFromPeer:(MCPeerID *)peer withContext:(NSData *)context invitationHandler:(void (^)(BOOL, MCSession *))handler {
    if (!context || context.length > 256) { handler(NO, nil); return; }
    dispatch_async(dispatch_get_main_queue(), ^{
        id value = [NSJSONSerialization JSONObjectWithData:context options:0 error:nil];
        NSString *code = [value isKindOfClass:NSDictionary.class] ? value[@"code"] : nil;
        BOOL digits = CSString(code, 6) && code.length == 6 && [code rangeOfCharacterFromSet:[NSCharacterSet characterSetWithCharactersInString:@"0123456789"].invertedSet].location == NSNotFound;
        if (advertiser != self.advertiser || self.mode != 2 || self.partner || self.invitationReply || self.executing || self.presentedViewController || UIApplication.sharedApplication.applicationState != UIApplicationStateActive || !digits || !CSKeys(value, @[@"v", @"code"]) || !CSInteger(value[@"v"], 1, 1)) { handler(NO, nil); return; }
        self.invitationReply = handler;
        NSUInteger epoch = self.epoch;
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Запрос помощи" message:[NSString stringWithFormat:@"%@ хочет подключиться. Код: %@. Сравни его с кодом на втором iPhone. Это разрешает только соединение; действия подтверждаются отдельно.", peer.displayName, code] preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"Отклонить" style:UIAlertActionStyleCancel handler:^(UIAlertAction *a) { if (self.epoch == epoch && self.invitationReply) { self.invitationReply(NO, nil); self.invitationReply = nil; } }]];
        [alert addAction:[UIAlertAction actionWithTitle:@"Код совпадает, подключить" style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
            if (self.epoch != epoch || !self.invitationReply) return;
            self.partner = peer; self.code = code;
            self.invitationReply(YES, self.session); self.invitationReply = nil; [self refresh];
        }]];
        [self presentViewController:alert animated:YES completion:nil];
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 55 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
            if (self.epoch == epoch && self.invitationReply) { self.invitationReply(NO, nil); self.invitationReply = nil; [alert dismissViewControllerAnimated:YES completion:nil]; }
        });
    });
}
// Only small command/result messages are accepted, never files or byte streams.
- (void)session:(MCSession *)session didReceiveStream:(NSInputStream *)stream withName:(NSString *)name fromPeer:(MCPeerID *)peer { [stream close]; }
- (void)session:(MCSession *)session didStartReceivingResourceWithName:(NSString *)name fromPeer:(MCPeerID *)peer withProgress:(NSProgress *)progress { [progress cancel]; }
- (void)session:(MCSession *)session didFinishReceivingResourceWithName:(NSString *)name fromPeer:(MCPeerID *)peer atURL:(NSURL *)url withError:(NSError *)error { /* No imported or executed resource. */ }
@end
