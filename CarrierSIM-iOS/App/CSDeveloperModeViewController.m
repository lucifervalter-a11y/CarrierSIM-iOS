#import "CSDeveloperModeViewController.h"
#import "airlift.h"

static NSString *CSModeString(id value) { return [value isKindOfClass:NSString.class] ? value : @""; }

@interface CSDeveloperModeViewController ()
@property (nonatomic, copy) NSString *pairingPath;
@property (nonatomic, copy) NSDictionary *target;
@property (nonatomic, strong) NSURL *work;
@property (nonatomic, strong) dispatch_queue_t queue;
@property (nonatomic, strong) NSDictionary *result;
@property (nonatomic, copy) NSString *message;
@property (nonatomic, copy) NSString *waitingHash;
@property (nonatomic, strong) NSDate *waitingSince;
@property (nonatomic, strong) NSTimer *timer;
@property (nonatomic) BOOL busy;
@property (nonatomic) BOOL visible;
@end

@implementation CSDeveloperModeViewController
- (instancetype)initWithPairingPath:(NSString *)pairingPath workDirectory:(NSURL *)work
                             target:(NSDictionary *)target operationQueue:(dispatch_queue_t)queue {
    if ((self=[super initWithStyle:UITableViewStyleInsetGrouped])) {
        _pairingPath=[pairingPath copy]; _work=work; _target=[target copy]; _queue=queue;
        _message=@"Проверь выбранный iPhone, затем запроси показ пункта в его настройках. Владелец подтверждает действия на своём телефоне.";
        NSDictionary *pending=[NSDictionary dictionaryWithContentsOfURL:[self pendingURL]];
        NSString *hash=CSModeString(pending[@"identity"]);
        if (hash.length==64 && [pending[@"started"] isKindOfClass:NSDate.class]) {
            _waitingHash=hash;_waitingSince=pending[@"started"];
        }
        [NSNotificationCenter.defaultCenter addObserver:self selector:@selector(active) name:UIApplicationDidBecomeActiveNotification object:nil];
        [NSNotificationCenter.defaultCenter addObserver:self selector:@selector(inactive) name:UIApplicationWillResignActiveNotification object:nil];
    } return self;
}
+ (BOOL)hasPendingAtDirectory:(NSURL *)work {
    return [NSFileManager.defaultManager fileExistsAtPath:[[work URLByAppendingPathComponent:@"developer-mode-pending.plist"] path]];
}
- (NSURL *)pendingURL {return [self.work URLByAppendingPathComponent:@"developer-mode-pending.plist"];}
- (void)dealloc { [self.timer invalidate];[NSNotificationCenter.defaultCenter removeObserver:self]; }
- (void)viewDidLoad {
    [super viewDidLoad];self.title=@"Режим разработчика";
    self.tableView.rowHeight=UITableViewAutomaticDimension;self.tableView.estimatedRowHeight=72;
}
- (void)viewDidAppear:(BOOL)animated {
    [super viewDidAppear:animated];self.visible=YES;
    if (self.waitingSince && -self.waitingSince.timeIntervalSinceNow>300) {
        [self stopWaiting];self.message=@"Время ожидания истекло. Состояние неизвестно: проверь экран выбранного iPhone и нажми «Проверить состояние».";
    }
    if (!self.busy) [self run:@"status"];
}
- (void)viewWillDisappear:(BOOL)animated {
    [super viewWillDisappear:animated];self.visible=NO;[self.timer invalidate];self.timer=nil;
}
- (void)inactive { [self.timer invalidate];self.timer=nil; }
- (void)active { if (self.visible && !self.busy && self.waitingSince) [self tick]; }
- (void)notify:(NSDictionary *)result {
    if (self.onState) self.onState(result,self.busy,self.waitingSince!=nil);
    [self.tableView reloadData];
}
- (void)alert:(NSString *)title message:(NSString *)message {
    UIAlertController *alert=[UIAlertController alertControllerWithTitle:title message:message preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"Понятно" style:UIAlertActionStyleDefault handler:nil]];
    if (self.visible && !self.presentedViewController) [self presentViewController:alert animated:YES completion:nil];
}
- (NSString *)identity { return self.waitingHash ?: CSModeString(self.result[@"device"][@"identity_hash"]); }
- (BOOL)startWaiting:(NSString *)hash {
    if (hash.length!=64) return NO;
    self.waitingHash=hash;self.waitingSince=NSDate.date;
    NSData *record=[NSPropertyListSerialization dataWithPropertyList:@{@"identity":hash,@"started":self.waitingSince}
        format:NSPropertyListBinaryFormat_v1_0 options:0 error:nil];
    BOOL saved=[record writeToURL:[self pendingURL] options:NSDataWritingAtomic|NSDataWritingFileProtectionCompleteUntilFirstUserAuthentication error:nil];
    saved=saved && [NSFileManager.defaultManager setAttributes:@{NSFilePosixPermissions:@0600} ofItemAtPath:[self pendingURL].path error:nil];
    [[self pendingURL] setResourceValue:@YES forKey:NSURLIsExcludedFromBackupKey error:nil];
    if (!saved) self.message=[self.message stringByAppendingString:@"\nНе удалось сохранить ожидание. Оставь CarrierSIM открытым и повторно проверь состояние после перезагрузки."];
    [self schedule];return saved;
}
- (void)stopWaiting {
    [self.timer invalidate];self.timer=nil;self.waitingHash=nil;self.waitingSince=nil;
    [NSFileManager.defaultManager removeItemAtURL:[self pendingURL] error:nil];
    [self notify:self.result];
}
- (void)schedule {
    [self.timer invalidate];self.timer=nil;
    if (self.visible && self.waitingSince && !self.busy && UIApplication.sharedApplication.applicationState==UIApplicationStateActive) {
        __weak typeof(self) weakSelf=self;
        self.timer=[NSTimer scheduledTimerWithTimeInterval:10 repeats:NO block:^(NSTimer *timer){[weakSelf tick];}];
    }
}
- (void)tick {
    if (!self.waitingSince || self.busy) return;
    if (-self.waitingSince.timeIntervalSinceNow>=300) {
        [self stopWaiting];self.message=@"За 5 минут включение не подтверждено. Проверь экран iPhone и актуальный адрес Wi-Fi. Запрос включения не повторялся.";
        [self.tableView reloadData];return;
    }
    [self run:@"status"];
}
- (void)run:(NSString *)action {
    if (self.busy || (self.waitingSince && ![action isEqualToString:@"status"])) return;
    NSString *hash=[self identity];
    if (![action isEqualToString:@"status"] && hash.length!=64) return;
    NSMutableDictionary *request=[@{@"action":action} mutableCopy];
    if (self.target) request[@"target"]=self.target;
    if (hash.length==64) request[@"expected_device_hash"]=hash;
    // Persist the intent before a reboot request: a killed/suspended app must
    // resume with reads only, never silently retry the state-changing action.
    if ([action isEqualToString:@"request_enable"] && ![self startWaiting:hash]) {
        [self stopWaiting];self.message=@"Не удалось сохранить ожидание. Запрос включения не отправлен. Освободи память или включи режим вручную.";
        [self notify:self.result];return;
    }
    NSString *text=[[NSString alloc] initWithData:[NSJSONSerialization dataWithJSONObject:request options:0 error:nil] encoding:NSUTF8StringEncoding];
    self.busy=YES;self.message=[action isEqualToString:@"status"] ? @"Проверяю выбранный iPhone и состояние режима…" : @"Отправляю запрос на проверенный iPhone…";
    [self notify:nil];
    dispatch_async(self.queue,^{
        @autoreleasepool {
            char *output=NULL,*errorText=NULL;
            int32_t code=cs_developer_mode(self.pairingPath.UTF8String,self.work.path.UTF8String,text.UTF8String,NULL,NULL,&output,&errorText);
            NSDictionary *result=output ? [NSJSONSerialization JSONObjectWithData:[[NSString stringWithUTF8String:output] dataUsingEncoding:NSUTF8StringEncoding] options:0 error:nil] : nil;
            if (![result isKindOfClass:NSDictionary.class]) result=nil;
            NSString *error=errorText ? [NSString stringWithUTF8String:errorText] : nil;
            if (output) al_string_free(output);if (errorText) al_string_free(errorText);
            dispatch_async(dispatch_get_main_queue(),^{
                self.busy=NO;
                if (code==0 && result) {
                    self.result=result;self.message=CSModeString(result[@"message"]);
                    NSString *capability=CSModeString(result[@"capability_error"]);
                    if (capability.length && ![CSModeString(result[@"status"]) isEqualToString:@"on"]) self.message=[self.message stringByAppendingFormat:@"\n%@",capability];
                    if ([result[@"waiting_needed"] boolValue] && !self.waitingSince) [self startWaiting:hash];
                    if ([action isEqualToString:@"request_enable"] && ![result[@"waiting_needed"] boolValue]) [self stopWaiting];
                    if (self.waitingSince && [CSModeString(result[@"status"]) isEqualToString:@"on"]) {
                        [self stopWaiting];self.message=@"Включение подтверждено iOS на том же iPhone. Можно вернуться к установке или применению профиля.";
                    }
                } else {
                    // Keep the durable pending intent on an unclassified FFI
                    // failure: a reboot may already have been requested.
                    self.result=nil;
                    self.message=error.length ? error : @"Проверка не завершилась. Проверь подключение и экран выбранного iPhone.";
                    if (self.waitingSince) self.message=[self.message stringByAppendingString:@"\nОжидаю возвращения телефона; запрос включения не повторяется. При смене IP вернись к выбору адреса."];
                }
                [self notify:self.result];if (self.onLog) self.onLog(self.message);
                [self schedule];
                if (![action isEqualToString:@"status"]) [self alert:@"Результат запроса" message:self.message];
            });
        }
    });
}
- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {return 2;}
- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {return section==0 ? 1 : 4;}
- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section {return section==0 ? @"Выбранный iPhone" : @"Действия";}
- (NSString *)tableView:(UITableView *)tableView titleForFooterInSection:(NSInteger)section {
    return section==1 ? @"При установленном код-пароле iOS может потребовать ручное включение. Владелец подтверждает включение после перезагрузки. Если пункта нет и соединение недоступно, сначала начните доверенное сопряжение через компьютер. Прямой кабель между двумя iPhone пока не поддерживается." : nil;
}
- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)path {
    UITableViewCell *cell=[[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:nil];
    cell.textLabel.numberOfLines=0;cell.detailTextLabel.numberOfLines=0;
    cell.detailTextLabel.textColor=UIColor.secondaryLabelColor;
    BOOL enabled=!self.busy;
    if (path.section==0) {
        NSString *name=CSModeString(self.result[@"device"][@"name"]),*model=CSModeString(self.result[@"device"][@"model"]);
        cell.textLabel.text=name.length ? [NSString stringWithFormat:@"%@ · %@",name,model] : (self.target ? @"iPhone друга" : @"Этот iPhone");
        cell.detailTextLabel.text=self.message;enabled=NO;
    } else {
        NSArray *titles=@[@"Проверить состояние",@"Показать пункт в настройках",@"Запросить включение",self.waitingSince ? @"Остановить ожидание" : @"Ждать после ручного включения"];
        cell.textLabel.text=titles[path.row];
        if (path.row==1) enabled=enabled && !self.waitingSince && [self.result[@"amfi_available"] boolValue];
        if (path.row==2) enabled=enabled && !self.waitingSince && [self.result[@"amfi_available"] boolValue] && ![self.result[@"needs_recovery"] boolValue] && [CSModeString(self.result[@"status"]) isEqualToString:@"off"];
        if (path.row==3) enabled=enabled && (self.waitingSince || [self identity].length==64);
        if (path.row==2) cell.detailTextLabel.text=@"Выбранный iPhone может перезагрузиться";
        if (path.row==3) cell.detailTextLabel.text=@"Только чтение состояния, до 5 минут";
    }
    cell.selectionStyle=enabled ? UITableViewCellSelectionStyleDefault : UITableViewCellSelectionStyleNone;
    cell.textLabel.textColor=enabled ? UIColor.labelColor : UIColor.tertiaryLabelColor;
    cell.userInteractionEnabled=enabled;return cell;
}
- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)path {
    [tableView deselectRowAtIndexPath:path animated:YES];if (path.section!=1 || self.busy) return;
    if (path.row==0){[self run:@"status"];return;}
    if (path.row==1){[self run:@"reveal"];return;}
    if (path.row==3){
        if (self.waitingSince){[self stopWaiting];self.message=@"Ожидание остановлено. Для подтверждения состояния нажми «Проверить состояние».";}
        else {[self startWaiting:[self identity]];self.message=@"Жду возвращения выбранного iPhone. Владелец подтверждает включение после перезагрузки.";[self notify:self.result];}
        [self.tableView reloadData];return;
    }
    if (self.waitingSince || ![self.result[@"amfi_available"] boolValue] || [self.result[@"needs_recovery"] boolValue]) return;
    NSString *name=CSModeString(self.result[@"device"][@"name"]);
    UIAlertController *alert=[UIAlertController alertControllerWithTitle:@"Запросить включение?"
        message:[NSString stringWithFormat:@"iPhone: %@\n\nТелефон может перезагрузиться. Владелец должен сохранить свою работу и подтвердить включение после перезагрузки. При отказе из-за код-пароля используйте переключатель в настройках.",name]
        preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"Отмена" style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"Запросить" style:UIAlertActionStyleDefault handler:^(UIAlertAction *a){[self run:@"request_enable"];}]];
    [self presentViewController:alert animated:YES completion:nil];
}
@end
