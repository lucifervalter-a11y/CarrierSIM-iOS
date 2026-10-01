#import "CSMainViewController.h"
#import "CSConnectionManager.h"
#import "airlift.h"
#import "CSLANBrowserViewController.h"
#import "CSDeveloperModeViewController.h"
#import "CSShareViewController.h"
#import <arpa/inet.h>
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>

// Kept here as well as the Rust header so the app interface is explicit.
extern int32_t cs_execute(const char *, const char *, const char *, const char *, ALLogCallback, void *, char **, char **);

static NSString *CSText(id value) {
    return [value isKindOfClass:NSString.class] ? value : @"";
}

static NSString *CSRedact(NSString *input) {
    if (!input) return @"";
    NSString *lower = input.lowercaseString;
    for (NSString *secret in @[@"private_key", @"privatekey", @"private key", @"begin certificate", @"hostcertificate", @"pairrecord", @"pairing record:", @"pin issued"]) {
        if ([lower containsString:secret]) return @"[Служебные данные сопряжения скрыты]";
    }
    NSMutableString *result = [input mutableCopy];
    for (NSString *pattern in @[@"(?<![0-9])[0-9]{15,22}(?![0-9])", @"(?i)(?<![a-f0-9])[a-f0-9]{8}-[a-f0-9]{16}(?![a-f0-9])", @"(?i)(?<![a-f0-9])[a-f0-9]{32,}(?![a-f0-9])"]) {
        NSRegularExpression *regex = [NSRegularExpression regularExpressionWithPattern:pattern options:0 error:nil];
        [regex replaceMatchesInString:result options:0 range:NSMakeRange(0, result.length) withTemplate:@"[скрыто]"];
    }
    return result;
}

@interface CSMainViewController () <UIDocumentPickerDelegate>
@property (nonatomic, strong) CSConnectionManager *connection;
@property (nonatomic, copy) NSDictionary *remoteTarget;
@property (nonatomic, copy) NSDictionary *installationDevice;
@property (nonatomic) BOOL developerWaiting;
@property (nonatomic) BOOL selectingIPA;
@property (nonatomic, strong) NSURL *workDirectory;
@property (nonatomic, strong) NSMutableArray<NSString *> *logLines;
@property (nonatomic, strong) NSDictionary *snapshot;
@property (nonatomic, strong) NSDictionary *operationResult;
@property (nonatomic, copy) NSString *bundleName;
@property (nonatomic, copy) NSString *lastMessage;
@property (nonatomic, copy) NSString *pairingPIN;
@property (nonatomic) NSInteger SIMSelection;
@property (nonatomic) BOOL busy;
@property (nonatomic) BOOL connectionChecked;
@property (nonatomic) BOOL needsRecovery;
@property (nonatomic) UIBackgroundTaskIdentifier backgroundTask;
@property (nonatomic, strong) dispatch_queue_t operationQueue;
- (void)appendLog:(NSString *)line;
@end

static void CSLogCallback(void *context, const char *message) {
    if (!context || !message) return;
    NSString *copy = CSRedact([NSString stringWithUTF8String:message] ?: @"");
    CSMainViewController *controller = (__bridge CSMainViewController *)context;
    dispatch_async(dispatch_get_main_queue(), ^{ [controller appendLog:copy]; });
}

@implementation CSMainViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"CarrierSIM";
    self.tableView.backgroundColor = UIColor.systemGroupedBackgroundColor;
    self.tableView.estimatedRowHeight = 72;
    self.tableView.rowHeight = UITableViewAutomaticDimension;
    self.tableView.cellLayoutMarginsFollowReadableWidth = YES;
    self.bundleName = @"Vodafone_hu";
    self.lastMessage = @"Начни с подключения. Все нужные пакеты уже внутри приложения.";
    self.logLines = NSMutableArray.array;
    self.backgroundTask = UIBackgroundTaskInvalid;
    self.operationQueue = dispatch_queue_create("com.tema.CarrierSIM.operations", DISPATCH_QUEUE_SERIAL);
    NSURL *support = [NSFileManager.defaultManager URLsForDirectory:NSApplicationSupportDirectory inDomains:NSUserDomainMask].firstObject;
    self.workDirectory = [support URLByAppendingPathComponent:@"CarrierSIM/runs" isDirectory:YES];
    NSError *directoryError = nil;
    [NSFileManager.defaultManager createDirectoryAtURL:self.workDirectory withIntermediateDirectories:YES attributes:@{NSFileProtectionKey:NSFileProtectionCompleteUntilFirstUserAuthentication} error:&directoryError];
    [self.workDirectory setResourceValue:@YES forKey:NSURLIsExcludedFromBackupKey error:nil];
    if (directoryError) self.lastMessage = @"Не удалось создать место для резервных копий. Освободи память и перезапусти приложение.";
    NSDictionary *savedTarget = [NSUserDefaults.standardUserDefaults dictionaryForKey:@"CarrierSIM.remoteTarget"];
    if ([NSUserDefaults.standardUserDefaults boolForKey:@"CarrierSIM.remoteMode"] && [savedTarget[@"host"] isKindOfClass:NSString.class]) self.remoteTarget = savedTarget;
    [self configureConnection];
    [NSNotificationCenter.defaultCenter addObserver:self selector:@selector(becameActive) name:UIApplicationDidBecomeActiveNotification object:nil];
    [self buildHeader];
    [self appendLog:@"CarrierSIM 1.2.1 • Подпись P12, подготовка режима разработчика и прямое применение профиля другу."];
}


- (void)configureConnection {
    self.connection = [[CSConnectionManager alloc] initWithTargetIdentifier:self.remoteTarget ? @"remote" : nil];
    __weak typeof(self) weakSelf = self;
    self.connection.onStatus = ^(NSString *status) {
        [weakSelf appendLog:CSRedact(status)];
        [weakSelf.tableView reloadData];
    };
    self.connection.onPIN = ^(NSString *pin) {
        weakSelf.pairingPIN = pin;
        [weakSelf.tableView reloadData];
    };
    self.connection.onPairingDone = ^(NSError *error) {
        weakSelf.pairingPIN = nil;
        weakSelf.connectionChecked = NO;
        weakSelf.snapshot = nil;
        weakSelf.installationDevice = nil;
        weakSelf.lastMessage = error ? CSRedact(error.localizedDescription) : (weakSelf.remoteTarget ? @"Сопряжение сохранено. Проверь адрес и порт iPhone друга, затем нажми «Проверить iPhone»." : @"Сопряжение сохранено. Теперь включи локальное подключение и нажми «Проверить iPhone».");
        [weakSelf.tableView reloadData];
    };

    NSURL *support = [NSFileManager.defaultManager URLsForDirectory:NSApplicationSupportDirectory inDomains:NSUserDomainMask].firstObject;
    self.workDirectory = [support URLByAppendingPathComponent:self.remoteTarget ? @"CarrierSIM/remote/runs" : @"CarrierSIM/runs" isDirectory:YES];
    [NSFileManager.defaultManager createDirectoryAtURL:self.workDirectory withIntermediateDirectories:YES attributes:@{NSFileProtectionKey:NSFileProtectionCompleteUntilFirstUserAuthentication, NSFilePosixPermissions:@0700} error:nil];
    [self.workDirectory setResourceValue:@YES forKey:NSURLIsExcludedFromBackupKey error:nil];
    self.connectionChecked = NO; self.snapshot = nil; self.operationResult = nil; self.needsRecovery = NO; self.pairingPIN = nil;
    self.installationDevice = nil;
    self.developerWaiting = [CSDeveloperModeViewController hasPendingAtDirectory:self.workDirectory];
}

- (NSString *)targetName {
    NSString *name = CSText(self.installationDevice[@"name"]);
    if (!name.length) name = CSText(self.snapshot[@"device"][@"name"]);
    return name.length ? name : (self.remoteTarget ? @"iPhone друга" : @"этот iPhone");
}

- (void)targetMenu {
    UIAlertController *sheet = [UIAlertController alertControllerWithTitle:@"С каким iPhone работать" message:@"Для iPhone друга подключитесь к одной Wi-Fi-сети. У каждого телефона свои ключи и резервные копии." preferredStyle:UIAlertControllerStyleActionSheet];
    [sheet addAction:[UIAlertAction actionWithTitle:@"Этот iPhone" style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
        self.remoteTarget = nil; [NSUserDefaults.standardUserDefaults setBool:NO forKey:@"CarrierSIM.remoteMode"];
        [self configureConnection]; self.lastMessage = @"Выбран этот iPhone. Включи локальное подключение и проверь его."; [self.tableView reloadData];
    }]];
    [sheet addAction:[UIAlertAction actionWithTitle:@"Другой iPhone: найти в Wi-Fi" style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) { [self findRemotePhone]; }]];
    [sheet addAction:[UIAlertAction actionWithTitle:@"Другой iPhone: указать адрес" style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) { [self enterRemoteAddress:nil port:0]; }]];
    [sheet addAction:[UIAlertAction actionWithTitle:@"Отмена" style:UIAlertActionStyleCancel handler:nil]]; [self presentSheet:sheet];
}

- (void)enterRemoteAddress:(NSString *)host port:(NSInteger)port {
    NSDictionary *saved = self.remoteTarget ?: [NSUserDefaults.standardUserDefaults dictionaryForKey:@"CarrierSIM.remoteTarget"];
    UIAlertController *entry = [UIAlertController alertControllerWithTitle:@"Другой iPhone" message:@"Адрес друга: Настройки → Wi-Fi → ⓘ → IP-адрес. Порт службы можно выбрать через поиск в Wi-Fi; 49152 — начальное значение для Remote Pairing. С готовым Lockdown-сопряжением используется порт 62078. После выбора открой «Режим разработчика» и проверь телефон. Для первоначального доверия может потребоваться компьютер." preferredStyle:UIAlertControllerStyleAlert];
    [entry addTextFieldWithConfigurationHandler:^(UITextField *f) { f.placeholder = @"192.168.1.25"; f.text = host ?: CSText(saved[@"host"]); f.keyboardType = UIKeyboardTypeDecimalPad; }];
    [entry addTextFieldWithConfigurationHandler:^(UITextField *f) { f.placeholder = @"Порт RSD / Remote Pairing"; f.text = port > 0 ? [@(port) stringValue] : [saved[@"rsd_port"] description] ?: @"49152"; f.keyboardType = UIKeyboardTypeNumberPad; }];
    [entry addAction:[UIAlertAction actionWithTitle:@"Отмена" style:UIAlertActionStyleCancel handler:nil]];
    [entry addAction:[UIAlertAction actionWithTitle:@"Выбрать" style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
        NSString *ip = [entry.textFields[0].text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
        struct in_addr addr; NSInteger p = entry.textFields[1].text.integerValue;
        uint32_t value = inet_pton(AF_INET, ip.UTF8String, &addr) == 1 ? ntohl(addr.s_addr) : 0;
        BOOL local = (value >> 24) == 10 || (value >> 20) == 0xAC1 || (value >> 16) == 0xC0A8 || (value >> 16) == 0xA9FE;
        BOOL loopbackVPN = (value & 0xFFFFFF00) == 0x0A070000 && (value & 255) >= 1 && (value & 255) <= 3;
        if (!local || loopbackVPN || p < 1 || p > 65535) { [self message:@"Проверь адрес" text:@"Нужен IPv4-адрес iPhone друга в локальной сети и порт от 1 до 65535."]; return; }
        [self.connection stopVPN];
        self.remoteTarget = @{@"host":ip, @"rsd_port":@(p)};
        [NSUserDefaults.standardUserDefaults setObject:self.remoteTarget forKey:@"CarrierSIM.remoteTarget"];
        [NSUserDefaults.standardUserDefaults setBool:YES forKey:@"CarrierSIM.remoteMode"];
        [self configureConnection];
        self.lastMessage = @"Выбран iPhone друга. Создай сопряжение, подтвердив код на его телефоне, или импортируй его pairing-файл. Затем проверь iPhone.";
        [self.tableView reloadData];
    }]]; [self presentViewController:entry animated:YES completion:nil];
}

- (void)dealloc { [NSNotificationCenter.defaultCenter removeObserver:self]; }

- (void)becameActive {
    [self.connection refreshVPNStatus];
    [self.tableView reloadData];
}

- (void)buildHeader {
    CGFloat width = self.view.bounds.size.width;
    UIView *holder = [[UIView alloc] initWithFrame:CGRectMake(0, 0, width, 162)];
    UIView *card = UIView.new;
    card.translatesAutoresizingMaskIntoConstraints = NO;
    card.backgroundColor = [UIColor colorWithRed:0.03 green:0.29 blue:0.29 alpha:1];
    card.layer.cornerRadius = 24;
    UIImageView *icon = [[UIImageView alloc] initWithImage:[UIImage systemImageNamed:@"simcard.fill"]];
    icon.tintColor = [UIColor colorWithRed:0.45 green:0.97 blue:0.8 alpha:1];
    icon.contentMode = UIViewContentModeScaleAspectFit;
    icon.translatesAutoresizingMaskIntoConstraints = NO;
    UILabel *title = UILabel.new;
    title.text = @"Твой iPhone.\nТвой профиль связи.";
    title.numberOfLines = 2;
    title.font = [UIFont systemFontOfSize:22 weight:UIFontWeightBold];
    title.textColor = UIColor.whiteColor;
    title.translatesAutoresizingMaskIntoConstraints = NO;
    UILabel *caption = UILabel.new;
    caption.text = @"iOS 26+ · экспериментальная версия";
    caption.font = [UIFont systemFontOfSize:12 weight:UIFontWeightMedium];
    caption.textColor = [UIColor colorWithWhite:1 alpha:0.72];
    caption.translatesAutoresizingMaskIntoConstraints = NO;
    [holder addSubview:card]; [card addSubview:icon]; [card addSubview:title]; [card addSubview:caption];
    [NSLayoutConstraint activateConstraints:@[
        [card.leadingAnchor constraintEqualToAnchor:holder.leadingAnchor constant:20],
        [card.trailingAnchor constraintEqualToAnchor:holder.trailingAnchor constant:-20],
        [card.topAnchor constraintEqualToAnchor:holder.topAnchor constant:4],
        [card.bottomAnchor constraintEqualToAnchor:holder.bottomAnchor constant:-8],
        [icon.leadingAnchor constraintEqualToAnchor:card.leadingAnchor constant:20],
        [icon.centerYAnchor constraintEqualToAnchor:card.centerYAnchor constant:-5],
        [icon.widthAnchor constraintEqualToConstant:50], [icon.heightAnchor constraintEqualToConstant:60],
        [title.leadingAnchor constraintEqualToAnchor:icon.trailingAnchor constant:16],
        [title.topAnchor constraintEqualToAnchor:card.topAnchor constant:25],
        [title.trailingAnchor constraintEqualToAnchor:card.trailingAnchor constant:-14],
        [caption.leadingAnchor constraintEqualToAnchor:title.leadingAnchor],
        [caption.topAnchor constraintEqualToAnchor:title.bottomAnchor constant:10],
        [caption.trailingAnchor constraintLessThanOrEqualToAnchor:card.trailingAnchor constant:-12]
    ]];
    self.tableView.tableHeaderView = holder;
}

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView { return 5; }
- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    return section == 0 ? 8 : section == 1 ? 3 : section == 2 ? 3 : 2;
}
- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section {
    return @[@"1. Подключение", @"2. SIM и профиль", @"3. Действие", @"Результат", @"Помощь"][section];
}
- (NSString *)tableView:(UITableView *)tableView titleForFooterInSection:(NSInteger)section {
    if (section == 0 && self.remoteTarget) return self.developerWaiting ? @"Ожидается подтверждение режима разработчика. Открой этот раздел и проверь состояние либо останови ожидание." : @"Можно применить профиль напрямую без CarrierSIM на телефоне друга. Чтобы передать сам CarrierSIM, проверь телефон и выбери «Отправить CarrierSIM другу».";
    if (section == 0) return @"Сопряжение создаётся один раз. Разрешения на локальную сеть, VPN и сопряжение подтверждаются в iOS.";
    if (section == 1) return @"По умолчанию выбран Vodafone_hu, как в твоём архиве. Это выбор настроек iPhone; тариф и SIM не меняются.";
    if (section == 2) return self.busy ? @"Идёт операция. Оставь CarrierSIM открытым и не отключай локальное VPN-подключение." : @"Перед записью создаётся копия. «Штатные профили» удаляет IMSI-ссылки для всех SIM. «Восстановление» завершает прерванную операцию.";
    if (section == 4) return @"ОРИГИНАЛ ВЗЯТ ИЗ IOS-BUNDLES/CARRIERSIM: https://github.com/ios-bundles/CarrierSIM\nCarrierSIM 1.2 · AirLift, AirCard-iOS, idevice, LocalDevVPN и isideload-apple-codesign.";
    return nil;
}

- (UITableViewCell *)cellWithTitle:(NSString *)title detail:(NSString *)detail symbol:(NSString *)symbol enabled:(BOOL)enabled {
    UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:nil];
    cell.textLabel.text = title;
    cell.textLabel.font = [UIFont preferredFontForTextStyle:UIFontTextStyleBody];
    cell.textLabel.adjustsFontForContentSizeCategory = YES;
    cell.textLabel.numberOfLines = 0;
    cell.detailTextLabel.text = detail;
    cell.detailTextLabel.font = [UIFont preferredFontForTextStyle:UIFontTextStyleFootnote];
    cell.detailTextLabel.adjustsFontForContentSizeCategory = YES;
    cell.detailTextLabel.numberOfLines = 0;
    cell.detailTextLabel.textColor = UIColor.secondaryLabelColor;
    cell.imageView.image = [UIImage systemImageNamed:symbol];
    cell.imageView.tintColor = enabled ? self.view.tintColor : UIColor.tertiaryLabelColor;
    cell.textLabel.textColor = enabled ? UIColor.labelColor : UIColor.tertiaryLabelColor;
    cell.selectionStyle = enabled ? UITableViewCellSelectionStyleDefault : UITableViewCellSelectionStyleNone;
    cell.accessoryType = enabled ? UITableViewCellAccessoryDisclosureIndicator : UITableViewCellAccessoryNone;
    cell.accessibilityLabel = [NSString stringWithFormat:@"%@. %@", title, detail ?: @""];
    return cell;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    BOOL idle = !self.busy && !self.connection.isPairing && !self.connection.isImporting;
    NSInteger row = indexPath.row;
    if (indexPath.section == 0) {
        if (row == 4) return [self cellWithTitle:@"Выбранный iPhone" detail:self.remoteTarget ? [NSString stringWithFormat:@"Другой iPhone · %@:%@", self.remoteTarget[@"host"], self.remoteTarget[@"rsd_port"]] : @"Этот iPhone" symbol:@"iphone.gen3.radiowaves.left.and.right" enabled:idle && !self.connection.isVPNStarting];
        if (row == 5) return [self cellWithTitle:@"Отправить CarrierSIM другу" detail:@"Подписать P12 и установить этот же CarrierSIM" symbol:@"square.and.arrow.up" enabled:idle && self.remoteTarget && self.installationDevice && !self.needsRecovery && !self.developerWaiting];
        if (row == 6) return [self cellWithTitle:@"Режим разработчика" detail:self.developerWaiting ? @"Ожидание после перезагрузки · проверить состояние" : @"Проверить телефон, показать пункт, запросить включение" symbol:@"hammer" enabled:idle && (self.connection.hasPairing || self.developerWaiting)];
        if (row == 7) return [self cellWithTitle:@"Установить готовый подписанный IPA" detail:@"Выбрать файл для проверенного iPhone друга" symbol:@"square.and.arrow.down" enabled:idle && self.remoteTarget && self.installationDevice && !self.needsRecovery && !self.developerWaiting];
        if (row == 0) {
            NSString *detail = self.connection.hasPairing ? (self.remoteTarget ? @"Сохранено отдельно для iPhone друга" : @"Сохранено на этом iPhone") : @"Создать внутри CarrierSIM, без компьютера";
            if (self.connection.isPairing) detail = self.pairingPIN.length ? [NSString stringWithFormat:@"Код для настроек: %@. Нажми, чтобы скопировать или остановить.", self.pairingPIN] : @"Открой настройки iOS → Режим разработчика → Сопряжение с CarrierSIM";
            return [self cellWithTitle:self.connection.isPairing ? @"Идёт сопряжение" : @"Сопряжение с iPhone" detail:detail symbol:@"link" enabled:!self.busy && !self.connection.isImporting];
        }
        if (row == 1 && self.remoteTarget) return [self cellWithTitle:@"Соединение по Wi-Fi" detail:[NSString stringWithFormat:@"%@:%@ · открыть настройки адреса", self.remoteTarget[@"host"], self.remoteTarget[@"rsd_port"]] symbol:@"wifi" enabled:idle];
        if (row == 1) return [self cellWithTitle:@"Локальное подключение" detail:self.connection.isVPNConnected ? @"Встроенный VPN включён" : (self.connection.isVPNStarting ? @"Подключается…" : (self.connection.hasEmbeddedVPN ? @"Включить встроенный локальный VPN" : @"Открыть LocalDevVPN для подключения")) symbol:@"network" enabled:idle && !self.connection.isVPNStarting];
        if (row == 2) return [self cellWithTitle:self.busy ? @"Подожди завершения операции" : @"Проверить iPhone и SIM" detail:@"Подготовить прямое применение профиля без установки другу" symbol:@"checkmark.shield" enabled:idle && self.connection.hasPairing];
        return [self cellWithTitle:@"Уже есть файл Stik Pair" detail:@"Импортировать .plist / .rppairing через «Файлы»" symbol:@"square.and.arrow.down" enabled:idle];
    }
    if (indexPath.section == 1) {
        if (row == 0) return [self cellWithTitle:@"Какие SIM изменить" detail:@[@"Все обнаруженные SIM", @"Только SIM 1", @"Только SIM 2"][self.SIMSelection] symbol:@"simcard.2" enabled:idle];
        if (row == 1) return [self cellWithTitle:@"Профиль оператора" detail:self.bundleName symbol:@"antenna.radiowaves.left.and.right" enabled:idle];
        NSArray *sims = [self.snapshot[@"sims"] isKindOfClass:NSArray.class] ? self.snapshot[@"sims"] : @[];
        NSMutableArray *rows = NSMutableArray.array;
        for (NSDictionary *sim in sims) {
            NSString *slot = [CSText(sim[@"slot"]) isEqualToString:@"kTwo"] ? @"SIM 2" : @"SIM 1";
            NSString *carrier = CSText(sim[@"carrier"]);
            if (!carrier.length) carrier = [NSString stringWithFormat:@"%@ %@", CSText(sim[@"mcc"]), CSText(sim[@"mnc"])];
            [rows addObject:[NSString stringWithFormat:@"%@: %@", slot, carrier]];
        }
        NSDictionary *device = self.snapshot[@"device"];
        NSString *name = CSText(device[@"name"]);
        NSString *ios = CSText(device[@"ios"]);
        NSString *detail = rows.count ? [rows componentsJoinedByString:@"\n"] : @"Появятся после проверки iPhone";
        if (name.length && ios.length) detail = [NSString stringWithFormat:@"%@ · iOS %@\n%@", name, ios, detail];
        return [self cellWithTitle:@"Обнаруженные SIM" detail:detail symbol:@"iphone" enabled:NO];
    }
    if (indexPath.section == 2) {
        BOOL ready = idle && self.connectionChecked && !self.needsRecovery && !self.developerWaiting;
        if (row == 0) {
            UITableViewCell *cell = [self cellWithTitle:@"Применить профиль" detail:@"Копия → запись → обратное чтение → проверка выбора iOS" symbol:@"bolt.shield.fill" enabled:ready && [self.snapshot[@"can_apply"] boolValue]];
            if (ready) cell.textLabel.textColor = self.view.tintColor;
            return cell;
        }
        if (row == 1) return [self cellWithTitle:@"Вернуть штатные профили" detail:@"Убрать IMSI-ссылки для всех SIM" symbol:@"arrow.uturn.backward" enabled:ready];
        return [self cellWithTitle:@"Восстановить после сбоя" detail:self.needsRecovery ? @"Есть незавершённая операция. Начни с восстановления." : @"Проверить и восстановить незавершённые изменения" symbol:@"cross.case" enabled:idle && self.connection.hasPairing];
    }
    if (indexPath.section == 3) {
        if (row == 0) {
            UITableViewCell *cell = [self cellWithTitle:self.busy ? @"Выполняется…" : @"Состояние" detail:self.lastMessage symbol:self.needsRecovery ? @"exclamationmark.triangle" : @"info.circle" enabled:NO];
            cell.textLabel.textColor = UIColor.labelColor;
            if (self.busy) {
                UIActivityIndicatorView *spinner = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleMedium];
                [spinner startAnimating]; cell.accessoryView = spinner;
            }
            return cell;
        }
        return [self cellWithTitle:@"Журнал и диагностика" detail:@"Посмотреть или поделиться журналом без ключей сопряжения" symbol:@"doc.text.magnifyingglass" enabled:YES];
    }
    if (row == 0) return [self cellWithTitle:@"Установка другу и проверка 5G" detail:@"Короткая инструкция внутри приложения" symbol:@"questionmark.circle" enabled:YES];
    return [self cellWithTitle:@"Компоненты и лицензии" detail:@"Исходные проекты и сведения о сборке" symbol:@"chevron.left.forwardslash.chevron.right" enabled:YES];
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    NSInteger section = indexPath.section, row = indexPath.row;
    if (section == 3 && row == 1) { [self showLogs]; return; }
    if (section == 4) { row == 0 ? [self showGuide] : [self showLicenses]; return; }
    if (self.busy || self.connection.isImporting) return;
    if (section == 0 && row == 0) { [self pairingMenu]; return; }
    if (self.connection.isPairing) return;
    if (section == 0) {
        if (row == 1) { if (self.remoteTarget) [self enterRemoteAddress:nil port:0]; else [self VPNMenu]; }
        if (row == 4 && !self.connection.isVPNStarting) [self targetMenu];
        if (row == 5 && self.remoteTarget && self.installationDevice && !self.needsRecovery && !self.developerWaiting) [self shareCarrierSIM];
        if (row == 6 && (self.connection.hasPairing || self.developerWaiting)) [self developerModeMenu];
        if (row == 7 && self.remoteTarget && self.installationDevice && !self.needsRecovery && !self.developerWaiting) [self selectIPA];
        if (row == 2 && self.connection.hasPairing) [self runAction:@"status"];
        if (row == 3) [self importPairing];
    } else if (section == 1) {
        if (row == 0) [self chooseSIM];
        if (row == 1) [self chooseBundle];
    } else if (section == 2) {
        if (row == 2 && self.connection.hasPairing) { [self confirmAction:@"recover"]; return; }
        if (!self.connectionChecked || self.needsRecovery || self.developerWaiting) return;
        if (row == 0 && [self.snapshot[@"can_apply"] boolValue]) [self confirmAction:@"apply"];
        if (row == 1) [self confirmAction:@"restore"];
    }
}

- (void)presentSheet:(UIAlertController *)sheet {
    if (sheet.popoverPresentationController) {
        sheet.popoverPresentationController.sourceView = self.view;
        sheet.popoverPresentationController.sourceRect = CGRectMake(self.view.bounds.size.width/2, self.view.bounds.size.height/2, 1, 1);
    }
    [self presentViewController:sheet animated:YES completion:nil];
}
- (void)message:(NSString *)title text:(NSString *)text {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:title message:text preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"Понятно" style:UIAlertActionStyleDefault handler:nil]];
    if (!self.presentedViewController) [self presentViewController:alert animated:YES completion:nil];
}

- (void)pairingMenu {
    UIAlertController *sheet = [UIAlertController alertControllerWithTitle:self.remoteTarget ? @"Сопряжение с iPhone друга" : @"Сопряжение" message:self.connection.isPairing ? @"В настройках iOS выбери CarrierSIM. Код появится здесь и в уведомлении." : @"Приложение создаст файл сопряжения само. Останется подтвердить подключение в настройках iOS." preferredStyle:UIAlertControllerStyleActionSheet];
    if (self.connection.isPairing) {
        if (self.pairingPIN.length) [sheet addAction:[UIAlertAction actionWithTitle:[@"Скопировать код " stringByAppendingString:self.pairingPIN] style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) { UIPasteboard.generalPasteboard.string = self.pairingPIN; }]];
        [sheet addAction:[UIAlertAction actionWithTitle:@"Остановить сопряжение" style:UIAlertActionStyleDestructive handler:^(UIAlertAction *a) { [self.connection cancelPairing]; }]];
    } else {
        [sheet addAction:[UIAlertAction actionWithTitle:self.connection.hasPairing ? @"Создать заново" : @"Создать сопряжение" style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
            [self.connection startPairing];
            self.lastMessage = self.remoteTarget ? @"На iPhone друга открой Настройки → Конфиденциальность и безопасность → Режим разработчика → Сопряжение с CarrierSIM. Код смотри на своём iPhone. После сопряжения найди адрес и порт друга в Wi-Fi и проверь соединение." : @"Открой настройки iOS → Конфиденциальность и безопасность → Режим разработчика → Сопряжение с CarrierSIM. Код придёт в уведомлении. Затем вернись сюда.";
            [self.tableView reloadData];
            [self message:@"Теперь открой настройки iOS" text:self.lastMessage];
        }]];
        [sheet addAction:[UIAlertAction actionWithTitle:@"Импортировать файл Stik Pair" style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) { [self importPairing]; }]];
    }
    [sheet addAction:[UIAlertAction actionWithTitle:@"Закрыть" style:UIAlertActionStyleCancel handler:nil]];
    [self presentSheet:sheet];
}

- (void)VPNMenu {
    if (self.connection.isVPNStarting) return;
    UIAlertController *sheet = [UIAlertController alertControllerWithTitle:@"Локальное подключение" message:@"Соединяет CarrierSIM со службами этого iPhone. Для работы встроенного VPN подпись IPA должна разрешать Network Extension." preferredStyle:UIAlertControllerStyleActionSheet];
    if (self.connection.isVPNConnected) {
        [sheet addAction:[UIAlertAction actionWithTitle:@"Выключить встроенный VPN" style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
            [self.connection stopVPN]; self.connectionChecked = NO; [self.tableView reloadData];
        }]];
    } else if (self.connection.hasEmbeddedVPN) {
        [sheet addAction:[UIAlertAction actionWithTitle:@"Включить встроенный VPN" style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
            self.connectionChecked = NO;
            [self.connection startVPN:^(NSError *error) {
                self.lastMessage = error ? error.localizedDescription : @"Локальное подключение включено. Нажми «Проверить iPhone».";
                [self.tableView reloadData];
                if (error) [self message:@"Встроенный VPN не включился" text:[error.localizedDescription stringByAppendingString:@"\n\nЕсли сервис подписи не поддерживает расширение VPN, можно включить LocalDevVPN и вернуться в CarrierSIM."]];
            }];
            [self.tableView reloadData];
        }]];
    }
    [sheet addAction:[UIAlertAction actionWithTitle:@"Использовать LocalDevVPN" style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
        [self.connection openLocalDevVPN:^(NSError *error) {
            if (error) [self message:@"LocalDevVPN" text:@"LocalDevVPN не установлен или не открылся. Используй встроенный VPN с подходящей подписью. Ссылка на оригинальный LocalDevVPN есть в разделе «Компоненты»." ];
        }];
    }]];
    [sheet addAction:[UIAlertAction actionWithTitle:@"Отмена" style:UIAlertActionStyleCancel handler:nil]];
    [self presentSheet:sheet];
}

- (void)importPairing {
    self.selectingIPA = NO;
    UIDocumentPickerViewController *picker = [[UIDocumentPickerViewController alloc] initForOpeningContentTypes:@[UTTypeData] asCopy:YES];
    picker.delegate = self; picker.allowsMultipleSelection = NO;
    [self presentViewController:picker animated:YES completion:nil];
}

- (void)findRemotePhone {
    CSLANBrowserViewController *browser = [[CSLANBrowserViewController alloc] initWithStyle:UITableViewStyleInsetGrouped];
    __weak typeof(self) weakSelf = self;
    browser.onSelect = ^(NSString *host, NSInteger port) { [weakSelf enterRemoteAddress:host port:port]; };
    [self.navigationController pushViewController:browser animated:YES];
}

- (void)selectIPA {
    if (!self.remoteTarget || !self.installationDevice || self.developerWaiting || self.needsRecovery) return;
    self.selectingIPA = YES;
    UIDocumentPickerViewController *picker = [[UIDocumentPickerViewController alloc] initForOpeningContentTypes:@[UTTypeData] asCopy:YES];
    picker.delegate = self; picker.allowsMultipleSelection = NO;
    [self presentViewController:picker animated:YES completion:nil];
}

- (void)developerModeMenu {
    if (self.busy || self.connection.isPairing || self.connection.isImporting) return;
    CSDeveloperModeViewController *controller=[[CSDeveloperModeViewController alloc] initWithPairingPath:self.connection.pairingPath workDirectory:self.workDirectory target:self.remoteTarget operationQueue:self.operationQueue];
    __weak typeof(self) weakSelf=self;
    controller.onLog=^(NSString *message){[weakSelf appendLog:message];};
    controller.onState=^(NSDictionary *result,BOOL busy,BOOL waiting){
        weakSelf.busy=busy;weakSelf.developerWaiting=waiting;weakSelf.connectionChecked=NO;
        UIApplication.sharedApplication.idleTimerDisabled=busy;
        weakSelf.installationDevice=[result[@"device"] isKindOfClass:NSDictionary.class] ? result[@"device"] : nil;
        if (result) weakSelf.needsRecovery=[result[@"needs_recovery"] boolValue];
        if (waiting) weakSelf.lastMessage=@"Подтверди включение на телефоне друга. Режим разработчика проверяется после перезагрузки.";
        else if (result) weakSelf.lastMessage=CSText(result[@"message"]);
        [weakSelf.tableView reloadData];
    };
    [self.navigationController pushViewController:controller animated:YES];
}

- (void)shareCarrierSIM {
    if (self.busy || !self.remoteTarget || !self.installationDevice || self.needsRecovery || self.developerWaiting) return;
    CSShareViewController *controller=[[CSShareViewController alloc] initWithPairingPath:self.connection.pairingPath workDirectory:self.workDirectory target:self.remoteTarget device:self.installationDevice operationQueue:self.operationQueue];
    __weak typeof(self) weakSelf=self;
    controller.onBusy=^(BOOL busy){weakSelf.busy=busy;UIApplication.sharedApplication.idleTimerDisabled=busy;[weakSelf.tableView reloadData];};
    controller.onLog=^(NSString *message){weakSelf.lastMessage=message;[weakSelf appendLog:message];};
    controller.onFinished=^(NSDictionary *result){weakSelf.installationDevice=nil;weakSelf.connectionChecked=NO;[weakSelf.tableView reloadData];};
    [self.navigationController pushViewController:controller animated:YES];
}

- (void)confirmInstallURL:(NSURL *)url {
    if (self.busy || self.connection.isPairing || self.connection.isImporting || !self.remoteTarget || !self.installationDevice || self.developerWaiting || self.needsRecovery) {
        [self message:@"Сначала проверь iPhone друга" text:@"Выбери «Другой iPhone», создай или импортируй его сопряжение и нажми «Проверить iPhone». После проверки можно установить подписанный IPA."]; return;
    }
    if (!url.isFileURL || ![url.pathExtension.lowercaseString isEqualToString:@"ipa"]) { [self message:@"Выбери IPA" text:@"Нужен файл приложения с расширением .ipa."]; return; }
    NSString *body = [NSString stringWithFormat:@"iPhone: %@\nФайл: %@\n\nIPA должен быть подписан для телефона друга. DDE Store должен разрешать его устройство в профиле подписи. iOS проверит сертификат. Оставь оба телефона разблокированными в одной Wi-Fi-сети.",[self targetName],url.lastPathComponent];
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Установить приложение другу?" message:body preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"Отмена" style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"Установить" style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) { [self installIPAAtURL:url]; }]];
    if (!self.presentedViewController) [self presentViewController:alert animated:YES completion:nil];
}

- (void)installIPAAtURL:(NSURL *)url {
    NSString *hash = CSText(self.installationDevice[@"identity_hash"]);
    if (!self.remoteTarget || !self.installationDevice || hash.length != 64 || self.busy || self.developerWaiting || self.needsRecovery) return;
    NSData *json = [NSJSONSerialization dataWithJSONObject:@{@"target":self.remoteTarget,@"expected_device_hash":hash} options:0 error:nil];
    NSString *request = [[NSString alloc] initWithData:json encoding:NSUTF8StringEncoding];
    NSString *pairPath = self.connection.pairingPath;
    NSString *workPath = self.workDirectory.path;
    NSURL *copyURL = [self.workDirectory URLByAppendingPathComponent:@"selected-install.ipa"];
    self.busy = YES; self.lastMessage = @"Готовлю IPA для установки другу…";
    UIApplication.sharedApplication.idleTimerDisabled = YES; [self.tableView reloadData];
    self.backgroundTask = [UIApplication.sharedApplication beginBackgroundTaskWithName:@"CarrierSIM IPA install" expirationHandler:^{
        self.lastMessage = @"Вернись в CarrierSIM: iOS ограничивает работу в фоне. Перед повтором проверь, установилось ли приложение другу.";
        UIBackgroundTaskIdentifier task = self.backgroundTask; self.backgroundTask = UIBackgroundTaskInvalid;
        if (task != UIBackgroundTaskInvalid) [UIApplication.sharedApplication endBackgroundTask:task];
    }];
    dispatch_async(self.operationQueue, ^{
        @autoreleasepool {
            BOOL scoped = [url startAccessingSecurityScopedResource]; NSError *copyError = nil;
            NSDictionary *attributes = [NSFileManager.defaultManager attributesOfItemAtPath:url.path error:&copyError];
            unsigned long long length = [attributes[NSFileSize] unsignedLongLongValue];
            [NSFileManager.defaultManager removeItemAtURL:copyURL error:nil];
            BOOL copied = attributes && length > 0 && length <= 512ULL*1024*1024 && [NSFileManager.defaultManager copyItemAtURL:url toURL:copyURL error:&copyError];
            if (scoped) [url stopAccessingSecurityScopedResource];
            char *output = NULL, *errorText = NULL; int32_t code = 1; NSDictionary *result = nil;
            NSString *error = copied ? nil : @"Не удалось прочитать IPA. Дождись загрузки файла; размер должен быть не больше 512 МБ.";
            if (copied) {
                BOOL protected = [NSFileManager.defaultManager setAttributes:@{NSFileProtectionKey:NSFileProtectionCompleteUntilFirstUserAuthentication, NSFilePosixPermissions:@0600} ofItemAtPath:copyURL.path error:&copyError] && [copyURL setResourceValue:@YES forKey:NSURLIsExcludedFromBackupKey error:&copyError];
                if (protected) {
                    code = cs_install_ipa(pairPath.UTF8String,copyURL.path.UTF8String,workPath.UTF8String,request.UTF8String,CSLogCallback,(__bridge void *)self,&output,&errorText);
                    if (output) result = [NSJSONSerialization JSONObjectWithData:[[NSString stringWithUTF8String:output] dataUsingEncoding:NSUTF8StringEncoding] options:0 error:nil];
                    if (errorText) error = CSRedact([NSString stringWithUTF8String:errorText]);
                } else error = @"Не удалось защитить временную копию IPA.";
            }
            if (output) al_string_free(output); if (errorText) al_string_free(errorText);
            [NSFileManager.defaultManager removeItemAtURL:copyURL error:nil];
            dispatch_async(dispatch_get_main_queue(), ^{
                self.busy = NO; UIApplication.sharedApplication.idleTimerDisabled = NO;
                if (self.backgroundTask != UIBackgroundTaskInvalid) { [UIApplication.sharedApplication endBackgroundTask:self.backgroundTask]; self.backgroundTask = UIBackgroundTaskInvalid; }
                self.connectionChecked = NO;
                self.installationDevice = nil;
                self.lastMessage = code == 0 && [result[@"installed"] boolValue] ? CSText(result[@"message"]) : (error ?: @"Установка не подтверждена. Проверь телефон друга и журнал.");
                [self appendLog:self.lastMessage]; [self.tableView reloadData];
                [self message:code == 0 && [result[@"installed"] boolValue] ? @"Приложение установлено" : @"Установка не подтверждена" text:self.lastMessage];
            });
        }
    });
}
- (void)documentPicker:(UIDocumentPickerViewController *)controller didPickDocumentsAtURLs:(NSArray<NSURL *> *)urls {
    BOOL ipa = self.selectingIPA; self.selectingIPA = NO;
    if (urls.firstObject) { if (ipa) [self confirmInstallURL:urls.firstObject]; else [self importURL:urls.firstObject]; }
}
- (void)documentPickerWasCancelled:(UIDocumentPickerViewController *)controller { self.selectingIPA = NO; }
- (void)importURL:(NSURL *)url {
    if (self.busy || self.connection.isPairing || self.connection.isImporting) { [self message:@"Подожди завершения" text:@"Файл можно импортировать после текущей операции."]; return; }
    [self.connection importPairingAtURL:url completion:^(NSError *error) {
        self.connectionChecked = NO; self.snapshot = nil; self.installationDevice = nil;
        self.lastMessage = error ? error.localizedDescription : @"Сопряжение импортировано. Включи локальное подключение и проверь iPhone.";
        [self.tableView reloadData];
        if (error) [self message:@"Файл не подходит" text:error.localizedDescription];
    }];
}
- (void)handleIncomingURL:(NSURL *)url {
    [self loadViewIfNeeded];
    if (url.isFileURL && [url.pathExtension.lowercaseString isEqualToString:@"ipa"]) { [self confirmInstallURL:url]; return; }
    if (url.isFileURL) {
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Импортировать сопряжение?" message:@"CarrierSIM проверит выбранный файл и сохранит его внутри приложения." preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"Отмена" style:UIAlertActionStyleCancel handler:nil]];
        [alert addAction:[UIAlertAction actionWithTitle:@"Импортировать" style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) { [self importURL:url]; }]];
        if (!self.presentedViewController) [self presentViewController:alert animated:YES completion:nil];
    } else if ([url.scheme.lowercaseString isEqualToString:@"carriersim"]) {
        [self.connection refreshVPNStatus];
        self.connectionChecked = NO;
        self.lastMessage = @"Вернулся в CarrierSIM. Нажми «Проверить iPhone», чтобы проверить реальное подключение.";
        [self.tableView reloadData];
    }
}

- (void)chooseSIM {
    UIAlertController *sheet = [UIAlertController alertControllerWithTitle:@"Какие SIM изменить" message:nil preferredStyle:UIAlertControllerStyleActionSheet];
    NSArray *names = @[@"Все обнаруженные SIM", @"Только SIM 1", @"Только SIM 2"];
    for (NSInteger index = 0; index < 3; index++) {
        [sheet addAction:[UIAlertAction actionWithTitle:names[index] style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
            self.SIMSelection = index; self.connectionChecked = NO; self.lastMessage = @"Выбор SIM изменён. Нажми «Проверить iPhone» перед применением."; [self.tableView reloadData];
        }]];
    }
    [sheet addAction:[UIAlertAction actionWithTitle:@"Отмена" style:UIAlertActionStyleCancel handler:nil]];
    [self presentSheet:sheet];
}

- (void)chooseBundle {
    UIAlertController *sheet = [UIAlertController alertControllerWithTitle:@"Профиль оператора" message:@"Выбранный пакет должен существовать в системе iPhone. По умолчанию используется Vodafone_hu." preferredStyle:UIAlertControllerStyleActionSheet];
    for (NSString *name in @[@"Vodafone_hu", @"O2_Germany", @"Swisscom_ch"]) {
        [sheet addAction:[UIAlertAction actionWithTitle:name style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) { self.bundleName = name; self.connectionChecked = NO; [self.tableView reloadData]; }]];
    }
    [sheet addAction:[UIAlertAction actionWithTitle:@"Указать имя другого пакета" style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
        UIAlertController *entry = [UIAlertController alertControllerWithTitle:@"Имя системного пакета" message:@"Например, Vodafone_hu. Без пути к папке." preferredStyle:UIAlertControllerStyleAlert];
        [entry addTextFieldWithConfigurationHandler:^(UITextField *field) { field.text = self.bundleName; field.autocapitalizationType = UITextAutocapitalizationTypeNone; field.autocorrectionType = UITextAutocorrectionTypeNo; }];
        [entry addAction:[UIAlertAction actionWithTitle:@"Отмена" style:UIAlertActionStyleCancel handler:nil]];
        [entry addAction:[UIAlertAction actionWithTitle:@"Выбрать" style:UIAlertActionStyleDefault handler:^(UIAlertAction *b) {
            NSString *name = [entry.textFields.firstObject.text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
            if ([name hasSuffix:@".bundle"]) name = [name substringToIndex:name.length - 7];
            NSRegularExpression *valid = [NSRegularExpression regularExpressionWithPattern:@"^[A-Za-z0-9_]{1,96}$" options:0 error:nil];
            if (![valid numberOfMatchesInString:name options:0 range:NSMakeRange(0, name.length)]) { [self message:@"Проверь имя" text:@"Разрешены латинские буквы, цифры и нижнее подчёркивание."]; return; }
            self.bundleName = name; self.connectionChecked = NO; [self.tableView reloadData];
        }]];
        [self presentViewController:entry animated:YES completion:nil];
    }]];
    [sheet addAction:[UIAlertAction actionWithTitle:@"Отмена" style:UIAlertActionStyleCancel handler:nil]];
    [self presentSheet:sheet];
}

- (void)confirmAction:(NSString *)action {
    NSString *title, *body;
    if ([action isEqualToString:@"apply"]) {
        title = @"Применить профиль?";
        body = [NSString stringWithFormat:@"Профиль: %@\nSIM: %@\n\nСначала будет сохранена копия. Во время изменения связь может временно пропасть. Оставь приложение открытым.", self.bundleName, @[@"все обнаруженные", @"SIM 1", @"SIM 2"][self.SIMSelection]];
    } else if ([action isEqualToString:@"restore"]) {
        title = @"Вернуть штатные профили?";
        body = @"Будут удалены IMSI-ссылки для всех SIM, добавленные таким способом. Исходные файлы операторов сохранятся. Перед действием создаётся копия.";
    } else { title = @"Восстановить после сбоя?"; body = @"Приложение проверит журнал и восстановит незавершённые изменения на этом же iPhone. Не закрывай CarrierSIM до окончания."; }
    body = [NSString stringWithFormat:@"iPhone: %@\n\n%@", [self targetName], body];
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:title message:body preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"Отмена" style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"Продолжить" style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) { [self runAction:action]; }]];
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)runAction:(NSString *)action {
    if (self.busy || self.connection.isPairing || self.connection.isImporting || !self.connection.hasPairing) return;
    if (self.developerWaiting && ![action isEqualToString:@"status"]) { [self message:@"Дождись режима разработчика" text:@"Проверь состояние в разделе режима разработчика или останови ожидание."]; return; }
    NSString *assets = [NSBundle.mainBundle pathForResource:@"assets" ofType:@"zip"];
    if (!assets) { [self message:@"Повреждён пакет приложения" text:@"Не найден встроенный assets.zip. Переустанови полный IPA."]; return; }
    self.busy = YES; UIApplication.sharedApplication.idleTimerDisabled = YES;
    self.lastMessage = [action isEqualToString:@"status"] ? @"Проверяю подключение и читаю SIM…" : @"Начинаю операцию. Оставь приложение открытым.";
    self.operationResult = nil;
    [self.tableView reloadData];
    NSArray *slots = self.SIMSelection == 1 ? @[@"kOne"] : self.SIMSelection == 2 ? @[@"kTwo"] : @[@"kOne", @"kTwo"];
    NSMutableDictionary *request = [@{@"action":action, @"bundle":self.bundleName, @"slots":slots} mutableCopy];
    if (self.remoteTarget) request[@"target"] = self.remoteTarget;
    NSString *identity = CSText(self.snapshot[@"device"][@"identity_hash"]);
    if (![action isEqualToString:@"status"] && identity.length) request[@"expected_device_hash"] = identity;
    NSData *json = [NSJSONSerialization dataWithJSONObject:request options:0 error:nil];
    NSString *requestString = [[NSString alloc] initWithData:json encoding:NSUTF8StringEncoding];
    NSString *pairPath = self.connection.pairingPath;
    NSString *workPath = self.workDirectory.path;
    self.backgroundTask = [UIApplication.sharedApplication beginBackgroundTaskWithName:@"CarrierSIM operation" expirationHandler:^{
        self.lastMessage = @"iOS ограничивает работу в фоне. Вернись в CarrierSIM. При прерывании используй восстановление.";
        UIBackgroundTaskIdentifier task = self.backgroundTask;
        self.backgroundTask = UIBackgroundTaskInvalid;
        if (task != UIBackgroundTaskInvalid) [UIApplication.sharedApplication endBackgroundTask:task];
    }];
    dispatch_async(self.operationQueue, ^{
        @autoreleasepool {
            char *output = NULL, *errorText = NULL;
            int32_t code = cs_execute(pairPath.UTF8String, workPath.UTF8String, assets.UTF8String, requestString.UTF8String, CSLogCallback, (__bridge void *)self, &output, &errorText);
            NSString *returned = output ? [NSString stringWithUTF8String:output] : nil;
            NSString *error = errorText ? CSRedact([NSString stringWithUTF8String:errorText]) : nil;
            NSDictionary *result = returned ? [NSJSONSerialization JSONObjectWithData:[returned dataUsingEncoding:NSUTF8StringEncoding] options:0 error:nil] : nil;
            if (![result isKindOfClass:NSDictionary.class]) result = nil;
            if (output) al_string_free(output);
            if (errorText) al_string_free(errorText);
            dispatch_async(dispatch_get_main_queue(), ^{ [self completedAction:action code:code result:result error:error]; });
        }
    });
}

- (void)completedAction:(NSString *)action code:(int32_t)code result:(NSDictionary *)result error:(NSString *)error {
    self.busy = NO; UIApplication.sharedApplication.idleTimerDisabled = NO;
    if (self.backgroundTask != UIBackgroundTaskInvalid) {
        [UIApplication.sharedApplication endBackgroundTask:self.backgroundTask];
        self.backgroundTask = UIBackgroundTaskInvalid;
    }
    self.operationResult = result;
    self.needsRecovery = [result[@"needs_recovery"] boolValue];
    BOOL isStatus = [action isEqualToString:@"status"];
    self.connectionChecked = isStatus && code == 0;
    self.installationDevice = isStatus && code == 0 ? result[@"device"] : nil;
    if (isStatus && code == 0) {
        self.snapshot = result;
        self.lastMessage = self.needsRecovery ? @"Найдена незавершённая операция. Нажми «Восстановить после сбоя»." : ([result[@"can_apply"] boolValue] ? @"iPhone доступен. Проверь выбранные SIM и профиль, затем нажми «Применить»." : @"iPhone доступен, но данных для применения недостаточно. Проверь, что SIM включена и телефон разблокирован.");
        NSString *reason = CSText(result[@"reason"]);
        if (reason.length && !self.needsRecovery) self.lastMessage = reason;
    } else if (code == 1 || !result) {
        self.lastMessage = error.length ? error : @"Операция не завершилась. Посмотри журнал и проверь подключение.";
        if (self.needsRecovery) self.lastMessage = [self.lastMessage stringByAppendingString:@"\nСначала выполни «Восстановить после сбоя»." ];
    } else {
        NSString *message = CSText(result[@"message"]);
        BOOL catalog = [result[@"catalog_verified"] boolValue], confirmed = [result[@"commcenter_verified"] boolValue];
        if ([action isEqualToString:@"recover"]) self.lastMessage = message.length ? message : @"Проверка восстановления завершена. Перед применением снова проверь iPhone.";
        else if (catalog && confirmed) self.lastMessage = @"Каталог проверен обратным чтением. Выбор профиля подтверждён iOS. Теперь проверь связь и вызовы по Wi-Fi по инструкции ниже.";
        else if (catalog) self.lastMessage = @"Запись проверена обратным чтением. Выбор профиля со стороны iOS пока не подтверждён. Это ещё не подтверждает работу вызовов по Wi-Fi.";
        else self.lastMessage = message.length ? message : @"Операция завершилась без подтверждения применения. Посмотри журнал.";
        if ([result[@"rolled_back"] boolValue]) self.lastMessage = @"Новый профиль не подтверждён. Прежние настройки возвращены. Проверь имя пакета в журнале.";
    }
    NSString *compatibility = CSText(result[@"warning"]);
    if (compatibility.length) self.lastMessage = [self.lastMessage stringByAppendingFormat:@"\n%@", compatibility];
    [self appendLog:self.lastMessage];
    [self.tableView reloadData];
    if (!isStatus) [self message:code == 0 ? @"Операция завершена" : (code == 2 ? @"Нужна проверка" : @"Операция остановлена") text:self.lastMessage];
}

- (void)appendLog:(NSString *)line {
    if (!line.length) return;
    NSString *safe = CSRedact(line);
    if (safe.length > 2000) safe = [[safe substringToIndex:2000] stringByAppendingString:@"…"];
    NSDateFormatter *format = NSDateFormatter.new; format.dateFormat = @"HH:mm:ss";
    [self.logLines addObject:[NSString stringWithFormat:@"%@  %@", [format stringFromDate:NSDate.date], safe]];
    if (self.logLines.count > 600) [self.logLines removeObjectsInRange:NSMakeRange(0, self.logLines.count - 600)];
    if (self.busy) {
        self.lastMessage = safe;
        [self.tableView reloadSections:[NSIndexSet indexSetWithIndex:3] withRowAnimation:UITableViewRowAnimationNone];
    }
}

- (void)showText:(NSString *)text title:(NSString *)title share:(BOOL)share {
    UIViewController *controller = UIViewController.new;
    controller.title = title;
    UITextView *view = UITextView.new;
    view.editable = NO; view.selectable = YES;
    view.backgroundColor = UIColor.systemBackgroundColor;
    view.textContainerInset = UIEdgeInsetsMake(20, 16, 24, 16);
    view.font = [UIFont preferredFontForTextStyle:UIFontTextStyleBody];
    view.adjustsFontForContentSizeCategory = YES;
    view.text = text;
    controller.view = view;
    if (share) controller.navigationItem.rightBarButtonItem = [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemAction target:self action:@selector(shareLog)];
    [self.navigationController pushViewController:controller animated:YES];
}
- (void)showLogs { [self showText:[self.logLines componentsJoinedByString:@"\n\n"] title:@"Журнал" share:YES]; }
- (void)shareLog {
    NSString *text = [self.logLines componentsJoinedByString:@"\n"];
    NSURL *directory = [[NSFileManager.defaultManager URLsForDirectory:NSCachesDirectory inDomains:NSUserDomainMask].firstObject URLByAppendingPathComponent:@"Diagnostics" isDirectory:YES];
    [NSFileManager.defaultManager createDirectoryAtURL:directory withIntermediateDirectories:YES attributes:@{NSFileProtectionKey:NSFileProtectionCompleteUntilFirstUserAuthentication} error:nil];
    NSURL *file = [directory URLByAppendingPathComponent:@"CarrierSIM-diagnostics.txt"];
    NSError *error = nil;
    [CSRedact(text) writeToURL:file atomically:YES encoding:NSUTF8StringEncoding error:&error];
    if (error) { [self message:@"Не удалось создать журнал" text:error.localizedDescription]; return; }
    UIActivityViewController *share = [[UIActivityViewController alloc] initWithActivityItems:@[file] applicationActivities:nil];
    share.popoverPresentationController.barButtonItem = self.navigationController.topViewController.navigationItem.rightBarButtonItem;
    [self.navigationController.topViewController presentViewController:share animated:YES completion:nil];
}
- (void)showGuide {
    [self showText:@"ДВА СПОСОБА РАБОТЫ С IPHONE ДРУГА\n\n1. ПРИМЕНИТЬ ПРОФИЛЬ БЕЗ УСТАНОВКИ CARRIERSIM ДРУГУ\n\nПодключите оба телефона к одной Wi-Fi-сети. Выбери «Другой iPhone», создай или импортируй его сопряжение и укажи адрес службы. Нажми «Проверить iPhone и SIM», выбери линию и профиль, снова проверь телефон и примени профиль. Устанавливать CarrierSIM другу для этой операции не нужно. Если службы Apple недоступны, сначала подготовь телефон и доверенное сопряжение через компьютер.\n\n2. ОТПРАВИТЬ САМ CARRIERSIM\n\nПосле сопряжения открой «Режим разработчика»: приложение прочитает имя и модель друга, даже если активной SIM нет. Вернись и выбери «Отправить CarrierSIM другу». Импортируй свой P12 и .mobileprovision, разрешающий телефон друга и com.tema.CarrierSIM. Для встроенного VPN нужен также профиль com.tema.CarrierSIM.Tunnel; оба профиля должны разрешать Network Extension. Введи пароль P12 и нажми «Подписать и установить». Пароль не сохраняется, P12 не передаётся другу. Можно выбрать уже подписанный CarrierSIM из DDE Store. Вход через Apple Account в этой версии не реализован.\n\nБез профиля расширения передаётся вариант для LocalDevVPN. Если сертификат зарегистрирован только для твоего UDID, попроси поставщика добавить iPhone друга и выдать новый профиль. P12 без подходящего профиля не разрешает установку.\n\nРЕЖИМ РАЗРАБОТЧИКА\n\n«Показать пункт в настройках» запрашивает появление переключателя на проверенном телефоне. Владелец открывает Настройки → Конфиденциальность и безопасность → Режим разработчика, включает его и подтверждает перезагрузку. После неё нужно подтвердить включение и ввести код-пароль.\n\n«Запросить включение» может перезагрузить выбранный телефон. Если iOS отказывает из-за код-пароля, включите режим вручную, сохранив код-пароль. CarrierSIM читает состояние после перезагрузки и не повторяет команду включения. Для ручного пути нажми «Ждать после ручного включения». Если IP изменился, вернись, укажи новый адрес и открой раздел заново: проверка должна подтвердить тот же iPhone.\n\nЕсли нет сопряжения или службы недоступны при выключенном режиме, сетевой запрос не поможет: начни доверенное сопряжение через совместимый компьютер. Прямой USB-C между двумя iPhone и работа через мобильный интернет в этой версии отсутствуют.\n\nСОПРЯЖЕНИЕ И ПОДПИСЬ\n\nДля работы на самом iPhone включи встроенный локальный VPN или LocalDevVPN, затем проверь устройство. Создание Remote Pairing в настройках рассчитано на iOS 27; на iOS 26 нужен готовый файл. VPN твоего телефона не открывает службы друга. Wi-Fi-сеть должна разрешать соединение между устройствами.\n\nПРОВЕРКА 5G\n\niPhone 12 и новее поддерживают 5G аппаратно. После изменения профиля проверь Настройки → Сотовая связь → нужная SIM → Параметры данных → Голос и данные. Фактическая сеть 5G зависит от оператора, SIM, тарифа и покрытия. Профиль не создаёт услугу 5G у Yota или t2.\n\nПРИ ПРЕРЫВАНИИ\n\nПроверь, установилось ли приложение на телефоне друга, прежде чем повторять установку. Для незавершённого изменения профиля используй «Восстановить после сбоя». Не удаляй CarrierSIM с управляющего телефона: в нём резервные копии. Во время ожидания перезагрузки запись профиля и установка заблокированы.\n\nСОВМЕСТИМОСТЬ\n\nВерсия 1.2 экспериментальная: сборка и автоматические проверки не подтверждают работу на физическом iPhone. Возможности служб меняются между версиями iOS.\n\nОРИГИНАЛ CARRIERSIM ВЗЯТ ИЗ https://github.com/ios-bundles/CarrierSIM" title:@"Как пользоваться" share:NO];
}

- (void)showLicenses {
    NSMutableString *text = [NSMutableString stringWithString:@"CarrierSIM для iOS\nВерсия 1.2\n\nОРИГИНАЛ CARRIERSIM ВЗЯТ ИЗ https://github.com/ios-bundles/CarrierSIM\n\nПеренос CarrierSIM v4 из предоставленного архива. Интерфейс, сопряжение и локальное подключение встроены.\n\nИспользуется код:\n• AirCard-iOS — https://github.com/Mak5er/AirCard-iOS\n• AirLift — https://github.com/0xjohnnydev/airlift\n• idevice — https://github.com/jkcoxson/idevice\n• LocalDevVPN (SideStore Team): встроенный локальный туннель основан на коде этого проекта — https://github.com/jkcoxson/LocalDevVPN\n\nПодпись P12: isideload-apple-codesign — https://github.com/nab138/isideload-apple-platform-rs\n\nСовместим с файлами Stik Pair — https://github.com/StikDebug/StikPair\n\nЭто самостоятельная производная сборка CarrierSIM, не официальный выпуск перечисленных проектов.\n\n"];
    NSArray *files = [NSFileManager.defaultManager contentsOfDirectoryAtPath:[NSBundle.mainBundle.bundlePath stringByAppendingPathComponent:@"Licenses"] error:nil];
    for (NSString *file in [files sortedArrayUsingSelector:@selector(compare:)]) {
        NSString *path = [[NSBundle.mainBundle.bundlePath stringByAppendingPathComponent:@"Licenses"] stringByAppendingPathComponent:file];
        NSString *license = [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:nil];
        if (license) [text appendFormat:@"\n%@\n\n%@\n", file, license];
    }
    [self showText:text title:@"Компоненты" share:NO];
}
@end
