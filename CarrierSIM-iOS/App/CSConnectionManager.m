#import "CSConnectionManager.h"
#import "airlift.h"
#import <UIKit/UIKit.h>
#import <AVFoundation/AVFoundation.h>
#import <NetworkExtension/NetworkExtension.h>
#import <UserNotifications/UserNotifications.h>

// Added by CarrierSIM to the bundled native pairing engine. Cancellation closes
// the actual listener/handshake; the manager never pretends an active run ended.
extern void al_pairing_cancel_host(void);

static NSString * const CSErrorDomain = @"CarrierSIM.Connection";
static const NSUInteger CSMaximumPairingBytes = 1024 * 1024;

static NSError *CSError(NSInteger code, NSString *message) {
    return [NSError errorWithDomain:CSErrorDomain code:code
                          userInfo:@{NSLocalizedDescriptionKey: message}];
}

static NSString *CSString(const char *value) {
    if (!value) return @"";
    return [NSString stringWithUTF8String:value] ?: @"";
}

static BOOL CSNonemptyString(id value) {
    return [value isKindOfClass:NSString.class] && [value length] > 0 && [value length] <= 1024;
}

static BOOL CSDataSize(id value, NSUInteger length) {
    return [value isKindOfClass:NSData.class] && [value length] == length;
}

/// Structural validation follows the bundled idevice RpPairingFile and
/// RawPairingFile definitions. Successful import is not authentication proof.
static NSDictionary *CSValidatePairing(NSData *data, NSString **kind, NSError **error) {
    if (!data.length || data.length > CSMaximumPairingBytes) {
        if (error) *error = CSError(10, @"Файл подключения пустой или слишком большой.");
        return nil;
    }
    NSError *parseError = nil;
    id object = [NSPropertyListSerialization propertyListWithData:data
                                                        options:NSPropertyListImmutable
                                                         format:NULL error:&parseError];
    if (![object isKindOfClass:NSDictionary.class]) {
        if (error) *error = CSError(11, @"Это не файл подключения StikPair или Lockdown в формате plist.");
        return nil;
    }
    NSDictionary *record = object;
    if (record[@"public_key"] || record[@"private_key"] || record[@"identifier"]) {
        if (!CSDataSize(record[@"public_key"], 32) ||
            !CSDataSize(record[@"private_key"], 32) ||
            !CSNonemptyString(record[@"identifier"]) ||
            (record[@"alt_irk"] && !CSDataSize(record[@"alt_irk"], 16))) {
            if (error) *error = CSError(12, @"Файл StikPair повреждён: неверные ключи Remote Pairing.");
            return nil;
        }
        if (kind) *kind = @"Remote Pairing";
        return record;
    }
    for (NSString *key in @[@"DeviceCertificate", @"HostPrivateKey", @"HostCertificate",
                            @"RootPrivateKey", @"RootCertificate"]) {
        id value = record[key];
        if (![value isKindOfClass:NSData.class] || [value length] == 0) {
            if (error) *error = CSError(13, @"В файле нет полного набора сертификатов Lockdown. Выберите файл подключения устройства.");
            return nil;
        }
    }
    for (NSString *key in @[@"HostID", @"SystemBUID", @"WiFiMACAddress"]) {
        if (!CSNonemptyString(record[key])) {
            if (error) *error = CSError(14, @"Файл Lockdown неполный. Создайте новое подключение или импортируйте полный pairing-файл.");
            return nil;
        }
    }
    if (record[@"EscrowBag"] && ![record[@"EscrowBag"] isKindOfClass:NSData.class]) {
        if (error) *error = CSError(15, @"Файл Lockdown повреждён: неверный EscrowBag.");
        return nil;
    }
    if (kind) *kind = @"Lockdown";
    return record;
}

static NSData *CSReadLimitedURL(NSURL *url, NSError **error) {
    NSInputStream *stream = [NSInputStream inputStreamWithURL:url];
    if (!stream) {
        if (error) *error = CSError(16, @"Не удалось открыть выбранный файл.");
        return nil;
    }
    [stream open];
    NSMutableData *data = [NSMutableData data];
    uint8_t buffer[8192];
    NSInteger count;
    while ((count = [stream read:buffer maxLength:sizeof(buffer)]) > 0) {
        if (data.length + (NSUInteger)count > CSMaximumPairingBytes) {
            [stream close];
            if (error) *error = CSError(17, @"Файл подключения должен быть меньше 1 МБ.");
            return nil;
        }
        [data appendBytes:buffer length:(NSUInteger)count];
    }
    NSError *readError = stream.streamError;
    [stream close];
    if (count < 0 || readError) {
        if (error) *error = CSError(18, @"Не удалось прочитать файл. Дождитесь его загрузки в приложении «Файлы» и повторите.");
        return nil;
    }
    return data;
}

static BOOL CSProtectURL(NSURL *url, BOOL directory, NSError **error) {
    NSDictionary *attributes = @{
        NSFileProtectionKey: NSFileProtectionCompleteUntilFirstUserAuthentication,
        NSFilePosixPermissions: directory ? @0700 : @0600
    };
    if (![[NSFileManager defaultManager] setAttributes:attributes ofItemAtPath:url.path error:error]) return NO;
    return [url setResourceValue:@YES forKey:NSURLIsExcludedFromBackupKey error:error];
}

static BOOL CSWritePrivateData(NSData *data, NSURL *url, NSError **error) {
    if (![data writeToURL:url options:(NSDataWritingAtomic |
                                      NSDataWritingFileProtectionCompleteUntilFirstUserAuthentication)
                   error:error]) return NO;
    return CSProtectURL(url, NO, error);
}

static NSData *CSSilentWAV(void) {
    // One second of in-memory PCM silence. This keeps the user-initiated pairing
    // listener alive while iOS Settings is in front, without microphone access.
    const uint32_t samples = 8000;
    const uint32_t byteCount = samples * 2;
    NSMutableData *data = [NSMutableData dataWithLength:44 + byteCount];
    uint8_t *bytes = data.mutableBytes;
    memcpy(bytes, "RIFF", 4);
    uint32_t size = CFSwapInt32HostToLittle(byteCount + 36);
    memcpy(bytes + 4, &size, 4);
    memcpy(bytes + 8, "WAVEfmt ", 8);
    uint32_t fmtSize = CFSwapInt32HostToLittle(16);
    memcpy(bytes + 16, &fmtSize, 4);
    uint16_t pcm = CFSwapInt16HostToLittle(1);
    memcpy(bytes + 20, &pcm, 2);
    memcpy(bytes + 22, &pcm, 2);
    uint32_t rate = CFSwapInt32HostToLittle(samples);
    uint32_t bytesPerSecond = CFSwapInt32HostToLittle(samples * 2);
    memcpy(bytes + 24, &rate, 4);
    memcpy(bytes + 28, &bytesPerSecond, 4);
    uint16_t alignment = CFSwapInt16HostToLittle(2);
    uint16_t bits = CFSwapInt16HostToLittle(16);
    memcpy(bytes + 32, &alignment, 2);
    memcpy(bytes + 34, &bits, 2);
    memcpy(bytes + 36, "data", 4);
    uint32_t payloadSize = CFSwapInt32HostToLittle(byteCount);
    memcpy(bytes + 40, &payloadSize, 4);
    return data;
}

@interface CSConnectionManager () <NSNetServiceDelegate>
@property (nonatomic, copy, readwrite) NSString *pairingPath;
@property (nonatomic, copy, readwrite) NSString *status;
@property (nonatomic, readwrite) BOOL isPairing;
@property (nonatomic, readwrite) BOOL hasPairing;
@property (nonatomic, readwrite) BOOL isVPNStarting;
@property (atomic) BOOL cancelRequested;
- (void)nativeReadyWithService:(NSString *)serviceID port:(uint16_t)port txt:(NSDictionary *)txt;
- (void)nativePIN:(NSString *)pin;
@end

static void CSReadyCallback(void *context, const char *serviceID, uint16_t port,
                            const char *const *keys, const char *const *values, size_t count) {
    CSConnectionManager *manager = (__bridge CSConnectionManager *)context;
    NSString *identifier = CSString(serviceID);
    NSMutableDictionary *txt = [NSMutableDictionary dictionary];
    if (keys && values && count <= 64) {
        for (size_t i = 0; i < count; i++) {
            NSString *key = CSString(keys[i]);
            NSString *value = CSString(values[i]);
            if (key.length && key.length < 128 && value.length < 256) {
                txt[key] = [value dataUsingEncoding:NSUTF8StringEncoding];
            }
        }
    }
    dispatch_async(dispatch_get_main_queue(), ^{
        [manager nativeReadyWithService:identifier port:port txt:txt];
    });
}

static void CSPINCallback(const char *pin, void *context) {
    CSConnectionManager *manager = (__bridge CSConnectionManager *)context;
    NSString *value = CSString(pin);
    dispatch_async(dispatch_get_main_queue(), ^{ [manager nativePIN:value]; });
}

@implementation CSConnectionManager {
    NSURL *_stateDirectory;
    NSURL *_identityURL;
    NSURL *_pendingURL;
    NSError *_storageError;
    NSNetService *_netService;
    AVAudioPlayer *_silentPlayer;
    UIBackgroundTaskIdentifier _backgroundTask;
    NETunnelProviderManager *_vpnManager;
    CSConnectionCompletion _vpnCompletion;
    NSUInteger _vpnGeneration;
    BOOL _vpnSawConnecting;
    BOOL _importing;
    BOOL _externalVPNOpened;
    NSString *_publicationFailure;
}

- (instancetype)init {
    return [self initWithTargetIdentifier:nil];
}

- (instancetype)initWithTargetIdentifier:(NSString *)identifier {
    if ((self = [super init])) {
        _backgroundTask = UIBackgroundTaskInvalid;
        NSURL *support = [[[NSFileManager defaultManager] URLsForDirectory:NSApplicationSupportDirectory
                                                                 inDomains:NSUserDomainMask] firstObject];
        _stateDirectory = [support URLByAppendingPathComponent:@"CarrierSIM" isDirectory:YES];
        if ([identifier isEqualToString:@"remote"]) {
            _stateDirectory = [_stateDirectory URLByAppendingPathComponent:@"remote" isDirectory:YES];
        }
        _pairingPath = [[_stateDirectory URLByAppendingPathComponent:@"pairing.plist"] path];
        _identityURL = [_stateDirectory URLByAppendingPathComponent:@"host-identity.plist"];
        _pendingURL = [_stateDirectory URLByAppendingPathComponent:@"pairing-pending.plist"];
        [self preparePrivateDirectory];
        if (!_storageError) {
            NSData *data = CSReadLimitedURL([NSURL fileURLWithPath:_pairingPath], NULL);
            _hasPairing = CSValidatePairing(data, NULL, NULL) != nil;
            if (_hasPairing) CSProtectURL([NSURL fileURLWithPath:_pairingPath], NO, NULL);
        }
        _status = _storageError ? @"Не удалось открыть защищённое хранилище подключения."
                                : (_hasPairing ? @"Подключение сохранено. Выполните проверку iPhone."
                                               : @"Создайте подключение к этому iPhone.");
        [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(vpnStatusChanged:)
                                                     name:NEVPNStatusDidChangeNotification object:nil];
        [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(appDidBecomeActive:)
                                                     name:UIApplicationDidBecomeActiveNotification object:nil];
    }
    return self;
}

- (void)dealloc {
    [[NSNotificationCenter defaultCenter] removeObserver:self];
}

- (void)preparePrivateDirectory {
    NSError *error = nil;
    NSDictionary *attributes = @{NSFileProtectionKey: NSFileProtectionCompleteUntilFirstUserAuthentication,
                                 NSFilePosixPermissions: @0700};
    if (![[NSFileManager defaultManager] createDirectoryAtURL:_stateDirectory
                                withIntermediateDirectories:YES attributes:attributes error:&error] ||
        !CSProtectURL(_stateDirectory, YES, &error)) {
        _storageError = error ?: CSError(19, @"Не удалось создать защищённое хранилище.");
    } else {
        _storageError = nil;
    }
}

- (void)publishStatus:(NSString *)status {
    self.status = status;
    if (self.onStatus) self.onStatus(status);
}

- (BOOL)supportsOnDevicePairing {
    return [[NSProcessInfo processInfo] isOperatingSystemAtLeastVersion:(NSOperatingSystemVersion){27, 0, 0}];
}

- (NSString *)embeddedVPNIdentifier {
    NSURL *plugins = NSBundle.mainBundle.builtInPlugInsURL;
    if (!plugins) return nil;
    NSArray<NSURL *> *items = [[NSFileManager defaultManager] contentsOfDirectoryAtURL:plugins
                                                   includingPropertiesForKeys:nil options:0 error:NULL];
    for (NSURL *url in items) {
        if (![url.pathExtension isEqualToString:@"appex"]) continue;
        NSBundle *bundle = [NSBundle bundleWithURL:url];
        NSDictionary *extension = bundle.infoDictionary[@"NSExtension"];
        if ([extension[@"NSExtensionPointIdentifier"] isEqualToString:@"com.apple.networkextension.packet-tunnel"] &&
            [extension[@"NSExtensionPrincipalClass"] isEqualToString:@"PacketTunnelProvider"]) {
            return bundle.bundleIdentifier;
        }
    }
    return nil;
}

- (BOOL)hasEmbeddedVPN {
    return [self embeddedVPNIdentifier].length > 0;
}

- (BOOL)isVPNConnected {
    return _vpnManager && _vpnManager.connection.status == NEVPNStatusConnected;
}

- (BOOL)isImporting {
    return _importing;
}

- (void)postNotification:(NSString *)identifier title:(NSString *)title body:(NSString *)body {
    UNMutableNotificationContent *content = [UNMutableNotificationContent new];
    content.title = title;
    content.body = body;
    content.sound = [UNNotificationSound defaultSound];
    [[UNUserNotificationCenter currentNotificationCenter]
        addNotificationRequest:[UNNotificationRequest requestWithIdentifier:identifier content:content trigger:nil]
         withCompletionHandler:nil];
}

- (void)startPairing {
    if (![NSThread isMainThread]) {
        dispatch_async(dispatch_get_main_queue(), ^{ [self startPairing]; });
        return;
    }
    if (self.isPairing || _importing) {
        [self publishStatus:@"Подключение уже выполняется. Дождитесь его завершения."];
        return;
    }
    if (!self.supportsOnDevicePairing) {
        NSError *error = CSError(20, @"Подключение без компьютера через StikPair доступно начиная с iOS 27. На этой версии можно импортировать существующий pairing-файл; совместимость CarrierSIM всё равно требует проверки.");
        [self publishStatus:error.localizedDescription];
        if (self.onPairingDone) self.onPairingDone(error);
        return;
    }
    [self preparePrivateDirectory];
    if (_storageError) {
        NSError *error = CSError(21, @"Не удалось подготовить защищённое хранилище. Разблокируйте iPhone и повторите.");
        [self publishStatus:error.localizedDescription];
        if (self.onPairingDone) self.onPairingDone(error);
        return;
    }
    self.isPairing = YES;
    self.cancelRequested = NO;
    _publicationFailure = nil;
    [self publishStatus:@"Подготовка подключения. Разрешите уведомления, чтобы видеть код в настройках."];
    UNUserNotificationCenter *center = UNUserNotificationCenter.currentNotificationCenter;
    [center getNotificationSettingsWithCompletionHandler:^(UNNotificationSettings *settings) {
        void (^continuePairing)(void) = ^{
            dispatch_async(dispatch_get_main_queue(), ^{ [self beginNativePairing]; });
        };
        if (settings.authorizationStatus == UNAuthorizationStatusNotDetermined) {
            [center requestAuthorizationWithOptions:UNAuthorizationOptionAlert | UNAuthorizationOptionSound
                                  completionHandler:^(BOOL granted, NSError *error) { continuePairing(); }];
        } else {
            continuePairing();
        }
    }];
}

- (NSString *)savedHostAltIRKForRecord:(NSDictionary *)record {
    NSDictionary *identity = [NSDictionary dictionaryWithContentsOfURL:_identityURL];
    NSString *value = identity[@"hostAltIRK"];
    if (![identity[@"publicKey"] isEqual:record[@"public_key"]] ||
        ![value isKindOfClass:NSString.class] || value.length != 32) return @"";
    NSCharacterSet *nonHex = [[NSCharacterSet characterSetWithCharactersInString:@"0123456789abcdefABCDEF"] invertedSet];
    return [value rangeOfCharacterFromSet:nonHex].location == NSNotFound ? value : @"";
}

- (void)beginNativePairing {
    if (!self.isPairing) return;
    if (self.cancelRequested) {
        [self finishPairing:CSError(NSUserCancelledError, @"Подключение отменено.")];
        return;
    }
    NSError *error = nil;
    NSData *active = CSReadLimitedURL([NSURL fileURLWithPath:self.pairingPath], NULL);
    NSString *kind = nil;
    NSDictionary *record = CSValidatePairing(active, &kind, NULL);
    [[NSFileManager defaultManager] removeItemAtURL:_pendingURL error:NULL];
    NSString *hostAltIRK = @"";
    if ([kind isEqualToString:@"Remote Pairing"]) {
        hostAltIRK = [self savedHostAltIRKForRecord:record];
        if (!CSWritePrivateData(active, _pendingURL, &error)) {
            [self finishPairing:CSError(22, @"Не удалось подготовить файл подключения. Исходное подключение сохранено.")];
            return;
        }
    }
    [self beginPairingKeepAlive];
    [self publishStatus:@"Подготовка локального сервера подключения…"];
    NSString *pendingPath = _pendingURL.path;
    // The block retains self until native completion. FFI callbacks copy all
    // borrowed strings before scheduling UI work. Only one invocation exists.
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool {
            ALPairResult result = {0};
            NSError *operationError = nil;
            BOOL committed = NO;
            if (self.cancelRequested) {
                operationError = CSError(NSUserCancelledError, @"Подключение отменено.");
            } else {
                int32_t rc = al_pairing_run_host("0.0.0.0", 0, "CarrierSIM", "Mac17,7",
                    pendingPath.fileSystemRepresentation, hostAltIRK.UTF8String,
                    CSReadyCallback, CSPINCallback, (__bridge void *)self, &result);
                if (rc != 0) {
                    NSString *detail = CSString(result.error);
                    operationError = CSError(23, detail.length ?
                        [@"Не удалось создать подключение: " stringByAppendingString:detail] :
                        @"iPhone не завершил подключение. Проверьте разрешение «Локальная сеть» и повторите.");
                } else if (!self.cancelRequested) {
                    NSError *readError = nil;
                    NSData *issuedData = CSReadLimitedURL([NSURL fileURLWithPath:pendingPath], &readError);
                    NSDictionary *issued = CSValidatePairing(issuedData, NULL, &readError);
                    NSString *issuedIRK = CSString(result.host_alt_irk_hex);
                    if (!issued || issuedIRK.length != 32) {
                        operationError = readError ?: CSError(24, @"Подключение завершилось без корректного файла ключей. Повторите попытку.");
                    } else {
                        committed = [self commitRecord:issuedData hostAltIRK:issuedIRK record:issued error:&operationError];
                    }
                }
            }
            al_pairing_result_free(&result);
            dispatch_async(dispatch_get_main_queue(), ^{
                if (!committed && self.cancelRequested) {
                    [self finishPairing:CSError(NSUserCancelledError, @"Подключение отменено.")];
                } else if (!committed && self->_publicationFailure.length) {
                    [self finishPairing:CSError(25, self->_publicationFailure)];
                } else {
                    [self finishPairing:operationError];
                }
            });
        }
    });
}

- (BOOL)commitRecord:(NSData *)data hostAltIRK:(NSString *)hostAltIRK
               record:(NSDictionary *)record error:(NSError **)error {
    // First save matching identity metadata, then atomically replace the active
    // record. If replacing the record fails, restore the previous metadata.
    NSData *oldIdentity = [NSData dataWithContentsOfURL:_identityURL];
    NSDictionary *identity = hostAltIRK.length ?
        @{@"hostAltIRK": hostAltIRK, @"publicKey": record[@"public_key"] ?: [NSData data]} : @{};
    NSData *identityData = [NSPropertyListSerialization dataWithPropertyList:identity
                                      format:NSPropertyListBinaryFormat_v1_0 options:0 error:error];
    if (!identityData || !CSWritePrivateData(identityData, _identityURL, error)) return NO;
    if (!CSWritePrivateData(data, [NSURL fileURLWithPath:self.pairingPath], error)) {
        if (oldIdentity) CSWritePrivateData(oldIdentity, _identityURL, NULL);
        else [[NSFileManager defaultManager] removeItemAtURL:_identityURL error:NULL];
        return NO;
    }
    return YES;
}

- (void)beginPairingKeepAlive {
    NSError *error = nil;
    AVAudioSession *session = AVAudioSession.sharedInstance;
    [session setCategory:AVAudioSessionCategoryPlayback withOptions:AVAudioSessionCategoryOptionMixWithOthers error:&error];
    if (!error) [session setActive:YES error:&error];
    if (!error) {
        _silentPlayer = [[AVAudioPlayer alloc] initWithData:CSSilentWAV() error:&error];
        _silentPlayer.numberOfLoops = -1;
        _silentPlayer.volume = 0.01f;
        [_silentPlayer prepareToPlay];
        [_silentPlayer play];
    }
    __weak CSConnectionManager *weakSelf = self;
    _backgroundTask = [[UIApplication sharedApplication] beginBackgroundTaskWithName:@"CarrierSIM pairing"
        expirationHandler:^{
            CSConnectionManager *strongSelf = weakSelf;
            if (!strongSelf) return;
            // Always release the finite UIKit assertion immediately. Audio
            // may still provide legitimate background runtime independently.
            if (strongSelf->_backgroundTask != UIBackgroundTaskInvalid) {
                UIBackgroundTaskIdentifier token = strongSelf->_backgroundTask;
                strongSelf->_backgroundTask = UIBackgroundTaskInvalid;
                [[UIApplication sharedApplication] endBackgroundTask:token];
            }
            if (!strongSelf.isPairing || strongSelf->_silentPlayer.isPlaying) return;
            strongSelf->_publicationFailure = @"iOS остановила фоновое подключение. Вернитесь в CarrierSIM и повторите.";
            [strongSelf publishStatus:strongSelf->_publicationFailure];
            al_pairing_cancel_host();
        }];
}

- (void)endPairingKeepAlive {
    [_silentPlayer stop];
    _silentPlayer = nil;
    [AVAudioSession.sharedInstance setActive:NO
                                withOptions:AVAudioSessionSetActiveOptionNotifyOthersOnDeactivation error:NULL];
    if (_backgroundTask != UIBackgroundTaskInvalid) {
        [[UIApplication sharedApplication] endBackgroundTask:_backgroundTask];
        _backgroundTask = UIBackgroundTaskInvalid;
    }
}

- (void)nativeReadyWithService:(NSString *)serviceID port:(uint16_t)port txt:(NSDictionary *)txt {
    if (!self.isPairing) return;
    if (self.cancelRequested) {
        // Also handles cancellation before Rust's worker started/reset its flag.
        al_pairing_cancel_host();
        return;
    }
    if (!serviceID.length || !port || !txt[@"authTag"] || !txt[@"name"] || !txt[@"model"]) {
        _publicationFailure = @"Не удалось подготовить объявление подключения iPhone.";
        al_pairing_cancel_host();
        return;
    }
    [_netService stop];
    _netService = [[NSNetService alloc] initWithDomain:@"local."
                                               type:@"_remotepairing-pairable-host._tcp."
                                               name:serviceID port:port];
    _netService.delegate = self;
    [_netService setTXTRecordData:[NSNetService dataFromTXTRecordDictionary:txt]];
    [_netService scheduleInRunLoop:NSRunLoop.mainRunLoop forMode:NSRunLoopCommonModes];
    [_netService publish];
    [self publishStatus:@"Разрешите «Локальную сеть». Затем: Настройки → Конфиденциальность и безопасность → Режим разработчика → Подключить к CarrierSIM."];
}

- (void)netServiceDidPublish:(NSNetService *)sender {
    if (sender != _netService || !self.isPairing || self.cancelRequested) return;
    [self publishStatus:@"CarrierSIM готов к подключению. Откройте настройки режима разработчика и выберите CarrierSIM. Код появится в уведомлении."];
}

- (void)netService:(NSNetService *)sender didNotPublish:(NSDictionary<NSString *, NSNumber *> *)errorDict {
    if (sender != _netService || !self.isPairing) return;
    _publicationFailure = @"iOS не разрешила локальное подключение. В настройках CarrierSIM включите «Локальная сеть» и повторите.";
    [self publishStatus:_publicationFailure];
    al_pairing_cancel_host();
}

- (void)nativePIN:(NSString *)pin {
    if (!self.isPairing || self.cancelRequested) return;
    NSCharacterSet *invalid = [[NSCharacterSet decimalDigitCharacterSet] invertedSet];
    if (pin.length < 4 || pin.length > 10 || [pin rangeOfCharacterFromSet:invalid].location != NSNotFound) return;
    if (self.onPIN) self.onPIN(pin);
    [self publishStatus:@"Введите код из уведомления в окне подключения iPhone."];
    [self postNotification:@"carriersim.pairing.pin" title:@"CarrierSIM: код подключения"
                      body:[NSString stringWithFormat:@"Введите %@ в настройках режима разработчика.", pin]];
}

- (void)cancelPairing {
    if (![NSThread isMainThread]) {
        dispatch_async(dispatch_get_main_queue(), ^{ [self cancelPairing]; });
        return;
    }
    if (!self.isPairing) return;
    self.cancelRequested = YES;
    [_netService stop];
    _netService = nil;
    al_pairing_cancel_host();
    [self endPairingKeepAlive];
    [self publishStatus:@"Завершаем подключение…"];
}

- (void)finishPairing:(NSError *)error {
    [_netService stop];
    _netService = nil;
    [self endPairingKeepAlive];
    [[NSFileManager defaultManager] removeItemAtURL:_pendingURL error:NULL];
    [[UNUserNotificationCenter currentNotificationCenter]
        removeDeliveredNotificationsWithIdentifiers:@[@"carriersim.pairing.pin"]];
    self.isPairing = NO;
    self.cancelRequested = NO;
    self.hasPairing = CSValidatePairing(CSReadLimitedURL([NSURL fileURLWithPath:self.pairingPath], NULL), NULL, NULL) != nil;
    if (error) {
        [self publishStatus:error.localizedDescription];
    } else {
        [self publishStatus:@"Подключение сохранено. Включите локальный VPN и проверьте iPhone."];
        [self postNotification:@"carriersim.pairing.done" title:@"CarrierSIM: подключение готово"
                          body:@"Вернитесь в CarrierSIM. Файл подключения уже сохранён автоматически."];
    }
    if (self.onPairingDone) self.onPairingDone(error);
}

- (void)importPairingAtURL:(NSURL *)url completion:(CSConnectionCompletion)completion {
    if (![NSThread isMainThread]) {
        dispatch_async(dispatch_get_main_queue(), ^{ [self importPairingAtURL:url completion:completion]; });
        return;
    }
    if (self.isPairing || _importing) {
        completion(CSError(30, @"Сначала завершите текущее подключение."));
        return;
    }
    if (!url.isFileURL) {
        completion(CSError(31, @"Выберите локальный файл подключения через приложение «Файлы»."));
        return;
    }
    [self preparePrivateDirectory];
    if (_storageError) {
        completion(CSError(32, @"Не удалось открыть защищённое хранилище. Разблокируйте iPhone."));
        return;
    }
    _importing = YES;
    [self publishStatus:@"Проверяем выбранный файл подключения…"];
    BOOL scoped = [url startAccessingSecurityScopedResource];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool {
            __block NSError *error = nil;
            __block NSData *data = nil;
            NSError *coordinationError = nil;
            NSFileCoordinator *coordinator = [[NSFileCoordinator alloc] initWithFilePresenter:nil];
            [coordinator coordinateReadingItemAtURL:url options:NSFileCoordinatorReadingWithoutChanges
                                              error:&coordinationError byAccessor:^(NSURL *newURL) {
                data = CSReadLimitedURL(newURL, &error);
            }];
            if (!error && coordinationError) error = CSError(33, @"Не удалось получить выбранный файл из приложения «Файлы».");
            NSString *kind = nil;
            NSDictionary *record = error ? nil : CSValidatePairing(data, &kind, &error);
            if (record) [self commitRecord:data hostAltIRK:@"" record:record error:&error];
            if (scoped) [url stopAccessingSecurityScopedResource];
            dispatch_async(dispatch_get_main_queue(), ^{
                self->_importing = NO;
                self.hasPairing = CSValidatePairing(CSReadLimitedURL([NSURL fileURLWithPath:self.pairingPath], NULL), NULL, NULL) != nil;
                [self publishStatus:error ? error.localizedDescription :
                    [NSString stringWithFormat:@"Файл %@ сохранён. Теперь проверьте подключение к этому iPhone.", kind]];
                completion(error);
            });
        }
    });
}

#pragma mark - Optional embedded VPN

- (NSError *)vpnError:(NSError *)error {
    NSString *reason = error.localizedDescription ?: @"iOS отклонила запуск расширения";
    return CSError(40, [NSString stringWithFormat:
        @"Локальный VPN не запущен: %@. Для встроенного VPN подпись приложения должна разрешать Network Extensions. Можно использовать кнопку LocalDevVPN.", reason]);
}

- (void)completeVPN:(NSError *)error {
    CSConnectionCompletion completion = _vpnCompletion;
    _vpnCompletion = nil;
    self.isVPNStarting = NO;
    if (error) [self publishStatus:error.localizedDescription];
    else [self publishStatus:@"Локальный VPN включён. Теперь проверьте подключение к iPhone."];
    if (completion) completion(error);
}

- (void)startVPN:(CSConnectionCompletion)completion {
    if (![NSThread isMainThread]) {
        dispatch_async(dispatch_get_main_queue(), ^{ [self startVPN:completion]; });
        return;
    }
    NSString *providerID = [self embeddedVPNIdentifier];
    if (!providerID.length) {
        completion(CSError(41, @"В этой сборке нет встроенного VPN. Используйте кнопку LocalDevVPN."));
        return;
    }
    if (self.isVPNStarting) {
        completion(CSError(42, @"Локальный VPN уже запускается."));
        return;
    }
    self.isVPNStarting = YES;
    _vpnCompletion = [completion copy];
    _vpnSawConnecting = NO;
    NSUInteger generation = ++_vpnGeneration;
    [self publishStatus:@"Подготовка локального VPN. Если iOS спросит, разрешите добавить конфигурацию VPN."];
    [NETunnelProviderManager loadAllFromPreferencesWithCompletionHandler:^(NSArray<NETunnelProviderManager *> *managers, NSError *error) {
        dispatch_async(dispatch_get_main_queue(), ^{
            if (generation != self->_vpnGeneration || !self.isVPNStarting) return;
            if (error) { [self completeVPN:[self vpnError:error]]; return; }
            NETunnelProviderManager *manager = nil;
            for (NETunnelProviderManager *candidate in managers) {
                NETunnelProviderProtocol *proto = (id)candidate.protocolConfiguration;
                if ([proto isKindOfClass:NETunnelProviderProtocol.class] &&
                    [proto.providerBundleIdentifier isEqualToString:providerID]) {
                    manager = candidate;
                    break;
                }
            }
            if (manager.connection.status == NEVPNStatusConnected) {
                self->_vpnManager = manager;
                [self completeVPN:nil];
                return;
            }
            if (!manager) manager = [NETunnelProviderManager new];
            self->_vpnManager = manager;
            NETunnelProviderProtocol *proto = [NETunnelProviderProtocol new];
            proto.providerBundleIdentifier = providerID;
            proto.serverAddress = @"10.7.0.1";
            proto.disconnectOnSleep = NO;
            manager.protocolConfiguration = proto;
            manager.localizedDescription = @"CarrierSIM · подключение к iPhone";
            manager.enabled = YES;
            manager.onDemandEnabled = NO;
            [manager saveToPreferencesWithCompletionHandler:^(NSError *saveError) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    if (generation != self->_vpnGeneration || !self.isVPNStarting) return;
                    if (saveError) { [self completeVPN:[self vpnError:saveError]]; return; }
                    [manager loadFromPreferencesWithCompletionHandler:^(NSError *loadError) {
                        dispatch_async(dispatch_get_main_queue(), ^{
                            if (generation != self->_vpnGeneration || !self.isVPNStarting) return;
                            if (loadError) { [self completeVPN:[self vpnError:loadError]]; return; }
                            NSError *startError = nil;
                            if (![manager.connection startVPNTunnelAndReturnError:&startError]) {
                                [self completeVPN:[self vpnError:startError]];
                                return;
                            }
                            [self observeCurrentVPNStatus];
                            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 25 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
                                if (generation != self->_vpnGeneration || !self.isVPNStarting) return;
                                if (manager.connection.status == NEVPNStatusConnected) {
                                    [self completeVPN:nil];
                                } else {
                                    [manager.connection stopVPNTunnel];
                                    [self completeVPN:CSError(43, @"iOS не запустила локальный VPN за 25 секунд. Проверьте поддержку Network Extensions вашей подписью или используйте LocalDevVPN.")];
                                }
                            });
                        });
                    }];
                });
            }];
        });
    }];
}

- (void)observeCurrentVPNStatus {
    if (!_vpnManager) return;
    NEVPNStatus state = _vpnManager.connection.status;
    if (state == NEVPNStatusConnected) {
        if (self.isVPNStarting) [self completeVPN:nil];
    } else if (state == NEVPNStatusConnecting || state == NEVPNStatusReasserting) {
        _vpnSawConnecting = YES;
        if (self.isVPNStarting) [self publishStatus:@"iOS запускает локальное подключение…"];
    } else if (self.isVPNStarting &&
               (state == NEVPNStatusInvalid || (_vpnSawConnecting && state == NEVPNStatusDisconnected))) {
        [self completeVPN:CSError(44, @"Локальное расширение VPN не запустилось. Проверьте подпись приложения или используйте LocalDevVPN.")];
    }
}

- (void)vpnStatusChanged:(NSNotification *)notification {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (notification.object == self->_vpnManager.connection) [self observeCurrentVPNStatus];
    });
}

- (void)stopVPN {
    if (![NSThread isMainThread]) {
        dispatch_async(dispatch_get_main_queue(), ^{ [self stopVPN]; });
        return;
    }
    ++_vpnGeneration;
    [_vpnManager.connection stopVPNTunnel];
    if (self.isVPNStarting) [self completeVPN:CSError(NSUserCancelledError, @"Запуск VPN отменён.")];
    [self publishStatus:@"Локальный VPN CarrierSIM выключен."];
}

- (void)refreshVPNStatus {
    if (![NSThread isMainThread]) {
        dispatch_async(dispatch_get_main_queue(), ^{ [self refreshVPNStatus]; });
        return;
    }
    if (_vpnManager) { [self observeCurrentVPNStatus]; return; }
    if (self.isVPNStarting) return;
    NSString *providerID = [self embeddedVPNIdentifier];
    if (!providerID.length) return;
    [NETunnelProviderManager loadAllFromPreferencesWithCompletionHandler:^(NSArray<NETunnelProviderManager *> *managers, NSError *error) {
        dispatch_async(dispatch_get_main_queue(), ^{
            if (self.isVPNStarting || error) return;
            for (NETunnelProviderManager *candidate in managers) {
                NETunnelProviderProtocol *proto = (id)candidate.protocolConfiguration;
                if ([proto isKindOfClass:NETunnelProviderProtocol.class] &&
                    [proto.providerBundleIdentifier isEqualToString:providerID]) {
                    self->_vpnManager = candidate;
                    [self observeCurrentVPNStatus];
                    break;
                }
            }
        });
    }];
}

- (void)appDidBecomeActive:(NSNotification *)notification {
    [self refreshVPNStatus];
}

- (void)openLocalDevVPN:(CSConnectionCompletion)completion {
    if (![NSThread isMainThread]) {
        dispatch_async(dispatch_get_main_queue(), ^{ [self openLocalDevVPN:completion]; });
        return;
    }
    NSURL *url = [NSURL URLWithString:@"localdevvpn://enable?scheme=carriersim"];
    [UIApplication.sharedApplication openURL:url options:@{} completionHandler:^(BOOL success) {
        dispatch_async(dispatch_get_main_queue(), ^{
            if (!success) {
                NSError *error = CSError(45, @"LocalDevVPN не установлен или iOS не разрешила его открыть.");
                [self publishStatus:error.localizedDescription];
                completion(error);
                return;
            }
            self->_externalVPNOpened = YES;
            [self publishStatus:@"LocalDevVPN открыт. После возвращения проверьте подключение к iPhone."];
            completion(nil);
        });
    }];
}

@end
