#import "CSShareViewController.h"
#import "airlift.h"
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>

static NSString *CSShareText(id value) {return [value isKindOfClass:NSString.class] ? value : @"";}
@interface CSShareViewController () <UIDocumentPickerDelegate>
@property (nonatomic, copy) NSString *pairingPath;
@property (nonatomic, copy) NSDictionary *target;
@property (nonatomic, copy) NSDictionary *device;
@property (nonatomic, strong) NSURL *work;
@property (nonatomic, strong) dispatch_queue_t queue;
@property (nonatomic, copy) NSString *message;
@property (nonatomic) NSInteger importing;
@property (nonatomic) BOOL busy;
@property (nonatomic) BOOL sourceHasVPN;
@property (nonatomic) UIBackgroundTaskIdentifier backgroundTask;
@end

static void CSShareLog(void *context,const char *message) {
    if (!context || !message) return;
    CSShareViewController *controller=(__bridge CSShareViewController *)context;
    NSString *text=[NSString stringWithUTF8String:message] ?: @"";
    dispatch_async(dispatch_get_main_queue(),^{controller.message=text;[controller.tableView reloadData];if (controller.onLog) controller.onLog(text);});
}
@implementation CSShareViewController
- (instancetype)initWithPairingPath:(NSString *)pairingPath workDirectory:(NSURL *)work
                             target:(NSDictionary *)target device:(NSDictionary *)device operationQueue:(dispatch_queue_t)queue {
    if ((self=[super initWithStyle:UITableViewStyleInsetGrouped])) {
        _pairingPath=[pairingPath copy];_work=work;_target=[target copy];_device=[device copy];_queue=queue;
        _message=@"Выбери свой P12 и профиль, разрешающий iPhone друга. Пароль вводится перед подписью и не сохраняется.";
        _backgroundTask=UIBackgroundTaskInvalid;
        _sourceHasVPN=[NSFileManager.defaultManager fileExistsAtPath:[NSBundle.mainBundle.bundlePath stringByAppendingPathComponent:@"PlugIns/CarrierSIMTunnel.appex"]];
    }return self;
}
- (void)viewDidLoad {
    [super viewDidLoad];self.title=@"Отправить CarrierSIM";
    self.tableView.rowHeight=UITableViewAutomaticDimension;self.tableView.estimatedRowHeight=72;
}
- (NSURL *)signingDirectory {return [self.work URLByAppendingPathComponent:@"signing" isDirectory:YES];}
- (NSURL *)fileForRole:(NSInteger)role {return [[self signingDirectory] URLByAppendingPathComponent:@[@"certificate.p12",@"app.mobileprovision",@"vpn.mobileprovision"][role]];}
- (BOOL)exists:(NSInteger)role {return [NSFileManager.defaultManager fileExistsAtPath:[self fileForRole:role].path];}
- (void)alert:(NSString *)title text:(NSString *)text {
    UIAlertController *alert=[UIAlertController alertControllerWithTitle:title message:text preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"Понятно" style:UIAlertActionStyleDefault handler:nil]];
    if (!self.presentedViewController && self.view.window) [self presentViewController:alert animated:YES completion:nil];
}
- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {return 3;}
- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {return section==0 ? 1 : section==1 ? 3 : 3;}
- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section {return @[@"Кому",@"Подпись",@"Действия"][section];}
- (NSString *)tableView:(UITableView *)tableView titleForFooterInSection:(NSInteger)section {
    if (section==1) return @"P12 содержит сертификат и закрытый ключ. Файлы хранятся защищённо на этом iPhone. Профиль должен разрешать com.tema.CarrierSIM и телефон друга. Для встроенного VPN нужны отдельный профиль com.tema.CarrierSIM.Tunnel и разрешения VPN в обоих профилях.";
    if (section==2) return @"Передаётся только текущий CarrierSIM. Без профиля VPN отправляется вариант для LocalDevVPN. Оба телефона должны быть в одной Wi-Fi-сети с доступным сопряжением. Подпись через вход в Apple Account в этом выпуске отсутствует.";
    return nil;
}
- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)path {
    UITableViewCell *cell=[[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:nil];
    cell.textLabel.numberOfLines=0;cell.detailTextLabel.numberOfLines=0;cell.detailTextLabel.textColor=UIColor.secondaryLabelColor;
    BOOL enabled=!self.busy;
    if (path.section==0){
        cell.textLabel.text=[NSString stringWithFormat:@"%@ · %@",CSShareText(self.device[@"name"]),CSShareText(self.device[@"model"])];
        cell.detailTextLabel.text=self.message;enabled=NO;
    } else if (path.section==1){
        cell.textLabel.text=@[@"Сертификат P12",@"Профиль приложения",@"Профиль встроенного VPN (необязательно)"][path.row];
        cell.detailTextLabel.text=[self exists:path.row] ? @"Файл импортирован. Нажми, чтобы заменить." : @"Выбрать файл";
        if (path.row==2 && !self.sourceHasVPN) {enabled=NO;cell.detailTextLabel.text=@"В текущем CarrierSIM нет встроенного VPN";}
    } else {
        cell.textLabel.text=@[@"Подписать и установить CarrierSIM другу",@"Отправить уже подписанный CarrierSIM",@"Удалить сохранённые файлы подписи"][path.row];
        if (path.row==0) enabled=enabled && [self exists:0] && [self exists:1];
        if (path.row==1) cell.detailTextLabel.text=@"Выбрать IPA, подготовленный в DDE Store";
        if (path.row==2) cell.detailTextLabel.text=@"Удаляет P12 и оба профиля из CarrierSIM";
    }
    cell.textLabel.textColor=enabled ? UIColor.labelColor : UIColor.tertiaryLabelColor;
    cell.selectionStyle=enabled ? UITableViewCellSelectionStyleDefault : UITableViewCellSelectionStyleNone;
    cell.userInteractionEnabled=enabled;return cell;
}
- (void)choose:(NSInteger)role {
    self.importing=role;
    UIDocumentPickerViewController *picker=[[UIDocumentPickerViewController alloc] initForOpeningContentTypes:@[UTTypeData] asCopy:YES];
    picker.delegate=self;picker.allowsMultipleSelection=NO;[self presentViewController:picker animated:YES completion:nil];
}
- (void)documentPicker:(UIDocumentPickerViewController *)controller didPickDocumentsAtURLs:(NSArray<NSURL *> *)urls {
    NSURL *url=urls.firstObject;if (!url || self.busy) return;
    if (self.importing==3){[self sendPrepared:url];return;}
    NSInteger role=self.importing;NSString *extension=url.pathExtension.lowercaseString;
    if ((role==0 && ![@[@"p12",@"pfx"] containsObject:extension]) || (role!=0 && ![extension isEqualToString:@"mobileprovision"])) {
        [self alert:@"Файл не подходит" text:role==0 ? @"Нужен .p12 или .pfx с сертификатом и закрытым ключом." : @"Нужен оригинальный .mobileprovision от поставщика сертификата."];return;
    }
    BOOL scoped=[url startAccessingSecurityScopedResource];NSError *error=nil;
    NSDictionary *attributes=[NSFileManager.defaultManager attributesOfItemAtPath:url.path error:&error];
    unsigned long long size=[attributes[NSFileSize] unsignedLongLongValue];
    NSURL *dir=[self signingDirectory],*file=[self fileForRole:role],*temp=[dir URLByAppendingPathComponent:@"import.tmp"];
    BOOL saved=size>0 && size<=(role==0 ? 8ULL : 4ULL)*1024*1024 &&
        [NSFileManager.defaultManager createDirectoryAtURL:dir withIntermediateDirectories:YES attributes:@{NSFilePosixPermissions:@0700,NSFileProtectionKey:NSFileProtectionComplete} error:&error];
    [NSFileManager.defaultManager removeItemAtURL:temp error:nil];
    saved=saved && [NSFileManager.defaultManager copyItemAtURL:url toURL:temp error:&error] &&
        [NSFileManager.defaultManager setAttributes:@{NSFilePosixPermissions:@0600,NSFileProtectionKey:NSFileProtectionComplete} ofItemAtPath:temp.path error:&error];
    if (saved){
        [dir setResourceValue:@YES forKey:NSURLIsExcludedFromBackupKey error:nil];
        saved=[NSFileManager.defaultManager fileExistsAtPath:file.path] ? [NSFileManager.defaultManager replaceItemAtURL:file withItemAtURL:temp backupItemName:nil options:0 resultingItemURL:nil error:&error] : [NSFileManager.defaultManager moveItemAtURL:temp toURL:file error:&error];
    }
    if (scoped) [url stopAccessingSecurityScopedResource];[NSFileManager.defaultManager removeItemAtURL:temp error:nil];
    self.message=saved ? @"Файл сохранён. Сертификат и разрешение телефона проверятся при подписи." : @"Файл не удалось сохранить. Проверь загрузку и размер: P12 до 8 МБ, профиль до 4 МБ.";
    [self.tableView reloadData];if (!saved) [self alert:@"Импорт не завершён" text:self.message];
}
- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)path {
    [tableView deselectRowAtIndexPath:path animated:YES];if (self.busy || path.section==0) return;
    if (path.section==1){[self choose:path.row];return;}
    if (path.row==1){[self choose:3];return;}
    if (path.row==2){
        UIAlertController *alert=[UIAlertController alertControllerWithTitle:@"Удалить файлы подписи?" message:@"P12 и профили будут удалены из CarrierSIM. Исходные файлы в «Файлах» сохранятся." preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"Отмена" style:UIAlertActionStyleCancel handler:nil]];
        [alert addAction:[UIAlertAction actionWithTitle:@"Удалить" style:UIAlertActionStyleDestructive handler:^(UIAlertAction *a){[NSFileManager.defaultManager removeItemAtURL:[self signingDirectory] error:nil];self.message=@"Файлы подписи удалены из CarrierSIM.";[self.tableView reloadData];}]];
        [self presentViewController:alert animated:YES completion:nil];return;
    }
    NSString *variant=[self exists:2] && self.sourceHasVPN ? @"С встроенным VPN, если профили его разрешают." : @"Без встроенного VPN. Для работы на самом телефоне друга потребуется LocalDevVPN.";
    UIAlertController *alert=[UIAlertController alertControllerWithTitle:@"Подписать и установить?"
        message:[NSString stringWithFormat:@"CarrierSIM → %@\n\n%@\n\nВведи пароль P12. Оставь оба телефона разблокированными.",CSShareText(self.device[@"name"]),variant] preferredStyle:UIAlertControllerStyleAlert];
    [alert addTextFieldWithConfigurationHandler:^(UITextField *field){field.placeholder=@"Пароль P12 (может быть пустым)";field.secureTextEntry=YES;field.autocorrectionType=UITextAutocorrectionTypeNo;field.autocapitalizationType=UITextAutocapitalizationTypeNone;}];
    __weak UIAlertController *weakAlert=alert;
    [alert addAction:[UIAlertAction actionWithTitle:@"Отмена" style:UIAlertActionStyleCancel handler:^(UIAlertAction *a){weakAlert.textFields.firstObject.text=nil;}]];
    [alert addAction:[UIAlertAction actionWithTitle:@"Подписать и установить" style:UIAlertActionStyleDefault handler:^(UIAlertAction *a){NSString *password=weakAlert.textFields.firstObject.text ?: @"";weakAlert.textFields.firstObject.text=nil;[self signAndSend:password];}]];
    [self presentViewController:alert animated:YES completion:nil];
}
- (void)begin {
    self.busy=YES;if (self.onBusy) self.onBusy(YES);[self.tableView reloadData];
    self.backgroundTask=[UIApplication.sharedApplication beginBackgroundTaskWithName:@"CarrierSIM share" expirationHandler:^{
        self.message=@"Вернись в CarrierSIM. iOS ограничивает работу в фоне; перед повтором проверь телефон друга.";
        [self.tableView reloadData];UIBackgroundTaskIdentifier task=self.backgroundTask;self.backgroundTask=UIBackgroundTaskInvalid;
        if (task!=UIBackgroundTaskInvalid) [UIApplication.sharedApplication endBackgroundTask:task];
    }];
}
- (void)finish:(NSDictionary *)result error:(NSString *)error {
    self.busy=NO;if (self.onBusy) self.onBusy(NO);
    if (self.backgroundTask!=UIBackgroundTaskInvalid){[UIApplication.sharedApplication endBackgroundTask:self.backgroundTask];self.backgroundTask=UIBackgroundTaskInvalid;}
    BOOL installed=[result[@"installed"] boolValue];self.message=installed ? CSShareText(result[@"message"]) : (error ?: @"Установка не подтверждена. Проверь iPhone друга перед повтором.");
    if (self.onLog) self.onLog(self.message);if (self.onFinished) self.onFinished(result);
    [self.tableView reloadData];[self alert:installed ? @"CarrierSIM установлен" : @"Отправка не завершена" text:self.message];
}
- (NSDictionary *)install:(NSString *)ipa error:(NSString **)error {
    NSData *data=[NSJSONSerialization dataWithJSONObject:@{@"target":self.target,@"expected_device_hash":self.device[@"identity_hash"],@"carriersim_only":@YES} options:0 error:nil];
    NSString *request=[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];char *output=NULL,*errorText=NULL;
    int32_t code=cs_install_ipa(self.pairingPath.UTF8String,ipa.UTF8String,self.work.path.UTF8String,request.UTF8String,CSShareLog,(__bridge void *)self,&output,&errorText);
    NSDictionary *result=output ? [NSJSONSerialization JSONObjectWithData:[[NSString stringWithUTF8String:output] dataUsingEncoding:NSUTF8StringEncoding] options:0 error:nil] : nil;
    if (errorText && error) *error=[NSString stringWithUTF8String:errorText];
    if (output) al_string_free(output);if (errorText) al_string_free(errorText);
    return code==0 && [result isKindOfClass:NSDictionary.class] ? result : nil;
}
- (void)signAndSend:(NSString *)password {
    if (self.busy || ![self exists:0] || ![self exists:1]) return;
    [self begin];
    dispatch_async(self.queue,^{@autoreleasepool {
        NSString *request=[[NSString alloc] initWithData:[NSJSONSerialization dataWithJSONObject:@{@"expected_device_hash":self.device[@"identity_hash"]} options:0 error:nil] encoding:NSUTF8StringEncoding];
        NSString *extension=[self exists:2] && self.sourceHasVPN ? [self fileForRole:2].path : @"";
        char *output=NULL,*errorText=NULL;
        int32_t code=cs_sign_self(NSBundle.mainBundle.bundlePath.UTF8String,self.work.path.UTF8String,[self fileForRole:0].path.UTF8String,password.UTF8String,
            [self fileForRole:1].path.UTF8String,extension.UTF8String,request.UTF8String,CSShareLog,(__bridge void *)self,&output,&errorText);
        NSDictionary *signedResult=output ? [NSJSONSerialization JSONObjectWithData:[[NSString stringWithUTF8String:output] dataUsingEncoding:NSUTF8StringEncoding] options:0 error:nil] : nil;
        NSString *error=errorText ? [NSString stringWithUTF8String:errorText] : nil;
        if (output) al_string_free(output);if (errorText) al_string_free(errorText);
        NSString *ipa=CSShareText(signedResult[@"ipa_path"]);NSDictionary *installed=nil;
        if (code==0 && [signedResult[@"signed"] boolValue] && ipa.length) installed=[self install:ipa error:&error];
        if (ipa.length) [NSFileManager.defaultManager removeItemAtPath:ipa error:nil];
        dispatch_async(dispatch_get_main_queue(),^{[self finish:installed error:error];});
    }});
}
- (void)sendPrepared:(NSURL *)url {
    if (!url.isFileURL || ![url.pathExtension.lowercaseString isEqualToString:@"ipa"]) {[self alert:@"Нужен IPA" text:@"Выбери CarrierSIM, уже подписанный для телефона друга."];return;}
    UIAlertController *alert=[UIAlertController alertControllerWithTitle:@"Установить выбранный CarrierSIM?" message:[NSString stringWithFormat:@"iPhone: %@\nФайл: %@\n\nВ IPA должно быть приложение CarrierSIM, подписанное для этого телефона.",CSShareText(self.device[@"name"]),url.lastPathComponent] preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"Отмена" style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"Установить" style:UIAlertActionStyleDefault handler:^(UIAlertAction *a){
        [self begin];dispatch_async(self.queue,^{@autoreleasepool {
            BOOL scoped=[url startAccessingSecurityScopedResource];NSURL *copy=[self.work URLByAppendingPathComponent:@"prepared-share.ipa"];
            NSDictionary *attributes=[NSFileManager.defaultManager attributesOfItemAtPath:url.path error:nil];unsigned long long size=[attributes[NSFileSize] unsignedLongLongValue];
            [NSFileManager.defaultManager removeItemAtURL:copy error:nil];
            BOOL copied=size>0 && size<=512ULL*1024*1024 && [NSFileManager.defaultManager copyItemAtURL:url toURL:copy error:nil] &&
                [NSFileManager.defaultManager setAttributes:@{NSFilePosixPermissions:@0600,NSFileProtectionKey:NSFileProtectionComplete} ofItemAtPath:copy.path error:nil];
            if (scoped) [url stopAccessingSecurityScopedResource];NSString *error=copied ? nil : @"IPA недоступен или больше 512 МБ.";
            if (copied) copied=[copy setResourceValue:@YES forKey:NSURLIsExcludedFromBackupKey error:nil];
            NSDictionary *result=copied ? [self install:copy.path error:&error] : nil;[NSFileManager.defaultManager removeItemAtURL:copy error:nil];
            dispatch_async(dispatch_get_main_queue(),^{[self finish:result error:error];});
        }});
    }]];[self presentViewController:alert animated:YES completion:nil];
}
@end
