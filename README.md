# CarrierSIM 1.2 для iPhone

**ОРИГИНАЛ CARRIERSIM ВЗЯТ ИЗ [IOS-BUNDLES/CARRIERSIM](https://github.com/ios-bundles/CarrierSIM).**

[Скачать 1.2](https://github.com/lucifervalter-a11y/CarrierSIM-iOS/releases/tag/v1.2.0) · [Инструкция](CarrierSIM-iOS/README.md) · [Исходники](CarrierSIM-iOS/)

CarrierSIM на вашем iPhone предлагает два сценария для телефона друга:

- **Работать с профилем оператора без установки CarrierSIM другу.** Выберите «Другой iPhone», подключитесь через доверенное сопряжение, проверьте его SIM и примените профиль.
- **Передать это же приложение другу.** Импортируйте P12 и provisioning profile, разрешающий его устройство, затем подпишите CarrierSIM и запросите установку по Wi-Fi.

Добавлен экран режима разработчика: чтение состояния, запрос показа пункта в настройках и запрос включения через доступную службу AMFI. Перезагрузку и системные подтверждения выполняет владелец телефона; приложение проверяет состояние после его возвращения.

## Скачать

- [Полный комплект CarrierSIM-1.2-LAN.zip](https://github.com/lucifervalter-a11y/CarrierSIM-iOS/raw/refs/heads/main/downloads/CarrierSIM-1.2-LAN.zip) — два IPA, исходники, инструкция и результаты проверок.
- [CarrierSIM-1.2-unsigned.ipa](https://github.com/lucifervalter-a11y/CarrierSIM-iOS/raw/refs/heads/main/downloads/CarrierSIM-1.2-unsigned.ipa) — со встроенным VPN. Для подписи нужны профили приложения и VPN-расширения с соответствующими разрешениями.
- [CarrierSIM-1.2-external-vpn.ipa](https://github.com/lucifervalter-a11y/CarrierSIM-iOS/raw/refs/heads/main/downloads/CarrierSIM-1.2-external-vpn.ipa) — без расширения; для локального подключения нужен отдельный LocalDevVPN.

Сначала подпишите выбранный IPA для своего телефона через ваш сервис установки. Публичные IPA содержат техническую ad-hoc подпись и требуют подписи Apple для установки. Вход через iCloud/Apple Account и выпуск сертификатов в 1.2 не реализованы. Для встроенной подписи нужны настоящий P12, пароль и подходящий `.mobileprovision`. Пароль вводится в приложении и не сохраняется; сертификаты сюда загружать не нужно.

## Проверка и пределы

**Экспериментальный выпуск:** прошли 68 основных Rust-тестов и отдельный тест туннеля; обе нативные ARM64 IPA проверены. Проверена подпись реального ARM64-бандла тестовым P12, проверка подписи и обнаружение изменения файла. Физические iPhone в среде сборки недоступны: стабильность Wi-Fi-установки, AMFI и смены профиля на iOS 26/27 пока не подтверждена.

Общая Wi-Fi-сеть не гарантирует доступ к службам Apple. Нужны сопряжение именно с целевым iPhone и доступные службы. При первоначальной подготовке может понадобиться компьютер. USB-C между двумя iPhone и доступ через мобильную сеть в этой версии отсутствуют.

Пакет требует iOS 26+. Встроенное создание Remote Pairing через настройки рассчитано на iOS 27; на iOS 26 нужен готовый файл. Аппаратная поддержка 5G у iPhone 12+ не означает, что смена профиля включит настоящую сеть 5G у Yota/t2: нужны услуга, SIM, тариф и покрытие оператора.

[Если нет режима разработчика или не подходит сертификат](TROUBLESHOOTING.md) · [Что изменилось в 1.2](docs/RELEASE-1.2.md) · [Проектирование AMFI](docs/DEVELOPER-MODE-PLAN.md)

## Сборка

Полный проект находится в `CarrierSIM-iOS/`. GitHub Actions **Build CarrierSIM IPA** собирает оба пакета и запускает проверки.

```sh
cd CarrierSIM-iOS
bash scripts/setup-linux.sh --build
```

[Требования сборки](CarrierSIM-iOS/scripts/BUILDING.md) · [Протокол проверки](CarrierSIM-iOS/Tests/VALIDATION.txt) · [Авторы](CREDITS.md)
