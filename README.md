# CarrierSIM 1.1 для iPhone

**ОРИГИНАЛ CARRIERSIM ВЗЯТ ИЗ [IOS-BUNDLES/CARRIERSIM](https://github.com/ios-bundles/CarrierSIM).**

[Скачать версию 1.1](https://github.com/lucifervalter-a11y/CarrierSIM-iOS/releases/tag/v1.1.0) · [Полная инструкция](CarrierSIM-iOS/README.md) · [Исходники](CarrierSIM-iOS/)

Новая экспериментальная сборка: выбор своего или другого iPhone, поиск служб Apple в Wi-Fi, установка подписанного IPA, отдельные сопряжения и резервные копии.

## Что скачать

- **[CarrierSIM-1.1-LAN.zip](https://github.com/lucifervalter-a11y/CarrierSIM-iOS/raw/refs/heads/main/downloads/CarrierSIM-1.1-LAN.zip)** — полный комплект: два IPA, исходники, инструкция и SHA-256.
- **[CarrierSIM-1.1-unsigned.ipa](https://github.com/lucifervalter-a11y/CarrierSIM-iOS/raw/refs/heads/main/downloads/CarrierSIM-1.1-unsigned.ipa)** — приложение со встроенным локальным VPN; для установки нужна подходящая подпись приложения и расширения.
- **[CarrierSIM-1.1-external-vpn.ipa](https://github.com/lucifervalter-a11y/CarrierSIM-iOS/raw/refs/heads/main/downloads/CarrierSIM-1.1-external-vpn.ipa)** — вариант для подписи без VPN-расширения; нужен отдельный LocalDevVPN.

Все IPA в этом репозитории требуют подписи Apple для целевого iPhone. Для установки другу его устройство должно быть разрешено профилем подписи. Автоматическая подпись через Apple Account в этой версии отсутствует.

## Проверено и ограничения

Сборка ARM64 и структура обеих IPA проверены. Прошли 57 основных Rust-тестов и отдельный тест адресов туннеля. На физических iPhone работа этой версии по LAN, установка и смена профиля пока не проверены.

iPhone 12 и новее поддерживают 5G аппаратно, однако профиль оператора не создаёт покрытие или услугу 5G. Поддержку для SIM, тарифа и места использования нужно уточнять у Yota, t2 или своего оператора.

Пакет допускает запуск на iOS 26+. Сопряжение без компьютера рассчитано на iOS 27; на iOS 26 нужен готовый pairing-файл. Работа метода смены профиля на iOS 26 и последних бетах 27 не подтверждена.

[Если не появляется режим разработчика или нужен USB-C](TROUBLESHOOTING.md)

## Сборка

Актуальный полный проект находится в `CarrierSIM-iOS/`. GitHub Actions **Build CarrierSIM IPA** собирает этот каталог, проверяет пакеты и запускает тесты. Результаты сборки требуют подписи для установки.

```sh
cd CarrierSIM-iOS
bash scripts/setup-linux.sh --build
```

[Инструкция сборки](CarrierSIM-iOS/scripts/BUILDING.md) · [Результаты локальных проверок](CarrierSIM-iOS/Tests/VALIDATION.txt)
