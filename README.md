# CiscoScan v2.0

Сканер известных уязвимостей Cisco SSL VPN / AnyConnect / ASA. Работает
**только в режиме детектирования** — никаких эксплойтов, только безопасные
read-only HTTP-запросы и сравнение версий. Архитектура построена по образцу
[nuclei](https://github.com/projectdiscovery/nuclei): каждая CVE описана
отдельным YAML-шаблоном в каталоге `templates/`, добавление новой проверки
не требует правки Python-кода.

## Что делает инструмент

Шаблонный CVE-сканер для Cisco ASA / AnyConnect / WebVPN. Детектирование, без эксплуатации.База будет пополняться

## Установка

```bash
pip install -r requirements.txt
```

Требуется Python 3.9+.

## Использование

```bash
# Одна цель
python cisco_vpn_scan.py -t vpn.example.com

# Список целей из файла + JSON-отчёт
python cisco_vpn_scan.py -l targets.txt -j report.json

# Свой каталог шаблонов
python cisco_vpn_scan.py -t vpn.example.com --templates ./my-templates

# Через Burp / mitmproxy
python cisco_vpn_scan.py -t 10.0.0.5 --proxy http://127.0.0.1:8080

# «Тихий» режим: ограничить параллельность и добавить паузу
python cisco_vpn_scan.py -l targets.txt --concurrency 4 --rate-limit 0.5
```

Формат файла со списком целей — одна цель на строку, строки с `#`
считаются комментариями. Допускаются `host`, `host:port`, полный URL.

## Встроенные шаблоны

| ID шаблона        | Тип         | Что детектируется                                              |
|-------------------|-------------|----------------------------------------------------------------|
| CVE-2018-0101     | version     | ASA WebVPN: double-free XML-парсера (RCE)                      |
| CVE-2020-3187     | version     | ASA/FTD WebVPN: path traversal (чтение, удаление файлов, DoS)  |
| CVE-2020-3452     | http (safe) | ASA/FTD WebVPN: read-only path traversal (безопасная проба)    |
| CVE-2021-1585     | http        | ASDM-клиент: RCE через MITM — флаг доступности ASDM            |
| CVE-2022-20866    | version     | ASA/FTD: утечка приватного RSA-ключа                           |
| CVE-2023-20198    | fingerprint | IOS XE Web UI: privesc — флаг доступности веб-интерфейса       |
| CVE-2023-20269    | version     | ASA/FTD RA-VPN: неавторизованный доступ / подбор паролей       |

Для деструктивных CVE (удаление файлов, извлечение ключей) реализовано
**только сравнение по версии** — ни один запрос не трогает уязвимую
поверхность.


## Флаги

| Флаг                | Описание                                                                 |
|---------------------|--------------------------------------------------------------------------|
| `-t`, `--target`    | одна цель (IP, домен или URL)                                            |
| `-l`, `--list`      | файл со списком целей (одна строка — одна цель, `#` — комментарий)       |
| `-j`, `--json`      | путь для JSON-отчёта                                                     |
| `--templates`       | каталог с YAML-шаблонами                                                 |
| `--timeout`         | таймаут на запрос, секунд (по умолчанию 10)                              |
| `--concurrency`     | максимум параллельных целей (по умолчанию 20)                            |
| `--rate-limit`      | пауза между запросами в рамках одной цели                                |
| `--proxy`           | HTTP(S)-прокси, например `http://127.0.0.1:8080`                         |
| `--user-agent`      | свой User-Agent                                                          |
| `--no-color`        | отключить ANSI-цвета в консоли                                           |
| `--no-banner`       | не печатать баннер при старте                                            |

## Зависимости

- Python 3.9+
- [aiohttp](https://pypi.org/project/aiohttp/)
- [PyYAML](https://pypi.org/project/PyYAML/)




