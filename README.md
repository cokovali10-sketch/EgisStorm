# EgisStorm — Security Suite

Набор из 24 инструментов кибербезопасности для самопроверки и аудита своей инфраструктуры.
Всё работает локально, ничего не хранится на сервере.

> **Назначение:** только проверка *своих* данных и *своей* инфраструктуры.
> Инструменты OSINT работают исключительно с публичными данными (DNS, RDAP, SSL-сертификаты)
> и не раскрывают персональные данные третьих лиц.

## Возможности

### Breach & Passwords
- **Email по утечкам** — проверка своего адреса по базе HaveIBeenPwned (график утечек по годам)
- **Проверка пароля** — сколько раз пароль встречался в утечках (Pwned Passwords) + оценка силы
- **Генератор паролей** — криптостойкие пароли через Python `secrets`

### Network Intel
- **Мой IP** — внешний адрес, гео, провайдер
- **DNS записи** — A / AAAA / CNAME / NS / MX / TXT
- **WHOIS / RDAP** — регистратор, даты, статусы домена
- **Инфо по IP** — гео, ASN, reverse DNS (ipwho.is)
- **Владелец IP** — организация и диапазон сети через RDAP
- **TCP порт** — проверка порта + скан общих сервисов
- **SSL сертификат** — издатель, SAN, срок действия, TLS-версия
- **Security headers** — аудит HSTS, CSP, X-Frame-Options и др. с оценкой
- **Subnet / CIDR** — калькулятор подсетей
- **Проверка MX** — почтовые серверы домена + детект одноразовых доменов

### Crypto & Web
- **Хеширование** — MD5 / SHA-1 / SHA-2 / SHA-3 + определение алгоритма
- **Base64** — кодирование / декодирование
- **JWT декодер** — проверка `alg=none`, `exp`, `nbf`
- **Анализатор URL** — индикаторы фишинга (HTTPS, IP-хост, punycode, шортнеры)
- **Развёртка ссылки** — цепочка редиректов коротких URL
- **robots.txt** — правила сайта и sitemap
- **Шифрование AES** — AES-256-CBC + PKCS7 (образовательный)
- **Поиск CVE** — уязвимости по продукту через NVD
- **2FA / TOTP** — генерация секрета и QR, автообновляемый код в браузере
- **WireGuard VPN** — генерация клиентского конфига и Curve25519 ключей

Интерактив: SVG-графики без внешних зависимостей, история проверок (localStorage + серверная SQLite),
экспорт результатов в JSON, тост-уведомления.

Дополнительно:
- **Rate limiting** — защита API (flask-limiter, 120 запросов/час, строже на внешних инструментах)
- **Серверная история** — SQLite (пароли и ключи в логах маскируются)
- **Опциональная авторизация** — Basic Auth через переменную `APP_PASSWORD`
- **Docker** — готовые Dockerfile и docker-compose
- **CI** — GitHub Actions: линт + pytest

## Технологии

- **Backend:** Python 3.12, Flask, flask-limiter, SQLite
- **Frontend:** HTML / CSS / JS (vanilla, без фреймворков)
- **Библиотеки:** requests, dnspython, phonenumbers, pyotp, qrcode, cryptography, PyNaCl

## Установка и запуск

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows
pip install -r requirements.txt
python run.py                   # http://127.0.0.1:5000
```

### Docker

```bash
docker compose up --build
```

### Переменные окружения

| Переменная      | Описание                                             |
|-----------------|------------------------------------------------------|
| `HIBP_API_KEY`  | Ключ HaveIBeenPwned (без него — демо-режим)          |
| `APP_PASSWORD`  | Пароль Basic Auth (не задан — доступ открыт)         |

### Живые данные HIBP

Без API-ключа сервис работает в демо-режиме. Для живых проверок:

```bash
set HIBP_API_KEY=ваш_ключ       # Windows PowerShell
export HIBP_API_KEY=ваш_ключ    # Linux/macOS
```

### Тесты

```bash
pip install pytest flake8
pytest -q                       # 17 тестов
flake8 app.py run.py tools db.py --select=E9,F63,F7,F82
```

## Структура проекта

```
├── app.py              # Flask-приложение, API, лимиты, авторизация
├── run.py              # точка запуска (без reloader)
├── db.py               # SQLite-история
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── templates/
│   └── index.html      # интерфейс
├── static/
│   ├── style.css
│   ├── app.js          # логика интерфейса
│   ├── charts.js       # SVG-графики (donut/bar/gauge/line)
│   └── totp.js         # клиентский TOTP (WebCrypto)
├── tests/
│   ├── conftest.py
│   └── test_app.py     # 17 тестов
├── .github/workflows/
│   └── ci.yml          # линт + тесты
└── tools/
    ├── network.py      # DNS, RDAP, IP, CIDR, MX, CVE
    ├── cert.py         # SSL-сертификаты
    ├── webcheck.py     # headers, URL-анализ, редиректы
    ├── crypto_tools.py # хеши, base64, пароли
    ├── crypt_tool.py   # AES-256-CBC
    ├── jwt_tool.py     # JWT-декодер
    └── portcheck.py    # TCP-порты, robots.txt
```

## Дорожная карта

- [x] Dockerfile + docker-compose
- [x] Rate limiting на API
- [x] История проверок на сервере (SQLite)
- [x] Авторизация (опциональная, Basic Auth)
- [x] CI (lint + тесты)
- [ ] Telegram-бот-обёртка для ключевых инструментов
- [ ] Экспорт отчёта в PDF
