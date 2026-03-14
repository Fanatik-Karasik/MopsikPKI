# MopsikPKI

Проект для создания простой инфраструктуры открытых ключей (PKI).
Первый спринт: инициализация самоподписанного корневого удостоверяющего центра (УЦ).

## Установка

1. Клонировать репозиторий
2. Создать виртуальное окружение: `python -m venv venv`
3. Активировать его: `.\venv\Scripts\activate`
4. Установить зависимости: `pip install -r requirements.txt`

## Использование

### Пример команды для создания корневого УЦ:

```bash
python -m micropki.cli ca init --subject "/CN=My Root CA" --passphrase-file secrets/ca.pass
```

### Запустите инициализацию корневого УЦ:
```bash
python -m micropki.cli ca init --subject "/CN=My Root CA" --passphrase-file secrets\ca.pass
```

### Или через скрипт-обертку:
```bash
micropki ca init --subject "CN=My Root CA" --passphrase-file secrets\ca.pass
```

### Тестирование
```bash
pytest tests -v
```

### Зависимости

    Python 3.9+

    cryptography

    pytest


## Sprint 2 — Промежуточный УЦ и конечные сертификаты

```bash
.\micropki.bat ca issue-intermediate `
  --root-cert .\pki\certs\ca.cert.pem `
  --root-key  .\pki\private\ca.key.pem `
  --root-pass-file .\secrets\ca.pass ` 
  --subject "CN=Mopsik Intermediate CA,O=MopsikPKI,C=RU" `
  --key-type rsa `
  --key-size 4096 `
  --passphrase-file .\secrets\intermediate.pass `
  --out-dir .\pki `
  --validity-days 1825 `
  --pathlen 0
```

```bash
.\micropki.bat ca issue-cert `
  --ca-cert        .\pki\certs\ca.cert.pem `
  --ca-key         .\pki\private\ca.key.pem `
  --ca-pass-file   .\secrets\ca.pass `
  --template       code_signing `
  --subject        "CN=Mopsik Code Signing 2026" `
  --out-dir        .\pki\certs
```
# Серверный сертификат
```bash
.\micropki.bat ca issue-cert `
  --ca-cert .\pki\certs\intermediate.cert.pem `
  --ca-key .\pki\private\intermediate.key.pem `
  --ca-pass-file .\secrets\intermediate.pass `
  --template server `
  --subject "CN=web.mopsik.test" `
  --san "dns:web.mopsik.test" `
  --san "ip:192.168.10.55" `
  --out-dir .\pki\certs `
  --validity-days 398
```
