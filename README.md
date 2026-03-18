## Sprint 1 — Создание корневого удостоверяющего центра (Root CA)
# Установка
```powershell
git clone https://github.com/Fanatik-Karasik/Compilator_pulyator.git
cd Compilator_pulyator

python -m venv venv 
.\venv\Scripts\Activate.ps1 
pip install -r requirements.txt   
```

# Тесты
```powershell
pip install pytest

pytest tests/test_pki.py -v
```

```powershell
# 1. Создать пароль для Root CA (один раз)
"RootPass2026!" | Out-File -FilePath .\secrets\root.pass -Encoding ascii -NoNewline

# 2. Создать корневой сертификат (основная команда Sprint 1)
.\micropki.bat ca init `
  --subject "CN=Mopsik Root CA,O=MopsikPKI,C=RU" `
  --key-type rsa `
  --key-size 4096 `
  --passphrase-file .\secrets\root.pass `
  --validity-days 3650
```

Проверка после выполнения:
```PowerShell
# Должны появиться файлы
dir .\pki\certs\ca.cert.pem
dir .\pki\private\ca.key.pem

# Ключ должен быть зашифрован
type .\pki\private\ca.key.pem | findstr "ENCRYPTED"
```

## Sprint 2 — Промежуточный УЦ и конечные сертификаты
# 2.1. Создание промежуточного удостоверяющего центра (Intermediate CA)
```PowerShell
# 1. Создать пароль для Intermediate CA (один раз)
"IntermediatePass2026!" | Out-File -FilePath .\secrets\intermediate.pass -Encoding ascii -NoNewline

# 2. Выпустить промежуточный сертификат
.\micropki.bat ca issue-intermediate `
  --root-cert    .\pki\certs\ca.cert.pem `
  --root-key     .\pki\private\ca.key.pem `
  --root-pass-file .\secrets\root.pass `
  --subject      "CN=Mopsik Intermediate CA,O=MopsikPKI,C=RU" `
  --key-type     rsa `
  --key-size     4096 `
  --passphrase-file .\secrets\intermediate.pass `
  --out-dir      .\pki `
  --validity-days 1825 `
  --pathlen      0
```

# 2.2. Выпуск конечных сертификатов по шаблонам
Серверный сертификат (TLS/HTTPS)
```PowerShell
.\micropki.bat ca issue-cert `
  --ca-cert        .\pki\certs\intermediate.cert.pem `
  --ca-key         .\pki\private\intermediate.key.pem `
  --ca-pass-file   .\secrets\intermediate.pass `
  --template       server `
  --subject        "CN=web.mopsik.local" `
  --san            "dns:web.mopsik.local" `
  --san            "ip:192.168.1.100" `
  --out-dir        .\pki\certs `
  --validity-days  398
```

Клиентский сертификат (аутентификация пользователя)
```PowerShell
.\micropki.bat ca issue-cert `
  --ca-cert        .\pki\certs\intermediate.cert.pem `
  --ca-key         .\pki\private\intermediate.key.pem `
  --ca-pass-file   .\secrets\intermediate.pass `
  --template       client `
  --subject        "CN=Иванов Иван Иванович,EMAIL=ivanov@mopsik.local" `
  --san            "email:ivanov@mopsik.local" `
  --out-dir        .\pki\certs `
  --validity-days  365
```

Сертификат для подписи кода (Code Signing)
```PowerShell
.\micropki.bat ca issue-cert `
  --ca-cert        .\pki\certs\intermediate.cert.pem `
  --ca-key         .\pki\private\intermediate.key.pem `
  --ca-pass-file   .\secrets\intermediate.pass `
  --template       code_signing `
  --subject        "CN=Mopsik Code Signing 2026,O=MopsikPKI" `
  --out-dir        .\pki\certs `
  --validity-days  365
```