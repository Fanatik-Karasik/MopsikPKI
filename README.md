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