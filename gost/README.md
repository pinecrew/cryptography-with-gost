# cryptography-with-gost

Сборка [cryptography](https://github.com/pyca/cryptography) с поддержкой
российских криптографических алгоритмов (ГОСТ) и контейнеров PKCS#12 (PFX),
экспортированных КриптоПро CSP.

Дистрибутив называется `cryptography-with-gost`, но импортируется как
`cryptography` и полностью заменяет её: библиотеки, зависящие от cryptography
(pyOpenSSL, requests, paramiko и др.), работают с ним без изменений. Версия
совпадает с версией cryptography, на которой основана сборка; перевыпуски
получают суффикс `.postN`.

В колесо статически встроены OpenSSL 4.0 и провайдер `gostprov` из
[gost-engine](https://github.com/gost-engine/engine); внешняя libcrypto и
конфигурация OpenSSL не нужны.

## Возможности

- Загрузка ключей ГОСТ Р 34.10-2001 и ГОСТ Р 34.10-2012 (256 и 512 бит) из
  PKCS#8, SubjectPublicKeyInfo и PKCS#12; классы `GostPrivateKey` и
  `GostPublicKey` (модуль `cryptography.hazmat.primitives.asymmetric.gost`).
- Чтение контейнеров PKCS#12 КриптоПро CSP (PBE `1.2.840.113549.1.12.1.80`),
  в том числе с паролями из кириллицы и символов вне BMP.
- Экспорт PKCS#12 по RFC 9548 (PBES2 с Кузнечиком или Магмой в режиме
  CTR-ACPKM по RFC 9337, MAC HMAC-ГОСТ Р 34.11-2012) и чтение таких
  контейнеров.
- Проверка ГОСТ-подписей сертификатов: `Certificate.verify_directly_issued_by()`
  и построение цепочек верификатором `cryptography.x509.verification`.

## Установка

В окружении должен быть установлен **только один** из пакетов `cryptography`
и `cryptography-with-gost`: оба содержат пакет Python `cryptography`, и при
совместной установке файлы одного перезаписывают файлы другого. Средствами
упаковки этот конфликт выразить нельзя, поэтому зависимость других пакетов от
`cryptography` нужно исключить явно.

### uv (проект)

В `pyproject.toml` проекта:

```toml
[project]
dependencies = [
    "cryptography-with-gost==50.0.2",
    # прочие зависимости, в том числе зависящие от cryptography
]

[tool.uv]
# Исключает cryptography из разрешения зависимостей: маркер никогда не
# выполняется.
override-dependencies = ["cryptography; sys_platform == 'never'"]
```

### uv pip

Файл `overrides.txt`:

```text
cryptography; sys_platform == 'never'
```

```bash
uv pip install --overrides overrides.txt cryptography-with-gost pyopenssl
```

### pip

pip не умеет исключать зависимости, поэтому установка выполняется в три шага:
зависимости проекта, удаление `cryptography`, установка
`cryptography-with-gost` без зависимостей.

```bash
pip install -r requirements.txt
pip uninstall -y cryptography
pip install --force-reinstall --no-deps cryptography-with-gost
```

Зависимость `cffi` в этом случае должна быть установлена заранее (её приносит
`cryptography`). `pip check` сообщит, что пакет `cryptography`, необходимый
другим пакетам, не установлен; это ожидаемо.

### Восстановление после совместной установки

Если в окружение попали оба пакета, следует удалить оба и установить
`cryptography-with-gost` заново:

```bash
pip uninstall -y cryptography cryptography-with-gost
pip install --no-deps cryptography-with-gost
```

### Проверка

```bash
python -c "from cryptography.hazmat.primitives.asymmetric import gost; from cryptography.hazmat.backends.openssl.backend import backend; print(backend.gost_supported())"
```

Команда выводит `True`. Если модуль `gost` не найден, установлена
`cryptography` из PyPI.

## Использование

```python
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

with open("container.pfx", "rb") as f:
    key, cert, additional_certs = pkcs12.load_key_and_certificates(
        f.read(), "пароль".encode()
    )

key.key_type    # 'gost2012_256'
key.key_size    # 256

signature = key.sign(b"data")                 # ГОСТ Р 34.10-2012 + ГОСТ Р 34.11-2012
cert.public_key().verify(signature, b"data")  # InvalidSignature при несовпадении

pem = key.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption(),             # или BestAvailableEncryption(b"...")
)
```

Методы `GostPrivateKey`: `key_type`, `key_size`, `sign(data)`, `public_key()`,
`private_bytes(encoding, format, encryption_algorithm)` (только PKCS8, PEM/DER).
Методы `GostPublicKey`: `key_type`, `key_size`, `verify(signature, data)`,
`public_bytes(encoding, format)` (только SubjectPublicKeyInfo, PEM/DER), `==`.
Хеш-функция подписи определяется типом ключа.

### Экспорт PKCS#12 по RFC 9548

```python
encryption = (
    serialization.PrivateFormat.PKCS12.encryption_builder()
    .key_cert_algorithm(pkcs12.PBES.PBESv2Streebog512AndKuznyechikCTRACPKM)
    .kdf_rounds(2048)  # необязательно; по умолчанию 20000, минимум по RFC — 1000
    .build("пароль".encode())
)
pfx = pkcs12.serialize_key_and_certificates(
    b"friendly name", key, cert, additional_certs, encryption
)
```

| Элемент | Значение |
|---------|----------|
| Ключ и сертификаты | PBES2 (`1.2.840.113549.1.5.13`) |
| KDF | PBKDF2, PRF HMAC-ГОСТ Р 34.11-2012 512 бит (`1.2.643.7.1.1.4.2`), соль 32 байта, пароль в UTF-8 |
| Шифр | Кузнечик CTR-ACPKM (`1.2.643.7.1.1.5.2.1`) или Магма CTR-ACPKM (`1.2.643.7.1.1.5.1.1`) |
| MAC | HMAC-ГОСТ Р 34.11-2012 512 бит (`1.2.643.7.1.1.2.3`) |

`hmac_hash()` с ГОСТ-вариантами `PBES` вызывает `ValueError`: RFC 9548
фиксирует алгоритм MAC. Варианты с OMAC (`1.2.643.7.1.1.5.x.2`) не
поддерживаются. Стандартные способы защиты (`BestAvailableEncryption()` и др.)
с ГОСТ-ключом также работают, но шифруют контейнер западными алгоритмами.

### Переменные окружения

- `CRYPTOGRAPHY_OPENSSL_NO_GOST=1` — не загружать провайдер `gostprov`;
  ГОСТ-алгоритмы при этом недоступны.

## Ограничения

- Проприетарный формат контейнера КриптоПро поддерживается только на чтение;
  для экспорта следует использовать RFC 9548.
- Импорт в КриптоПро CSP контейнеров, экспортированных по RFC 9548, не
  проверялся.
- Кириллические пароли контейнеров КриптоПро поддерживаются патчем gost-engine
  и не сверены с файлом, созданным самим КриптоПро CSP.
- ГОСТ-алгоритмы разрешены в политике верификатора `x509.verification`
  безусловно, для всех политик.
- Атрибут `friendlyName` КриптоПро записывает в keybag, а не в сертификат,
  поэтому `PKCS12Certificate.friendly_name` равен `None`.
- Подписи CMS/PKCS#7 ГОСТ не поддерживаются.
- Колёса собираются для Linux (manylinux, x86_64 и aarch64) и macOS (arm64 и
  x86_64); исходный дистрибутив не публикуется.

## Устройство сборки

Исходный код ведётся в форке
[pinecrew/cryptography-with-gost](https://github.com/pinecrew/cryptography-with-gost):
ветка `gost/<линия>` (например, `gost/50.0.x`) отходит от тега выпуска
cryptography и содержит серию коммитов с поддержкой ГОСТ и их тестами. Переход
на новую версию выполняется командой `git rebase --onto <новый тег>`.

Изменения OpenSSL и gost-engine хранятся патчами в каталоге
[`gost/`](https://github.com/pinecrew/cryptography-with-gost/tree/gost/50.0.x/gost):

| Файл | Назначение |
|------|------------|
| `sources.env` | версия, адрес и SHA-256 OpenSSL; коммит, хеш дерева и ревизия подмодуля `libprov` gost-engine |
| `patches/openssl/` | провайдерный PBE для ГОСТ-шифров в PKCS#12 (из gost-engine) и исправление передачи параметров AlgorithmIdentifier только шифрам сторонних провайдеров |
| `patches/gost-engine/` | пароли с не-ASCII символами в контейнерах КриптоПро; статическая библиотека провайдера |
| `build-deps.sh` | загрузка и проверка исходников, наложение патчей, сборка статических OpenSSL и gostprov, проверка MAC эталонных PFX из RFC 9548 |
| `stage.sh` | подстановка имени дистрибутива и описания в `pyproject.toml` перед сборкой |
| `cibuildwheel.toml` | конфигурация cibuildwheel |
| `tests/rfc9548/` | эталонные PFX из приложения A RFC 9548 (пароль «Пароль для PFX») и программа проверки их MAC |

Локальная сборка колеса (требуются `curl`, `git`, `perl`, `make`, C-компилятор,
`cmake`, Rust и [uv](https://docs.astral.sh/uv/)):

```bash
gost/build-deps.sh
gost/stage.sh
OPENSSL_DIR=$PWD/build/gost-deps/prefix OPENSSL_STATIC=1 \
    CRYPTOGRAPHY_GOST_STATIC_LIB_DIR=$PWD/build/gost-deps/prefix/lib \
    uv build --wheel --config-setting build-args=--features=pyo3/abi3-py311
git checkout pyproject.toml
```

На macOS следует задать `MACOSX_DEPLOYMENT_TARGET` (например, `11.0`), чтобы
OpenSSL, gost-engine и колесо собирались для одной версии системы.

Тесты устроены так же, как в cryptography (`tests/`, векторы в `vectors/`);
без провайдера `gostprov` ГОСТ-тесты пропускаются.

## Лицензия

Как у cryptography: Apache-2.0 или BSD-3-Clause, по выбору. OpenSSL
распространяется по лицензии Apache-2.0, gost-engine — по лицензии
Apache-2.0.
