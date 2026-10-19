#!/usr/bin/env bash
# Подготовка дерева к сборке колеса cryptography-with-gost: подстановка имени
# дистрибутива, описания и адресов проекта в pyproject.toml. Изменения не
# коммитятся, чтобы не создавать конфликтов при rebase на новую версию
# cryptography.
#
# Использование: gost/stage.sh [ВЕРСИЯ]
#   ВЕРСИЯ — версия выпуска (например, 50.0.2.post1, тег v50.0.2.post1); должна
#            начинаться с версии cryptography из pyproject.toml. Без аргумента
#            версия не меняется.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PYPROJECT="$ROOT/pyproject.toml"
export VERSION="${1:-}"

python3 - <<'EOF'
import os
import re

path = os.environ["PYPROJECT"]
version = os.environ["VERSION"]
text = open(path, encoding="utf-8").read()

fork = "https://github.com/pinecrew/cryptography-with-gost"
replacements = [
    (r'^name = "cryptography"$', 'name = "cryptography-with-gost"'),
    (r'^readme = "README\.rst"$', 'readme = "gost/README.md"'),
    (r'^homepage = ".*"$', f'homepage = "{fork}"'),
    (r'^source = ".*"$', f'source = "{fork}"'),
    (r'^issues = ".*"$', f'issues = "{fork}/issues"'),
]

current = re.search(r'^version = "(.*)"$', text, re.M).group(1)
if version:
    if not re.fullmatch(re.escape(current) + r"(\.post\d+)?", version):
        raise SystemExit(
            f"Версия {version} не соответствует версии cryptography {current}"
        )
    replacements.append((r'^version = ".*"$', f'version = "{version}"'))

for pattern, replacement in replacements:
    text, count = re.subn(pattern, replacement, text, count=1, flags=re.M)
    if count != 1:
        raise SystemExit(f"В pyproject.toml не найдено: {pattern}")

open(path, "w", encoding="utf-8").write(text)
print(f"pyproject.toml: cryptography-with-gost {version or current}")
EOF
