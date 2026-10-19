#!/usr/bin/env bash
# Сборка статических зависимостей колеса cryptography-with-gost: OpenSSL и
# провайдера gostprov (gost-engine). Используется как before-all в
# cibuildwheel и для локальной сборки.
#
# Версии и контрольные суммы исходников — gost/sources.env, патчи —
# gost/patches/<источник>/.
#
# Результат в $GOST_DEPS_DIR (по умолчанию <корень репозитория>/build/gost-deps):
#   prefix/                  — OpenSSL (только статические библиотеки) для
#                              OPENSSL_DIR и OPENSSL_STATIC=1;
#   prefix/lib/libgostprov.a — gostprov вместе со всеми зависимостями из
#                              gost-engine, для CRYPTOGRAPHY_GOST_STATIC_LIB_DIR.
#
# Сборка повторяется, только если изменились sources.env, патчи или этот
# сценарий.
#
# Переменные окружения (необязательные):
#   GOST_DEPS_DIR — каталог сборки и установки;
#   CMAKE         — путь к cmake (по умолчанию cmake из PATH);
#   JOBS          — число параллельных задач сборки.
set -euo pipefail

GOST="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$GOST")"
DEPS="${GOST_DEPS_DIR:-$ROOT/build/gost-deps}"
SRC="$DEPS/src"
BUILD="$DEPS/build"
PREFIX="$DEPS/prefix"
CMAKE="${CMAKE:-cmake}"
JOBS="${JOBS:-$(getconf _NPROCESSORS_ONLN)}"

# shellcheck source=sources.env
. "$GOST/sources.env"

for tool in curl git tar perl make cc "$CMAKE"; do
    command -v "$tool" >/dev/null || { echo "Не найдено: $tool" >&2; exit 1; }
done

if command -v sha256sum >/dev/null; then
    sha256() { sha256sum "$@" | cut -d' ' -f1; }
else
    sha256() { shasum -a 256 "$@" | cut -d' ' -f1; }
fi

STAMP="$(cd "$GOST" && cat build-deps.sh sources.env patches/*/*.patch tests/rfc9548/* \
    | sha256 -)"
if [ -f "$PREFIX/.stamp" ] && [ "$(cat "$PREFIX/.stamp")" = "$STAMP" ]; then
    echo "Зависимости в $PREFIX уже собраны."
    exit 0
fi

rm -rf "$SRC" "$BUILD" "$PREFIX"
mkdir -p "$SRC" "$BUILD" "$DEPS/downloads"

# Накладывает серию патчей. Каталог должен быть корнем git-репозитория:
# внутри чужого рабочего дерева (например, форка, если GOST_DEPS_DIR лежит в
# нём) git apply молча пропускает пути вне текущего подкаталога.
apply_patches() {
    local dir="$1" series="$2" patch
    for patch in "$series"/*.patch; do
        echo "Патч: $(basename "$patch")"
        git -C "$dir" apply --whitespace=nowarn "$patch"
    done
    if git -C "$dir" diff --quiet; then
        echo "Патчи не изменили $dir" >&2
        exit 1
    fi
}

# --- 1. Исходники OpenSSL -----------------------------------------------------
tarball="$DEPS/downloads/openssl-$OPENSSL_VERSION.tar.gz"
if [ ! -f "$tarball" ] || [ "$(sha256 "$tarball")" != "$OPENSSL_SHA256" ]; then
    curl -fsSL --retry 3 -o "$tarball.part" "$OPENSSL_URL"
    mv "$tarball.part" "$tarball"
fi
actual="$(sha256 "$tarball")"
if [ "$actual" != "$OPENSSL_SHA256" ]; then
    echo "SHA-256 архива OpenSSL не совпадает: $actual" >&2
    exit 1
fi
tar -xzf "$tarball" -C "$SRC"
mv "$SRC/openssl-$OPENSSL_VERSION" "$SRC/openssl"
git init -q "$SRC/openssl"
git -C "$SRC/openssl" add -A
git -C "$SRC/openssl" -c user.name=build -c user.email=build@localhost \
    commit -q --no-verify -m "openssl-$OPENSSL_VERSION"
apply_patches "$SRC/openssl" "$GOST/patches/openssl"

# --- 2. Исходники gost-engine -------------------------------------------------
git init -q "$SRC/gost-engine"
git -C "$SRC/gost-engine" fetch -q --depth 1 "$GOST_ENGINE_GIT" "$GOST_ENGINE_COMMIT"
git -C "$SRC/gost-engine" -c advice.detachedHead=false checkout -q FETCH_HEAD
tree="$(git -C "$SRC/gost-engine" rev-parse 'HEAD^{tree}')"
if [ "$tree" != "$GOST_ENGINE_TREE" ]; then
    echo "Дерево gost-engine не совпадает: $tree" >&2
    exit 1
fi
libprov="$(git -C "$SRC/gost-engine" ls-tree HEAD libprov | awk '{print $3}')"
if [ "$libprov" != "$GOST_ENGINE_LIBPROV" ]; then
    echo "Ревизия подмодуля libprov не совпадает: $libprov" >&2
    exit 1
fi
git -C "$SRC/gost-engine" submodule -q update --init --depth 1 libprov
apply_patches "$SRC/gost-engine" "$GOST/patches/gost-engine"

# --- 3. OpenSSL ---------------------------------------------------------------
# Только статические библиотеки и без загружаемых модулей: провайдер legacy
# встраивается в libcrypto, gostprov регистрируется как встроенный при
# инициализации cryptography.
mkdir -p "$BUILD/openssl"
(
    cd "$BUILD/openssl"
    "$SRC/openssl/Configure" no-shared no-module no-tests no-docs -fPIC \
        --prefix="$PREFIX" --openssldir="$PREFIX/ssl" --libdir=lib
    make -j"$JOBS"
    make install_sw
)

# --- 4. gostprov --------------------------------------------------------------
# pkg-config ограничен своим префиксом: иначе FindOpenSSL может взять
# системный libcrypto.pc с лишними зависимостями (-lz, brotli, zstd).
# OPENSSL_ENGINES_DIR обязателен, даже когда модуль engine не собирается.
PKG_CONFIG_LIBDIR="$PREFIX/lib/pkgconfig" "$CMAKE" \
    -S "$SRC/gost-engine" -B "$BUILD/gost-engine" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    -DOPENSSL_ROOT_DIR="$PREFIX" \
    -DOPENSSL_USE_STATIC_LIBS=TRUE \
    -DOPENSSL_ENGINES_DIR="$PREFIX/lib/engines-4" \
    -DGOST_BUILD_ENGINE=OFF \
    -DGOST_BUILD_STATIC_PROVIDER=ON
"$CMAKE" --build "$BUILD/gost-engine" -j"$JOBS" --target gost_prov_static

# Статическая библиотека провайдера не включает зависимости из gost-engine;
# они объединяются в один архив.
archives=()
for lib in gostprov_static gost_core gost89 gosthash gosthash2012 \
    gosttls12additional gost_err prov; do
    archive="$(find "$BUILD/gost-engine" -name "lib$lib.a" -not -path '*/CMakeFiles/*')"
    if [ -z "$archive" ] || [ "$(printf '%s\n' "$archive" | wc -l)" -ne 1 ]; then
        echo "Архив lib$lib.a не найден или не единственный: $archive" >&2
        exit 1
    fi
    archives+=("$archive")
done
case "$(uname -s)" in
    Darwin)
        libtool -static -no_warning_for_no_symbols -o "$PREFIX/lib/libgostprov.a" "${archives[@]}"
        ;;
    *)
        {
            echo "CREATE $PREFIX/lib/libgostprov.a"
            printf 'ADDLIB %s\n' "${archives[@]}"
            echo "SAVE"
            echo "END"
        } | ar -M
        ranlib "$PREFIX/lib/libgostprov.a"
        ;;
esac

# --- 5. Проверка патча OpenSSL на эталонных PFX из RFC 9548 -------------------
# Ключи в эталонных контейнерах зашифрованы OMAC-вариантами шифров, которые
# не поддерживаются, поэтому через cryptography их не открыть; проверяется
# только сходимость MAC.
case "$(uname -s)" in
    Darwin) syslibs="" ;;
    *)      syslibs="-pthread -ldl" ;;
esac
cc -o "$BUILD/rfc9548-mac" -I"$PREFIX/include" "$GOST/tests/rfc9548/mac.c" \
    "$PREFIX/lib/libgostprov.a" "$PREFIX/lib/libcrypto.a" $syslibs
"$BUILD/rfc9548-mac" "Пароль для PFX" "$GOST"/tests/rfc9548/*.pfx

echo "$STAMP" > "$PREFIX/.stamp"
echo "Зависимости собраны в $PREFIX."
