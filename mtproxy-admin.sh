#!/usr/bin/env bash
#
# Несколько экземпляров mtg (план A): пользователь = свой secret + свой host_port + свой контейнер.
# Использование: sudo ./mtproxy-admin.sh <команда> [аргументы]
#
set -euo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
DATA_DIR="${MTPROXY_DATA_DIR:-$SCRIPT_DIR/mtproxy}"
USERS_DIR="$DATA_DIR/users"
TEMPLATE_TOML="$DATA_DIR/template/config.toml"
IMAGE="${MTPROXY_IMAGE:-nineseconds/mtg:2}"
PORT_MIN="${MTPROXY_PORT_MIN:-17400}"
PORT_MAX="${MTPROXY_PORT_MAX:-19999}"
DEFAULT_FAKE_DOMAIN="${MTPROXY_FAKE_DOMAIN:-cloudflare.com}"

DOCKER=(sudo docker)

die() {
  echo -e "${RED}❌ $*${NC}" >&2
  exit 1
}

info() { echo -e "${BLUE}[*]${NC} $*"; }
ok() { echo -e "${GREEN}[ok]${NC} $*"; }

require_template() {
  if [[ ! -f "$TEMPLATE_TOML" ]]; then
    die "Нет шаблона: $TEMPLATE_TOML (ожидается bind-to в репозитории: mtproxy/template/config.toml)"
  fi
}

validate_slug() {
  local s="$1"
  [[ "$s" =~ ^[a-z0-9]([a-z0-9_-]{0,47})$ ]] || die "Некорректный slug: $s (a-z0-9, _, -, до 48 символов)"
}

container_name() {
  echo "mtproto-proxy-$1"
}

# Порт занят системой (ss) или выделен другому пользователю в meta.json
port_is_taken() {
  local p="$1"
  if ss -tuln 2>/dev/null | grep -q ":${p} "; then
    return 0
  fi
  local meta
  for meta in "$USERS_DIR"/*/meta.json; do
    [[ -f "$meta" ]] || continue
    local u
    u="$(sed -n 's/.*"host_port"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$meta" | head -n1)"
    [[ -n "$u" && "$u" == "$p" ]] && return 0
  done
  return 1
}

pick_free_port() {
  local span=$((PORT_MAX - PORT_MIN + 1))
  if [ "$span" -le 0 ] || [ "$PORT_MIN" -lt 1 ]; then
    die "Некорректный диапазон портов: $PORT_MIN-$PORT_MAX"
  fi
  # Случайный выбор в диапазоне (много попыток — при плотной занятости ниже запасной линейный проход)
  local a p
  local max_attempts=$((span * 4))
  [ "$max_attempts" -gt 8000 ] && max_attempts=8000
  for ((a = 0; a < max_attempts; a++)); do
    p=$((PORT_MIN + RANDOM % span))
    if ! port_is_taken "$p"; then
      echo "$p"
      return 0
    fi
  done
  for ((p = PORT_MIN; p <= PORT_MAX; p++)); do
    if ! port_is_taken "$p"; then
      echo "$p"
      return 0
    fi
  done
  die "Не найден свободный порт в диапазоне $PORT_MIN-$PORT_MAX"
}

read_secret_from_toml() {
  local f="$1"
  sed -nE 's/^[[:space:]]*secret[[:space:]]*=[[:space:]]*"([^"]*)"[[:space:]]*.*$/\1/p' "$f" | head -n1
}

read_host_port_from_meta() {
  local f="$1"
  sed -n 's/.*"host_port"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$f" | head -n1
}

insert_secret_after_bind() {
  local src="$1"
  local dest="$2"
  local secret_line="$3"
  awk -v secret_line="$secret_line" '
    BEGIN{inserted=0}
    /^[[:space:]]*bind-to[[:space:]]*=/ && inserted==0 { print; print secret_line; inserted=1; next }
    { print }
    END{ if(inserted==0){ print secret_line } }
  ' "$src" > "$dest"
}

ensure_user_config_secret() {
  local config_toml="$1"
  local domain="$2"
  local secret
  if grep -Eq '^[[:space:]]*secret[[:space:]]*=' "$config_toml"; then
    secret="$(read_secret_from_toml "$config_toml")"
    [[ -n "$secret" ]] || die "В $config_toml пустой secret"
    ensure_concurrency_in_config "$config_toml"
    echo "$secret"
    return 0
  fi
  secret="$("${DOCKER[@]}" run --rm "$IMAGE" generate-secret "$domain")"
  local tmp
  tmp="$(mktemp)"
  insert_secret_after_bind "$config_toml" "$tmp" "secret = \"${secret}\""
  mv "$tmp" "$config_toml"
  ensure_concurrency_in_config "$config_toml"
  echo "$secret"
}

ensure_concurrency_in_config() {
  local config_toml="$1"
  local conc_line="concurrency = 3"

  # Если concurrency уже есть — заменяем.
  # Если нет — вставляем после secret, а при отсутствии secret — после bind-to.
  if grep -Eq '^[[:space:]]*concurrency[[:space:]]*=' "$config_toml"; then
    tmp="$(mktemp)"
    awk -v conc_line="$conc_line" '
      /^[[:space:]]*concurrency[[:space:]]*=/ { print conc_line; next }
      { print }
    ' "$config_toml" > "$tmp" && mv "$tmp" "$config_toml"
    return 0
  fi

  tmp="$(mktemp)"
  awk -v conc_line="$conc_line" '
    BEGIN{inserted=0}
    /^[[:space:]]*secret[[:space:]]*=/ && inserted==0 { print; print conc_line; inserted=1; next }
    /^[[:space:]]*bind-to[[:space:]]*=/ && inserted==0 { print; print conc_line; inserted=1; next }
    { print }
    END{ if(inserted==0){ print conc_line } }
  ' "$config_toml" > "$tmp" && mv "$tmp" "$config_toml"
}

iptables_allow_port() {
  local port="$1"
  if sudo iptables -C INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null; then
    info "iptables: порт $port уже разрешён"
  else
    sudo iptables -I INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null || true
    ok "iptables: открыт TCP $port"
  fi
}

iptables_maybe_remove() {
  local port="$1"
  sudo iptables -D INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null || true
}

get_ipv4() {
  curl -s -4 --connect-timeout 5 ifconfig.me || true
}

cmd_add() {
  local slug=""
  local domain="$DEFAULT_FAKE_DOMAIN"
  local want_port=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --domain)
        domain="${2:-}"; shift 2 || die "--domain без значения"
        ;;
      --port)
        want_port="${2:-}"; shift 2 || die "--port без значения"
        [[ "$want_port" =~ ^[0-9]+$ ]] || die "Порт должен быть числом"
        ;;
      -*)
        die "Неизвестный флаг: $1"
        ;;
      *)
        [[ -z "$slug" ]] || die "Лишний аргумент: $1"
        slug="$1"
        shift
        ;;
    esac
  done
  [[ -n "$slug" ]] || die "Использование: add <slug> [--domain HOST] [--port N]"

  validate_slug "$slug"
  require_template
  mkdir -p "$USERS_DIR"

  local user_dir="$USERS_DIR/$slug"
  [[ ! -d "$user_dir" ]] || die "Пользователь уже существует: $slug"

  local host_port
  if [[ -n "$want_port" ]]; then
    port_is_taken "$want_port" && die "Порт $want_port уже занят (ss или другой пользователь mtproxy)"
    host_port="$want_port"
  else
    host_port="$(pick_free_port)"
  fi

  mkdir -p "$user_dir"
  cp "$TEMPLATE_TOML" "$user_dir/config.toml"

  info "Генерация/фиксация secret (домен FakeTLS: $domain)…"
  local secret
  secret="$(ensure_user_config_secret "$user_dir/config.toml" "$domain")"

  local created
  created="$(date -Iseconds 2>/dev/null || date)"

  printf '{"slug":"%s","host_port":%s,"fake_domain":"%s","created":"%s"}\n' \
    "$slug" "$host_port" "$domain" "$created" > "$user_dir/meta.json"

  local cname
  cname="$(container_name "$slug")"
  info "Запуск контейнера $cname → :$host_port → 443…"
  "${DOCKER[@]}" stop "$cname" >/dev/null 2>&1 || true
  "${DOCKER[@]}" rm "$cname" >/dev/null 2>&1 || true
  "${DOCKER[@]}" run -d \
    --name "$cname" \
    --restart always \
    -p "${host_port}:443" \
    -v "$user_dir/config.toml:/config.toml" \
    "$IMAGE" >/dev/null

  iptables_allow_port "$host_port"

  sleep 1
  if "${DOCKER[@]}" ps --format '{{.Names}}' | grep -qx "$cname"; then
    ok "Пользователь $slug запущен (порт $host_port)"
  else
    echo -e "${YELLOW}Контейнер не в списке running; логи:${NC}"
    "${DOCKER[@]}" logs "$cname" 2>&1 | tail -30 || true
    die "Сбой запуска контейнера $cname"
  fi

  local ip
  ip="$(get_ipv4)"
  echo ""
  echo -e "${GREEN}tg://proxy?server=${ip}&port=${host_port}&secret=${secret}${NC}"
}

cmd_remove() {
  local slug="${1:-}"
  [[ -n "$slug" ]] || die "Использование: remove <slug>"
  validate_slug "$slug"
  local user_dir="$USERS_DIR/$slug"
  [[ -d "$user_dir" ]] || die "Нет пользователя: $slug"

  local meta="$user_dir/meta.json"
  local host_port=""
  [[ -f "$meta" ]] && host_port="$(read_host_port_from_meta "$meta")"

  local cname
  cname="$(container_name "$slug")"
  "${DOCKER[@]}" stop "$cname" >/dev/null 2>&1 || true
  "${DOCKER[@]}" rm "$cname" >/dev/null 2>&1 || true

  [[ -n "$host_port" ]] && iptables_maybe_remove "$host_port"

  rm -rf "$user_dir"
  ok "Удалён $slug"
}

cmd_disable() {
  local slug="${1:-}"
  [[ -n "$slug" ]] || die "Использование: disable <slug>"
  validate_slug "$slug"
  local user_dir="$USERS_DIR/$slug"
  [[ -d "$user_dir" ]] || die "Нет пользователя: $slug"

  local meta="$user_dir/meta.json"
  [[ -f "$meta" ]] || die "Нет meta.json для пользователя: $slug"

  local host_port=""
  host_port="$(read_host_port_from_meta "$meta")"
  [[ -n "$host_port" ]] || die "Не удалось прочитать host_port из meta.json для $slug"

  local cname
  cname="$(container_name "$slug")"

  # Останавливаем контейнер, но сохраняем каталог пользователя.
  "${DOCKER[@]}" stop "$cname" >/dev/null 2>&1 || true
  "${DOCKER[@]}" rm "$cname" >/dev/null 2>&1 || true

  # Снимаем разрешение порта.
  iptables_maybe_remove "$host_port"

  ok "Отключён $slug (контейнер остановлен, каталог сохранён)"
}

cmd_enable() {
  local slug="${1:-}"
  [[ -n "$slug" ]] || die "Использование: enable <slug>"
  validate_slug "$slug"
  local user_dir="$USERS_DIR/$slug"
  [[ -d "$user_dir" ]] || die "Нет пользователя: $slug"

  local meta="$user_dir/meta.json"
  [[ -f "$meta" ]] || die "Нет meta.json для пользователя: $slug"

  local host_port=""
  host_port="$(read_host_port_from_meta "$meta")"
  [[ -n "$host_port" ]] || die "Не удалось прочитать host_port из meta.json для $slug"

  local cfg="$user_dir/config.toml"
  [[ -f "$cfg" ]] || die "Нет config.toml для пользователя: $slug"

  local domain=""
  domain="$(sed -n 's/.*"fake_domain"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$meta" | head -n1)"
  [[ -n "$domain" ]] || domain="$DEFAULT_FAKE_DOMAIN"

  # На всякий случай гарантируем наличие secret + нужную concurrency.
  ensure_user_config_secret "$cfg" "$domain" >/dev/null
  ensure_concurrency_in_config "$cfg" >/dev/null

  local cname
  cname="$(container_name "$slug")"

  # Поднимаем контейнер снова (без генерации новых данных пользователя).
  "${DOCKER[@]}" stop "$cname" >/dev/null 2>&1 || true
  "${DOCKER[@]}" rm "$cname" >/dev/null 2>&1 || true

  "${DOCKER[@]}" run -d \
    --name "$cname" \
    --restart always \
    -p "${host_port}:443" \
    -v "$cfg:/config.toml" \
    "$IMAGE" >/dev/null

  iptables_allow_port "$host_port"

  sleep 1
  if "${DOCKER[@]}" ps --format '{{.Names}}' | grep -qx "$cname"; then
    ok "Включён $slug (контейнер запущен на порту $host_port)"
  else
    echo -e "${YELLOW}Контейнер не в списке running; логи:${NC}"
    "${DOCKER[@]}" logs "$cname" 2>&1 | tail -30 || true
    die "Сбой запуска контейнера $cname"
  fi

  local ip
  ip="$(get_ipv4)"
  local secret
  secret="$(read_secret_from_toml "$cfg")"
  [[ -n "$secret" ]] || die "Пустой secret в $cfg"

  echo ""
  echo -e "${GREEN}tg://proxy?server=${ip}&port=${host_port}&secret=${secret}${NC}"
}

cmd_list() {
  mkdir -p "$USERS_DIR"
  local found=0
  for meta in "$USERS_DIR"/*/meta.json; do
    [[ -f "$meta" ]] || continue
    found=1
    local slug host_port domain created cname running
    slug="$(basename "$(dirname "$meta")")"
    host_port="$(read_host_port_from_meta "$meta")"
    domain="$(sed -n 's/.*"fake_domain"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$meta" | head -n1)"
    created="$(sed -n 's/.*"created"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$meta" | head -n1)"
    cname="$(container_name "$slug")"
    running="no"
    if "${DOCKER[@]}" ps --format '{{.Names}}' | grep -qx "$cname"; then
      running="yes"
    fi
    echo -e "${BLUE}$slug${NC}  port=${host_port:-?}  domain=${domain:-?}  running=$running  created=${created:-?}"
  done
  [[ "$found" -eq 1 ]] || info "Пользователей пока нет ($USERS_DIR)"
}

cmd_link() {
  local plain=0
  if [[ "${1:-}" == "--plain" ]]; then
    plain=1
    shift
  fi
  local slug="${1:-}"
  [[ -n "$slug" ]] || die "Использование: link [--plain] <slug>"
  validate_slug "$slug"
  local user_dir="$USERS_DIR/$slug"
  local cfg="$user_dir/config.toml"
  local meta="$user_dir/meta.json"
  [[ -f "$cfg" && -f "$meta" ]] || die "Нет данных пользователя $slug"

  local secret host_port ip
  secret="$(read_secret_from_toml "$cfg")"
  host_port="$(read_host_port_from_meta "$meta")"
  [[ -n "$secret" && -n "$host_port" ]] || die "Не удалось прочитать secret или host_port"
  ip="$(get_ipv4)"
  if [[ "$plain" -eq 1 ]]; then
    printf '%s\n' "tg://proxy?server=${ip}&port=${host_port}&secret=${secret}"
  else
    echo -e "${GREEN}tg://proxy?server=${ip}&port=${host_port}&secret=${secret}${NC}"
  fi
}

cmd_restart() {
  local slug="${1:-}"
  [[ -n "$slug" ]] || die "Использование: restart <slug>"
  validate_slug "$slug"
  local cname
  cname="$(container_name "$slug")"
  "${DOCKER[@]}" restart "$cname" >/dev/null
  ok "restart $cname"
}

cmd_logs() {
  local slug="${1:-}"
  [[ -n "$slug" ]] || die "Использование: logs <slug>"
  validate_slug "$slug"
  local cname
  cname="$(container_name "$slug")"
  "${DOCKER[@]}" logs --tail 80 "$cname"
}

cmd_start_all() {
  require_template
  mkdir -p "$USERS_DIR"
  for meta in "$USERS_DIR"/*/meta.json; do
    [[ -f "$meta" ]] || continue
    local slug user_dir host_port cname domain
    slug="$(basename "$(dirname "$meta")")"
    user_dir="$(dirname "$meta")"
    host_port="$(read_host_port_from_meta "$meta")"
    [[ -n "$host_port" ]] || continue
    cname="$(container_name "$slug")"
    domain="$(sed -n 's/.*"fake_domain"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$meta" | head -n1)"
    [[ -z "$domain" ]] && domain="$DEFAULT_FAKE_DOMAIN"
    ensure_user_config_secret "$user_dir/config.toml" "$domain" >/dev/null
    ensure_concurrency_in_config "$user_dir/config.toml" >/dev/null
    "${DOCKER[@]}" stop "$cname" >/dev/null 2>&1 || true
    "${DOCKER[@]}" rm "$cname" >/dev/null 2>&1 || true
    "${DOCKER[@]}" run -d \
      --name "$cname" \
      --restart always \
      -p "${host_port}:443" \
      -v "$user_dir/config.toml:/config.toml" \
      "$IMAGE" >/dev/null
    iptables_allow_port "$host_port"
    ok "start $cname (:$host_port)"
  done
}

cmd_stop_all() {
  for meta in "$USERS_DIR"/*/meta.json; do
    [[ -f "$meta" ]] || continue
    local slug cname
    slug="$(basename "$(dirname "$meta")")"
    cname="$(container_name "$slug")"
    "${DOCKER[@]}" stop "$cname" >/dev/null 2>&1 || true
    ok "stop $cname"
  done
}

usage() {
  cat <<'EOF'
mtproxy-admin.sh — несколько mtg по плану A

  add <slug> [--domain HOST] [--port N]   создать пользователя, поднять контейнер
  remove <slug>                           остановить, удалить контейнер и каталог
  disable <slug>                          остановить контейнер и снять iptables, каталог сохранить
  enable <slug>                           поднять контейнер из сохранённого каталога
  list                                    список пользователей
  link [--plain] <slug>                  ссылка tg://proxy?... (--plain без ANSI, для бота)
  restart <slug>
  logs <slug>                             последние логи контейнера
  start-all | stop-all

Переменные окружения:
  MTPROXY_DATA_DIR     каталог данных (по умолчанию <repo>/mtproxy)
  MTPROXY_IMAGE        образ docker (по умолчанию nineseconds/mtg:2)
  MTPROXY_PORT_MIN     начало диапазона портов (по умолчанию 17400)
  MTPROXY_PORT_MAX     конец диапазона (по умолчанию 19999)
  MTPROXY_FAKE_DOMAIN  домен для generate-secret при первом создании secret
EOF
}

main() {
  local cmd="${1:-}"
  if (($# > 0)); then shift; fi
  case "$cmd" in
    add) cmd_add "$@" ;;
    remove) cmd_remove "$@" ;;
    disable) cmd_disable "$@" ;;
    enable) cmd_enable "$@" ;;
    list) cmd_list "$@" ;;
    link) cmd_link "$@" ;;
  restart) cmd_restart "$@" ;;
  logs) cmd_logs "$@" ;;
  start-all) cmd_start_all "$@" ;;
  stop-all) cmd_stop_all "$@" ;;
    ""|-h|--help|help) usage ;;
    *) die "Неизвестная команда: $cmd (см. --help)" ;;
  esac
}

main "$@"
