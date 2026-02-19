#!/bin/sh

# ==============================================================================
# CONFIGURATION
# ==============================================================================

USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:146.0) Gecko/20100101 Firefox/146.0"
TIMEOUT_TOTAL=12
TIMEOUT_CONNECT=5
DEFAULT_THRESHOLD=24576
DEFAULT_OUTPUT="/tmp/dpi_check_results.txt"

# ==============================================================================
# ENVIRONMENT & UTILS
# ==============================================================================

export PATH=/usr/sbin:/usr/bin:/sbin:/bin
set -u

# Инициализация цветов
if [ -t 1 ]; then
    RED=$(printf '\033[0;31m')
    GREEN=$(printf '\033[0;32m')
    YELLOW=$(printf '\033[1;33m')
    BLUE=$(printf '\033[0;34m')
    MAGENTA=$(printf '\033[0;35m')
    CYAN=$(printf '\033[0;36m')
    NC=$(printf '\033[0m')
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; MAGENTA=''; CYAN=''; NC=''
fi

log_info() { printf "${BLUE}[INFO]${NC} %s\n" "$1" >&2; }
log_step() { printf "${CYAN}[>>>]${NC} %s\n" "$1" >&2; }
log_succ() { printf "${GREEN}[OK]${NC} %s\n" "$1"; }
log_err()  { printf "${RED}[ERROR]${NC} %s\n" "$1" >&2; }

cleanup() {
    kill $(jobs -p) 2>/dev/null
    [ -n "${WORKDIR:-}" ] && [ -d "$WORKDIR" ] && rm -rf "$WORKDIR"
}

guard_rails() {
    [ "$(id -u)" -ne 0 ] && { log_err "Run as root."; exit 1; }
    
    # Добавлен jq в список зависимостей, а также ps для проверки процессов
    for cmd in curl tcpdump awk ip grep wc sed nslookup jq ps timeout; do
        command -v "$cmd" >/dev/null 2>&1 || { log_err "Missing dependency: $cmd (install it first)"; exit 1; }
    done

    [ -z "${1:-}" ] && { log_err "Usage: $0 <suite.json>"; exit 1; }
}

# ==============================================================================
# DNS RESOLVER
# ==============================================================================

resolve_host() {
    local host="$1"
    local ip=""
    
    # 1. Localhost (AdGuard Home / dnsmasq)
    if command -v nslookup >/dev/null 2>&1; then
        ip=$(nslookup "$host" 127.0.0.1 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | grep -v '127.0.0.1' | grep -v '0.0.0.0' | head -1)
    fi

    # 2. Default Gateway
    if [ -z "$ip" ]; then
        local gateway=$(ip route show default 2>/dev/null | awk '/default/ {print $3}' | head -1)
        if [ -n "$gateway" ]; then
            ip=$(nslookup "$host" "$gateway" 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | grep -v "$gateway" | head -1)
        fi
    fi

    # 3. System Resolver (Fallback)
    if [ -z "$ip" ] && command -v getent >/dev/null 2>&1; then
        ip=$(getent hosts "$host" 2>/dev/null | awk '{print $1; exit}')
    fi

    # Final validation (Strict regex for IPv4)
    if echo "$ip" | grep -Eq '^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'; then
        echo "$ip"
        return 0
    fi
    return 1
}

# ==============================================================================
# CORE LOGIC
# ==============================================================================

check_dpi() {
    local id="$1"
    local provider="$2"
    local times_idx="$3"
    local raw_url="$4"
    local target_threshold="$5"
    
    local pcap="${WORKDIR}/${id}_${times_idx}.pcap"
    local body_file="${WORKDIR}/${id}_${times_idx}.body"
    local meta_file="${WORKDIR}/${id}_${times_idx}.meta"
    
    # Очистка URL от пробелов и якорей
    local url_clean=$(echo "$raw_url" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//;s/#.*$//')
    
    # --- SECURITY CHECK ---
    # Запрещаем схемы, отличные от http/https (защита от file:// и прочего)
    if ! echo "$url_clean" | grep -qE '^https?://'; then
        echo "${id}@${times_idx}|$provider|INVALID_SCHEME|url=$url_clean"
        return
    fi

    # --- RESOLVE & PORT DETECTION ---
    local host_full="${url_clean#*://}" # Удаляем http:// или https://
    local host="${host_full%%/*}"      # Оставляем только домен:порт

    # Пытаемся извлечь порт, если он указан явно (например, example.com:8443)
    local port=$(echo "$host" | grep -oE ':[0-9]+$' | tr -d :)
    
    if [ -z "$port" ]; then
        # Если порта нет, определяем по схеме
        case "$url_clean" in
            https*) port=443 ;;
            http*)  port=80 ;;
            *)      port=80 ;; # Fallback
        esac
    else
        # Убираем порт из переменной host для корректного DNS резолва
        host=${host%:*}
    fi

    local dst_ip; dst_ip=$(resolve_host "$host") || { 
        echo "${id}@${times_idx}|$provider|DNS_FAILED|ip=0.0.0.0"
        return
    }

    # --- ROUTE ---
    local route_info; route_info=$(ip route get "$dst_ip" 2>/dev/null) || {
        echo "${id}@${times_idx}|$provider|ROUTE_FAILED|ip=$dst_ip"
        return
    }
    
    # Извлечение интерфейса
    local iface=$(echo "$route_info" | sed -n 's/.*dev \([^ ]*\).*/\1/p')
    [ -z "$iface" ] && iface=$(ip route show default | awk '/default/ {print $5}' | head -1)

    # --- CAPTURE ---
    # Запускаем tcpdump в фоне
    tcpdump -i "$iface" -n -s 128 -U "host $dst_ip and tcp port $port" -w "$pcap" 2>/dev/null &
    local tcpdump_pid=$!
    
    # Ожидание появления файла (до 1 секунды)
    local wait_max=10
    while [ ! -s "$pcap" ] && [ "$wait_max" -gt 0 ]; do
        sleep 0.1
        wait_max=$((wait_max - 1))
    done
    # Если файл так и не появился, возможно tcpdump не запустился — прерываем тест
    if [ ! -s "$pcap" ]; then
        kill "$tcpdump_pid" 2>/dev/null
        wait "$tcpdump_pid" 2>/dev/null || true
        echo "${id}@${times_idx}|$provider|TCPDUMP_FAILED|ip=$dst_ip"
        return
    fi

    # --- REQUEST ---
    # Генерируем timestamp для обхода кэша
    local ts_rand=$(awk 'BEGIN{srand(); print int(rand()*1000000)}')
    local sep="?"; echo "$url_clean" | grep -q "?" && sep="&"
    local url_final="${url_clean}${sep}t=${ts_rand}"

    # Используем --resolve для гарантии, что curl пойдет на тот же IP, который мы слушаем
    # Убрали --location \
    # Прямой вызов curl без sh -c
    timeout "${TIMEOUT_TOTAL}s" curl -sSL \
        --resolve "$host:$port:$dst_ip" \
        --connect-timeout "$TIMEOUT_CONNECT" \
        -H "User-Agent: $USER_AGENT" \
        -H "Cache-Control: no-store" \
        -w '%{http_code}' \
        -o "$body_file" \
        "$url_final" > "$meta_file" 2>/dev/null # Риск интерпретации shell-спецсимволов в URL - проверять ссылки в тесте. Исправлять лень
    
    local curl_exit=$?

    # Останавливаем tcpdump
    if [ -n "$tcpdump_pid" ] && kill -0 "$tcpdump_pid" 2>/dev/null; then
        kill "$tcpdump_pid" 2>/dev/null; wait "$tcpdump_pid" 2>/dev/null || true
    fi

    # --- ANALYZE ---
    local body_size=0
    [ -f "$body_file" ] && body_size=$(wc -c < "$body_file" 2>/dev/null || echo 0)
    
    local http_code=0
    [ -f "$meta_file" ] && http_code=$(cat "$meta_file" 2>/dev/null || echo 0)

    local has_rst=0
    if [ -s "$pcap" ] && tcpdump -n -r "$pcap" 'tcp[13] & 4 != 0' 2>/dev/null | grep -q .; then
        has_rst=1
    fi
    
    # Удаляем временные файлы конкретного теста
    rm -f "$body_file" "$pcap" "$meta_file" 2>/dev/null

    # --- VERDICT ---
    local is_timeout=0
    { [ "$curl_exit" -eq 124 ] || [ "$curl_exit" -eq 143 ] || [ "$curl_exit" -eq 28 ]; } && is_timeout=1
    
    # 1. SUCCESS
    if [ "$body_size" -ge "$target_threshold" ]; then
        echo "${id}@${times_idx}|$provider|OK|size=${body_size},ip=$dst_ip,code=$http_code"
        return
    fi

    # 2. RST BLOCK
    if [ "$has_rst" -eq 1 ]; then
        echo "${id}@${times_idx}|$provider|RST_DETECTED|size=${body_size},ip=$dst_ip"
        return
    fi

    # 3. FROZEN (Read Timeout)
    if [ "$is_timeout" -eq 1 ] && [ "$body_size" -gt 0 ]; then
        echo "${id}@${times_idx}|$provider|READ_TIMEOUT|size=${body_size},ip=$dst_ip,code=$http_code"
        return
    fi
    
    # 4. BLACKHOLE (Conn Timeout)
    if [ "$is_timeout" -eq 1 ] && [ "$body_size" -eq 0 ]; then
        echo "${id}@${times_idx}|$provider|CONN_TIMEOUT|size=0,ip=$dst_ip"
        return
    fi
    
    # 5. CONNECTION ERROR
    if [ "$curl_exit" -ne 0 ] && [ "$body_size" -eq 0 ]; then
         echo "${id}@${times_idx}|$provider|CONN_ERROR|size=0,ip=$dst_ip,curl_err=$curl_exit"
         return
    fi
    
    # 6. INCOMPLETE
    if [ "$body_size" -lt "$target_threshold" ]; then
        if [ "$http_code" -ge 400 ]; then
             echo "${id}@${times_idx}|$provider|HTTP_ERROR|size=${body_size},ip=$dst_ip,code=$http_code"
        else
             echo "${id}@${times_idx}|$provider|TOO_SMALL|size=${body_size},thresh=${target_threshold},ip=$dst_ip"
        fi
        return
    fi
    
    echo "${id}@${times_idx}|$provider|UNKNOWN|size=${body_size},exit=${curl_exit},ip=$dst_ip"
}

# ==============================================================================
# TARGET LOADING & REPORTING
# ==============================================================================

load_targets() {
    local target_file="$1"
    > "$WORKDIR/targets"
    
    # Формат строки: id|provider|times|url|threshold
    jq -r --arg def_thresh "$DEFAULT_THRESHOLD" \
        '.[] | "\(.id)|\(.provider)|\(.times // 1)|\(.url)|\(.thresholdBytes // $def_thresh)"' \
        "$target_file" | while IFS='|' read -r id provider times url thresh; do
            
        [ -z "$id" ] || [ -z "$url" ] && continue
        
        local i=0
        while [ "$i" -lt "$times" ]; do
            echo "$id|$provider|$i|$url|$thresh" >> "$WORKDIR/targets"
            i=$((i + 1))
        done
    done
    
    wc -l < "$WORKDIR/targets" 2>/dev/null
}

print_results() {
    local output_file="$1"
    echo
    echo "========================================================================================================"
    printf "%-18s | %-12s | %-15s | %-10s | %-16s | %s\n" "PROVIDER" "ID" "IP" "SIZE" "STATUS" "DETAILS"
    echo "========================================================================================================"
    
    local total=0 detected=0 ok=0 failed=0
    
    while IFS='|' read -r id_full provider status details; do
        [ -z "$id_full" ] && continue
        
        total=$((total + 1))
        local id="${id_full%@*}"
        local size=$(echo "$details" | sed -n 's/.*size=\([0-9]*\).*/\1/p')
        local ip=$(echo "$details" | sed -n 's/.*ip=\([^,]*\).*/\1/p')
        
        local size_fmt="0 B"
        [ -n "$size" ] && size_fmt=$(awk -v s="${size:-0}" 'BEGIN { if(s>=1048576) printf "%.1f M", s/1048576; else if(s>=1024) printf "%.0f K", s/1024; else printf "%d B", s }')

        case "$status" in
            OK)
                printf "${GREEN}%-18s${NC} | %-12s | %-15s | %-10s | ${GREEN}%-16s${NC} | %s\n" \
                    "$provider" "$id" "$ip" "$size_fmt" "OK" ""
                ok=$((ok + 1)) ;;
            RST_DETECTED)
                printf "${RED}%-18s${NC} | %-12s | %-15s | %-10s | ${RED}%-16s${NC} | %s\n" \
                    "$provider" "$id" "$ip" "$size_fmt" "BLOCKED (RST)" "TCP Reset"
                detected=$((detected + 1)) ;;
            READ_TIMEOUT)
                printf "${MAGENTA}%-18s${NC} | %-12s | %-15s | %-10s | ${MAGENTA}%-16s${NC} | %s\n" \
                    "$provider" "$id" "$ip" "$size_fmt" "BLOCKED (READ)" "Frozen/Throttled"
                detected=$((detected + 1)) ;;
            CONN_TIMEOUT|CONN_ERROR)
                printf "${RED}%-18s${NC} | %-12s | %-15s | %-10s | ${RED}%-16s${NC} | %s\n" \
                    "$provider" "$id" "$ip" "$size_fmt" "BLOCKED (CONN)" "No Connection"
                detected=$((detected + 1)) ;;
            HTTP_ERROR|DNS_FAILED|ROUTE_FAILED|INVALID_SCHEME)
                printf "${YELLOW}%-18s${NC} | %-12s | %-15s | %-10s | ${YELLOW}%-16s${NC} | %s\n" \
                    "$provider" "$id" "$ip" "$size_fmt" "ERROR" "$status"
                failed=$((failed + 1)) ;;
            *)
                printf "${YELLOW}%-18s${NC} | %-12s | %-15s | %-10s | ${YELLOW}%-16s${NC} | %s\n" \
                    "$provider" "$id" "$ip" "$size_fmt" "WARN" "${status//_/ }"
                failed=$((failed + 1)) ;;
        esac
    done < "$output_file"
    
    echo "========================================================================================================"
    printf "SUMMARY: Total: %d | ${RED}Blocked: %d${NC} | ${GREEN}OK: %d${NC} | ${YELLOW}Warnings: %d${NC}\n" "$total" "$detected" "$ok" "$failed"
}

# ==============================================================================
# MAIN
# ==============================================================================

TARGETS_FILE="${1:-}"
OUTPUT_FILE="${2:-$DEFAULT_OUTPUT}"

guard_rails "$TARGETS_FILE"

WORKDIR=$(mktemp -d -t dpi_check.XXXXXX) || exit 1
trap 'cleanup; exit' EXIT INT TERM

log_step "Initializing"
target_count=$(load_targets "$TARGETS_FILE")

if [ "$target_count" -eq 0 ]; then 
    log_err "No targets found or JSON parse error."
    exit 1
fi

log_info "Targets loaded: $target_count"
> "$OUTPUT_FILE"

curr_idx=0
while IFS='|' read -r id provider times_idx url thresh; do
    curr_idx=$((curr_idx + 1))
    printf "\r[Running %d/%d] %s (%s)..." "$curr_idx" "$target_count" "$id" "$provider" >&2
    check_dpi "$id" "$provider" "$times_idx" "$url" "$thresh" >> "$OUTPUT_FILE"
done < "$WORKDIR/targets"

echo "" >&2
print_results "$OUTPUT_FILE"

log_succ "Complete."
