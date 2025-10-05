#!/usr/bin/env bash
set -euo pipefail

SRC_PROMPT="${1:-}"
read -p "Targets (file or 2-letter country code, default 'ru'): " SRC
SRC="${SRC:-${SRC_PROMPT:-ru}}"
read -p "Port (default 25565): " PORT
PORT="${PORT:-25565}"
read -p "Rate (packets/sec) (default 5000): " RATE
RATE="${RATE:-5000}"
read -p "Out file (default results.txt): " OUT_FILE
OUT_FILE="${OUT_FILE:-results.txt}"
read -p "Workers for python checker (default 20): " WORKERS
WORKERS="${WORKERS:-20}"

PKG_MANAGER=""
if command -v apt-get >/dev/null 2>&1; then PKG_MANAGER="apt"; fi
if command -v dnf >/dev/null 2>&1; then PKG_MANAGER="dnf"; fi
if command -v yum >/dev/null 2>&1; then PKG_MANAGER="yum"; fi
if command -v pacman >/dev/null 2>&1; then PKG_MANAGER="pacman"; fi
if command -v zypper >/dev/null 2>&1; then PKG_MANAGER="zypper"; fi
if command -v apk >/dev/null 2>&1; then PKG_MANAGER="apk"; fi

install_pkg() {
  pkg="$1"
  case "$PKG_MANAGER" in
    apt) sudo apt-get install -y --no-install-recommends ${pkg} ;;
    dnf) sudo dnf install -y ${pkg} ;;
    yum) sudo yum install -y ${pkg} ;;
    pacman) sudo pacman -S --noconfirm ${pkg} ;;
    zypper) sudo zypper install -y ${pkg} ;;
    apk) sudo apk add ${pkg} ;;
    *) echo "Install ${pkg} manually"; return 1 ;;
  esac
}

if ! command -v masscan >/dev/null 2>&1; then
  case "$PKG_MANAGER" in
    apt) install_pkg masscan || true ;;
    dnf|yum) install_pkg masscan || true ;;
    pacman) install_pkg masscan || true ;;
    zypper) install_pkg masscan || true ;;
    apk) install_pkg masscan || true ;;
    *) echo "masscan not installed and package manager unknown. Please install masscan manually." ;;
  esac
fi

if ! command -v python3 >/dev/null 2>&1; then
  case "$PKG_MANAGER" in
    apt) install_pkg python3 python3-venv python3-pip || true ;;
    dnf|yum) install_pkg python3 python3-venv python3-pip || true ;;
    pacman) install_pkg python python-virtualenv python-pip || true ;;
    zypper) install_pkg python3 python3-venv python3-pip || true ;;
    apk) install_pkg python3 py3-virtualenv py3-pip || true ;;
    *) echo "python3 not installed; please install manually." ;;
  esac
fi

if ! command -v pip3 >/dev/null 2>&1; then
  case "$PKG_MANAGER" in
    apt) install_pkg python3-pip || true ;;
    dnf|yum) install_pkg python3-pip || true ;;
    pacman) install_pkg python-pip || true ;;
    zypper) install_pkg python3-pip || true ;;
    apk) install_pkg py3-pip || true ;;
    *) echo "pip3 not installed; please install manually." ;;
  esac
fi

if command -v setcap >/dev/null 2>&1 && command -v masscan >/dev/null 2>&1; then
  sudo setcap cap_net_raw+ep "$(command -v masscan)" || true
fi

VENV_DIR=".venv_masscan"
PY_PACKAGES=(dnspython colorama)
PIP_OK=0

if command -v pip3 >/dev/null 2>&1; then
  if pip3 install --user "${PY_PACKAGES[@]}" 2>/tmp/pip_install_err.log; then
    PIP_OK=1
  else
    # check for PEP 668 / externally managed message
    grep -qi "externally-managed-environment" /tmp/pip_install_err.log || true
    rm -f /tmp/pip_install_err.log || true
  fi
fi

if [ "$PIP_OK" -ne 1 ]; then
  if [ ! -d "$VENV_DIR" ]; then
    python3 -m venv "$VENV_DIR"
  fi
  # shellcheck source=/dev/null
  source "${VENV_DIR}/bin/activate"
  pip install --upgrade pip >/dev/null || true
  pip install "${PY_PACKAGES[@]}"
  deactivate
fi

TARGETS_FILE=""
if [ -f "$SRC" ]; then
  TARGETS_FILE="$SRC"
else
  cc="$(echo "$SRC" | tr '[:upper:]' '[:lower:]')"
  if [[ ! $cc =~ ^[a-z]{2}$ ]]; then
    echo "Argument must be existing file path or 2-letter country code (e.g. ru, us, de)."
    exit 1
  fi
  TARGETS_FILE="${cc}.zone"
  if [ ! -f "${TARGETS_FILE}" ]; then
    url="https://www.ipdeny.com/ipblocks/data/countries/${cc}.zone"
    echo "Downloading CIDR list for country '${cc}' from ${url} ..."
    if command -v curl >/dev/null 2>&1; then
      if ! curl -sSf -o "${TARGETS_FILE}" "${url}"; then
        echo "curl failed to download ${url} (DNS/network problem?). Trying wget..."
        rm -f "${TARGETS_FILE}"
      fi
    fi
    if [ ! -s "${TARGETS_FILE}" ] && command -v wget >/dev/null 2>&1; then
      if ! wget -q -O "${TARGETS_FILE}" "${url}"; then
        echo "wget failed to download ${url}."
        rm -f "${TARGETS_FILE}"
      fi
    fi
    if [ ! -s "${TARGETS_FILE}" ]; then
      echo "Failed to download ${url}."
      echo "Possible reasons: no internet, DNS blocking, site unavailable."
      echo "Options:"
      echo "  1) Check connection and DNS, then retry."
      echo "  2) Download manually and place the file as ${TARGETS_FILE}."
      echo "     Example: curl -s -o ${TARGETS_FILE} https://www.ipdeny.com/ipblocks/data/countries/${cc}.zone"
      exit 1
    fi
  fi
fi

if [ ! -s "${TARGETS_FILE}" ]; then
  echo "Targets file '${TARGETS_FILE}' missing or empty."
  exit 1
fi

if ! command -v masscan >/dev/null 2>&1; then
  echo "masscan not found in PATH. Install it and re-run."
  exit 1
fi

echo "Running masscan: targets=${TARGETS_FILE}, port=${PORT}, rate=${RATE}, out=${OUT_FILE}"
stdbuf -oL masscan -p"${PORT}" --rate "${RATE}" --open -iL "${TARGETS_FILE}" -oL "${OUT_FILE}"

echo "Running python checker..."
PY_RUN="python3"
if [ -x "${VENV_DIR}/bin/python" ]; then
  PY_RUN="${VENV_DIR}/bin/python"
fi

if [ ! -f "main.py" ]; then
  echo "main.py not found in current directory."
  exit 1
fi

"${PY_RUN}" main.py -i "${OUT_FILE}" -p "${PORT}" -w "${WORKERS}" -t 3.0