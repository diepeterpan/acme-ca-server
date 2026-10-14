#!/usr/bin/env bash
set -e

# Resolve repository root directory
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_DIR"

# 1. Activate or create virtual environment (.venv or venv)
if [ -f "$REPO_DIR/.venv/bin/activate" ] && [ -f "$REPO_DIR/.venv/bin/pip" ]; then
    echo "--> Activating virtualenv: .venv"
    source "$REPO_DIR/.venv/bin/activate"
elif [ -f "$REPO_DIR/venv/bin/activate" ] && [ -f "$REPO_DIR/venv/bin/pip" ]; then
    echo "--> Activating virtualenv: venv"
    source "$REPO_DIR/venv/bin/activate"
else
    echo "--> Setting up Python virtual environment at .venv..."
    VENV_DIR="$REPO_DIR/.venv"
    rm -rf "$VENV_DIR"
    if ! python3 -m venv "$VENV_DIR" 2>/dev/null; then
        echo "--> Notice: Standard venv creation failed (ensurepip missing). Bootstrapping venv with pip..."
        rm -rf "$VENV_DIR"
        python3 -m venv --without-pip "$VENV_DIR"
        PIP_WHL=$(find /var/lib/flatpak /usr/share /usr/lib -name "pip*-any.whl" 2>/dev/null | head -n 1)
        if [ -n "$PIP_WHL" ]; then
            "$VENV_DIR/bin/python3" "$PIP_WHL/pip" install --no-index "$PIP_WHL" -q
        else
            curl -sSL https://bootstrap.pypa.io/get-pip.py | "$VENV_DIR/bin/python3" - -q
        fi
    fi

    if [ ! -f "$VENV_DIR/bin/activate" ] || [ ! -f "$VENV_DIR/bin/pip" ]; then
        echo "Error: Failed to create virtual environment with pip."
        echo "Please run: sudo apt install python3-venv"
        exit 1
    fi
    source "$VENV_DIR/bin/activate"
    echo "--> Virtual environment ready!"
fi

# 2. Install / verify dependencies from requirements.txt
if [ -f "$REPO_DIR/requirements.txt" ]; then
    echo "--> Installing / updating dependencies from requirements.txt..."
    pip install --upgrade pip -q
    pip install -r "$REPO_DIR/requirements.txt"
fi

# 3. Ensure Swagger UI and Milligram CSS assets exist locally in app/web/www/libs
LIBS_DIR="$REPO_DIR/app/web/www/libs"
if [ ! -f "$LIBS_DIR/swagger-ui.css" ] || [ ! -f "$LIBS_DIR/swagger-ui-bundle.js" ]; then
    echo "--> Downloading Swagger UI static assets to app/web/www/libs..."
    mkdir -p "$LIBS_DIR"
    curl -fsSL "https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css" -o "$LIBS_DIR/swagger-ui.css" || true
    curl -fsSL "https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js" -o "$LIBS_DIR/swagger-ui-bundle.js" || true
    curl -fsSL "https://cdnjs.cloudflare.com/ajax/libs/milligram/1.4.1/milligram.min.css" -o "$LIBS_DIR/milligram.min.css" || true
fi

# 4. Check for .env file; create from .env.example if missing
if [ ! -f "$REPO_DIR/.env" ]; then
    if [ -f "$REPO_DIR/.env.example" ]; then
        echo "--> No .env file found. Creating from .env.example..."
        cp "$REPO_DIR/.env.example" "$REPO_DIR/.env"
        echo "--> .env created! (Note: .env is in .gitignore and will not be checked into git)"
    else
        echo "Error: Neither .env nor .env.example found!"
        exit 1
    fi
fi

# 4. Load environment variables from .env
echo "--> Loading environment configuration from .env..."
set -a
# shellcheck source=/dev/null
source "$REPO_DIR/.env"
set +a

# 5. Helper function to test if PostgreSQL is responding at DB_DSN
check_db_reachable() {
    python3 -c "
import socket, os
dsn = os.environ.get('DB_DSN', '')
if '://' in dsn:
    netloc = dsn.split('://', 1)[1].split('/', 1)[0]
    if '@' in netloc:
        netloc = netloc.split('@', 1)[1]
    if ':' in netloc:
        host, port = netloc.split(':', 1)
        port = int(port)
    else:
        host, port = netloc, 5432
else:
    host, port = 'localhost', 5432
s = socket.socket()
s.settimeout(1.5)
s.connect((host, port))
s.close()
" 2>/dev/null
}

# 6. Helper to determine docker execution command (docker or sudo docker)
get_docker_cmd() {
    if command -v docker &>/dev/null; then
        if docker ps &>/dev/null; then
            echo "docker"
        else
            echo "sudo docker"
        fi
    else
        echo ""
    fi
}

# 7. Helper to install Docker if missing
ensure_docker_installed() {
    local cmd
    cmd=$(get_docker_cmd)
    if [ -n "$cmd" ]; then
        return 0
    fi

    echo ""
    echo "=========================================================="
    echo " Docker is not installed on this system."
    echo " A container manager is required to run the local database."
    echo "=========================================================="
    read -r -p "Would you like to install Docker now? [Y/n] " install_resp
    install_resp="${install_resp:-Y}"
    if [[ "$install_resp" =~ ^[Yy]$ ]]; then
        echo "--> Installing Docker via official script (curl -fsSL https://get.docker.com | sudo sh)..."
        curl -fsSL https://get.docker.com | sudo sh
        echo "--> Adding current user ($USER) to docker group..."
        sudo usermod -aG docker "$USER" || true
        sudo systemctl enable --now docker || true
        echo "--> Docker installed and service enabled!"
        return 0
    else
        echo "--> Docker installation skipped. Please ensure PostgreSQL is running at ${DB_DSN}."
        return 1
    fi
}

# 8. Manage PostgreSQL local container lifecycle
ensure_postgres_running() {
    local DOCKER_CMD
    DOCKER_CMD=$(get_docker_cmd)

    local CONTAINER_NAME="acme-postgres-dev"
    local VOLUME_NAME="acme_postgres_data"

    # 1. If docker is available, check if our dev container already exists (running or stopped)
    if [ -n "$DOCKER_CMD" ]; then
        local CONTAINER_EXISTS
        CONTAINER_EXISTS=$($DOCKER_CMD ps -a --filter "name=^/${CONTAINER_NAME}$" --format '{{.Names}}' 2>/dev/null || true)

        if [ -n "$CONTAINER_EXISTS" ]; then
            echo ""
            echo "=========================================================="
            echo " Existing PostgreSQL dev container ('${CONTAINER_NAME}') found."
            echo "=========================================================="
            read -r -p "Recreate it for a fresh test database? (deletes existing volume/data) [y/N]: " reset_resp
            reset_resp="${reset_resp:-N}"
            if [[ "$reset_resp" =~ ^[Yy]$ ]]; then
                echo "--> Removing existing container '${CONTAINER_NAME}'..."
                $DOCKER_CMD rm -f "$CONTAINER_NAME"
                echo "--> Removing existing volume '${VOLUME_NAME}'..."
                $DOCKER_CMD volume rm -f "$VOLUME_NAME" 2>/dev/null || true
                CONTAINER_EXISTS=""
            else
                # Re-use existing container: start if stopped
                if [ -z "$($DOCKER_CMD ps --filter "name=^/${CONTAINER_NAME}$" --format '{{.Names}}')" ]; then
                    echo "--> Starting existing PostgreSQL container '${CONTAINER_NAME}'..."
                    $DOCKER_CMD start "$CONTAINER_NAME"
                else
                    echo "--> PostgreSQL container '${CONTAINER_NAME}' is running."
                fi
                echo "--> Waiting for PostgreSQL to be ready..."
                until $DOCKER_CMD exec "$CONTAINER_NAME" pg_isready -U postgres &>/dev/null; do
                    sleep 1
                done
                echo "--> PostgreSQL is ready!"
                return 0
            fi
        fi
    fi

    # 2. If no dev container exists, check if PostgreSQL is already running externally
    if check_db_reachable; then
        echo "--> PostgreSQL is running and reachable at ${DB_DSN}."
        return 0
    fi

    # 3. If unreachable and dev container doesn't exist, ensure Docker is installed
    echo "--> PostgreSQL is not responding at ${DB_DSN}."
    ensure_docker_installed || return 0

    DOCKER_CMD=$(get_docker_cmd)
    if [ -z "$DOCKER_CMD" ]; then
        echo "Error: Docker command could not be resolved."
        return 1
    fi

    # Ensure docker daemon service is started
    if ! $DOCKER_CMD info &>/dev/null; then
        echo "--> Starting Docker daemon..."
        sudo systemctl start docker || true
    fi

    echo ""
    read -r -p "Create and run local PostgreSQL database container ('${CONTAINER_NAME}') on port 5432? [Y/n]: " create_resp
    create_resp="${create_resp:-Y}"
    if [[ "$create_resp" =~ ^[Yy]$ ]]; then
        echo "--> Launching PostgreSQL container '${CONTAINER_NAME}' with volume '${VOLUME_NAME}'..."
        $DOCKER_CMD run -d \
            --name "$CONTAINER_NAME" \
            --restart unless-stopped \
            -p 127.0.0.1:5432:5432 \
            -e POSTGRES_USER=postgres \
            -e POSTGRES_PASSWORD=secret \
            -e POSTGRES_DB=postgres \
            -v "${VOLUME_NAME}:/var/lib/postgresql/data" \
            postgres:16-alpine

        # Persist dev options in .env if not present
        if ! grep -q "^DEV_DB_CONTAINER=" "$REPO_DIR/.env" 2>/dev/null; then
            echo "" >> "$REPO_DIR/.env"
            echo "# Persisted local dev container configuration" >> "$REPO_DIR/.env"
            echo "DEV_CONTAINER_ENGINE=docker" >> "$REPO_DIR/.env"
            echo "DEV_DB_CONTAINER=${CONTAINER_NAME}" >> "$REPO_DIR/.env"
        fi
    else
        echo "--> Skipped container creation. Please start PostgreSQL manually."
        return 0
    fi

    # Wait for PostgreSQL to be ready
    echo "--> Waiting for PostgreSQL to be ready to accept connections..."
    local attempts=0
    until $DOCKER_CMD exec "$CONTAINER_NAME" pg_isready -U postgres &>/dev/null || [ $attempts -ge 30 ]; do
        sleep 1
        attempts=$((attempts + 1))
    done

    if [ $attempts -ge 30 ]; then
        echo "Warning: Timed out waiting for PostgreSQL to be ready."
    else
        echo "--> PostgreSQL is ready!"
    fi
}

# Run the database verification / provisioning check
ensure_postgres_running

# 9. Ensure uvicorn is installed
if ! command -v uvicorn &>/dev/null; then
    echo "Error: 'uvicorn' command not found."
    echo "Please install requirements first: pip install -r requirements.txt"
    exit 1
fi

HOST="${HOST:-0.0.0.0}"
PORT="${PORT:-8080}"

echo "=========================================================="
echo " Starting ACME CA Server at http://${HOST}:${PORT}"
echo " External URL: ${EXTERNAL_URL:-http://localhost:8080}"
echo " Database:     ${DB_DSN}"
echo "=========================================================="

# 10. Start Uvicorn from the app directory with reload enabled
cd "$REPO_DIR/app"
exec uvicorn main:app --host "$HOST" --port "$PORT" --reload
