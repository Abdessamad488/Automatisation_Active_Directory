#!/bin/bash
# PentestAI-AD Setup Script for Kali Linux
# Run as: sudo bash setup_kali.sh

set -e

echo "=========================================="
echo "PentestAI-AD Setup for Kali Linux"
echo "=========================================="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root or with sudo"
    exit 1
fi

echo "[*] Updating system..."
apt update && apt upgrade -y

echo "[*] Installing system dependencies..."
apt install -y \
    python3 \
    python3-pip \
    python3-venv \
    git \
    responder \
    mitm6 \
    netexec \
    crackmapexec \
    python3-nmap \
    postgresql \
    neo4j

echo "[*] Installing Python tools..."
pip3 install impacket ldap3 bloodhound pyasn1

echo "[*] Setting up PostgreSQL..."
systemctl enable postgresql
systemctl start postgresql

# Create database
sudo -u postgres psql -c "CREATE USER pentestai WITH PASSWORD 'pentestai123';" 2>/dev/null || true
sudo -u postgres psql -c "CREATE DATABASE pentestdb OWNER pentestai;" 2>/dev/null || true
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE pentestdb TO pentestai;" 2>/dev/null || true

echo "[*] Setting up Neo4j..."
systemctl enable neo4j
systemctl start neo4j

# Configure Neo4j
echo "dbms.security.auth_enabled=false" >> /etc/neo4j/neo4j.conf 2>/dev/null || true

echo "[*] Installing Ollama..."
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull llama3.1:8b

echo "[*] Setting up Python virtual environment..."
cd /opt/PentestAI-AD/backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

echo "[*] Creating environment file..."
cat > .env << EOF
# Database
DATABASE_URL=postgresql://pentestai:pentestai123@localhost:5432/pentestdb
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=neo4j
REDIS_URL=redis://localhost:6379

# AI
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3.1:8b

# Security
SECRET_KEY=your-secret-key-change-in-production
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

# Lab Configuration
DC_IP=192.168.142.128
ATTACKER_IP=192.168.142.131
TARGET_IPS=192.168.142.134
DOMAIN=DATAPROTECT.local
EOF

echo "[*] Running database migrations..."
alembic upgrade head

echo ""
echo "=========================================="
echo "Setup Complete!"
echo "=========================================="
echo ""
echo "To start the application:"
echo "  cd /opt/PentestAI-AD/backend"
echo "  source venv/bin/activate"
echo "  uvicorn app.main:app --host 0.0.0.0 --port 8000"
echo ""
echo "Access the API at: http://192.168.142.131:8000/docs"
echo ""