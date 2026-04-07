# nutc-voting-system/Dockerfile
# 多階段建構：先安裝依賴，再複製程式碼，減少映像大小

# ── Stage 1: 依賴安裝 ──────────────────────────────────────
FROM python:3.11-slim AS builder

RUN apt-get update && apt-get install -y \
    gcc \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /install
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install/deps -r requirements.txt


# ── Stage 2: 執行映像 ──────────────────────────────────────
FROM python:3.11-slim

# 安裝執行期所需的系統套件
RUN apt-get update && apt-get install -y \
    openssl \
    && rm -rf /var/lib/apt/lists/*

# 從 builder 複製已安裝的 Python 套件
COPY --from=builder /install/deps /usr/local

# 設定工作目錄
WORKDIR /app

# 複製整個專案（包含 shared/）
COPY . .

# 設定 Python 路徑，確保 shared/ 可被所有服務 import
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# 預設啟動命令（由 docker-compose 覆蓋）
CMD ["python", "-m", "flask", "--version"]
