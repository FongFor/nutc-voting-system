# /online-voting-system/Dockerfile
FROM python:3.11-slim

# 安裝 OpenSSL 等等等...
RUN apt-get update && apt-get install -y \
    openssl \
    libssl-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# 設定工作目錄
WORKDIR /app

# 複製 requirements.txt 並安裝套件
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 將當前目錄的所有檔案複製到容器內
COPY . .