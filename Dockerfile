# cvehub：Landscape × Canonical OSV 的 CVE 管理服務
# 內網：.env 設 BASE_IMAGE（事先 docker load 進來的基礎 image）、PIP_INDEX_URL（Nexus）
# 主機不能 docker pull 時：基礎 image 必須已在本機，建置不會去 registry 抓
ARG BASE_IMAGE=python:3.12-slim
FROM ${BASE_IMAGE}

ARG PIP_INDEX_URL=https://pypi.org/simple
ARG PIP_TRUSTED_HOST=
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --disable-pip-version-check --index-url "${PIP_INDEX_URL}" \
        ${PIP_TRUSTED_HOST:+--trusted-host "$PIP_TRUSTED_HOST"} -r requirements.txt

COPY cvehub ./cvehub
COPY tests ./tests

# 以非 root 執行；/data 放資料庫、放檔目錄、報表
RUN useradd --system --uid 10001 --home /data cvehub && mkdir -p /data /config && chown cvehub /data
USER cvehub
VOLUME ["/data"]
EXPOSE 8080

HEALTHCHECK --interval=60s --timeout=5s CMD python -c "import socket;socket.create_connection(('127.0.0.1',8080),3)" || exit 1
# 單一 worker（內建排程只能有一份），多執行緒處理網頁請求
# WEB_TLS_CERT／WEB_TLS_KEY 有設定就直接提供 HTTPS
CMD ["sh", "-c", "exec gunicorn --workers 1 --threads 8 --timeout 120 --bind ${WEB_LISTEN:-0.0.0.0}:${WEB_PORT:-8080} ${WEB_TLS_CERT:+--certfile $WEB_TLS_CERT --keyfile $WEB_TLS_KEY} 'cvehub.web:create_app()'"]
