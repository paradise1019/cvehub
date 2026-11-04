# wheels/

離線安裝包（`scripts/make-offline.sh` 產生）會把 Python 套件放在這裡。
這裡有 `*.whl` 時，建置 image 只從這裡安裝套件（`pip install --no-index`），不連任何套件來源；
沒有時照 `.env` 的 `PIP_INDEX_URL` 安裝。一般安裝不需要動這個目錄。
