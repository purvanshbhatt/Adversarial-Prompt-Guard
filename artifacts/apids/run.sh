#!/bin/bash
set -e

cd "$(dirname "$0")"

# Start FastAPI backend in background on port 6000
echo "Starting FastAPI backend on port 6000..."
python3 -m uvicorn app.main:app --host 0.0.0.0 --port 6000 --log-level info &
FASTAPI_PID=$!

# Give FastAPI a moment to start
sleep 3

# Start Streamlit dashboard in foreground on port 8099
echo "Starting Streamlit dashboard on port 8099..."
python3 -m streamlit run dashboard/streamlit_app.py \
    --server.port 8099 \
    --server.address 0.0.0.0 \
    --server.headless true \
    --server.enableCORS false \
    --server.enableXsrfProtection false

# If Streamlit exits, kill FastAPI too
kill $FASTAPI_PID 2>/dev/null || true
