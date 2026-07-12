# AC-2035 API image.
# Build context is the repo root (see docker-compose.yml). The API imports
# from backtrace/, graph/, killswitch/, deployer/, collector/, detector/, so
# all of them are copied in — not just api/.
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Shared modules the API depends on.
COPY api/ ./api/
COPY graph/ ./graph/
COPY backtrace/ ./backtrace/
COPY killswitch/ ./killswitch/
COPY deployer/ ./deployer/
COPY collector/ ./collector/
COPY detector/ ./detector/

EXPOSE 8000

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
