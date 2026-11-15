FROM python:3.12-slim
WORKDIR /app

COPY phylax ./phylax
# RUN install -d -o 10001 -g 10001 data/first-demo
# COPY --chown=10001:10001 data/first-demo/phylax-demo.db ./data/first-demo/phylax-demo.db

COPY scripts/prepare_sensor_demo.py scripts/generate_passive_demo.py ./scripts/
COPY tests/fixtures/public_cisa_icsa_24_004_01.json ./tests/fixtures/
RUN python scripts/prepare_sensor_demo.py --presentation --output-dir data/presentation \
    && chown -R 10001:10001 data/presentation

USER 10001:10001
ENV PHYLAX_PUBLIC=1 PYTHONUNBUFFERED=1
CMD ["sh", "-c", "exec python -m phylax --db data/presentation/phylax-demo.db --host 0.0.0.0 --port \"${PORT:-8765}\""]
