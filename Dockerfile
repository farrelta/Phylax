FROM python:3.12-slim
WORKDIR /app

COPY phylax ./phylax
RUN install -d -o 10001 -g 10001 data/first-demo
COPY --chown=10001:10001 data/first-demo/phylax-demo.db ./data/first-demo/phylax-demo.db

USER 10001:10001
ENV PHYLAX_PUBLIC=1 PYTHONUNBUFFERED=1
CMD ["sh", "-c", "exec python -m phylax --db data/first-demo/phylax-demo.db serve --host 0.0.0.0 --port \"${PORT:-8765}\""]
