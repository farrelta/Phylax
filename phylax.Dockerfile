# Phylax in a container, still reachable only from the computer running Docker.
#
# Phylax refuses to listen on anything but 127.0.0.1 and only accepts requests
# addressed to localhost on its own port. Inside the container it keeps doing
# exactly that; socat relays the published port to it. Publish the port on
# 127.0.0.1 with the same number on both sides (see docker-compose.yml).
FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends socat \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY phylax ./phylax
COPY scripts ./scripts
COPY README.md ./
COPY docker/phylax-entrypoint.sh /usr/local/bin/phylax-entrypoint

# Windows checkouts may add CRLF line endings, which break shell scripts.
RUN sed -i 's/\r$//' /usr/local/bin/phylax-entrypoint \
    && chmod 755 /usr/local/bin/phylax-entrypoint \
    && useradd --create-home --uid 10001 phylax \
    && mkdir -p /data \
    && chown phylax /data

USER phylax
ENV PYTHONUNBUFFERED=1 \
    PHYLAX_PORT=8765 \
    PHYLAX_DB=/data/phylax.db \
    PHYLAX_DEMO=0
VOLUME /data
EXPOSE 8765

ENTRYPOINT ["phylax-entrypoint"]
