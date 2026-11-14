FROM python:3.10-slim
WORKDIR /app
COPY . /app/
RUN echo "Build $(date)" && ls -la /app/ && ls -la /app/phylax/ && python -c "import phylax; print('phylax module OK')"
ENV PHYLAX_PUBLIC=1
CMD python -m phylax --db data/first-demo/phylax-demo.db serve --host 0.0.0.0 --port ${PORT:-8765}
