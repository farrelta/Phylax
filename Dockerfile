FROM python:3.10-slim
WORKDIR /app
COPY . .
ENV PHYLAX_PUBLIC=1
EXPOSE 8765
CMD ["python", "-m", "phylax", "--db", "data/first-demo/phylax-demo.db", "serve", "--host", "0.0.0.0", "--port", "8765"]
