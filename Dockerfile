FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml ./
COPY README.md ./
COPY namazu ./namazu
RUN pip install --no-cache-dir . && useradd --create-home namazu
USER namazu
EXPOSE 8010
CMD ["namazu", "--host", "0.0.0.0", "--port", "8010"]
