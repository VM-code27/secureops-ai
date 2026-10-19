# One image, two entrypoints (dashboard by default, API via docker-compose).
# Also works unchanged as a Hugging Face Docker Space (it sets PORT=7860).
FROM python:3.12-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PORT=8501
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd -m app && mkdir -p data && chown -R app /app
USER app
EXPOSE 8501
CMD ["sh", "-c", "streamlit run streamlit_app.py --server.port ${PORT} --server.address 0.0.0.0"]
