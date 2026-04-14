FROM python:3.11-slim

WORKDIR /app

# Cài dependencies trước (tận dụng Docker cache)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Tải spaCy model
RUN python -m spacy download en_core_web_lg

# Copy source code
COPY app/ ./app/

# Expose port
EXPOSE 8000

# Chạy server
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]