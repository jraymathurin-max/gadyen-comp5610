FROM python:3.12-slim
WORKDIR /app
RUN useradd --create-home gadyen
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY gadyen ./gadyen
USER gadyen
ENV GADYEN_DB_PATH=/home/gadyen/gadyen.db
EXPOSE 8000
CMD ["uvicorn", "gadyen.api:app", "--host", "0.0.0.0", "--port", "8000"]
