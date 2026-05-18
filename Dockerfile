FROM python:3.12-slim
LABEL Name=projectplutonium Version=0.0.1

WORKDIR /app
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt
COPY . /app

EXPOSE 8080 5678
CMD ["python", "-m", "uvicorn", "scanner:app", "--host", "0.0.0.0", "--port", "8080", "--reload"]
