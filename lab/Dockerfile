FROM python:3.12-slim

WORKDIR /lab
COPY app.py /lab/app.py
RUN pip install --no-cache-dir "fastapi>=0.115,<1" "uvicorn>=0.30,<1"
RUN useradd --system --uid 10001 --no-create-home labuser

EXPOSE 8090
USER 10001:10001
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8090"]
