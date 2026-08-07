FROM python:3.12-slim

WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# data dir for sqlite + logs; Out Plane provides persistent disk at /data
ENV DATABASE_URL=sqlite:////data/monitor.db
VOLUME ["/data"]

EXPOSE 8080
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]