# Intentionally vulnerable A2A agent. DO NOT DEPLOY.
FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir 'a2a-sdk[http-server]>=1.1' 'uvicorn>=0.30'
COPY agent.py /app/lab/a2a/agent.py
ENV PYTHONPATH=/app A2A_LAB_HOST=0.0.0.0 A2A_LAB_PORT=9700
EXPOSE 9700
CMD ["python", "-m", "lab.a2a.agent"]
