# Reference-SDK MCP lab server. Intentionally vulnerable - do not deploy.
FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir "mcp>=2.0"
COPY server.py /app/server.py
ENV MCP_LAB_HOST=0.0.0.0 MCP_LAB_PORT=9800 MCP_LAB_TRANSPORT=streamable-http
EXPOSE 9800
ENTRYPOINT ["python", "/app/server.py"]
