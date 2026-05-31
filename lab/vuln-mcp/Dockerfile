# Optional: build with `docker build -t vuln-mcp lab/vuln-mcp`
# Run interactively: `docker run --rm -i vuln-mcp`
# NOT wired into docker-compose.yml on purpose (MCP STDIO requires a live client session).
FROM python:3.12-slim
WORKDIR /app
COPY server.py /app/server.py
ENTRYPOINT ["python", "/app/server.py"]
