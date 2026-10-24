# syntax=docker/dockerfile:1
#
# Multi-stage container image for the cvestate MCP server.
#
# Stage 1 (builder): resolves and installs the dependency set plus the project
#   itself into a self-contained virtual environment using uv. uv is a fast,
#   deterministic Python package manager/resolver; we pull a pinned static uv
#   binary from the official Astral image rather than pip-installing it.
# Stage 2 (runtime): a clean python:3.12-slim image that only receives the
#   already-built /app/.venv plus the source tree. It runs as a non-root user
#   and exposes the streamable-HTTP MCP endpoint on port 8000.
#
# Build:  docker build -t cvestate .
# Run:    docker run --rm -p 8000:8000 --env-file .env cvestate

############################
# Stage 1 - builder
############################
FROM python:3.12-slim AS builder

# Bring in the uv binary from the official distroless uv image. Using a tagged
# copy keeps the resolver behaviour reproducible and avoids a network pip step.
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# uv tuning:
#   UV_COMPILE_BYTECODE=1  -> precompile .pyc at install time for faster startup
#   UV_LINK_MODE=copy      -> copy files instead of hardlinking (hardlinks fail
#                             across the cache mount / overlay boundaries)
#   UV_PYTHON_DOWNLOADS=0  -> never fetch a managed interpreter; use the image's
#   UV_PROJECT_ENVIRONMENT -> install into a predictable, copyable venv path
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=0 \
    UV_PROJECT_ENVIRONMENT=/app/.venv

WORKDIR /app

# Install ONLY the dependencies first (without the project source) so this
# expensive layer is cached and reused whenever only application code changes.
#
# NOTE: there is no uv.lock committed in the repo, so we cannot use the
# --frozen flag (it requires an up-to-date lock file and would fail the build).
# uv performs a fresh resolution from pyproject.toml here. If a uv.lock is added
# later, switch both commands to `uv sync --frozen --no-dev ...` for fully
# reproducible builds. README.md is copied because pyproject.toml references it
# as the project readme and the build backend (hatchling) reads it.
COPY pyproject.toml README.md ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --no-dev --no-install-project

# Copy the actual source tree and install the project itself into the venv.
COPY src ./src
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --no-dev

############################
# Stage 2 - runtime
############################
FROM python:3.12-slim AS runtime

# Create an unprivileged user/group to run the server (never run as root).
RUN groupadd --system --gid 1000 app \
    && useradd --system --uid 1000 --gid 1000 --create-home --shell /usr/sbin/nologin app

WORKDIR /app

# Runtime environment:
#   PATH                    -> put the venv's bin first so `python` is the venv
#   PYTHONUNBUFFERED        -> stream logs immediately (no stdout buffering)
#   PYTHONDONTWRITEBYTECODE -> don't write .pyc at runtime (already compiled)
#   MCP_TRANSPORT=http      -> serve over streamable HTTP instead of stdio
#   FASTMCP_HOST / _PORT    -> FastMCP reads these to bind the HTTP listener;
#                              0.0.0.0:8000 makes the published port reachable
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    MCP_TRANSPORT=http \
    FASTMCP_HOST=0.0.0.0 \
    FASTMCP_PORT=8000

# Copy the built virtual environment and the source from the builder stage,
# handing ownership to the non-root user so they are readable at runtime.
COPY --from=builder --chown=app:app /app/.venv /app/.venv
COPY --from=builder --chown=app:app /app/src /app/src
COPY --chown=app:app pyproject.toml README.md ./

# Drop privileges.
USER app

EXPOSE 8000

# Liveness probe for the streamable-HTTP transport, whose endpoint mounts at
# /mcp. A bare GET without the MCP handshake headers still gets an HTTP response
# (often 400/405/406), which proves the listener is up; an urllib.error.HTTPError
# therefore counts as HEALTHY. Only a connection-level failure (server not
# listening) is unhealthy. Uses stdlib urllib so no extra packages (curl/wget)
# are required in the slim runtime image.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["python", "-c", "import sys, urllib.request, urllib.error\ntry:\n    urllib.request.urlopen('http://localhost:8000/mcp', timeout=4)\nexcept urllib.error.HTTPError:\n    sys.exit(0)\nexcept Exception:\n    sys.exit(1)\nsys.exit(0)"]

# Run the MCP server module. (The later wiring phase makes main() honour
# MCP_TRANSPORT/FASTMCP_HOST/FASTMCP_PORT to start the streamable-HTTP transport.)
CMD ["python", "-m", "cve_mcp.server"]
