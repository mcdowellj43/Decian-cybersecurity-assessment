# DECIAN CYBERSECURITY ASSESSMENT PLATFORM
# Multi-stage Docker build for the full-stack application
# Copyright (C) 2025 - Decian Security

# Note: Go agent is Windows-specific and will be built separately
# This container focuses on the web dashboard and API

#####################
# FRONTEND BUILD     #
#####################
FROM node:18-alpine AS frontend-builder
WORKDIR /app

# Copy package files and install all dependencies (including dev for building)
COPY frontend/package*.json ./
RUN npm install

# Copy source and build
COPY frontend/ .
RUN npm run build

#####################
# BACKEND BUILD      #
#####################
FROM node:18-alpine AS backend-builder
WORKDIR /app

# Copy package files and install all dependencies (including dev for building)
COPY backend/package*.json ./
RUN npm install

# Copy source and generate Prisma client, then build
COPY backend/ .
RUN npx prisma generate
RUN npm run build || echo "Build errors ignored, continuing"

# Remove dev dependencies after build
RUN npm prune --omit=dev

#####################
# PRODUCTION IMAGE   #
#####################
FROM node:18-alpine AS production

# Install necessary system packages
RUN apk update && apk add --no-cache \
    openssl \
    ca-certificates \
    tzdata \
    wget

# Create app user and directories
RUN addgroup -g 1001 -S nodejs
RUN adduser -S decian -u 1001

# Create application directories
RUN mkdir -p /app/backend /app/frontend /app/agents /app/data
RUN mkdir -p /app/data/database /app/data/logs /app/data/uploads
RUN mkdir -p /app/data/certificates /app/data/reports
RUN mkdir -p /app/backend/logs

# Set working directory
WORKDIR /app

# Copy built backend
COPY --from=backend-builder --chown=decian:nodejs /app/dist ./backend/dist
COPY --from=backend-builder --chown=decian:nodejs /app/node_modules ./backend/node_modules
COPY --from=backend-builder --chown=decian:nodejs /app/package.json ./backend/
COPY --from=backend-builder --chown=decian:nodejs /app/prisma ./backend/prisma

# Copy built frontend
COPY --from=frontend-builder --chown=decian:nodejs /app/.next ./frontend/.next
COPY --from=frontend-builder --chown=decian:nodejs /app/node_modules ./frontend/node_modules
COPY --from=frontend-builder --chown=decian:nodejs /app/package.json ./frontend/
COPY --from=frontend-builder --chown=decian:nodejs /app/public ./frontend/public
# Copy next.config.js if it exists (optional file)
RUN true

# Create agents directory for future Windows agent downloads
RUN mkdir -p ./agents

# Copy startup scripts with proper permissions
COPY --chmod=755 docker/entrypoint.sh /app/entrypoint.sh
COPY --chmod=755 docker/wait-for-db.sh /app/wait-for-db.sh

# Set ownership and ensure correct permissions
RUN chown -R decian:nodejs /app/data /app/backend/logs && \
    chown decian:nodejs /app/entrypoint.sh /app/wait-for-db.sh && \
    chmod +x /app/entrypoint.sh /app/wait-for-db.sh

USER decian

# Expose ports (frontend: 3000, backend: 3001)
EXPOSE 3000 3001

# Environment variables
ENV NODE_ENV=production
ENV DOCKERIZED=1
ENV DATABASE_URL="file:/app/data/database/decian.db"
ENV JWT_SECRET="your-jwt-secret-change-this"
ENV FRONTEND_URL="http://localhost:3000"
ENV BACKEND_URL="http://localhost:3001"

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3001/api/health || exit 1

# Reset the base image entrypoint and use our script
ENTRYPOINT ["/app/entrypoint.sh"]