#!/bin/sh
# DECIAN CYBERSECURITY ASSESSMENT PLATFORM
# Docker entrypoint script for production deployment

set -e

echo "🚀 Starting Decian Cybersecurity Assessment Platform..."

# Wait for database directory to be ready
/app/wait-for-db.sh

# Navigate to backend and run database migrations
echo "📊 Setting up database..."
cd /app/backend
npx prisma generate
npx prisma db push

# Start backend in background
echo "🔧 Starting backend API server on port 3001..."
node -r module-alias/register dist/index.js &
BACKEND_PID=$!

# Navigate to frontend and start
echo "🎨 Starting frontend dashboard on port 3000..."
cd /app/frontend
npm start &
FRONTEND_PID=$!

# Function to handle shutdown
shutdown() {
    echo "🛑 Shutting down Decian platform..."
    kill $BACKEND_PID $FRONTEND_PID 2>/dev/null
    wait $BACKEND_PID $FRONTEND_PID 2>/dev/null
    echo "✅ Shutdown complete"
    exit 0
}

# Trap signals for graceful shutdown
trap 'shutdown' TERM INT

# Wait for processes
wait $BACKEND_PID $FRONTEND_PID