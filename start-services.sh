#!/bin/bash

# Kill processes on ports 3000, 3001, and 5557
echo "Killing processes on ports 3000, 3001, and 5557..."

# Kill port 3000
PID_3000=$(netstat -ano | grep :3000 | awk '{print $5}' | head -n1)
if [ ! -z "$PID_3000" ]; then
    taskkill //F //PID $PID_3000 2>/dev/null || echo "Could not kill process on port 3000"
fi

# Kill port 3001
PID_3001=$(netstat -ano | grep :3001 | awk '{print $5}' | head -n1)
if [ ! -z "$PID_3001" ]; then
    taskkill //F //PID $PID_3001 2>/dev/null || echo "Could not kill process on port 3001"
fi

# Kill port 5557
PID_5557=$(netstat -ano | grep :5557 | awk '{print $5}' | head -n1)
if [ ! -z "$PID_5557" ]; then
    taskkill //F //PID $PID_5557 2>/dev/null || echo "Could not kill process on port 5557"
fi

echo "Starting services..."

# Start frontend on port 3000 in background
(cd frontend && PORT=3000 npm run dev) &
FRONTEND_PID=$!

# Start backend on port 3001 with jobs API enabled in background
(cd backend && JOBS_API_ENABLED=true npm run dev) &
BACKEND_PID=$!

# Start Prisma Studio on port 5557 in background
(cd backend && npx prisma studio --port 5557) &
PRISMA_PID=$!

# Wait a few seconds for services to start
sleep 5

echo "Checking service status..."

# Check frontend
curl -s http://localhost:3000 > /dev/null && echo "✅ Frontend running on port 3000" || echo "❌ Frontend not responding on port 3000"

# Check backend
curl -s http://localhost:3001/health > /dev/null && echo "✅ Backend running on port 3001" || echo "❌ Backend not responding on port 3001"

# Check Prisma Studio
curl -s http://localhost:5557 > /dev/null && echo "✅ Prisma Studio running on port 5557" || echo "❌ Prisma Studio not responding on port 5557"

echo "Services started. PIDs: Frontend=$FRONTEND_PID, Backend=$BACKEND_PID, Prisma=$PRISMA_PID"