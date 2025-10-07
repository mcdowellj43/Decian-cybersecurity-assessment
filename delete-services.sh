#!/bin/bash

echo "Killing processes on ports 3000, 3001, and 5557..."

# Kill port 3000
PID_3000=$(netstat -ano | grep :3000 | awk '{print $5}' | head -n1)
if [ ! -z "$PID_3000" ]; then
    taskkill //F //PID $PID_3000 2>/dev/null || echo "Could not kill process on port 3000"
else
    echo "No process found on port 3000"
fi

# Kill port 3001
PID_3001=$(netstat -ano | grep :3001 | awk '{print $5}' | head -n1)
if [ ! -z "$PID_3001" ]; then
    taskkill //F //PID $PID_3001 2>/dev/null || echo "Could not kill process on port 3001"
else
    echo "No process found on port 3001"
fi

# Kill port 5557
PID_5557=$(netstat -ano | grep :5557 | awk '{print $5}' | head -n1)
if [ ! -z "$PID_5557" ]; then
    taskkill //F //PID $PID_5557 2>/dev/null || echo "Could not kill process on port 5557"
else
    echo "No process found on port 5557"
fi

echo "Process cleanup complete."