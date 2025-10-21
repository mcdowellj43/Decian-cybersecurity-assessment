#!/bin/sh
# Wait for database directory to be ready and create SQLite database if needed

set -e

echo "⏳ Checking database setup..."

# Ensure database directory exists
if [ ! -d "/app/data/database" ]; then
    echo "📁 Creating database directory..."
    mkdir -p /app/data/database
fi

# Check if database file exists, if not it will be created by Prisma
DB_FILE="/app/data/database/decian.db"
if [ ! -f "$DB_FILE" ]; then
    echo "🔧 Database file will be created by Prisma migrations..."
else
    echo "✅ Database file exists at $DB_FILE"
fi

echo "✅ Database setup complete"