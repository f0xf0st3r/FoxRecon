-- FoxRecon PostgreSQL initialization
-- Creates extensions and initial configuration

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Enable pg_trgm for full-text search (future AI features)
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- Enable hstore for flexible metadata
CREATE EXTENSION IF NOT EXISTS "hstore";

-- Set default timezone
ALTER DATABASE foxrecon SET timezone TO 'UTC';

-- Create indexes for common query patterns
-- These are also defined in SQLAlchemy models but added here for clarity
-- The actual indexes will be created by Alembic migrations
