# KGuard Backend API

FastAPI-based backend service that processes network events from the kernel module and provides REST API and WebSocket endpoints for the frontend dashboard.

## Features

- REST API for network events, statistics, and alerts
- Real-time WebSocket streaming
- SQLite database with SQLAlchemy ORM
- Anomaly detection and alert generation
- Rate limiting and security controls
- Comprehensive logging and monitoring

## Setup

### Development Environment

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set up environment variables
cp .env.example .env
# Edit .env with your configuration
```

### Database Setup

```bash
# Initialize database
alembic upgrade head

# Create new migration (after model changes)
alembic revision --autogenerate -m "Description"
```

## Running

### Development Server

```bash
# Start development server with auto-reload
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Or using the run script
python -m app.main
```

### Production Server

```bash
# Start production server
uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4
```

## API Documentation

Once running, visit:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## API Endpoints

### Events
- `GET /api/events` - List network events with pagination
- `GET /api/events/stats` - Traffic statistics
- `GET /api/events/{id}` - Get specific event

### Alerts
- `GET /api/alerts` - List security alerts
- `POST /api/alerts/{id}/acknowledge` - Acknowledge alert

### System
- `GET /api/health` - Health check
- `WebSocket /ws` - Real-time event stream

## Configuration

Environment variables (create `.env` file):

```env
# Database
DATABASE_URL=sqlite:///./kguard.db

# API Settings
API_HOST=0.0.0.0
API_PORT=8000
DEBUG=true

# Security
SECRET_KEY=your-secret-key-here
ACCESS_TOKEN_EXPIRE_MINUTES=30

# Logging
LOG_LEVEL=INFO

# Anomaly Detection
PORT_SCAN_THRESHOLD=10
ALERT_COOLDOWN_SECONDS=300
```

## Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=app

# Run specific test file
pytest tests/test_api.py

# Run with verbose output
pytest -v
```

## Development

### Project Structure

```
backend/
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI application
│   ├── config.py            # Configuration settings
│   ├── database.py          # Database connection
│   ├── models/              # SQLAlchemy models
│   ├── schemas/             # Pydantic schemas
│   ├── api/                 # API routes
│   ├── services/            # Business logic
│   └── utils/               # Utility functions
├── tests/                   # Test files
├── alembic/                 # Database migrations
├── requirements.txt         # Dependencies
└── README.md               # This file
```

### Adding New Features

1. Create/update models in `app/models/`
2. Create Pydantic schemas in `app/schemas/`
3. Implement business logic in `app/services/`
4. Add API routes in `app/api/`
5. Write tests in `tests/`
6. Create database migration if needed