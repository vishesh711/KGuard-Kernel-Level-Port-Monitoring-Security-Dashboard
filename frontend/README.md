# KGuard Frontend Dashboard

React-based security monitoring dashboard that provides real-time visualization of network traffic, security alerts, and system analytics.

## Features

- Real-time network event monitoring
- Interactive charts and graphs
- Security alert notifications
- Traffic analytics and statistics
- Responsive design for desktop and mobile
- WebSocket integration for live updates

## Tech Stack

- **React 18** with TypeScript
- **Vite** for fast development and building
- **Tailwind CSS** for styling
- **Recharts** for data visualization
- **React Router** for navigation
- **React Query** for data fetching and caching
- **Socket.IO** for real-time WebSocket communication

## Setup

### Prerequisites

- Node.js 18+ and npm/yarn
- Backend API running on http://localhost:8000

### Installation

```bash
# Install dependencies
npm install

# Start development server
npm run dev

# Build for production
npm run build

# Preview production build
npm run preview
```

## Development

### Project Structure

```
frontend/
├── src/
│   ├── components/          # Reusable UI components
│   │   ├── ui/             # Base UI components
│   │   ├── charts/         # Chart components
│   │   └── layout/         # Layout components
│   ├── pages/              # Page components
│   │   ├── Dashboard.tsx   # Main dashboard
│   │   ├── Events.tsx      # Event listing
│   │   ├── Alerts.tsx      # Alert management
│   │   └── Analytics.tsx   # Traffic analytics
│   ├── hooks/              # Custom React hooks
│   ├── services/           # API services
│   ├── types/              # TypeScript type definitions
│   ├── utils/              # Utility functions
│   ├── App.tsx             # Main app component
│   └── main.tsx            # Entry point
├── public/                 # Static assets
├── package.json            # Dependencies and scripts
└── README.md              # This file
```

### Available Scripts

```bash
# Development
npm run dev          # Start development server
npm run build        # Build for production
npm run preview      # Preview production build

# Testing
npm run test         # Run tests
npm run test:watch   # Run tests in watch mode
npm run test:coverage # Run tests with coverage

# Linting
npm run lint         # Check code style
npm run lint:fix     # Fix code style issues
```

## Configuration

### Environment Variables

Create a `.env` file in the frontend directory:

```env
# API Configuration
VITE_API_BASE_URL=http://localhost:8000
VITE_WS_URL=ws://localhost:8000/ws

# App Configuration
VITE_APP_TITLE=KGuard Security Dashboard
VITE_REFRESH_INTERVAL=5000
```

### Tailwind Configuration

The project uses Tailwind CSS for styling. Configuration is in `tailwind.config.js`.

## Features

### Dashboard Pages

1. **Overview Dashboard**
   - Real-time metrics
   - Recent alerts
   - Traffic summary charts

2. **Live Events**
   - Real-time event table
   - Filtering and search
   - Event details modal

3. **Analytics**
   - Traffic patterns over time
   - Protocol distribution
   - Top source/destination IPs

4. **Alerts**
   - Security alert management
   - Alert acknowledgment
   - Severity filtering

### Real-time Updates

The dashboard connects to the backend WebSocket for real-time updates:

- Live event streaming
- Alert notifications
- Metric updates
- Connection status monitoring

## API Integration

### REST API

The frontend communicates with the backend REST API:

```typescript
// Example API calls
const events = await api.getEvents({ page: 1, limit: 50 });
const stats = await api.getStats();
const alerts = await api.getAlerts();
```

### WebSocket

Real-time data is received via WebSocket:

```typescript
// WebSocket connection
const socket = io(WS_URL);
socket.on('network_event', handleNewEvent);
socket.on('security_alert', handleNewAlert);
```

## Testing

### Unit Tests

```bash
# Run all tests
npm run test

# Run specific test file
npm run test -- EventTable.test.tsx

# Run tests with coverage
npm run test:coverage
```

### Test Structure

```
src/
├── components/
│   └── __tests__/          # Component tests
├── hooks/
│   └── __tests__/          # Hook tests
└── utils/
    └── __tests__/          # Utility tests
```

## Deployment

### Docker

```bash
# Build Docker image
docker build -t kguard-frontend .

# Run container
docker run -p 3000:80 kguard-frontend
```

### Production Build

```bash
# Build for production
npm run build

# Serve static files
# The build/ directory contains the production build
```

## Contributing

1. Follow the existing code style
2. Write tests for new features
3. Update documentation as needed
4. Use TypeScript for type safety
5. Follow React best practices