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

### Pages

All pages need a login (see the backend's *Login and security*). Viewers
see everything but no controls that change things; admins also get
acknowledge, resolve, block, unblock, allowlist and "mark expected".

| Page | What it shows |
|---|---|
| Dashboard | Totals, traffic chart, protocol mix, recent events and alerts (with country, threat lists and MITRE tags) |
| Live Events | Every event, filterable by address, port, protocol, direction, process, host and suspicious flag, paginated; new events appear at once |
| Security Alerts | Open / acknowledged / resolved alerts by severity and type |
| Alert detail (`/alerts/:id`) | Summary with country, threat lists and MITRE technique; a panel for the alert type (scan type and ports, OS / tool fingerprint, SYN cookies, spoofing reason, amplification factor, DNS tunnel domain, TLS JA3/JA4, ...); related events; pcap download |
| Analytics | Alerts and events over time, top sources, ports, alert types, for 1 h / 24 h / 7 days |
| Hosts | One row per agent: status, engine, version, events per second, drops, blocklist state; the kernel module's own counters on this server (buffer fill, drops, ns per packet, guard counters) |
| Processes | Listening ports and connections with process, PID and user, for this server or any agent; listeners that appeared after the host's first snapshot are highlighted until marked expected |
| Blocked | Active blocks and history (reason, manual or automatic with its alert, host, time left), block / unblock, allowlist, audit log, each agent's enforcement state |
| Settings | The configuration in force: detection thresholds, automatic blocking, notification channels, enrichment and retention |

### Live updates

One WebSocket (`/ws?token=...`) for the whole app. A new event is put
straight into the lists of newest events (the Events page's first page
without filters, and the dashboard), with no request; filtered lists and
statistics refresh at most every 2 seconds. New alerts refresh alert data
immediately. Measured in Chromium against a real backend: 26-72 ms from an
agent sending an event to the row on screen.

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