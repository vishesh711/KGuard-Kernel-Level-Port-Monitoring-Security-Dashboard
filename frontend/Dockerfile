# KGuard Frontend Dockerfile
FROM node:20-alpine AS base

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Development stage
FROM base AS development

# Install all dependencies (including dev dependencies)
RUN npm install

# Copy source code
COPY . .

# Expose port
EXPOSE 3000

# Start development server
CMD ["npm", "run", "dev", "--", "--host"]

# Build stage
FROM base AS build

# All dependencies: the build needs the dev tools (TypeScript, Vite)
RUN npm ci

# Copy source code
COPY . .

# Build the application. With no VITE_API_BASE_URL the dashboard calls /api and
# /ws on its own host, which nginx (nginx.conf) passes to the backend.
RUN npm run build

# Production stage
FROM nginx:1.27-alpine AS production

# Copy custom nginx config
COPY nginx.conf /etc/nginx/nginx.conf

# Copy built application from build stage
COPY --from=build /app/dist /usr/share/nginx/html

# Create nginx user and set permissions
RUN chown -R nginx:nginx /usr/share/nginx/html && \
    chmod -R 755 /usr/share/nginx/html

# Expose ports
EXPOSE 80

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget -q -O /dev/null http://localhost/ || exit 1

# Start nginx
CMD ["nginx", "-g", "daemon off;"]