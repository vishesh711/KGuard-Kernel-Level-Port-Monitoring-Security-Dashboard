/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_API_BASE_URL: string
  readonly VITE_WS_URL: string
  readonly VITE_APP_TITLE: string
  readonly VITE_APP_VERSION: string
  readonly VITE_REFRESH_INTERVAL: string
  readonly VITE_WEBSOCKET_RECONNECT_INTERVAL: string
  readonly VITE_CHART_ANIMATION_DURATION: string
  readonly VITE_MAX_CHART_POINTS: string
  readonly VITE_DEFAULT_PAGE_SIZE: string
  readonly VITE_MAX_PAGE_SIZE: string
  readonly VITE_DEBUG: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}