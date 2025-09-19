import { useState, useEffect, useRef, useCallback } from 'react'
import { ConnectionStatus, WebSocketMessage } from '../types'
import toast from 'react-hot-toast'

const WS_URL = import.meta.env.VITE_WS_URL || 'ws://localhost:8000/ws'
const RECONNECT_INTERVAL = 3000
const MAX_RECONNECT_ATTEMPTS = 5

export function useWebSocket() {
    const [connectionStatus, setConnectionStatus] = useState<ConnectionStatus>({
        connected: false,
        reconnecting: false,
    })

    const [lastMessage, setLastMessage] = useState<WebSocketMessage | null>(null)
    const [messageHistory, setMessageHistory] = useState<WebSocketMessage[]>([])

    const ws = useRef<WebSocket | null>(null)
    const reconnectAttempts = useRef(0)
    const reconnectTimeout = useRef<NodeJS.Timeout | null>(null)
    const pingInterval = useRef<NodeJS.Timeout | null>(null)

    const handleMessage = useCallback((message: WebSocketMessage) => {
        switch (message.type) {
            case 'network_event':
                // Handle new network event
                break

            case 'security_alert':
                // Show toast notification for new alerts
                const alertData = message.data
                if (alertData.severity === 'CRITICAL' || alertData.severity === 'HIGH') {
                    toast.error(`Security Alert: ${alertData.title}`, {
                        duration: 6000,
                    })
                } else {
                    toast(`Security Alert: ${alertData.title}`, {
                        icon: '⚠️',
                        duration: 4000,
                    })
                }
                break

            case 'system_metric':
                // Handle system metric updates
                break

            case 'stats_update':
                // Handle statistics updates
                break

            case 'heartbeat':
                // Handle heartbeat messages
                break

            case 'pong':
                // Handle pong responses
                break

            default:
                console.log('Unknown message type:', message.type)
        }
    }, [])

    const attemptReconnect = useCallback(() => {
        if (reconnectAttempts.current >= MAX_RECONNECT_ATTEMPTS) {
            return
        }

        reconnectAttempts.current++
        setConnectionStatus(prev => ({
            ...prev,
            reconnecting: true,
            error: `Reconnecting... (${reconnectAttempts.current}/${MAX_RECONNECT_ATTEMPTS})`,
        }))

        reconnectTimeout.current = setTimeout(() => {
            connect()
        }, RECONNECT_INTERVAL)
    }, [])

    const connect = useCallback(() => {
        try {
            ws.current = new WebSocket(WS_URL)

            ws.current.onopen = () => {
                console.log('WebSocket connected')
                setConnectionStatus({
                    connected: true,
                    reconnecting: false,
                    lastConnected: new Date(),
                })
                reconnectAttempts.current = 0

                // Start ping interval
                pingInterval.current = setInterval(() => {
                    if (ws.current?.readyState === WebSocket.OPEN) {
                        ws.current.send(JSON.stringify({
                            type: 'ping',
                            timestamp: new Date().toISOString(),
                        }))
                    }
                }, 30000) // Ping every 30 seconds
            }

            ws.current.onmessage = (event) => {
                try {
                    const message: WebSocketMessage = JSON.parse(event.data)
                    setLastMessage(message)

                    // Add to message history (keep last 100 messages)
                    setMessageHistory(prev => {
                        const newHistory = [...prev, message].slice(-100)
                        return newHistory
                    })

                    // Handle different message types
                    handleMessage(message)
                } catch (error) {
                    console.error('Error parsing WebSocket message:', error)
                }
            }

            ws.current.onclose = (event) => {
                console.log('WebSocket disconnected:', event.code, event.reason)
                setConnectionStatus(prev => ({
                    ...prev,
                    connected: false,
                }))

                // Clear ping interval
                if (pingInterval.current) {
                    clearInterval(pingInterval.current)
                    pingInterval.current = null
                }

                // Attempt to reconnect if not a manual close
                if (event.code !== 1000 && reconnectAttempts.current < MAX_RECONNECT_ATTEMPTS) {
                    attemptReconnect()
                } else if (reconnectAttempts.current >= MAX_RECONNECT_ATTEMPTS) {
                    setConnectionStatus(prev => ({
                        ...prev,
                        error: 'Max reconnection attempts reached',
                        reconnecting: false,
                    }))
                    toast.error('Connection lost. Please refresh the page.')
                }
            }

            ws.current.onerror = (error) => {
                console.error('WebSocket error:', error)
                setConnectionStatus(prev => ({
                    ...prev,
                    error: 'Connection error',
                }))
            }
        } catch (error) {
            console.error('Error creating WebSocket connection:', error)
            setConnectionStatus(prev => ({
                ...prev,
                error: 'Failed to create connection',
            }))
        }
    }, [handleMessage, attemptReconnect])

    const sendMessage = useCallback((message: any) => {
        if (ws.current?.readyState === WebSocket.OPEN) {
            ws.current.send(JSON.stringify(message))
            return true
        }
        return false
    }, [])

    const disconnect = useCallback(() => {
        if (reconnectTimeout.current) {
            clearTimeout(reconnectTimeout.current)
            reconnectTimeout.current = null
        }

        if (pingInterval.current) {
            clearInterval(pingInterval.current)
            pingInterval.current = null
        }

        if (ws.current) {
            ws.current.close(1000, 'Manual disconnect')
            ws.current = null
        }

        setConnectionStatus({
            connected: false,
            reconnecting: false,
        })
    }, [])

    // Connect on mount
    useEffect(() => {
        connect()

        // Cleanup on unmount
        return () => {
            disconnect()
        }
    }, [connect, disconnect])

    return {
        connectionStatus,
        lastMessage,
        messageHistory,
        sendMessage,
        disconnect,
        reconnect: connect,
    }
}