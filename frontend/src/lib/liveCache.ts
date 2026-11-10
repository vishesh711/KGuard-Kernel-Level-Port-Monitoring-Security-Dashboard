import { Query, QueryClient } from '@tanstack/react-query'
import { NetworkEvent, PaginatedResponse } from '../types'

/**
 * Lists that show the newest events unfiltered: the Events page's first
 * page with no filters (['events','list',1,{}]) and the dashboard's recent
 * events (['events','recent',n]). A live event goes straight into these.
 */
export function isNewestEventsList(key: readonly unknown[]): boolean {
  if (key[0] !== 'events') return false
  if (key[1] === 'recent') return true
  if (key[1] !== 'list' || key[2] !== 1) return false
  const filters = key[3] as Record<string, unknown> | undefined
  return !filters || Object.keys(filters).length === 0
}

/** Put a live event at the top of every newest-events list (U7.1) */
export function addLiveEvent(client: QueryClient, event: NetworkEvent): void {
  client.setQueriesData<PaginatedResponse<NetworkEvent>>(
    { predicate: (q: Query) => isNewestEventsList(q.queryKey) },
    (old) => {
      if (!old || old.items.some((e) => e.id === event.id)) return old
      const total = old.total + 1
      return {
        ...old,
        items: [event, ...old.items].slice(0, old.size),
        total,
        pages: Math.ceil(total / old.size),
      }
    },
  )
}

/** Everything about events except the lists kept current by addLiveEvent */
export function staleEventQueries(q: Query): boolean {
  return q.queryKey[0] === 'events' && !isNewestEventsList(q.queryKey)
}
