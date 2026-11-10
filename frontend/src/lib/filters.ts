import { FilterOptions } from '../types'

/** Form values are strings; the API wants numbers and booleans */
export interface EventFilterForm {
  src_ip: string
  dst_ip: string
  dst_port: string
  protocol: string
  direction: string
  process_name: string
  suspicious: string
  host_id: string
}

export const EMPTY_EVENT_FILTERS: EventFilterForm = {
  src_ip: '',
  dst_ip: '',
  dst_port: '',
  protocol: '',
  direction: '',
  process_name: '',
  suspicious: '',
  host_id: '',
}

export function toFilters(form: EventFilterForm): FilterOptions {
  const f: FilterOptions = {}
  if (form.src_ip.trim()) f.src_ip = form.src_ip.trim()
  if (form.dst_ip.trim()) f.dst_ip = form.dst_ip.trim()
  if (form.dst_port.trim()) f.dst_port = Number(form.dst_port)
  if (form.protocol) f.protocol = form.protocol
  if (form.direction) f.direction = form.direction as FilterOptions['direction']
  if (form.process_name.trim()) f.process_name = form.process_name.trim()
  if (form.suspicious) f.is_suspicious = form.suspicious === 'yes'
  if (form.host_id) f.host_id = Number(form.host_id)
  return f
}
