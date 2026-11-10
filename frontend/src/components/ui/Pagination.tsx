interface PaginationProps {
  page: number
  pages: number
  total: number
  onPage: (page: number) => void
}

export function Pagination({ page, pages, total, onPage }: PaginationProps) {
  return (
    <div className="flex items-center justify-between border-t px-4 py-3 text-sm text-gray-600">
      <span>
        {total.toLocaleString()} {total === 1 ? 'result' : 'results'}
      </span>
      <div className="flex items-center gap-2">
        <button
          type="button"
          className="btn-secondary btn-sm"
          disabled={page <= 1}
          onClick={() => onPage(page - 1)}
        >
          Previous
        </button>
        <span>
          Page {page} of {Math.max(pages, 1)}
        </span>
        <button
          type="button"
          className="btn-secondary btn-sm"
          disabled={page >= pages}
          onClick={() => onPage(page + 1)}
        >
          Next
        </button>
      </div>
    </div>
  )
}
