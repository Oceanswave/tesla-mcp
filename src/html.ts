// Minimal HTML helpers for the server's few browser pages (sign-in result,
// client approval). Every value interpolated into a page goes through escapeHtml.

export function escapeHtml(value: string): string {
  return value.replace(
    /[&<>"']/g,
    (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char] ?? char,
  );
}

/** A complete page. `title` is escaped; `body` must already be escaped HTML. */
export function htmlPage(title: string, body: string, status: number, headers: HeadersInit = {}): Response {
  const response = new Response(
    `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>${escapeHtml(title)}</title></head>
<body>${body}</body></html>
`,
    { status, headers },
  );
  response.headers.set("Content-Type", "text/html; charset=utf-8");
  return response;
}
