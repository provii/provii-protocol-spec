interface Env {
  ASSETS: Fetcher;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    // `/` is now served by the static landing page in dist/index.html.
    // Cloudflare static assets auto-strip `.html`, so canonical protocol URL
    // is `/v0/protocol`. Redirect the legacy `.html` path for backward compat.
    if (url.pathname === "/v0/protocol.html") {
      return Response.redirect(`${url.origin}/v0/protocol`, 301);
    }

    const response = await env.ASSETS.fetch(request);

    const headers = new Headers(response.headers);
    headers.set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload");
    headers.set("X-Content-Type-Options", "nosniff");
    headers.set("Referrer-Policy", "no-referrer");
    // CSP: this is a zero-JS static spec site. The only `<script>` elements are
    // `<script type="application/ld+json">` blocks for schema.org structured data.
    // Browsers evaluate CSP on those too, so `script-src 'unsafe-inline'` is
    // required for Google's Rich Results crawler (real Chrome) to pick them up.
    // There is no runtime JavaScript, so the 'unsafe-inline' surface is bounded
    // by our own static HTML, which is built from source in CI.
    headers.set("Content-Security-Policy",
      "default-src 'none'; style-src 'unsafe-inline' 'self'; script-src 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");

    return new Response(response.body, { status: response.status, headers });
  },
};
