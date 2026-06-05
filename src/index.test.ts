import { describe, it, expect, vi } from "vitest";
import worker from "./index";

/** Minimal ASSETS mock that returns a 200 with empty headers. */
function mockAssets(body = "OK", status = 200): { ASSETS: Fetcher } {
  return {
    ASSETS: {
      fetch: vi.fn().mockResolvedValue(new Response(body, { status })),
    } as unknown as Fetcher,
  };
}

describe("fetch handler", () => {
  it("redirects /v0/protocol.html to /v0/protocol with 301", async () => {
    const req = new Request("https://spec.provii.app/v0/protocol.html");
    const res = await worker.fetch(req, mockAssets());

    expect(res.status).toBe(301);
    expect(res.headers.get("Location")).toBe(
      "https://spec.provii.app/v0/protocol",
    );
  });

  it("sets security headers on proxied responses", async () => {
    const req = new Request("https://spec.provii.app/v0/protocol");
    const res = await worker.fetch(req, mockAssets("<html></html>"));

    expect(res.status).toBe(200);
    expect(res.headers.get("Strict-Transport-Security")).toBe(
      "max-age=63072000; includeSubDomains; preload",
    );
    expect(res.headers.get("X-Content-Type-Options")).toBe("nosniff");
    expect(res.headers.get("Referrer-Policy")).toBe("no-referrer");
    expect(res.headers.get("Content-Security-Policy")).toContain(
      "default-src 'none'",
    );
  });

  it("preserves upstream status codes", async () => {
    const req = new Request("https://spec.provii.app/missing");
    const res = await worker.fetch(req, mockAssets("Not Found", 404));

    expect(res.status).toBe(404);
  });

  it("passes the request through to ASSETS for non-redirect paths", async () => {
    const env = mockAssets("page content");
    const req = new Request("https://spec.provii.app/");
    await worker.fetch(req, env);

    expect(env.ASSETS.fetch).toHaveBeenCalledWith(req);
  });

  it("does not call ASSETS.fetch for the redirect path", async () => {
    const env = mockAssets();
    const req = new Request("https://spec.provii.app/v0/protocol.html");
    await worker.fetch(req, env);

    expect(env.ASSETS.fetch).not.toHaveBeenCalled();
  });
});
