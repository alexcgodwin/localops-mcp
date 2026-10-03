export type IntelligenceHealth = {
  configured: boolean;
  reachable: boolean;
  url: string;
  version: string | null;
  limitation: string | null;
};

type FetchLike = typeof fetch;

function intelligenceUrl(): URL {
  const raw = String(
    process.env.LOCALOPS_INTELLIGENCE_URL ??
      "http://127.0.0.1:43123"
  );
  const url = new URL(raw);

  if (url.protocol !== "http:") {
    throw new Error(
      "LOCALOPS_INTELLIGENCE_URL must use http on a loopback address."
    );
  }

  const hostname = url.hostname.toLowerCase();
  if (!["127.0.0.1", "::1", "[::1]"].includes(hostname)) {
    throw new Error(
      "LOCALOPS_INTELLIGENCE_URL must use a literal loopback IP address."
    );
  }

  if (url.username || url.password) {
    throw new Error(
      "LOCALOPS_INTELLIGENCE_URL must not contain credentials."
    );
  }

  url.pathname = url.pathname.replace(/\/$/, "");
  return url;
}

function intelligenceToken(): string {
  const token = String(process.env.LOCALOPS_INTELLIGENCE_TOKEN ?? "");
  if (token.length < 32) {
    throw new Error(
      "LOCALOPS_INTELLIGENCE_TOKEN must be configured with at least 32 characters."
    );
  }
  return token;
}

async function fetchWithTimeout(
  url: string,
  options: RequestInit,
  timeoutMs: number,
  fetchImpl: FetchLike
) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetchImpl(url, {
      ...options,
      signal: controller.signal
    });
  } finally {
    clearTimeout(timer);
  }
}

export async function intelligenceStatus(
  fetchImpl: FetchLike = fetch
): Promise<IntelligenceHealth> {
  let url: URL;
  try {
    url = intelligenceUrl();
  } catch (error) {
    return {
      configured: false,
      reachable: false,
      url: "invalid",
      version: null,
      limitation:
        error instanceof Error ? error.message : "Invalid intelligence URL."
    };
  }

  let token: string;
  try {
    token = intelligenceToken();
  } catch (error) {
    return {
      configured: false,
      reachable: false,
      url: url.origin,
      version: null,
      limitation:
        error instanceof Error
          ? error.message
          : "Intelligence token is not configured."
    };
  }

  try {
    const response = await fetchWithTimeout(
      url.origin + "/health",
      {
        method: "GET",
        headers: {
          authorization: "Bearer " + token,
          accept: "application/json"
        }
      },
      3000,
      fetchImpl
    );

    if (!response.ok) {
      return {
        configured: true,
        reachable: false,
        url: url.origin,
        version: null,
        limitation:
          "Private intelligence core returned HTTP " + response.status + "."
      };
    }

    const body = (await response.json()) as {
      version?: string;
      status?: string;
    };

    return {
      configured: true,
      reachable: body.status === "ok",
      url: url.origin,
      version: body.version ?? null,
      limitation:
        body.status === "ok"
          ? null
          : "Private intelligence core health response was not healthy."
    };
  } catch {
    return {
      configured: true,
      reachable: false,
      url: url.origin,
      version: null,
      limitation:
        "Private intelligence core is not reachable on the configured loopback endpoint."
    };
  }
}

export async function callPrivateIntelligence(
  path: string,
  evidenceBundle: Record<string, unknown>,
  fetchImpl: FetchLike = fetch
): Promise<Record<string, unknown>> {
  const url = intelligenceUrl();
  const token = intelligenceToken();

  if (!/^\/v1\/(correlate\/(process|service|identity|network|persistence)|timeline|root-cause\/(rank|confidence|evidence-chain|investigation|change-trigger|blast-radius|remediation)|fleet\/(compare|configuration-drift|software-drift|patch-drift|certificate-drift|security-drift)|infrastructure\/(device-health|topology)|database\/(health|replication|contention|pressure)|backup\/(snapshot-health|recovery-readiness|risk-correlation)|topology\/(dependency-path|path-redundancy|failure-domains|change-impact)|remediation\/workflow-plan|predictive\/health)$/.test(path)) {
    throw new Error("Unsupported private intelligence route.");
  }

  let response: Response;
  try {
    response = await fetchWithTimeout(
      url.origin + path,
      {
        method: "POST",
        headers: {
          authorization: "Bearer " + token,
          "content-type": "application/json",
          accept: "application/json"
        },
        body: JSON.stringify(evidenceBundle)
      },
      10000,
      fetchImpl
    );
  } catch {
    throw new Error(
      "Private intelligence core is not reachable on the configured loopback endpoint."
    );
  }

  if (!response.ok) {
    throw new Error(
      "Private intelligence core returned HTTP " + response.status + "."
    );
  }

  return (await response.json()) as Record<string, unknown>;
}
