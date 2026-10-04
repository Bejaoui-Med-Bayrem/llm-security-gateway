import { clearToken, getToken } from "./auth";

export const API_URL =
  process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

export class ApiError extends Error {
  status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export type DefenseMode = "on" | "off";

export type User = {
  id: string;
  email: string;
  full_name: string;
  role: string;
  is_active: boolean;
};

export type Application = {
  id: string;
  name: string;
  description: string | null;
  endpoint_url: string;
  model_name: string;
  application_type: string;
  is_active: boolean;
  created_by: string;
};

export type ApplicationInput = Omit<Application, "id" | "created_by">;

export type Campaign = {
  id: string;
  name: string;
  description: string | null;
  status: string;
  application_id: string;
  created_by: string;
};

export type CampaignInput = {
  name: string;
  description: string | null;
  status: string;
  application_id: string;
};

export type Evaluation = {
  id: string;
  campaign_id: string;
  total_attacks: number;
  successful_attacks: number;
  blocked_attacks: number;
  detected_attacks: number;
  false_positives: number;
  attack_success_rate: number;
  detection_rate: number;
  false_positive_rate: number;
  average_latency_ms: number;
  created_at: string;
};

export type Attack = {
  id: string;
  campaign_id: string;
  category: string;
  technique: string;
  payload: string;
  language: string;
  generation_method: string;
  severity: string;
};

export type AttackInput = Omit<Attack, "id">;

export type AttackExecution = {
  id: string;
  attack_id: string;
  request: string;
  response: string | null;
  conversation_id: string | null;
  gateway_action: string | null;
  attack_success: boolean;
  risk_score: number | null;
  latency_ms: number | null;
  executed_at: string;
};

export type GatewayDecision = {
  id: string;
  execution_id: string;
  action: string;
  risk_score: number;
  detector: string;
  reason: string | null;
  matched_rule: string | null;
  processing_time_ms: number | null;
  created_at: string;
};

export type ExecuteResult = {
  execution: AttackExecution;
  decision: GatewayDecision;
  response: { reply?: string } | null;
};

export type Comparison = {
  before: Evaluation;
  after: Evaluation;
  comparable: boolean;
  differences: Record<string, number>;
};

export type RetestResult = {
  campaign: Campaign;
  evaluation: Evaluation;
  skipped_attacks: number;
};

function describe(detail: unknown): string | null {
  if (typeof detail === "string") return detail;

  if (Array.isArray(detail)) {
    return detail
      .map((item) => {
        const where = Array.isArray(item?.loc)
          ? item.loc.filter((part: unknown) => part !== "body").join(".")
          : "";
        const message = String(item?.msg ?? "valeur invalide");
        return where ? `${where} : ${message}` : message;
      })
      .join(" ; ");
  }

  return null;
}

async function request<T>(
  path: string,
  init: RequestInit = {},
  authenticated = true,
): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set("Accept", "application/json");

  if (init.body) {
    headers.set("Content-Type", "application/json");
  }

  if (authenticated) {
    const token = getToken();

    if (!token) {
      throw new ApiError(401, "Non connecté.");
    }

    headers.set("Authorization", `Bearer ${token}`);
  }

  let response: Response;

  try {
    response = await fetch(`${API_URL}${path}`, { ...init, headers });
  } catch {
    throw new ApiError(
      0,
      `Impossible de joindre le Gateway (${API_URL}). Vérifie qu'il tourne et que CORS autorise cette origine.`,
    );
  }

  if (response.status === 401 && authenticated) {
    clearToken();
    throw new ApiError(401, "Session expirée.");
  }

  if (!response.ok) {
    let message = `Erreur ${response.status}`;

    try {
      const body = await response.json();
      message = describe(body.detail) ?? message;
    } catch {
      // the body is not JSON: keep the generic message
    }

    const retryAfter = response.headers.get("Retry-After");

    if (response.status === 429 && retryAfter) {
      message += ` (réessaie dans ${retryAfter} s)`;
    }

    throw new ApiError(response.status, message);
  }

  if (response.status === 204) {
    return undefined as T;
  }

  return (await response.json()) as T;
}

const send = <T>(method: string, path: string, body?: unknown) =>
  request<T>(path, {
    method,
    body: body === undefined ? undefined : JSON.stringify(body),
  });

export async function login(email: string, password: string): Promise<string> {
  const data = await request<{ access_token: string }>(
    "/api/auth/login",
    { method: "POST", body: JSON.stringify({ email, password }) },
    false,
  );

  return data.access_token;
}

export const register = (email: string, fullName: string, password: string) =>
  request<User>(
    "/api/auth/register",
    {
      method: "POST",
      body: JSON.stringify({ email, full_name: fullName, password }),
    },
    false,
  );

export const listApplications = () => request<Application[]>("/api/applications/");
export const createApplication = (input: ApplicationInput) =>
  send<Application>("POST", "/api/applications/", input);
export const updateApplication = (id: string, input: Partial<ApplicationInput>) =>
  send<Application>("PUT", `/api/applications/${id}`, input);
export const deleteApplication = (id: string) =>
  send<void>("DELETE", `/api/applications/${id}`);

export const listCampaigns = () => request<Campaign[]>("/api/campaigns/");
export const getCampaign = (id: string) => request<Campaign>(`/api/campaigns/${id}`);
export const createCampaign = (input: CampaignInput) =>
  send<Campaign>("POST", "/api/campaigns/", input);
export const deleteCampaign = (id: string) =>
  send<void>("DELETE", `/api/campaigns/${id}`);
export const cloneCampaign = (id: string) =>
  send<Campaign>("POST", `/api/campaigns/${id}/clone`);
export const retestCampaign = (id: string, defenseMode: DefenseMode) =>
  send<RetestResult>("POST", `/api/campaigns/${id}/retest?defense_mode=${defenseMode}`);

export const listEvaluations = () => request<Evaluation[]>("/api/evaluations/");
export const computeEvaluation = (campaignId: string) =>
  send<Evaluation>("POST", `/api/evaluations/campaign/${campaignId}`);
export const compareEvaluations = (before: string, after: string) =>
  request<Comparison>(`/api/evaluations/compare?before=${before}&after=${after}`);

export async function getEvaluationOrNull(
  campaignId: string,
): Promise<Evaluation | null> {
  try {
    return await request<Evaluation>(`/api/evaluations/campaign/${campaignId}`);
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) return null;
    throw error;
  }
}

export const listAttacks = (campaignId: string) =>
  request<Attack[]>(`/api/attacks/campaign/${campaignId}`);
export const createAttack = (input: AttackInput) =>
  send<Attack>("POST", "/api/attacks/", input);
export const deleteAttack = (id: string) =>
  send<void>("DELETE", `/api/attacks/${id}`);

export const listExecutions = () =>
  request<AttackExecution[]>("/api/attack-executions/");
export const listExecutionsByAttack = (attackId: string) =>
  request<AttackExecution[]>(`/api/attack-executions/attack/${attackId}`);
export const listDecisions = () =>
  request<GatewayDecision[]>("/api/gateway-decisions/");

export const executeAttack = (
  attackId: string,
  defenseMode: DefenseMode,
  conversationId?: string,
) =>
  send<ExecuteResult>("POST", "/api/ai-goat/execute", {
    attack_id: attackId,
    defense_mode: defenseMode,
    conversation_id: conversationId ?? null,
  });