"use client";

import { FormEvent, useCallback, useEffect, useMemo, useState } from "react";
import { createBrowserClient } from "@supabase/ssr";

const API = process.env.NEXT_PUBLIC_SAFESCOPE_API ?? "http://localhost:8000";
const SUPABASE_URL = process.env.NEXT_PUBLIC_SUPABASE_URL;
const SUPABASE_PUBLISHABLE_KEY = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY;
const supabase = SUPABASE_URL && SUPABASE_PUBLISHABLE_KEY
  ? createBrowserClient(SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY)
  : null;
let accessToken: string | null = null;

type Organization = { id: string; name: string };
type Project = { id: string; organization_id: string; name: string };
type Target = {
  id: string;
  project_id: string;
  base_url: string;
  mode: string;
  verified: boolean;
};
type Scope = {
  id: string;
  target_id: string;
  origin: string;
  is_excluded: boolean;
  path_pattern: string | null;
};
type Authorization = {
  id: string;
  target_id: string;
  representative_name: string;
  valid_from: string;
  valid_until: string;
  active_testing: boolean;
};
type Job = { id: string; target_id: string; status: string; mode: string; created_at: string };
type Finding = {
  id: string;
  target_id: string;
  title: string;
  severity: string;
  confidence: number;
  status: string;
  description: string;
  remediation: string | null;
};
type Evidence = {
  id: string;
  source: string;
  url: string;
  sanitized_data: Record<string, unknown>;
  observed_at: string;
};
type Summary = {
  score: number;
  deductions: number;
  open_findings: number;
  total_findings: number;
  targets: number;
  pending_jobs: number;
  running_jobs: number;
  completed_jobs: number;
};
type Created = { id: string };
type FindingStatus = "OPEN" | "ACKNOWLEDGED" | "FIXED" | "ACCEPTED_RISK";

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API}${path}`, {
    ...init,
    headers: {
      ...(init?.body ? { "content-type": "application/json" } : {}),
      ...(accessToken ? { authorization: `Bearer ${accessToken}` } : {}),
      ...init?.headers,
    },
  });
  if (!response.ok) {
    const detail = await response.json().catch(() => null) as { detail?: string } | null;
    throw new Error(detail?.detail ?? `API respondeu com status ${response.status}`);
  }
  return response.json() as Promise<T>;
}

function severityClass(severity: string): string {
  return `severity severity-${severity.toLowerCase()}`;
}

function hostname(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
}

export function Dashboard() {
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [projects, setProjects] = useState<Project[]>([]);
  const [targets, setTargets] = useState<Target[]>([]);
  const [scopes, setScopes] = useState<Scope[]>([]);
  const [authorizations, setAuthorizations] = useState<Authorization[]>([]);
  const [jobs, setJobs] = useState<Job[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [summary, setSummary] = useState<Summary | null>(null);
  const [zapAvailable, setZapAvailable] = useState(false);
  const [organizationId, setOrganizationId] = useState("");
  const [projectId, setProjectId] = useState("");
  const [targetId, setTargetId] = useState("");
  const [organizationName, setOrganizationName] = useState("");
  const [projectName, setProjectName] = useState("");
  const [targetUrl, setTargetUrl] = useState("");
  const [scopeOrigin, setScopeOrigin] = useState("");
  const [scopePath, setScopePath] = useState("");
  const [scopeExcluded, setScopeExcluded] = useState(false);
  const [representativeName, setRepresentativeName] = useState("");
  const [representativeEmail, setRepresentativeEmail] = useState("");
  const [validFrom, setValidFrom] = useState("");
  const [validUntil, setValidUntil] = useState("");
  const [includeZapBaseline, setIncludeZapBaseline] = useState(false);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [evidence, setEvidence] = useState<Evidence[]>([]);
  const [message, setMessage] = useState("Painel pronto para uma avaliação passiva.");
  const [busy, setBusy] = useState(false);
  const [apiOnline, setApiOnline] = useState(true);
  const [authEmail, setAuthEmail] = useState("");
  const [authPassword, setAuthPassword] = useState("");
  const [signedInEmail, setSignedInEmail] = useState<string | null>(null);

  const loadAll = useCallback(async (quiet = false) => {
    try {
      const [organizationItems, projectItems, targetItems, scopeItems, authorizationItems, jobItems, findingItems, currentSummary, zap] =
        await Promise.all([
          api<Organization[]>("/organizations"),
          api<Project[]>("/projects"),
          api<Target[]>("/targets"),
          api<Scope[]>("/scopes"),
          api<Authorization[]>("/authorizations"),
          api<Job[]>("/scan-jobs"),
          api<Finding[]>("/findings"),
          api<Summary>("/summary"),
          api<{ available: boolean }>("/integrations/zap"),
        ]);
      setOrganizations(organizationItems);
      setProjects(projectItems);
      setTargets(targetItems);
      setScopes(scopeItems);
      setAuthorizations(authorizationItems);
      setJobs(jobItems);
      setFindings(findingItems);
      setSummary(currentSummary);
      setZapAvailable(zap.available);
      setApiOnline(true);
      setOrganizationId((current) => current || organizationItems[0]?.id || "");
      setProjectId((current) => current || projectItems[0]?.id || "");
      setTargetId((current) => current || targetItems[0]?.id || "");
      if (!quiet) setMessage("Dados atualizados.");
    } catch (error) {
      setApiOnline(false);
      setMessage(error instanceof Error ? error.message : "Não foi possível consultar a API.");
    }
  }, []);

  useEffect(() => {
    void loadAll(true);
    const timer = window.setInterval(() => void loadAll(true), 4000);
    return () => window.clearInterval(timer);
  }, [loadAll]);

  useEffect(() => {
    if (!supabase) return;
    void supabase.auth.getSession().then(({ data }) => {
      accessToken = data.session?.access_token ?? null;
      setSignedInEmail(data.session?.user.email ?? null);
      if (data.session) void loadAll(true);
    });
    const { data } = supabase.auth.onAuthStateChange((_event, session) => {
      accessToken = session?.access_token ?? null;
      setSignedInEmail(session?.user.email ?? null);
      if (session) void loadAll(true);
    });
    return () => data.subscription.unsubscribe();
  }, [loadAll]);

  const selectedTarget = useMemo(
    () => targets.find((target) => target.id === targetId) ?? null,
    [targetId, targets],
  );
  const targetScopes = scopes.filter((scope) => scope.target_id === targetId);
  const targetAuthorizations = authorizations.filter((item) => item.target_id === targetId);
  const targetJobs = jobs.filter((job) => job.target_id === targetId);
  const targetFindings = findings.filter((finding) => !targetId || finding.target_id === targetId);

  useEffect(() => {
    if (selectedTarget && !scopeOrigin) setScopeOrigin(selectedTarget.base_url);
  }, [scopeOrigin, selectedTarget]);

  async function perform(action: () => Promise<void>, success: string) {
    setBusy(true);
    try {
      await action();
      setMessage(success);
      await loadAll(true);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "A operação falhou.");
    } finally {
      setBusy(false);
    }
  }

  async function createOrganization(event: FormEvent) {
    event.preventDefault();
    await perform(async () => {
      const item = await api<Created>("/organizations", {
        method: "POST",
        body: JSON.stringify({ name: organizationName }),
      });
      setOrganizationId(item.id);
      setOrganizationName("");
    }, "Organização criada.");
  }

  async function createProject(event: FormEvent) {
    event.preventDefault();
    await perform(async () => {
      const item = await api<Created>("/projects", {
        method: "POST",
        body: JSON.stringify({ organization_id: organizationId, name: projectName }),
      });
      setProjectId(item.id);
      setProjectName("");
    }, "Projeto criado.");
  }

  async function createTarget(event: FormEvent) {
    event.preventDefault();
    await perform(async () => {
      const item = await api<Created>("/targets", {
        method: "POST",
        body: JSON.stringify({ project_id: projectId, base_url: targetUrl }),
      });
      setTargetId(item.id);
      setTargetUrl("");
    }, "Target cadastrado em modo PASSIVE.");
  }

  async function createScope(event: FormEvent) {
    event.preventDefault();
    await perform(async () => {
      await api<Created>("/scopes", {
        method: "POST",
        body: JSON.stringify({
          target_id: targetId,
          origin: scopeOrigin,
          path_pattern: scopePath || null,
          is_excluded: scopeExcluded,
        }),
      });
      setScopePath("");
    }, "Regra de escopo salva.");
  }

  async function createAuthorization(event: FormEvent) {
    event.preventDefault();
    await perform(async () => {
      await api<Created>("/authorizations", {
        method: "POST",
        body: JSON.stringify({
          target_id: targetId,
          representative_name: representativeName,
          representative_email: representativeEmail,
          valid_from: new Date(validFrom).toISOString(),
          valid_until: new Date(validUntil).toISOString(),
        }),
      });
      setRepresentativeName("");
      setRepresentativeEmail("");
    }, "Autorização registrada. Testes ativos continuam bloqueados nesta fase.");
  }

  async function enqueue() {
    await perform(async () => {
      await api<Created>("/scan-jobs", {
        method: "POST",
        body: JSON.stringify({ target_id: targetId, include_zap_baseline: includeZapBaseline }),
      });
    }, includeZapBaseline ? "Scan passivo com ZAP Baseline entrou na fila." : "Scan passivo entrou na fila. O worker irá processá-lo.");
  }

  async function signIn(event: FormEvent) {
    event.preventDefault();
    if (!supabase) return;
    setBusy(true);
    try {
      const { error } = await supabase.auth.signInWithPassword({ email: authEmail, password: authPassword });
      if (error) throw error;
      setAuthPassword("");
      setMessage("Sessão autenticada. Carregando sua organização.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Não foi possível iniciar a sessão.");
    } finally {
      setBusy(false);
    }
  }

  async function signOut() {
    if (!supabase) return;
    await supabase.auth.signOut();
    accessToken = null;
    setSignedInEmail(null);
    setMessage("Sessão encerrada.");
  }

  async function downloadReport(kind: "executive" | "technical" | "proposal" | "roe") {
    if (!targetId) return;
    const suffix = kind === "executive" || kind === "technical" ? `${kind}.pdf` : `${kind}.md`;
    await perform(async () => {
      const response = await fetch(`${API}/reports/targets/${targetId}/${suffix}`, {
        headers: accessToken ? { authorization: `Bearer ${accessToken}` } : undefined,
      });
      if (!response.ok) throw new Error(`API respondeu com status ${response.status}`);
      const blob = await response.blob();
      const href = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = href;
      anchor.download = `safescope-${suffix}`;
      anchor.click();
      URL.revokeObjectURL(href);
    }, "Relatório baixado.");
  }

  async function openFinding(finding: Finding) {
    setSelectedFinding(finding);
    setEvidence([]);
    try {
      setEvidence(await api<Evidence[]>(`/findings/${finding.id}/evidence`));
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Falha ao carregar evidências.");
    }
  }

  async function changeFindingStatus(status: FindingStatus) {
    if (!selectedFinding) return;
    await perform(async () => {
      const updated = await api<Finding>(`/findings/${selectedFinding.id}`, {
        method: "PATCH",
        body: JSON.stringify({ status }),
      });
      setSelectedFinding(updated);
    }, "Status do finding atualizado.");
  }

  return (
    <main>
      <header className="hero">
        <div>
          <p className="eyebrow">SAFE SCOPE</p>
          <h1>Auditoria defensiva, com escopo.</h1>
          <p className="subtitle">{message}</p>
        </div>
        <span className={apiOnline ? "connection online" : "connection offline"}>
          {apiOnline ? "API online" : "API offline"}
        </span>
      </header>

      {supabase && (
        <section className="auth-panel" aria-label="Autenticação">
          {signedInEmail ? (
            <p>Sessão Supabase: <strong>{signedInEmail}</strong> <button className="secondary" onClick={() => void signOut()}>Sair</button></p>
          ) : (
            <form onSubmit={signIn} className="auth-form">
              <label>E-mail<input type="email" value={authEmail} onChange={(event) => setAuthEmail(event.target.value)} required /></label>
              <label>Senha<input type="password" value={authPassword} onChange={(event) => setAuthPassword(event.target.value)} required /></label>
              <button disabled={busy}>Entrar</button>
            </form>
          )}
        </section>
      )}

      <section className="metrics" aria-label="Resumo">
        <article><span>Security Score</span><strong>{summary?.score ?? "—"}</strong><small>-{summary?.deductions ?? 0} pontos</small></article>
        <article><span>Findings abertos</span><strong>{summary?.open_findings ?? 0}</strong><small>{summary?.total_findings ?? 0} no total</small></article>
        <article><span>Targets</span><strong>{summary?.targets ?? 0}</strong><small>modo passivo</small></article>
        <article><span>Fila</span><strong>{(summary?.pending_jobs ?? 0) + (summary?.running_jobs ?? 0)}</strong><small>{summary?.completed_jobs ?? 0} concluídos</small></article>
      </section>

      <section>
        <div className="section-heading">
          <div><p className="step">CONFIGURAÇÃO</p><h2>Organização, projeto e target</h2></div>
          <button className="secondary" disabled={busy} onClick={() => void loadAll()}>Atualizar tudo</button>
        </div>
        <div className="form-grid">
          <form onSubmit={createOrganization}>
            <label>Nova organização<input value={organizationName} onChange={(event) => setOrganizationName(event.target.value)} required /></label>
            <button disabled={busy}>Criar</button>
          </form>
          <form onSubmit={createProject}>
            <label>Organização
              <select value={organizationId} onChange={(event) => setOrganizationId(event.target.value)} required>
                <option value="">Selecione</option>
                {organizations.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}
              </select>
            </label>
            <label>Novo projeto<input value={projectName} onChange={(event) => setProjectName(event.target.value)} required /></label>
            <button disabled={busy || !organizationId}>Criar</button>
          </form>
          <form onSubmit={createTarget}>
            <label>Projeto
              <select value={projectId} onChange={(event) => setProjectId(event.target.value)} required>
                <option value="">Selecione</option>
                {projects.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}
              </select>
            </label>
            <label>URL pública<input type="url" value={targetUrl} onChange={(event) => setTargetUrl(event.target.value)} placeholder="https://empresa.com.br" required /></label>
            <button disabled={busy || !projectId}>Adicionar</button>
          </form>
        </div>
      </section>

      <section>
        <div className="section-heading">
          <div><p className="step">OPERAÇÃO</p><h2>Escopo e autorização</h2></div>
          <label className="target-picker">Target
            <select value={targetId} onChange={(event) => { setTargetId(event.target.value); setScopeOrigin(""); }}>
              <option value="">Selecione</option>
              {targets.map((item) => <option key={item.id} value={item.id}>{item.base_url}</option>)}
            </select>
          </label>
        </div>
        {!selectedTarget ? <p className="empty">Cadastre ou selecione um target.</p> : (
          <div className="two-columns">
            <div>
              <h3>Regras de escopo</h3>
              <form className="stacked" onSubmit={createScope}>
                <label>Origem permitida<input type="url" value={scopeOrigin} onChange={(event) => setScopeOrigin(event.target.value)} required /></label>
                <label>Padrão de caminho (opcional)<input value={scopePath} onChange={(event) => setScopePath(event.target.value)} placeholder="/area-publica/*" /></label>
                <label className="check"><input type="checkbox" checked={scopeExcluded} onChange={(event) => setScopeExcluded(event.target.checked)} />Esta é uma exclusão</label>
                <button disabled={busy}>Salvar escopo</button>
              </form>
              <ul className="compact-list">
                {targetScopes.map((item) => <li key={item.id}><strong>{item.is_excluded ? "EXCLUIR" : "PERMITIR"}</strong> {item.origin}{item.path_pattern ?? ""}</li>)}
              </ul>
            </div>
            <div>
              <h3>Termo de autorização</h3>
              <form className="stacked" onSubmit={createAuthorization}>
                <label>Responsável<input value={representativeName} onChange={(event) => setRepresentativeName(event.target.value)} required /></label>
                <label>E-mail<input type="email" value={representativeEmail} onChange={(event) => setRepresentativeEmail(event.target.value)} required /></label>
                <div className="date-grid">
                  <label>Início<input type="datetime-local" value={validFrom} onChange={(event) => setValidFrom(event.target.value)} required /></label>
                  <label>Fim<input type="datetime-local" value={validUntil} onChange={(event) => setValidUntil(event.target.value)} required /></label>
                </div>
                <button disabled={busy}>Registrar autorização</button>
              </form>
              <p className="hint">{targetAuthorizations.length} autorização(ões). Ativo e mutações: bloqueados.</p>
            </div>
          </div>
        )}
      </section>

      <section>
        <div className="section-heading">
          <div><p className="step">SCANS</p><h2>Fila do worker</h2></div>
          <div className="scan-actions">
            <label className="check zap-check"><input type="checkbox" checked={includeZapBaseline} onChange={(event) => setIncludeZapBaseline(event.target.checked)} disabled={!targetId || !zapAvailable} />{zapAvailable ? "Incluir ZAP Baseline passivo" : "ZAP Baseline não instalado"}</label>
            <button className="scan" disabled={busy || !targetId} onClick={() => void enqueue()}>Iniciar avaliação PASSIVE</button>
          </div>
        </div>
        <div className="job-list">
          {targetJobs.length === 0 ? <p className="empty">Nenhum job para este target.</p> : targetJobs.map((item) => (
            <article key={item.id}>
              <span className={`job-status status-${item.status.toLowerCase()}`}>{item.status}</span>
              <div><strong>{item.mode}</strong><small>{new Date(item.created_at).toLocaleString("pt-BR")}</small></div>
            </article>
          ))}
        </div>
      </section>

      <section>
        <div className="section-heading">
          <div><p className="step">RESULTADOS</p><h2>Findings e correção</h2></div>
          <div className="report-actions">
            <button className="secondary" disabled={!targetId} onClick={() => downloadReport("executive")}>Relatório executivo PDF</button>
            <button className="secondary" disabled={!targetId} onClick={() => downloadReport("technical")}>Relatório técnico PDF</button>
            <button className="secondary" disabled={!targetId} onClick={() => downloadReport("proposal")}>Proposta</button>
            <button className="secondary" disabled={!targetId} onClick={() => downloadReport("roe")}>ROE</button>
          </div>
        </div>
        <div className="findings-layout">
          <div className="finding-list">
            {targetFindings.length === 0 ? <p className="empty">Nenhum finding registrado.</p> : targetFindings.map((item) => (
              <button key={item.id} className={selectedFinding?.id === item.id ? "finding selected" : "finding"} onClick={() => void openFinding(item)}>
                <span className={severityClass(item.severity)}>{item.severity}</span>
                <span><strong>{item.title}</strong><small>{Math.round(item.confidence * 100)}% de confiança · {item.status}</small></span>
              </button>
            ))}
          </div>
          <aside className="finding-detail">
            {!selectedFinding ? <p className="empty">Selecione um finding para ver detalhes e evidências.</p> : (
              <>
                <span className={severityClass(selectedFinding.severity)}>{selectedFinding.severity}</span>
                <h3>{selectedFinding.title}</h3>
                <p>{selectedFinding.description}</p>
                <h4>Como corrigir</h4>
                <p>{selectedFinding.remediation ?? "Sem orientação cadastrada."}</p>
                <label>Status
                  <select value={selectedFinding.status} onChange={(event) => void changeFindingStatus(event.target.value as FindingStatus)}>
                    <option value="OPEN">Aberto</option>
                    <option value="ACKNOWLEDGED">Reconhecido</option>
                    <option value="FIXED">Corrigido</option>
                    <option value="ACCEPTED_RISK">Risco aceito</option>
                  </select>
                </label>
                <h4>Evidências sanitizadas</h4>
                {evidence.length === 0 ? <p className="empty">Nenhuma evidência.</p> : evidence.map((item) => (
                  <details key={item.id}>
                    <summary>{item.source} · {hostname(item.url)}</summary>
                    <pre>{JSON.stringify(item.sanitized_data, null, 2)}</pre>
                  </details>
                ))}
              </>
            )}
          </aside>
        </div>
      </section>
    </main>
  );
}
