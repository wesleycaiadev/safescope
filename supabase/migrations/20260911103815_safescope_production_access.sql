-- Apply after `alembic -x db_url="$DATABASE_URL" upgrade head` created the
-- application schema. This migration protects the public/Data API surface;
-- SafeScope's FastAPI control plane enforces the same tenant boundary.

create schema if not exists private;
revoke all on schema private from public;
grant usage on schema private to authenticated;

alter table public.organizations enable row level security;
alter table public.organization_memberships enable row level security;
alter table public.projects enable row level security;
alter table public.targets enable row level security;
alter table public.scopes enable row level security;
alter table public.authorizations enable row level security;
alter table public.domain_verifications enable row level security;
alter table public.scan_jobs enable row level security;
alter table public.scan_runs enable row level security;
alter table public.findings enable row level security;
alter table public.evidence enable row level security;
alter table public.audit_logs enable row level security;

-- This definer function deliberately has no caller-controlled user identifier.
-- It is private, has a fixed search path, and always derives membership from
-- the verified Supabase identity, preventing policy recursion without trusting
-- mutable JWT user metadata.
create or replace function private.current_organization_ids()
returns setof text
language sql
security definer
set search_path = ''
stable
as $$
  select membership.organization_id
  from public.organization_memberships as membership
  where membership.user_id = (select auth.uid()::text)
$$;
revoke all on function private.current_organization_ids() from public;
grant execute on function private.current_organization_ids() to authenticated;

create or replace function private.current_project_ids()
returns setof text
language sql
security definer
set search_path = ''
stable
as $$
  select project.id
  from public.projects as project
  where project.organization_id in (select private.current_organization_ids())
$$;
revoke all on function private.current_project_ids() from public;
grant execute on function private.current_project_ids() to authenticated;

create or replace function private.current_target_ids()
returns setof text
language sql
security definer
set search_path = ''
stable
as $$
  select target.id
  from public.targets as target
  where target.project_id in (select private.current_project_ids())
$$;
revoke all on function private.current_target_ids() from public;
grant execute on function private.current_target_ids() to authenticated;

revoke all on table public.organizations, public.organization_memberships, public.projects,
  public.targets, public.scopes, public.authorizations, public.domain_verifications,
  public.scan_jobs, public.scan_runs, public.findings, public.evidence, public.audit_logs
  from anon, authenticated;
grant select on table public.organizations, public.organization_memberships, public.projects,
  public.targets, public.scopes, public.authorizations, public.domain_verifications,
  public.scan_jobs, public.scan_runs, public.findings, public.evidence, public.audit_logs
  to authenticated;

drop policy if exists organization_member_read on public.organizations;
create policy organization_member_read on public.organizations for select to authenticated
  using (id in (select private.current_organization_ids()));
drop policy if exists own_membership_read on public.organization_memberships;
create policy own_membership_read on public.organization_memberships for select to authenticated
  using (user_id = (select auth.uid()::text));
drop policy if exists project_member_read on public.projects;
create policy project_member_read on public.projects for select to authenticated
  using (organization_id in (select private.current_organization_ids()));
drop policy if exists target_member_read on public.targets;
create policy target_member_read on public.targets for select to authenticated
  using (project_id in (select private.current_project_ids()));

drop policy if exists scope_member_read on public.scopes;
create policy scope_member_read on public.scopes for select to authenticated
  using (target_id in (select private.current_target_ids()));
drop policy if exists authorization_member_read on public.authorizations;
create policy authorization_member_read on public.authorizations for select to authenticated
  using (target_id in (select private.current_target_ids()));
drop policy if exists verification_member_read on public.domain_verifications;
create policy verification_member_read on public.domain_verifications for select to authenticated
  using (target_id in (select private.current_target_ids()));
drop policy if exists scan_job_member_read on public.scan_jobs;
create policy scan_job_member_read on public.scan_jobs for select to authenticated
  using (target_id in (select private.current_target_ids()));
drop policy if exists scan_run_member_read on public.scan_runs;
create policy scan_run_member_read on public.scan_runs for select to authenticated
  using (job_id in (select job.id from public.scan_jobs as job where job.target_id in (select private.current_target_ids())));
drop policy if exists finding_member_read on public.findings;
create policy finding_member_read on public.findings for select to authenticated
  using (target_id in (select private.current_target_ids()));
drop policy if exists evidence_member_read on public.evidence;
create policy evidence_member_read on public.evidence for select to authenticated
  using (finding_id in (select finding.id from public.findings as finding where finding.target_id in (select private.current_target_ids())));
drop policy if exists audit_member_read on public.audit_logs;
create policy audit_member_read on public.audit_logs for select to authenticated
  using (organization_id in (select private.current_organization_ids()));

-- Audit events can be inserted only by SafeScope's server-side database role.
-- They cannot be altered or erased, including through an accidentally privileged
-- maintenance session.
create or replace function private.reject_audit_mutation()
returns trigger
language plpgsql
security invoker
set search_path = ''
as $$
begin
  raise exception 'audit logs are append-only';
end;
$$;
revoke all on function private.reject_audit_mutation() from public;
drop trigger if exists audit_logs_immutable on public.audit_logs;
create trigger audit_logs_immutable
before update or delete on public.audit_logs
for each row execute function private.reject_audit_mutation();
