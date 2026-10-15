-- RLS on a child row does not establish ownership of its foreign-key targets.
-- Keep the existing own-row policies, and require every referenced entity to
-- belong to that same user on INSERT/UPDATE. Restrictive policies combine with
-- the existing policies using AND, rather than opening an alternative write path.
--
-- USING (true) deliberately allows owners to read/delete legacy malformed rows;
-- WITH CHECK prevents creating or retaining a cross-user reference on a write.
-- Existing foreign keys and their deletion behavior remain unchanged, including
-- PostgREST's embedded relationships. Service-role jobs must still scope reads.
do $$
declare
  ref record;
begin
  for ref in select * from (values
    ('categories', 'group_id', 'category_groups'),
    ('accounts', 'plaid_item_id', 'plaid_items'),
    ('transactions', 'account_id', 'accounts'),
    ('transactions', 'category_id', 'categories'),
    ('category_rules', 'category_id', 'categories'),
    ('account_balance_history', 'account_id', 'accounts'),
    ('budgets', 'category_id', 'categories'),
    ('budget_limits', 'category_id', 'categories'),
    ('group_budget_limits', 'group_id', 'category_groups'),
    ('tag_budget_limits', 'tag_id', 'tags'),
    ('merchant_categories', 'category_id', 'categories'),
    ('separate_account_values', 'separate_account_id', 'separate_accounts'),
    ('separate_account_values', 'recurring_contribution_id', 'recurring_contributions'),
    ('recurring_contributions', 'separate_account_id', 'separate_accounts'),
    ('zbb_assignments', 'category_id', 'categories'),
    ('transaction_tags', 'transaction_id', 'transactions'),
    ('transaction_tags', 'tag_id', 'tags'),
    ('transaction_splits', 'transaction_id', 'transactions'),
    ('transaction_splits', 'category_id', 'categories'),
    ('tag_category_rules', 'tag_id', 'tags'),
    ('tag_category_rules', 'category_id', 'categories')
  ) as refs(child_table, child_column, parent_table)
  loop
    execute format(
      'create policy %I on public.%I as restrictive for all to authenticated
       using (true) with check (
         %I is null or exists (
           select 1 from public.%I as parent
           where parent.id = %I.%I and parent.user_id = %I.user_id
         )
       )',
      'owner_of_' || ref.child_column, ref.child_table, ref.child_column,
      ref.parent_table, ref.child_table, ref.child_column, ref.child_table
    );
  end loop;
end;
$$;

-- A policy on categories cannot query categories directly: PostgreSQL detects
-- that as recursive RLS. This SECURITY DEFINER helper performs only the parent
-- ownership lookup, bound to the caller's auth.uid(), and exposes a boolean.
create or replace function public.owns_category_parent(candidate_id uuid)
returns boolean
language sql stable security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.categories parent
    where parent.id = candidate_id and parent.user_id = auth.uid()
  );
$$;
revoke all on function public.owns_category_parent(uuid) from public;
grant execute on function public.owns_category_parent(uuid) to authenticated;

create policy owner_of_parent_id on public.categories as restrictive for all to authenticated
  using (true)
  with check (parent_id is null or public.owns_category_parent(parent_id));

-- Historical malformed rows may already exist, and the service role bypasses
-- RLS. Partition balance selection by owner before picking the newest row, and
-- join every contribution on both the entity ID and its owner.
create or replace view public.latest_balances with (security_invoker = true) as
select distinct on (user_id, account_id)
  account_id, user_id, current_balance, available_balance, date
from public.account_balance_history
where current_balance is not null
order by user_id, account_id, date desc;

create or replace view public.current_net_worth with (security_invoker = true) as
select
  user_id,
  total_assets,
  total_liabilities,
  (total_assets - total_liabilities)::numeric(12,2) as net_worth,
  as_of
from (
  with contributions as (
    select
      lb.user_id,
      greatest(coalesce(lb.current_balance, 0), 0) as balance,
      a.type in ('credit', 'loan') as is_liability,
      lb.date as as_of
    from public.latest_balances lb
    join public.accounts a
      on a.id = lb.account_id and a.user_id = lb.user_id and a.is_active
    union all
    select
      sa.user_id,
      greatest(coalesce(sum(v.amount), 0), 0) as balance,
      sa.type in ('credit', 'loan') as is_liability,
      null::date as as_of
    from public.separate_accounts sa
    left join public.separate_account_values v
      on v.separate_account_id = sa.id and v.user_id = sa.user_id
    where sa.is_active
    group by sa.id
  )
  select
    user_id,
    coalesce(sum(balance) filter (where not is_liability), 0)::numeric(12,2) as total_assets,
    coalesce(sum(balance) filter (where is_liability), 0)::numeric(12,2) as total_liabilities,
    max(as_of) as as_of
  from contributions
  group by user_id
) totals;

-- Keep category attribution owner-consistent, even for rows created before the
-- write policies above. A foreign split can no longer suppress a legitimate
-- unsplit transaction or contribute to another user's spend.
create or replace view public.category_spend with (security_invoker = true) as
select
  c.user_id,
  (date_trunc('month', c.effective_date))::date as month,
  c.category_id,
  sum(c.amount) as spent
from (
  select t.user_id, t.effective_date, t.category_id, t.amount
  from public.transactions t
  join public.categories cat on cat.id = t.category_id and cat.user_id = t.user_id
  where not t.exclude_from_totals
    and not t.is_reimbursement
    and t.amount > 0
    and not exists (
      select 1 from public.transaction_splits s
      join public.categories split_cat
        on split_cat.id = s.category_id and split_cat.user_id = s.user_id
      where s.transaction_id = t.id and s.user_id = t.user_id
    )
  union all
  select t.user_id, t.effective_date, s.category_id, s.amount
  from public.transaction_splits s
  join public.transactions t on t.id = s.transaction_id and t.user_id = s.user_id
  join public.categories cat on cat.id = s.category_id and cat.user_id = s.user_id
  where not t.exclude_from_totals
    and not t.is_reimbursement
    and s.amount > 0
  union all
  select t.user_id, t.effective_date, t.category_id, t.amount
  from public.transactions t
  join public.categories cat on cat.id = t.category_id and cat.user_id = t.user_id
  where not t.exclude_from_totals
    and t.is_reimbursement
    and t.amount < 0
) c
group by c.user_id, date_trunc('month', c.effective_date), c.category_id;

-- Tags attach to the whole transaction. Keep all three owners aligned when
-- computing spend, including when old malformed tag links remain in the DB.
create or replace view public.tag_spend with (security_invoker = true) as
select
  tt.user_id,
  (date_trunc('month', t.effective_date))::date as month,
  tt.tag_id,
  sum(t.amount) as spent
from public.transaction_tags tt
join public.transactions t on t.id = tt.transaction_id and t.user_id = tt.user_id
join public.tags tag on tag.id = tt.tag_id and tag.user_id = tt.user_id
where not t.exclude_from_totals
  and t.amount > 0
group by tt.user_id, date_trunc('month', t.effective_date), tt.tag_id;
