import { createContext, useContext, useEffect, useMemo, useRef, useState } from 'react'
import { HeadloAuthClientV2, type HeadloAuthClientV2Config, type AuthStateV2 } from './client-v2'

// Multi-environment auth for a single renderer. Enables a desktop / dashboard
// to hold independent sessions for local / dev / prod (or any set of named
// envs) at the same time, so a request routed to api-local.headlo.com uses
// the session for auth-local.headlo.com and a request to api.headlo.com uses
// the session for auth.headlo.com.
//
// Storage isolation comes for free from Phase 1's `storageKey` support in
// HeadloAuthClientV2 — the registry just passes the env name as the
// storageKey and each client gets its own session token / PKCE verifier /
// user cache / broadcast channel bucket.
//
// Backward compat: HeadloProviderV2 (single-session) stays unchanged. Multi-
// env is purely additive. Consumers on one env keep working; consumers
// wanting N envs wrap with HeadloMultiEnvProvider.

// ─── Registry — one HeadloAuthClientV2 per env, lazy-created ───────────

/** Config for a single env slot. The registry fills in storageKey itself
 *  from the env name so callers can't accidentally collide. */
export type EnvClientConfig = Omit<HeadloAuthClientV2Config, 'storageKey'>

/** In-memory registry of per-env clients. One instance per renderer; owns
 *  the lifecycle of each client (init on first access, destroy on remove).
 *  Not React-aware — the provider wraps it for state subscriptions. */
export class HeadloAuthMultiEnvRegistry {
  private clients = new Map<string, HeadloAuthClientV2>()
  private inits   = new Map<string, Promise<void>>()

  /** Ensure a client for `env` exists. Creates + kicks off init the first
   *  time; returns the existing client on subsequent calls. `config` is
   *  used only for the FIRST call — subsequent calls with different config
   *  are ignored (client is already bound). */
  ensure(env: string, config: EnvClientConfig): HeadloAuthClientV2 {
    let client = this.clients.get(env)
    if (client) return client
    client = new HeadloAuthClientV2({ ...config, storageKey: env })
    this.clients.set(env, client)
    // Fire init but don't await — the caller (React state hook) reads state
    // via subscription so a slow init doesn't block hook return. Track the
    // in-flight promise so consumers that WANT to await can via .initFor(env).
    this.inits.set(env, client.init().catch(err => {
      console.error(`[headlo-auth:multi] init failed for env=${env}`, err)
    }))
    return client
  }

  /** Optional: await the init promise for an env (useful in tests or when
   *  the consumer must know when hydration is complete). Resolves
   *  immediately when init already finished. Rejects only if init hasn't
   *  been kicked off yet (call ensure() first). */
  async initFor(env: string): Promise<void> {
    const p = this.inits.get(env)
    if (!p) throw new Error(`[headlo-auth:multi] no client for env=${env} — call ensure(env, config) first`)
    await p
  }

  /** Look up an existing client without creating one. Returns null when
   *  the env hasn't been ensured yet. */
  get(env: string): HeadloAuthClientV2 | null {
    return this.clients.get(env) ?? null
  }

  /** Env names that currently have a client. Ordering is insertion order. */
  list(): string[] { return Array.from(this.clients.keys()) }

  /** Destroy the client for `env` and drop from the registry. Its session
   *  storage stays intact — call `client.signOut()` first if you want to
   *  also clear the token. Useful when swapping between "profiles" in the
   *  same tab (rare). */
  async remove(env: string): Promise<void> {
    const c = this.clients.get(env)
    if (!c) return
    this.clients.delete(env)
    this.inits.delete(env)
    // HeadloAuthClientV2 doesn't have a public destroy() today; we just
    // drop the reference. In-flight timers get GC'd when nothing subscribes.
    // Signout is the caller's responsibility to preserve backward compat.
    void c
  }
}

// ─── React context + hooks ──────────────────────────────────────────────

const RegistryContext = createContext<HeadloAuthMultiEnvRegistry | null>(null)

export interface HeadloMultiEnvProviderProps {
  /** Per-env configs. The provider ensures a client for every env at mount
   *  so all sessions hydrate in parallel (rather than lazily on first hook
   *  access). Add / remove envs = re-render with a different map. */
  envs:     Record<string, EnvClientConfig>
  children: React.ReactNode
}

/** Wraps children with a registry seeded from `envs`. The registry is
 *  stable across re-renders (kept in a ref) so hook consumers don't
 *  re-create clients on every render. */
export function HeadloMultiEnvProvider({ envs, children }: HeadloMultiEnvProviderProps): React.ReactElement {
  const registryRef = useRef<HeadloAuthMultiEnvRegistry | null>(null)
  if (registryRef.current === null) registryRef.current = new HeadloAuthMultiEnvRegistry()
  const registry = registryRef.current

  // Ensure every configured env has a client. Runs on mount + any time the
  // envs map identity changes (typical: never after first mount). Adding
  // a new env at runtime = re-render with an extended envs map; the ensure
  // call is idempotent so existing envs aren't touched.
  useEffect(() => {
    for (const [env, cfg] of Object.entries(envs)) registry.ensure(env, cfg)
  }, [envs, registry])

  return <RegistryContext.Provider value={registry}>{children}</RegistryContext.Provider>
}

/** Access the multi-env registry directly. Rare — most consumers should
 *  use `useAuthClient(env)` or `useAuthStateForEnv(env)` instead. Throws
 *  when no HeadloMultiEnvProvider is in the tree; use
 *  `useOptionalAuthRegistry()` when null is acceptable (e.g. hooks that
 *  gracefully degrade to a single-session mode). */
export function useAuthRegistry(): HeadloAuthMultiEnvRegistry {
  const r = useContext(RegistryContext)
  if (!r) throw new Error('useAuthRegistry: no HeadloMultiEnvProvider in the tree')
  return r
}

/** Optional variant of useAuthRegistry — returns null when no provider
 *  is in the tree instead of throwing. Use in hooks/components that
 *  should keep working under a single-session (V2-only) setup. */
export function useOptionalAuthRegistry(): HeadloAuthMultiEnvRegistry | null {
  return useContext(RegistryContext)
}

/** Get the HeadloAuthClientV2 instance for a named env. Returns null when
 *  the env hasn't been configured in the provider. */
export function useAuthClient(env: string | null): HeadloAuthClientV2 | null {
  const registry = useAuthRegistry()
  return env ? registry.get(env) : null
}

/** Subscribe to auth state for a specific env — token, user, isSignedIn,
 *  isLoaded — plus action closures bound to that env's client. Re-renders
 *  the calling component whenever the env's session changes.
 *
 *  Returns null when the env hasn't been configured (misconfigured
 *  provider or a typo'd env name). Consumers should guard against null. */
export function useAuthStateForEnv(env: string | null): (AuthStateV2 & {
  signIn:  (opts?: Parameters<HeadloAuthClientV2['signIn']>[0])  => Promise<void>
  signOut: () => Promise<void>
  getToken: () => Promise<string | null>
}) | null {
  const client = useAuthClient(env)
  const [state, setState] = useState<AuthStateV2 | null>(null)

  useEffect(() => {
    if (!client) { setState(null); return }
    // Prime with the current state, then subscribe via onChange. onChange
    // returns an unsubscribe fn per HeadloAuthClientV2's contract.
    setState(client.getState())
    const off = client.onChange(next => setState(next))
    return off
  }, [client])

  return useMemo(() => {
    if (!client || !state) return null
    return {
      ...state,
      signIn:   opts => client.signIn(opts),
      signOut:  () => client.signOut(),
      getToken: () => client.getToken(),
    }
  }, [client, state])
}
