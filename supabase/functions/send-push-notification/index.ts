import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'

const SUPABASE_URL = Deno.env.get('SUPABASE_URL')!
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!
const SUPABASE_ANON_KEY = Deno.env.get('SUPABASE_ANON_KEY')!

function pemToArrayBuffer(pem: string): ArrayBuffer {
  const pemBody = pem
    .replace(/-----BEGIN PRIVATE KEY-----/, '')
    .replace(/-----END PRIVATE KEY-----/, '')
    .replace(/\s+/g, '')
  const binary = atob(pemBody)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes.buffer
}

const base64url = (input: string | Uint8Array): string => {
  const bytes = typeof input === 'string' ? new TextEncoder().encode(input) : input
  let binary = ''
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i])
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
}

async function getFCMAccessToken(): Promise<string> {
  const raw = Deno.env.get('FIREBASE_SERVICE_ACCOUNT_JSON')
  if (!raw) throw new Error('FIREBASE_SERVICE_ACCOUNT_JSON secret not set')

  let sa: any
  try {
    sa = JSON.parse(raw)
  } catch (e) {
    throw new Error('FIREBASE_SERVICE_ACCOUNT_JSON is not valid JSON: ' + e)
  }
  if (!sa.client_email) throw new Error('Service account JSON missing client_email')
  if (!sa.private_key) throw new Error('Service account JSON missing private_key')
  console.log('[Auth] Building JWT for:', sa.client_email)

  const now = Math.floor(Date.now() / 1000)
  const header  = base64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }))
  const payload = base64url(JSON.stringify({
    iss:   sa.client_email,
    scope: 'https://www.googleapis.com/auth/firebase.messaging',
    aud:   'https://oauth2.googleapis.com/token',
    iat:   now,
    exp:   now + 3600,
  }))
  const signingInput = `${header}.${payload}`

  const keyData = pemToArrayBuffer(sa.private_key)
  console.log('[Auth] Private key decoded:', keyData.byteLength, 'bytes (expect ~1218 for RSA-2048 PKCS8)')

  const cryptoKey = await crypto.subtle.importKey(
    'pkcs8',
    keyData,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign'],
  )
  console.log('[Auth] CryptoKey imported successfully')

  const sigBuffer = await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5', cryptoKey,
    new TextEncoder().encode(signingInput),
  )

  const jwt = `${signingInput}.${base64url(new Uint8Array(sigBuffer))}`
  console.log('[Auth] JWT assembled, exchanging for OAuth2 access token…')

  const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: jwt,
    }),
  })

  const tokenJson = await tokenRes.json()
  if (!tokenRes.ok || !tokenJson.access_token) {
    console.error('[Auth] Google OAuth error — HTTP', tokenRes.status, '— full response:', JSON.stringify(tokenJson))
    throw new Error('Token exchange failed: ' + JSON.stringify(tokenJson))
  }
  console.log('[Auth] Access token obtained (type:', tokenJson.token_type, 'expires_in:', tokenJson.expires_in, ')')
  return tokenJson.access_token
}

function isLegacyToken(token: string): boolean {
  return token.includes(':APA91b')
}

async function sendFCMv1(
  token: string,
  title: string,
  body: string,
  data: Record<string, string>,
  accessToken: string,
): Promise<{ ok: boolean; unregistered: boolean }> {
  const payload = {
    message: {
      token,
      notification: { title, body },
      apns: { payload: { aps: { badge: 1, sound: 'default' } } },
      data,
    },
  }
  const FCM_URL = 'https://fcm.googleapis.com/v1/projects/sisterhoodverb-70743/messages:send'
  console.log('[FCM-v1] Sending to token:', token.slice(0, 20) + '…')

  const res = await fetch(FCM_URL, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(payload),
  })

  if (res.ok) {
    const responseBody = await res.json().catch(() => ({}))
    console.log('[FCM-v1] Success for token:', token.slice(0, 20) + '…', 'response:', JSON.stringify(responseBody))
    return { ok: true, unregistered: false }
  }

  const err = await res.json().catch(() => ({}))
  console.error('[FCM-v1] Error for token:', token.slice(0, 20) + '…', 'status:', res.status, 'error:', JSON.stringify(err))
  const unregistered = err?.error?.details?.some(
    (d: any) => d.errorCode === 'UNREGISTERED',
  ) ?? false
  return { ok: false, unregistered }
}

async function sendFCMLegacy(
  token: string,
  title: string,
  body: string,
  data: Record<string, string>,
): Promise<{ ok: boolean; unregistered: boolean }> {
  const serverKey = Deno.env.get('FCM_SERVER_KEY')
  if (!serverKey) throw new Error('FCM_SERVER_KEY secret not set')

  const payload = {
    to: token,
    notification: { title, body, sound: 'default', badge: '1' },
    data,
  }
  console.log('[FCM-Legacy] Sending to token:', token.slice(0, 20) + '…')

  const res = await fetch('https://fcm.googleapis.com/fcm/send', {
    method: 'POST',
    headers: {
      Authorization: `key=${serverKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(payload),
  })

  const json = await res.json().catch(() => ({}))
  console.log('[FCM-Legacy] Response status:', res.status, 'body:', JSON.stringify(json))

  if (!res.ok) {
    return { ok: false, unregistered: false }
  }

  const result = json?.results?.[0]
  if (result?.error) {
    const unregistered = result.error === 'NotRegistered' || result.error === 'InvalidRegistration'
    console.error('[FCM-Legacy] Error:', result.error, 'for token:', token.slice(0, 20) + '…')
    return { ok: false, unregistered }
  }

  console.log('[FCM-Legacy] Success for token:', token.slice(0, 20) + '…')
  return { ok: true, unregistered: false }
}

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, {
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
      },
    })
  }

  try {
    const authHeader = req.headers.get('Authorization')
    if (!authHeader) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 })
    }

    // Verify the caller is an authenticated app user
    const callerClient = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
      global: { headers: { Authorization: authHeader } },
    })
    const { data: { user: caller }, error: authErr } = await callerClient.auth.getUser()
    if (authErr || !caller) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 })
    }

    const { user_id, circle_name, poster_id, title, body, data = {} } = await req.json()
    console.log('[Request] body:', JSON.stringify({ user_id, circle_name, poster_id, title, body }))

    if (!title || !body) {
      console.error('[Request] Missing title or body')
      return new Response(JSON.stringify({ error: 'Missing title or body' }), { status: 400 })
    }

    const admin = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)
    let targetUserIds: string[] = []

    if (user_id) {
      targetUserIds = [user_id]
      console.log('[Targeting] single user:', user_id)
    } else if (circle_name && poster_id) {
      const { data: members, error: membersError } = await admin
        .from('circle_members')
        .select('user_id')
        .eq('circle_name', circle_name)
        .neq('user_id', poster_id)
      if (membersError) console.error('[Targeting] circle_members query error:', membersError)
      targetUserIds = (members ?? []).map((m: any) => m.user_id)
      console.log('[Targeting] circle', circle_name, '→', targetUserIds.length, 'members (excluding poster)')
    } else {
      console.warn('[Targeting] No user_id or circle_name+poster_id provided — nothing to send')
    }

    if (!targetUserIds.length) {
      console.log('[Targeting] No target users, returning sent:0')
      return new Response(JSON.stringify({ sent: 0 }), {
        headers: { 'Content-Type': 'application/json' },
      })
    }

    const { data: tokenRows, error: tokenError } = await admin
      .from('push_tokens')
      .select('token, user_id')
      .in('user_id', targetUserIds)

    if (tokenError) console.error('[Tokens] push_tokens query error:', tokenError)
    console.log('[Tokens] found', tokenRows?.length ?? 0, 'token(s) for', targetUserIds.length, 'user(s)')

    if (!tokenRows?.length) {
      console.warn('[Tokens] No push tokens found for users:', targetUserIds)
      return new Response(JSON.stringify({ sent: 0 }), {
        headers: { 'Content-Type': 'application/json' },
      })
    }

    const stringData = Object.fromEntries(
      Object.entries(data).map(([k, v]) => [k, String(v)])
    )

    const legacyTokenRows = tokenRows.filter((r: any) => isLegacyToken(r.token))
    const v1TokenRows = tokenRows.filter((r: any) => !isLegacyToken(r.token))
    console.log(`[Tokens] ${legacyTokenRows.length} legacy APNs token(s), ${v1TokenRows.length} FCM v1 token(s)`)

    let accessToken: string | null = null
    if (v1TokenRows.length > 0) {
      console.log('[Auth] Getting FCM access token…')
      accessToken = await getFCMAccessToken()
      console.log('[Auth] FCM access token obtained')
    }

    let sent = 0
    const staleTokens: string[] = []

    for (const { token, user_id: tokenUserId } of tokenRows) {
      const legacy = isLegacyToken(token)
      console.log('[FCM] Dispatching to user:', tokenUserId, legacy ? '(legacy APNs)' : '(FCM v1)')
      const { ok, unregistered } = legacy
        ? await sendFCMLegacy(token, title, body, stringData)
        : await sendFCMv1(token, title, body, stringData, accessToken!)
      if (ok) sent++
      else if (unregistered) {
        console.warn('[FCM] Token unregistered, will prune:', token.slice(0, 20) + '…')
        staleTokens.push(token)
      }
    }

    if (staleTokens.length) {
      console.log('[Cleanup] Pruning', staleTokens.length, 'stale token(s)')
      await admin.from('push_tokens').delete().in('token', staleTokens)
    }

    console.log('[Done] sent:', sent, '/', tokenRows.length)
    return new Response(JSON.stringify({ sent }), {
      headers: { 'Content-Type': 'application/json' },
    })
  } catch (err: any) {
    return new Response(JSON.stringify({ error: err.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    })
  }
})
