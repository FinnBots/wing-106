/*
 * phantom-mobile.js
 * FinnBots — shared Phantom mobile deeplink helper (Chat 10.1, 5 July 2026)
 *
 * WHY THIS EXISTS:
 * window.solana.connect() (the injected provider) only exists in Phantom's
 * own in-app browser, or in Safari with the Phantom Safari Extension turned
 * on. Chrome and Edge on iOS never get it injected — that's an iOS platform
 * restriction (extensions are Safari-only), not a bug in this site.
 *
 * This module implements Phantom's official mobile deeplink protocol
 * (https://phantom.app/ul/v1/...) so Connect and (where needed) transaction
 * signing work from ANY mobile browser by round-tripping through the
 * Phantom app itself.
 *
 * REQUIRES: phantom-deeplink-libs.min.js loaded first (exposes window.nacl
 * and window.bs58). Pinned versions: tweetnacl 1.0.3, bs58 5.0.0.
 * SHA-256 of phantom-deeplink-libs.min.js: (recorded in TechnicalSpecs)
 *
 * SECURITY NOTE: the "dapp encryption secret key" stored in sessionStorage
 * below is NOT a wallet key and controls no funds. It's a throwaway
 * X25519 key generated fresh per browser tab, used only to set up an
 * encrypted channel with Phantom for this one connect/sign round-trip.
 * This is the same approach used in Phantom's own reference integration.
 * The real wallet keys never leave Phantom.
 *
 * USAGE (see integration comments in index.html for each site):
 *   PhantomMobile.isMobile()                -> bool
 *   PhantomMobile.hasPendingRedirect()       -> bool (call on every page load)
 *   PhantomMobile.consumePendingRedirect()   -> { type:'connect', publicKey } |
 *                                                { type:'signTransaction', txBytes:Uint8Array } |
 *                                                { type:'error', message } | null
 *   PhantomMobile.connect(appUrl)            -> redirects the page away, never resolves
 *   PhantomMobile.signTransaction(txBytes, appUrl) -> redirects the page away, never resolves
 */
(function (global) {
  'use strict';

  var STORAGE_PREFIX = 'fb_phantom_';
  var CLUSTER = 'mainnet-beta';
  var SESSION_MAX_AGE_MS = 24 * 60 * 60 * 1000; // sessions older than 24h are treated as expired

  function b58enc(bytes) { return global.bs58.encode(bytes); }
  function b58dec(str) { return new Uint8Array(global.bs58.decode(str)); }

  // localStorage, NOT sessionStorage — deliberately. Phantom's in-app browser
  // opens every deeplink return in a brand-new tab (confirmed on-device,
  // 6 July 2026), and sessionStorage is per-tab so it never survives that.
  // localStorage is shared across all tabs of the same browser, so the
  // session established in one tab is visible to every subsequent one.
  function saveJSON(key, obj) {
    try { localStorage.setItem(STORAGE_PREFIX + key, JSON.stringify(obj)); } catch (e) {}
  }
  function loadJSON(key) {
    try {
      var v = localStorage.getItem(STORAGE_PREFIX + key);
      return v ? JSON.parse(v) : null;
    } catch (e) { return null; }
  }
  function clearKey(key) {
    try { localStorage.removeItem(STORAGE_PREFIX + key); } catch (e) {}
  }

  function isMobile() {
    var ua = navigator.userAgent || '';
    return /iPhone|iPad|iPod|Android/i.test(ua);
  }

  // Strips our own query params off the URL bar after we've read them,
  // so a page refresh doesn't try to re-process a stale redirect.
  function stripQueryParams(names) {
    try {
      var url = new URL(window.location.href);
      names.forEach(function (n) { url.searchParams.delete(n); });
      window.history.replaceState({}, document.title, url.pathname + (url.search ? url.search : '') + url.hash);
    } catch (e) {}
  }

  function getParam(name) {
    var params = new URLSearchParams(window.location.search);
    return params.get(name);
  }

  // ---- CONNECT ----
  //
  // NOTE on the dapp_secret URL param below: this is deliberately carried in
  // the URL rather than only in sessionStorage. On iOS, tapping Connect in
  // Chrome/Edge often causes Phantom to bring the redirect back inside its
  // OWN in-app browser — a different storage partition entirely from the
  // Chrome tab that started this, so anything saved to sessionStorage before
  // navigating away is invisible when we land back. Putting the secret in
  // the URL sidesteps that; it's safe because this key is single-use,
  // controls no funds, and can only decrypt the one connect response it's
  // paired with.
  function buildConnectURL(appUrl) {
    var dappKeyPair = global.nacl.box.keyPair();
    saveJSON('connect_kp', {
      pub: b58enc(dappKeyPair.publicKey),
      sec: b58enc(dappKeyPair.secretKey)
    });
    var redirectLink = appUrl + (appUrl.indexOf('?') >= 0 ? '&' : '?') +
      'phantom_action=connect&dapp_secret=' + encodeURIComponent(b58enc(dappKeyPair.secretKey));
    var params = new URLSearchParams({
      dapp_encryption_public_key: b58enc(dappKeyPair.publicKey),
      cluster: CLUSTER,
      app_url: appUrl,
      redirect_link: redirectLink
    });
    return 'https://phantom.app/ul/v1/connect?' + params.toString();
  }

  function connect(appUrl) {
    window.location.href = buildConnectURL(appUrl);
    return new Promise(function () {}); // page is navigating away
  }

  function handleConnectRedirect() {
    var errCode = getParam('errorCode');
    if (errCode) {
      stripQueryParams(['phantom_action', 'dapp_secret', 'errorCode', 'errorMessage']);
      return { type: 'error', message: getParam('errorMessage') || 'Connection was cancelled in Phantom.' };
    }
    var phantomPubB58 = getParam('phantom_encryption_public_key');
    var nonceB58 = getParam('nonce');
    var dataB58 = getParam('data');
    if (!phantomPubB58 || !nonceB58 || !dataB58) return null;

    // Prefer the secret carried in the URL — it survives Phantom bouncing us
    // into its own in-app browser, which sessionStorage cannot. Only fall
    // back to storage for the rarer case where the URL param is missing
    // (e.g. an older cached page still using the previous connect link).
    var secretB58 = getParam('dapp_secret');
    if (!secretB58) {
      var kp = loadJSON('connect_kp');
      secretB58 = kp ? kp.sec : null;
    }
    stripQueryParams(['phantom_action', 'dapp_secret', 'phantom_encryption_public_key', 'nonce', 'data']);
    if (!secretB58) return { type: 'error', message: 'Connection session expired — please tap Connect again.' };

    try {
      var secretKey = b58dec(secretB58);
      var phantomPub = b58dec(phantomPubB58);
      var sharedSecret = global.nacl.box.before(phantomPub, secretKey);
      var nonce = b58dec(nonceB58);
      var data = b58dec(dataB58);
      var decrypted = global.nacl.box.open.after(data, nonce, sharedSecret);
      if (!decrypted) return { type: 'error', message: 'Could not verify the response from Phantom. Please try connecting again.' };
      var payload = JSON.parse(new TextDecoder().decode(decrypted));
      // Session persists for the life of this tab — needed again for signTransaction.
      // dappPub is stored because sign requests MUST present the same
      // dapp_encryption_public_key that connect used — Phantom derives the
      // shared secret from whatever key is on the request, so sending a
      // different one makes its response undecryptable.
      var dappPubForSession = global.nacl.box.keyPair.fromSecretKey(secretKey).publicKey;
      saveJSON('session', {
        session: payload.session,
        publicKey: payload.public_key,
        sharedSecret: b58enc(sharedSecret),
        dappPub: b58enc(dappPubForSession),
        createdAt: Date.now()
      });
      clearKey('connect_kp');
      return { type: 'connect', publicKey: payload.public_key };
    } catch (e) {
      return { type: 'error', message: 'Could not read the response from Phantom. Please try connecting again.' };
    }
  }

  // ---- SIGN TRANSACTION (sign-only — matches this site's existing pattern
  //      of never letting Phantom submit; the page always sends it itself) ----

  function buildSignTransactionURL(txBytes, appUrl, marker) {
    var sess = loadJSON('session');
    if (!sess) throw new Error('No active Phantom session — reconnect your wallet first.');
    var sharedSecret = b58dec(sess.sharedSecret);
    var payload = { transaction: b58enc(txBytes), session: sess.session };
    var nonce = global.nacl.randomBytes(24);
    var encrypted = global.nacl.box.after(
      new TextEncoder().encode(JSON.stringify(payload)), nonce, sharedSecret
    );
    // CRITICAL: sign requests must present the SAME dapp_encryption_public_key
    // that connect used. Phantom derives the shared secret from the key on the
    // request — a different key means its response can never be decrypted.
    // (Earlier versions sent a random key here; that was a bug.)
    if (!sess.dappPub) throw new Error('Session is from an older connect — reconnect your wallet first.');
    // Carry the shared secret in the redirect_link too, same reasoning as
    // Connect: if this round-trip also lands in a different storage context
    // than it started in, the response can still be decrypted without it.
    var redirectLink = appUrl + (appUrl.indexOf('?') >= 0 ? '&' : '?') +
      'phantom_action=' + marker + '&dapp_shared=' + encodeURIComponent(sess.sharedSecret);
    var params = new URLSearchParams({
      dapp_encryption_public_key: sess.dappPub,
      nonce: b58enc(nonce),
      redirect_link: redirectLink,
      payload: b58enc(encrypted)
    });
    return 'https://phantom.app/ul/v1/signTransaction?' + params.toString();
  }

  function signTransaction(txBytes, appUrl, marker) {
    saveJSON('pending_sign_marker', { marker: marker || 'sign' });
    window.location.href = buildSignTransactionURL(txBytes, appUrl, marker || 'sign');
    return new Promise(function () {}); // page is navigating away
  }

  function handleSignRedirect(expectedMarker) {
    var action = getParam('phantom_action');
    if (action !== (expectedMarker || 'sign')) return null;

    var errCode = getParam('errorCode');
    if (errCode) {
      stripQueryParams(['phantom_action', 'dapp_shared', 'errorCode', 'errorMessage']);
      return { type: 'error', message: getParam('errorMessage') || 'Signing was cancelled in Phantom.' };
    }
    var nonceB58 = getParam('nonce');
    var dataB58 = getParam('data');
    var sharedB58FromUrl = getParam('dapp_shared');
    stripQueryParams(['phantom_action', 'dapp_shared', 'nonce', 'data']);
    if (!nonceB58 || !dataB58) return null;

    var sess = loadJSON('session');
    if (!sharedB58FromUrl && !sess) return { type: 'error', message: 'Your Phantom session expired — reconnect and try again.' };

    try {
      var sharedSecret = b58dec(sharedB58FromUrl || sess.sharedSecret);
      var nonce = b58dec(nonceB58);
      var data = b58dec(dataB58);
      var decrypted = global.nacl.box.open.after(data, nonce, sharedSecret);
      if (!decrypted) return { type: 'error', message: 'Could not verify the signed transaction from Phantom.' };
      var payload = JSON.parse(new TextDecoder().decode(decrypted));
      return { type: 'signTransaction', txBytes: b58dec(payload.transaction) };
    } catch (e) {
      return { type: 'error', message: 'Could not read the signed transaction from Phantom.' };
    }
  }

  // ---- Unified redirect check, call once on every page load ----

  function consumePendingRedirect(expectedSignMarker) {
    var signResult = handleSignRedirect(expectedSignMarker);
    if (signResult) return signResult;
    var action = getParam('phantom_action');
    if (action === 'connect') return handleConnectRedirect();
    return null;
  }

  function hasSession() {
    var s = loadJSON('session');
    if (!s || !s.publicKey) return false;
    // Persistent storage can outlive the session's real validity — treat
    // anything older than 24h as expired and self-clean.
    if (s.createdAt && (Date.now() - s.createdAt) > SESSION_MAX_AGE_MS) {
      clearSession();
      return false;
    }
    return true;
  }
  function getSessionPublicKey() {
    var s = loadJSON('session');
    return s ? s.publicKey : null;
  }
  function clearSession() {
    clearKey('session');
    clearKey('connect_kp');
  }

  global.PhantomMobile = {
    isMobile: isMobile,
    connect: connect,
    signTransaction: signTransaction,
    consumePendingRedirect: consumePendingRedirect,
    hasSession: hasSession,
    getSessionPublicKey: getSessionPublicKey,
    clearSession: clearSession
  };
})(window);
