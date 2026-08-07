(() => {
  "use strict";
  const FLAG = Symbol.for("shownet.browser-hook.runtime.v1");
  if (globalThis[FLAG]) return;
  Object.defineProperty(globalThis, FLAG, { value: true, configurable: false });

  const BRIDGE = "__SHOWNET_HOOK_BRIDGE__";
  const QUEUE = "__SHOWNET_HOOK_QUEUE__";
  const MAX_STRING = 8192;
  const MAX_BINARY = 256;
  const trim = (value, maximum = MAX_STRING) => {
    const text = String(value ?? "");
    return text.length <= maximum ? text : `${text.slice(0, maximum)}\n[TRUNCATED]`;
  };

  const selector = (node) => {
    if (!node || node.nodeType !== 1) return "";
    if (node.id) return `#${CSS.escape(node.id)}`;
    const parts = [];
    let current = node;
    while (current && current.nodeType === 1 && parts.length < 5) {
      let part = current.tagName.toLowerCase();
      if (current.classList?.length) part += `.${[...current.classList].slice(0, 2).map(CSS.escape).join(".")}`;
      const parent = current.parentElement;
      if (parent) {
        const siblings = [...parent.children].filter((item) => item.tagName === current.tagName);
        if (siblings.length > 1) part += `:nth-of-type(${siblings.indexOf(current) + 1})`;
      }
      parts.unshift(part);
      current = parent;
    }
    return parts.join(" > ");
  };

  const scrub = (value, depth = 0, seen = new WeakSet()) => {
    if (depth > 7) return "[TRUNCATED: depth]";
    if (value == null || typeof value === "number" || typeof value === "boolean") return value;
    if (typeof value === "string") return trim(value);
    if (typeof value === "bigint") return `${value}n`;
    if (typeof value === "function") return `[Function ${value.name || "anonymous"}]`;
    if (value instanceof Error) return { name: value.name, message: trim(value.message), stack: trim(value.stack, 16384) };
    if (value instanceof ArrayBuffer || ArrayBuffer.isView(value)) {
      const bytes = value instanceof ArrayBuffer
        ? new Uint8Array(value)
        : new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
      return {
        type: value.constructor?.name || "binary",
        byteLength: bytes.byteLength,
        hex: [...bytes.slice(0, MAX_BINARY)].map((byte) => byte.toString(16).padStart(2, "0")).join(""),
        truncated: bytes.byteLength > MAX_BINARY,
      };
    }
    if (typeof value !== "object") return trim(value);
    if (seen.has(value)) return "[Circular]";
    seen.add(value);
    if (Array.isArray(value)) {
      try { return value.slice(0, 200).map((item) => scrub(item, depth + 1, seen)); } catch { return "[Unavailable]"; }
    }
    // Enumerating is itself refusable — a proxy can throw from its ownKeys
    // trap — so listing the keys has to be guarded, not just reading them.
    let keys;
    try { keys = Object.keys(value).slice(0, 200); } catch { return "[Unavailable]"; }
    const output = {};
    for (const entry of keys) {
      try { output[trim(entry, 256)] = scrub(value[entry], depth + 1, seen); } catch { output[entry] = "[Unavailable]"; }
    }
    return output;
  };

  // Never throws: it is called while building a payload in the *caller's* frame,
  // outside emit's guard, so a throw here would surface as the page's own error.
  const headerEntries = (value) => {
    if (!value) return [];
    try { return [...new Headers(value).entries()].map(([name, headerValue]) => ({ name, value: headerValue })); }
    catch {}
    try { return scrub(value); } catch { return "[Unavailable]"; }
  };

  // Nothing in here may throw. These hooks sit in the middle of the page's own
  // control flow, so an observer that raises kills the very call it was
  // watching — payload building walks hostile objects and can trip on a getter
  // or an unserialisable value at any depth.
  const emit = (event) => {
    try {
      const payload = {
        timestamp: Date.now(),
        kind: event.kind || "runtime",
        name: event.name || "unknown",
        url: trim(event.url || location.href),
        method: event.method || undefined,
        input: scrub(event.input),
        output: scrub(event.output),
        stack: trim(event.stack || new Error().stack, 16384),
        durationMs: Math.max(0, Math.round(event.durationMs || 0)),
      };
      try {
        const bridge = globalThis[BRIDGE];
        if (typeof bridge === "function") {
          bridge(JSON.stringify(payload));
          return;
        }
      } catch {}
      const queue = globalThis[QUEUE] || [];
      queue.push(payload);
      if (queue.length > 500) queue.splice(0, queue.length - 500);
      globalThis[QUEUE] = queue;
    } catch {}
  };

  /** Wrapper -> the function it replaced, so toString can answer for the original. */
  const nativeSources = new WeakMap();
  /** Wrappers we installed, kept off the functions themselves. */
  const wrappedFunctions = new WeakSet();

  /**
   * Makes `replacement` report `original`'s source, name and arity.
   *
   * The cookie setter is the loudest leak in this file when left alone:
   * `Object.getOwnPropertyDescriptor(Document.prototype, "cookie").set.toString()`
   * dumps a page-authored function body, comments and all.
   */
  const registerNative = (replacement, original) => {
    try {
      nativeSources.set(replacement, original);
      wrappedFunctions.add(replacement);
      Object.defineProperty(replacement, "name", {
        configurable: true,
        value: Reflect.get(original, "name"),
      });
      Object.defineProperty(replacement, "length", {
        configurable: true,
        value: Reflect.get(original, "length"),
      });
    } catch {}
    return replacement;
  };

  // Report the original source for anything we wrapped, however it is asked.
  // `Function.prototype.toString.call(fn)` is the standard probe and an own
  // toString on the wrapper does not answer it.
  try {
    const originalToString = Function.prototype.toString;
    // A plain function, not a Proxy: V8 renders a callable Proxy as
    // "function () { [native code] }" instead of "function toString() { … }",
    // which is a one-line tell. And marking the replacement with our symbol
    // would forward through a Proxy onto the real toString, planting the marker
    // on the most-probed function in the language. This registers itself in
    // nativeSources instead, so it reports the original's source about itself.
    if (!nativeSources.has(originalToString)) {
      // Method shorthand, not a function expression: a function expression is a
      // constructor and owns `prototype`, so the replacement reported three own
      // properties where every native function reports two — a fresh tell on the
      // most-probed function in the language.
      const replacement = {
        toString() {
          const source = nativeSources.get(this);
          return Reflect.apply(originalToString, source ?? this, arguments);
        },
      }.toString;
      nativeSources.set(replacement, originalToString);
      Object.defineProperty(Function.prototype, "toString", {
        configurable: true,
        writable: true,
        value: replacement,
      });
    }
  } catch {}

  const skipReports = new WeakMap();
  const primitiveSkipReports = new Set();

  /** Emits `hook.skipped` the first time a given property is passed over. */
  const reportSkippedOnce = (owner, key, reason) => {
    try {
      // A WeakMap rejects primitive keys, and a page can set `globalThis.sm4`
      // to a string. Those still need deduping — the probe retries every 500ms
      // up to 120 times, so an undeduped branch floods the log just as badly as
      // the one this replaced. A plain Set keyed by value works because a
      // primitive is its own identity.
      if (owner === null || (typeof owner !== "object" && typeof owner !== "function")) {
        const marker = `${typeof owner}:${String(owner)}:${String(key)}`;
        if (primitiveSkipReports.has(marker)) return;
        primitiveSkipReports.add(marker);
        emit({ kind: "runtime", name: "hook.skipped", input: { property: String(key), reason }, output: null });
        return;
      }
      let seen = skipReports.get(owner);
      if (!seen) {
        seen = new Set();
        skipReports.set(owner, seen);
      }
      const name = String(key);
      if (seen.has(name)) return;
      seen.add(name);
      emit({ kind: "runtime", name: "hook.skipped", input: { property: name, reason }, output: null });
    } catch {}
  };

  /**
   * True when `key` resolves to an accessor anywhere on the prototype chain.
   *
   * The walk is depth-bounded because a Proxy can return itself from a
   * `getPrototypeOf` trap, and an ordinary `for` loop over such a chain never
   * terminates. This runs on a 500ms interval on the page's main thread, so an
   * unbounded walk would hang the tab outright — and hostile prototypes are
   * exactly what this file exists to survive.
   */
  const inheritedAccessor = (owner, key) => {
    let node = owner;
    for (let depth = 0; node && depth < 100; depth += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(node, key);
      if (descriptor) return typeof descriptor.get === "function" || typeof descriptor.set === "function";
      node = Object.getPrototypeOf(node);
    }
    // Bound exhausted without an answer. Only a pathological chain gets here, so
    // report "accessor" and decline to wrap: a chain we could not inspect is not
    // one to install a data property onto.
    return Boolean(node);
  };

  const replace = (owner, key, factory) => {
    if (!owner) return false;
    // Reading the property can trip a throwing getter, and building the wrapper
    // runs page-supplied code, so both sit inside the guard.
    let original;
    let wrapped;
    try {
      // An accessor is left alone. Replacing one with a data property would
      // shadow the getter for good, losing whatever per-access work it does and
      // silently disabling the matching setter.
      if (inheritedAccessor(owner, key)) {
        // Wrapping would flatten the accessor into a data property, losing its
        // per-access behaviour. Skipping is the safe choice, but it is a hole in
        // what gets captured, so it is reported — once. The library probe retries
        // on a 500ms interval up to 120 times, so reporting on every pass would
        // bury the log an operator reads under a thousand copies of one fact.
        reportSkippedOnce(owner, key, "accessor");
        return false;
      }
      original = owner[key];
      if (typeof original !== "function" || wrappedFunctions.has(original)) return false;
      wrapped = factory(original);
    } catch { return false; }
    try {
      // `window.fetch.name === "shownetFetch"` was a one-property check that
      // named the product doing the hooking, and `fetch.length` disagreed with
      // the original's arity. Both are copied across.
      Object.defineProperty(wrapped, "name", {
        configurable: true,
        value: Reflect.get(original, "name"),
      });
      Object.defineProperty(wrapped, "length", {
        configurable: true,
        value: Reflect.get(original, "length"),
      });
      // Not an own property: `Object.getOwnPropertySymbols(fetch)` returned one
      // entry on every wrapper and none on any native function, and the key was
      // in the global registry so a page could read it back by name.
      wrappedFunctions.add(wrapped);
      // No own `toString` here: an own toString on a native-looking function is
      // itself a tell, and it does not survive
      // `Function.prototype.toString.call(wrapper)`, which is what probes
      // actually use. The prototype method is proxied once instead, below.
      nativeSources.set(wrapped, original);
      // An inherited method has no own descriptor to copy, and defineProperty's
      // defaults would install it non-writable and non-configurable, so the page
      // could never reassign or delete its own method again. Restore writability
      // without also making it enumerable: a prototype method is never an own
      // enumerable key, and inventing one changes Object.keys, for...in, object
      // spread and structuredClone on every instance.
      const existing = Object.getOwnPropertyDescriptor(owner, key)
        ?? { writable: true, enumerable: false, configurable: true };
      Object.defineProperty(owner, key, { ...existing, value: wrapped });
      return true;
    } catch { return false; }
  };

  replace(globalThis, "fetch", (original) => function shownetFetch(resource, init) {
    const started = performance.now();
    // Reading `resource.url`, `.method`, `.headers` and `.credentials` runs
    // page-supplied getters, so it happens once, defensively, and never on the
    // path to issuing the request. Doing it inline ahead of the real fetch meant
    // a throwing getter aborted the request the page had asked for.
    const describe = () => {
      try {
        return {
          url: typeof resource === "string" ? resource : resource?.url,
          method: String(init?.method || resource?.method || "GET").toUpperCase(),
          input: {
            headers: headerEntries(init?.headers || resource?.headers),
            credentials: init?.credentials || resource?.credentials,
            body: init?.body,
          },
        };
      } catch { return { url: undefined, method: "GET", input: "[Unavailable]" }; }
    };
    const report = (output) => {
      try {
        const { url, method, input } = describe();
        emit({ kind: "network", name: "window.fetch", url, method, input, output, durationMs: performance.now() - started });
      } catch {}
    };
    let promise;
    try { promise = Reflect.apply(original, this, arguments); } catch (error) {
      // Report best-effort, then rethrow what fetch actually threw. Describing
      // the failed call must not become the failure the page sees.
      report({ error });
      throw error;
    }
    // Observing the result must not change what the caller gets back, and a
    // caller that hands us a thenable-less value must still get it back.
    try {
      promise.then(
        (response) => {
          // Reading the response also runs page code when it is a proxy, and a
          // throw here would surface as an unhandledrejection on the page —
          // observable to exactly the scripts this runtime watches.
          try {
            report({ status: response.status, ok: response.ok, redirected: response.redirected, headers: headerEntries(response.headers) });
          } catch { report({ error: "[Unavailable]" }); }
        },
        (error) => report({ error }),
      );
    } catch {}
    return promise;
  });

  if (globalThis.XMLHttpRequest) {
    const xhrState = new WeakMap();
    replace(XMLHttpRequest.prototype, "open", (original) => function shownetXhrOpen(method, url) {
      xhrState.set(this, { method: String(method || "GET").toUpperCase(), url: String(url || ""), started: 0, body: undefined, headers: [] });
      return Reflect.apply(original, this, arguments);
    });
    replace(XMLHttpRequest.prototype, "setRequestHeader", (original) => function shownetXhrSetRequestHeader(name, value) {
      const state = xhrState.get(this) || { method: "GET", url: "", started: 0, headers: [] };
      state.headers.push({ name: String(name || ""), value: String(value || "") });
      xhrState.set(this, state);
      return Reflect.apply(original, this, arguments);
    });
    replace(XMLHttpRequest.prototype, "send", (original) => function shownetXhrSend(body) {
      const state = xhrState.get(this) || { method: "GET", url: "", started: 0, headers: [] };
      state.started = performance.now();
      state.body = body;
      xhrState.set(this, state);
      // Registered before send so a synchronous XHR is still observed, but
      // guarded: a page that shadows addEventListener must not be able to
      // cancel its own request through our listener.
      try {
        // The callback body reads responseURL/status/withCredentials, which a
        // fingerprinting page can redefine as throwing getters. A throw inside
        // DOM dispatch cannot stop the request, but it does raise an uncaught
        // error on window for every XHR — so the body is guarded too, not just
        // the addEventListener call.
        this.addEventListener("loadend", () => {
          try {
            emit({
              kind: "network", name: "XMLHttpRequest.send", url: this.responseURL || state.url,
              method: state.method, input: { headers: state.headers, body: state.body, withCredentials: this.withCredentials }, output: { status: this.status, responseType: this.responseType, headers: this.getAllResponseHeaders() },
              durationMs: performance.now() - state.started,
            });
          } catch {}
        }, { once: true });
      } catch {}
      return Reflect.apply(original, this, arguments);
    });
  }

  const subtle = globalThis.SubtleCrypto?.prototype;
  for (const operation of ["encrypt", "decrypt", "sign", "verify", "digest", "deriveBits", "deriveKey", "generateKey", "importKey", "exportKey", "wrapKey", "unwrapKey"]) {
    replace(subtle, operation, (original) => function shownetSubtleOperation() {
      const started = performance.now();
      let promise;
      try { promise = Reflect.apply(original, this, arguments); } catch (error) {
        emit({ kind: "crypto", name: `crypto.subtle.${operation}`, input: [...arguments], output: { error }, durationMs: performance.now() - started });
        throw error;
      }
      try {
        promise.then(
          (result) => emit({ kind: "crypto", name: `crypto.subtle.${operation}`, input: [...arguments], output: result, durationMs: performance.now() - started }),
          (error) => emit({ kind: "crypto", name: `crypto.subtle.${operation}`, input: [...arguments], output: { error }, durationMs: performance.now() - started }),
        );
      } catch {}
      return promise;
    });
  }

  const wrapLibraryMethod = (owner, key, name) => replace(owner, key, (original) => function shownetLibraryHook() {
    const started = performance.now();
    try {
      const result = Reflect.apply(original, this, arguments);
      emit({ kind: "crypto", name, input: [...arguments], output: result, durationMs: performance.now() - started });
      return result;
    } catch (error) {
      emit({ kind: "crypto", name, input: [...arguments], output: { error }, durationMs: performance.now() - started });
      throw error;
    }
  });

  let libraryAttempts = 0;
  const libraryTimer = setInterval(() => {
    libraryAttempts += 1;
    // Reading these globals runs page code. Unguarded, a throwing getter on
    // `CryptoJS` dispatched an uncaught error to the page every 500 ms for a
    // minute — plainly visible to anything listening on window.onerror.
    try { probeCryptoLibraries(); } catch {}
    if (libraryAttempts >= 120) clearInterval(libraryTimer);
  }, 500);

  function probeCryptoLibraries() {
    const CryptoJS = globalThis.CryptoJS;
    if (CryptoJS) {
      for (const algorithm of ["AES", "DES", "TripleDES", "Rabbit", "RC4"]) {
        for (const operation of ["encrypt", "decrypt"]) wrapLibraryMethod(CryptoJS[algorithm], operation, `CryptoJS.${algorithm}.${operation}`);
      }
      for (const operation of ["MD5", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512", "HmacMD5", "HmacSHA1", "HmacSHA256", "HmacSHA512", "PBKDF2"]) {
        wrapLibraryMethod(CryptoJS, operation, `CryptoJS.${operation}`);
      }
    }
    const sm2 = globalThis.sm2 || globalThis.SM2;
    for (const operation of ["doEncrypt", "doDecrypt", "doSignature", "doVerifySignature", "encrypt", "decrypt", "sign", "verify"]) {
      wrapLibraryMethod(sm2, operation, `sm2.${operation}`);
    }
    const sm3 = globalThis.sm3 || globalThis.SM3;
    if (typeof sm3 === "function") wrapLibraryMethod(globalThis, globalThis.sm3 === sm3 ? "sm3" : "SM3", "sm3");
    const sm4 = globalThis.sm4 || globalThis.SM4;
    for (const operation of ["encrypt", "decrypt"]) wrapLibraryMethod(sm4, operation, `sm4.${operation}`);
  }

  const cookieDescriptor = globalThis.Document && Object.getOwnPropertyDescriptor(Document.prototype, "cookie");
  if (cookieDescriptor?.get && cookieDescriptor?.set) {
    try {
      Object.defineProperty(Document.prototype, "cookie", {
        configurable: cookieDescriptor.configurable,
        enumerable: cookieDescriptor.enumerable,
        get: cookieDescriptor.get,
        // Same reason as above: a real accessor is not constructible and has no
        // `prototype`, so the setter is defined as a method, not an expression.
        set: registerNative({ set(value) {
          // The write goes first and unconditionally. Reporting the cookie used
          // to happen before it, so anything that went wrong while describing
          // the cookie meant the cookie was never stored at all — a challenge
          // page that cannot keep its clearance cookie reloads forever.
          const result = Reflect.apply(cookieDescriptor.set, this, [value]);
          try {
            const text = String(value || "");
            const [pair, ...attributes] = text.split(";");
            const name = pair.split("=")[0]?.trim();
            emit({ kind: "storage", name: "document.cookie.set", input: { name, value: text, attributes: attributes.map((item) => item.trim()) }, output: null });
          } catch {}
          return result;
        } }.set, cookieDescriptor.set),
      });
    } catch {}
  }

  replace(globalThis.Storage?.prototype, "setItem", (original) => function shownetStorageSetItem(key, value) {
    const result = Reflect.apply(original, this, arguments);
    try {
      emit({ kind: "storage", name: "Storage.prototype.setItem", input: { key: String(key || ""), value }, output: null });
    } catch {}
    return result;
  });

  const formValue = (target) => {
    if (!target) return { value: undefined };
    const snapshot = { value: target.value };
    if ("checked" in target) snapshot.checked = Boolean(target.checked);
    if (target.files) {
      snapshot.files = [...target.files].map((file) => ({
        name: file.name,
        type: file.type,
        size: file.size,
        lastModified: file.lastModified,
      }));
    }
    return snapshot;
  };

  // `selector` and `formValue` read page-controlled properties, and they run in
  // the listener's frame rather than inside emit. A throw here cannot stop
  // dispatch, but it does surface as an uncaught error on every click.
  const observe = (build) => (event) => {
    try { emit(build(event)); } catch {}
  };

  addEventListener("click", observe((event) => ({ kind: "interaction", name: "pointer.click", input: { selector: selector(event.target), button: event.button, x: event.clientX, y: event.clientY }, output: null })), true);
  addEventListener("input", observe((event) => ({ kind: "interaction", name: "form.input", input: { selector: selector(event.target), inputType: event.inputType, ...formValue(event.target) }, output: null })), true);

  // Agent-facing lab surface: fixed params / dump / hijack logs without replacing core hooks.
  globalThis.__SHOWNET_LAB__ = Object.assign(globalThis.__SHOWNET_LAB__ || {}, {
    version: "hook-runtime/1.2",
    emit,
    scrub,
    getQueue: () => (globalThis[QUEUE] || []).slice(-200),
    dumpPaths: (paths = []) => {
      const resolve = (path) => {
        try {
          return String(path).split(".").reduce((object, key) => (object == null ? undefined : object[key]), globalThis);
        } catch (error) {
          return { error: String(error) };
        }
      };
      const report = {};
      for (const path of paths) report[path] = scrub(resolve(path));
      emit({ kind: "runtime", name: "object.dump", input: { paths }, output: report });
      return report;
    },
    setFixedNote: (profile) => {
      globalThis.__SHOWNET_FIXED_PROFILE__ = profile || globalThis.__SHOWNET_FIXED_PROFILE__;
      emit({ kind: "runtime", name: "fixed.profile", input: { profile: globalThis.__SHOWNET_FIXED_PROFILE__ }, output: { ok: true } });
      return globalThis.__SHOWNET_FIXED_PROFILE__;
    },
  });
})();
