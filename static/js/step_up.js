/* Step-up: require a fresh passkey assertion before submitting a form.
 *
 * Usage: <form data-step-up-purpose="api_token_create"> ... <output data-step-up-status>
 * On submit, runs /webauthn/step-up/start/ -> navigator.credentials.get() ->
 * /webauthn/step-up/finish/, then submits the form natively. The server
 * independently refuses the form POST unless the one-shot grant is fresh, so
 * this script is a convenience, not the control.
 */
(() => {
  "use strict";

  function b64uToBytes(s) {
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    const bin = atob(s);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }

  function bytesToB64u(buf) {
    const bytes = new Uint8Array(buf);
    let bin = "";
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function csrfToken(form) {
    const field = form.querySelector("input[name=csrfmiddlewaretoken]");
    return field ? field.value : "";
  }

  async function postJSON(url, body, token) {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRFToken": token },
      body: JSON.stringify(body || {}),
      credentials: "same-origin",
    });
    if (!res.ok) throw new Error("step-up failed");
    return res.json();
  }

  function decodeOptions(options) {
    options.challenge = b64uToBytes(options.challenge);
    if (Array.isArray(options.allowCredentials)) {
      options.allowCredentials = options.allowCredentials.map((c) => ({ ...c, id: b64uToBytes(c.id) }));
    }
    return options;
  }

  function assertionPayload(credential) {
    return {
      id: credential.id,
      rawId: bytesToB64u(credential.rawId),
      type: credential.type,
      response: {
        clientDataJSON: bytesToB64u(credential.response.clientDataJSON),
        authenticatorData: bytesToB64u(credential.response.authenticatorData),
        signature: bytesToB64u(credential.response.signature),
        userHandle: credential.response.userHandle ? bytesToB64u(credential.response.userHandle) : null,
      },
      clientExtensionResults: credential.getClientExtensionResults ? credential.getClientExtensionResults() : {},
    };
  }

  document.querySelectorAll("form[data-step-up-purpose]").forEach((form) => {
    const status = form.querySelector("[data-step-up-status]");
    const submit = form.querySelector("button[type=submit]");
    function show(text, kind) {
      if (!status) return;
      status.textContent = text;
      status.className = "status " + (kind || "");
    }

    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (!form.reportValidity()) return;
      if (submit) submit.disabled = true;
      show("Confirm with your passkey…");
      const token = csrfToken(form);
      try {
        const options = await postJSON("/webauthn/step-up/start/", { purpose: form.dataset.stepUpPurpose }, token);
        const credential = await navigator.credentials.get({ publicKey: decodeOptions(options) });
        await postJSON("/webauthn/step-up/finish/", assertionPayload(credential), token);
        show("Confirmed. Creating token…", "success");
        HTMLFormElement.prototype.submit.call(form);
      } catch (_err) {
        show("Passkey confirmation failed. Try again.", "error");
        if (submit) submit.disabled = false;
      }
    });
  });
})();
