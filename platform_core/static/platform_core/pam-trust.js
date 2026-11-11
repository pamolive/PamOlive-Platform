"use strict";

(() => {
  const form = document.getElementById("pam-trust-form");
  if (!form) return;
  const state = JSON.parse(document.getElementById("pam-trust-ceremony").textContent);
  const status = document.getElementById("pam-trust-status");
  const selector = document.getElementById("pam-trust-credential");
  const button = form.querySelector("button");
  const csrf = form.querySelector("input[name='csrfmiddlewaretoken']").value;

  function decode(value) {
    const bytes = atob(value.replace(/-/g, "+").replace(/_/g, "/"));
    return Uint8Array.from(bytes, (character) => character.charCodeAt(0));
  }

  function encode(value) {
    return btoa(String.fromCharCode(...new Uint8Array(value)))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function publicKeyOptions(value) {
    const options = structuredClone(value);
    options.challenge = decode(options.challenge);
    if (options.user) options.user.id = decode(options.user.id);
    for (const name of ["allowCredentials", "excludeCredentials"]) {
      if (options[name]) options[name] = options[name].map((item) => ({...item, id: decode(item.id)}));
    }
    return options;
  }

  function credentialJSON(credential) {
    const response = {clientDataJSON: encode(credential.response.clientDataJSON)};
    for (const name of ["authenticatorData", "attestationObject", "signature", "userHandle"]) {
      if (credential.response[name]) response[name] = encode(credential.response[name]);
    }
    return {id: credential.id, rawId: encode(credential.rawId), type: credential.type, response};
  }

  async function post(body) {
    const response = await fetch(state.endpoint, {
      method: "POST", credentials: "same-origin", cache: "no-store",
      headers: {"Content-Type": "application/json", "X-CSRFToken": csrf},
      body: JSON.stringify(body),
    });
    const result = await response.json();
    if (!response.ok) throw new Error("La preuve PAM a été refusée ou a expiré. Reprenez l’action.");
    return result;
  }

  for (const [index, id] of (state.credentials || []).entries()) {
    const option = document.createElement("option");
    option.value = id;
    option.textContent = `Authentificateur ${index + 1} · ${id.slice(0, 12)}`;
    selector.appendChild(option);
  }
  document.getElementById("pam-trust-credential-label").hidden = selector.options.length < 2;

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    button.disabled = true;
    status.textContent = "Validation de votre authentificateur…";
    try {
      if (!window.isSecureContext || !navigator.credentials) {
        throw new Error("Un navigateur compatible WebAuthn et HTTPS est nécessaire.");
      }
      if (state.mode === "create") {
        const registration = await post({operation: "begin"});
        const created = await navigator.credentials.create({
          publicKey: publicKeyOptions(registration.publicKey),
        });
        const possession = await post({
          operation: "register", challenge: registration.challenge, credential: credentialJSON(created),
        });
        const assertion = await navigator.credentials.get({
          publicKey: publicKeyOptions(possession.publicKey),
        });
        const receipt = await post({
          operation: "finish", enrollment: possession.enrollment, credential: credentialJSON(assertion),
        });
        document.getElementById("pam-trust-enrollment-json").textContent = JSON.stringify(receipt, null, 2);
        document.getElementById("pam-trust-enrollment-result").hidden = false;
        status.textContent = "Possession vérifiée. Soumettez le reçu aux dépositaires.";
        return;
      }
      if (selector.value && selector.value !== state.publicKey.allowCredentials[0].id) {
        Object.assign(state, await post({
          operation: "choose", challenge: state.challenge, credential: selector.value,
        }));
      }
      const assertion = await navigator.credentials.get({publicKey: publicKeyOptions(state.publicKey)});
      const verified = await post({
        operation: "finish", challenge: state.challenge, credential: credentialJSON(assertion),
      });
      if (!verified.resume) {
        status.textContent = "Action authentifiée.";
        form.dispatchEvent(new CustomEvent("pam-action-authenticated", {detail: verified}));
        return;
      }
      if (!verified.resume.path.startsWith("/") || verified.resume.path.startsWith("//")) {
        throw new Error("Reprise d’action invalide.");
      }
      const resume = document.createElement("form");
      resume.method = "POST";
      resume.action = verified.resume.path;
      const fields = [...verified.resume.fields,
        ["csrfmiddlewaretoken", csrf], ["_pam_trust_proof", verified.proof]];
      for (const [name, value] of fields) {
        const input = document.createElement("input");
        input.type = "hidden";
        input.name = name;
        input.value = value;
        resume.appendChild(input);
      }
      document.body.appendChild(resume);
      resume.submit();
    } catch (error) {
      status.textContent = error.name === "NotAllowedError"
        ? "Validation annulée ou expirée. Reprenez l’action." : error.message;
    } finally {
      button.disabled = false;
    }
  });
})();
