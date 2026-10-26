/* interlock cloud review UI: WebAuthn step-up.
 *
 * TOTP is the always-available path and needs no JavaScript. This file adds
 * a passkey assertion for browsers that support one. It is same-origin, has
 * no dependencies, and does nothing until the reviewer presses the button.
 */
(function () {
  "use strict";

  function decodeChallenge(value) {
    var padded = value.replace(/-/g, "+").replace(/_/g, "/");
    while (padded.length % 4) { padded += "="; }
    var raw = window.atob(padded);
    var bytes = new Uint8Array(raw.length);
    for (var i = 0; i < raw.length; i += 1) { bytes[i] = raw.charCodeAt(i); }
    return bytes;
  }

  function encodeCredential(credential) {
    var response = credential.response;
    var bytes = new Uint8Array(response.signature);
    var signature = "";
    for (var i = 0; i < bytes.length; i += 1) {
      signature += String.fromCharCode(bytes[i]);
    }
    return JSON.stringify({
      credential: {
        id: credential.id,
        rawId: window.btoa(String.fromCharCode.apply(null, new Uint8Array(credential.rawId))),
        type: credential.type,
        response: {
          clientDataJSON: window.btoa(String.fromCharCode.apply(null, new Uint8Array(response.clientDataJSON))),
          authenticatorData: window.btoa(String.fromCharCode.apply(null, new Uint8Array(response.authenticatorData))),
          signature: window.btoa(signature)
        }
      },
      sign_count: 0
    });
  }

  function submitAssertion(button, assertion) {
    var csrf = document.querySelector('input[name="csrf"]');
    var form = document.createElement("form");
    form.method = "post";
    form.action = button.getAttribute("data-action");
    var fields = {
      csrf: csrf ? csrf.value : "",
      method: "webauthn",
      challenge_id: button.getAttribute("data-challenge") || "",
      assertion: assertion
    };
    Object.keys(fields).forEach(function (name) {
      var input = document.createElement("input");
      input.type = "hidden";
      input.name = name;
      input.value = fields[name];
      form.appendChild(input);
    });
    document.body.appendChild(form);
    form.submit();
  }

  document.addEventListener("click", function (event) {
    var button = event.target.closest("[data-stepup-webauthn]");
    if (!button) { return; }
    if (!window.PublicKeyCredential || !navigator.credentials) {
      window.alert("This browser does not support passkeys; use a one-time code.");
      return;
    }
    event.preventDefault();
    button.disabled = true;
    navigator.credentials.get({
      publicKey: {
        challenge: decodeChallenge(button.getAttribute("data-challenge") || ""),
        timeout: 60000,
        userVerification: "required"
      }
    }).then(function (credential) {
      submitAssertion(button, encodeCredential(credential));
    }).catch(function () {
      button.disabled = false;
      window.alert("The passkey prompt was cancelled; use a one-time code.");
    });
  });
}());
