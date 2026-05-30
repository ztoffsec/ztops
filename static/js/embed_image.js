/* Embed images into a markdown editor by paste / drag-drop.
 *
 * Each markdown wrapper carries one of two attributes:
 *
 *   data-image-upload-url        the per-finding upload endpoint
 *                                (rendered when a finding already exists)
 *   data-image-upload-create-url the lazy-create endpoint
 *                                (rendered on the new-finding form, where
 *                                 there is no finding id yet)
 *
 * On the new form, the first paste/drop POSTs the current form state plus
 * the image; the server creates the Finding, attaches the image, and
 * returns the new IDs. The client then promotes every create-url wrapper
 * in the form to a regular upload-url wrapper, redirects subsequent
 * submits to the edit URL, and inserts the markdown image reference.
 * From that point on the create form behaves exactly like the edit form.
 */
(function () {
  function csrfToken() {
    var m = document.cookie.match(/(?:^|;\s*)csrftoken=([^;]+)/);
    return m ? decodeURIComponent(m[1]) : "";
  }

  function insertAtCursor(ta, text) {
    var start = ta.selectionStart || 0;
    var end = ta.selectionEnd || 0;
    ta.value = ta.value.slice(0, start) + text + ta.value.slice(end);
    ta.selectionStart = ta.selectionEnd = start + text.length;
    ta.dispatchEvent(new Event("input", { bubbles: true }));
    ta.focus();
  }

  function replaceOnce(ta, needle, replacement) {
    ta.value = ta.value.replace(needle, replacement);
    ta.dispatchEvent(new Event("input", { bubbles: true }));
  }

  function imageFiles(list) {
    var out = [];
    for (var i = 0; i < (list ? list.length : 0); i++) {
      if (list[i].type && list[i].type.indexOf("image/") === 0) out.push(list[i]);
    }
    return out;
  }

  function placeholder(file) {
    return "![uploading " + (file.name || "image") + "…]()";
  }

  /* Normal upload path: POSTs just the image to a per-finding endpoint.
     Used on edit forms and on the create form after lazy-create promoted
     it. */
  function uploadToExisting(url, ta, file) {
    if (!file || file.type.indexOf("image/") !== 0) return;
    var tag = placeholder(file);
    insertAtCursor(ta, tag);
    var fd = new FormData();
    fd.append("image", file);
    fetch(url, {
      method: "POST",
      headers: { "X-CSRFToken": csrfToken() },
      body: fd,
      credentials: "same-origin",
    })
      .then(function (r) { if (!r.ok) throw new Error("upload failed"); return r.json(); })
      .then(function (data) {
        replaceOnce(ta, tag, "![" + (data.filename || "image") + "](" + data.url + ")");
      })
      .catch(function () {
        replaceOnce(ta, tag, "![image upload failed]()");
      });
  }

  /* Promote every create-url wrapper in the form so subsequent images use
     the regular per-finding endpoint. Also retarget the form submit and
     the URL bar to the edit URL the server just allocated. */
  function promoteForm(form, data) {
    form.querySelectorAll("[data-image-upload-create-url]").forEach(function (w) {
      w.removeAttribute("data-image-upload-create-url");
      w.setAttribute("data-image-upload-url", data.image_upload_url);
    });
    if (data.edit_url) {
      form.setAttribute("action", data.edit_url);
      try { history.replaceState(null, "", data.edit_url); } catch (_) { /* ignore */ }
    }
  }

  function formError(data) {
    if (!data || !data.errors) return "image upload failed";
    var names = Object.keys(data.errors);
    if (!names.length) return "image upload failed";
    var first = data.errors[names[0]];
    var msg = (first && first[0] && first[0].message) || "required";
    return "fill the " + names[0] + " field first (" + msg + ")";
  }

  /* Lazy-create path: POSTs the whole form + the image; server creates the
     Finding and attaches the image atomically. */
  function uploadAndCreate(url, ta, file, wrap) {
    if (!file || file.type.indexOf("image/") !== 0) return;
    var form = wrap.closest("form");
    if (!form) { uploadToExisting(url, ta, file); return; }
    var tag = placeholder(file);
    insertAtCursor(ta, tag);
    var fd = new FormData(form);
    fd.append("image", file);
    fetch(url, {
      method: "POST",
      headers: { "X-CSRFToken": csrfToken() },
      body: fd,
      credentials: "same-origin",
    })
      .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, body: j }; }); })
      .then(function (res) {
        if (!res.ok) {
          var hint = res.body && res.body.error === "form_invalid"
            ? formError(res.body)
            : (res.body && res.body.error) || "image upload failed";
          replaceOnce(ta, tag, "![" + hint + "]()");
          return;
        }
        promoteForm(form, res.body);
        replaceOnce(
          ta,
          tag,
          "![" + (res.body.image_filename || "image") + "](" + res.body.image_url + ")",
        );
      })
      .catch(function () {
        replaceOnce(ta, tag, "![image upload failed]()");
      });
  }

  function dispatchUpload(wrap, ta, file) {
    var existing = wrap.getAttribute("data-image-upload-url");
    if (existing) { uploadToExisting(existing, ta, file); return; }
    var create = wrap.getAttribute("data-image-upload-create-url");
    if (create) { uploadAndCreate(create, ta, file, wrap); }
  }

  function wire(wrap) {
    var ta = wrap.querySelector("textarea");
    if (!ta) return;
    ta.addEventListener("paste", function (e) {
      var items = (e.clipboardData || {}).items || [];
      for (var i = 0; i < items.length; i++) {
        if (items[i].kind === "file") {
          var file = items[i].getAsFile();
          if (file && file.type.indexOf("image/") === 0) {
            e.preventDefault();
            dispatchUpload(wrap, ta, file);
          }
        }
      }
    });
    ta.addEventListener("dragover", function (e) {
      if (imageFiles((e.dataTransfer || {}).files).length) e.preventDefault();
    });
    ta.addEventListener("drop", function (e) {
      var imgs = imageFiles((e.dataTransfer || {}).files);
      if (!imgs.length) return;
      e.preventDefault();
      imgs.forEach(function (f) { dispatchUpload(wrap, ta, f); });
    });
  }

  document
    .querySelectorAll("[data-image-upload-url], [data-image-upload-create-url]")
    .forEach(wire);
})();
