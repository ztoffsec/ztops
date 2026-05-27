/* Embed images into a markdown editor by paste / drag-drop.
 *
 * Activates on any element carrying data-image-upload-url that contains a
 * <textarea>. Pasted or dropped image files are POSTed to that URL, which
 * re-encodes them server-side and returns {url, filename}; we then insert a
 * markdown image reference at the cursor. Non-image data is ignored (normal
 * paste/drop behaviour is preserved).
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

  function uploadAndInsert(url, ta, file) {
    if (!file || file.type.indexOf("image/") !== 0) return;
    var tag = "![uploading " + (file.name || "image") + "…]()";
    insertAtCursor(ta, tag);
    var fd = new FormData();
    fd.append("image", file);
    fetch(url, {
      method: "POST",
      headers: { "X-CSRFToken": csrfToken() },
      body: fd,
      credentials: "same-origin",
    })
      .then(function (r) {
        if (!r.ok) throw new Error("upload failed");
        return r.json();
      })
      .then(function (data) {
        replaceOnce(ta, tag, "![" + (data.filename || "image") + "](" + data.url + ")");
      })
      .catch(function () {
        replaceOnce(ta, tag, "![image upload failed]()");
      });
  }

  function imageFiles(list) {
    var out = [];
    for (var i = 0; i < (list ? list.length : 0); i++) {
      if (list[i].type && list[i].type.indexOf("image/") === 0) out.push(list[i]);
    }
    return out;
  }

  document.querySelectorAll("[data-image-upload-url]").forEach(function (wrap) {
    var url = wrap.getAttribute("data-image-upload-url");
    var ta = wrap.querySelector("textarea");
    if (!url || !ta) return;

    ta.addEventListener("paste", function (e) {
      var items = (e.clipboardData || {}).items || [];
      for (var i = 0; i < items.length; i++) {
        if (items[i].kind === "file") {
          var file = items[i].getAsFile();
          if (file && file.type.indexOf("image/") === 0) {
            e.preventDefault();
            uploadAndInsert(url, ta, file);
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
      imgs.forEach(function (f) { uploadAndInsert(url, ta, f); });
    });
  });
})();
