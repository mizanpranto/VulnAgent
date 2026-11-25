(function () {
  var form = document.getElementById("scan-form");
  var input = document.getElementById("archive");
  var drop = document.getElementById("drop");
  var picked = document.getElementById("picked");
  var submit = document.getElementById("submit");
  var errorBox = document.getElementById("error");
  var ai = document.getElementById("ai");
  var discover = document.getElementById("discover");
  var aiStatus = document.getElementById("ai-status");
  var MAX = 50 * 1024 * 1024;

  function showError(message) {
    errorBox.textContent = message;
    errorBox.className = "err" + (message ? " show" : "");
  }

  function size(bytes) {
    return bytes > 1048576 ? (bytes / 1048576).toFixed(1) + " MB" : Math.max(1, Math.round(bytes / 1024)) + " KB";
  }

  function check() {
    var file = input.files[0];
    showError("");
    drop.classList.toggle("has-file", !!file);
    submit.disabled = true;
    if (!file) { return; }
    picked.textContent = file.name + " (" + size(file.size) + ")";
    if (!/\.zip$/i.test(file.name)) { showError("Only .zip files are accepted."); return; }
    if (file.size > MAX) { showError("That file is larger than the 50 MB limit."); return; }
    submit.disabled = false;
  }

  input.addEventListener("change", check);
  ["dragenter", "dragover"].forEach(function (name) {
    drop.addEventListener(name, function (event) { event.preventDefault(); drop.classList.add("over"); });
  });
  ["dragleave", "drop"].forEach(function (name) {
    drop.addEventListener(name, function () { drop.classList.remove("over"); });
  });
  drop.addEventListener("drop", function (event) {
    event.preventDefault();
    if (event.dataTransfer.files.length) { input.files = event.dataTransfer.files; check(); }
  });
  // Remember report details (not the logo) in this browser only.
  var KEY = "vulnagent.report-details";
  var remember = document.getElementById("remember");
  var fields = form.querySelectorAll('.fields input[type="text"], .fields select, .fields input[type="date"]');
  try {
    var saved = JSON.parse(window.localStorage.getItem(KEY) || "{}");
    Array.prototype.forEach.call(fields, function (el) {
      if (saved[el.name] && el.name !== "report_date") { el.value = saved[el.name]; }
    });
  } catch (e) { /* storage unavailable: the form still works */ }
  function saveDetails() {
    try {
      if (!remember.checked) { window.localStorage.removeItem(KEY); return; }
      var out = {};
      Array.prototype.forEach.call(fields, function (el) { out[el.name] = el.value; });
      window.localStorage.setItem(KEY, JSON.stringify(out));
    } catch (e) { /* ignore */ }
  }

  discover.addEventListener("change", function () { if (discover.checked) { ai.checked = true; } });

  fetch("/api/status").then(function (r) { return r.json(); }).then(function (info) {
    var chip = document.createElement("span");
    chip.className = "pill-status";
    if (info.ollama) {
      chip.textContent = "Ollama is running with " + info.model;
    } else {
      chip.textContent = "Ollama not detected. Only static analysis will run.";
      ai.checked = false; ai.disabled = true; discover.disabled = true;
    }
    aiStatus.textContent = "";
    aiStatus.appendChild(chip);
  }).catch(function () { aiStatus.textContent = ""; });

  form.addEventListener("submit", function (event) {
    event.preventDefault();
    if (submit.disabled) { return; }
    submit.disabled = true;
    submit.textContent = "Uploading…";
    saveDetails();
    var data = new FormData(form);
    if (!ai.checked) { data.delete("ai"); }
    fetch("/api/scans", { method: "POST", body: data })
      .then(function (r) { return r.json().then(function (body) { return { ok: r.ok, body: body }; }); })
      .then(function (res) {
        if (!res.ok) { throw new Error(res.body.error || "Upload failed."); }
        window.location.href = res.body.url;
      })
      .catch(function (error) {
        showError(error.message || "Upload failed.");
        submit.textContent = "Scan archive";
        submit.disabled = false;
      });
  });
})();
