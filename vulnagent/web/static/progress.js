(function () {
  var root = document.getElementById("progress");
  var id = root.getAttribute("data-id");
  var bar = document.getElementById("bar");
  var stage = document.getElementById("stage");
  var detail = document.getElementById("detail");
  var errorBox = document.getElementById("error");
  var order = ["extract", "scan", "triage", "discovery", "done"];
  var failures = 0;

  function mark(current) {
    var index = order.indexOf(current);
    Array.prototype.forEach.call(document.querySelectorAll(".stages li"), function (li) {
      var at = order.indexOf(li.getAttribute("data-stage"));
      if (at === index) { li.setAttribute("aria-current", "step"); } else { li.removeAttribute("aria-current"); }
    });
  }

  function poll() {
    fetch("/api/scans/" + encodeURIComponent(id)).then(function (r) {
      if (!r.ok) { throw new Error("gone"); }
      return r.json();
    }).then(function (job) {
      failures = 0;
      stage.textContent = job.stage_label;
      detail.textContent = job.message || "";
      var order_index = Math.max(0, order.indexOf(job.stage));
      var within = job.total ? job.done / job.total : 0;
      bar.value = Math.min(97, Math.round(((order_index + within) / order.length) * 100) + 3);
      mark(job.stage);
      if (job.status === "done" || job.status === "error") { window.location.reload(); return; }
      setTimeout(poll, 900);
    }).catch(function () {
      failures += 1;
      if (failures > 5) {
        errorBox.textContent = "Lost contact with the server. It may have restarted. Start a new scan.";
        errorBox.className = "err show";
        return;
      }
      setTimeout(poll, 1500);
    });
  }
  poll();
})();
