(function () {
  var chips = Array.prototype.slice.call(document.querySelectorAll(".chip"));
  var search = document.getElementById("q");
  var rows = Array.prototype.slice.call(document.querySelectorAll("#findings .finding"));
  var count = document.getElementById("count");
  if (!count) { return; }

  function apply() {
    var on = {};
    chips.forEach(function (chip) { on[chip.getAttribute("data-sev")] = chip.getAttribute("aria-pressed") === "true"; });
    var text = (search.value || "").trim().toLowerCase();
    var shown = 0;
    rows.forEach(function (row) {
      var okSev = on[row.getAttribute("data-sev")] !== false;
      var okText = !text || row.getAttribute("data-text").indexOf(text) !== -1;
      row.hidden = !(okSev && okText);
      if (!row.hidden) { shown += 1; }
    });
    count.textContent = "Showing " + shown + " of " + rows.length;
  }

  chips.forEach(function (chip) {
    chip.addEventListener("click", function () {
      chip.setAttribute("aria-pressed", chip.getAttribute("aria-pressed") === "true" ? "false" : "true");
      apply();
    });
  });
  search.addEventListener("input", apply);
  apply();
})();
