// 勾選全部
document.addEventListener("change", function (e) {
  if (e.target.matches("input[data-check-all]")) {
    var form = e.target.closest("form");
    form.querySelectorAll("input[name=ids]").forEach(function (c) { c.checked = e.target.checked; });
  }
});
// 送出前確認
document.addEventListener("submit", function (e) {
  var b = e.submitter;
  var msg = (b && b.dataset.confirm) || e.target.dataset.confirm;
  if (msg && !window.confirm(msg)) { e.preventDefault(); }
});
