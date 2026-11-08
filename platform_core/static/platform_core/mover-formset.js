(() => {
  const form = document.querySelector("[data-role-form]");
  if (!form) return;
  const total = form.querySelector("[name='entries-TOTAL_FORMS']");
  const target = form.querySelector("[data-role-entries]");
  const template = form.querySelector("[data-role-entry]");
  const add = form.querySelector("[data-role-add]");
  add.hidden = false;
  add.disabled = Number(total.value) >= 20;
  add.addEventListener("click", () => {
    const index = Number(total.value);
    if (!Number.isInteger(index) || index < 0 || index >= 20) return;
    const fragment = template.content.cloneNode(true);
    for (const node of fragment.querySelectorAll("[name], [id], [for], [aria-describedby]")) {
      for (const key of ["name", "id", "for", "aria-describedby"]) {
        if (node.hasAttribute(key)) {
          node.setAttribute(key, node.getAttribute(key).replaceAll("__prefix__", String(index)));
        }
      }
    }
    target.append(fragment);
    total.value = String(index + 1);
    add.disabled = index + 1 >= 20;
    target.lastElementChild.querySelector("select")?.focus();
  });
})();
