"use strict";
// Display only: the server independently validates and constructs the callback.
const realm = document.getElementById("id_slug");
const preview = document.getElementById("oidc-callback-preview");
if (realm && preview) {
  const update = () => {
    const slug = realm.value;
    preview.textContent = /^[a-zA-Z0-9_-]{1,50}$/.test(slug)
      ? preview.dataset.pattern.replace("/__realm__/", "/" + slug + "/")
      : "Saisissez un identifiant de domaine valide (lettres, chiffres, tiret ou soulignement).";
  };
  realm.addEventListener("input", update);
  update();
}
