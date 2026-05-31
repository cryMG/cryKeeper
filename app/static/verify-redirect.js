(() => {
  const helpers = window.CryKeeperChallenge;
  if (!helpers || typeof helpers.takeReturnFragment !== "function") {
    return;
  }

  window.addEventListener("DOMContentLoaded", () => {
    const root = document.getElementById("verify-redirect");
    if (!root) {
      return;
    }

    const returnPath = root.dataset.returnPath || "/";
    const fragment = helpers.takeReturnFragment(returnPath);
    window.location.replace(`${returnPath}${fragment}`);
  });
})();
