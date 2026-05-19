(() => {
  const helpers = window.GatekeeperChallenge;
  if (!helpers) {
    return;
  }

  window.addEventListener("DOMContentLoaded", () => {
    const state = helpers.init();
    const dummyButton = document.getElementById("dummy-submit-button");

    if (!state || state.verificationMode !== "dummy" || !dummyButton) {
      return;
    }

    if (state.rateLimited) {
      dummyButton.disabled = true;
      return;
    }

    let animationInFlight = false;
    dummyButton.addEventListener("click", (event) => {
      if (animationInFlight) {
        event.preventDefault();
        return;
      }

      event.preventDefault();
      animationInFlight = true;
      dummyButton.disabled = true;
      state.setStatus(state.messages.dummy_progress_running || "");

      const start = performance.now();
      const duration = 3000;

      const animate = (timestamp) => {
        const elapsed = timestamp - start;
        const progress = Math.min(100, (elapsed / duration) * 100);
        state.setProgress(progress);

        if (elapsed < duration) {
          window.requestAnimationFrame(animate);
          return;
        }

        state.setStatus(state.messages.progress_complete || "");
        state.submit();
      };

      state.setProgress(0);
      window.requestAnimationFrame(animate);
    });
  });
})();
