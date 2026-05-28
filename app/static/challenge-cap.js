(() => {
  const helpers = window.CryKeeperChallenge;
  if (!helpers) {
    return;
  }

  const bootstrapForm = document.getElementById("verification-form");
  if (bootstrapForm) {
    const providerOptions = helpers.parseJson(bootstrapForm.dataset.providerOptions);
    if (providerOptions.wasmUrl) {
      window.CAP_CUSTOM_WASM_URL = providerOptions.wasmUrl;
    }
  }

  const hideActionButton = (button) => {
    if (button) {
      button.classList.add("is-hidden");
    }
  };

  const showActionButton = (button, label) => {
    if (button) {
      button.textContent = label;
      button.classList.remove("is-hidden");
    }
  };

  window.addEventListener("DOMContentLoaded", () => {
    const state = helpers.init();
    const tokenInput = document.getElementById("cap-token");
    const actionButton = state?.actionButton();

    if (!state || state.verificationMode !== "cap" || !tokenInput || !actionButton) {
      return;
    }

    const capApiEndpoint = state.providerOptions.apiEndpoint || "";

    if (state.rateLimited) {
      actionButton.disabled = true;
      return;
    }

    let cap = null;
    let solveInFlight = false;

    const startVerification = async () => {
      if (!cap || solveInFlight) {
        return;
      }

      state.clearError();
      tokenInput.value = "";
      solveInFlight = true;
      hideActionButton(actionButton);
      state.setProgress(0);
      state.setStatus(state.messages.progress_checking || "");

      try {
        const result = await cap.solve();
        tokenInput.value = result.token;
        state.setProgress(100);
        state.setStatus(state.messages.progress_verifying || "");
        state.submit();
      } catch {
        solveInFlight = false;
        state.setProgress(0);
        state.setStatus(state.messages.status_retry_ready || "");
        showActionButton(actionButton, state.messages.retry_button || "Retry");
        state.showError(state.messages.error_failed);
      }
    };

    actionButton.addEventListener("click", () => {
      if (typeof window.Cap !== "function") {
        window.location.reload();
        return;
      }

      void startVerification();
    });

    if (typeof window.Cap !== "function" || !capApiEndpoint) {
      state.setProgress(0);
      state.setStatus(state.messages.status_reload_ready || "");
      state.showError(state.messages.error_widget_load);
      showActionButton(actionButton, state.messages.reload_button || "Reload");
      return;
    }

    cap = new window.Cap({ apiEndpoint: capApiEndpoint });

    cap.addEventListener("progress", (event) => {
      const progress = event.detail?.progress;
      if (solveInFlight && typeof progress === "number") {
        state.setProgress(progress);
        state.setStatus(state.messages.progress_checking || "");
      }
    });

    cap.addEventListener("error", () => {
      tokenInput.value = "";
      solveInFlight = false;
      state.setProgress(0);
      state.setStatus(state.messages.status_retry_ready || "");
      showActionButton(actionButton, state.messages.retry_button || "Retry");
      state.showError(state.messages.error_widget_runtime);
    });

    if (state.shouldAutoStart) {
      void startVerification();
      return;
    }

    state.setProgress(0);
    state.setStatus(state.messages.status_retry_ready || "");
    showActionButton(actionButton, state.messages.retry_button || "Retry");
  });
})();
