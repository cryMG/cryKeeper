(() => {
  const helpers = window.GatekeeperChallenge;
  if (!helpers) {
    return;
  }

  window.addEventListener("DOMContentLoaded", async () => {
    const state = helpers.init();
    const widget = document.getElementById("altcha-widget");

    if (!state || state.verificationMode !== "altcha" || !widget) {
      return;
    }

    if (state.rateLimited) {
      return;
    }

    if (!window.customElements || typeof window.customElements.whenDefined !== "function") {
      state.setStatus(state.messages.status_reload_ready || "");
      state.showError(state.messages.error_widget_load);
      return;
    }

    try {
      await window.customElements.whenDefined("altcha-widget");
    } catch {
      state.setStatus(state.messages.status_reload_ready || "");
      state.showError(state.messages.error_widget_load);
      return;
    }

    const onRuntimeError = () => {
      state.setProgress(0);
      state.setStatus(state.messages.status_retry_ready || state.messages.status_altcha_ready || "");
      state.showError(state.messages.error_widget_runtime);
    };

    widget.addEventListener("load", () => {
      state.setProgress(10);
      state.setStatus(
        state.shouldAutoStart
          ? state.messages.progress_checking || ""
          : state.messages.status_altcha_ready || ""
      );
    });

    widget.addEventListener("statechange", (event) => {
      const widgetState = event.detail?.state;
      if (widgetState === "verifying") {
        state.setProgress(55);
        state.setStatus(state.messages.progress_checking || "");
        return;
      }

      if (widgetState === "verified") {
        state.clearError();
        state.setProgress(100);
        state.setStatus(state.messages.progress_verifying || state.messages.progress_complete || "");
        state.submit();
        return;
      }

      if (widgetState === "error" || widgetState === "expired") {
        onRuntimeError();
      }
    });

    widget.addEventListener("serververification", () => {
      state.setProgress(80);
      state.setStatus(state.messages.progress_verifying || "");
    });

    widget.addEventListener("expired", onRuntimeError);
  });
})();
