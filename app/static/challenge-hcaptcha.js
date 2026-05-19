(() => {
  const helpers = window.GatekeeperChallenge;
  if (!helpers) {
    return;
  }

  window.addEventListener("DOMContentLoaded", () => {
    const state = helpers.init();
    const widgetContainer = document.getElementById("hcaptcha-widget");

    if (!state || state.verificationMode !== "hcaptcha" || !widgetContainer) {
      return;
    }

    if (state.rateLimited) {
      return;
    }

    const siteKey = state.providerOptions.siteKey || "";
    if (!siteKey) {
      state.setStatus(state.messages.status_reload_ready || "");
      state.showError(state.messages.error_widget_load);
      return;
    }

    let attempts = 0;
    let widgetId = null;

    const startVerification = () => {
      if (
        typeof window.hcaptcha !== "object"
        || typeof window.hcaptcha.execute !== "function"
        || widgetId === null
      ) {
        state.setStatus(state.messages.status_reload_ready || "");
        state.showError(state.messages.error_widget_load);
        return;
      }

      state.clearError();
      state.setProgress(10);
      state.setStatus(state.messages.progress_checking || "");
      window.hcaptcha.execute(widgetId);
    };

    const onError = (message) => {
      state.setProgress(0);
      state.setStatus(state.messages.status_hcaptcha_ready || "");
      state.showError(message || state.messages.error_widget_runtime);
    };

    const renderWidget = () => {
      if (typeof window.hcaptcha !== "object" || typeof window.hcaptcha.render !== "function") {
        attempts += 1;
        if (attempts < 30) {
          window.setTimeout(renderWidget, 200);
          return;
        }

        state.setStatus(state.messages.status_reload_ready || "");
        state.showError(state.messages.error_widget_load);
        return;
      }

      widgetId = window.hcaptcha.render(widgetContainer, {
        sitekey: siteKey,
        size: "normal",
        callback() {
          state.clearError();
          state.setProgress(100);
          state.setStatus(state.messages.progress_verifying || "");
          state.submit();
        },
        "error-callback"() {
          onError(state.messages.error_widget_runtime);
        },
        "expired-callback"() {
          onError(state.messages.error_failed);
        },
      });

      state.setProgress(10);
      state.setStatus(state.messages.status_hcaptcha_ready || "");
      if (state.shouldAutoStart) {
        startVerification();
        return;
      }
    };

    renderWidget();
  });
})();
