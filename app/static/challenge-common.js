(() => {
  const returnFragmentStorageKey = (returnPath) =>
    `crykeeper:return-fragment:${returnPath || "/"}`;

  const storeReturnFragment = (returnPath, fragment) => {
    if (!returnPath) {
      return;
    }

    try {
      if (fragment) {
        window.sessionStorage.setItem(
          returnFragmentStorageKey(returnPath),
          fragment,
        );
      } else {
        window.sessionStorage.removeItem(returnFragmentStorageKey(returnPath));
      }
    } catch { /* noop */ }
  };

  const takeReturnFragment = (returnPath) => {
    if (!returnPath) {
      return "";
    }

    try {
      const fragment =
        window.sessionStorage.getItem(returnFragmentStorageKey(returnPath)) || "";
      window.sessionStorage.removeItem(returnFragmentStorageKey(returnPath));
      return fragment.startsWith("#") ? fragment : "";
    } catch {
      return "";
    }
  };

  const parseJson = (rawValue) => {
    if (!rawValue) {
      return {};
    }

    try {
      return JSON.parse(rawValue);
    } catch {
      return {};
    }
  };

  const setProgress = (progressBar, progressPercent, progressShell, value) => {
    const clamped = Math.max(0, Math.min(100, Number(value) || 0));
    const rounded = Math.round(clamped);
    progressBar.style.width = `${rounded}%`;
    progressPercent.textContent = `${rounded}%`;
    progressShell.setAttribute("aria-valuenow", String(rounded));
  };

  const ensureErrorNode = (form) => {
    const existingErrorNode = document.querySelector(".error");
    if (existingErrorNode) {
      return existingErrorNode;
    }

    const errorNode = document.createElement("p");
    errorNode.className = "error";
    form.before(errorNode);
    return errorNode;
  };

  const showError = (form, message) => {
    if (!message) {
      return;
    }

    const errorNode = ensureErrorNode(form);
    errorNode.textContent = message;
  };

  const clearError = () => {
    const errorNode = document.querySelector(".error");
    if (errorNode) {
      errorNode.remove();
    }
  };

  const init = () => {
    const form = document.getElementById("verification-form");
    const returnPathInput = form?.querySelector('[name="return"]');
    const progressBar = document.getElementById("progress-bar");
    const progressPercent = document.getElementById("progress-percent");
    const statusText = document.getElementById("status-text");
    const progressShell = document.querySelector("[role='progressbar']");

    if (!form || !progressBar || !progressPercent || !statusText || !progressShell) {
      return null;
    }

    const syncReturnFragment = () => {
      storeReturnFragment(returnPathInput?.value || "", window.location.hash || "");
    };

    syncReturnFragment();
    window.addEventListener("hashchange", syncReturnFragment);
    form.addEventListener("submit", syncReturnFragment);

    return {
      form,
      progressBar,
      progressPercent,
      progressShell,
      statusText,
      messages: parseJson(form.dataset.clientMessages),
      providerOptions: parseJson(form.dataset.providerOptions),
      rateLimited: form.dataset.rateLimited === "true",
      shouldAutoStart: form.dataset.autoStart === "true",
      verificationMode: form.dataset.verificationMode || "dummy",
      setProgress(value) {
        setProgress(progressBar, progressPercent, progressShell, value);
      },
      setStatus(message) {
        statusText.textContent = message || "";
      },
      showError(message) {
        showError(form, message);
      },
      clearError,
      submit() {
        syncReturnFragment();
        if (typeof form.requestSubmit === "function") {
          form.requestSubmit();
          return;
        }

        form.submit();
      },
      actionButton() {
        return document.getElementById("action-button");
      },
    };
  };

  window.CryKeeperChallenge = {
    init,
    parseJson,
    storeReturnFragment,
    takeReturnFragment,
  };
})();
