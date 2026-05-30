(function () {
  var errorHideTimer = null;

  function findStatus(row, name) {
    return row.querySelector('[data-check="' + name + '"]');
  }

  function setStatus(element, className, text) {
    element.classList.remove("status-loading", "status-ok", "status-error");
    element.classList.add(className);
    element.textContent = text;
  }

  function showError(message) {
    var box = document.querySelector("[data-health-error]");
    var text = document.querySelector("[data-health-error-text]");
    if (!box) {
      return;
    }

    if (text) {
      text.textContent = message;
    } else {
      box.textContent = message;
    }
    box.hidden = false;

    if (errorHideTimer) {
      window.clearTimeout(errorHideTimer);
    }
    errorHideTimer = window.setTimeout(hideError, 10000);
  }

  function hideError() {
    var box = document.querySelector("[data-health-error]");
    if (!box) {
      return;
    }

    box.hidden = true;
    if (errorHideTimer) {
      window.clearTimeout(errorHideTimer);
      errorHideTimer = null;
    }
  }

  function buildUrl(path, host) {
    return path + "?host=" + encodeURIComponent(host);
  }

  function requestJson(url) {
    return fetch(url, {
      method: "GET",
      credentials: "same-origin",
      headers: {
        "Accept": "application/json"
      }
    }).then(function (response) {
      return response.json().then(function (data) {
        if (!response.ok) {
          throw new Error(data.error || "HTTP " + response.status);
        }
        return data;
      });
    });
  }

  function formatSuccessfulStatus(kind, data) {
    if (kind === "dns") {
      return formatDnsStatus(data);
    }

    if (kind === "ping") {
      var rtt = data.rtt_avg_ms === null || data.rtt_avg_ms === undefined
        ? "n/a"
        : Number(data.rtt_avg_ms).toFixed(1) + " ms";
      var loss = data.packet_loss_percent === null || data.packet_loss_percent === undefined
        ? "n/a"
        : Number(data.packet_loss_percent).toFixed(0) + "%";
      return "RTT " + rtt + ", loss " + loss;
    }

    var suffix = data.status_code ? " (" + data.status_code + ")" : "";
    return "OK" + suffix;
  }

  function formatDnsStatus(data) {
    var system = data.system || {};
    var google = data.google || {};
    var cloudflare = data.cloudflare || {};

    return formatDnsLine("System", system) +
      "\n" + formatDnsLine("Google", google) +
      "\n" + formatDnsLine("Cloudflare", cloudflare);
  }

  function formatDnsLine(label, result) {
    return (label + ":").padEnd(12, " ") + formatDnsResolverResult(result);
  }

  function formatDnsResolverResult(result) {
    var addresses = result.addresses || [];
    if (!addresses.length) {
      return result.error || "n/a";
    }

    return addresses.slice(0, 3).join(", ");
  }

  function check(row, kind, path) {
    var host = row.getAttribute("data-host");
    var status = findStatus(row, kind);

    if (!host || !status) {
      return;
    }

    requestJson(buildUrl(path, host)).then(function (data) {
      if (data.ok) {
        setStatus(status, "status-ok", formatSuccessfulStatus(kind, data));
        return;
      }

      var error = data.error || "Проверка не прошла";
      setStatus(status, "status-error", kind === "dns" ? formatDnsStatus(data) : error);
    }).catch(function (error) {
      var message = error && error.message ? error.message : "Ошибка запроса";
      setStatus(status, "status-error", message);
      showError(host + ": " + message);
    });
  }

  function startHealthChecks() {
    var close = document.querySelector("[data-health-error-close]");
    if (close) {
      close.addEventListener("click", hideError);
    }

    var rows = document.querySelectorAll(".health-row");
    rows.forEach(function (row) {
      check(row, "connect", "/api/health/connect");
      check(row, "dns", "/api/health/dns");
      check(row, "head", "/api/health/head");
      check(row, "ping", "/api/health/ping");
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", startHealthChecks);
  } else {
    startHealthChecks();
  }
}());
