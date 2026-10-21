(function () {
  var errorHideTimer = null;
  var reputationRequest = 0;
  var redirectingToLogin = false;

  function findStatus(row, name) {
    return row.querySelector('[data-check="' + name + '"]');
  }

  function setStatus(element, className, text) {
    element.classList.remove("status-loading", "status-ok", "status-na", "status-error");
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
    return path + (path.indexOf("?") === -1 ? "?" : "&") + "host=" + encodeURIComponent(host);
  }

  function fetchAuthenticated(url, options) {
    return fetch(url, options).then(function (response) {
      if (response.status === 401) {
        if (!redirectingToLogin) {
          redirectingToLogin = true;
          var retpath = window.location.pathname + window.location.search + window.location.hash;
          window.location.replace("/?retpath=" + encodeURIComponent(retpath));
        }
        throw new Error("Требуется вход");
      }
      return response;
    });
  }

  function requestJson(url) {
    return fetchAuthenticated(url, {
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
    if (kind.indexOf("dns-") === 0) {
      return formatDnsResolverResult(data);
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

    if (kind === "h2" || kind === "h3") return data.status_line;

    if (kind === "head" && data.status_line) {
      var transport = [data.proxy_http_version, data.proxy_tls_version].filter(Boolean).join(" · ");
      if (data.proxy_fallback_from) transport += " (" + data.proxy_fallback_from + " недоступен)";
      return data.status_line + (transport ? "\nPX Manager → прокси: " + transport : "");
    }

    var suffix = data.status_code ? " (" + data.status_code + ")" : "";
    return "OK" + suffix;
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
      if (kind === "head") {
        updateCountry(row, data);
        updateCertificate(row, data);
      }
      if (data.ok) {
        setStatus(status, "status-ok", formatSuccessfulStatus(kind, data));
        if (kind === "head" && data.exit_ip) {
          var button = row.querySelector("[data-reputation]");
          button.hidden = false;
          button.setAttribute("aria-label", "Репутация IP " + data.exit_ip);
          button.onclick = function () { openReputation(host, data.exit_ip); };
        }
        return;
      }

      var error = data.error || "Проверка не прошла";
      setStatus(status, "status-error", error);
    }).catch(function (error) {
      var message = error && error.message ? error.message : "Ошибка запроса";
      setStatus(status, "status-error", message);
      if (kind === "head") {
        updateCountry(row, {country_error: message});
        updateCertificate(row, {});
      }
      showError(host + ": " + message);
    });
  }

  function updateCertificate(row, data) {
    var status = findStatus(row, "certificate");
    if (!status) return;
    var cert = data.proxy_certificate;
    if (!cert) {
      setStatus(status, "status-na", "Недоступен");
      status.removeAttribute("title");
      return;
    }
    setStatus(status, "status-ok", "Кому: " + cert.subject + "\nКем: " + cert.issuer +
      "\nДействует до: " + new Date(cert.not_after).toLocaleString("ru-RU"));
    status.title = "Действует с: " + new Date(cert.not_before).toLocaleString("ru-RU") +
      "\nSHA-256: " + cert.sha256;
  }

  function openReputation(host, ip) {
    var dialog = document.querySelector(".ip-reputation-dialog");
    var results = dialog.querySelector("[data-reputation-results]");
    var request = ++reputationRequest;
    dialog.querySelector("[data-reputation-ip]").textContent = ip;
    results.textContent = "Проверяется…";
    results.setAttribute("aria-busy", "true");
    dialog.showModal();
    requestJson(buildUrl("/api/health/reputation", host) + "&ip=" + encodeURIComponent(ip)).then(function (data) {
      if (request !== reputationRequest) return;
      results.replaceChildren();
      data.results.forEach(function (result) {
        var section = document.createElement("section");
        var heading = document.createElement("h3");
        heading.textContent = result.name;
        section.append(heading);
        if (result.status === "ok") {
          var fields = document.createElement("dl");
          Object.keys(result.fields).forEach(function (label) {
            var term = document.createElement("dt");
            var value = document.createElement("dd");
            var field = result.fields[label];
            term.textContent = label;
            value.textContent = field === true || field === "yes" ? "Да"
              : field === false || field === "no" ? "Нет"
              : field === null ? "Нет данных" : String(field);
            fields.append(term, value);
          });
          section.append(fields);
        } else {
          var error = document.createElement("p");
          error.textContent = result.error || "Сервис недоступен";
          section.append(error);
        }
        if (result.checked_at) {
          var time = document.createElement("p");
          time.className = "reputation-time";
          time.textContent = (result.cached ? "Из кеша · " : "Проверено · ")
            + new Date(result.checked_at * 1000).toLocaleString("ru");
          section.append(time);
        }
        results.append(section);
      });
    }).catch(function (error) {
      if (request === reputationRequest) results.textContent = error.message;
    }).finally(function () {
      if (request === reputationRequest) results.removeAttribute("aria-busy");
    });
  }

  function setupSpeedTest() {
    var dialog = document.querySelector(".speed-dialog");
    var form = dialog.querySelector("[data-speed-form]");
    var status = dialog.querySelector("[data-speed-status]");
    var start = dialog.querySelector("[data-speed-start]");
    var stop = dialog.querySelector("[data-speed-stop]");
    var protocol = form.elements.protocol;
    var active = null;
    var host = null;

    function busy(value) {
      start.disabled = value;
      stop.disabled = !value;
      protocol.disabled = value;
      form.elements.megabytes.disabled = value;
    }

    function resetResults() {
      dialog.querySelectorAll("[data-speed-value]").forEach(function (item) {
        item.textContent = "—";
      });
    }

    document.querySelectorAll("[data-speed]").forEach(function (button) {
      button.addEventListener("click", function () {
        host = button.closest(".health-row").getAttribute("data-host");
        dialog.querySelector("[data-speed-host]").textContent = host;
        protocol.querySelector('[value="h3"]').disabled = button.getAttribute("data-speed-http3") !== "true";
        if (protocol.selectedOptions[0].disabled) protocol.value = "h2";
        resetResults();
        status.textContent = "Готов к замеру";
        dialog.showModal();
      });
    });

    stop.addEventListener("click", function () { if (active) active.abort(); });
    dialog.addEventListener("close", function () {
      if (active) active.abort();
      active = null;
      busy(false);
    });

    form.addEventListener("submit", async function (event) {
      event.preventDefault();
      if (active) return;
      var controller = new AbortController();
      var body = new FormData(form);
      active = controller;
      resetResults();
      busy(true);
      status.textContent = "Подключение к прокси…";
      var complete = false;
      var stages = {metadata: "Получение выходного IP…", latency: "Замер задержки…",
        download: "Замер загрузки…", upload: "Замер отправки…", complete: "Замер завершён"};

      function update(line) {
        if (!line.trim() || active !== controller) return;
        var data = JSON.parse(line);
        if (data.stage === "error") throw new Error(data.error);
        status.textContent = stages[data.stage] || data.stage;
        dialog.querySelectorAll("[data-speed-value]").forEach(function (item) {
          var key = item.getAttribute("data-speed-value");
          if (data[key] === undefined) return;
          item.textContent = key === "latency_ms" ? data[key] + " мс"
            : key.endsWith("_mbps") ? data[key] + " Мбит/с"
            : key === "protocol" ? {h1: "HTTP/1.1", h2: "HTTP/2", h3: "HTTP/3"}[data[key]] : data[key];
        });
        if (data.country_code) updateCountry(dialog, {country_code: data.country_code, country_provider: "Cloudflare"});
        if (data.stage === "complete") complete = true;
      }

      try {
        var response = await fetchAuthenticated(buildUrl("/api/health/speed", host), {
          method: "POST", credentials: "same-origin", body: body, signal: controller.signal
        });
        if (!response.ok) {
          var error = await response.json();
          throw new Error(error.error || "HTTP " + response.status);
        }
        var reader = response.body.getReader();
        var decoder = new TextDecoder();
        var pending = "";
        while (true) {
          var chunk = await reader.read();
          if (chunk.done) break;
          pending += decoder.decode(chunk.value, {stream: true});
          var lines = pending.split("\n");
          pending = lines.pop();
          lines.forEach(update);
        }
        update(pending + decoder.decode());
        if (!complete) throw new Error("Замер прерван до завершения");
      } catch (error) {
        if (active === controller) status.textContent = error.name === "AbortError" ? "Замер остановлен" : error.message;
        controller.abort();
      } finally {
        if (active === controller) {
          active = null;
          busy(false);
        }
      }
    });
  }

  function updateCountry(row, data) {
    var status = findStatus(row, "country");
    if (!status) return;
    var code = data.country_code;
    if (!code || !/^[A-Z]{2}$/.test(code)) {
      setStatus(status, "status-na", "Не определена");
      status.title = data.country_error || data.error || "Выходной IP недоступен";
      return;
    }
    var name = code;
    try {
      name = new Intl.DisplayNames(["ru"], {type: "region"}).of(code);
    } catch (error) {}
    var flag = Array.from(code).map(function (letter) {
      return String.fromCodePoint(0x1F1E6 + letter.charCodeAt(0) - 65);
    }).join("");
    setStatus(status, "status-ok", " " + name + " (" + code + ")");
    var flagElement = document.createElement("span");
    flagElement.className = "country-flag";
    flagElement.setAttribute("aria-hidden", "true");
    flagElement.textContent = flag;
    status.prepend(flagElement);
    status.title = "Источник: " + data.country_provider;
  }

  function startHealthChecks() {
    setupSpeedTest();
    var close = document.querySelector("[data-health-error-close]");
    if (close) {
      close.addEventListener("click", hideError);
    }

    var rows = document.querySelectorAll(".health-row");
    rows.forEach(function (row) {
      var checks = (row.getAttribute("data-health-checks") || "")
        .split(",")
        .filter(Boolean);
      if (!checks.length) {
        checks = ["dns", "ping", "connect", "head"];
      }

      [
        ["dns-system", "/api/health/dns?resolver=system"],
        ["dns-cloudflare", "/api/health/dns?resolver=cloudflare"],
        ["ping", "/api/health/ping"],
        ["connect", "/api/health/connect"],
        ["head", "/api/health/head"],
        ["h2", "/api/health/protocol?protocol=h2"],
        ["h3", "/api/health/protocol?protocol=h3"]
      ].forEach(function (item) {
        var permission = item[0] === "h2" || item[0] === "h3" ? "head" : item[0].split("-")[0];
        if (checks.indexOf(permission) === -1) {
          var status = findStatus(row, item[0]);
          if (status) {
            setStatus(status, "status-na", "N/A");
          }
          return;
        }

        check(row, item[0], item[1]);
      });
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", startHealthChecks);
  } else {
    startHealthChecks();
  }
}());
