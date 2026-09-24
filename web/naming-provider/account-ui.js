// Progressive enhancement: forms remain usable without JavaScript.
document.addEventListener("submit", async (event) => {
  const form = event.target;
  if (
    !(form instanceof HTMLFormElement) ||
    form.method.toLowerCase() !== "post" ||
    !new URL(form.action).pathname.startsWith("/bsn-np/account/")
  )
    return;
  event.preventDefault();
  const button = event.submitter;
  const body = new URLSearchParams(new FormData(form));
  if (button) button.disabled = true;
  try {
    const response = await fetch(form.action, {
      method: "POST",
      body,
      credentials: "same-origin",
      redirect: "follow",
      signal: AbortSignal.timeout(20000),
    });
    if (new URL(response.url).origin !== location.origin)
      throw Error("Неверный адрес ответа");
    const html = await response.text();
    const page = new DOMParser().parseFromString(html, "text/html");
    document.title = page.title;
    document.body.replaceChildren(...Array.from(page.body.childNodes));
    // Keep a GET address for reload; POST results are not replayed on refresh.
    history.replaceState(null, "", response.redirected ? new URL(response.url).pathname : "/bsn-np/account");
    window.scrollTo(0, 0);
  } catch (error) {
    const message = document.createElement("p");
    message.setAttribute("role", "alert");
    message.textContent =
      "Не удалось получить ответ. Проверьте соединение и повторите.";
    form.after(message);
    if (button) button.disabled = false;
  }
});
