function showCtf(correct) {
  const el = document.getElementById("ctf-result");
  if (!el) return;
  el.hidden = false;
  el.textContent = correct
    ? "Good choice. Never share passwords or OTPs through an unexpected link. Verify independently using the official channel."
    : "Not the safest choice. Unexpected urgency and requests for passwords or OTPs are warning signs. Verify through the official channel.";
  el.classList.add("visible");
}
