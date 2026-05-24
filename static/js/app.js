// UX enhancements

document.addEventListener('DOMContentLoaded', () => {
  // Submit-state: disable button & change label while submitting
  const form = document.getElementById('scan-form');
  const button = form && form.querySelector('.btn-scan');
  if (form && button) {
    form.addEventListener('submit', () => {
      button.disabled = true;
      const span = button.querySelector('span');
      const arrow = button.querySelector('.btn-arrow');
      if (span) span.textContent = 'SCANNING';
      if (arrow) arrow.textContent = '...';
    });
  }

  // Quick-target buttons fill the host field
  document.querySelectorAll('.quick-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const host = document.querySelector('input[name="host"]');
      if (host) {
        host.value = btn.dataset.host;
        host.focus();
      }
    });
  });

  // "/" key focuses host input
  document.addEventListener('keydown', (e) => {
    if (e.key === '/' && !['INPUT', 'TEXTAREA'].includes(document.activeElement.tagName)) {
      const host = document.querySelector('input[name="host"]');
      if (host) { e.preventDefault(); host.focus(); host.select(); }
    }
  });

  // Severity counter rollup
  document.querySelectorAll('.sev-pill .sp-n').forEach(el => {
    const target = parseInt(el.textContent, 10);
    if (isNaN(target) || target === 0) return;
    let n = 0;
    el.textContent = 0;
    const step = Math.max(1, Math.floor(target / 18));
    const tick = setInterval(() => {
      n = Math.min(target, n + step);
      el.textContent = n;
      if (n >= target) clearInterval(tick);
    }, 25);
  });
});
