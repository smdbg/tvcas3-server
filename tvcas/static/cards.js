/* Card UI helpers. UTC matches the server form parser; all 32 mask bits are unsigned. */
(function () {
  'use strict';
  function maskToBits(value) {
    if (!/^[0-9a-f]{8}$/i.test(value)) return null;
    const mask = Number.parseInt(value, 16);
    return Array.from({length:32}, (_, bit) => Boolean((mask >>> bit) & 1));
  }
  function bitsToMask(bits) {
    let mask = 0;
    for (let bit = 0; bit < 32; bit++) if (bits[bit]) mask += 2 ** bit;
    return mask.toString(16).toUpperCase().padStart(8, '0');
  }
  function utcInput(date) { return date.toISOString().slice(0, 19); }
  function parseUTC(value) {
    if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2})?$/.test(value)) return null;
    const parsed = new Date(value + 'Z');
    if (!Number.isFinite(parsed.getTime())) return null;
    const normalized = utcInput(parsed);
    return normalized === (value.length === 16 ? value + ':00' : value) ? parsed : null;
  }
  function addMonth(value, now = new Date()) {
    const date = value ? parseUTC(value) : new Date(now);
    if (!date) return null;
    const day = date.getUTCDate();
    date.setUTCDate(1);
    date.setUTCMonth(date.getUTCMonth() + 1);
    const last = new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth() + 1, 0)).getUTCDate();
    date.setUTCDate(Math.min(day, last));
    return utcInput(date);
  }
  if (typeof module !== 'undefined' && module.exports) module.exports = {maskToBits,bitsToMask,parseUTC,utcInput,addMonth};
  if (typeof document === 'undefined') return;
  function openHashDetails() {
    const id = location.hash.slice(1);
    const element = id && document.getElementById(id);
    if (element && element.tagName === 'DETAILS') element.open = true;
  }
  openHashDetails(); window.addEventListener('hashchange', openHashDetails);
  for (const form of document.querySelectorAll('[data-card-form]')) {
    const mask = form.querySelector('[data-access-mask]');
    const toggles = Array.from(form.querySelectorAll('[data-access-bit]'));
    const help = form.querySelector('[data-access-help]');
    function showMask() {
      mask.value = mask.value.toUpperCase();
      const bits = maskToBits(mask.value);
      mask.setCustomValidity(bits ? '' : 'Въведи точно 8 HEX знака (0–9, A–F).');
      mask.setAttribute('aria-invalid', bits ? 'false' : 'true');
      toggles.forEach(toggle => { toggle.disabled = !bits; if (bits) toggle.checked = bits[Number(toggle.dataset.accessBit)]; });
      help.textContent = bits ? 'Отметките и HEX маската се променят заедно. Бит 31 е най-вляво.' : 'Въведи точно 8 HEX знака (0–9, A–F), за да използваш отметките.';
    }
    mask.addEventListener('input', showMask);
    toggles.forEach(toggle => toggle.addEventListener('change', () => {
      const bits = Array(32).fill(false);
      toggles.forEach(item => { bits[Number(item.dataset.accessBit)] = item.checked; });
      mask.value = bitsToMask(bits);
      showMask();
    }));
    showMask();
    const start = form.elements.namedItem('start'), finish = form.elements.namedItem('finish');
    function validateDates() {
      const first = parseUTC(start.value), last = parseUTC(finish.value);
      finish.setCustomValidity(first && last && last < first ? 'Крайната дата предхожда началната.' : '');
    }
    form.querySelector('[data-date-now]').addEventListener('click', () => { start.value = utcInput(new Date()); validateDates(); });
    form.querySelector('[data-date-month]').addEventListener('click', () => {
      const next = addMonth(finish.value);
      if (next) { finish.value = next; validateDates(); }
      else finish.reportValidity();
    });
    start.addEventListener('input', validateDates); finish.addEventListener('input', validateDates);
    const details = form.querySelector('[data-card-advanced-details]');
    details.addEventListener('toggle', () => {
      /* Untouched advanced fields are absent from ordinary edit submissions. */
      if (details.open) details.querySelector('[data-card-advanced]').disabled = false;
    });
  }
}());
