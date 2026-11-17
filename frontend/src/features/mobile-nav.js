/* ---------------- Mobile navigation ----------------
   On small screens the tool list is collapsed behind a three-line button (see #navToggle in
   index.html; CSS hides the button on desktop, so this does nothing there). Tapping a tool,
   pressing Escape, tapping outside the bar, or resizing to desktop closes the list again.
   It only toggles a class on the sidebar; tab switching itself is still handled by tabs.js. */

export function initMobileNav() {
  const sidebar = document.querySelector('.sidebar');
  const button = document.getElementById('navToggle');
  const menu = document.getElementById('toolTabs');
  if (!sidebar || !button || !menu) return;

  const isOpen = () => sidebar.classList.contains('nav-open');

  const setOpen = (open) => {
    sidebar.classList.toggle('nav-open', open);
    button.setAttribute('aria-expanded', String(open));
    button.setAttribute('aria-label', open ? 'Close menu' : 'Open menu');
  };

  button.addEventListener('click', () => setOpen(!isOpen()));

  // Choosing a tool closes the list (tabs.js switches the panel on the same click).
  menu.addEventListener('click', (e) => {
    if (e.target.closest('.tab')) setOpen(false);
  });

  document.addEventListener('click', (e) => {
    if (isOpen() && !sidebar.contains(e.target)) setOpen(false);
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && isOpen()) {
      setOpen(false);
      button.focus();
    }
  });

  window.matchMedia('(max-width: 900px)').addEventListener('change', () => setOpen(false));
}