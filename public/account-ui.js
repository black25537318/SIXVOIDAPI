(async function(){
  try {
    const response = await fetch('/api/auth/me', { credentials: 'same-origin' });
    if (!response.ok) return;
    const data = await response.json();
    if (!data.authenticated) return;
    const box = document.createElement('div');
    box.style.cssText = 'position:fixed;left:14px;bottom:14px;z-index:9999;display:flex;align-items:center;gap:9px;padding:9px 12px;border:1px solid #a77aff55;border-radius:12px;background:#120d1df2;color:#f7f2ff;font:12px DM Sans,sans-serif;box-shadow:0 8px 28px #0008';
    const label = document.createElement('span');
    label.textContent = 'Conta: ' + (data.user?.name || data.user?.email || 'conectada');
    const button = document.createElement('button');
    button.type = 'button';
    button.textContent = 'SAIR';
    button.style.cssText = 'border:0;border-radius:7px;padding:7px 9px;background:linear-gradient(110deg,#8958e9,#b36bdf);color:white;font-weight:700;font-size:10px';
    button.addEventListener('click', async () => {
      button.disabled = true;
      try { await fetch('/api/auth/logout', { method:'POST', credentials:'same-origin' }); }
      finally { location.replace('/login.html'); }
    });
    box.append(label, button);
    document.body.appendChild(box);
  } catch (_) {}
})();
