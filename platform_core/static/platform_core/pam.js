/* Native display only. Connection parameters and target credentials stay on the server. */
(() => {
  'use strict';
  const node = document.getElementById('pam-player-config');
  if (!node || !window.Guacamole) return;
  const config = JSON.parse(node.textContent);
  node.remove();
  const viewport = document.getElementById('pam-display');
  const state = document.getElementById('pam-state');
  const size = () => ({width:Math.max(320,Math.min(1920,viewport.clientWidth)),height:Math.max(240,Math.min(1080,window.innerHeight-240))});
  function fit(display) {
    if (display.getWidth()) display.scale(Math.min(1,viewport.clientWidth/display.getWidth()));
  }
  function fail(message) { state.textContent = message; }
  if (config.mode === 'live') {
    const tunnel = new Guacamole.Tunnel();
    const parser = new Guacamole.Parser();
    let socket = null;
    parser.oninstruction = (opcode,args) => { if (tunnel.oninstruction) tunnel.oninstruction(opcode,args); };
    tunnel.connect = () => {
      tunnel.setState(Guacamole.Tunnel.State.CONNECTING);
      const url = new URL(config.websocket_path,window.location.href);
      url.protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      socket = new WebSocket(url,'guacamole');
      socket.onopen = () => {
        socket.send(JSON.stringify({ticket:config.ticket,...size()}));
        delete config.ticket;
        tunnel.setState(Guacamole.Tunnel.State.OPEN);
        state.textContent = 'Vérification de la cible et de l’autorisation…';
      };
      socket.onmessage = event => { try { parser.receive(event.data); } catch (_) { tunnel.disconnect(); fail('Flux distant invalide.'); } };
      socket.onerror = () => fail('Relais indisponible. Consultez sa fiche puis relancez une ouverture.');
      socket.onclose = () => { tunnel.setState(Guacamole.Tunnel.State.CLOSED); document.getElementById('pam-close').disabled = true; state.textContent = 'Relais fermé — consultez la fiche pour le motif et la capture.'; };
    };
    tunnel.sendMessage = (...args) => {
      if (socket && socket.readyState === WebSocket.OPEN) socket.send(args.map(value => {
        const text = String(value); return Array.from(text).length+'.'+text;
      }).join(',')+';');
    };
    tunnel.disconnect = () => { if (socket && socket.readyState < WebSocket.CLOSING) socket.close(1000); };
    const client = new Guacamole.Client(tunnel);
    const display = client.getDisplay();
    viewport.appendChild(display.getElement());
    display.onresize = () => fit(display);
    const keyboard = new Guacamole.Keyboard(viewport);
    keyboard.onkeydown = keysym => { client.sendKeyEvent(1,keysym); return false; };
    keyboard.onkeyup = keysym => { client.sendKeyEvent(0,keysym); return false; };
    const mouse = new Guacamole.Mouse(viewport);
    mouse.onmousedown = mouse.onmouseup = mouse.onmousemove = mouseState => client.sendMouseState(mouseState,true);
    viewport.addEventListener('mousedown',() => viewport.focus());
    viewport.addEventListener('blur',() => keyboard.reset());
    client.onstatechange = value => { if (value === Guacamole.Client.State.CONNECTED) state.textContent = 'Relais ouvert — affichage enregistré'; };
    client.onerror = () => fail('Connexion distante interrompue. Consultez la fiche du relais.');
    document.getElementById('pam-close').onclick = () => client.disconnect();
    window.addEventListener('pagehide',() => client.disconnect(),{once:true});
    window.addEventListener('resize',() => { fit(display); const current=size(); client.sendSize(current.width,current.height); });
    client.connect();
    viewport.focus();
  } else {
    (async () => {
      if (!Number.isSafeInteger(config.bytes) || config.bytes < 0 || config.bytes > 268435456) throw Error('size');
      const response = await fetch(config.url,{credentials:'same-origin',cache:'no-store'});
      if (!response.ok) throw Error('capture');
      const blob = await response.blob();
      if (blob.size !== config.bytes) throw Error('incomplete');
      const recording = new Guacamole.SessionRecording(blob);
      const display = recording.getDisplay();
      viewport.appendChild(display.getElement());
      display.onresize = () => fit(display);
      const play = document.getElementById('pam-play');
      const position = document.getElementById('pam-position');
      recording.onprogress = () => { position.max=String(recording.getDuration()); play.disabled=false; state.textContent='Capture vérifiée — prête à lire'; };
      recording.onseek = () => { position.value=String(recording.getPosition()); document.getElementById('pam-time').textContent=Math.floor(recording.getPosition()/1000)+' s'; };
      recording.onerror = () => fail('La capture ne peut pas être lue.');
      play.onclick = () => recording.isPlaying() ? recording.pause() : recording.play();
      position.onchange = () => recording.seek(Number(position.value));
      window.addEventListener('resize',() => fit(display));
      window.addEventListener('pagehide',() => recording.abort(),{once:true});
    })().catch(() => fail('Capture indisponible, expirée ou incomplète. Ouvrez-la à nouveau après validation MFA.'));
  }
})();
