
(function(){
  const ws = new WebSocket("ws://localhost:8080/ws");
  ws.onopen = () => console.log("WS connected");
  ws.onmessage = (ev) => {
    try {
      const d = JSON.parse(ev.data);
      document.getElementById("pps").innerText = d.pps ?? 0;
      document.getElementById("qps").innerText = d.qps ?? 0;
      document.getElementById("bps").innerText = d.bps ?? 0;
      document.getElementById("dropped").innerText = d.dropped ?? 0;
    } catch(e) { console.error(e); }
  };
  ws.onclose = () => console.log("WS closed");
})();
