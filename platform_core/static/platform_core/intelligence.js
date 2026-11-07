(() => {
  const focusGraphs = () => document.querySelectorAll('.graph-canvas').forEach(canvas => {
    if (canvas.clientWidth < 700) {
      canvas.scrollLeft = Math.max(0, 525 - canvas.clientWidth / 2);
    }
  });
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', focusGraphs, {once: true});
  } else {
    focusGraphs();
  }
  window.addEventListener('resize', focusGraphs);
})();
