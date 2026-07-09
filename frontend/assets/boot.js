/**
 * boot.js – Boot Screen Matrix Rain and Access Granted Chromatic Glitch overlays.
 *
 * Implements two screen transitions:
 *   1. BOOT SCREEN: Falling brass characters rendering a silhouette, with typewriter log lines.
 *   2. ACCESS GRANTED REVEAL: Static silhouette chromatic jitter + stamp reveal on successful login.
 */

(function () {
  const silhouettePathStr = "M10 95 C15 75, 25 65, 30 55 C30 35, 35 10, 50 5 C65 10, 70 35, 70 55 C75 65, 85 75, 90 95 Z";

  // Check if browser supports canvas
  function supportsCanvas() {
    return !!window.HTMLCanvasElement;
  }

  document.addEventListener("DOMContentLoaded", () => {
    const bootOverlay = document.getElementById("boot-overlay");
    const loginCard = document.querySelector(".login-card");

    if (!bootOverlay) return;

    // Check session storage
    if (sessionStorage.getItem("boot_played") === "true") {
      bootOverlay.style.display = "none";
      if (loginCard) loginCard.style.opacity = "1";
      return;
    }

    // Degrade gracefully if canvas not supported
    if (!supportsCanvas()) {
      bootOverlay.style.display = "none";
      if (loginCard) loginCard.style.opacity = "1";
      sessionStorage.setItem("boot_played", "true");
      return;
    }

    // Initialize boot animation
    runBootAnimation(bootOverlay, loginCard);
  });

  function runBootAnimation(overlay, card) {
    const canvas = document.getElementById("boot-canvas");
    if (!canvas) return;

    const ctx = canvas.getContext("2d");
    let isAnimating = true;

    // Set dimensions
    function resizeCanvas() {
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
    }
    resizeCanvas();
    window.addEventListener("resize", resizeCanvas);

    // Characters definition
    const chars = "01ΣΔ⊕ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    const fontSize = 14;
    let columns = Math.floor(canvas.width / fontSize);
    let drops = [];
    let speeds = [];

    for (let i = 0; i < columns; i++) {
      drops[i] = Math.random() * -100;
      speeds[i] = 1 + Math.random() * 2; // varied fall speeds
    }

    // Path2D for hooded figure
    const silhouettePath = new Path2D(silhouettePathStr);

    let startTimestamp = null;

    function draw(timestamp) {
      if (!isAnimating) return;
      if (!startTimestamp) startTimestamp = timestamp;
      const elapsed = timestamp - startTimestamp;

      // Draw background fade trail
      ctx.fillStyle = "rgba(20, 24, 29, 0.2)"; // var(--color-bg)
      ctx.fillRect(0, 0, canvas.width, canvas.height);

      // 1. Draw graphite background rain (dimmer, trailing)
      ctx.font = fontSize + "px monospace";

      for (let i = 0; i < drops.length; i++) {
        const x = i * fontSize;
        const speed = speeds[i];
        
        // Draw trailing characters
        for (let j = 0; j < 12; j++) {
          const y = (drops[i] - j) * fontSize;
          if (y < 0 || y > canvas.height) continue;

          // Fade character opacity down the trail
          const opacity = (1 - (j / 12)) * 0.25;
          ctx.fillStyle = `rgba(42, 49, 56, ${opacity})`; // var(--color-line) graphite

          const text = chars[Math.floor(Math.random() * chars.length)];
          ctx.fillText(text, x, y);
        }

        // Update drop position
        drops[i] += speed * 0.15; // slow down speed a bit to make it readable
        if (drops[i] * fontSize > canvas.height && Math.random() > 0.98) {
          drops[i] = 0;
        }
      }

      // 2. Draw subtle graphite blueprint outline of the silhouette
      ctx.save();
      const scale = Math.min(canvas.width * 0.35, canvas.height * 0.45);
      const left = (canvas.width - scale) / 2;
      const top = (canvas.height - scale) / 2 - 30;
      ctx.translate(left, top);
      ctx.scale(scale / 100, scale / 100);
      ctx.strokeStyle = "rgba(42, 49, 56, 0.25)";
      ctx.lineWidth = 1.5;
      ctx.stroke(silhouettePath);
      ctx.restore();

      // 3. Draw brass silhouette rain inside clipped path
      ctx.save();
      ctx.translate(left, top);
      ctx.scale(scale / 100, scale / 100);
      ctx.clip(silhouettePath);
      ctx.setTransform(1, 0, 0, 1, 0, 0); // reset transform but keep clip

      // Density/brightness increases over 1.5s
      const density = Math.min(elapsed / 1500, 1);

      for (let i = 0; i < drops.length; i++) {
        const x = i * fontSize;
        
        // Draw trailing characters inside the silhouette with brass color
        for (let j = 0; j < 14; j++) {
          const y = (drops[i] - j) * fontSize;
          if (y < 0 || y > canvas.height) continue;

          const opacity = (1 - (j / 14)) * (0.3 + density * 0.7);
          ctx.fillStyle = `rgba(184, 134, 59, ${opacity})`; // var(--color-accent) brass

          const text = chars[Math.floor(Math.random() * chars.length)];
          ctx.fillText(text, x, y);
          
          // Extra noise character for density inside figure
          if (Math.random() < density * 0.15) {
            ctx.fillText(chars[Math.floor(Math.random() * chars.length)], x, y - 4);
          }
        }
      }

      ctx.restore();

      requestAnimationFrame(draw);
    }

    requestAnimationFrame(draw);

    // Typewriter log lines (150ms/char)
    const lines = [
      "INITIALIZING CIPHER CORE...",
      "LOADING KEY MATRIX...",
      "ACCESS TERMINAL READY"
    ];
    const textEl = document.getElementById("boot-text");
    
    async function runTypewriter() {
      if (!textEl) return;
      for (let i = 0; i < lines.length; i++) {
        textEl.textContent = "";
        const line = lines[i];
        for (let c = 0; c < line.length; c++) {
          if (!isAnimating) return;
          textEl.textContent += line[c];
          await new Promise(r => setTimeout(r, 150));
        }
        await new Promise(r => setTimeout(r, 300));
      }
    }
    runTypewriter();

    // End-state trigger after 2.5s
    const timeoutId = setTimeout(() => {
      endBootAnimation();
    }, 2800);

    function endBootAnimation() {
      if (!isAnimating) return;
      isAnimating = false;
      window.removeEventListener("resize", resizeCanvas);

      overlay.classList.add("glitch-out-active");
      sessionStorage.setItem("boot_played", "true");

      setTimeout(() => {
        overlay.style.display = "none";
        if (card) {
          card.style.opacity = "1";
          card.style.transform = "scale(1)";
        }
      }, 400); // match glitch out duration
    }

    // Skip logic (click anywhere)
    overlay.addEventListener("click", () => {
      clearTimeout(timeoutId);
      isAnimating = false;
      window.removeEventListener("resize", resizeCanvas);
      overlay.style.display = "none";
      sessionStorage.setItem("boot_played", "true");
      if (card) {
        card.style.opacity = "1";
        card.style.transform = "scale(1)";
      }
    });
  }

  // ── Access Granted Reveal ──────────────────────────
  window.triggerAccessGrantedReveal = function (callback) {
    const overlay = document.getElementById("granted-overlay");
    if (!overlay) {
      if (callback) callback();
      return;
    }

    overlay.style.display = "flex";
    overlay.classList.add("flicker");

    let isSkipped = false;

    function proceed() {
      if (isSkipped) return;
      isSkipped = true;
      overlay.classList.add("fade-out");
      setTimeout(() => {
        overlay.style.display = "none";
        if (callback) callback();
      }, 400);
    }

    // Auto proceed after 1.4s
    const timeoutId = setTimeout(proceed, 1400);

    // Skip immediately on click
    overlay.addEventListener("click", () => {
      clearTimeout(timeoutId);
      proceed();
    });
  };
})();
