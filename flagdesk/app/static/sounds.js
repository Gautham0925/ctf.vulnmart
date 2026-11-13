const Snd = (() => {
  let ctx = null;
  let enabled = false;
  const mutedKey = "fd_mute";
  const isMuted = () => localStorage.getItem(mutedKey) === "1";

  function enable() {
    if (!ctx) ctx = new (window.AudioContext || window.webkitAudioContext)();
    if (ctx.resume) ctx.resume();
    if (window.speechSynthesis) {
      try { speechSynthesis.getVoices(); const u = new SpeechSynthesisUtterance(" "); u.volume = 0; speechSynthesis.speak(u); } catch (e) {}
    }
    enabled = true;
  }

  function tone(freq, start, dur, type = "sine", gain = 0.25, slideTo = null, vibrato = 0) {
    const t0 = ctx.currentTime + start;
    const osc = ctx.createOscillator();
    const g = ctx.createGain();
    osc.type = type;
    osc.frequency.setValueAtTime(freq, t0);
    if (slideTo) osc.frequency.exponentialRampToValueAtTime(slideTo, t0 + dur);
    if (vibrato) {
      const lfo = ctx.createOscillator();
      const lg = ctx.createGain();
      lfo.frequency.value = 6;
      lg.gain.value = vibrato;
      lfo.connect(lg);
      lg.connect(osc.frequency);
      lfo.start(t0);
      lfo.stop(t0 + dur + 0.05);
    }
    g.gain.setValueAtTime(0.0001, t0);
    g.gain.exponentialRampToValueAtTime(gain, t0 + 0.02);
    g.gain.exponentialRampToValueAtTime(0.0001, t0 + dur);
    osc.connect(g);
    g.connect(ctx.destination);
    osc.start(t0);
    osc.stop(t0 + dur + 0.05);
  }

  function speak(text, langs, rate, pitch) {
    if (!window.speechSynthesis) return false;
    try {
      const voices = speechSynthesis.getVoices();
      let voice = null;
      for (const l of langs) { voice = voices.find((v) => v.lang && v.lang.toLowerCase().startsWith(l)); if (voice) break; }
      const u = new SpeechSynthesisUtterance(text);
      if (voice) { u.voice = voice; u.lang = voice.lang; } else u.lang = langs[0];
      u.rate = rate;
      u.pitch = pitch;
      u.volume = 1;
      speechSynthesis.cancel();
      speechSynthesis.speak(u);
      return true;
    } catch (e) { return false; }
  }

  const BUILTIN = {
    ding: () => { tone(880, 0, 0.35, "sine", 0.3); tone(1320, 0.12, 0.4, "sine", 0.2); },
    happy: () => { [523, 659, 784, 1047].forEach((f, i) => tone(f, i * 0.11, 0.3, "triangle", 0.28)); tone(1319, 0.5, 0.5, "sine", 0.22); },
    trombone: () => { [[233, 0], [220, 0.4], [208, 0.8]].forEach(([f, t]) => tone(f, t, 0.38, "sawtooth", 0.2)); tone(196, 1.2, 1.2, "sawtooth", 0.22, 150, 4); },
    boing: () => { tone(180, 0, 0.5, "sine", 0.35, 700, 25); tone(700, 0.5, 0.35, "sine", 0.3, 220, 20); },
    fanfare: () => { [[523, 0], [523, 0.16], [523, 0.32], [659, 0.5], [784, 0.75]].forEach(([f, t]) => tone(f, t, 0.22, "square", 0.18)); tone(1047, 1.0, 0.7, "square", 0.2); },
    siren: () => { for (let i = 0; i < 4; i++) tone(i % 2 ? 900 : 650, i * 0.35, 0.34, "square", 0.18); },
    fahhh: () => { tone(520, 0, 1.4, "sawtooth", 0.28, 90, 8); speak("Fahhh", ["en"], 0.45, 0.1); },
    anna: () => { tone(330, 0, 0.25, "triangle", 0.2); const ok = speak("Anna, nanna kaiyyalli aaytilla anna", ["kn", "hi", "en-in", "en"], 0.85, 1.1); if (!ok) tone(220, 0.3, 1.0, "sawtooth", 0.2, 120); },
    bruh: () => { tone(160, 0, 0.9, "sawtooth", 0.25, 70, 5); speak("Bruhhh", ["en"], 0.5, 0.2); },
  };

  function play(name) {
    if (!enabled || isMuted() || !name || name === "silent") return;
    if (name.startsWith("custom:")) {
      try { const a = new Audio(`/api/sounds/${encodeURIComponent(name.slice(7))}`); a.volume = 1; a.play().catch(() => {}); } catch (e) {}
      return;
    }
    const fn = BUILTIN[name] || BUILTIN.ding;
    try { fn(); } catch (e) {}
  }

  function preview(name) {
    if (!enabled) enable();
    const was = localStorage.getItem(mutedKey);
    localStorage.removeItem(mutedKey);
    play(name || "ding");
    if (was) localStorage.setItem(mutedKey, was);
  }

  return { enable, play, preview, isEnabled: () => enabled, isMuted, setMuted: (m) => localStorage.setItem(mutedKey, m ? "1" : "0") };
})();

const SOUND_LABELS = {
  "": "Default ding",
  fahhh: "Fahhh (meme voice)",
  anna: "Anna Nanna Kaiyalli Aaytilla Anna",
  trombone: "Sad trombone",
  happy: "Happy chime",
  boing: "Funny boing",
  fanfare: "Celebration fanfare",
  siren: "Alert siren",
  bruh: "Bruh",
  silent: "Silent",
};
