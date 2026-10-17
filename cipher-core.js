/*
  加密通信器 — 恩尼格碼核心（純前端，與電腦版 enigma.exe 演算法完全相同、可互通）
  ‧ 恩尼格碼 M3：轉子 I～V 選 3、反射器 B、環設定、接線板 10 組、中間轉子雙重跳格
  ‧ 密文格式：「本號-加密後訊息鑰匙」＋每 5 字一組的內文
  ‧ 中文：UTF-8 每個位元組拆成兩個字母（A～P）再加密
  ‧ 通關密語 → PBKDF2-SHA256（20 萬次）→ 每本 SHA256 亂數流 → 20 本密碼本
  ‧ 本檔不含任何鑰匙；鑰匙只存在使用者自己的瀏覽器
*/
(function (root) {
  'use strict';

  const ROTOR_WIRING = [
    'EKMFLGDQVZNTOWYHXUSPAIBRCJ', // I
    'AJDKSIRUXBLHWTMCQGZNPYFVOE', // II
    'BDFHJLCPRTXVZNYEIWGAKMUSQO', // III
    'ESOVPZJAYQUIRHXLNFTGKDCMWB', // IV
    'VZBRGITYUPSDNHLXAWMJQOFECK', // V
  ];
  const ROTOR_NOTCH = 'QEVJZ';
  const REFLECTOR_B = 'YRUHQSLDPXNGOKMIEBFZCWVJAT';
  const ROTOR_NAMES = ['I', 'II', 'III', 'IV', 'V'];
  const BOOK_COUNT = 20;
  const PLUG_PAIRS = 10;
  const PASS_SALT = 'luho-enigma-v1';
  const PASS_ROUNDS = 200000;
  const STREAM_BLOCKS = 8;
  const MIN_PASS_CHARS = 6;

  const A = 65;
  const toLetters = (s) => {
    const out = [];
    for (const ch of s.toUpperCase()) {
      const c = ch.charCodeAt(0);
      if (ch.length === 1 && c >= A && c < A + 26) out.push(c - A);
    }
    return out;
  };
  const fromLetters = (v) => String.fromCharCode(...v.map((c) => c + A));

  // ── 機器本體 ──
  function makeRotor(kind, ring, pos) {
    const forward = [], backward = [];
    for (let i = 0; i < 26; i++) {
      const c = ROTOR_WIRING[kind].charCodeAt(i) - A;
      forward[i] = c;
      backward[c] = i;
    }
    return { forward, backward, notch: ROTOR_NOTCH.charCodeAt(kind) - A, ring, pos };
  }

  function passRotor(r, c, table) {
    const shift = (r.pos + 26 - r.ring) % 26;
    return (table[(c + shift) % 26] + 26 - shift) % 26;
  }

  function makeMachine(rotors, rings, pos, plugPairs) {
    const rs = [0, 1, 2].map((i) => makeRotor(rotors[i], rings[i], pos[i]));
    const reflector = [...REFLECTOR_B].map((ch) => ch.charCodeAt(0) - A);
    const plug = [...Array(26).keys()];
    for (const [a, b] of plugPairs) { plug[a] = b; plug[b] = a; }
    function step() {
      if (rs[1].pos === rs[1].notch) { // 中間轉子在缺口：自己和左邊一起跳（雙重跳格）
        rs[1].pos = (rs[1].pos + 1) % 26;
        rs[0].pos = (rs[0].pos + 1) % 26;
      } else if (rs[2].pos === rs[2].notch) {
        rs[1].pos = (rs[1].pos + 1) % 26;
      }
      rs[2].pos = (rs[2].pos + 1) % 26;
    }
    function press(c) {
      step();
      let x = plug[c];
      for (let i = 2; i >= 0; i--) x = passRotor(rs[i], x, rs[i].forward);
      x = reflector[x];
      for (let i = 0; i < 3; i++) x = passRotor(rs[i], x, rs[i].backward);
      return plug[x];
    }
    return {
      run: (letters) => letters.map(press),
      positions: () => rs.map((r) => r.pos),
    };
  }

  // ── 密碼本驗證 ──
  function parseBook(b) {
    const n = b.number;
    const rotors = b.rotors.map((name) => {
      const i = ROTOR_NAMES.indexOf(name);
      if (i < 0) throw new Error(`第 ${n} 本的轉子「${name}」不存在（只有 I～V）`);
      return i;
    });
    if (rotors.length !== 3 || new Set(rotors).size !== 3) throw new Error(`第 ${n} 本的三個轉子不可重複`);
    const three = (s, what) => {
      const v = toLetters(s || '');
      if (v.length !== 3 || String(s).trim().length !== 3) throw new Error(`第 ${n} 本的${what}必須是 3 個英文字母`);
      return v;
    };
    const used = new Array(26).fill(false);
    const plugs = [];
    for (const pair of String(b.plugboard || '').split(/\s+/).filter(Boolean)) {
      const p = toLetters(pair);
      if (p.length !== 2 || pair.length !== 2 || p[0] === p[1] || used[p[0]] || used[p[1]])
        throw new Error(`第 ${n} 本的接線板「${pair}」不正確（每個字母只能接一次）`);
      used[p[0]] = used[p[1]] = true;
      plugs.push(p);
    }
    return { rotors, rings: three(b.rings, '環設定'), plugs, ground: three(b.ground, '基本位置') };
  }

  /** 驗證整份密碼本（匯入用），通過回傳整理過的陣列 */
  function validateBooks(books) {
    if (!Array.isArray(books)) throw new Error('密碼本格式不對（應該是 20 本的清單）');
    if (books.length !== BOOK_COUNT) throw new Error(`密碼本應該有 ${BOOK_COUNT} 本，這份有 ${books.length} 本`);
    return books.map((b, i) => {
      if (!b || b.number !== i + 1) throw new Error(`密碼本編號順序不對（第 ${i + 1} 個）`);
      const clean = { number: b.number, rotors: [...b.rotors], rings: b.rings, plugboard: b.plugboard, ground: b.ground };
      parseBook(clean);
      return clean;
    });
  }

  // ── 中文 ⇄ 字母 ──
  function textToPayload(text) {
    const out = [];
    for (const byte of new TextEncoder().encode(text)) out.push(byte >> 4, byte & 15);
    return out;
  }
  function payloadToText(v) {
    const bad = '解出來的內容不對：可能密碼本不同，或密文被改過（複製時少了一段？）';
    if (v.length % 2 !== 0 || v.some((c) => c > 15)) throw new Error(bad);
    const bytes = new Uint8Array(v.length / 2);
    for (let i = 0; i < bytes.length; i++) bytes[i] = (v[2 * i] << 4) | v[2 * i + 1];
    try { return new TextDecoder('utf-8', { fatal: true }).decode(bytes); } catch (e) { throw new Error(bad); }
  }

  function randomLetters(n) {
    const out = [];
    const buf = new Uint8Array(1);
    while (out.length < n) {
      root.crypto.getRandomValues(buf);
      if (buf[0] < 234) out.push(buf[0] % 26); // 拒絕取樣，確保平均
    }
    return out;
  }

  /** 加密：回傳「本號-訊息鑰匙」＋每 5 字一組的密文 */
  function encrypt(book, text) {
    if (!text) throw new Error('沒有輸入訊息');
    const p = parseBook(book);
    const msgKey = randomLetters(3);
    const indicator = makeMachine(p.rotors, p.rings, p.ground, p.plugs).run(msgKey);
    const body = fromLetters(makeMachine(p.rotors, p.rings, msgKey, p.plugs).run(textToPayload(text)));
    const groups = body.match(/.{1,5}/g) || [];
    const lines = [];
    for (let i = 0; i < groups.length; i += 10) lines.push(groups.slice(i, i + 10).join(' '));
    return `${String(book.number).padStart(2, '0')}-${fromLetters(indicator)}\n${lines.join('\n')}`;
  }

  /** 解密：回傳 { number, text } */
  function decrypt(books, cipher) {
    cipher = String(cipher || '').trim();
    const dash = cipher.indexOf('-');
    if (dash < 0) throw new Error('密文開頭應該是「本號-三個字母」，例如 07-KXQ');
    const number = parseInt(cipher.slice(0, dash).trim(), 10);
    if (!(number >= 1 && number <= books.length)) throw new Error('密文開頭的本號看不懂');
    const letters = toLetters(cipher.slice(dash + 1));
    if (letters.length < 4) throw new Error('密文太短');
    const p = parseBook(books[number - 1]);
    const msgKey = makeMachine(p.rotors, p.rings, p.ground, p.plugs).run(letters.slice(0, 3));
    const payload = makeMachine(p.rotors, p.rings, msgKey, p.plugs).run(letters.slice(3));
    return { number, text: payloadToText(payload) };
  }

  // ── 通關密語 → 20 本密碼本 ──
  async function sha256(bytes) {
    return new Uint8Array(await root.crypto.subtle.digest('SHA-256', bytes));
  }

  async function fromPassphrase(pass) {
    pass = String(pass || '').trim();
    if ([...pass].length < MIN_PASS_CHARS) throw new Error(`通關密語至少要 ${MIN_PASS_CHARS} 個字`);
    const enc = new TextEncoder();
    const keyMat = await root.crypto.subtle.importKey('raw', enc.encode(pass), 'PBKDF2', false, ['deriveBits']);
    const master = new Uint8Array(await root.crypto.subtle.deriveBits(
      { name: 'PBKDF2', hash: 'SHA-256', salt: enc.encode(PASS_SALT), iterations: PASS_ROUNDS }, keyMat, 256));
    const books = [];
    for (let n = 1; n <= BOOK_COUNT; n++) {
      const stream = [];
      for (let k = 0; k < STREAM_BLOCKS; k++) {
        const input = new Uint8Array(34);
        input.set(master);
        input[32] = n;
        input[33] = k;
        stream.push(...(await sha256(input)));
      }
      let at = 0;
      const below = (m) => {
        const limit = 256 - (256 % m);
        for (;;) {
          if (at >= stream.length) throw new Error('亂數流用完了（極罕見），請換一句通關密語');
          const b = stream[at++];
          if (b < limit) return b % m;
        }
      };
      const shuffle = (v) => {
        for (let i = v.length - 1; i >= 1; i--) {
          const j = below(i + 1);
          [v[i], v[j]] = [v[j], v[i]];
        }
      };
      const kinds = [0, 1, 2, 3, 4];
      shuffle(kinds);
      const rings = [below(26), below(26), below(26)];
      const letters = [...Array(26).keys()];
      shuffle(letters);
      const pairs = [];
      for (let i = 0; i < PLUG_PAIRS * 2; i += 2) pairs.push(fromLetters(letters.slice(i, i + 2)));
      const ground = [below(26), below(26), below(26)];
      books.push({
        number: n,
        rotors: [0, 1, 2].map((i) => ROTOR_NAMES[kinds[i]]),
        rings: fromLetters(rings),
        plugboard: pairs.join(' '),
        ground: fromLetters(ground),
      });
    }
    return books;
  }

  /** 鑰匙指紋：雙方看到同一組 6 碼＝密碼本完全相同 */
  async function fingerprint(books) {
    const canon = books.map((b) => `${b.number}:${b.rotors.join(',')}:${b.rings}:${b.plugboard}:${b.ground}`).join('|');
    const h = await sha256(new TextEncoder().encode(canon));
    return [...h.slice(0, 3)].map((x) => x.toString(16).padStart(2, '0').toUpperCase()).join('');
  }

  const api = { encrypt, decrypt, fromPassphrase, fingerprint, validateBooks, MIN_PASS_CHARS, BOOK_COUNT, _machine: makeMachine, _toLetters: toLetters, _fromLetters: fromLetters };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.LuhoCipher = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
