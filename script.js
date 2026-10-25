/* PassForge — client-side password analyzer + generator. No network, no storage. */
const $ = id => document.getElementById(id);

/* ---------- data ---------- */
const COMMON = ['password','123456','12345678','qwerty','abc123','letmein','welcome','admin','iloveyou','monkey','dragon','football',
  'master','login','princess','sunshine','shadow','passw0rd','trustno1','000000','111111','123123','qwertyuiop','changeme','india123'];
const KEYBOARD = ['qwerty','asdfgh','zxcvbn','qazwsx','1qaz2wsx','123456','654321','poiuyt'];
const WORDS = ('able acid aged also area army atom aunt away baby back ball band bank base bath bear beef bell belt bike bird blue boat body bone book boot '+
  'born boss brave bread brick bridge brown bush cabin cake calm camp card cash cave chair chart chess chief city clay clean clock cloud coast coin cold '+
  'copper coral corn cost craft crew crow dance dark dawn deep desk dice dive dock door dove draft dream drum dust eagle earth east echo edge ember engine '+
  'fair farm fast fern field fire fish flag flame flint floor foam fog forest fort fox frame frost gate gem giant glass globe gold grain grape grass green '+
  'grove gull hammer harbor hawk heart hill honey horn house ice iron island ivory jade jazz jungle keen kite lake lamp lane leaf lemon light lime lion '+
  'lunar maple marsh meadow metal mint mist moon moss mountain nest night noble north oak ocean olive orbit otter owl paper peak pearl pine plain plum '+
  'pond port quartz quiet rain raven reef ridge river robin rock root rose sage sail salt sand scout shadow shell silver sky slate snow solar spark spring '+
  'stone storm stream sun swift tide tiger timber torch tower trail tree tulip valley velvet violet wave west wheat willow wind winter wolf wood yard zinc').split(' ');
const AMBIG = /[O0lI1|]/g;

/* ---------- analyzer ---------- */
function poolSize(pw){
  let n = 0;
  if(/[a-z]/.test(pw)) n += 26;
  if(/[A-Z]/.test(pw)) n += 26;
  if(/[0-9]/.test(pw)) n += 10;
  if(/[^A-Za-z0-9]/.test(pw)) n += 32;
  return n;
}
function hasSequence(pw){
  const s = pw.toLowerCase();
  for(let i=0;i<s.length-3;i++){
    const a=s.charCodeAt(i), b=s.charCodeAt(i+1), c=s.charCodeAt(i+2), d=s.charCodeAt(i+3);
    if(b-a===1 && c-b===1 && d-c===1) return true;
    if(a-b===1 && b-c===1 && c-d===1) return true;
  }
  return false;
}
function analyze(pw){
  const len = pw.length;
  const lower = pw.toLowerCase();
  const issues = [];
  let bits = len ? len * Math.log2(Math.max(poolSize(pw),1)) : 0;

  if(COMMON.some(w => lower === w)){ bits = Math.min(bits, 10); issues.push('This is one of the most common passwords in the world.'); }
  else if(COMMON.some(w => lower.includes(w))){ bits *= 0.6; issues.push('Contains a very common password or word.'); }
  if(KEYBOARD.some(k => lower.includes(k))){ bits *= 0.7; issues.push('Keyboard patterns (like qwerty) are tried first by attackers.'); }
  if(/(.)\1{2,}/.test(pw)){ bits *= 0.8; issues.push('Repeated characters (aaa) add little real strength.'); }
  if(hasSequence(pw)){ bits *= 0.8; issues.push('Sequences like abcd or 4321 are easy to guess.'); }
  if(/^[A-Za-z]+\d{1,4}[^A-Za-z0-9]?$/.test(pw)){ bits *= 0.75; issues.push('Word + digits at the end is a very predictable shape.'); }
  if(/(19|20)\d{2}/.test(pw)){ bits *= 0.9; issues.push('Years are among the first things guessed.'); }
  return { bits: Math.max(0, bits), issues };
}
function crackTime(bits){
  if(bits <= 0) return '—';
  const seconds = Math.pow(2, bits) / 2 / 1e10;
  if(seconds < 1) return 'instantly';
  const units = [['year',31557600],['day',86400],['hour',3600],['minute',60],['second',1]];
  if(seconds > 31557600 * 1e9) return 'longer than the universe';
  if(seconds >= 31557600){
    const y = seconds / 31557600;
    if(y >= 1e6) return (y/1e6).toFixed(y>=1e7?0:1) + ' million years';
    if(y >= 1e3) return Math.round(y).toLocaleString() + ' years';
    return Math.round(y) + ' years';
  }
  for(const [name,sec] of units){
    if(seconds >= sec){ const v = Math.round(seconds/sec); return v + ' ' + name + (v>1?'s':''); }
  }
}
function rate(bits){
  if(bits < 28) return ['Very weak', 12, '#c43d2f'];
  if(bits < 45) return ['Weak', 30, '#d9622b'];
  if(bits < 60) return ['Fair', 52, '#e0861a'];
  if(bits < 80) return ['Strong', 78, '#6a9a2f'];
  return ['Excellent', 100, '#2f7d4f'];
}
function renderAnalysis(){
  const pw = $('pw').value;
  const { bits, issues } = analyze(pw);
  const [label, pct, color] = pw ? rate(bits) : ['Waiting for input', 0, '#c43d2f'];
  $('verdict').textContent = label;
  $('bar').style.width = pct + '%';
  $('bar').style.background = color;
  $('entropy').textContent = Math.round(bits) + ' bits';
  $('crack').textContent = pw ? crackTime(bits) : '—';
  $('len').textContent = pw.length;

  const checks = [
    ['12+ characters', pw.length >= 12],
    ['Lowercase letters', /[a-z]/.test(pw)],
    ['Uppercase letters', /[A-Z]/.test(pw)],
    ['Numbers', /\d/.test(pw)],
    ['Symbols', /[^A-Za-z0-9]/.test(pw)],
    ['Not a common password', pw.length > 0 && !COMMON.includes(pw.toLowerCase())],
  ];
  $('checks').innerHTML = checks.map(([t,ok]) => `<li class="${ok?'ok':''}">${t}</li>`).join('');

  const tips = [...issues];
  if(pw && pw.length < 12) tips.push('Aim for at least 12 characters. Length beats complexity.');
  if(pw && bits >= 60 && !issues.length) tips.push('Looks good. Use a unique password for every account and a password manager.');
  $('tips').innerHTML = tips.map(t => `<p></p>`).join('');
  [...$('tips').children].forEach((p,i) => p.textContent = tips[i]);
}

/* ---------- generator ---------- */
function randInt(max){            // unbiased random integer in [0, max)
  const limit = Math.floor(0x100000000 / max) * max;
  const buf = new Uint32Array(1);
  do { crypto.getRandomValues(buf); } while(buf[0] >= limit);
  return buf[0] % max;
}
let mode = 'password';
function genPassword(){
  const sets = [];
  if($('optLower').checked) sets.push('abcdefghijklmnopqrstuvwxyz');
  if($('optUpper').checked) sets.push('ABCDEFGHIJKLMNOPQRSTUVWXYZ');
  if($('optNum').checked)   sets.push('0123456789');
  if($('optSym').checked)   sets.push('!@#$%^&*()-_=+[]{};:,.?');
  if(!sets.length) return 'Select at least one character set';
  const clean = s => $('optAmb').checked ? s.replace(AMBIG,'') : s;
  const cleaned = sets.map(clean);
  const all = cleaned.join('');
  const len = +$('length').value;
  const out = cleaned.map(s => s[randInt(s.length)]);      // guarantee one from each set
  while(out.length < len) out.push(all[randInt(all.length)]);
  for(let i=out.length-1;i>0;i--){ const j = randInt(i+1); [out[i],out[j]] = [out[j],out[i]]; }  // Fisher–Yates
  return out.join('');
}
function genPassphrase(){
  const n = +$('words').value, sep = $('sep').value;
  let ws = Array.from({length:n}, () => WORDS[randInt(WORDS.length)]);
  if($('optCap').checked) ws = ws.map(w => w[0].toUpperCase() + w.slice(1));
  let p = ws.join(sep);
  if($('optDigit').checked) p += sep + randInt(100);
  return p;
}
function generate(){ $('out').textContent = mode === 'password' ? genPassword() : genPassphrase(); }

/* ---------- events ---------- */
$('pw').addEventListener('input', renderAnalysis);
$('toggle').addEventListener('click', () => {
  const show = $('pw').type === 'password';
  $('pw').type = show ? 'text' : 'password';
  $('toggle').textContent = show ? 'Hide' : 'Show';
  $('toggle').setAttribute('aria-pressed', show);
});
$('length').addEventListener('input', () => { $('lengthVal').textContent = $('length').value; generate(); });
$('words').addEventListener('input', () => { $('wordsVal').textContent = $('words').value; generate(); });
document.querySelectorAll('#passwordOpts input[type=checkbox], #phraseOpts input[type=checkbox], #sep').forEach(el => el.addEventListener('change', generate));
$('regen').addEventListener('click', generate);
$('copy').addEventListener('click', async () => {
  try { await navigator.clipboard.writeText($('out').textContent); $('copy').textContent = 'Copied ✓'; }
  catch { $('copy').textContent = 'Press Ctrl+C'; }
  setTimeout(() => $('copy').textContent = 'Copy', 1500);
});
$('analyzeGen').addEventListener('click', () => {
  $('pw').value = $('out').textContent; renderAnalysis(); $('pw').scrollIntoView({behavior:'smooth', block:'center'});
});
document.querySelectorAll('.tab').forEach(t => t.addEventListener('click', () => {
  document.querySelectorAll('.tab').forEach(x => x.classList.remove('active'));
  t.classList.add('active'); mode = t.dataset.mode;
  $('passwordOpts').hidden = mode !== 'password';
  $('phraseOpts').hidden = mode !== 'passphrase';
  generate();
}));

renderAnalysis(); generate();
