
function toBig(n){ return BigInt(n); }


function modPow(base, exp, mod) {
  base = BigInt(base) % BigInt(mod);
  exp = BigInt(exp);
  mod = BigInt(mod);
  let result = 1n;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % mod;
    base = (base * base) % mod;
    exp >>= 1n;
  }
  return result;
}


function egcd(a,b){
  a = BigInt(a); b = BigInt(b);
  if (b === 0n) return {g:a, x:1n, y:0n};
  let {g,x:y1,y:x1} = egcd(b, a % b);
  return {g, x: x1, y: y1 - (a / b) * x1};
}
function modInverse(a,m){
  a=BigInt(a); m=BigInt(m);
  
  const res = egcd(a, m);
  if (res.g !== 1n) return null;
  let inv = res.x % m;
  if (inv < 0n) inv += m;
  return inv;
}


function isProbablePrime(n){
  n = BigInt(n);
  if (n < 2n) return false;
  const smallPrimes = [2n,3n,5n,7n,11n,13n,17n,19n,23n];
  for (let p of smallPrimes) if (n === p) return true;
  for (let p of smallPrimes) if (n % p === 0n) return false;

  
  let s = 0n;
  let d = n - 1n;
  while ((d & 1n) === 0n) { d >>= 1n; s += 1n; }

  
  const bases = [2n, 3n, 5n, 7n, 11n];
  for (let a of bases) {
    if (a >= n - 2n) continue;
    let x = modPow(a, d, n);
    if (x === 1n || x === n - 1n) continue;
    let cont = false;
    for (let r = 1n; r < s; r++) {
      x = (x * x) % n;
      if (x === n - 1n) { cont = true; break; }
    }
    if (cont) continue;
    return false;
  }
  return true;
}


function cryptoRandBetween(min, max){
  min = BigInt(min); max = BigInt(max);
  if (max <= min) return min;
  const range = max - min + 1n;
  const bits = range.toString(2).length;
  const bytes = Math.ceil(bits / 8);
  const buf = new Uint8Array(bytes);
  while (true) {
    crypto.getRandomValues(buf);
    let r = 0n;
    for (let i = 0; i < buf.length; i++) {
      r = (r << 8n) + BigInt(buf[i]);
    }
    if (r < (1n << BigInt(bytes*8)) - ((1n << BigInt(bytes*8)) % range)) {
      return min + (r % range);
    }
  }
}


const $ = id => document.getElementById(id);
const messages = $('messages');

function showMsg(txt, isError=false){
  messages.textContent = txt;
  messages.style.color = isError ? '#ff8b8b' : 'var(--muted)';
}

function markError(el, cond){
  if (cond) el.classList.add('error'); else el.classList.remove('error');
}


function analyzeText(){
  const text = $('plainText').value || '';
  if (!text) { showMsg('Введи текст для аналізу.', true); return; }

  
  let maxCode = 0;
  for (const ch of text) {
    const cp = ch.codePointAt(0);
    if (cp > maxCode) maxCode = cp;
  }

 
  const candidates = [65537n, 131071n, 262139n, 1000003n, 10000019n];
  let suitable = candidates.filter(c => c > BigInt(maxCode));
  
  if (suitable.length === 0) {
    let pTry = BigInt(maxCode) + 101n;
    while (!isProbablePrime(pTry)) pTry += 2n;
    suitable.push(pTry);
  }

  
  $('p').value = suitable[0].toString();
  $('pHint').textContent = `Максимальний код у тексті: ${maxCode}. Рекомендовані p: ${suitable.map(s=>s.toString()).join(', ')}`;
  showMsg('Проаналізовано: вибери p або натисни "Автогенерувати g, x, k".');
  markError($('p'), false);
}


function genAll(){
  try{
    const pStr = $('p').value.trim();
    if (!pStr) { showMsg('Вкажи p перед автогенерацією.', true); markError($('p'), true); return; }
    const p = BigInt(pStr);
    if (!isProbablePrime(p)) { showMsg('p має бути простим числом! Введи інше p.', true); markError($('p'), true); return; }
    markError($('p'), false);

    
    let g = 2n;
    if (p > 3n) {
     
      const tries = [2n,3n,5n,7n,11n];
      let found = false;
      for (let cand of tries){
        if (cand >= p-1n) continue;
        g = cand;
        found = true;
        break;
      }
      if (!found) g = 2n;
    }

    
    const x = cryptoRandBetween(2n, p-2n);
    
    const k = cryptoRandBetween(2n, p-2n);

    $('g').value = g.toString();
    $('x').value = x.toString();
    $('k').value = k.toString();
    $('gHint').textContent = 'g обрано автоматично (невелике число). Якщо хочеш, можна ввести інше.';
    $('xHint').textContent = 'Закритий ключ згенеровано крипто-гарантовано.';
    $('kHint').textContent = 'k згенеровано. Для кожного шифрування бажано нове k.';
    showMsg('g, x, k згенеровано.');
  }catch(e){
    showMsg('Помилка при генерації: ' + e.toString(), true);
  }
}


function genPublic(){
  try{
    const p = BigInt($('p').value);
    const g = BigInt($('g').value);
    const x = BigInt($('x').value);
    if (!isProbablePrime(p)){ showMsg('p має бути простим!', true); markError($('p'), true); return; }
    markError($('p'), false);
    if (!(g >= 2n && g <= p-2n)){ showMsg('g має бути в діапазоні [2, p-2]', true); markError($('g'), true); return; }
    markError($('g'), false);
    if (!(x >= 1n && x <= p-2n)){ showMsg('x має бути в діапазоні [1, p-2]', true); markError($('x'), true); return; }
    markError($('x'), false);

    const y = modPow(g, x, p);
    $('y').value = y.toString();
    showMsg('Відкритий ключ згенеровано.');
  } catch(e){
    showMsg('Помилка: ' + e.toString(), true);
  }
}


function encryptText(){
  try{
    const p = BigInt($('p').value);
    const g = BigInt($('g').value);
    const y = $('y').value ? BigInt($('y').value) : null;
    let k = $('k').value ? BigInt($('k').value) : null;
    const text = $('plainText').value || '';

    
    if (!isProbablePrime(p)){ showMsg('p має бути простим!', true); markError($('p'), true); return; }
    markError($('p'), false);
    if (!(g >= 2n && g <= p-2n)){ showMsg('g має бути в діапазоні [2, p-2]', true); markError($('g'), true); return; }
    markError($('g'), false);
    if (!y){ showMsg('Спочатку згенеруй відкритий ключ y (натисни "Згенерувати відкритий ключ").', true); return; }

    if (!k || k < 2n || k > p-2n){
      
      k = cryptoRandBetween(2n, p-2n);
      $('k').value = k.toString();
      $('kHint').textContent = 'k автозгенеровано (щоб не повторювати вручну).';
    }

    
    let maxCode = 0;
    const codePoints = [];
    for (const ch of text) {
      const cp = ch.codePointAt(0);
      codePoints.push(cp);
      if (cp > maxCode) maxCode = cp;
    }
    if (BigInt(maxCode) >= p) { showMsg(`Максимальний код символа у тексті = ${maxCode} >= p. Обери більший p.`, true); markError($('p'), true); return; }
    markError($('p'), false);

    let cipher = [];
   
    const a = modPow(g, k, p);
    const yk = modPow(y, k, p);

    for (let cp of codePoints){
      const m = BigInt(cp);
      const b = (m * yk) % p;
      cipher.push([a.toString(), b.toString()]);
    }

    $('cipher').value = JSON.stringify(cipher);
    showMsg('Текст зашифровано. Шифротекст у полі нижче.');
  } catch(e){
    showMsg('Помилка при шифруванні: ' + e.toString(), true);
  }
}


function decryptText(){
  try{
    const p = BigInt($('p').value);
    const x = BigInt($('x').value);
    const ctext = $('cipher').value;
    if (!ctext){ showMsg('Немає шифротексту. Зашифруй або встав JSON.', true); return; }

    let cipher;
    try { cipher = JSON.parse(ctext); } catch(e){ showMsg('Шифротекст має бути у форматі JSON (масив пар).', true); markError($('cipher'), true); return; }
    markError($('cipher'), false);

   
    let out = '';
    for (let pair of cipher){
      if (!Array.isArray(pair) || pair.length < 2) { showMsg('Невірний формат однієї з пар у шифротексті.', true); return; }
      const a = BigInt(pair[0]);
      const b = BigInt(pair[1]);
      const s = modPow(a, x, p);
      const inv = modInverse(s, p);
      if (inv === null){ showMsg('Не вдалося знайти обернений елемент (s та p не взаємно прості).', true); return; }
      const m = (b * inv) % p;
      out += String.fromCodePoint(Number(m));
    }

    $('decrypted').value = out;
    showMsg('Розшифровано успішно.');
  } catch(e){
    showMsg('Помилка при дешифруванні: ' + e.toString(), true);
  }
}

function clearAll(){
  $('cipher').value = '';
  $('decrypted').value = '';
  showMsg('Поля очищено.');
}


document.addEventListener('DOMContentLoaded', () => {
  $('analyzeBtn').addEventListener('click', analyzeText);
  $('genAllBtn').addEventListener('click', genAll);
  $('genPubBtn').addEventListener('click', genPublic);
  $('encryptBtn').addEventListener('click', encryptText);
  $('decryptBtn').addEventListener('click', decryptText);
  $('clearBtn').addEventListener('click', clearAll);

  
  $('plainText').addEventListener('input', () => {
    showMsg('Текст змінено — натисни "Аналізувати текст та запропонувати p" щоб оновити підказки.');
  });

  
  $('p').value = '65537';
  $('g').value = '3';
  showMsg('Готово. Введи текст і натисни "Аналізувати текст".');
});
