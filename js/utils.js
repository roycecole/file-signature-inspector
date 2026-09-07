/* =============================================================
   utils.js — 共用小工具
   ---------------------------------------------------------------
   這裡的函式不依賴任何其他檔案，被本專案幾乎所有模組使用，
   所以要放在 <script> 載入順序的最前面（utils.js 必須第一個載入）。

   內容：
   - esc()        HTML escape，所有動態插入的字串都要經過這裡，避免 XSS
   - hexOf()      Uint8Array → 大寫十六進位字串
   - getExt()     從檔名取出副檔名（含點、小寫）
   - baseName()   從檔名去掉副檔名
   - ascii()      Uint8Array 指定範圍 → ASCII 字串（用來讀 RIFF/ftyp 這類標記）
   - readBytes()  File.slice() 的簡化包裝，回傳 Uint8Array
   - u16()/u32()  從 Uint8Array 指定位移讀小端序整數
   - fmtSize()/fmtTime()/pad2()  顯示用的格式化函式
   - toast()      畫面下方跳出的短暫提示
   - copyText()   複製到剪貼簿（含不支援 Clipboard API 時的備援）
   ============================================================= */

function esc(s){
  return String(s).replace(/[&<>"']/g, function(c){
    return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];
  });
}

function hexOf(bytes){
  let s = '';
  for(let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).toUpperCase().padStart(2,'0');
  return s;
}

function getExt(n){ const i = n.lastIndexOf('.'); return i > 0 ? n.slice(i).toLowerCase() : ''; }
function baseName(n){ const i = n.lastIndexOf('.'); return i > 0 ? n.slice(0,i) : n; }

function ascii(b, s, e){ return String.fromCharCode.apply(null, b.subarray(s,e)); }

async function readBytes(file, start, end){
  return new Uint8Array(await file.slice(start, Math.min(end, file.size)).arrayBuffer());
}

function u16(b,o){ return b[o] | (b[o+1]<<8); }
function u32(b,o){ return (b[o] | (b[o+1]<<8) | (b[o+2]<<16) | (b[o+3]<<24)) >>> 0; }

function fmtSize(n){
  if(n == null) return '-';
  if(n < 1024) return n + ' B';
  if(n < 1048576) return (n/1024).toFixed(1) + ' KB';
  if(n < 1073741824) return (n/1048576).toFixed(1) + ' MB';
  return (n/1073741824).toFixed(2) + ' GB';
}
function pad2(n){ return String(n).padStart(2,'0'); }
function fmtTime(ms){
  if(!ms) return '-';
  const d = new Date(ms);
  return d.getFullYear()+'-'+pad2(d.getMonth()+1)+'-'+pad2(d.getDate())+' '+pad2(d.getHours())+':'+pad2(d.getMinutes());
}

// 畫面下方的短暫提示（複製成功、批次作業完成…）
// role="status" + aria-live="polite"：這是非緊急的提示，螢幕報讀器
// 會在使用者目前操作的空檔唸出來，不會打斷正在進行的其他朗讀。
function toast(msg){
  const el = document.createElement('div');
  el.className = 'toast';
  el.setAttribute('role', 'status');
  el.setAttribute('aria-live', 'polite');
  el.textContent = msg;
  document.body.appendChild(el);
  setTimeout(function(){ el.remove(); }, 1800);
}

// 複製文字到剪貼簿；不支援 navigator.clipboard 時退回 execCommand('copy')
function copyText(t2){
  if(navigator.clipboard && navigator.clipboard.writeText){
    navigator.clipboard.writeText(t2).then(function(){ toast(t('toast.copied')); }, fallback);
  } else fallback();
  function fallback(){
    const ta = document.createElement('textarea');
    ta.value = t2; ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta); ta.select();
    try{ document.execCommand('copy'); toast(t('toast.copied')); }catch(e){ toast(t('toast.copyFailed')); }
    ta.remove();
  }
}
