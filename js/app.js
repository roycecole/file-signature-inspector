/* =============================================================
   app.js — 主程式：狀態、掃描流程、表格渲染、事件綁定
   ---------------------------------------------------------------
   這是整個工具的「膠水」：串接 detectors.js 的判定結果、
   preview.js 的預覽功能，畫成畫面上的表格，並處理使用者互動。

   載入順序要求（index.html 已按此順序引入）：
   utils.js → sha256.js → signatures.js → detectors.js →
   preview.js → reference-table.js → app.js（本檔案，最後載入）

   內容（依原本開發時的章節編號，方便對照舊版）：
   §3   DOM 參照與全域狀態
   §10  取得檔案（含資料夾遞迴 / 拖曳）
   §11  掃描流程（逐檔呼叫 analyzeFile）
   §9   analyzeFile()：分析單一檔案，整合 detectors.js 的結果
   §12  位元組對照與明細面板（renderDetail）
   §13  表格繪製（render / renderHead / visibleRows / renderSummary）
   §14  使用者動作（移除、重新下載、計算雜湊）
   §15  匯出（CSV / TXT 報告）
   §17  事件綁定（放在檔案最後，確保上面用到的函式都已定義）
   ============================================================= */

var $ = function(id){ return document.getElementById(id); };
var dropzone=$('dropzone'), fileInput=$('fileInput'), dirInput=$('dirInput'),
    controls=$('controls'), summaryEl=$('summary'), tableWrap=$('tableWrap'),
    tbody=$('tbody'), theadRow=$('theadRow'), filterCk=$('filterToggle'),
    searchBox=$('searchBox'), progressEl=$('progress'),
    alertBar=$('alertBar'), alertTitle=$('alertTitle'), alertText=$('alertText'),
    themeBtn=$('themeToggle'), langBtn=$('langToggle');

var allResults = [], expanded = new Set(), nextId = 1;
var sortKey = 'risk', sortDir = 1;
var MAX_FILES = 3000;
var RENDER_STEP = 150, renderLimit = RENDER_STEP;
var dupOnlyCk = $('dupOnly');
var hideReviewedCk = $('hideReviewed');

// 摘要 chip 點下去會變成篩選器。null 代表沒有套用任何 chip 篩選；
// 其餘可能值對應 renderSummary() 裡每個 chip 的 data-filter。
var chipFilter = null;

// 刪除復原用的堆疊。存的是 {result, index}，復原時放回原本的位置，
// 而不是一律插到最後——誤刪之後清單順序不會莫名其妙改變。
var undoStack = [];
var UNDO_LIMIT = 20;

/* ---------------------------------------------------------------
   已檢查標記的本機記憶（預設關閉）
   ---------------------------------------------------------------
   這是整個工具唯一會在使用者裝置上留下紀錄的功能，所以：
   - 預設關閉，必須自己勾選才會啟用
   - 索引用檔案內容的 SHA-256，不是檔名或路徑（換個檔名、換台機器
     的同一份檔案仍然認得出來，而且存下來的東西看不出原始檔名）
   - 只存雜湊值本身，不存檔名、大小、路徑或任何其他中繼資料
   - 隨時可以一鍵清除
   --------------------------------------------------------------- */
var PERSIST_KEY = 'fsi-reviewed';
var persistCk = $('persistReviewed');

function loadReviewedSet(){
  try{
    var raw = localStorage.getItem(PERSIST_KEY);
    if(!raw) return new Set();
    var arr = JSON.parse(raw);
    return new Set(Array.isArray(arr) ? arr : []);
  }catch(e){ return new Set(); }
}
function saveReviewedSet(set){
  // 注意：Set 不是 array-like（沒有 length），所以不能用
  // Array.prototype.slice.call() 轉換——那樣會永遠得到空陣列，
  // 結果就是「看起來有存，實際上什麼都沒寫進去」。必須用 Array.from()。
  try{ localStorage.setItem(PERSIST_KEY, JSON.stringify(Array.from(set))); }
  catch(e){ /* 隱私模式或容量已滿：靜靜失敗，功能仍可用，只是這次記不住 */ }
}
var reviewedHashes = loadReviewedSet();

/* ---------------------------------------------------------------
   把目前的檢視狀態同步到網址列 hash
   ---------------------------------------------------------------
   目的是「把這個檢視的連結貼給同事」。注意只存**檢視條件**
   （搜尋字串、篩選、排序、語言），不存任何檔案內容或檔名清單——
   檔案本身從來沒有離開過瀏覽器，連結自然也帶不走它們。
   用 replaceState 而不是直接改 location.hash，避免每動一個篩選
   就在瀏覽器歷史裡塞一筆，害使用者按上一頁按半天。
   --------------------------------------------------------------- */
var applyingHash = false;   // 套用 hash 期間避免又反過來寫回 hash

function writeHashState(){
  if(applyingHash) return;
  var parts = [];
  var q = searchBox.value.trim();
  if(q) parts.push('q=' + encodeURIComponent(q));
  if(chipFilter) parts.push('chip=' + chipFilter);
  if(!filterCk.checked) parts.push('all=1');            // 預設是勾選的，只記錄「非預設」
  if(dupOnlyCk.checked) parts.push('dup=1');
  if(hideReviewedCk && hideReviewedCk.checked) parts.push('hiderev=1');
  if(sortKey !== 'risk' || sortDir !== 1) parts.push('sort=' + sortKey + (sortDir === 1 ? '' : ':desc'));
  if(currentLang !== 'zh') parts.push('lang=' + currentLang);
  var hash = parts.length ? ('#' + parts.join('&')) : '';
  try{
    history.replaceState(null, '', location.pathname + location.search + hash);
  }catch(e){ /* file:// 下某些瀏覽器會擋 replaceState，忽略即可 */ }
}

function readHashState(){
  var raw = (location.hash || '').replace(/^#/, '');
  if(!raw) return;
  applyingHash = true;
  raw.split('&').forEach(function(pair){
    var i = pair.indexOf('=');
    var k = i < 0 ? pair : pair.slice(0, i);
    var v = i < 0 ? '' : decodeURIComponent(pair.slice(i + 1));
    if(k === 'q') searchBox.value = v;
    else if(k === 'chip' && CHIP_FILTERS[v]) chipFilter = v;
    else if(k === 'all') filterCk.checked = false;
    else if(k === 'dup') dupOnlyCk.checked = true;
    else if(k === 'hiderev' && hideReviewedCk) hideReviewedCk.checked = true;
    else if(k === 'sort'){
      var bits = v.split(':');
      sortKey = bits[0]; sortDir = (bits[1] === 'desc') ? -1 : 1;
    }
    else if(k === 'lang' && LANGS.indexOf(v) >= 0 && v !== currentLang) setLang(v);
  });
  applyingHash = false;
}


// COLUMNS 的 label 是函式而不是固定字串，因為語言可能中途切換；
// renderHead() 每次都重新呼叫 c.label() 取得當下語言的欄名。
var COLUMNS = [
  {key:null,     label:function(){return t('col.preview');}, sortable:false},
  {key:'name',   label:function(){return t('col.name');},    sortable:true},
  {key:'size',   label:function(){return t('col.size');},    sortable:true},
  {key:'mtime',  label:function(){return t('col.mtime');},   sortable:true},
  {key:'claimed',label:function(){return t('col.ext');},     sortable:true},
  {key:'type',   label:function(){return t('col.type');},    sortable:true},
  {key:'format', label:function(){return t('col.format');},  sortable:true},
  {key:'risk',   label:function(){return t('col.verdict');}, sortable:true},
  {key:null,     label:function(){return '';},                sortable:false}
];


function walkEntry(entry, out, prefix, depth){
  return new Promise(function(resolve){
    if(out.length >= MAX_FILES) return resolve();
    if(entry.isFile){
      entry.file(function(f){ out.push({file:f, path: prefix + f.name}); resolve(); }, function(){ resolve(); });
    } else if(entry.isDirectory && depth < 16){
      var reader = entry.createReader(), acc = [];
      var readBatch = function(){
        reader.readEntries(function(ents){
          if(!ents.length){
            (async function(){
              for(var i=0;i<acc.length;i++) await walkEntry(acc[i], out, prefix + entry.name + '/', depth+1);
              resolve();
            })();
          } else { acc = acc.concat(Array.prototype.slice.call(ents)); readBatch(); }
        }, function(){ resolve(); });
      };
      readBatch();
    } else resolve();
  });
}
async function filesFromDataTransfer(dt){
  var items = dt.items, entries = [];
  if(items && items.length && items[0].webkitGetAsEntry){
    for(var i=0;i<items.length;i++){
      var e = items[i].webkitGetAsEntry && items[i].webkitGetAsEntry();
      if(e) entries.push(e);
    }
  }
  if(entries.length){
    var out = [];
    for(var j=0;j<entries.length;j++) await walkEntry(entries[j], out, '', 0);
    if(out.length) return out;
  }
  return Array.prototype.slice.call(dt.files).map(function(f){ return {file:f, path:f.name}; });
}

/* ---------------------------------------------------------------
   分析用 Worker 池：把 analyzeFileCore() 的實際運算平行丟給多個
   detect-worker.js 執行，主執行緒只負責發派、收結果、補上 id 跟
   預覽 Blob。跟 sha256Async() 是同一套退回哲學：任何一個環節失敗
   都要能悄悄接住、退回主執行緒直接呼叫 analyzeFileCore()，不能讓
   使用者卡住。

   為什麼要「池」而不是單一個 Worker：ZIP／CFB 解析、文字啟發式這些
   都是 CPU 密集工作，單一 Worker 只是把工作搬到別的執行緒，並沒有
   平行化；開好幾個 Worker 輪流分派，才能真正用上多核心 CPU，大量
   檔案時感受得出差異。池子大小抓 CPU 邏輯核心數減一（留一顆給主
   執行緒跑 UI），並限制在 1～4 之間，避免核心數異常多的機器一次開
   太多 Worker 反而拖累（Worker 啟動本身有成本）。
   --------------------------------------------------------------- */
var detectWorkers = [];
var detectRR = 0;
var detectCallbacks = {};
var detectMsgId = 0;
var DETECT_TIMEOUT_MS = 30000;
var DETECT_POOL_SIZE = Math.max(1, Math.min(4, ((typeof navigator !== 'undefined' && navigator.hardwareConcurrency) || 2) - 1));

function spawnDetectWorker(){
  var w;
  try{ w = new Worker('js/detect-worker.js'); }catch(e){ return null; }
  w.onmessage = function(e){
    var d = e.data, cb = d && detectCallbacks[d.reqId];
    if(!cb) return;
    delete detectCallbacks[d.reqId];
    cb(d.type === 'result' ? d.result : null, d.type === 'error' ? d.error : null);
  };
  w.onerror = function(){
    // 這顆 worker 掛了：從池子裡換掉，並嘗試補一顆新的頂上，讓池子盡量
    // 維持原本的大小；如果新的也建不起來，就讓池子縮小，剩下的 worker
    // 繼續分擔工作，真的全部掛光才整組退回主執行緒。
    var idx = detectWorkers.indexOf(w);
    if(idx >= 0) detectWorkers.splice(idx, 1);
    var replacement = spawnDetectWorker();
    if(replacement) detectWorkers.push(replacement);
  };
  try{ w.postMessage({type:'sync-custom-sigs', sigs: customSigs}); }catch(e){}
  return w;
}
function initDetectWorkerPool(){
  if(typeof Worker === 'undefined') return;
  for(var i = 0; i < DETECT_POOL_SIZE; i++){
    var w = spawnDetectWorker();
    if(!w) break; // 第一顆就建不起來，大概率是環境完全不支援（例如 file://），不用再試
    detectWorkers.push(w);
  }
}
initDetectWorkerPool();

function broadcastCustomSigsToWorkers(){
  detectWorkers.forEach(function(w){ try{ w.postMessage({type:'sync-custom-sigs', sigs: customSigs}); }catch(e){} });
}

function runAnalysisCore(file, relPath){
  return new Promise(function(resolve){
    function fallbackLocal(){ analyzeFileCore(file, relPath).then(resolve); }
    if(!detectWorkers.length){ fallbackLocal(); return; }

    var w = detectWorkers[detectRR % detectWorkers.length];
    detectRR++;

    var reqId = ++detectMsgId;
    var timedOut = false;
    var timer = setTimeout(function(){
      timedOut = true;
      delete detectCallbacks[reqId];
      fallbackLocal();
    }, DETECT_TIMEOUT_MS);

    detectCallbacks[reqId] = function(result, err){
      if(timedOut) return;
      clearTimeout(timer);
      if(err || !result) fallbackLocal();
      else resolve(result);
    };

    try{
      w.postMessage({type:'analyze', reqId:reqId, file:file, relPath:relPath, lang:currentLang});
    }catch(e){
      clearTimeout(timer);
      delete detectCallbacks[reqId];
      fallbackLocal();
    }
  });
}

// 預覽用的 Blob URL 只在主執行緒建立（見 detectors.js 裡 analyzeFileCore
// 開頭的說明）。analyzeFileCore 已經決定好 previewKind/previewMime，
// 這裡只需要依大小門檻決定要不要「現在就」建立，或是留到使用者在
// 燈箱裡按「仍要載入預覽」才建立。
function attachPreview(r, file){
  r.previewUrl = null;
  r.previewTooLarge = false;
  if(!r.previewKind) return;
  var limit = PREVIEW_SIZE_LIMIT[r.previewKind] || Infinity;
  if(file.size <= limit){
    try{ r.previewUrl = URL.createObjectURL(file.slice(0, file.size, r.previewMime)); }catch(e){}
  } else {
    r.previewTooLarge = true;
  }
}

async function analyzeFile(file, relPath){
  var r = await runAnalysisCore(file, relPath);
  r.id = nextId++;
  r.file = file;
  r.sha256 = null;
  r.hashing = false;
  r.reviewed = false;
  attachPreview(r, file);
  return r;
}

var scanning = false;
async function handleEntries(list){
  if(scanning) return;
  scanning = true;
  controls.classList.remove('hidden');
  if(list.length > MAX_FILES){
    list = list.slice(0, MAX_FILES);
    toast(t('toast.tooManyFiles', {n:MAX_FILES}));
  }
  progressEl.classList.remove('hidden');
  for(var i=0;i<list.length;i++){
    progressEl.textContent = t('progress.scanning', {i:i+1, n:list.length, path:list[i].path});
    allResults.push(await analyzeFile(list[i].file, list[i].path));
    if(i % 100 === 0){ render(); await new Promise(function(r){ setTimeout(r,0); }); }
  }
  progressEl.classList.add('hidden');
  progressEl.textContent = '';
  scanning = false;
  render();
}


// r.suggestExt 在「純文字檔（無簽章）」的情況下是空字串，改用一句
// 語言中立的說明文字（"fmt.genericTextExt"）顯示，而不是把 40 種
// TEXT_EXT 副檔名整串列出來；由於是在顯示當下才查表，切換語言後
// 這裡也會跟著換，不會卡住舊語言。
function suggestExtDisplay(r){
  return r.suggestExtGeneric ? t('fmt.genericTextExt') : r.suggestExt;
}

function buildMismatchDetail(r){
  var expected = EXT_SIG_MAP[r.claimed];
  if(!expected){
    return {hasGrid:false, note:t('detail.noExpectedSig', {ext:esc(r.claimed), format:esc(formatName(r.format))})};
  }
  var em = expected.magic, ec = em.length/2;
  var show = Math.min(12, Math.max(ec+2, 8));
  var cells = [], allMatch = true, comparable = false;
  for(var i=0;i<show;i++){
    var ab = r.rawHex.substr(i*2,2) || null;
    var eb = i < ec ? em.substr(i*2,2) : null;
    var st = 'empty';
    if(eb && ab){ comparable = true; st = (eb === ab) ? 'match' : 'mismatch'; if(st==='mismatch') allMatch = false; }
    cells.push({eb:eb, ab:ab, st:st});
  }
  // 預期格式的顯示名稱：ZIP 家族要用 family 現組句子（見 signatures.js 的
  // 註解），其餘直接查 FORMAT_NAME_I18N。
  var expectedDisplay = expected.isZip
    ? t('fmt.zipContainerOf', {family: formatName(expected.family)})
    : formatName(expected.name);
  var note;
  if(expected.isZip && allMatch && comparable){
    note = t('detail.zipHeaderOk', {
      magic: em.replace(/(..)/g,'$1 ').trim(),
      format: esc(formatName(r.format)),
      ext: esc(r.claimed)
    });
  } else {
    var idx = -1;
    for(var k=0;k<cells.length;k++){ if(cells[k].st==='mismatch'){ idx=k; break; } }
    var posText = idx>=0 ? t('detail.byteN', {n:idx+1}) : t('detail.firstFewBytes');
    note = t('detail.mismatchExplain', {
      ext: esc(r.claimed),
      expected: '<b>'+esc(expectedDisplay)+'</b>',
      pos: posText,
      format: esc(formatName(r.format))
    });
  }
  return {hasGrid:true, cells:cells, note:note, firstBad: cells.findIndex ? cells.findIndex(function(c){return c.st==='mismatch';}) : -1};
}

function hexDump(bytes, badCount){
  var out = [], i, j;
  for(i=0;i<bytes.length;i+=16){
    var offs = i.toString(16).padStart(8,'0');
    var hexPart = '', asciiPart = '';
    for(j=0;j<16;j++){
      if(i+j < bytes.length){
        var b = bytes[i+j];
        var hx = b.toString(16).toUpperCase().padStart(2,'0');
        hexPart += (i+j < badCount ? '<span class="hl">'+hx+'</span>' : hx) + ' ';
        asciiPart += (b >= 0x20 && b < 0x7F) ? esc(String.fromCharCode(b)) : '.';
      } else { hexPart += '   '; asciiPart += ' '; }
      if(j === 7) hexPart += ' ';
    }
    out.push('<span class="off">'+offs+'</span>  '+hexPart+' <span class="as">|'+asciiPart+'|</span>');
  }
  return '<div class="hexdump">'+out.join('<br>')+'</div>';
}

function renderDetail(r){
  var html = '';

  if(r.risks && r.risks.length){
    html += r.risks.map(function(w){
      return '<div class="detail-warning'+(w.level==='info'?' info':'')+'">'+
             '<h4>'+(w.level==='high'?'⚠ ':'ℹ ')+esc(w.title)+'</h4><p>'+esc(w.text)+'</p></div>';
    }).join('');
  }

  if(r.verdict === 'mismatch'){
    var d = buildMismatchDetail(r);
    html += '<p class="detail-note">'+d.note+'</p>';
    if(d.hasGrid){
      var exp = d.cells.map(function(c){ return c.eb===null ? '<span class="bytecell empty">–</span>' : '<span class="bytecell '+c.st+'">'+c.eb+'</span>'; }).join('');
      var act = d.cells.map(function(c){ return c.ab===null ? '<span class="bytecell empty">–</span>' : '<span class="bytecell '+(c.st==='empty'?'':c.st)+'">'+c.ab+'</span>'; }).join('');
      html += '<div class="bytegrid-wrap">'+
        '<div class="byterow"><span class="rowlabel">'+t('detail.byteGridExpected')+'</span><span class="bytecells">'+exp+'</span></div>'+
        '<div class="byterow"><span class="rowlabel">'+t('detail.byteGridActual')+'</span><span class="bytecells">'+act+'</span></div></div>'+
        '<div class="legend"><span><i class="match"></i>'+t('detail.legendMatch')+'</span><span><i class="mismatch"></i>'+t('detail.legendMismatch')+'</span><span><i class="empty"></i>'+t('detail.legendEmpty')+'</span></div>';
    }
  }

  html += '<div class="dsec"><div class="dsec-title">'+t('detail.fileInfoTitle')+'</div><dl class="kv">'+
    '<dt>'+t('detail.fullPath')+'</dt><dd>'+esc(r.name)+'</dd>'+
    '<dt>'+t('detail.size')+'</dt><dd>'+fmtSize(r.size)+'（'+r.size.toLocaleString()+' bytes）</dd>'+
    '<dt>'+t('detail.mtime')+'</dt><dd>'+fmtTime(r.mtime)+'</dd>'+
    '<dt>'+t('detail.detectedFormat')+'</dt><dd>'+esc(formatName(r.format))+'</dd>'+
    '<dt>'+t('detail.suggestedExt')+'</dt><dd>'+esc(suggestExtDisplay(r))+'</dd>'+
    '</dl></div>';

  // 不符時，把「依副檔名本應是簽章」的那幾個位元組在傾印中標紅
  var badLen = 0;
  if(r.verdict === 'mismatch' && EXT_SIG_MAP[r.claimed] && !EXT_SIG_MAP[r.claimed].isZip)
    badLen = EXT_SIG_MAP[r.claimed].magic.length / 2;
  html += '<div class="dsec"><div class="dsec-title-row">'+
            '<div class="dsec-title">'+t('detail.headBytesTitle', {n:r.head.length, note: badLen ? t('detail.headBytesNote') : ''})+'</div>'+
            '<button class="minibtn" data-copy-hex="'+r.id+'" title="'+t('detail.copyHexTitle')+'">'+t('detail.copyHex')+'</button>'+
          '</div>'+hexDump(r.head, badLen)+'</div>';

  html += '<div class="dsec"><div class="dsec-title">'+t('detail.sha256Title')+'</div><div class="hashrow">';
  if(r.sha256){
    html += '<code class="hashval">'+r.sha256+'</code>'+
            '<button class="minibtn" data-copy-hash="'+r.id+'">'+t('detail.copy')+'</button>'+
            '<a class="vt-link" target="_blank" rel="noopener noreferrer" href="https://www.virustotal.com/gui/file/'+r.sha256+'">'+t('detail.vtLink')+'</a>';
  } else if(r.hashing){
    html += '<span class="detail-note" style="margin:0">'+t('detail.hashing')+'</span>';
  } else {
    html += '<button class="minibtn" data-hash="'+r.id+'">'+t('detail.calcSha256')+'</button>'+
            '<span class="detail-note" style="margin:0">'+t('detail.hashHint')+'</span>';
  }
  html += '</div></div>';

  if(r.dupCount > 1){
    var sibs = (dupIndex[r.sha256] || []).filter(function(x){ return x.id !== r.id; });
    html += '<div class="dsec"><div class="dsec-title">'+t('detail.dupTitle', {n:r.dupCount})+'</div>'+
            '<div class="hexdump">'+sibs.map(function(x){ return esc(x.name); }).join('<br>')+'</div></div>';
  }

  if(r.zipEntries && r.zipEntries.length){
    var preview = r.zipEntries.slice(0, 12).map(esc).join('<br>');
    html += '<div class="dsec"><div class="dsec-title">'+t('detail.zipEntriesTitle', {n:r.zipEntries.length})+'</div>'+
            '<div class="hexdump">'+preview+'</div></div>';
  }

  if(r.cfbNames && r.cfbNames.length){
    var cn = r.cfbNames.slice(0, 14).map(function(x){
      return esc(x.replace(/[\u0000-\u001F]/g, '·').replace(/[\u3800-\u4DFF]/g, '◇'));
    }).join('<br>');
    html += '<div class="dsec"><div class="dsec-title">'+t('detail.cfbEntriesTitle', {n:r.cfbNames.length})+'</div>'+
            '<div class="hexdump">'+cn+'</div>'+
            '<p class="detail-note" style="margin-top:7px">'+t('detail.msiHint')+'</p></div>';
  }

  return '<div class="detail-panel">'+html+'</div>';
}

function riskRank(r){ return r.high ? 0 : (r.type==='exec' ? 1 : (r.verdict==='mismatch' ? 2 : (r.verdict==='unknown' ? 3 : 4))); }

/* 依 SHA-256 分組，找出內容完全相同的檔案 */
var dupIndex = {};
function rebuildDupIndex(){
  var m = {};
  allResults.forEach(function(r){
    if(!r.sha256) return;
    (m[r.sha256] = m[r.sha256] || []).push(r);
  });
  dupIndex = {};
  Object.keys(m).forEach(function(h){ if(m[h].length > 1) dupIndex[h] = m[h]; });
  allResults.forEach(function(r){
    r.dupCount = (r.sha256 && dupIndex[r.sha256]) ? dupIndex[r.sha256].length : 0;
  });
}

// chip 篩選的判定：每個可點擊的 chip 對應一個判斷函式，
// renderSummary() 產生 chip 時用同一組 key，兩邊必須一致。
var CHIP_FILTERS = {
  image:    function(r){ return r.type === 'image'; },
  doc:      function(r){ return r.type === 'doc'; },
  text:     function(r){ return r.type === 'text'; },
  mismatch: function(r){ return r.verdict === 'mismatch'; },
  dup:      function(r){ return r.dupCount > 0; },
  exec:     function(r){ return r.type === 'exec'; },
  high:     function(r){ return r.high; },
  reviewed: function(r){ return r.reviewed; }
};

function visibleRows(){
  var q = searchBox.value.trim().toLowerCase();
  var rows = allResults.filter(function(r){
    if(q && r.name.toLowerCase().indexOf(q) < 0) return false;
    if(dupOnlyCk.checked && !r.dupCount) return false;
    if(hideReviewedCk && hideReviewedCk.checked && r.reviewed) return false;
    // chip 篩選優先於「只顯示可辨識類型」——使用者主動點了「高風險 3」，
    // 就應該看到那三筆，不該再被類型篩選擋掉。
    if(chipFilter && CHIP_FILTERS[chipFilter]) return CHIP_FILTERS[chipFilter](r);
    if(filterCk.checked){
      if(r.high || r.type==='exec') return true;
      return r.type==='image' || r.type==='doc' || r.type==='text';
    }
    return true;
  });
  rows.sort(function(a,b){
    var va, vb;
    if(sortKey === 'risk'){ va = riskRank(a); vb = riskRank(b); }
    else if(sortKey === 'size' || sortKey === 'mtime'){ va = a[sortKey]; vb = b[sortKey]; }
    else if(sortKey === 'type'){ va = kindLabel(a.type); vb = kindLabel(b.type); }
    else { va = String(a[sortKey]||''); vb = String(b[sortKey]||''); }
    if(va < vb) return -1 * sortDir;
    if(va > vb) return  1 * sortDir;
    return a.name.localeCompare(b.name);
  });
  return rows;
}

function renderHead(){
  theadRow.innerHTML = COLUMNS.map(function(c){
    if(!c.sortable) return '<th>'+c.label()+'</th>';
    var active = sortKey === c.key;
    var arrow = active ? (sortDir === 1 ? '▲' : '▼') : '▲';
    return '<th class="sortable'+(active?' active':'')+'" data-sort="'+c.key+'">'+c.label()+'<span class="arrow">'+arrow+'</span></th>';
  }).join('');
  theadRow.querySelectorAll('th.sortable').forEach(function(th){
    th.addEventListener('click', function(){
      var k = th.getAttribute('data-sort');
      if(sortKey === k) sortDir = -sortDir; else { sortKey = k; sortDir = 1; }
      refilter();
    });
  });
}

function render(){
  renderHead();
  var all = visibleRows();
  var rows = all.slice(0, renderLimit);
  var html = [];

  rows.forEach(function(r){
    var isOpen = expanded.has(r.id);
    var vh;
    if(r.high) vh = '<span class="verdict danger">'+t('verdict.high')+'</span>';
    else if(r.verdict === 'match') vh = '<span class="verdict match">'+t('verdict.match')+'</span>';
    else if(r.verdict === 'mismatch') vh = '<span class="verdict mismatch">'+t('verdict.mismatchArrow', {ext:esc(r.suggestFirst||'')})+'</span>';
    else vh = '<span class="verdict unknown">'+t('verdict.unknown')+'</span>';
    vh += ' <span class="chev'+(isOpen?' open':'')+'">▸</span>';

    var prev = buildPreviewCell(r);

    var dupTag = r.dupCount ? ' <span class="duptag" title="'+t('row.dupTitle',{n:r.dupCount})+'">'+t('row.dupTag',{n:r.dupCount})+'</span>' : '';

    var actions = '';
    if(r.verdict === 'mismatch' && r.suggestFirst)
      actions += '<button class="icon-btn" data-fix="'+r.id+'" title="'+t('row.titleFix')+'">⤓</button>';
    actions += '<button class="icon-btn compare" data-compare="'+r.id+'" aria-pressed="'+(isInCompare(r.id)?'true':'false')+'" '+
               'title="'+esc(t('compare.addTitle'))+'">⇄</button>';
    actions += '<button class="icon-btn review" data-review="'+r.id+'" aria-pressed="'+(r.reviewed?'true':'false')+'" '+
               'title="'+esc(r.reviewed ? t('review.unToggle') : t('review.toggle'))+'" '+
               'aria-label="'+esc(t(r.reviewed ? 'review.ariaUnmark' : 'review.ariaMark', {name:r.name}))+'">✓</button>';
    actions += '<button class="icon-btn rm" data-remove="'+r.id+'" title="'+t('row.titleRemove')+'">✕</button>';

    var rowVerdictWord = r.high ? t('verdict.high') : r.verdict==='match' ? t('verdict.match') : r.verdict==='mismatch' ? t('verdict.mismatchPlain') : t('verdict.unknown');

    // data-label 屬性給手機版的卡片版面用（見 styles.css 的 @media 區塊）：
    // 窄螢幕時 <table> 會切換成卡片式排列，每個儲存格前面用 CSS
    // content:attr(data-label) 補上欄位名稱，取代看不到的表頭。
    //
    // 無障礙：整列本身也能用鍵盤展開（tabindex/role="button"/
    // aria-expanded 三兄弟），對應的明細 <tr> 用 aria-controls 指過去，
    // 這樣螢幕報讀器能唸出「按鈕，已收合／已展開」，Tab 過去按 Enter
    // 或空白鍵也能像滑鼠點擊一樣把明細打開。
    html.push('<tr class="datarow'+(r.high?' danger':'')+(r.reviewed?' reviewed':'')+'" data-key="'+r.id+'" '+
      'tabindex="0" role="button" aria-expanded="'+(isOpen?'true':'false')+'" '+
      'aria-controls="detail-'+r.id+'" aria-label="'+esc(t('aria.rowLabel',{name:r.name, verdict:rowVerdictWord}))+'">'+
      '<td class="preview" data-label="">'+prev+'</td>'+
      '<td class="name" data-label="'+t('col.name')+'" title="'+esc(r.name)+'">'+esc(r.name)+dupTag+'</td>'+
      '<td class="num" data-label="'+t('col.size')+'">'+fmtSize(r.size)+'</td>'+
      '<td class="time" data-label="'+t('col.mtime')+'">'+fmtTime(r.mtime)+'</td>'+
      '<td class="ext" data-label="'+t('col.ext')+'">'+esc(r.claimed)+'</td>'+
      '<td data-label="'+t('col.type')+'"><span class="kind-pill '+(KIND_CLASS[r.type]||'other')+'">'+kindLabel(r.type)+'</span></td>'+
      '<td class="fmt" data-label="'+t('col.format')+'">'+esc(formatName(r.format))+'</td>'+
      '<td data-label="'+t('col.verdict')+'">'+vh+'</td>'+
      '<td class="rowaction" data-label="">'+actions+'</td></tr>');

    if(isOpen) html.push('<tr class="detail-row" id="detail-'+r.id+'" role="region" aria-label="'+esc(t('aria.detailRegion',{name:r.name}))+'"><td colspan="9">'+renderDetail(r)+'</td></tr>');
  });

  if(all.length > rows.length){
    html.push('<tr class="moreRow"><td colspan="9"><div class="morebar">'+
      t('more.shown',{shown:rows.length, total:all.length})+
      '<button class="minibtn" id="moreBtn">'+t('more.showMore',{n:Math.min(RENDER_STEP, all.length - rows.length)})+'</button>'+
      '<button class="minibtn" id="allBtn">'+t('more.showAll')+'</button></div></td></tr>');
  }

  if(!all.length && allResults.length)
    html.push('<tr><td colspan="9"><div class="empty-state">'+t('empty.noMatch')+'</div></td></tr>');

  tbody.innerHTML = html.join('');
  tableWrap.classList.toggle('hidden', allResults.length === 0);
  bindRowEvents();
  var mb = document.getElementById('moreBtn');
  if(mb) mb.addEventListener('click', function(){ renderLimit += RENDER_STEP; render(); });
  var ab = document.getElementById('allBtn');
  if(ab) ab.addEventListener('click', function(){ renderLimit = Infinity; render(); });
  renderSummary();
}

function bindRowEvents(){
  function toggleRow(k){
    if(expanded.has(k)) expanded.delete(k); else expanded.add(k);
    render();
  }

  tbody.querySelectorAll('tr.datarow').forEach(function(tr){
    var k = Number(tr.getAttribute('data-key'));
    tr.addEventListener('click', function(e){
      if(e.target.closest('button') || e.target.closest('a') || e.target.closest('[data-zoom]')) return;
      toggleRow(k);
    });
    // 鍵盤：焦點在「列本身」時按 Enter／空白鍵展開，等同滑鼠點擊整列。
    // 空白鍵預設會捲動頁面，這裡要 preventDefault 蓋掉。
    tr.addEventListener('keydown', function(e){
      if(e.target !== tr) return; // 焦點在列內的按鈕/縮圖上時，交給它們自己的 keydown 處理
      if(e.key === 'Enter' || e.key === ' ' || e.key === 'Spacebar'){
        e.preventDefault();
        toggleRow(k);
      }
    });
  });

  tbody.querySelectorAll('[data-zoom]').forEach(function(el){
    el.addEventListener('click', function(e){ e.stopPropagation(); openLightbox(Number(el.getAttribute('data-zoom'))); });
    // 縮圖是 <img>/<span role="button">，不是原生 <button>，瀏覽器不會
    // 自動把 Enter/空白鍵轉成 click，要自己補上。
    el.addEventListener('keydown', function(e){
      if(e.key === 'Enter' || e.key === ' ' || e.key === 'Spacebar'){
        e.preventDefault();
        e.stopPropagation();
        openLightbox(Number(el.getAttribute('data-zoom')));
      }
    });
  });
  tbody.querySelectorAll('[data-compare]').forEach(function(b){
    b.addEventListener('click', function(e){ e.stopPropagation(); toggleCompareSlot(Number(b.getAttribute('data-compare'))); });
  });
  tbody.querySelectorAll('[data-review]').forEach(function(b){
    b.addEventListener('click', function(e){ e.stopPropagation(); toggleReviewed(Number(b.getAttribute('data-review'))); });
  });
  tbody.querySelectorAll('[data-remove]').forEach(function(b){
    b.addEventListener('click', function(e){ e.stopPropagation(); removeResult(Number(b.getAttribute('data-remove'))); });
  });
  tbody.querySelectorAll('[data-fix]').forEach(function(b){
    b.addEventListener('click', function(e){ e.stopPropagation(); downloadFixed(Number(b.getAttribute('data-fix'))); });
  });
  tbody.querySelectorAll('[data-hash]').forEach(function(b){
    b.addEventListener('click', function(e){ e.stopPropagation(); computeHash(Number(b.getAttribute('data-hash'))); });
  });
  tbody.querySelectorAll('[data-copy-hash]').forEach(function(b){
    b.addEventListener('click', function(e){
      e.stopPropagation();
      var r = allResults.find(function(x){ return x.id === Number(b.getAttribute('data-copy-hash')); });
      if(r && r.sha256) copyText(r.sha256);
    });
  });
  tbody.querySelectorAll('[data-copy-hex]').forEach(function(b){
    b.addEventListener('click', function(e){
      e.stopPropagation();
      var r = allResults.find(function(x){ return x.id === Number(b.getAttribute('data-copy-hex')); });
      if(r && r.head) copyText(hexOf(r.head));
    });
  });
}

function renderSummary(){
  rebuildDupIndex();
  var n = allResults.length;
  var cnt = function(f){ return allResults.filter(f).length; };
  var high = cnt(function(r){ return r.high; });

  // 產生一個可點擊的篩選 chip。key 要對應 CHIP_FILTERS 裡的判斷函式。
  // 計數為 0 的 chip 仍然顯示（讓數字位置穩定），但不做成可點擊的，
  // 因為點了只會得到空清單，沒有意義。
  function chip(key, label, count, extraClass){
    var active = chipFilter === key;
    if(!count) return '<div class="chip '+(extraClass||'')+'">'+label+'</div>';
    return '<button type="button" class="chip clickable '+(extraClass||'')+'" '+
           'data-chip="'+key+'" aria-pressed="'+(active?'true':'false')+'" '+
           'title="'+esc(t('filter.chipHint').trim())+'">'+label+'</button>';
  }

  var reviewedCount = cnt(function(r){ return r.reviewed; });
  var chips = [
    '<div class="chip">'+t('summary.scanned',{n:n})+'</div>',
    chip('image',    t('summary.image',{n:cnt(CHIP_FILTERS.image)}),       cnt(CHIP_FILTERS.image), 'img'),
    chip('doc',      t('summary.doc',{n:cnt(CHIP_FILTERS.doc)}),           cnt(CHIP_FILTERS.doc), 'doc'),
    chip('text',     t('summary.text',{n:cnt(CHIP_FILTERS.text)}),         cnt(CHIP_FILTERS.text)),
    chip('mismatch', t('summary.mismatch',{n:cnt(CHIP_FILTERS.mismatch)}), cnt(CHIP_FILTERS.mismatch))
  ];
  var groups = Object.keys(dupIndex).length;
  if(groups){
    var dupFiles = cnt(CHIP_FILTERS.dup);
    var wasted = 0;
    Object.keys(dupIndex).forEach(function(h){
      var g = dupIndex[h];
      wasted += g[0].size * (g.length - 1);
    });
    chips.push(chip('dup', t('summary.dup',{groups:groups, files:dupFiles, size:fmtSize(wasted)}), dupFiles));
  }
  var ex = cnt(CHIP_FILTERS.exec);
  if(ex) chips.push(chip('exec', t('summary.exec',{n:ex}), ex, 'danger'));
  if(high) chips.push(chip('high', t('summary.high',{n:high}), high, 'danger'));
  if(reviewedCount) chips.push(chip('reviewed', t('summary.reviewed',{done:reviewedCount, total:n}), reviewedCount));

  summaryEl.innerHTML = chips.join('');
  summaryEl.classList.toggle('hidden', n === 0);

  // chip 點擊：同一個再點一次就取消篩選（toggle）
  summaryEl.querySelectorAll('[data-chip]').forEach(function(b){
    b.addEventListener('click', function(){
      var key = b.getAttribute('data-chip');
      chipFilter = (chipFilter === key) ? null : key;
      if(!chipFilter) toast(t('filter.clearedAll'));
      refilter();
    });
  });

  // 有結果之後把拖放區縮成一條細長的提示，把版面讓給結果清單
  dropzone.classList.toggle('compact', n > 0);
  var dzTitle = dropzone.querySelector('strong');
  if(dzTitle) dzTitle.textContent = n > 0 ? t('dropzone.more') : t('dropzone.title');

  // 空狀態引導：只在完全沒有結果時顯示
  var emptyEl = $('emptyState');
  if(emptyEl) emptyEl.classList.toggle('hidden', n > 0);

  // 復原按鈕只在真的有東西可以復原時才啟用，避免變成一顆永遠按不動的死鈕
  var undoBtn = $('undoBtn');
  if(undoBtn) undoBtn.disabled = undoStack.length === 0;

  // 開啟本機記憶時顯示一段說明，明確告知使用者「這時候開始會留下紀錄」
  var notice = $('persistNotice');
  if(notice) notice.classList.toggle('hidden', !(persistCk && persistCk.checked));

  if(high){
    alertTitle.textContent = t('alert.title', {n:high});
    alertText.textContent = t('alert.text');
    alertBar.classList.remove('hidden');
  } else alertBar.classList.add('hidden');
}

// 取得目前焦點所在的結果列。document.activeElement 在某些情況下會是 null
// （元素剛被移除、文件本身還沒取得焦點等），而且並非所有節點型別都有
// closest()，所以這兩層都要防；少了任一層就會在真實瀏覽器裡偶發性拋錯。
function focusedRow(){
  var el = document.activeElement;
  if(!el || typeof el.closest !== 'function') return null;
  return el.closest('tr.datarow');
}

/* ---------------------------------------------------------------
   SHA-256 計算：優先丟給 Web Worker，失敗就自動退回主執行緒
   ---------------------------------------------------------------
   sha256File()（定義在 sha256.js）本身已經是「WebCrypto 優先、純
   JS 備援」，這裡再包一層「Worker 優先、主執行緒備援」，兩層退回
   互不影響：Worker 裡一樣會先試 WebCrypto。

   任何一個環節出狀況都要能悄悄接住、退回主執行緒繼續算，不能讓
   使用者卡在「一直轉圈圈但什麼都不會發生」：
   - 這個瀏覽器根本沒有 Worker（極舊瀏覽器）
   - new Worker() 直接拋例外（例如部分瀏覽器不允許 file:// 頁面建立
     Worker，這是已知限制，不是 bug）
   - postMessage 傳 File 物件失敗（少數瀏覽器的結構化複製限制）
   - Worker 內部出錯，或超過合理時間都沒回應

   用「池」而不是單一個 Worker，理由跟 detect-worker 的池子一樣：
   單一 Worker 只是把運算搬到別的執行緒，並沒有平行化。一次勾選
   「計算全部 SHA-256」處理上百個檔案時，多顆 Worker 輪流分攤才能
   真的縮短總時間。任何一顆 Worker 意外掛掉（onerror）會嘗試補一顆
   新的頂上，讓池子盡量維持原本大小，不會「壞一顆、少一顆」用到後來
   整組都退回主執行緒。
   --------------------------------------------------------------- */
var hashWorkers = [];
var hashRR = 0;
var workerCallbacks = {};
var workerMsgId = 0;
var WORKER_TIMEOUT_MS = 60000; // 一般檔案幾秒內就會有結果，超過一分鐘視為卡死
var HASH_POOL_SIZE = Math.max(1, Math.min(4, ((typeof navigator !== 'undefined' && navigator.hardwareConcurrency) || 2) - 1));

function spawnHashWorker(){
  var w;
  try{ w = new Worker('js/sha256-worker.js'); }catch(e){ return null; }
  w.onmessage = function(e){
    var id = e.data && e.data.id;
    var cb = workerCallbacks[id];
    if(!cb) return;
    delete workerCallbacks[id];
    cb(e.data.error ? null : e.data.hash, e.data.error);
  };
  w.onerror = function(){
    // 這顆掛了：從池子換掉，嘗試補一顆新的頂上。還在等這顆回應的請求
    // 沒辦法個別得知是哪些，交給 sha256Async() 自己的逾時機制去退回
    // 主執行緒即可，不需要在這裡特別處理。
    var idx = hashWorkers.indexOf(w);
    if(idx >= 0) hashWorkers.splice(idx, 1);
    var replacement = spawnHashWorker();
    if(replacement) hashWorkers.push(replacement);
  };
  return w;
}
function initHashWorkerPool(){
  if(typeof Worker === 'undefined') return;
  for(var i = 0; i < HASH_POOL_SIZE; i++){
    var w = spawnHashWorker();
    if(!w) break; // 第一顆就建不起來，環境大概率完全不支援，不用再試
    hashWorkers.push(w);
  }
}
initHashWorkerPool();

function sha256Async(file){
  return new Promise(function(resolve){
    function fallbackMainThread(){
      sha256File(file).then(resolve).catch(function(){ resolve(null); });
    }
    if(!hashWorkers.length){ fallbackMainThread(); return; }

    var w = hashWorkers[hashRR % hashWorkers.length];
    hashRR++;

    var id = ++workerMsgId;
    var timedOut = false;
    var timer = setTimeout(function(){
      timedOut = true;
      delete workerCallbacks[id];
      fallbackMainThread();
    }, WORKER_TIMEOUT_MS);

    workerCallbacks[id] = function(hash, err){
      if(timedOut) return; // 已經觸發過逾時退回，這個回應來得太晚，不理它
      clearTimeout(timer);
      if(err || !hash) fallbackMainThread();
      else resolve(hash);
    };

    try{
      w.postMessage({ id: id, file: file });
    }catch(e){
      // postMessage 本身就丟例外（例如這個瀏覽器不允許把 File 複製給 Worker）
      clearTimeout(timer);
      delete workerCallbacks[id];
      fallbackMainThread();
    }
  });
}

// 限制同時進行中的工作數量不超過 limit，跑完一個馬上補下一個進來，
// 而不是等一整批都排隊完成才開始下一批——這樣池子裡的 Worker 隨時
// 都有事做，不會出現「等最慢的那個」拖累整體速度的情況。
function runWithConcurrency(items, limit, task){
  return new Promise(function(resolveAll){
    var idx = 0, active = 0;
    if(!items.length){ resolveAll(); return; }
    function next(){
      if(idx >= items.length && active === 0){ resolveAll(); return; }
      while(active < limit && idx < items.length){
        (function(item){
          active++;
          task(item).catch(function(){}).then(function(){
            active--;
            next();
          });
        })(items[idx++]);
      }
    }
    next();
  });
}

function toggleReviewed(id){
  var target = allResults.find(function(r){ return r.id === id; });
  if(!target) return;
  target.reviewed = !target.reviewed;

  // 開啟本機記憶時，把這筆的 SHA-256 記下／移除。雜湊還沒算過的話
  // 先在背景算出來再存——所以標記大檔案時可能會慢一兩秒，這是必要成本，
  // 因為我們刻意用「檔案內容」而不是檔名當索引。
  if(persistCk && persistCk.checked){
    if(target.sha256){
      if(target.reviewed) reviewedHashes.add(target.sha256);
      else reviewedHashes.delete(target.sha256);
      saveReviewedSet(reviewedHashes);
    } else if(target.reviewed){
      toast(t('toast.hashingForPersist'));
      sha256Async(target.file).then(function(h){
        target.sha256 = h;
        if(target.reviewed){ reviewedHashes.add(h); saveReviewedSet(reviewedHashes); }
        render();
      }).catch(function(){ /* 算不出來就只是這次記不住，不影響畫面標記 */ });
    }
  }

  // 標記完之後如果「隱藏已檢查」是開著的，這一列會立刻消失；
  // 記住焦點原本在第幾列，重繪後把焦點放到接手該位置的那一列，
  // 讓連續用鍵盤標記一整批檔案時不會每標一次就要重新找位置。
  var rowsBefore = Array.prototype.slice.call(tbody.querySelectorAll('tr.datarow'));
  var focusIdx = rowsBefore.indexOf(focusedRow());
  render();
  if(focusIdx >= 0){
    var rowsAfter = tbody.querySelectorAll('tr.datarow');
    var next = rowsAfter[Math.min(focusIdx, rowsAfter.length - 1)];
    if(next) next.focus();
  }
}

// 掃描完成後，把本機記憶裡認得的檔案自動標記回「已檢查」。
// 需要雜湊才比對得出來，所以只對已經算過 SHA-256 的項目生效。
function applyStoredReviewMarks(){
  if(!persistCk || !persistCk.checked || !reviewedHashes.size) return;
  var changed = false;
  allResults.forEach(function(r){
    if(r.sha256 && !r.reviewed && reviewedHashes.has(r.sha256)){ r.reviewed = true; changed = true; }
  });
  return changed;
}

function undoRemove(){
  if(!undoStack.length){ toast(t('toast.nothingToUndo')); return; }
  var entry = undoStack.pop();
  // 放回原本的索引位置，避免復原之後清單順序莫名其妙變了
  allResults.splice(Math.min(entry.index, allResults.length), 0, entry.result);
  controls.classList.remove('hidden');
  render();
  toast(t('toast.undone', {name: entry.result.name.split('/').pop()}));
}

function removeResult(id){
  var idx = allResults.findIndex(function(r){ return r.id === id; });
  if(idx < 0) return;
  var target = allResults[idx];
  // 刻意「不」在這裡 revokeObjectURL：使用者可能只是誤按，
  // 一旦 revoke 掉，復原之後縮圖就再也顯示不出來了。
  // 真正的釋放時機改成「被擠出復原堆疊」或「清除全部」。
  undoStack.push({result: target, index: idx});
  if(undoStack.length > UNDO_LIMIT){
    var dropped = undoStack.shift();
    if(dropped.result.previewUrl) URL.revokeObjectURL(dropped.result.previewUrl);
  }
  allResults.splice(idx, 1);
  expanded.delete(id);
  var cIdx = compareSlots.indexOf(id);
  if(cIdx >= 0){ compareSlots.splice(cIdx, 1); renderCompareBar(); }
  if(!allResults.length){
    summaryEl.classList.add('hidden');
    tableWrap.classList.add('hidden'); alertBar.classList.add('hidden');
  }
  render();
}

function downloadFixed(id){
  var r = allResults.find(function(x){ return x.id === id; });
  if(!r || !r.suggestFirst) return;
  var plain = r.name.split('/').pop();
  var newName = baseName(plain) + r.suggestFirst;
  var url = URL.createObjectURL(r.file);
  var a = document.createElement('a');
  a.href = url; a.download = newName;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(function(){ URL.revokeObjectURL(url); }, 5000);
  toast(t('toast.savedAs', {name:newName}));
}

async function computeHash(id){
  var r = allResults.find(function(x){ return x.id === id; });
  if(!r || r.sha256 || r.hashing) return;
  r.hashing = true; render();
  try{ r.sha256 = await sha256Async(r.file); }
  catch(e){ toast(t('toast.hashFailed')); }
  r.hashing = false; render();
}

async function hashAll(){
  var todo = allResults.filter(function(r){ return !r.sha256; });
  if(!todo.length){ toast(t('toast.allHashed')); return; }
  progressEl.classList.remove('hidden');
  var done = 0;
  // 平行度跟 Worker 池的大小一致：沒有任何 Worker 可用時，
  // sha256Async() 會退回主執行緒同步計算，這種情況下開再高的並行度
  // 也沒有意義（主執行緒本來就一次只能做一件事），所以池子是空的時候
  // 並行度退回 1，跟以前逐一處理的行為一致，不會反而變慢或出錯。
  var concurrency = hashWorkers.length || 1;
  await runWithConcurrency(todo, concurrency, async function(item){
    try{ item.sha256 = await sha256Async(item.file); }catch(e){}
    done++;
    progressEl.textContent = t('progress.hashing', {i:done, n:todo.length, name:item.name});
  });
  progressEl.classList.add('hidden');
  // 雜湊都算出來了，這時才有辦法比對本機記憶裡存的 SHA-256
  applyStoredReviewMarks();
  render();
  toast(t('toast.hashedN', {n:todo.length}));
}

// openLightbox()／buildPreviewCell() 已搬到 preview.js，跟其他預覽相關程式碼放在一起。

function reportRows(){
  var rows = visibleRows().slice();
  return rows;
}
function stamp(){
  var d = new Date();
  return d.getFullYear()+pad2(d.getMonth()+1)+pad2(d.getDate())+'_'+pad2(d.getHours())+pad2(d.getMinutes())+pad2(d.getSeconds());
}
function saveBlob(text, filename, mime){
  var blob = new Blob(['\ufeff' + text], {type: mime});
  var a = document.createElement('a');
  a.href = URL.createObjectURL(blob); a.download = filename;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(function(){ URL.revokeObjectURL(a.href); }, 5000);
}
function csvCell(v){
  var s = (v == null ? '' : String(v));
  return /[",\r\n]/.test(s) ? '"' + s.replace(/"/g,'""') + '"' : s;
}
// 把目前套用的篩選條件描述成一串人看得懂的文字，寫進匯出報告。
// 做稽核紀錄時這很重要：一份只列出 12 筆的 CSV，如果沒寫清楚
// 「這是套了『只看高風險』之後的結果」，日後回頭看會誤以為
// 當時整批只有 12 個檔案。
function describeActiveFilters(){
  var list = [];
  var q = searchBox.value.trim();
  if(q) list.push(t('export.filterSearch', {q:q}));
  if(filterCk.checked) list.push(t('export.filterKnownOnly'));
  if(dupOnlyCk.checked) list.push(t('export.filterDupOnly'));
  if(hideReviewedCk && hideReviewedCk.checked) list.push(t('export.filterHideReviewed'));
  if(chipFilter){
    var nameMap = {
      image:t('kind.image'), doc:t('kind.doc'), text:t('kind.text'), exec:t('kind.exec'),
      mismatch:t('verdict.mismatchPlain'), high:t('export.verdictHigh'),
      dup:t('controls.dupOnly'), reviewed:t('export.reviewed')
    };
    list.push(t('export.filterChip', {name: nameMap[chipFilter] || chipFilter}));
  }
  return list.length ? list.join('、') : t('export.filterNone');
}

function reviewStatusText(r){
  return r.reviewed ? t('export.reviewed') : t('export.notReviewed');
}

function exportCsv(){
  if(!allResults.length) return;
  var rows = reportRows();
  var reviewedCount = allResults.filter(function(r){ return r.reviewed; }).length;
  // CSV 開頭放兩行以 # 開頭的註記，記錄匯出當下的篩選條件與檢查進度。
  // Excel 會把它們當成一般文字列，不影響下面的表格解析。
  var lines = [
    csvCell('# ' + t('export.activeFilters', {list: describeActiveFilters()})),
    csvCell('# ' + t('export.reviewedSummary', {done: reviewedCount, total: allResults.length}))
  ];
  var head = [t('col.name'), t('export.sizeBytes'), t('col.size'), t('col.mtime'), t('export.currentExt'),
    t('col.type'), t('col.format'), t('detail.suggestedExt'), t('col.verdict'), t('export.reviewStatus'),
    t('export.riskNote'), t('export.hex'), t('export.sha256')];
  lines.push(head.map(csvCell).join(','));
  rows.forEach(function(r){
    var v = r.high ? t('export.verdictHigh') : r.verdict==='match' ? t('verdict.match') : r.verdict==='mismatch' ? t('export.verdictMismatchCsv',{ext:r.suggestFirst}) : t('verdict.unknown');
    var risk = (r.risks||[]).map(function(w){ return (w.level==='high'?t('export.tagHigh'):t('export.tagInfo'))+w.title; }).join('；');
    lines.push([r.name, r.size, fmtSize(r.size), fmtTime(r.mtime), r.claimed,
      kindLabel(r.type), formatName(r.format), suggestExtDisplay(r), v, reviewStatusText(r),
      risk, r.hex, r.sha256||''].map(csvCell).join(','));
  });
  saveBlob(lines.join('\r\n'), t('export.filenamePrefix')+'_'+stamp()+'.csv', 'text/csv;charset=utf-8');
}
function exportTxt(){
  if(!allResults.length) return;
  var rows = reportRows();
  var highs = allResults.filter(function(r){ return r.high; });
  var d = new Date();
  var ts = d.getFullYear()+'-'+pad2(d.getMonth()+1)+'-'+pad2(d.getDate())+' '+pad2(d.getHours())+':'+pad2(d.getMinutes())+':'+pad2(d.getSeconds());
  var L = [];
  L.push('='.repeat(94));
  L.push(t('export.reportTitle'));
  L.push(t('export.checkedAt', {ts:ts}));
  L.push(t('export.summaryLine', {
    total: allResults.length,
    mismatch: allResults.filter(function(r){return r.verdict==='mismatch';}).length,
    exec: allResults.filter(function(r){return r.type==='exec';}).length,
    high: highs.length
  }));
  L.push(t('export.note1'));
  L.push(t('export.note2'));
  L.push('');
  L.push(t('export.activeFilters', {list: describeActiveFilters()}));
  L.push(t('export.reviewedSummary', {
    done: allResults.filter(function(r){ return r.reviewed; }).length,
    total: allResults.length
  }));
  L.push('='.repeat(94)); L.push('');
  if(highs.length){
    L.push(t('export.highSectionTitle'));
    highs.forEach(function(r){
      L.push('  ● '+r.name + (r.sha256 ? '   SHA-256: '+r.sha256 : ''));
      (r.risks||[]).filter(function(w){return w.level==='high';}).forEach(function(w){ L.push('      - '+w.title+'：'+w.text); });
    });
    L.push('');
  }
  L.push([t('col.name'), t('col.size'), t('col.mtime'), t('col.ext'), t('col.type'), t('col.format'),
    t('detail.suggestedExt'), t('col.verdict'), t('export.reviewStatus'), t('export.hex'), t('export.sha256')].join('\t'));
  rows.forEach(function(r){
    var v = r.high ? t('export.verdictHigh') : r.verdict==='match' ? t('verdict.match') : r.verdict==='mismatch' ? t('export.verdictMismatchTxt',{ext:r.suggestFirst}) : t('verdict.unknown');
    L.push([r.name, fmtSize(r.size), fmtTime(r.mtime), r.claimed, kindLabel(r.type),
            formatName(r.format), suggestExtDisplay(r), v, reviewStatusText(r), r.hex, r.sha256||t('export.notCalculated')].join('\t'));
  });
  saveBlob(L.join('\r\n'), t('export.filenamePrefix')+'_'+stamp()+'.txt', 'text/plain;charset=utf-8');
}

// JSON 匯出：跟 CSV/TXT 不同，這裡是給程式讀的，不是給人看的，
// 所以欄位用穩定的英文 key（而不是隨語言變動的翻譯字串），格式名稱、
// 判定結果都同時給「語言中立版」（未翻譯的內部值／verdict 代碼）跟
// 「目前介面語言顯示的版本」，串接的人要哪個都拿得到。
function exportJson(){
  if(!allResults.length) return;
  var rows = reportRows();
  var payload = {
    generatedAt: new Date().toISOString(),
    tool: 'file-signature-inspector',
    language: currentLang,
    filters: {
      description: describeActiveFilters(),
      search: searchBox.value.trim() || null,
      onlyKnownTypes: filterCk.checked,
      duplicatesOnly: dupOnlyCk.checked,
      hideReviewed: !!(hideReviewedCk && hideReviewedCk.checked),
      chip: chipFilter
    },
    summary: {
      total: allResults.length,
      exported: rows.length,
      reviewed: allResults.filter(function(r){ return r.reviewed; }).length,
      mismatched: allResults.filter(function(r){ return r.verdict === 'mismatch'; }).length,
      executables: allResults.filter(function(r){ return r.type === 'exec'; }).length,
      highRisk: allResults.filter(function(r){ return r.high; }).length
    },
    files: rows.map(function(r){
      return {
        name: r.name,
        sizeBytes: r.size,
        modifiedAt: r.mtime ? new Date(r.mtime).toISOString() : null,
        claimedExtension: r.claimed,
        detectedType: r.type,
        detectedFormat: r.format,
        detectedFormatDisplay: formatName(r.format),
        suggestedExtensions: r.suggestExtGeneric ? null : (r.suggestExt ? r.suggestExt.split(' ') : []),
        verdict: r.verdict,
        highRisk: !!r.high,
        reviewed: !!r.reviewed,
        duplicateCount: r.dupCount || 0,
        headHex: r.hex,
        sha256: r.sha256 || null,
        risks: (r.risks || []).map(function(w){ return {level:w.level, title:w.title, text:w.text}; })
      };
    })
  };
  saveBlob(JSON.stringify(payload, null, 2), t('export.filenamePrefix')+'_'+stamp()+'.json', 'application/json;charset=utf-8');
}

/* ---------------------------------------------------------------
   全域鍵盤快速鍵
   ---------------------------------------------------------------
   設計原則：
   - 在輸入框／文字區域裡一律不攔截，否則使用者連 "j" 都打不出來。
     唯一的例外是搜尋框裡的 Esc（那是使用者預期的「清除」行為）。
   - 有修飾鍵（Ctrl/Cmd/Alt）時不攔截，避免蓋掉瀏覽器原生快捷鍵。
   - 燈箱開啟時不攔截，讓燈箱自己的 Esc／Tab 處理優先。
   --------------------------------------------------------------- */
function isTypingTarget(el){
  if(!el) return false;
  var tag = (el.tagName || '').toLowerCase();
  return tag === 'input' || tag === 'textarea' || tag === 'select' || el.isContentEditable;
}

function focusAdjacentRow(dir){
  var rows = Array.prototype.slice.call(tbody.querySelectorAll('tr.datarow'));
  if(!rows.length) return;
  var current = focusedRow();
  var idx = current ? rows.indexOf(current) : -1;
  var nextIdx;
  if(idx < 0) nextIdx = (dir > 0) ? 0 : rows.length - 1;   // 還沒選任何一列時，j 從頭、k 從尾
  else nextIdx = Math.min(Math.max(idx + dir, 0), rows.length - 1);
  var target = rows[nextIdx];
  if(target){
    target.focus();
    // 只在必要時捲動，避免每按一次就整頁跳動
    if(target.scrollIntoView) target.scrollIntoView({block:'nearest'});
  }
}

/* ---------------------------------------------------------------
   PWA：註冊 Service Worker（有條件才做）
   ---------------------------------------------------------------
   Service Worker 只能在安全情境（https:// 或 http://localhost）下
   註冊，這是瀏覽器規格的限制。用 file:// 打開這個工具（本來就支援、
   也會繼續支援的用法）時，下面這段直接不執行，不會嘗試註冊、
   也不會產生任何錯誤訊息——PWA 安裝純粹是「透過網頁伺服器提供時」
   多一個選項，不是這個工具運作的必要條件。
   --------------------------------------------------------------- */
if('serviceWorker' in navigator &&
   (location.protocol === 'https:' || location.hostname === 'localhost' || location.hostname === '127.0.0.1')){
  window.addEventListener('load', function(){
    navigator.serviceWorker.register('service-worker.js').catch(function(){
      // 註冊失敗就算了（例如伺服器沒有正確設定 MIME type），
      // 工具本身完全不受影響，離線安裝只是少了這個而已。
    });
  });
}

document.addEventListener('keydown', function(e){
  if(e.ctrlKey || e.metaKey || e.altKey) return;
  if(document.querySelector('.lightbox')) return;   // 燈箱開著時交給燈箱處理

  // 搜尋框裡的 Esc：第一次清空內容，內容已空的話就離開輸入框
  if(e.key === 'Escape' && document.activeElement === searchBox){
    if(searchBox.value){
      searchBox.value = '';
      renderLimit = RENDER_STEP;
      render();
    } else {
      searchBox.blur();
    }
    e.preventDefault();
    return;
  }

  if(isTypingTarget(document.activeElement)) return;

  if(e.key === '/'){
    e.preventDefault();
    searchBox.focus();
    searchBox.select();
    return;
  }
  if(e.key === 'j'){ e.preventDefault(); focusAdjacentRow(1);  return; }
  if(e.key === 'k'){ e.preventDefault(); focusAdjacentRow(-1); return; }
  if(e.key === 'u'){ e.preventDefault(); undoRemove(); return; }
  if(e.key === 'c'){
    var crow = focusedRow();
    if(crow){ e.preventDefault(); toggleCompareSlot(Number(crow.getAttribute('data-key'))); }
    return;
  }
  if(e.key === 'r'){
    var row = focusedRow();
    if(row){ e.preventDefault(); toggleReviewed(Number(row.getAttribute('data-key'))); }
    return;
  }
});

/* ---------------------------------------------------------------
   自訂簽章管理介面
   --------------------------------------------------------------- */
function renderSigList(){
  var el = $('sigList');
  if(!el) return;
  if(!customSigs.length){
    el.innerHTML = '<p class="sig-list-empty">'+t('sig.listEmpty')+'</p>';
    return;
  }
  var items = customSigs.map(function(s){
    return '<li>'+
      '<span class="sig-name">'+esc(s.name)+'</span>'+
      '<span class="sig-meta">'+esc(s.ext.join(' '))+'　·　'+esc(s.magic.replace(/(..)/g,'$1 ').trim())+'　·　'+kindLabel(s.type)+'</span>'+
      '<button type="button" data-remove-sig="'+esc(s.name)+'">'+t('sig.remove')+'</button>'+
    '</li>';
  }).join('');
  el.innerHTML = '<div class="sig-list-title">'+t('sig.listTitle')+'</div><ul class="sig-items">'+items+'</ul>';
  el.querySelectorAll('[data-remove-sig]').forEach(function(b){
    b.addEventListener('click', function(){
      var name = b.getAttribute('data-remove-sig');
      removeCustomSig(name);
      broadcastCustomSigsToWorkers();
      toast(t('sig.removed', {name:name}));
      renderSigList();
    });
  });
}
renderSigList();

var sigForm = $('sigForm');
if(sigForm){
  sigForm.addEventListener('submit', function(e){
    e.preventDefault();
    sigForm.querySelectorAll('.sig-form-error').forEach(function(el){ el.remove(); });
    var name = $('sigName').value, extRaw = $('sigExt').value,
        hexRaw = $('sigHex').value, type = $('sigType').value;
    var result = validateCustomSig(name, extRaw, hexRaw, type);
    if(!result.ok){
      var msg = document.createElement('p');
      msg.className = 'sig-form-error';
      msg.textContent = t(result.errorKey);
      sigForm.appendChild(msg);
      return;
    }
    addCustomSig(result.sig);
    broadcastCustomSigsToWorkers();
    toast(t('sig.added', {name:result.sig.name}));
    $('sigName').value = ''; $('sigExt').value = ''; $('sigHex').value = '';
    renderSigList();
  });
}

var sigExportBtn = $('sigExportBtn');
if(sigExportBtn){
  sigExportBtn.addEventListener('click', function(){
    if(!customSigs.length){ toast(t('sig.listEmpty')); return; }
    saveBlob(exportCustomSigsJson(), 'custom-signatures_' + stamp() + '.json', 'application/json;charset=utf-8');
  });
}
var sigImportBtn = $('sigImportBtn');
var sigImportInput = $('sigImportInput');
if(sigImportBtn && sigImportInput){
  sigImportBtn.addEventListener('click', function(){ sigImportInput.click(); });
  sigImportInput.addEventListener('change', function(){
    var file = sigImportInput.files && sigImportInput.files[0];
    sigImportInput.value = '';
    if(!file) return;
    var reader = new FileReader();
    reader.onload = function(){
      var result = importCustomSigsJson(String(reader.result));
      if(result.error){
        toast(t('sig.importError'));
        return;
      }
      broadcastCustomSigsToWorkers();
      renderSigList();
      toast(t('sig.importResult', {added:result.added, skipped:result.skipped, invalid:result.invalid}));
    };
    reader.onerror = function(){ toast(t('sig.importError')); };
    reader.readAsText(file);
  });
}

/* ---------------------------------------------------------------
   主題：淺色／深色／跟隨系統，三態循環
   ---------------------------------------------------------------
   跟語言選擇一樣存在 localStorage——這純粹是介面偏好設定，不涉及
   任何檔案內容，所以不像「已檢查標記」那樣需要額外開關保護。
   預設是 'system'（跟隨系統），沒有存過偏好時依 prefers-color-scheme
   判斷；使用者主動選了淺色或深色之後才會固定下來，不再跟著系統走。
   --------------------------------------------------------------- */
var THEME_KEY = 'fsi-theme';
function loadThemePref(){
  try{
    var v = localStorage.getItem(THEME_KEY);
    if(v === 'light' || v === 'dark' || v === 'system') return v;
  }catch(e){ /* 隱私模式擋 localStorage 時，安靜地退回預設值即可 */ }
  return 'system';
}
function saveThemePref(v){
  try{ localStorage.setItem(THEME_KEY, v); }catch(e){}
}
var themePref = loadThemePref();
var systemDarkMql = (typeof matchMedia === 'function') ? matchMedia('(prefers-color-scheme: dark)') : null;

function effectiveTheme(){
  if(themePref !== 'system') return themePref;
  return (systemDarkMql && systemDarkMql.matches) ? 'dark' : 'light';
}
// 按鈕顯示的永遠是「按下去會變成什麼」，跟語言切換鈕是同一套邏輯，
// 循環順序：淺色 → 深色 → 跟隨系統 → 淺色 → …
function nextThemePref(){
  return themePref === 'light' ? 'dark' : (themePref === 'dark' ? 'system' : 'light');
}
function themeLabelKey(pref){
  return pref === 'system' ? 'theme.system' : (pref === 'dark' ? 'theme.dark' : 'theme.light');
}
function applyTheme(){
  document.documentElement.setAttribute('data-theme', effectiveTheme());
  themeBtn.textContent = t(themeLabelKey(nextThemePref()));
}
// 「跟隨系統」狀態下，作業系統的深色/淺色設定改變時要能即時反映，
// 不用重新整理頁面。使用者已經手動選過淺色或深色的話，這裡不會生效。
if(systemDarkMql){
  var onSystemThemeChange = function(){ if(themePref === 'system') applyTheme(); };
  if(systemDarkMql.addEventListener) systemDarkMql.addEventListener('change', onSystemThemeChange);
  else if(systemDarkMql.addListener) systemDarkMql.addListener(onSystemThemeChange); // Safari 13 以下的舊寫法
}

// 語言切換：zh → en → ja → zh 循環。按鈕文字顯示的是「按下去會切換成
// 哪個語言」（跟主題按鈕邏輯一致），所以要用「下一個」語言的名稱。
function nextLang(){
  var i = LANGS.indexOf(currentLang);
  return LANGS[(i + 1) % LANGS.length];
}
function applyLangUI(){
  langBtn.textContent = t('lang.switchTo', {label: LANG_LABEL[nextLang()]});
  document.title = t('app.title');
}
// setLang()（定義在 i18n.js）存好語言之後會呼叫這個函式——
// 這是 i18n.js 跟畫面渲染之間唯一的耦合點，把「翻譯資料」跟
// 「怎麼重繪畫面」分開，i18n.js 不需要知道 app.js 內部長什麼樣子。
function onLangChange(){
  applyStaticI18n();
  applyLangUI();
  applyTheme();
  buildRef();
  renderSigList();
  writeHashState();
  render();
}
langBtn.addEventListener('click', function(){ setLang(nextLang()); });

applyStaticI18n();
applyLangUI();
applyTheme();
themeBtn.addEventListener('click', function(){ themePref = nextThemePref(); saveThemePref(themePref); applyTheme(); });

$('pickFiles').addEventListener('click', function(e){ e.stopPropagation(); fileInput.click(); });
$('pickDir').addEventListener('click', function(e){ e.stopPropagation(); dirInput.click(); });
dropzone.addEventListener('click', function(){ fileInput.click(); });
/* ---------------------------------------------------------------
   拖曳中的即時提示
   ---------------------------------------------------------------
   老實話寫在前面：瀏覽器的拖放安全模型不允許在 dragenter／dragover
   階段讀取被拖曳檔案的實際內容——File 物件要等使用者真的放開滑鼠、
   觸發 drop 事件之後才拿得到，dataTransfer.items 在拖曳過程中只給
   「有幾個項目」「大致是檔案還是文字」這類淺層資訊，不是設計疏漏，
   是各家瀏覽器故意的限制（避免網站在使用者放手之前就偷看到拖曳中
   的檔案內容）。

   所以這裡能做、也只做到「拖曳中顯示準備加入的項目數量」，不會、
   也不可能在放開之前就告訴你「其中有幾個是執行檔」——那需要讀取
   位元組，只有在 drop 之後才做得到（現有的掃描流程本來就會馬上做）。
   --------------------------------------------------------------- */
function countDraggedItems(e){
  var items = e.dataTransfer && e.dataTransfer.items;
  if(!items) return 0;
  var n = 0;
  for(var i = 0; i < items.length; i++){ if(items[i].kind === 'file') n++; }
  return n;
}
function showDragCount(e){
  var n = countDraggedItems(e);
  var el = $('dragCount');
  if(!el) return;
  if(n > 0){
    el.textContent = t('dropzone.dragCount', {n:n});
    el.classList.remove('hidden');
  } else {
    el.classList.add('hidden');
  }
}

['dragenter','dragover'].forEach(function(ev){ dropzone.addEventListener(ev, function(e){ e.preventDefault(); dropzone.classList.add('drag'); showDragCount(e); }); });
['dragleave'].forEach(function(ev){ dropzone.addEventListener(ev, function(e){ e.preventDefault(); dropzone.classList.remove('drag'); var el=$('dragCount'); if(el) el.classList.add('hidden'); }); });
dropzone.addEventListener('drop', async function(e){
  e.preventDefault(); dropzone.classList.remove('drag');
  var dc = $('dragCount'); if(dc) dc.classList.add('hidden');
  var list = await filesFromDataTransfer(e.dataTransfer);
  if(list.length) handleEntries(list);
});
window.addEventListener('dragover', function(e){ e.preventDefault(); });
window.addEventListener('drop', function(e){ e.preventDefault(); });

fileInput.addEventListener('change', function(e){
  var list = Array.prototype.slice.call(e.target.files).map(function(f){ return {file:f, path:f.name}; });
  if(list.length) handleEntries(list);
  fileInput.value = '';
});
dirInput.addEventListener('change', function(e){
  var list = Array.prototype.slice.call(e.target.files).map(function(f){
    return {file:f, path: f.webkitRelativePath || f.name};
  });
  if(list.length) handleEntries(list);
  dirInput.value = '';
});

function refilter(){ renderLimit = RENDER_STEP; writeHashState(); render(); }

filterCk.addEventListener('change', refilter);
dupOnlyCk.addEventListener('change', refilter);
if(hideReviewedCk) hideReviewedCk.addEventListener('change', refilter);

if(persistCk){
  persistCk.addEventListener('change', function(){
    if(persistCk.checked){
      toast(t('toast.persistOn'));
      // 立刻把已經算過雜湊、且記憶裡認得的檔案標記回來
      if(applyStoredReviewMarks()) render(); else render();
    } else {
      toast(t('toast.persistOff'));
      render();
    }
  });
}
$('clearStoredBtn').addEventListener('click', function(){
  var n = reviewedHashes.size;
  if(!n){ toast(t('toast.storedNone')); return; }
  reviewedHashes = new Set();
  try{ localStorage.removeItem(PERSIST_KEY); }catch(e){}
  toast(t('toast.storedCleared', {n:n}));
});
$('undoBtn').addEventListener('click', undoRemove);
$('copyLinkBtn').addEventListener('click', function(){
  writeHashState();
  copyText(location.href);
  toast(t('toast.linkCopied'));
});
var searchTimer = null;
searchBox.addEventListener('input', function(){
  clearTimeout(searchTimer);
  searchTimer = setTimeout(refilter, 140);
});

$('copyHashBtn').addEventListener('click', function(){
  var seen = {}, list = [];
  visibleRows().forEach(function(r){
    if(r.sha256 && !seen[r.sha256]){ seen[r.sha256] = 1; list.push(r.sha256); }
  });
  if(!list.length){ toast(t('toast.noHashYet')); return; }
  copyText(list.join('\n'));
  toast(t('toast.copiedN', {n:list.length}));
});
$('clearBtn').addEventListener('click', function(){
  allResults.forEach(function(r){ if(r.previewUrl) URL.revokeObjectURL(r.previewUrl); });
  // 復原堆疊裡的項目也要一起釋放，否則那些 blob: URL 會一直掛在記憶體裡
  undoStack.forEach(function(e){ if(e.result.previewUrl) URL.revokeObjectURL(e.result.previewUrl); });
  undoStack = [];
  allResults = []; expanded.clear();
  chipFilter = null;
  compareSlots = []; renderCompareBar();
  renderLimit = RENDER_STEP;
  controls.classList.add('hidden'); summaryEl.classList.add('hidden');
  tableWrap.classList.add('hidden'); alertBar.classList.add('hidden');
  searchBox.value = '';
  writeHashState();
  // 把拖放區還原成完整大小，因為畫面上已經沒有結果要讓位了
  dropzone.classList.remove('compact');
  var dzTitle = dropzone.querySelector('strong');
  if(dzTitle) dzTitle.textContent = t('dropzone.title');
  render();
});
$('hashAllBtn').addEventListener('click', hashAll);
$('csvBtn').addEventListener('click', exportCsv);
$('jsonBtn').addEventListener('click', exportJson);
$('downloadBtn').addEventListener('click', exportTxt);

/* ---------------------------------------------------------------
   初始化
   ---------------------------------------------------------------
   readHashState() 必須在所有 DOM 參照與 CHIP_FILTERS 都準備好之後才呼叫，
   所以放在檔案最後。它會把網址列 hash 裡的搜尋字串、篩選、排序、語言
   套用回控制項；如果其中有 lang=，setLang() 會連帶觸發 onLangChange()，
   把整個畫面用新語言重畫一次。
   --------------------------------------------------------------- */
readHashState();
render();
