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

var HEAD_LEN = 4096;
async function analyzeFile(file, relPath){
  var id = nextId++;
  var name = relPath || file.name;
  var claimed = getExt(name);
  var bytes;
  try{ bytes = await readBytes(file, 0, HEAD_LEN); }catch(e){ bytes = new Uint8Array(0); }

  var r = {
    id:id, file:file, name:name, claimed:claimed || '(無)',
    size:file.size, mtime:file.lastModified || 0,
    head:bytes.subarray(0, Math.min(bytes.length, 64)),
    sha256:null, hashing:false,
    previewUrl:null, previewKind:null, previewMime:null, previewTooLarge:false
  };

  if(!bytes.length){
    r.type='other'; r.format='空檔案或無法讀取'; r.suggestExt='-'; r.suggestFirst='';
    r.verdict='unknown'; r.rawHex=''; r.hex='-';
    r.risks = filenameRisks(name);
  } else {
    var rawHex = hexOf(bytes.subarray(0, Math.min(bytes.length, 64)));
    var det = await resolveSignature(file, bytes, rawHex);
    r.rawHex = rawHex;
    r.hex = rawHex.slice(0,16).replace(/(..)/g,'$1 ').trim();
    if(det){
      r.type = det.type; r.format = det.name;
      r.suggestExtGeneric = !!det.generic;
      r.suggestExt = det.generic ? '' : det.ext.join(' ');
      r.suggestFirst = det.ext[0];
      r.verdict = det.ext.indexOf(claimed) >= 0 ? 'match' : 'mismatch';
      if(det.generic && TEXT_EXT.has(claimed)) r.verdict = 'match';
      // 圖片／影片／音訊／PDF 都可以預覽：用「實際偵測到的格式」對應的
      // MIME 類型包一個新 Blob，而不是相信原本（可能被改過）的副檔名。
      // 這樣即使檔案被改名成 .txt，只要內容其實是 MP4，<video> 標籤
      // 一樣能正確播放——這也順便印證了判定結果是對的。
      var mp = MEDIA_PREVIEW[det.name];
      if(mp){
        r.previewKind = mp.kind;
        r.previewMime = mp.mime;
        var limit = PREVIEW_SIZE_LIMIT[mp.kind] || Infinity;
        if(file.size <= limit){
          try{ r.previewUrl = URL.createObjectURL(file.slice(0, file.size, mp.mime)); }catch(e){}
        } else {
          // 超過門檻：先不建立 Blob，等使用者在燈箱裡按「仍要載入預覽」才建立。
          r.previewTooLarge = true;
        }
      }
      r.zipEntries = det.entries || null;
      r.cfbNames = det.cfbNames || null;
    } else {
      r.type='other'; r.format='未知簽章'; r.suggestExt='-'; r.suggestFirst='';
      r.verdict='unknown';
    }

    var extra = [];
    if(det){
      var trailingResult = await checkTrailing(file, det, bytes);
      r.trailing = trailingResult.trailing;
      extra = extra.concat(trailingResult.risks);
      if(det.name === 'PDF') extra = extra.concat(await pdfRisks(file));
    }
    r.risks = filenameRisks(name).concat(contentRisks(r, det)).concat(extra);
  }
  r.high = r.risks.some(function(x){ return x.level === 'high'; });
  return r;
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

function visibleRows(){
  var q = searchBox.value.trim().toLowerCase();
  var rows = allResults.filter(function(r){
    if(q && r.name.toLowerCase().indexOf(q) < 0) return false;
    if(dupOnlyCk.checked && !r.dupCount) return false;
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
      renderLimit = RENDER_STEP;
      render();
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
    html.push('<tr class="datarow'+(r.high?' danger':'')+'" data-key="'+r.id+'" '+
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
  var chips = [
    '<div class="chip">'+t('summary.scanned',{n:n})+'</div>',
    '<div class="chip img">'+t('summary.image',{n:cnt(function(r){return r.type==='image';})})+'</div>',
    '<div class="chip doc">'+t('summary.doc',{n:cnt(function(r){return r.type==='doc';})})+'</div>',
    '<div class="chip">'+t('summary.text',{n:cnt(function(r){return r.type==='text';})})+'</div>',
    '<div class="chip">'+t('summary.mismatch',{n:cnt(function(r){return r.verdict==='mismatch';})})+'</div>'
  ];
  var groups = Object.keys(dupIndex).length;
  if(groups){
    var dupFiles = cnt(function(r){ return r.dupCount > 0; });
    var wasted = 0;
    Object.keys(dupIndex).forEach(function(h){
      var g = dupIndex[h];
      wasted += g[0].size * (g.length - 1);
    });
    chips.push('<div class="chip">'+t('summary.dup',{groups:groups, files:dupFiles, size:fmtSize(wasted)})+'</div>');
  }
  var ex = cnt(function(r){ return r.type==='exec'; });
  if(ex) chips.push('<div class="chip danger">'+t('summary.exec',{n:ex})+'</div>');
  if(high) chips.push('<div class="chip danger">'+t('summary.high',{n:high})+'</div>');
  summaryEl.innerHTML = chips.join('');
  summaryEl.classList.toggle('hidden', n === 0);

  if(high){
    alertTitle.textContent = t('alert.title', {n:high});
    alertText.textContent = t('alert.text');
    alertBar.classList.remove('hidden');
  } else alertBar.classList.add('hidden');
}

function removeResult(id){
  var target = allResults.find(function(r){ return r.id === id; });
  if(target && target.previewUrl) URL.revokeObjectURL(target.previewUrl);
  allResults = allResults.filter(function(r){ return r.id !== id; });
  expanded.delete(id);
  if(!allResults.length){
    controls.classList.add('hidden'); summaryEl.classList.add('hidden');
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
  try{ r.sha256 = await sha256File(r.file); }
  catch(e){ toast(t('toast.hashFailed')); }
  r.hashing = false; render();
}

async function hashAll(){
  var todo = allResults.filter(function(r){ return !r.sha256; });
  if(!todo.length){ toast(t('toast.allHashed')); return; }
  progressEl.classList.remove('hidden');
  for(var i=0;i<todo.length;i++){
    progressEl.textContent = t('progress.hashing', {i:i+1, n:todo.length, name:todo[i].name});
    try{ todo[i].sha256 = await sha256File(todo[i].file); }catch(e){}
  }
  progressEl.classList.add('hidden');
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
function exportCsv(){
  if(!allResults.length) return;
  var rows = reportRows();
  var head = [t('col.name'), t('export.sizeBytes'), t('col.size'), t('col.mtime'), t('export.currentExt'),
    t('col.type'), t('col.format'), t('detail.suggestedExt'), t('col.verdict'), t('export.riskNote'), t('export.hex'), t('export.sha256')];
  var lines = [head.map(csvCell).join(',')];
  rows.forEach(function(r){
    var v = r.high ? t('export.verdictHigh') : r.verdict==='match' ? t('verdict.match') : r.verdict==='mismatch' ? t('export.verdictMismatchCsv',{ext:r.suggestFirst}) : t('verdict.unknown');
    var risk = (r.risks||[]).map(function(w){ return (w.level==='high'?t('export.tagHigh'):t('export.tagInfo'))+w.title; }).join('；');
    lines.push([r.name, r.size, fmtSize(r.size), fmtTime(r.mtime), r.claimed,
      kindLabel(r.type), formatName(r.format), suggestExtDisplay(r), v, risk, r.hex, r.sha256||''].map(csvCell).join(','));
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
    t('detail.suggestedExt'), t('col.verdict'), t('export.hex'), t('export.sha256')].join('\t'));
  rows.forEach(function(r){
    var v = r.high ? t('export.verdictHigh') : r.verdict==='match' ? t('verdict.match') : r.verdict==='mismatch' ? t('export.verdictMismatchTxt',{ext:r.suggestFirst}) : t('verdict.unknown');
    L.push([r.name, fmtSize(r.size), fmtTime(r.mtime), r.claimed, kindLabel(r.type),
            formatName(r.format), suggestExtDisplay(r), v, r.hex, r.sha256||t('export.notCalculated')].join('\t'));
  });
  saveBlob(L.join('\r\n'), t('export.filenamePrefix')+'_'+stamp()+'.txt', 'text/plain;charset=utf-8');
}

var theme = 'light';
function applyTheme(){
  document.documentElement.setAttribute('data-theme', theme);
  themeBtn.textContent = t(theme === 'dark' ? 'theme.dark' : 'theme.light');
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
  render();
}
langBtn.addEventListener('click', function(){ setLang(nextLang()); });

applyStaticI18n();
applyLangUI();
applyTheme();
themeBtn.addEventListener('click', function(){ theme = theme === 'dark' ? 'light' : 'dark'; applyTheme(); });

$('pickFiles').addEventListener('click', function(e){ e.stopPropagation(); fileInput.click(); });
$('pickDir').addEventListener('click', function(e){ e.stopPropagation(); dirInput.click(); });
dropzone.addEventListener('click', function(){ fileInput.click(); });
['dragenter','dragover'].forEach(function(ev){ dropzone.addEventListener(ev, function(e){ e.preventDefault(); dropzone.classList.add('drag'); }); });
['dragleave'].forEach(function(ev){ dropzone.addEventListener(ev, function(e){ e.preventDefault(); dropzone.classList.remove('drag'); }); });
dropzone.addEventListener('drop', async function(e){
  e.preventDefault(); dropzone.classList.remove('drag');
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

filterCk.addEventListener('change', function(){ renderLimit = RENDER_STEP; render(); });
dupOnlyCk.addEventListener('change', function(){ renderLimit = RENDER_STEP; render(); });
var searchTimer = null;
searchBox.addEventListener('input', function(){
  clearTimeout(searchTimer);
  searchTimer = setTimeout(function(){ renderLimit = RENDER_STEP; render(); }, 140);
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
  allResults = []; expanded.clear();
  controls.classList.add('hidden'); summaryEl.classList.add('hidden');
  tableWrap.classList.add('hidden'); alertBar.classList.add('hidden');
  searchBox.value = '';
});
$('hashAllBtn').addEventListener('click', hashAll);
$('csvBtn').addEventListener('click', exportCsv);
$('downloadBtn').addEventListener('click', exportTxt);
