/* =============================================================
   compare.js — 差異比對模式
   ---------------------------------------------------------------
   讓使用者挑兩個結果，並排看開頭位元組哪裡不一樣。用途例如：
   「這兩個檔名很像的檔案，內容真的一樣嗎？」「改過的版本跟原始
   版本差在哪？」

   只比對每個檔案的前幾個 bytes，不是整個檔案——多數格式的差異
   （標頭、簽章、中繼資料）都會落在檔案開頭，逐位元組比對整個大檔案
   在瀏覽器裡既慢又沒必要。比對範圍可以在比較視窗裡用下拉選單調整
   （COMPARE_CAP_OPTIONS，預設 256 bytes），選擇會記在 compareCap，
   同一次瀏覽階段裡下次開啟比較視窗會沿用上次的選擇。如果兩個檔案
   需要確認「內容是否完全一致」，用 SHA-256 相同與否來判斷更準確、
   更快，這裡的位元組格線只負責回答「哪裡開始不一樣」。

   依賴：utils.js（esc/fmtSize）、i18n.js（t）、app.js 提供的
   allResults／readBytes／toast。跟 preview.js 的燈箱是各自獨立的
   對話框實作（兩邊都需要 role="dialog" 的焦點管理），沒有抽出共用
   輔助函式——目前只有這兩處用到，重複的十幾行 focus-trap 邏輯比
   為了兩個呼叫點就做一層抽象化更划算；如果之後出現第三個對話框，
   才值得抽成 openModal() 共用。
   ============================================================= */

var compareSlots = [];   // 最多 2 個 result id
var COMPARE_CAP_OPTIONS = [256, 1024, 4096, 65536];
var COMPARE_CAP_DEFAULT = 256;
var compareCap = COMPARE_CAP_DEFAULT; // 目前選擇的比對範圍，開啟比較視窗時可以換

function isInCompare(id){ return compareSlots.indexOf(id) >= 0; }

function toggleCompareSlot(id){
  var idx = compareSlots.indexOf(id);
  if(idx >= 0){
    compareSlots.splice(idx, 1);
  } else {
    if(compareSlots.length >= 2) compareSlots.shift(); // 滿了就擠掉最早選的那個
    compareSlots.push(id);
  }
  renderCompareBar();
  render();
}

function clearCompareSlots(){
  compareSlots = [];
  renderCompareBar();
  render();
}

function renderCompareBar(){
  var bar = document.getElementById('compareBar');
  if(!bar) return;
  if(!compareSlots.length){
    bar.classList.add('hidden');
    bar.innerHTML = '';
    return;
  }
  bar.classList.remove('hidden');
  var names = compareSlots.map(function(id){
    var r = allResults.find(function(x){ return x.id === id; });
    return r ? esc(r.name) : '?';
  });
  var ready = compareSlots.length === 2;
  bar.innerHTML =
    '<span class="compare-label">'+t('compare.selected',{n:compareSlots.length})+'：'+names.join('　vs　')+'</span>'+
    '<button type="button" class="minibtn primary" id="compareGoBtn" '+(ready?'':'disabled')+'>'+t('compare.button')+'</button>'+
    '<button type="button" class="icon-btn rm" id="compareClearBtn" title="'+esc(t('compare.clear'))+'">✕</button>';
  var goBtn = document.getElementById('compareGoBtn');
  if(goBtn) goBtn.addEventListener('click', openCompareView);
  var clearBtn = document.getElementById('compareClearBtn');
  if(clearBtn) clearBtn.addEventListener('click', clearCompareSlots);
}

// 逐位元組比對兩段 Uint8Array，回傳格線需要的資料，
// 順便算出「第一個差異在哪」「總共差幾個位元組」給文字摘要用。
function buildByteDiff(bytesA, bytesB, cap){
  var n = Math.min(cap, Math.max(bytesA.length, bytesB.length));
  var cells = [], firstDiff = -1, diffCount = 0;
  for(var i = 0; i < n; i++){
    var a = i < bytesA.length ? bytesA[i] : null;
    var b = i < bytesB.length ? bytesB[i] : null;
    var same = (a !== null && b !== null && a === b);
    if(!same){ diffCount++; if(firstDiff < 0) firstDiff = i; }
    cells.push({a:a, b:b, same:same});
  }
  return {cells:cells, firstDiff:firstDiff, diffCount:diffCount, compared:n};
}

function byteCellsHtml(cells, pick){
  return cells.map(function(c){
    var v = pick === 'a' ? c.a : c.b;
    if(v === null) return '<span class="bytecell empty">–</span>';
    var hex = v.toString(16).toUpperCase().padStart(2,'0');
    return '<span class="bytecell '+(c.same ? 'match' : 'mismatch')+'">'+hex+'</span>';
  }).join('');
}

async function openCompareView(){
  if(compareSlots.length !== 2) return;
  var ra = allResults.find(function(x){ return x.id === compareSlots[0]; });
  var rb = allResults.find(function(x){ return x.id === compareSlots[1]; });
  if(!ra || !rb) return;

  var previouslyFocused = document.activeElement;
  var box = document.createElement('div');
  box.className = 'lightbox';
  box.setAttribute('role', 'dialog');
  box.setAttribute('aria-modal', 'true');
  box.setAttribute('aria-label', t('compare.title', {a:ra.name, b:rb.name}));
  box.setAttribute('tabindex', '-1');

  var capOptionsHtml = COMPARE_CAP_OPTIONS.map(function(n){
    return '<option value="'+n+'"'+(n===compareCap?' selected':'')+'>'+esc(fmtSize(n))+'</option>';
  }).join('');

  box.innerHTML =
    '<button class="lightbox-close" aria-label="'+esc(t('lightbox.closeLabel'))+'">✕</button>'+
    '<div class="lightbox-media"><div class="compare-panel">'+
      '<h3>'+esc(t('compare.title', {a: ra.name.split("/").pop(), b: rb.name.split("/").pop()}))+'</h3>'+
      '<label class="compare-range-picker">'+t('compare.rangeLabel')+'&nbsp;'+
        '<select id="compareCapSelect">'+capOptionsHtml+'</select>'+
      '</label>'+
      '<div id="compareContent"></div>'+
    '</div></div>';

  var mediaWrap = box.querySelector('.lightbox-media');
  var closeBtn = box.querySelector('.lightbox-close');
  var contentEl = box.querySelector('#compareContent');
  var capSelect = box.querySelector('#compareCapSelect');

  // 比對內容（統計文字 + 位元組格線）獨立成一段可重畫的區塊，
  // 這樣切換比對範圍時只換這一塊，不用整個對話框關掉重開、
  // 也不會把使用者的焦點位置弄丟。
  async function renderCompareContent(cap){
    var bytesA, bytesB;
    try{
      bytesA = await readBytes(ra.file, 0, cap);
      bytesB = await readBytes(rb.file, 0, cap);
    }catch(e){
      contentEl.innerHTML = '<p class="detail-note">'+esc(t('toast.previewFailed'))+'</p>';
      return;
    }

    var diff = buildByteDiff(bytesA, bytesB, cap);

    var sizeLine = (ra.size === rb.size)
      ? t('compare.sameSize')
      : t('compare.diffSize', {diff: fmtSize(Math.abs(ra.size - rb.size))});

    var hashLine;
    if(ra.sha256 && rb.sha256){
      hashLine = (ra.sha256 === rb.sha256) ? t('compare.sameHash') : t('compare.diffHash');
    } else {
      hashLine = t('compare.hashNeedCompute');
    }

    var byteLine = diff.diffCount === 0
      ? t('compare.byteAllSame', {n:diff.compared})
      : t('compare.byteDiffCount', {n:diff.compared, diff:diff.diffCount, first:diff.firstDiff + 1});

    contentEl.innerHTML =
      '<dl class="kv compare-kv">'+
        '<dt>'+t('compare.fileA')+'</dt><dd>'+esc(ra.name)+'　('+fmtSize(ra.size)+')</dd>'+
        '<dt>'+t('compare.fileB')+'</dt><dd>'+esc(rb.name)+'　('+fmtSize(rb.size)+')</dd>'+
      '</dl>'+
      '<p class="detail-note">'+esc(sizeLine)+'<br>'+esc(hashLine)+'<br>'+esc(byteLine)+'</p>'+
      '<div class="bytegrid-wrap compare-grid">'+
        '<div class="byterow"><span class="rowlabel">'+t('compare.fileA')+'</span><span class="bytecells">'+byteCellsHtml(diff.cells,'a')+'</span></div>'+
        '<div class="byterow"><span class="rowlabel">'+t('compare.fileB')+'</span><span class="bytecells">'+byteCellsHtml(diff.cells,'b')+'</span></div>'+
      '</div>'+
      '<div class="legend">'+
        '<span><i class="match"></i>'+t('detail.legendMatch')+'</span>'+
        '<span><i class="mismatch"></i>'+t('detail.legendMismatch')+'</span>'+
        '<span><i class="empty"></i>'+t('detail.legendEmpty')+'</span>'+
      '</div>'+
      '<p class="detail-note compare-capnote">'+t('compare.capNote', {n:cap})+'</p>';
  }

  capSelect.addEventListener('change', function(){
    compareCap = parseInt(capSelect.value, 10) || COMPARE_CAP_DEFAULT;
    renderCompareContent(compareCap);
  });

  function focusableEls(){
    return Array.prototype.slice.call(box.querySelectorAll('button, a[href], select, [tabindex]:not([tabindex="-1"])'));
  }
  function close(){
    box.remove();
    document.removeEventListener('keydown', onKey);
    if(previouslyFocused && document.body.contains(previouslyFocused)) previouslyFocused.focus();
  }
  function onKey(ev){
    if(ev.key === 'Escape'){ close(); return; }
    if(ev.key === 'Tab'){
      var els = focusableEls();
      if(!els.length) return;
      var first = els[0], last = els[els.length - 1];
      if(ev.shiftKey && document.activeElement === first){ ev.preventDefault(); last.focus(); }
      else if(!ev.shiftKey && document.activeElement === last){ ev.preventDefault(); first.focus(); }
    }
  }
  box.addEventListener('click', close);
  mediaWrap.addEventListener('click', function(e){ e.stopPropagation(); });
  closeBtn.addEventListener('click', close);
  document.addEventListener('keydown', onKey);

  document.body.appendChild(box);
  closeBtn.focus();
  await renderCompareContent(compareCap);
}
