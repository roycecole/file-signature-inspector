/* =============================================================
   preview.js — 縮圖與燈箱（Lightbox）預覽
   ---------------------------------------------------------------
   負責三件事：
   1. buildPreviewCell(r)  → 產生表格「預覽」欄要放的 HTML
      （圖片顯示縮圖；影片/音訊/PDF 顯示可點擊的圖示；其餘顯示佔位符）
   2. openLightbox(id)     → 點縮圖時彈出的全螢幕預覽視窗，
      依 r.previewKind 決定要放 <img>／<video>／<audio>／<iframe>，
      或是「檔案過大，要不要仍然載入」的確認畫面
   3. 基本的無障礙支援：燈箱是 role="dialog"，開啟時把焦點移進去、
      用 Tab 鍵在裡面循環，Esc 或叉叉按鈕關閉時把焦點還給原本點擊的
      縮圖，並用鍵盤（Enter/Space）就能觸發縮圖，不必一定要用滑鼠。

   依賴：utils.js（esc/fmtSize）、signatures.js（MEDIA_PREVIEW／
   PREVIEW_SIZE_LIMIT）、app.js 提供的全域陣列 allResults。

   新增可預覽格式時通常不用改這個檔案，只要在 signatures.js 的
   MEDIA_PREVIEW（與需要的話 PREVIEW_SIZE_LIMIT）補一筆對照即可；
   除非是全新的「種類」（目前只有 image/video/audio/pdf 四種），
   才需要在這裡加一個 case。

   已知的無障礙限制：表格列本身可以用 Tab／Enter 展開明細（見
   app.js 的 render()），縮圖是那一列「裡面」另一個可各自 Tab 到
   的可點擊元素——嚴格來說是巢狀的可互動元素，並非教科書等級的
   ARIA 寫法，但主流螢幕報讀器（NVDA/VoiceOver/JAWS）對這種「列表
   內有個別可點項目」的樣式普遍能正確處理，是常見的務實折衷。
   ============================================================= */

var FALLBACK_ICON = {image:'🖼', doc:'📄', text:'📝', exec:'⚠', other:'·'};
var MEDIA_ICON = {video:'🎬', audio:'🎵', pdf:'📄'};

// 產生表格「預覽」欄的內容。
function buildPreviewCell(r){
  if(r.previewUrl){
    if(r.previewKind === 'image'){
      return '<img class="thumb" src="'+r.previewUrl+'" alt="" role="button" tabindex="0" ' +
             'aria-label="'+esc(t('preview.ariaLabel',{name:r.name}))+'" data-zoom="'+r.id+'">';
    }
    // 影片／音訊／PDF：表格裡放不下播放器，先顯示一個可點擊的圖示，
    // 實際播放/檢視放到 openLightbox() 裡處理。
    var icon = MEDIA_ICON[r.previewKind] || '▶';
    return '<span class="thumb-placeholder media" role="button" tabindex="0" ' +
           'aria-label="'+esc(t('preview.ariaLabel',{name:r.name}))+'" data-zoom="'+r.id+'">'+icon+'</span>';
  }
  if(r.previewTooLarge){
    // previewUrl 還沒建立（檔案太大），但一樣可以點開，只是進燈箱後
    // 看到的是確認畫面而不是直接播放。用虛線邊框跟一般縮圖做視覺區分。
    var icon2 = MEDIA_ICON[r.previewKind] || '▶';
    return '<span class="thumb-placeholder media toolarge" role="button" tabindex="0" ' +
           'aria-label="'+esc(t('preview.ariaLabelToolarge',{name:r.name}))+'" data-zoom="'+r.id+'" ' +
           'title="'+esc(t('preview.toolargeTitle'))+'">'+icon2+'</span>';
  }
  return '<span class="thumb-placeholder'+(r.type==='exec'?' exec':'')+'" aria-hidden="true">'+
         (FALLBACK_ICON[r.type] || '·')+'</span>';
}

// 依 previewKind 組出燈箱裡要放的媒體元素（previewUrl 已存在的情況）。
function buildLightboxMedia(r){
  var url = r.previewUrl;
  if(r.previewKind === 'image'){
    return '<img src="'+url+'" alt="'+esc(t('lightbox.previewAlt',{name:r.name}))+'">';
  }
  if(r.previewKind === 'video'){
    return '<video src="'+url+'" controls autoplay playsinline>'+esc(t('lightbox.videoUnsupported'))+'</video>';
  }
  if(r.previewKind === 'audio'){
    return '<div class="audio-panel">'+
             '<div class="audio-icon" aria-hidden="true">🎵</div>'+
             '<audio src="'+url+'" controls autoplay>'+esc(t('lightbox.audioUnsupported'))+'</audio>'+
           '</div>';
  }
  if(r.previewKind === 'pdf'){
    return '<div class="pdf-panel">'+
             '<iframe src="'+url+'" title="'+esc(t('lightbox.pdfTitle',{name:r.name}))+'"></iframe>'+
             '<a class="vt-link" href="'+url+'" target="_blank" rel="noopener noreferrer">'+esc(t('lightbox.openNewTab'))+'</a>'+
           '</div>';
  }
  return '<img src="'+url+'" alt="'+esc(t('lightbox.previewAlt',{name:r.name}))+'">';
}

// 檔案超過 PREVIEW_SIZE_LIMIT 時，燈箱裡先顯示這個確認畫面。
function buildTooLargeNotice(r){
  var limit = PREVIEW_SIZE_LIMIT[r.previewKind];
  var icon = MEDIA_ICON[r.previewKind] || '▶';
  return '<div class="toolarge-panel">'+
    '<div class="toolarge-icon" aria-hidden="true">'+icon+'</div>'+
    '<p>'+t('lightbox.tooLargeText', {size: fmtSize(r.size), limit: fmtSize(limit)})+'</p>'+
    '<button class="minibtn" data-load-preview="'+r.id+'">'+esc(t('lightbox.loadAnyway'))+'</button>'+
  '</div>';
}

// 使用者在「檔案過大」確認畫面按下「仍要載入預覽」後才真的建立 Blob。
function loadPreviewNow(r, mediaEl){
  try{
    r.previewUrl = URL.createObjectURL(r.file.slice(0, r.file.size, r.previewMime));
    r.previewTooLarge = false;
  }catch(e){
    toast(t('toast.previewFailed'));
    return;
  }
  mediaEl.innerHTML = buildLightboxMedia(r);
  // 表格裡的縮圖欄位也該從「待確認」換成正常縮圖，下次整體重繪就會是
  // 正確狀態；這裡不特別強制立即重繪整張表，避免使用者正在看的燈箱
  // 或已展開的其他列被打斷。
}

/* ---------------------------------------------------------------
   燈箱本體。
   無障礙重點：
   - role="dialog" + aria-modal="true"：告訴輔助科技這是一個蓋在
     畫面上的獨立情境，背景內容暫時不該被讀到。
   - 開啟時把焦點移進對話框、記住原本的焦點；關閉時還原焦點，
     使用鍵盤/螢幕報讀器的人不會「跳丟」，還能接著原本的位置操作。
   - Tab / Shift+Tab 在對話框內部的可聚焦元素之間循環，不會跳到
     背景的表格或按鈕。
   --------------------------------------------------------------- */
function openLightbox(id){
  var r = allResults.find(function(x){ return x.id === id; });
  if(!r || (!r.previewUrl && !r.previewTooLarge)) return;

  var previouslyFocused = document.activeElement;

  var box = document.createElement('div');
  box.className = 'lightbox';
  box.setAttribute('role', 'dialog');
  box.setAttribute('aria-modal', 'true');
  box.setAttribute('aria-label', t('lightbox.dialogLabel', {name:r.name}));
  box.setAttribute('tabindex', '-1');

  var mediaHtml = r.previewUrl ? buildLightboxMedia(r) : buildTooLargeNotice(r);
  box.innerHTML =
    '<button class="lightbox-close" aria-label="'+esc(t('lightbox.closeLabel'))+'">✕</button>' +
    '<div class="lightbox-media">' + mediaHtml + '</div>' +
    '<div class="cap">' + esc(r.name) + '　·　' + esc(formatName(r.format)) + '　·　' + fmtSize(r.size) + '</div>';

  var mediaWrap = box.querySelector('.lightbox-media');
  var closeBtn = box.querySelector('.lightbox-close');

  function focusableEls(){
    return Array.prototype.slice.call(
      box.querySelectorAll('button, a[href], [tabindex]:not([tabindex="-1"])')
    );
  }

  function close(){
    box.remove();
    document.removeEventListener('keydown', onKey);
    // 焦點還給原本觸發燈箱的縮圖，避免鍵盤使用者關閉後「不知道游標在哪」。
    if(previouslyFocused && document.body.contains(previouslyFocused)){
      previouslyFocused.focus();
    }
  }

  function onKey(ev){
    if(ev.key === 'Escape'){ close(); return; }
    if(ev.key === 'Tab'){
      var els = focusableEls();
      if(!els.length) return;
      var first = els[0], last = els[els.length - 1];
      if(ev.shiftKey && document.activeElement === first){
        ev.preventDefault(); last.focus();
      } else if(!ev.shiftKey && document.activeElement === last){
        ev.preventDefault(); first.focus();
      }
    }
  }

  // 點背景（不含媒體本身）關閉；媒體區的互動（播放列、iframe 內部、
  // 「仍要載入預覽」按鈕）不應冒泡到這裡變成「點背景關閉」。
  box.addEventListener('click', close);
  mediaWrap.addEventListener('click', function(e){ e.stopPropagation(); });
  mediaWrap.addEventListener('click', function(e){
    var btn = e.target.closest('[data-load-preview]');
    if(btn) loadPreviewNow(r, mediaWrap);
  });
  closeBtn.addEventListener('click', close);
  document.addEventListener('keydown', onKey);

  document.body.appendChild(box);
  closeBtn.focus();
}
