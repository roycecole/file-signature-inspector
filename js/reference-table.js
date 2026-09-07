/* =============================================================
   reference-table.js — 頁面下方「常見檔案簽章對照表」的資料與渲染
   ---------------------------------------------------------------
   純粹是靜態參考資料，跟實際的判定邏輯（detectors.js）完全分開。

   想要在對照表裡新增/修改一列：
     1. 在 REF 陣列加一筆 [kind, nameKey, ext, hex, noteKey]
        - kind 對應 signatures.js 的 KIND_LABEL / KIND_CLASS
        - nameKey／noteKey 是 i18n.js 裡 I18N.zh/en/ja 的 key，
          不是直接寫死的顯示字串——這樣切換語言時這裡才會跟著換。
          沒有備註就把 noteKey 留空字串。
        - ext／hex 兩欄是純副檔名跟十六進位字串，三種語言都一樣，
          不需要查表。
     2. 到 i18n.js 的三個語言物件裡，各自幫新的 nameKey／noteKey
        補上對應字串（key 要跟這裡填的一致）。
     3. 放一個 ['group', groupKey] 可以插入一條分類分隔列。

   buildRef() 不是自我執行的 IIFE，是一個「可以重複呼叫」的一般函式，
   因為使用者切換語言時（見 app.js 的 onLangChange）需要重新呼叫它，
   把對照表整個重新畫一次。

   依賴：signatures.js（KIND_LABEL/KIND_CLASS）、i18n.js（t()）；
        頁面需要有 id="refBody" 的 <tbody>。
   ============================================================= */

const REF = [
  ['group', 'ref.group.imageDoc'],
  ['image', 'ref.name.png', '.png', '89 50 4E 47 0D 0A 1A 0A', ''],
  ['image', 'ref.name.jpeg', '.jpg .jpeg', 'FF D8 FF', ''],
  ['doc',   'ref.name.pdf', '.pdf', '25 50 44 46', ''],
  ['doc',   'ref.name.office97', '.doc .xls .ppt', 'D0 CF 11 E0 A1 B1 1A E1', 'ref.note.office97'],
  ['doc',   'ref.name.rtf', '.rtf', '7B 5C 72 74 66', ''],
  ['image', 'ref.name.bmp', '.bmp', '42 4D', ''],
  ['image', 'ref.name.tiffIntel', '.tif .tiff', '49 49 2A 00', ''],
  ['image', 'ref.name.tiffMoto', '.tif .tiff', '4D 4D 00 2A', ''],
  ['image', 'ref.name.gif87', '.gif', '47 49 46 38 37 61', ''],
  ['image', 'ref.name.gif89', '.gif', '47 49 46 38 39 61', ''],
  ['image', 'ref.name.webp', '.webp', '52 49 46 46 <span class="wild">?? ?? ?? ??</span> 57 45 42 50', 'ref.note.webp'],
  ['image', 'ref.name.heic', '.heic .heif', '<span class="wild">?? ?? ?? ??</span> 66 74 79 70 68 65 69 63', 'ref.note.heic'],
  ['image', 'ref.name.avif', '.avif', '<span class="wild">?? ?? ?? ??</span> 66 74 79 70 61 76 69 66', 'ref.note.avif'],
  ['image', 'ref.name.psd', '.psd', '38 42 50 53', ''],
  ['doc',   'ref.name.zipContainer', '.docx .xlsx .pptx .odt .epub', '50 4B 03 04', 'ref.note.zipContainer'],
  ['text',  'ref.name.svg', '.svg', 'ref.hex.none', 'ref.note.svg'],
  ['text',  'ref.name.utf8NoBom', '.txt .json .xml .ps1 …', 'ref.hex.none', 'ref.note.utf8NoBom'],
  ['text',  'ref.name.utf8Bom', '.txt .csv …', 'EF BB BF', ''],
  ['text',  'ref.name.utf16', '.txt .ini …', 'FF FE ／ FE FF', ''],

  ['group', 'ref.group.archiveMedia'],
  ['other', 'ref.name.zip', '.zip', '50 4B 03 04', ''],
  ['other', 'ref.name.rar', '.rar', '52 61 72 21 1A 07 00 ／ … 01 00', ''],
  ['other', 'ref.name.sevenZip', '.7z', '37 7A BC AF 27 1C', ''],
  ['other', 'ref.name.gzip', '.gz .tgz', '1F 8B', ''],
  ['other', 'ref.name.bzip2', '.bz2', '42 5A 68', ''],
  ['other', 'ref.name.xz', '.xz', 'FD 37 7A 58 5A 00', ''],
  ['other', 'ref.name.tar', '.tar', 'ref.hex.tar', 'ref.note.tar'],
  ['other', 'ref.name.mp4', '.mp4 .m4v', '<span class="wild">?? ?? ?? ??</span> 66 74 79 70', ''],
  ['other', 'ref.name.quicktime', '.mov', '<span class="wild">?? ?? ?? ??</span> 66 74 79 70 71 74', ''],
  ['other', 'ref.name.matroska', '.mkv .webm', '1A 45 DF A3', ''],
  ['other', 'ref.name.avi', '.avi', '52 49 46 46 <span class="wild">?? ?? ?? ??</span> 41 56 49 20', ''],
  ['other', 'ref.name.wav', '.wav', '52 49 46 46 <span class="wild">?? ?? ?? ??</span> 57 41 56 45', ''],
  ['other', 'ref.name.mp3id3', '.mp3', '49 44 33', ''],
  ['other', 'ref.name.mp3nolabel', '.mp3', 'FF Ex / FF Fx', 'ref.note.mp3nolabel'],
  ['other', 'ref.name.flac', '.flac', '66 4C 61 43', ''],
  ['other', 'ref.name.ogg', '.ogg .opus', '4F 67 67 53', ''],
  ['other', 'ref.name.sqlite', '.sqlite .db', '53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00', 'ref.note.sqlite'],

  ['group', 'ref.group.exec'],
  ['exec', 'ref.name.pe', '.exe .dll .scr .sys', '4D 5A', 'ref.note.pe'],
  ['exec', 'ref.name.elf', 'ref.ext.elf', '7F 45 4C 46', ''],
  ['exec', 'ref.name.macho', '.dylib .bundle', 'CF FA ED FE ／ CE FA ED FE', 'ref.note.macho'],
  ['exec', 'ref.name.javaclass', '.class', 'CA FE BA BE', ''],
  ['exec', 'ref.name.shebang', '.sh .py .pl .rb', '23 21', 'ref.note.shebang'],
  ['exec', 'ref.name.lnk', '.lnk', '4C 00 00 00 01 14 02 00', 'ref.note.lnk'],
  ['exec', 'ref.name.cab', '.cab', '4D 53 43 46', ''],
  ['exec', 'ref.name.dex', '.dex', '64 65 78 0A', ''],
  ['exec', 'ref.name.jarApk', '.jar .apk', '50 4B 03 04', 'ref.note.jarApk'],
  ['exec', 'ref.name.deb', '.deb', '21 3C 61 72 63 68 3E', 'ref.note.deb'],
  ['exec', 'ref.name.rpm', '.rpm', 'ED AB EE DB', ''],
  ['exec', 'ref.name.swf', '.swf', '46 57 53 ／ 43 57 53', '']
];

function buildRef(){
  const body = document.getElementById('refBody');
  if(!body) return;
  body.innerHTML = REF.map(function(row){
    if(row[0] === 'group') return '<tr class="grouphead"><td colspan="4">'+t(row[1])+'</td></tr>';
    const kind = row[0], name = t(row[1]), ext = row[2], hex = row[3], noteKey = row[4];
    const hexDisplay = (hex === 'ref.hex.none' || hex === 'ref.hex.tar') ? t(hex) : hex;
    return '<tr><td><span class="kind-pill '+(KIND_CLASS[kind]||'other')+'">'+kindLabel(kind)+'</span></td>'+
           '<td>'+name+'</td><td class="ext">'+ext+'</td>'+
           '<td class="hexref">'+hexDisplay+(noteKey ? '<div class="hexnote">'+t(noteKey)+'</div>' : '')+'</td></tr>';
  }).join('');
}
buildRef();
