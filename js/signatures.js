/* =============================================================
   signatures.js — 簽章表與分類資料
   ---------------------------------------------------------------
   這個檔案只放「資料」，不放邏輯：已知檔案格式的開頭位元組
   （Magic Number）、副檔名對照、風險分類用的集合等等。

   要新增一種可辨識的格式，通常只需要在這個檔案加一筆資料，
   不需要碰 detectors.js 的判定流程：
     1. 在 SIGS 陣列加入 {type, name, ext, magic}
        - magic 是不含空格的大寫十六進位字串
        - 陣列會依 magic 長度由長到短自動排序，長簽章優先比對，
          避免像 "FF" 這種短前綴誤判掉更精確的格式
     2. 如果這個格式可以預覽（圖片/影片/音訊/PDF），
        在 MEDIA_PREVIEW 補上對應的 MIME type
     3. 如果想讓「常見檔案簽章對照表」也顯示，去 reference-table.js
        的 REF 陣列加一列

   type 的可能值：image / doc / text / exec / other
   ============================================================= */

var SIGS = [
  {type:"exec", name:"Windows 捷徑 (LNK)", ext:[".lnk"], magic:"4C0000000114020000000000C000000000000046"},
  {type:"other",name:"SQLite 資料庫",      ext:[".sqlite",".db",".sqlite3"], magic:"53514C69746520666F726D6174203300"},
  {type:"image",name:"PNG",                ext:[".png"], magic:"89504E470D0A1A0A"},
  {type:"doc",  name:"Office 97-2003 / CFB (doc/xls/ppt/msi)", ext:[".doc",".xls",".ppt",".msi"], magic:"D0CF11E0A1B11AE1"},
  {type:"other",name:"XZ 壓縮檔",           ext:[".xz"],  magic:"FD377A585A00"},
  {type:"image",name:"GIF (87a)",          ext:[".gif"], magic:"474946383761"},
  {type:"image",name:"GIF (89a)",          ext:[".gif"], magic:"474946383961"},
  {type:"other",name:"RAR 壓縮檔 (v5)",     ext:[".rar"], magic:"526172211A070100"},
  {type:"other",name:"RAR 壓縮檔 (v4)",     ext:[".rar"], magic:"526172211A0700"},
  {type:"other",name:"7-Zip 壓縮檔",        ext:[".7z"],  magic:"377ABCAF271C"},
  {type:"doc",  name:"RTF",                ext:[".rtf"], magic:"7B5C727466"},
  {type:"other",name:"WOFF2 字型",          ext:[".woff2"], magic:"774F4632"},
  {type:"other",name:"WOFF 字型",           ext:[".woff"],  magic:"774F4646"},
  {type:"other",name:"OpenType 字型",       ext:[".otf"],   magic:"4F54544F"},
  {type:"exec", name:"RPM 套件",            ext:[".rpm"], magic:"EDABEEDB"},
  {type:"exec", name:"ELF 執行檔 (Linux)",  ext:[".elf",".so",".bin"], magic:"7F454C46"},
  {type:"exec", name:"Mach-O (macOS, 64-bit)",     ext:[".dylib",".bundle",".o"], magic:"CFFAEDFE"},
  {type:"exec", name:"Mach-O (macOS, 32-bit)",     ext:[".dylib",".bundle",".o"], magic:"CEFAEDFE"},
  {type:"exec", name:"Mach-O (big-endian, 64-bit)",ext:[".dylib",".bundle",".o"], magic:"FEEDFACF"},
  {type:"exec", name:"Mach-O (big-endian, 32-bit)",ext:[".dylib",".bundle",".o"], magic:"FEEDFACE"},
  {type:"exec", name:"Java class / Mach-O 通用二進位", ext:[".class"], magic:"CAFEBABE"},
  {type:"exec", name:"Microsoft Cabinet (CAB)",    ext:[".cab"], magic:"4D534346"},
  {type:"exec", name:"Android DEX",        ext:[".dex"], magic:"6465780A"},
  {type:"other",name:"Matroska / WebM 影片",ext:[".mkv",".webm"], magic:"1A45DFA3"},
  {type:"image",name:"Photoshop PSD",      ext:[".psd"], magic:"38425053"},
  {type:"other",name:"OGG 音訊",            ext:[".ogg",".oga",".opus"], magic:"4F676753"},
  {type:"other",name:"FLAC 音訊",           ext:[".flac"], magic:"664C6143"},
  {type:"other",name:"MP3 音訊 (ID3 標籤)", ext:[".mp3"], magic:"494433"},
  {type:"image",name:"TIFF (Intel)",       ext:[".tif",".tiff"], magic:"49492A00"},
  {type:"image",name:"TIFF (Motorola)",    ext:[".tif",".tiff"], magic:"4D4D002A"},
  {type:"doc",  name:"PDF",                ext:[".pdf"], magic:"25504446"},
  {type:"image",name:"ICO 圖示",            ext:[".ico"], magic:"00000100"},
  {type:"other",name:"TrueType 字型",       ext:[".ttf"], magic:"00010000"},
  {type:"exec", name:"Flash SWF (未壓縮)",  ext:[".swf"], magic:"465753"},
  {type:"exec", name:"Flash SWF (壓縮)",    ext:[".swf"], magic:"435753"},
  {type:"image",name:"JPEG",               ext:[".jpg",".jpeg"], magic:"FFD8FF"},
  {type:"other",name:"BZIP2 壓縮檔",        ext:[".bz2",".tbz2"], magic:"425A68"},
  {type:"other",name:"GZIP 壓縮檔",         ext:[".gz",".tgz"], magic:"1F8B"},
  {type:"exec", name:"Windows 執行檔 / DLL (PE, MZ)", ext:[".exe",".dll",".scr",".sys",".ocx",".cpl",".com",".msi"], magic:"4D5A"},
  {type:"exec", name:"Shell / 腳本 (shebang #!)", ext:[".sh",".py",".pl",".rb",".bash"], magic:"2321"},
  {type:"text", name:"UTF-16 LE 文字檔",    ext:[".txt",".csv",".log",".ini",".reg"], magic:"FFFE"},
  {type:"text", name:"UTF-16 BE 文字檔",    ext:[".txt",".csv",".log",".ini"], magic:"FEFF"},
  {type:"image",name:"BMP",                ext:[".bmp"], magic:"424D"},
].sort(function(a,b){ return b.magic.length - a.magic.length; });

var KIND_LABEL = {image:"圖片", doc:"文件", text:"純文字", exec:"執行檔", other:"其他"};
var KIND_CLASS = {image:"img", doc:"doc", text:"text", exec:"exec", other:"other"};

/* -------------------------------------------------------------
   MEDIA_PREVIEW — 可以直接在畫面上預覽的格式
   ---------------------------------------------------------------
   key 是 resolveSignature() 回傳的格式名稱（必須完全對應 SIGS /
   detectors.js 裡用到的 name 字串），value 是：
     kind : 'image' | 'video' | 'audio' | 'pdf'  → 決定用哪種預覽 UI
     mime : 建立預覽用 Blob 時要強制指定的 MIME type

   為什麼要「強制指定」MIME，而不是用瀏覽器猜的？
   因為 File.type 是瀏覽器依照「檔名副檔名」查作業系統的對照表猜出來的，
   不是看內容。一個被改名成 .txt 的 MP4，其 file.type 會是文字類型，
   瀏覽器的 <video> 標籤就不會播放。我們是先用簽章判斷出「這其實是
   MP4」，所以改用 file.slice(0, file.size, 'video/mp4') 產生一個
   MIME 正確的 Blob，預覽才會正常運作——這也順便證明了判定是對的。
   ------------------------------------------------------------- */
/* -------------------------------------------------------------
   PREVIEW_SIZE_LIMIT — 自動建立預覽 Blob 的檔案大小門檻（bytes）
   ---------------------------------------------------------------
   建立預覽用的 Blob 本身很輕（File.slice() 只是參照，不會複製資料），
   真正花記憶體/效能的是瀏覽器把它塞進 <video>/<audio>/<iframe> 之後
   要解碼、渲染的那一刻，加上使用者可能一次拖進上百個檔案，若每個都
   自動建立預覽，容易在還沒點開任何一個之前就先卡住畫面。

   所以超過門檻的檔案不會自動建立 previewUrl，只會記住「這是什麼種類、
   要用什麼 MIME」；使用者點縮圖時看到的是「檔案過大，要不要仍然載入」
   的確認畫面，按下去才真的建立 Blob 並播放/顯示（見 preview.js 的
   loadPreviewNow()）。
   ------------------------------------------------------------- */
var PREVIEW_SIZE_LIMIT = {
  image: 30  * 1024 * 1024,   // 30 MB —— 正常圖片很少超過這個大小
  video: 300 * 1024 * 1024,   // 300 MB
  audio: 100 * 1024 * 1024,   // 100 MB
  pdf:   80  * 1024 * 1024    // 80 MB
};

var MEDIA_PREVIEW = {
  // 圖片
  "PNG":              {kind:"image", mime:"image/png"},
  "JPEG":             {kind:"image", mime:"image/jpeg"},
  "GIF (87a)":        {kind:"image", mime:"image/gif"},
  "GIF (89a)":        {kind:"image", mime:"image/gif"},
  "BMP":              {kind:"image", mime:"image/bmp"},
  "WebP":             {kind:"image", mime:"image/webp"},
  "ICO 圖示":          {kind:"image", mime:"image/x-icon"},
  "SVG 向量圖":        {kind:"image", mime:"image/svg+xml"},
  // 影片
  "MP4 / ISO BMFF 影片": {kind:"video", mime:"video/mp4"},
  "QuickTime 影片":      {kind:"video", mime:"video/quicktime"},
  "AVI 影片":            {kind:"video", mime:"video/x-msvideo"},
  // Matroska(.mkv) 與 WebM(.webm) 共用同一個 EBML 標頭簽章，無法單從
  // 開頭位元組分辨；瀏覽器對 WebM 支援度遠高於 MKV，一律嘗試用
  // video/webm 播放，播不出來時使用者仍可從縮圖旁的按鈕另存原檔查看。
  "Matroska / WebM 影片": {kind:"video", mime:"video/webm"},
  // 音訊
  "WAV 音訊":              {kind:"audio", mime:"audio/wav"},
  "MP3 音訊 (ID3 標籤)":   {kind:"audio", mime:"audio/mpeg"},
  "MP3 音訊（frame sync）":{kind:"audio", mime:"audio/mpeg"},
  "FLAC 音訊":             {kind:"audio", mime:"audio/flac"},
  "OGG 音訊":              {kind:"audio", mime:"audio/ogg"},
  "M4A 音訊":              {kind:"audio", mime:"audio/mp4"},
  // 文件
  "PDF":              {kind:"pdf", mime:"application/pdf"}
};

var EXEC_EXT = new Set([".exe",".dll",".scr",".sys",".ocx",".cpl",".com",".pif",".msi",".msp",".cab",
  ".bat",".cmd",".ps1",".psm1",".vbs",".vbe",".js",".jse",".wsf",".wsh",".hta",".reg",
  ".jar",".apk",".dex",".class",".sh",".bash",".py",".pl",".rb",".lnk",".swf",
  ".elf",".so",".dylib",".bundle",".app",".deb",".rpm",".run",".bin"]);

var SCRIPT_EXT = new Set([".ps1",".psm1",".bat",".cmd",".vbs",".vbe",".js",".jse",".wsf",".hta",".sh",".bash",".py",".pl",".rb",".reg"]);

var BENIGN_EXT = new Set(["pdf","doc","docx","xls","xlsx","ppt","pptx","txt","csv","rtf","odt","ods","odp",
  "jpg","jpeg","png","gif","bmp","tif","tiff","webp","heic","svg","ico",
  "mp3","mp4","mov","avi","wav","zip","rar","7z","html","htm","json","xml","log"]);

var TEXT_EXT = new Set([".txt",".csv",".tsv",".log",".md",".markdown",".json",".xml",".yml",".yaml",
  ".ini",".cfg",".conf",".properties",".html",".htm",".css",".js",".ts",".jsx",".sql",".srt",".vtt",
  ".ps1",".psm1",".bat",".cmd",".sh",".bash",".py",".pl",".rb",".php",".java",".c",".h",".cpp",".cs",
  ".go",".rs",".r",".m",".reg",".env",".gitignore",".svg"]);

var ZIP_FAMILY = {
  ".docx":"Word (OOXML)", ".docm":"Word (OOXML, 巨集)", ".xlsx":"Excel (OOXML)", ".xlsm":"Excel (OOXML, 巨集)",
  ".pptx":"PowerPoint (OOXML)", ".ppsx":"PowerPoint (OOXML)", ".pptm":"PowerPoint (OOXML, 巨集)",
  ".odt":"OpenDocument 文字", ".ods":"OpenDocument 試算表", ".odp":"OpenDocument 簡報",
  ".epub":"EPUB 電子書", ".zip":"ZIP 壓縮檔", ".jar":"Java JAR", ".apk":"Android APK"
};

// 副檔名 → 預期簽章的反查表，detectors.js 的 buildMismatchDetail() 用它
// 來畫「依副檔名應該長怎樣」的那排位元組方塊。
// 注意：ZIP 家族的項目不預先組好完整的顯示字串（例如「ZIP 容器格式
// （Word (OOXML)）」），而是存 family 原始值，讓 i18n.js 在顯示當下
// 才用 t('fmt.zipContainerOf', {family:...}) 組字串——這樣才能依照
// 使用者選的語言組出對的句子，而不是把中文句型寫死在資料裡。
var EXT_SIG_MAP = {};
SIGS.forEach(function(s){ s.ext.forEach(function(e){ if(!EXT_SIG_MAP[e]) EXT_SIG_MAP[e] = {magic:s.magic, name:s.name}; }); });
Object.keys(ZIP_FAMILY).forEach(function(e){
  if(!EXT_SIG_MAP[e]) EXT_SIG_MAP[e] = {magic:"504B0304", family:ZIP_FAMILY[e], isZip:true};
});
