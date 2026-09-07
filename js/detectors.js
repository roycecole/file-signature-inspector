/* =============================================================
   detectors.js — 判定邏輯
   ---------------------------------------------------------------
   這裡是整個工具的「大腦」：輸入一個 File 物件，輸出「這實際上是
   什麼格式」以及「有沒有需要注意的風險」。UI 相關程式碼（render、
   DOM 操作）完全不放在這裡，方便獨立測試與修改判定邏輯。

   依賴：utils.js（esc/hexOf/ascii/readBytes/u16/u32/fmtSize）、
        signatures.js（SIGS/EXT_SIG_MAP/EXEC_EXT/...）

   內容順序（與函式呼叫順序一致）：
   §5   ZIP 中央目錄解析          → detectZipContainer()
   §5b  CFB/OLE2 複合文件解析     → parseCfb() / classifyCfb()
   §6   純文字啟發式判讀          → looksLikeText() / sniffTextKind()
   §7   簽章判定主流程            → resolveSignature()  ← 主要進入點
   §7b  結尾附加資料 / polyglot   → checkTrailing()
   §7c  PDF 主動風險掃描          → pdfRisks()
   §8   風險判定（檔名 + 內容）   → filenameRisks() / contentRisks()
   ============================================================= */

// 回傳 {names, encrypted}：encrypted 是「任一項目的通用位元旗標第 0 位
// （加密位元）有沒有被設起來」——ZIP 加密只會擋掉項目的實際內容
// （壓縮資料本身），檔名清單通常還是看得到，所以巨集檔名比對
// （zipHasMacro()）多半仍然有效，但無法驗證加密項目「實際內容」
// 是否真的跟檔名相符，contentRisks() 會用這個旗標另外提示。
async function listZipEntries(file){
  try{
    let back = Math.min(file.size, 66000);
    let tail = await readBytes(file, file.size - back, file.size);
    let eocd = -1;
    for(let i = tail.length - 22; i >= 0; i--){
      if(tail[i]===0x50 && tail[i+1]===0x4B && tail[i+2]===0x05 && tail[i+3]===0x06){ eocd = i; break; }
    }
    if(eocd >= 0){
      let cdSize = u32(tail, eocd+12), cdOffset = u32(tail, eocd+16);
      if(cdOffset !== 0xFFFFFFFF && cdSize > 0 && cdOffset + cdSize <= file.size){
        let cd = await readBytes(file, cdOffset, cdOffset + cdSize);
        let names = [], encrypted = false, dec = new TextDecoder('utf-8'), p = 0;
        while(p + 46 <= cd.length && names.length < 4000){
          if(!(cd[p]===0x50 && cd[p+1]===0x4B && cd[p+2]===0x01 && cd[p+3]===0x02)) break;
          if(u16(cd,p+8) & 1) encrypted = true;   // 中央目錄的通用位元旗標
          let nl = u16(cd,p+28), el = u16(cd,p+30), cl = u16(cd,p+32);
          names.push(dec.decode(cd.subarray(p+46, p+46+nl)));
          p += 46 + nl + el + cl;
        }
        if(names.length) return {names:names, encrypted:encrypted};
      }
    }
  }catch(e){}
  try{
    let chunk = await readBytes(file, 0, Math.min(file.size, 512*1024));
    let out = [], encrypted2 = false, d2 = new TextDecoder('utf-8');
    for(let j=0; j+30 <= chunk.length && out.length < 500; j++){
      if(chunk[j]===0x50 && chunk[j+1]===0x4B && chunk[j+2]===0x03 && chunk[j+3]===0x04){
        if(u16(chunk, j+6) & 1) encrypted2 = true;   // 本機檔頭的通用位元旗標
        let n = u16(chunk, j+26);
        if(n>0 && n<300 && j+30+n <= chunk.length) out.push(d2.decode(chunk.subarray(j+30, j+30+n)));
      }
    }
    return {names:out, encrypted:encrypted2};
  }catch(e){ return {names:[], encrypted:false}; }
}
async function readStoredMimetype(file){
  try{
    let head = await readBytes(file, 0, 200);
    if(head.length < 38) return null;
    if(!(head[0]===0x50&&head[1]===0x4B&&head[2]===0x03&&head[3]===0x04)) return null;
    let method=u16(head,8), compSize=u32(head,18), nl=u16(head,26), el=u16(head,28);
    if(nl !== 8 || method !== 0 || compSize === 0 || compSize > 200) return null;
    if(new TextDecoder().decode(head.subarray(30,38)) !== 'mimetype') return null;
    let s = 30 + nl + el;
    return new TextDecoder().decode(await readBytes(file, s, s+compSize)).trim();
  }catch(e){ return null; }
}
function zipHasMacro(names){
  return names.some(function(n){
    return /(^|\/)vbaProject\.bin$/i.test(n) || /(^|\/)vbaData\.xml$/i.test(n) || /(^|\/)macros\//i.test(n);
  });
}

async function detectZipContainer(file){
  let zip = await listZipEntries(file);
  let names = zip.names, encryptedEntries = zip.encrypted;
  let has = function(p){ return names.some(function(n){ return n.indexOf(p) === 0; }); };
  let exact = function(f){ return names.indexOf(f) >= 0; };
  let macro = zipHasMacro(names);

  if(exact('classes.dex') || exact('AndroidManifest.xml'))
    return {type:"exec", name:"Android APK", ext:[".apk"], entries:names, encryptedEntries:encryptedEntries};

  // OOXML：.docx/.xlsx/.pptx 依規格「不得」含巨集，含巨集只能是 m 結尾的副檔名。
  // 因此偵測到 vbaProject.bin 時，建議副檔名必須排除非巨集版本，否則會誤判為相符。
  if(has('word/')){
    return macro
      ? {type:"doc", name:"Word 文件（OOXML，含 VBA 巨集）", ext:[".docm",".dotm"], entries:names, macro:true, encryptedEntries:encryptedEntries}
      : {type:"doc", name:"Word 文件 (OOXML)", ext:[".docx",".dotx",".docm",".dotm"], entries:names, encryptedEntries:encryptedEntries};
  }
  if(has('xl/')){
    if(exact('xl/workbook.bin'))
      return {type:"doc", name:"Excel 二進位活頁簿 (XLSB)", ext:[".xlsb"], entries:names, macro:macro, encryptedEntries:encryptedEntries};
    return macro
      ? {type:"doc", name:"Excel 活頁簿（OOXML，含 VBA 巨集）", ext:[".xlsm",".xltm",".xlam"], entries:names, macro:true, encryptedEntries:encryptedEntries}
      : {type:"doc", name:"Excel 活頁簿 (OOXML)", ext:[".xlsx",".xltx",".xlsm",".xltm"], entries:names, encryptedEntries:encryptedEntries};
  }
  if(has('ppt/')){
    return macro
      ? {type:"doc", name:"PowerPoint 簡報（OOXML，含 VBA 巨集）", ext:[".pptm",".potm",".ppsm"], entries:names, macro:true, encryptedEntries:encryptedEntries}
      : {type:"doc", name:"PowerPoint 簡報 (OOXML)", ext:[".pptx",".potx",".ppsx",".pptm"], entries:names, encryptedEntries:encryptedEntries};
  }

  let mime = await readStoredMimetype(file);
  if(mime){
    if(mime.indexOf('opendocument.text')>=0)         return {type:"doc", name:"OpenDocument 文字 (ODT)",   ext:[".odt",".ott"], entries:names, macro:macro, encryptedEntries:encryptedEntries};
    if(mime.indexOf('opendocument.spreadsheet')>=0)  return {type:"doc", name:"OpenDocument 試算表 (ODS)", ext:[".ods",".ots"], entries:names, macro:macro, encryptedEntries:encryptedEntries};
    if(mime.indexOf('opendocument.presentation')>=0) return {type:"doc", name:"OpenDocument 簡報 (ODP)",   ext:[".odp",".otp"], entries:names, macro:macro, encryptedEntries:encryptedEntries};
    if(mime.indexOf('epub')>=0)                      return {type:"doc", name:"EPUB 電子書",               ext:[".epub"], entries:names, encryptedEntries:encryptedEntries};
  }
  if(exact('META-INF/MANIFEST.MF') || names.some(function(n){ return /\.class$/.test(n); }))
    return {type:"exec", name:"Java JAR（可執行封裝）", ext:[".jar"], entries:names, encryptedEntries:encryptedEntries};
  if(!names.length) return {type:"other", name:"ZIP（無法解析內容）", ext:[".zip"], entries:names, encryptedEntries:encryptedEntries};
  return {type:"other", name:"ZIP 壓縮檔", ext:[".zip"], entries:names, encryptedEntries:encryptedEntries};
}

async function parseCfb(file){
  try{
    let hdr = await readBytes(file, 0, 512);
    if(hdr.length < 512) return null;
    let sectorShift = u16(hdr, 30);
    if(sectorShift < 7 || sectorShift > 14) return null;
    let sectorSize = 1 << sectorShift;
    let numFat = u32(hdr, 44);
    let firstDir = u32(hdr, 48);

    // 前 109 筆 DIFAT 直接放在標頭內，足以涵蓋一般大小的 Office 檔案
    let fatSectors = [];
    for(let i = 0; i < 109 && i < numFat; i++){
      let fs = u32(hdr, 76 + i*4);
      if(fs === 0xFFFFFFFF || fs === 0xFFFFFFFE) break;
      fatSectors.push(fs);
    }
    let fat = [];
    for(let k = 0; k < fatSectors.length; k++){
      let fo = (fatSectors[k] + 1) * sectorSize;
      if(fo + sectorSize > file.size) break;
      let fsec = await readBytes(file, fo, fo + sectorSize);
      for(let j = 0; j + 4 <= fsec.length; j += 4) fat.push(u32(fsec, j));
    }

    let names = [], clsid = null, macro = false;
    let perSector = sectorSize / 128;
    let cur = firstDir, guard = 0;
    while(cur !== 0xFFFFFFFE && cur !== 0xFFFFFFFF && guard++ < 256){
      let off = (cur + 1) * sectorSize;
      if(off + sectorSize > file.size) break;
      let ds = await readBytes(file, off, off + sectorSize);
      for(let e = 0; e < perSector; e++){
        let p = e * 128;
        let nameLen = u16(ds, p + 64);
        let objType = ds[p + 66];               // 1=storage 2=stream 5=root
        if(objType !== 1 && objType !== 2 && objType !== 5) continue;
        if(nameLen < 4 || nameLen > 64) continue;
        let chars = [];
        for(let c = 0; c <= nameLen - 4; c += 2) chars.push(ds[p+c] | (ds[p+c+1] << 8));
        if(!chars.length) continue;
        let nm = String.fromCharCode.apply(null, chars);
        if(objType === 5 && clsid === null) clsid = hexOf(ds.subarray(p + 80, p + 96));
        if(/^_VBA_PROJECT$/i.test(nm) || /^VBA$/i.test(nm) || /^Macros$/i.test(nm)) macro = true;
        names.push(nm);
      }
      if(cur >= fat.length) break;
      cur = fat[cur];
    }
    if(!names.length) return null;
    return {names:names, clsid:clsid, macro:macro};
  }catch(e){ return null; }
}

// MSI 的內部串流名稱使用一組落在 U+3800–U+4DFF 的專屬編碼字元
function hasMsiEncodedNames(names){
  return names.some(function(n){
    for(let i = 0; i < n.length; i++){
      let cc = n.charCodeAt(i);
      if(cc >= 0x3800 && cc <= 0x4DFF) return true;
    }
    return false;
  });
}

function classifyCfb(info){
  let names = info.names, clsid = (info.clsid || '').toUpperCase();
  let hasName = function(x){ return names.some(function(n){ return n.toLowerCase() === x.toLowerCase(); }); };
  let r;

  // 加密的 OOXML（用密碼保護存檔的 .docx/.xlsx/.pptx…）：規格上整包
  // ZIP 內容會被包成不透明的二進位塞進 CFB 的 EncryptedPackage 串流，
  // 連檔名清單都看不到——巨集偵測在這裡是完全的盲區，只能誠實告知
  // 使用者「這裡真的檢查不到」，不能假裝有檢查過然後說「沒有巨集」。
  if(hasName('EncryptionInfo') && hasName('EncryptedPackage')){
    r = {type:"doc", name:"加密的 Office 文件 (OOXML)",
      ext:[".docx",".docm",".xlsx",".xlsm",".pptx",".pptm"], generic:true, encryptedOOXML:true};
  }
  else if(clsid.indexOf('84100C00') === 0 || hasMsiEncodedNames(names))
    r = {type:"exec", name:"Windows Installer 安裝套件 (MSI)", ext:[".msi"]};
  else if(clsid.indexOf('86100C00') === 0)
    r = {type:"exec", name:"Windows Installer 修補檔 (MSP)", ext:[".msp"]};
  else if(hasName('WordDocument'))
    r = {type:"doc", name:"Word 97-2003 文件", ext:[".doc",".dot"]};
  else if(hasName('Workbook') || hasName('Book'))
    r = {type:"doc", name:"Excel 97-2003 活頁簿", ext:[".xls",".xlt",".xla"]};
  else if(hasName('PowerPoint Document'))
    r = {type:"doc", name:"PowerPoint 97-2003 簡報", ext:[".ppt",".pps",".pot"]};
  else if(hasName('__properties_version1.0') || hasName('__nameid_version1.0'))
    r = {type:"doc", name:"Outlook 郵件 (MSG)", ext:[".msg"]};
  else if(hasName('VisioDocument'))
    r = {type:"doc", name:"Visio 繪圖", ext:[".vsd",".vst"]};
  else
    r = {type:"doc", name:"CFB 複合文件（無法細分子類型）", ext:[".doc",".xls",".ppt",".msi",".msg"]};

  r.cfbNames = names;
  r.macro = info.macro;
  return r;
}

function looksLikeText(bytes){
  let n = bytes.length;
  if(!n) return null;
  let i = 0, printable = 0, total = 0;
  while(i < n){
    let b = bytes[i];
    if(b === 0x00) return null;                       // NUL → 判定為二進位
    if(b < 0x80){
      // 允許常見控制字元；其餘 C0 控制碼視為二進位特徵
      if(b === 0x09 || b === 0x0A || b === 0x0D || b === 0x0C || b === 0x1B) { printable++; }
      else if(b < 0x20 || b === 0x7F) { return null; }
      else printable++;
      total++; i++;
    } else if(b >= 0xC2 && b <= 0xDF){
      if(i+1 >= n) break;
      if((bytes[i+1] & 0xC0) !== 0x80) return null;
      printable++; total++; i += 2;
    } else if(b >= 0xE0 && b <= 0xEF){
      if(i+2 >= n) break;
      if((bytes[i+1] & 0xC0) !== 0x80 || (bytes[i+2] & 0xC0) !== 0x80) return null;
      printable++; total++; i += 3;
    } else if(b >= 0xF0 && b <= 0xF4){
      if(i+3 >= n) break;
      if((bytes[i+1] & 0xC0) !== 0x80 || (bytes[i+2] & 0xC0) !== 0x80 || (bytes[i+3] & 0xC0) !== 0x80) return null;
      printable++; total++; i += 4;
    } else return null;                                // 非法 UTF-8 起始位元組
  }
  if(total < 1) return null;
  if(printable / total < 0.95) return null;
  return true;
}

// UTF-8 驗證失敗時的第二道判讀：Big5 / GBK / Shift-JIS 等舊式雙位元組編碼。
// 台灣與中國大陸的舊系統匯出的 .txt/.csv 常見這種編碼，不該被歸為「未知簽章」。
function looksLikeLegacyText(bytes){
  let n = Math.min(bytes.length, 2048);
  if(n < 2) return false;
  let i = 0, chars = 0, dbcs = 0;
  while(i < n){
    let b = bytes[i];
    if(b === 0x00) return false;
    if(b < 0x80){
      if(b < 0x20 && b !== 0x09 && b !== 0x0A && b !== 0x0D && b !== 0x0C) return false;
      chars++; i++;
    } else if(b >= 0x81 && b <= 0xFE){
      if(i + 1 >= n) break;
      let nextByte = bytes[i+1];
      // Big5 次位元組 0x40-0x7E / 0xA1-0xFE；GBK 為 0x40-0xFE（不含 0x7F）
      if(nextByte < 0x40 || nextByte === 0x7F) return false;
      chars++; dbcs++; i += 2;
    } else return false;
  }
  // 需要有一定比例的雙位元組字元，否則純 ASCII 已由 UTF-8 那條路判掉
  return chars > 0 && dbcs > 0 && (dbcs / chars) > 0.15;
}

function sniffTextKind(bytes){
  let head = new TextDecoder('utf-8', {fatal:false}).decode(bytes.subarray(0, Math.min(bytes.length, 2048)));
  let txt = head.replace(/^\uFEFF/, '').trimStart();
  let low = txt.toLowerCase();

  if(/^<\?xml/.test(low) || /^<svg[\s>]/.test(low)){
    if(/<svg[\s>]/.test(low)) return {type:"image", name:"SVG 向量圖", ext:[".svg"], text:txt};
    return {type:"text", name:"XML 文件", ext:[".xml"], text:txt};
  }
  if(/^<!doctype\s+html/.test(low) || /^<html[\s>]/.test(low))
    return {type:"text", name:"HTML 文件", ext:[".html",".htm"], text:txt};
  if(/^[{[]/.test(txt))
    return {type:"text", name:"JSON 資料（推測）", ext:[".json"], text:txt};
  if(/^%!ps|^%pdf-adobe/.test(low))
    return {type:"doc", name:"PostScript / EPS", ext:[".ps",".eps"], text:txt};
  if(/^windows registry editor|^regedit4/.test(low))
    return {type:"text", name:"Windows 登錄檔匯出", ext:[".reg"], text:txt};
  if(/^-----begin [a-z ]*(certificate|key|pgp)/i.test(txt))
    return {type:"text", name:"PEM 憑證 / 金鑰", ext:[".pem",".crt",".key"], text:txt};
  return {type:"text", name:"純文字檔（無簽章）", ext:Array.from(TEXT_EXT), text:txt, generic:true};
}

async function resolveSignature(file, bytes, hex){
  if(hex.indexOf('52494646') === 0 && bytes.length >= 12){
    let riffType = ascii(bytes,8,12);
    if(riffType === 'WEBP') return {type:"image", name:"WebP", ext:[".webp"]};
    if(riffType === 'WAVE') return {type:"other", name:"WAV 音訊", ext:[".wav"]};
    if(riffType === 'AVI ') return {type:"other", name:"AVI 影片", ext:[".avi"]};
    return {type:"other", name:"RIFF 容器", ext:[".riff"]};
  }
  if(bytes.length >= 12 && ascii(bytes,4,8) === 'ftyp'){
    let brand = ascii(bytes,8,12).trim().toLowerCase();
    if(/^(heic|heix|hevc|hevx|mif1|msf1)/.test(brand)) return {type:"image", name:"HEIC/HEIF", ext:[".heic",".heif"]};
    if(/^avif/.test(brand)) return {type:"image", name:"AVIF", ext:[".avif"]};
    if(/^(qt)/.test(brand)) return {type:"other", name:"QuickTime 影片", ext:[".mov"]};
    if(/^(m4a)/.test(brand)) return {type:"other", name:"M4A 音訊", ext:[".m4a"]};
    return {type:"other", name:"MP4 / ISO BMFF 影片", ext:[".mp4",".m4v",".mov"]};
  }
  // TAR：偏移 257 處為 "ustar"
  if(bytes.length >= 262 && ascii(bytes,257,262) === 'ustar')
    return {type:"other", name:"TAR 封存檔", ext:[".tar"]};
  if(hex.indexOf('213C617263683E') === 0)
    return {type:"exec", name:"Debian 套件 / ar 封存", ext:[".deb",".a"]};
  if(hex.indexOf('504B0304') === 0 || hex.indexOf('504B0506') === 0 || hex.indexOf('504B0708') === 0)
    return await detectZipContainer(file);

  // CFB / OLE2：.doc/.xls/.ppt/.msi/.msg 開頭一致，必須讀目錄才分得出來
  if(hex.indexOf('D0CF11E0A1B11AE1') === 0){
    let cfb = await parseCfb(file);
    if(cfb) return classifyCfb(cfb);
    return {type:"doc", name:"CFB 複合文件（目錄無法解析）", ext:[".doc",".xls",".ppt",".msi",".msg"]};
  }

  // 混入使用者自己加的自訂簽章，一起依 magic 長度由長到短比對。
  let allSigs = allSigsSorted();
  for(let i=0;i<allSigs.length;i++){ if(hex.indexOf(allSigs[i].magic) === 0) return allSigs[i]; }

  // MP3 frame sync（無 ID3 標籤）。必須放在簽章表之後，
  // 否則 UTF-16 LE 的 BOM（FF FE）會被誤判成 MP3。
  if(bytes.length >= 2 && bytes[0] === 0xFF && (bytes[1] & 0xE0) === 0xE0 && (bytes[1] & 0x18) !== 0x08)
    return {type:"other", name:"MP3 音訊（frame sync）", ext:[".mp3"]};

  if(looksLikeText(bytes)) return sniffTextKind(bytes);
  if(looksLikeLegacyText(bytes)) return {type:"text", name:"純文字檔（非 UTF-8，可能為 Big5／GBK）", ext:Array.from(TEXT_EXT), generic:true, legacy:true};
  return null;
}

const TAIL_LEN = 262144;

function lastSeq(buf, seq){
  outer:
  for(let i = buf.length - seq.length; i >= 0; i--){
    for(let j = 0; j < seq.length; j++) if(buf[i+j] !== seq[j]) continue outer;
    return i;
  }
  return -1;
}
function findSeq(buf, seq, from){
  outer:
  for(let i = from || 0; i <= buf.length - seq.length; i++){
    for(let j = 0; j < seq.length; j++) if(buf[i+j] !== seq[j]) continue outer;
    return i;
  }
  return -1;
}

const END_MARKERS = {
  "JPEG":                {seq:[0xFF,0xD9], after:2},
  "PNG":                 {seq:[0x49,0x45,0x4E,0x44,0xAE,0x42,0x60,0x82], after:8},
  "GIF (87a)":           {seq:[0x3B], after:1},
  "GIF (89a)":           {seq:[0x3B], after:1},
  "PDF":                 {seq:[0x25,0x25,0x45,0x4F,0x46], after:5, slack:64}
};

const EMBEDDED_SIGS = [
  {seq:[0x50,0x4B,0x05,0x06], labelKey:'archive.eocd'},
  {seq:[0x52,0x61,0x72,0x21,0x1A,0x07], labelKey:'archive.rar'},
  {seq:[0x37,0x7A,0xBC,0xAF,0x27,0x1C], labelKey:'archive.sevenZip'}
];

async function checkTrailing(file, det, head){
  let out = {risks:[], trailing:0, declared:null};
  if(!det || !file.size) return out;
  let isZipLike = /ZIP|OOXML|APK|JAR|EPUB|OpenDocument|XLSB/i.test(det.name);
  let fmtDisp = formatName(det.name);

  let start = Math.max(0, file.size - TAIL_LEN);
  let tail;
  try{ tail = await readBytes(file, start, file.size); }catch(e){ return out; }

  // 1) 依格式的結束標記推算尾端多餘資料
  let m = END_MARKERS[det.name];
  if(m){
    let pos = lastSeq(tail, m.seq);
    if(pos >= 0){
      let endAbs = start + pos + m.after;
      let extra = file.size - endAbs;
      // 允許少量換行或補位
      let slack = m.slack || 16;
      if(extra > slack){
        out.trailing = extra;
        out.risks.push({level:'info', title:t('risk.trailingDataTitle', {extra: fmtSize(extra)}),
          text:t('risk.trailingDataText', {format: fmtDisp, extraBytes: extra.toLocaleString()})});
      }
    }
  }

  // 2) 非壓縮格式的尾端出現壓縮檔簽章 → 典型的 polyglot／檔案走私
  if(!isZipLike){
    for(let i = 0; i < EMBEDDED_SIGS.length; i++){
      let s = EMBEDDED_SIGS[i];
      let at = lastSeq(tail, s.seq);
      if(at >= 0 && (start + at) > 0){
        let lbl = t(s.labelKey);
        out.risks.push({level:'high', title:t('risk.embeddedArchiveTitle', {label: lbl}),
          text:t('risk.embeddedArchiveText', {format: fmtDisp, offset: (start + at).toLocaleString(), label: lbl})});
        break;
      }
    }
  }

  // 3) 標頭自述長度與實際檔案大小不符（BMP / RIFF）
  if(head && head.length >= 8){
    if(det.name === 'BMP'){
      let dec = u32(head, 2);
      if(dec > 0 && Math.abs(dec - file.size) > 1024){
        out.declared = dec;
        out.risks.push({level:'info', title:t('risk.bmpSizeTitle'),
          text:t('risk.bmpSizeText', {declared: fmtSize(dec), actual: fmtSize(file.size)})});
      }
    } else if(det.name === 'WAV 音訊' || det.name === 'AVI 影片' || det.name === 'WebP'){
      let dr = u32(head, 4) + 8;
      if(dr > 0 && file.size - dr > 1024){
        out.declared = dr;
        out.risks.push({level:'info', title:t('risk.riffSizeTitle'),
          text:t('risk.riffSizeText', {declared: fmtSize(dr), actual: fmtSize(file.size)})});
      }
    }
  }
  return out;
}

const PDF_TOKENS = [
  {tok:'/Launch',       level:'high', descKey:'pdf.tok.launch'},
  {tok:'/JavaScript',   level:'high', descKey:'pdf.tok.javascript'},
  {tok:'/JS',           level:'high', descKey:'pdf.tok.js'},
  {tok:'/OpenAction',   level:'info', descKey:'pdf.tok.openAction'},
  {tok:'/AA',           level:'info', descKey:'pdf.tok.aa'},
  {tok:'/EmbeddedFile', level:'info', descKey:'pdf.tok.embeddedFile'},
  {tok:'/RichMedia',    level:'info', descKey:'pdf.tok.richMedia'},
  {tok:'/XFA',          level:'info', descKey:'pdf.tok.xfa'},
  {tok:'/SubmitForm',   level:'info', descKey:'pdf.tok.submitForm'}
];

async function pdfRisks(file){
  let out = [];
  try{
    let dec = new TextDecoder('latin1');
    let n = Math.min(file.size, 1024 * 1024);
    let s = dec.decode(await readBytes(file, 0, n));
    if(file.size > n) s += dec.decode(await readBytes(file, Math.max(n, file.size - TAIL_LEN), file.size));

    let highs = [], infos = [];
    PDF_TOKENS.forEach(function(tk){
      if(s.indexOf(tk.tok) >= 0){
        let entry = tk.tok + '（' + t(tk.descKey) + '）';
        if(tk.level === 'high') highs.push(entry);
        else infos.push(entry);
      }
    });
    if(highs.length){
      out.push({level:'high', title:t('risk.pdfActionsTitle'),
        text:t('risk.pdfActionsText', {list: highs.join('、')})});
    }
    if(infos.length){
      out.push({level:'info', title:t('risk.pdfNotableTitle'),
        text:t('risk.pdfNotableText', {list: infos.join('、')})});
    }
    if(highs.length || infos.length){
      out.push({level:'info', title:t('risk.pdfLimitTitle'), text:t('risk.pdfLimitText')});
    }
  }catch(e){}
  return out;
}

function filenameRisks(name){
  let out = [];
  if(/[\u202A-\u202E\u2066-\u2069]/.test(name)){
    out.push({level:'high', title:t('risk.rloTitle'), text:t('risk.rloText')});
  }
  let parts = name.toLowerCase().split('.');
  if(parts.length >= 3){
    let last = '.' + parts[parts.length-1], prev = parts[parts.length-2];
    if(EXEC_EXT.has(last) && BENIGN_EXT.has(prev)){
      out.push({level:'high', title:t('risk.doubleExtTitle', {prev:prev, last:last}),
        text:t('risk.doubleExtText', {prev:prev, last:last})});
    }
  }
  if(/\s{8,}\S+$/.test(name)){
    out.push({level:'high', title:t('risk.whitespaceTitle'), text:t('risk.whitespaceText')});
  }
  return out;
}

function contentRisks(r, det){
  let out = [];
  let fmtDisp = formatName(r.format);
  if(r.type === 'exec'){
    if(!EXEC_EXT.has(r.claimed)){
      out.push({level:'high', title:t('risk.execMismatchTitle'),
        text:t('risk.execMismatchText', {claimed:r.claimed, format:fmtDisp})});
    } else {
      out.push({level:'info', title:t('risk.execMatchTitle'),
        text:t('risk.execMatchText', {format:fmtDisp})});
    }
  }
  if(det && det.text){
    let low = det.text.toLowerCase();
    let hasScript = /<script[\s>]/.test(low) || /javascript:/.test(low) || /\son\w+\s*=/.test(low);
    if(det.name === 'SVG 向量圖' && hasScript){
      out.push({level:'high', title:t('risk.svgScriptTitle'), text:t('risk.svgScriptText')});
    }
    if((det.name === 'HTML 文件') && !/^\.(html|htm)$/.test(r.claimed) && hasScript){
      out.push({level:'high', title:t('risk.htmlScriptMismatchTitle'),
        text:t('risk.htmlScriptMismatchText', {claimed:r.claimed})});
    }
  }
  if(r.type === 'text' && SCRIPT_EXT.has(r.claimed)){
    out.push({level:'info', title:t('risk.scriptMatchTitle'),
      text:t('risk.scriptMatchText', {claimed:r.claimed})});
  }
  if(det && det.macro){
    let m = /^\.(docm|dotm|xlsm|xltm|xlam|pptm|potm|ppsm|xlsb|doc|dot|xls|xlt|xla|ppt|pot|pps)$/.test(r.claimed);
    if(!m){
      out.push({level:'high', title:t('risk.macroMismatchTitle'),
        text:t('risk.macroMismatchText', {claimed:r.claimed})});
    } else {
      out.push({level:'info', title:t('risk.macroMatchTitle'), text:t('risk.macroMatchText')});
    }
  }
  // 加密文件是本工具明確的檢查盲區（見 classifyCfb()／detectZipContainer()
  // 的說明），這裡不判斷「有沒有風險」，只誠實告知使用者這裡沒檢查到。
  if(det && det.encryptedOOXML){
    out.push({level:'info', title:t('risk.encryptedOfficeTitle'), text:t('risk.encryptedOfficeText')});
  }
  if(det && det.encryptedEntries){
    out.push({level:'info', title:t('risk.encryptedZipTitle'), text:t('risk.encryptedZipText')});
  }
  return out;
}
/* =============================================================
   §9. 分析單一檔案（核心邏輯，主執行緒與 Worker 共用）
   ---------------------------------------------------------------
   這個函式刻意跟「怎麼跑」（主執行緒直接呼叫，還是丟給
   detect-worker.js 在背景執行緒跑）完全脫鉤：只吃 File 物件，
   吐出一份純資料（可以直接用 postMessage 結構化複製傳遞，沒有
   函式、沒有 File 參照、沒有 DOM 物件）。

   刻意不做的兩件事，都是因為它們只有在主執行緒才有意義：
   - 不指派 id（id 要在主執行緒統一發放，避免多個 Worker 平行跑
     的時候搶號碼）
   - 不建立預覽用的 Blob URL（見 app.js 的 attachPreview()）——
     URL.createObjectURL 在 Worker 裡技術上也能用，但「哪個 File
     參照才是正本」這件事只在主執行緒清楚，索性把這一步留在那邊。

   app.js 的 analyzeFile() 是這個函式的薄包裝：呼叫這裡（可能經過
   Worker 池，也可能在失敗時退回本機直接呼叫），拿到結果後再補上
   id／file／previewUrl 這幾個「執行環境相關」的欄位。
   ============================================================= */
const HEAD_LEN = 4096;

async function analyzeFileCore(file, relPath){
  let name = relPath || file.name;
  let claimed = getExt(name);
  let bytes, readError = null;
  // 讀取失敗不能只是靜默 catch——使用者會以為這個檔案「檢查過沒問題」，
  // 實際上我們根本沒讀到內容。把錯誤原因記下來，下面轉成一則風險說明顯示。
  try{ bytes = await readBytes(file, 0, HEAD_LEN); }
  catch(e){ bytes = new Uint8Array(0); readError = (e && e.message) ? e.message : String(e); }

  let r = {
    name:name, claimed:claimed || '(無)',
    size:file.size, mtime:file.lastModified || 0,
    head:bytes.subarray(0, Math.min(bytes.length, 64)),
    readError:readError,
    previewKind:null, previewMime:null
  };

  if(!bytes.length){
    r.type='other'; r.format='空檔案或無法讀取'; r.suggestExt='-'; r.suggestFirst='';
    r.verdict='unknown'; r.rawHex=''; r.hex='-';
    r.risks = filenameRisks(name);
    if(readError){
      r.risks.unshift({level:'high', title:t('risk.readErrorTitle'),
        text:t('risk.readErrorText', {reason: readError})});
    }
  } else {
    let rawHex = hexOf(bytes.subarray(0, Math.min(bytes.length, 64)));
    let det = await resolveSignature(file, bytes, rawHex);
    r.rawHex = rawHex;
    r.hex = rawHex.slice(0,16).replace(/(..)/g,'$1 ').trim();
    if(det){
      r.type = det.type; r.format = det.name;
      r.suggestExtGeneric = !!det.generic;
      r.suggestExt = det.generic ? '' : det.ext.join(' ');
      r.suggestFirst = det.ext[0];
      r.verdict = det.ext.indexOf(claimed) >= 0 ? 'match' : 'mismatch';
      if(det.generic && TEXT_EXT.has(claimed)) r.verdict = 'match';
      // 只決定「這個檔案可以用哪種方式預覽」，不在這裡真的建立 Blob URL——
      // 見上面檔案頂端的說明。
      let mp = MEDIA_PREVIEW[det.name];
      if(mp){ r.previewKind = mp.kind; r.previewMime = mp.mime; }
      r.zipEntries = det.entries || null;
      r.cfbNames = det.cfbNames || null;
    } else {
      r.type='other'; r.format='未知簽章'; r.suggestExt='-'; r.suggestFirst='';
      r.verdict='unknown';
    }

    let extra = [];
    if(det){
      let trailingResult = await checkTrailing(file, det, bytes);
      r.trailing = trailingResult.trailing;
      extra = extra.concat(trailingResult.risks);
      if(det.name === 'PDF') extra = extra.concat(await pdfRisks(file));
    }
    r.risks = filenameRisks(name).concat(contentRisks(r, det)).concat(extra);
  }
  r.high = r.risks.some(function(x){ return x.level === 'high'; });
  return r;
}
