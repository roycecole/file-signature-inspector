/* =============================================================
   detect-worker.js — 在背景執行緒執行檔案分析
   ---------------------------------------------------------------
   跟 sha256-worker.js 是同一套精神：用 importScripts() 直接載入
   正式程式碼，不維護第二份副本。這裡載入的是判定邏輯需要的四個
   檔案，跟 test.html 開發用的自我測試頁用的是同一組（純邏輯、
   不碰 DOM）：

     utils.js       readBytes/hexOf/ascii/u16/u32/getExt… 這些工具函式
     i18n.js        t()/formatName()——風險說明的文字要能正確翻譯
     signatures.js  SIGS/EXT_SIG_MAP/customSigs 這些資料
     detectors.js   真正的判定邏輯，包含這裡會呼叫的 analyzeFileCore()

   兩個跟「在 Worker 裡跑」有關、容易忽略的細節：

   1. localStorage 在 Worker 裡不存在。i18n.js 的 detectInitialLang()
      跟 signatures.js 的 loadCustomSigs() 都已經用 try/catch 包住
      localStorage 的存取，所以不會噴例外，只是會安靜地拿到空結果——
      這正是為什麼下面 'sync-custom-sigs' 這個訊息類型是必要的：
      主執行緒載入頁面時已經從 localStorage 讀到使用者自訂的簽章，
      Worker 這邊讀不到，需要主執行緒主動同步過來一次，之後使用者
      新增/刪除自訂簽章時也會再同步。

   2. currentLang（i18n.js）在每個 Worker 都是各自獨立的一份，
      不會因為使用者在主執行緒切換語言就自動更新。所以每個分析
      請求都帶著當下的語言（見下面 'analyze' 訊息的 lang 欄位），
      處理前先用 setLangSilent() 對齊——用「安靜」版本是因為一般的
      setLang() 會呼叫 document.documentElement.setAttribute()，
      Worker 裡沒有 document，會直接拋例外。
   ============================================================= */

importScripts('utils.js', 'i18n.js', 'signatures.js', 'detectors.js');

self.onmessage = async function(e){
  const msg = e.data;
  if(!msg) return;

  if(msg.type === 'sync-custom-sigs'){
    customSigs = Array.isArray(msg.sigs) ? msg.sigs : [];
    return;
  }

  if(msg.type === 'analyze'){
    setLangSilent(msg.lang);
    try{
      const result = await analyzeFileCore(msg.file, msg.relPath);
      self.postMessage({ type:'result', reqId: msg.reqId, result: result });
    }catch(err){
      self.postMessage({ type:'error', reqId: msg.reqId, error: (err && err.message) ? err.message : String(err) });
    }
  }
};
