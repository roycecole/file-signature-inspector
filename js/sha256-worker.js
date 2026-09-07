/* =============================================================
   sha256-worker.js — 在背景執行緒計算 SHA-256
   ---------------------------------------------------------------
   大檔案（幾百 MB 甚至更大）計算 SHA-256 時，就算優先用了
   WebCrypto，光是 file.arrayBuffer() 把整個檔案讀進記憶體、加上
   雜湊運算本身，都可能讓主執行緒卡住一兩秒甚至更久，畫面會整個
   凍住點不動。搬進 Worker 之後這些工作都在背景做，UI 隨時能互動。

   用 importScripts() 直接載入 sha256.js，而不是把程式碼複製一份——
   sha256.js 本身不碰 DOM（沒有 document/window），純粹是
   Sha256 類別與 sha256File() 函式，Worker 環境一樣能跑，沒必要
   維護兩份一樣的程式碼。

   File／Blob 物件可以透過 postMessage() 的結構化複製演算法直接
   傳進 Worker，不需要先轉成 ArrayBuffer——Worker 收到後一樣可以
   呼叫 .slice()／.arrayBuffer()，跟在主執行緒上用起來完全一樣。

   已知限制：部分瀏覽器在頁面本身是用 file:// 開啟時，不允許建立
   Worker（這是瀏覽器的安全限制，不是這支程式的問題）。app.js 那邊
   會偵測 Worker 建立/執行是否失敗，失敗就自動退回主執行緒計算，
   使用者不會因此不能用，只是大檔案時 UI 會卡一下。
   ============================================================= */

importScripts('sha256.js');

self.onmessage = async function(e){
  const id = e.data && e.data.id;
  const file = e.data && e.data.file;
  try{
    if(!file) throw new Error('no file payload');
    const hash = await sha256File(file);
    self.postMessage({ id: id, hash: hash });
  }catch(err){
    self.postMessage({ id: id, error: (err && err.message) ? err.message : String(err) });
  }
};
