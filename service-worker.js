/* =============================================================
   service-worker.js — 離線快取（PWA 用）
   ---------------------------------------------------------------
   重要限制先講在前面：Service Worker 是瀏覽器規格明訂只能在「安全
   情境」下註冊的功能——也就是 https:// 或 http://localhost。用
   file:// 直接打開 index.html（這個工具原本、也依然支援的用法）
   不會、也不能註冊這個檔案，`app.js` 裡的註冊程式碼會偵測不到
   `location.protocol` 符合條件，直接跳過，不會噴錯、不影響任何
   既有功能。這個檔案只服務「把整個資料夾放到網頁伺服器上」這種
   進階用法。

   快取策略選最簡單的「cache first, network fallback」：這個工具
   本來就標榜不連網路（CSP 也直接把 connect-src 設成 'none'），
   所有資源都是同來源的靜態檔案，沒有動態內容需要考慮新鮮度，
   用不著更複雜的策略。

   版本管理：CACHE_NAME 帶版號，之後修改核心檔案清單或內容時把
   版號往上加一，activate 階段會自動清掉舊版快取，不會讓使用者
   卡在舊版本一直看不到更新。
   ============================================================= */

const CACHE_NAME = 'fsi-cache-v1';

const CORE_ASSETS = [
  './',
  './index.html',
  './test.html',
  './manifest.json',
  './css/styles.css',
  './js/utils.js',
  './js/i18n.js',
  './js/sha256.js',
  './js/sha256-worker.js',
  './js/signatures.js',
  './js/detectors.js',
  './js/detect-worker.js',
  './js/preview.js',
  './js/compare.js',
  './js/reference-table.js',
  './js/app.js',
  './assets/favicon.svg'
];

self.addEventListener('install', function(e){
  e.waitUntil(
    caches.open(CACHE_NAME).then(function(cache){ return cache.addAll(CORE_ASSETS); })
  );
  self.skipWaiting();
});

self.addEventListener('activate', function(e){
  e.waitUntil(
    caches.keys().then(function(names){
      return Promise.all(
        names.filter(function(n){ return n !== CACHE_NAME; })
             .map(function(n){ return caches.delete(n); })
      );
    })
  );
  self.clients.claim();
});

self.addEventListener('fetch', function(e){
  if(e.request.method !== 'GET') return;
  e.respondWith(
    caches.match(e.request).then(function(cached){
      if(cached) return cached;
      return fetch(e.request).catch(function(){
        // 離線、又沒快取到：沒有更好的辦法，讓請求照常失敗即可，
        // 不要假裝提供一個看起來成功但內容是空的回應。
      });
    })
  );
});
