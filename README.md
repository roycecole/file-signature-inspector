# 檔案簽章鑑識台

讀取檔案開頭的位元組（Magic Number），判斷檔案「實際的格式」是否跟「目前的副檔名」相符，並標示偽裝成文件／圖片的執行檔。純前端、完全離線，不需要伺服器、不需要建置流程。

## 怎麼開啟

直接用瀏覽器打開 `index.html` 就能用。

**整個資料夾（含 `css/` 與 `js/` 子目錄）要保持在一起**——`index.html` 是用相對路徑載入樣式表和 JavaScript 檔案的，只複製 `index.html` 單獨拿出去用是打不開的。

不需要 `npm install`、不需要架本機伺服器、不需要網路連線。把整個資料夾複製到隨身碟、隔離環境或離線電腦，一樣可以正常運作。

## 資料夾結構

```
.
├── index.html              主頁面（結構層，沒有內嵌樣式或程式碼）
├── test.html                開發用的自我測試頁（詳見下方「開發與測試」）
├── CHANGELOG.md              版本異動紀錄
├── README.md                 就是這份文件
├── manifest.json              PWA manifest（可安裝，需 https:// 或 localhost）
├── service-worker.js          PWA 離線快取（同上，file:// 下不生效但不影響其他功能）
├── assets/
│   └── favicon.svg             網站圖示（純 SVG，不需要額外轉檔工具）
├── css/
│   └── styles.css             全部樣式（含分節註解、深色/淺色主題、響應式版面、動畫）
└── js/
    ├── utils.js                共用小工具（HTML escape、格式化、複製到剪貼簿…）
    ├── i18n.js                  多語系字典與翻譯函式（繁中／English／日本語）
    ├── sha256.js                SHA-256 雜湊（WebCrypto 優先，純 JS 備援）
    ├── sha256-worker.js         SHA-256 的 Web Worker 版本（importScripts 載入 sha256.js）
    ├── signatures.js            簽章表、分類資料、自訂簽章的儲存/驗證/匯出入
    ├── detectors.js             判定邏輯核心，含可在主執行緒或 Worker 共用的 analyzeFileCore()
    ├── detect-worker.js         檔案分析的 Web Worker 版本（importScripts 載入判定邏輯）
    ├── preview.js               縮圖與燈箱（圖片/影片/音訊/PDF 預覽）
    ├── compare.js               差異比對模式（選兩個檔案並排看位元組差異，範圍可調）
    ├── reference-table.js       頁面下方「常見檔案簽章對照表」的資料與渲染
    └── app.js                   狀態管理、掃描流程、Worker 池、表格渲染、事件綁定（主程式）
```

所有 JS 檔案都用傳統的 `<script src="...">` 依序載入，**沒有用模組系統（ES Module / CommonJS）**，也沒有 Webpack、Vite 這類建置工具。每個檔案的頂層函式/變數會掛在全域（`window`）上，後面載入的檔案可以直接使用前面檔案定義好的東西。載入順序寫在 `index.html` 底部，若新增檔案要注意順序：

```
utils.js → i18n.js → sha256.js → signatures.js → detectors.js → preview.js → compare.js → reference-table.js → app.js

（`sha256-worker.js` 與 `detect-worker.js` 不透過 `<script>` 載入，是被對應的 Worker 用 `importScripts()` 動態載入的，跟上面這條主執行緒的載入順序是分開的兩件事。）
```

這個順序背後的原則很單純：**先定義資料與工具，再定義用到它們的邏輯，最後才是把畫面組起來的主程式**。`i18n.js` 排在很前面，因為 `detectors.js` 的風險說明文字、`app.js` 的畫面文字都要呼叫它提供的 `t()` 函式。

## 想要修改功能，該改哪個檔案？

| 我想要… | 去改這個檔案 |
|---|---|
| 新增一種可辨識的檔案格式（開頭位元組固定的那種） | `js/signatures.js` 的 `SIGS` 陣列加一筆 |
| 新增一種需要額外邏輯才能判斷的格式（像 ZIP 系列、CFB 系列） | `js/detectors.js` |
| 讓某個格式可以在畫面上預覽 | `js/signatures.js` 的 `MEDIA_PREVIEW`（純圖片/影片/音訊/PDF 之外的新種類要動 `js/preview.js`） |
| 調整「常見檔案簽章對照表」顯示的內容 | `js/reference-table.js` 的 `REF` 陣列（記得對應的翻譯鍵要加到 `js/i18n.js`） |
| 調整風險判定的文字說明或新增風險項目 | `js/detectors.js` 的 `filenameRisks()` / `contentRisks()`，文字本身寫在 `js/i18n.js` 的 `risk.*` 鍵 |
| 調整表格欄位、排序、篩選、匯出格式 | `js/app.js` |
| 調整外觀、深色/淺色配色、手機版排版、動畫效果 | `css/styles.css`（檔案開頭有分節索引） |
| 調整頁面文案、頁尾參考連結 | `index.html`（文案本身透過 `data-i18n` 屬性指向 `js/i18n.js`） |
| 新增或修改語言、翻譯字串 | `js/i18n.js`（詳見下方「多語系」） |
| 調整差異比對的比較範圍或畫面 | `js/compare.js` |
| 調整自訂簽章的驗證規則、匯出入格式 | `js/signatures.js` 的 `validateCustomSig()` / `exportCustomSigsJson()` / `importCustomSigsJson()` |
| 調整 JSON 匯出的欄位 | `js/app.js` 的 `exportJson()` |
| 新增一種可辨識的格式，且要能在 Worker 裡跑 | 只要改 `js/detectors.js`／`js/signatures.js`，`analyzeFileCore()` 兩邊共用，不用另外處理 |
| 調整 Worker 池的大小、逾時時間 | `js/app.js` 的 `DETECT_POOL_SIZE`／`HASH_POOL_SIZE`／`*_TIMEOUT_MS` |
| 調整 PWA 快取的檔案清單 | `service-worker.js` 的 `CORE_ASSETS` |

## 多語系（i18n）

頁首的 🌐 按鈕可以在繁體中文／English／日本語之間循環切換。想加新語言或改文案：

- 所有翻譯字串都在 `js/i18n.js` 的 `I18N` 物件裡，照 `zh` / `en` / `ja` 分區塊，key 相同、value 是對應語言的字串。字串裡的 `{name}` 這種花括號變數，會在顯示當下被 `t('some.key', {name:'x.pdf'})` 換成實際值。
- `detectors.js`／`signatures.js` 內部用來判斷格式的字串（例如 `SIGS` 陣列裡的 `name` 欄位）**維持中文，不要改**——那些是給程式內部比對用的識別碼，跟畫面上顯示的文字是分開兩件事。畫面顯示時會透過 `formatName()` 查 `i18n.js` 的 `FORMAT_NAME_I18N` 表格轉換成目前語言；新增一種格式時，如果它的內部名稱不是英文，記得也在 `FORMAT_NAME_I18N` 補一筆對照，不然英文/日文介面會顯示中文。
- 新增一個會顯示給使用者看的字串時，養成習慣呼叫 `t('模組.用途')`，不要把文字直接寫死在程式碼裡——不然新功能就只有中文版，其他語言的使用者會看到介面中間突然冒出一句中文。
- **已知的命名陷阱**：因為全域翻譯函式叫 `t()`，寫程式時不要再用區域變數或函式參數叫 `t`（例如 `var t = someResult` 或 `function foo(t){...}`），會遮蔽掉全域的 `t()`，導致那個範圍內翻譯全部失效但不會報錯，很難察覺。這個專案裡已經修過幾個這樣的地方，新增程式碼時留意一下就好。
- 語言選擇存在 `localStorage`（只在使用者自己的瀏覽器裡，不會被上傳或蒐集），沒有選過的話會依瀏覽器語言（`navigator.language`）自動判斷 zh／ja，其餘一律預設英文。

## 開發與測試

改完 `js/detectors.js` 或 `js/signatures.js` 之後，不需要重新整個工具測一遍——打開 **`test.html`**，它會自動在瀏覽器裡當場產生一組測試用的二進位檔案（合成的 ZIP、CFB／OLE2、PDF、PNG 內容），跑過判定邏輯的核心案例並顯示 PASS/FAIL：

- CFB／OLE2 複合文件的目錄解析（`.doc` / `.xls` / `.ppt` / `.msi` / `.msg` 開頭完全相同，靠這個測試確保目錄解析沒有壞掉）
- OOXML 巨集感知（含 `vbaProject.bin` 的 `.docx` 是否正確被判定為「建議改用 .docm」）
- 附加資料／polyglot 偵測（PNG 後面接 ZIP、JPEG 結束標記後面還有資料）
- PDF 主動風險掃描（`/JavaScript`、`/Launch` 等關鍵物件）
- `signatures.js` 的簽章表與預覽對照是否完整
- SHA-256 純 JavaScript 實作是否符合 NIST 公開測試向量
- 執行檔簽章（PE／ELF／shebang／LNK／Mach-O），含「偽裝成文件應標高風險」與「副檔名正確不算高風險」兩種情境
- 檔名風險偵測（雙重副檔名、Unicode 文字方向控制字元、異常空白）
- 純文字啟發式判讀（SVG／HTML／JSON／PEM／登錄檔匯出，含「內嵌腳本應標高風險」情境）
- Big5／GBK 舊式雙位元組編碼、WebP／HEIC／AVIF、BMP／RIFF 標頭自述大小與實際不符

目前總計 54 項測試案例。

`test.html` 跟 `index.html` 一樣是純前端頁面，不需要 Node.js、不需要安裝任何東西，開啟就會自動執行一次；改完程式碼後重新整理這頁，比手動重新拖測試檔案進主頁面快很多。它只載入判定邏輯需要的四個檔案（`utils.js`／`sha256.js`／`signatures.js`／`detectors.js`），不會載入 `app.js` 或 `preview.js`，所以改動 UI 相關的程式碼不會影響這裡的測試結果——這是刻意的設計，讓「邏輯測試」跟「畫面」保持獨立。

如果你的開發環境有 Node.js，也可以把 `test.html` 裡 `buildFixtures()` / `buildTestGroups()` 那段程式碼配合 `utils.js`／`sha256.js`／`signatures.js`／`detectors.js` 一起餵進 Node 的 `vm` 模組執行（Node 18+ 內建 `File`/`Blob`/`crypto.subtle`，不需要額外套件）；這個專案開發過程中就是這樣做回歸測試的，只是沒有另外寫成一個固定的指令稿留在版本庫裡，因為 `test.html` 本身已經涵蓋了同一組案例。

## 鍵盤快速鍵

| 按鍵 | 作用 |
|---|---|
| <kbd>/</kbd> | 跳到搜尋框開始輸入 |
| <kbd>Esc</kbd> | 在搜尋框裡清空內容；已空則離開搜尋框 |
| <kbd>j</kbd> / <kbd>k</kbd> | 在結果列之間往下／往上移動焦點 |
| <kbd>r</kbd> | 把目前焦點所在的結果列標記為已檢查／取消 |
| <kbd>u</kbd> | 復原上一筆誤刪的結果（最多 20 筆） |
| <kbd>Enter</kbd> / <kbd>Space</kbd> | 展開／收合明細（焦點在結果列時） |
| <kbd>Tab</kbd> | 在按鈕、搜尋框、結果列、縮圖之間移動 |

快速鍵在輸入框與文字區域內不會作用，也不會覆蓋帶 Ctrl／Cmd／Alt 的瀏覽器原生快捷鍵。實作在 `js/app.js` 底部的全域 `keydown` 監聽器。

## 分次檢查大量檔案的工作流

掃描上百個檔案時，每一列右側的 ✓ 按鈕（或鍵盤 <kbd>r</kbd>）可以標記「這筆我看過了」，配合控制列的「隱藏已檢查」勾選，就能把工作分次做完而不會重複檢視。摘要列會顯示已檢查的進度。

摘要列的統計標籤同時也是篩選器：點「高風險 3」只顯示那三筆，再點一次取消。

## 大檔案的雜湊計算為什麼不會卡住畫面

SHA-256 優先丟給一個 Worker 池（`js/sha256-worker.js` 的多顆實例，數量依 CPU 核心數決定）平行計算，Worker 裡一樣是「WebCrypto 優先、純 JS 備援」。如果瀏覽器不允許建立 Worker（常見於用 `file://` 直接開啟頁面時，部分瀏覽器會限制），`sha256Async()`（`app.js`）會自動偵測並退回主執行緒計算；某一顆 Worker 意外崩潰時會自動補一顆新的頂上維持池子大小。「計算全部 SHA-256」用 `runWithConcurrency()` 限制同時進行的數量，真正平行分派給多顆 Worker，不是排隊等前一個算完才開始下一個。這幾層退回與並行邏輯測得最仔細（`worker_regress.js`／`pool_regress.js`），涵蓋六種失敗情境加上並行度限制。

## 自訂簽章

如果你的組織有自己的檔案格式，可以在頁面上的「自訂簽章」區塊加入名稱、副檔名與開頭 HEX，之後這份工具就能辨識它。設定存在 `localStorage`（key 為 `fsi-custom-sigs`）。跟「已檢查標記」不同，這裡存的是**你輸入的格式定義**，跟任何檔案內容都無關，所以預設就會記住，不需要另外開關。可以用「匯出」把設定存成 JSON 分享給同事，對方用「匯入」就能拿到一樣的設定——同名的簽章匯入時會跳過、不覆蓋既有設定。

新增／修改自訂簽章邏輯在 `js/signatures.js` 的 `validateCustomSig()` / `addCustomSig()` / `removeCustomSig()` / `exportCustomSigsJson()` / `importCustomSigsJson()`，混入判定流程的地方在 `js/detectors.js` 的 `resolveSignature()`（呼叫 `allSigsSorted()`）。因為檔案分析也會丟進 Worker 池執行，新增/移除自訂簽章時 `app.js` 會呼叫 `broadcastCustomSigsToWorkers()` 同步給所有 Worker——Worker 裡沒有 `localStorage`，不主動同步的話會讀不到使用者剛加的簽章。

## 差異比對模式

每列的「⇄」按鈕（或鍵盤 <kbd>c</kbd>）可以把該筆加入比較（最多兩筆），選滿後畫面下方會出現比較列，按下去開啟並排的位元組比較視窗，可以用下拉選單調整比對範圍（256 bytes～64 KB，定義在 `js/compare.js` 的 `COMPARE_CAP_OPTIONS`）。要確認兩個檔案內容是否完全一致，看 SHA-256 是否相同比逐位元組比對整個檔案快得多。

## 匯出格式

除了 CSV／TXT，也可以「匯出 JSON」拿到結構化資料串接其他工具。JSON 的欄位是穩定的英文 key（不會因為介面語言改變），格式名稱與判定結果同時提供語言中立版（`detectedFormat`）與目前語言的顯示版（`detectedFormatDisplay`）。

## PWA：把工具「安裝」起來

如果你是透過網頁伺服器提供這個工具（不是直接用 `file://` 開啟），瀏覽器會提示可以安裝成獨立視窗，離線也能從主畫面／應用程式清單開啟，不用每次都找到資料夾。**用 `file://` 直接開啟 `index.html` 不會有這個選項**——Service Worker 是瀏覽器規格明訂只能在安全情境（https:// 或 http://localhost）下註冊的功能，這是限制，不是這份工具沒做好。兩種用法都完整支援本工具的所有檢查功能，PWA 純粹是「安裝」這個額外選項。

修改快取的檔案清單在 `service-worker.js` 的 `CORE_ASSETS`；新增檔案時記得也要加進這個陣列，`pwa_regress.js`（開發用）有一個反向檢查會提醒你有沒有漏掉。

## 多執行緒：檔案分析與雜湊計算

檔案分析（讀位元組、解析 ZIP/CFB、跑風險判定）與 SHA-256 雜湊都會優先丟給背景執行緒的 Worker 池平行處理，池子大小依 `navigator.hardwareConcurrency` 決定（上限 4 顆）。任一顆 Worker 建立失敗、通訊失敗、逾時或意外崩潰，都會自動退回主執行緒直接運算，或補一顆新的 Worker 頂上——功能不會因為 Worker 出狀況而中斷，只是速度回到單執行緒的水準。

負責這件事的核心函式是 `detectors.js` 的 `analyzeFileCore()`（純邏輯，不含 id 或預覽 Blob 這些「執行環境相關」的欄位）與 `app.js` 的 `runAnalysisCore()` / `sha256Async()`（負責 Worker 池調度與失敗退回）。改動判定邏輯時只要改 `analyzeFileCore()` 本身，主執行緒與 Worker 兩條路徑會自動保持一致，不需要另外同步兩份程式碼。

## 隱私：唯一會在你裝置上留下紀錄的功能

預設情況下這個工具**什麼都不存**。唯一的例外是控制列裡的「記住已檢查標記」，勾選之後：

- 標記為已檢查時，會計算該檔案的 SHA-256 並存進瀏覽器的 `localStorage`（key 為 `fsi-reviewed`）。
- **只存雜湊值本身**，不存檔名、路徑、大小或任何其他中繼資料。用內容雜湊而非檔名當索引，好處是換名字、換資料夾的同一份檔案仍然認得出來，而且存下來的資料本身看不出原始檔名。
- 資料只在這台瀏覽器裡，不會上傳。隨時可以按「清除已存記錄」全部刪除。
- 這個選項**預設關閉**，需要自己勾選。勾選後畫面會出現一段說明提醒你狀態已改變。

另外「複製檢視連結」產生的 URL 只包含檢視條件（搜尋字串、篩選、排序、語言），**不含任何檔名或檔案內容**——檔案從來沒有離開瀏覽器，連結自然也帶不走它們。

## 無障礙（Accessibility）現況與已知限制

- 表格的每一列都可以用 <kbd>Tab</kbd> 移到、按 <kbd>Enter</kbd>／<kbd>空白鍵</kbd> 展開明細，等同滑鼠點擊；`aria-expanded` 會正確反映展開狀態。
- 縮圖（圖片/影片/音訊/PDF 的預覽觸發點）本身也能個別 <kbd>Tab</kbd> 到並用鍵盤觸發，會開啟燈箱。
- 燈箱是 `role="dialog"` + `aria-modal="true"`，開啟時焦點會移進去、<kbd>Tab</kbd> 在裡面循環、<kbd>Esc</kbd> 或按叉叉關閉後焦點會還給原本點擊的縮圖。
- 高風險警示橫幅是 `role="alert"`，複製成功等提示訊息（toast）是 `role="status"`，會被螢幕報讀器唸出來。
- **已知限制**：縮圖是放在「整列可展開」的 `role="button"` 列裡面的另一個獨立可聚焦元素，嚴格來說算是巢狀的可互動元素，不是教科書等級的 ARIA 寫法；主流螢幕報讀器普遍能正確處理這種「列表項目內有個別可點內容」的樣式，但如果你要往更嚴謹的方向做，可以考慮把整列的展開行為改成列內一個獨立的「展開」按鈕，而不是整個 `<tr>` 都是按鈕。

## 這個工具能證明什麼、不能證明什麼

簽章比對只讀取檔案開頭幾十個位元組（加上 ZIP／CFB 格式需要的目錄結構，以及尾端一小段用來抓附加資料）。它能有力地證明「這個檔案不是它宣稱的格式」，但**不能**證明檔案完整、未損毀，也不能證明檔案安全——一個副檔名相符的正常 `.docx` 一樣可能夾帶惡意巨集。頁面內的「這個工具能證明什麼、不能證明什麼」區塊有更完整的說明，改動判定邏輯時請一併檢查那段文字是否還準確。

## 隱私與離線

整個工具沒有引用任何 CDN、字型或外部程式庫，所有運算都在瀏覽器本機完成，檔案不會被上傳到任何地方。唯一會主動對外連線的地方，是明細面板裡「在 VirusTotal 查詢」的連結——而且只有使用者自己點擊才會連線。
