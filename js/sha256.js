/* =============================================================
   sha256.js — SHA-256 雜湊計算
   ---------------------------------------------------------------
   優先使用瀏覽器內建的 WebCrypto（crypto.subtle.digest），這是
   最快、最安全的做法。當環境不支援（極舊瀏覽器）或檔案太大導致
   一次性 arrayBuffer() 不划算時，退回下面這個純 JavaScript 的
   串流實作，逐塊讀取檔案，不需要把整個檔案一次載入記憶體。

   對照規格：FIPS PUB 180-4 (NIST)。
   已用 Node.js 的 crypto 模組跑過多組長度（含區塊邊界 55/56/63/
   64/65 bytes）與不對齊分塊輸入做過回歸測試，結果與標準函式庫一致。
   ============================================================= */

var SHA_K = [
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];

function Sha256(){
  this.H = new Int32Array([0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]);
  this.W = new Int32Array(64);
  this.buf = new Uint8Array(64);
  this.bufLen = 0;
  this.total = 0;
}
Sha256.prototype._block = function(d, p){
  var W = this.W, H = this.H, i, s0, s1, g0, g1;
  for(i=0;i<16;i++) W[i] = (d[p+i*4]<<24)|(d[p+i*4+1]<<16)|(d[p+i*4+2]<<8)|d[p+i*4+3];
  for(i=16;i<64;i++){
    g0 = W[i-15]; g1 = W[i-2];
    s0 = ((g0>>>7)|(g0<<25)) ^ ((g0>>>18)|(g0<<14)) ^ (g0>>>3);
    s1 = ((g1>>>17)|(g1<<15)) ^ ((g1>>>19)|(g1<<13)) ^ (g1>>>10);
    W[i] = (W[i-16] + s0 + W[i-7] + s1) | 0;
  }
  var a=H[0],b=H[1],c=H[2],dd=H[3],e=H[4],f=H[5],g=H[6],h=H[7],S0,S1,ch,maj,t1,t2;
  for(i=0;i<64;i++){
    S1 = ((e>>>6)|(e<<26)) ^ ((e>>>11)|(e<<21)) ^ ((e>>>25)|(e<<7));
    ch = (e & f) ^ (~e & g);
    t1 = (h + S1 + ch + SHA_K[i] + W[i]) | 0;
    S0 = ((a>>>2)|(a<<30)) ^ ((a>>>13)|(a<<19)) ^ ((a>>>22)|(a<<10));
    maj = (a & b) ^ (a & c) ^ (b & c);
    t2 = (S0 + maj) | 0;
    h=g; g=f; f=e; e=(dd+t1)|0; dd=c; c=b; b=a; a=(t1+t2)|0;
  }
  H[0]=(H[0]+a)|0; H[1]=(H[1]+b)|0; H[2]=(H[2]+c)|0; H[3]=(H[3]+dd)|0;
  H[4]=(H[4]+e)|0; H[5]=(H[5]+f)|0; H[6]=(H[6]+g)|0; H[7]=(H[7]+h)|0;
};
Sha256.prototype.update = function(bytes){
  var i = 0, n = bytes.length;
  this.total += n;
  if(this.bufLen){
    while(i < n && this.bufLen < 64) this.buf[this.bufLen++] = bytes[i++];
    if(this.bufLen === 64){ this._block(this.buf, 0); this.bufLen = 0; }
  }
  while(i + 64 <= n){ this._block(bytes, i); i += 64; }
  while(i < n) this.buf[this.bufLen++] = bytes[i++];
};
Sha256.prototype.hex = function(){
  var bitLenHi = Math.floor(this.total / 0x20000000);
  var bitLenLo = (this.total << 3) >>> 0;
  var pad = new Uint8Array(this.bufLen < 56 ? 64 : 128);
  pad.set(this.buf.subarray(0, this.bufLen));
  pad[this.bufLen] = 0x80;
  var L = pad.length;
  pad[L-8] = (bitLenHi >>> 24) & 0xff; pad[L-7] = (bitLenHi >>> 16) & 0xff;
  pad[L-6] = (bitLenHi >>> 8) & 0xff;  pad[L-5] = bitLenHi & 0xff;
  pad[L-4] = (bitLenLo >>> 24) & 0xff; pad[L-3] = (bitLenLo >>> 16) & 0xff;
  pad[L-2] = (bitLenLo >>> 8) & 0xff;  pad[L-1] = bitLenLo & 0xff;
  for(var p = 0; p < L; p += 64) this._block(pad, p);
  var out = '';
  for(var i=0;i<8;i++) out += (this.H[i] >>> 0).toString(16).padStart(8,'0');
  return out;
};

var HASH_CHUNK = 4 * 1024 * 1024;
async function sha256File(file, onProgress){
  var canSubtle = (typeof crypto !== 'undefined') && crypto.subtle && typeof crypto.subtle.digest === 'function';
  if(canSubtle && file.size <= 96 * 1024 * 1024){
    try{
      var buf = await file.arrayBuffer();
      var d = await crypto.subtle.digest('SHA-256', buf);
      var arr = new Uint8Array(d), s = '';
      for(var i=0;i<arr.length;i++) s += arr[i].toString(16).padStart(2,'0');
      return s;
    }catch(e){ /* 落到純 JS */ }
  }
  var h = new Sha256(), off = 0;
  while(off < file.size){
    var end = Math.min(off + HASH_CHUNK, file.size);
    var chunk = new Uint8Array(await file.slice(off, end).arrayBuffer());
    h.update(chunk);
    off = end;
    if(onProgress) onProgress(off / file.size);
    await new Promise(function(r){ setTimeout(r, 0); });
  }
  return h.hex();
}
