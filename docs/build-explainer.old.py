import os
import random
random.seed(11)
WORDS="ladder voice ripple cabin mango frost olive tiger paddle winter zebra lemon quiet beach eagle fabric garden honey island jacket kitten marble noble orbit pencil rabbit saddle tunnel velvet walnut yellow anchor bridge candle dragon ember falcon glove hammer ivory jungle kernel lantern meadow needle oyster pepper quartz river silver thunder umbrella violin wagon arrow basket cherry desert engine forest ginger harbor insect jewel knife ladder".split()
def code(): return random.choice(WORDS)
def T(x,y,en,zh,a=""):
    return f'<text class="en" x="{x}" y="{y}" {a}>{en}</text><text class="zh" x="{x}" y="{y}" {a}>{zh}</text>'
def S(en,zh): return f'<span class="en">{en}</span><span class="zh">{zh}</span>'
AR='<defs><marker id="%s" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" fill="%s"/></marker></defs>'
def box(x,y,w,h,fill="var(--panel)",stroke="currentColor",sw="1",extra=""):
    return f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="4" fill="{fill}" stroke="{stroke}" stroke-width="{sw}" {extra}/>'
def arrow(x1,y1,x2,y2,col="currentColor",m="ar"):
    return f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{col}" stroke-width="1.5" marker-end="url(#{m})"/>'

# ---------- Figure 0: how a payment travels ----------
FIG0=f'''<svg role="img" aria-label="A payment travels from a book printed in two parts, through a pen that copies 18 boxes, to any untrusted computer, to the chain, which checks hashes only" viewBox="0 0 780 200" xmlns="http://www.w3.org/2000/svg" font-family="var(--sans)" font-size="12">
{AR%("ar","currentColor")}
{box(20,50,130,60,"var(--secret-soft)","var(--secret)","1.5")}{T(85,74,"One book, two parts","一本簿子，兩部分",'text-anchor="middle" font-weight="600" fill="var(--secret)"')}{T(85,92,"printed, kept apart","印好，分開保存",'text-anchor="middle" fill="var(--secret)" font-size="11"')}
{arrow(152,80,178,80)}
{box(180,50,140,60)}{T(250,74,"A pen","一支筆",'text-anchor="middle" font-weight="600"')}{T(250,92,"copies 18 boxes, no device","抄 18 格，不用裝置",'text-anchor="middle" fill="var(--muted)" font-size="11"')}
{arrow(322,80,348,80)}
{box(350,50,150,60)}{T(425,74,"Any computer","任何電腦",'text-anchor="middle" font-weight="600"')}{T(425,92,"untrusted, only broadcasts","不需信任，只負責廣播",'text-anchor="middle" fill="var(--muted)" font-size="11"')}
{arrow(502,80,538,80)}
{box(540,36,220,88,"var(--public-soft)","var(--public)","1.5")}
{T(650,60,"The chain","區塊鏈",'text-anchor="middle" font-weight="600" fill="var(--public)"')}
{T(650,78,"checks hashes only","只驗證雜湊值",'text-anchor="middle" fill="var(--public)" font-size="11"')}
{T(650,94,"no elliptic curves anywhere","完全沒有橢圓曲線",'text-anchor="middle" fill="var(--public)" font-size="11"')}
{T(650,110,"nothing off-chain to remember","鏈下不需要記住任何狀態",'text-anchor="middle" fill="var(--public)" font-size="11"')}
{T(20,150,"Every account on the chain is a cheque book. Miners and exchanges drive theirs by software with the same cheque format; people drive theirs with a pen.","鏈上每個帳戶都是支票簿。礦工和交易所用軟體操作同樣格式的支票；一般人用筆。",'font-size="11" fill="var(--muted)"')}
{T(20,172,"Security rests on SHA-256 alone. Quantum computers halve the exponent, from 2^128 to 2^64 sequential steps, which is the level NIST accepts.","安全性只依賴 SHA-256。量子電腦只能把指數減半（2^128 → 2^64 個循序步驟），這是 NIST 接受的安全等級。",'font-size="11" fill="var(--muted)"')}
</svg>'''

# ---------- Figure 1: who holds what ----------
FIG1=f'''<svg role="img" aria-label="Device A prints Book A and publishes hashes of A; Device B prints Book B and publishes hashes of B; the two books together are the private key; the chain holds the account root built from both hash lists" viewBox="0 0 780 300" xmlns="http://www.w3.org/2000/svg" font-family="var(--sans)" font-size="12">
{AR%("arp","var(--public)")}{AR%("ars","var(--secret)")}
{box(20,40,190,54)}
{T(115,62,"Device A + printer A","裝置 A + 印表機 A",'text-anchor="middle" font-weight="600"')}
{T(115,80,"your phone, home printer","你的手機、家中印表機",'text-anchor="middle" fill="var(--muted)"')}
{box(20,206,190,54)}
{T(115,228,"Device B + printer B","裝置 B + 印表機 B",'text-anchor="middle" font-weight="600"')}
{T(115,246,"library PC, its printer","圖書館電腦及其印表機",'text-anchor="middle" fill="var(--muted)"')}
{box(320,40,150,54,"var(--secret-soft)","var(--secret)","1.5")}
{T(395,62,"Book A","簿子 A",'text-anchor="middle" font-weight="600" fill="var(--secret)"')}
{T(395,80,"left half of every cell","每格的左半",'text-anchor="middle" fill="var(--secret)"')}
{box(320,206,150,54,"var(--secret-soft)","var(--secret)","1.5")}
{T(395,228,"Book B","簿子 B",'text-anchor="middle" font-weight="600" fill="var(--secret)"')}
{T(395,246,"right half of every cell","每格的右半",'text-anchor="middle" fill="var(--secret)"')}
<path d="M480 50 H496 V250 H480" fill="none" stroke="var(--secret)" stroke-width="1.5"/>
{T(506,146,"both books together","兩本合起來",'fill="var(--secret)" font-weight="600"')}
{T(506,162,"= your private key","= 你的私鑰",'fill="var(--secret)"')}
{box(600,100,160,100,"var(--public-soft)","var(--public)","1.5")}
{T(680,124,"The chain","區塊鏈",'text-anchor="middle" font-weight="600" fill="var(--public)"')}
{T(680,144,"hash of every A half","每個 A 半段的雜湊值",'text-anchor="middle" fill="var(--public)"')}
{T(680,160,"hash of every B half","每個 B 半段的雜湊值",'text-anchor="middle" fill="var(--public)"')}
{T(680,182,"→ account id (root)","→ 帳戶 ID（根雜湊）",'text-anchor="middle" fill="var(--public)" font-weight="600"')}
{arrow(212,67,318,67,"var(--secret)","ars")}
{T(265,60,"prints","印出",'text-anchor="middle" fill="var(--secret)" font-size="11"')}
{arrow(212,233,318,233,"var(--secret)","ars")}
{T(265,226,"prints","印出",'text-anchor="middle" fill="var(--secret)" font-size="11"')}
<path d="M212 85 C 420 110, 480 130, 598 140" fill="none" stroke="var(--public)" stroke-width="1.5" marker-end="url(#arp)"/>
{T(290,112,"publishes hashes only","只公開雜湊值",'fill="var(--public)" font-size="11"')}
<path d="M212 215 C 420 190, 480 170, 598 160" fill="none" stroke="var(--public)" stroke-width="1.5" marker-end="url(#arp)"/>
{T(290,200,"publishes hashes only","只公開雜湊值",'fill="var(--public)" font-size="11"')}
{T(20,288,"A leak of A, its printer and its screen gives an attacker half of every cell. Forging still needs the other half: a 128-bit search per cell.","即使 A、它的印表機和螢幕全部外洩，攻擊者也只拿到每格的一半。偽造仍需另一半：每格要猜 2^128 次。",'fill="var(--muted)" font-size="11"')}
</svg>'''

# ---------- Figure 2: seed to book ----------
FIG2=f'''<svg role="img" aria-label="One seed on an offline computer derives all eleven cheques, printed once in two parts; the hashes of every cell go to the chain in a single registration" viewBox="0 0 780 250" xmlns="http://www.w3.org/2000/svg" font-family="var(--sans)" font-size="12">
{AR%("ar4","currentColor")}{AR%("arp4","var(--public)")}{AR%("ars4","var(--secret)")}
{box(20,60,120,60,"var(--secret-soft)","var(--secret)","1.5")}
{T(80,84,"Your seed","種子 A",'text-anchor="middle" font-weight="600" fill="var(--secret)"')}
{T(80,102,"24 words, on paper","24 個字，寫在紙上",'text-anchor="middle" fill="var(--secret)" font-size="11"')}
{arrow(142,90,168,90)}
{box(170,60,170,60)}
{T(255,84,"Device A, once","裝置 A，一次",'text-anchor="middle" font-weight="600"')}
{T(255,102,"key№ = hash(seed, №); cell = hash(key№, col, row)","支票金鑰 = hash(種子, 號碼)；格子 = hash(金鑰, 欄, 列)",'text-anchor="middle" font-size="9" fill="var(--muted)"')}
{arrow(342,80,378,80,"var(--secret)","ars4")}
{box(380,50,170,60,"var(--secret-soft)","var(--secret)","1.5")}
{T(465,72,"Book · parts A + B","簿子 · A + B 部分",'text-anchor="middle" font-weight="600" fill="var(--secret)"')}
{T(465,88,"cheques 0–10, 11 pages","第 0–10 號，11 頁",'text-anchor="middle" fill="var(--secret)" font-size="11"')}
{T(465,102,"printed once, never again","只印一次，不再印",'text-anchor="middle" fill="var(--secret)" font-size="10"')}
<path d="M255 122 V 180 H 598" fill="none" stroke="var(--public)" stroke-width="1.5" marker-end="url(#arp4)"/>
{T(270,172,"hashes of every cell of all 11 cheques","11 張支票所有格子的雜湊值",'fill="var(--public)" font-size="11"')}
{box(600,150,160,60,"var(--public-soft)","var(--public)","1.5")}
{T(680,172,"The chain","區塊鏈",'text-anchor="middle" font-weight="600" fill="var(--public)"')}
{T(680,190,"one registration, whole book","一次登記整本",'text-anchor="middle" fill="var(--public)" font-size="11"')}
{T(20,22,"Printed as two separate runs, part A then part B, on the same offline computer. The seed is never typed again unless the book is lost.","在同一台離線電腦上分兩次列印：先 A 部分，再 B 部分。除非簿子遺失，種子不會再輸入第二次。",'font-size="11" fill="var(--muted)"')}
{T(20,236,"Cheque 0 is the honesty check. Cheques 1–10 are your ten moves. Cheque 10 can sweep everything to a new book.","第 0 號用於誠實檢查。第 1–10 號是你的十次轉移。第 10 號可以把全部餘額轉到新簿子。",'font-size="11" fill="var(--muted)"')}
</svg>'''

# ---------- Figure 3: one cheque grid ----------
digits="000000482135"+"1500"+"5"+"2"
cols=["P%d"%(i+1) for i in range(12)]+["D1","D2","D3","D4","E","F"]
CW=52; RH=16; X0=40; Y0=86
W=X0+18*CW+10; H=Y0+10*RH+76+118
s=[f'<svg role="img" aria-label="One cheque: 18 columns of 10 rows; the 18 cells matching the payee number and amount are the signature" viewBox="0 0 {W} {H}" xmlns="http://www.w3.org/2000/svg" font-family="var(--mono)" font-size="9">']
s.append(T(X0,22,"CHEQUE No. 7","支票 第 7 號",'font-family="var(--sans)" font-size="13" font-weight="600"'))
s.append(T(X0+18*CW,22,'pay account <tspan font-weight="600">00000048213-5</tspan>  amount <tspan font-weight="600">1500</tspan> ×10^<tspan font-weight="600">5</tspan>  fee tier <tspan font-weight="600">2</tspan>',
                       '付給帳號 <tspan font-weight="600">00000048213-5</tspan>  金額 <tspan font-weight="600">1500</tspan> ×10^<tspan font-weight="600">5</tspan>  手續費等級 <tspan font-weight="600">2</tspan>',
                       'font-family="var(--sans)" font-size="12" text-anchor="end"'))
s.append(T(X0+6*CW,46,"payee account number (11 digits + check digit)","收款帳號（11 位數字 + 1 位檢查碼）",'font-family="var(--sans)" font-size="11" text-anchor="middle" fill="var(--muted)"'))
s.append(T(X0+14*CW,46,"amount digits","金額數字",'font-family="var(--sans)" font-size="11" text-anchor="middle" fill="var(--muted)"'))
s.append(T(X0+17*CW,46,"exp  fee","指數 手續費",'font-family="var(--sans)" font-size="11" text-anchor="middle" fill="var(--muted)"'))
for (c0,c1) in [(0,12),(12,16),(16,18)]:
    s.append(f'<line x1="{X0+c0*CW}" y1="52" x2="{X0+c1*CW-4}" y2="52" stroke="var(--muted)"/>')
for ci,cn in enumerate(cols):
    x=X0+ci*CW
    if ci==11:
        s.append(f'<rect x="{x-3}" y="{Y0-22}" width="{CW+3}" height="{10*RH+24}" rx="3" fill="none" stroke="var(--accent)" stroke-width="1.5" stroke-dasharray="4 3"/>')
        s.append(f'<text x="{x+CW/2}" y="{Y0-8}" text-anchor="middle" font-family="var(--sans)" font-size="10" font-weight="700" fill="var(--accent)">{cn} ✓</text>')
    else:
        s.append(f'<text x="{x+CW/2}" y="{Y0-8}" text-anchor="middle" font-family="var(--sans)" font-size="10" fill="var(--muted)">{cn}</text>')
    for ri in range(10):
        y=Y0+ri*RH
        if digits[ci]==str(ri):
            s.append(f'<rect x="{x}" y="{y}" width="{CW-3}" height="{RH-2}" fill="var(--secret-soft)" stroke="var(--secret)" stroke-width="1.2"/>')
            s.append(f'<text x="{x+4}" y="{y+11}" fill="var(--secret)" font-weight="700">{code()[:4]}…</text>')
        else:
            s.append(f'<rect x="{x}" y="{y}" width="{CW-3}" height="{RH-2}" fill="none" stroke="var(--line)" stroke-width="0.7"/>')
            s.append(f'<text x="{x+4}" y="{y+11}" fill="var(--muted)">{code()[:4]}…</text>')
for ri in range(10):
    s.append(f'<text x="{X0-10}" y="{Y0+ri*RH+11}" text-anchor="end" font-family="var(--sans)" font-size="10" fill="var(--muted)">{ri}</text>')
s.append(T(X0,H-46,'<tspan fill="var(--accent)" font-weight="700">P12 ✓ is the check digit.</tspan> It is computed from P1–P11 with a public table (0 0 0 0 0 0 4 8 2 1 3 → 5). Nodes recompute it: if any payee digit was copied wrong,',
                   '<tspan fill="var(--accent)" font-weight="700">P12 ✓ 是檢查碼。</tspan>它由 P1–P11 用一張公開的表算出（0 0 0 0 0 0 4 8 2 1 3 → 5）。節點會重新計算：只要收款帳號任何一位抄錯，',
                   'font-family="var(--sans)" font-size="11"'))
s.append(T(X0,H-32,'the cheque is rejected instead of paying a stranger. It protects the payee digits only; the amount is checked by eye on the broadcasting screen.',
                   '支票就會被拒絕，而不是付給陌生人。它只保護收款帳號的數字；金額則在廣播電腦的螢幕上用眼睛核對。',
                   'font-family="var(--sans)" font-size="11"'))
# callout: one signed cell enlarged, showing all 12 of its words
_cx=X0+11*CW; _cy=Y0+5*RH
_bx=X0; _by=Y0+10*RH+16; _bw=18*CW-10; _bh=86
s.append(f'<line x1="{_cx+CW/2-1.5}" y1="{_cy+RH-2}" x2="{_cx+CW/2-1.5}" y2="{_by}" stroke="var(--secret)" stroke-width="1.2" stroke-dasharray="3 2"/>')
s.append(f'<rect x="{_bx}" y="{_by}" width="{_bw}" height="{_bh}" rx="8" fill="var(--secret-soft)" stroke="var(--secret)" stroke-width="1.2"/>')
s.append(T(_bx+14,_by+20,'One cell, enlarged: P12, row 5. A cell is not one word: it is <tspan font-weight="700">12 words</tspan> (128 random bits). You copy all 12.',
                         '放大其中一格：P12 第 5 列。一格不是一個字，而是 <tspan font-weight="700">12 個字</tspan>（128 個隨機位元），12 個都要抄。',
                         'font-family="var(--sans)" font-size="11.5" fill="var(--secret)"'))
_w12=["unfold","ripple","cabin","harbor","ginger","meadow","cobalt","falcon","ribbon","tunnel","sketch","delta"]
for i,w in enumerate(_w12):
    _x=_bx+14+(i%6)*((_bw-28)/6); _y=_by+44+(i//6)*22
    s.append(f'<text x="{_x}" y="{_y}" font-family="var(--mono)" font-size="12" fill="var(--secret)"><tspan font-size="9" fill="var(--muted)">{i+1:>2} </tspan><tspan font-weight="700">{w[:4]}</tspan>{w[4:]}</text>')
s.append(T(X0,H-14,'Each cell is a secret of 12 ordinary words (first four letters of the first word shown). <tspan fill="var(--secret)" font-weight="600">Red cells</tspan> = the 18 you copy. Every cell\'s hash is already on the chain; the words themselves exist only on this paper.',
                   '每格是 12 個普通單字組成的秘密（圖中只顯示第一個字的前四個字母）。<tspan fill="var(--secret)" font-weight="600">紅色格子</tspan> = 你要抄的 18 格。每格的雜湊值早已在鏈上，單字本身只存在這張紙上。',
                   'font-family="var(--sans)" font-size="11"'))
s.append('</svg>')
FIG3="\n".join(s)

# ---------- Figure 4: signing & checking ----------
tabs=[("P1·0","ladder voice"),("P2·0","mango frost"),("P3·0","olive tiger"),("P4·0","paddle winter"),("P5·4","quiet beach")]
tabsvg="".join(f'<rect x="{20+i*6}" y="{44+i*18}" width="150" height="16" fill="var(--secret-soft)" stroke="var(--secret)"/><text x="{26+i*6}" y="{56+i*18}" fill="var(--secret)">{a}  {b}…</text>' for i,(a,b) in enumerate(tabs))
FIG4=f'''<svg role="img" aria-label="Eighteen torn tabs go to any computer, which broadcasts them; the chain hashes each tab, checks the cheque number and the check digit, and pays; a computer wanting to change the payee would need a cell that was never revealed" viewBox="0 0 780 330" xmlns="http://www.w3.org/2000/svg" font-family="var(--sans)" font-size="12">
{AR%("ar2","currentColor")}
<g font-family="var(--mono)" font-size="9">{tabsvg}</g>
{T(60,146,"… 13 more tabs","…還有 13 張",'fill="var(--secret)" font-size="11"')}
{T(20,30,"18 torn-off cells","撕下的 18 格",'font-weight="600"')}
{box(270,40,170,110)}
{T(355,64,"Any computer","任何電腦",'text-anchor="middle" font-weight="600"')}
{T(355,84,"untrusted is fine","不可信也沒關係",'text-anchor="middle" fill="var(--muted)"')}
{T(355,106,"reads the 18 cells","讀取 18 格",'text-anchor="middle"')}
{T(355,124,"sends them to the network","送到網路上",'text-anchor="middle"')}
{arrow(200,95,268,95,"var(--accent)","ar2")}
{T(234,86,"photo / type","拍照／輸入",'text-anchor="middle" fill="var(--accent)" font-size="11"')}
{box(520,30,240,140,"var(--public-soft)","var(--public)","1.5")}
{T(640,54,"Every node","每個節點",'text-anchor="middle" font-weight="600" fill="var(--public)"')}
{T(532,76,"for each of the 18 codes:","對 18 個碼逐一檢查：",'fill="var(--public)"')}
<text x="548" y="94" fill="var(--public)" font-family="var(--mono)" font-size="11">hash(12 words) == published hash?</text>
{T(532,114,"cheque No. 7 &gt; last used No.?","支票號 7 &gt; 上次用過的號碼？",'fill="var(--public)"')}
{T(532,132,"payee check digit correct?","收款帳號檢查碼正確？",'fill="var(--public)"')}
{T(532,156,"all yes → pay 00000048213-5 1.5 coins","全部通過 → 付 1.5 幣給 00000048213-5",'fill="var(--public)" font-weight="600"')}
{arrow(442,95,518,95,"var(--accent)","ar2")}
{T(480,86,"broadcast","廣播",'text-anchor="middle" fill="var(--accent)" font-size="11"')}
<line x1="20" y1="190" x2="760" y2="190" stroke="var(--line)"/>
{T(20,214,"What if the computer tries to pay itself instead?","如果電腦想改成付給自己呢？",'font-weight="600"')}
<rect x="20" y="232" width="150" height="16" fill="none" stroke="var(--line)" stroke-dasharray="3 2"/>
<text x="26" y="244" fill="var(--muted)" font-family="var(--mono)" font-size="9">P12·3  ????? ?????…</text>
{T(180,244,"it needs a different digit in a payee column, e.g. row 3 of P12 — never revealed, still only on your paper","它需要收款帳號某一欄的另一列，例如 P12 的第 3 列，這格從未公開，仍只在你的紙上",'font-size="11"')}
{T(180,262,'guessing one from its hash: 2<tspan font-size="8" dy="-5">128</tspan><tspan dy="5"> tries. Changing the amount needs other digit cells. Same wall.</tspan>','從雜湊值反推一格：要試 2<tspan font-size="8" dy="-5">128</tspan><tspan dy="5"> 次。改金額也需要其他數字格，同樣的牆。</tspan>','font-size="11"')}
{T(180,290,"The only thing it can do with your 18 codes is send exactly the payment you wrote, or refuse to send it.","拿著你這 18 個碼，它只能照你寫的付款送出，或拒絕送出。",'font-size="11" fill="var(--muted)"')}
</svg>'''

# ---------- Figure 5: cheque numbers ----------
def cb(x,n,fill,stroke,lab_en,lab_zh,extra="",tcol="var(--muted)",bold=""):
    o=f'<rect x="{x}" y="40" width="48" height="52" rx="3" fill="{fill}" stroke="{stroke}" {extra}/><text x="{x+24}" y="60" text-anchor="middle" fill="{tcol}" {bold}>{n}</text>'
    if lab_en: o+=T(x+24,78,lab_en,lab_zh,f'text-anchor="middle" font-size="9" fill="{tcol}"')
    return o
FIG5=f'''<svg role="img" aria-label="Eleven cheques numbered 0 to 10: 0 was the zero-coin honesty check, 1 to 3 are spent, 4 was lost and skipped, 5 is next, 6 to 10 are unused" viewBox="0 0 780 150" xmlns="http://www.w3.org/2000/svg" font-family="var(--sans)" font-size="12">
{cb(20,0,"var(--public-soft)","var(--public)","check","檢查",tcol="var(--public)",bold='font-weight="600"')}
{cb(86,1,"var(--line)","var(--muted)","spent","已用")}{cb(152,2,"var(--line)","var(--muted)","spent","已用")}{cb(218,3,"var(--line)","var(--muted)","spent","已用")}
{cb(284,4,"none","var(--muted)","lost","遺失",extra='stroke-dasharray="3 2"')}
{cb(350,5,"var(--accent-soft)","var(--accent)","next","下一張",extra='stroke-width="2"',tcol="var(--accent)",bold='font-weight="600"')}
{"".join(cb(416+i*66,6+i,"var(--panel)","var(--line)","","") for i in range(5))}
{T(706,78,"= sweep","= 轉走全部",'text-anchor="middle" font-size="9" fill="var(--muted)"')}
<line x1="20" y1="104" x2="332" y2="104" stroke="currentColor"/>
{T(176,122,"chain says last used = 3 → all of these are dead","鏈上記錄最後用到 3 → 這些全部失效",'text-anchor="middle" font-size="11"')}
<line x1="350" y1="104" x2="730" y2="104" stroke="currentColor"/>
{T(540,122,"any of these is valid once; gaps are fine","這些各可用一次，跳號沒關係",'text-anchor="middle" font-size="11"')}
{T(20,22,"A number is used up the moment any part of it is public. A written cheque you never sent is a live payment to that number only; to cancel it, confirm any higher number.","只要支票的任何部分被公開，該號碼就算用掉。寫好卻沒送出的支票仍是一張只能付給該帳號的有效付款；要作廢它，確認任何更大號碼即可。",'font-size="11" fill="var(--muted)"')}
</svg>'''

# ---------- Figure 6: piecewise ----------
FIG6=f'''<svg role="img" aria-label="Pieces of one cheque arrive from a phone at home, a library PC and a friend by text message; the chain fills the columns in order of arrival, payee first, and pays when all 18 are in" viewBox="0 0 780 300" xmlns="http://www.w3.org/2000/svg" font-family="var(--sans)" font-size="12">
{AR%("ar6","var(--accent)")}
{box(20,30,170,54)}{T(105,52,"Phone at home","家裡的手機",'text-anchor="middle" font-weight="600"')}{T(105,70,"columns P1–P6, Monday","P1–P6 欄，星期一",'text-anchor="middle" fill="var(--muted)" font-size="11"')}
{box(20,110,170,54)}{T(105,132,"Library PC","圖書館電腦",'text-anchor="middle" font-weight="600"')}{T(105,150,"columns P7–P12, Tuesday","P7–P12 欄，星期二",'text-anchor="middle" fill="var(--muted)" font-size="11"')}
{box(20,190,170,54)}{T(105,212,"A friend, by text message","朋友，用簡訊",'text-anchor="middle" font-weight="600"')}{T(105,230,"columns D1–F, Wednesday","D1–F 欄，星期三",'text-anchor="middle" fill="var(--muted)" font-size="11"')}
<path d="M192 57 C 300 57, 330 120, 418 120" fill="none" stroke="var(--accent)" stroke-width="1.5" marker-end="url(#ar6)"/>
<path d="M192 137 L 418 137" fill="none" stroke="var(--accent)" stroke-width="1.5" marker-end="url(#ar6)"/>
<path d="M192 217 C 300 217, 330 154, 418 154" fill="none" stroke="var(--accent)" stroke-width="1.5" marker-end="url(#ar6)"/>
{box(420,40,340,200,"var(--public-soft)","var(--public)","1.5")}
{T(590,66,"The chain, account 00000048213-5, cheque 7","區塊鏈：帳戶 00000048213-5，第 7 號支票",'text-anchor="middle" font-weight="600" fill="var(--public)"')}
<g font-family="var(--mono)" font-size="10" fill="var(--public)">
<text x="436" y="96">P1 P2 P3 P4 P5 P6  P7 P8 P9 P10 P11 P12  D1 D2 D3 D4 E F</text>
<text x="436" y="114"> 0  0  0  0  0  0   4  8  2  1   3   5    1  5  0  0 5 2</text>
</g>
<rect x="432" y="100" width="92" height="18" rx="2" fill="none" stroke="var(--public)" stroke-width="1"/>
<rect x="544" y="100" width="100" height="18" rx="2" fill="none" stroke="var(--public)" stroke-width="1"/>
<rect x="662" y="100" width="92" height="18" rx="2" fill="none" stroke="var(--public)" stroke-width="1"/>
{T(478,134,"Mon","一",'text-anchor="middle" fill="var(--public)" font-size="10"')}{T(594,134,"Tue","二",'text-anchor="middle" fill="var(--public)" font-size="10"')}{T(708,134,"Wed","三",'text-anchor="middle" fill="var(--public)" font-size="10"')}
{T(436,162,"first piece: number 7 is consumed, nonce = 7","第一塊到達：第 7 號即用掉，nonce = 7",'fill="var(--public)" font-size="11"')}
{T(436,180,"each column locks on arrival and can never change","每欄一到達就鎖定，永遠不能改",'fill="var(--public)" font-size="11"')}
{T(436,198,"18 of 18 in → payment executes, fee charged","18 欄齊全 → 付款執行、扣手續費",'fill="var(--public)" font-size="11" font-weight="600"')}
{T(436,216,"unfinished after 1,000 blocks → pieces dropped, number stays used","1,000 個區塊內未完成 → 丟棄碎片，號碼仍算用掉",'fill="var(--public)" font-size="11"')}
{T(20,278,"Send the payee columns first. Then the payee is locked before anything else about the cheque is public.","先送收款帳號的欄位。這樣在支票其他部分公開之前，收款人就已鎖定。",'font-size="11" fill="var(--muted)"')}
</svg>'''

# ---------- Figure 7: life of a book ----------
steps=[("Print","印製","11 cheques, once,","11 張，一次印好，","on 2 or 3 domains","在 2 或 3 個環境","var(--secret-soft)","var(--secret)","var(--secret)"),
       ("Register","登記","the whole book,","整本簿子，","once","一次","var(--public-soft)","var(--public)","var(--public)"),
       ("Check","檢查","cheque 0, zero coins:","第 0 號支票付 0 幣：","proves honest printing","證明印製誠實","var(--panel)","currentColor","currentColor"),
       ("Receive","存入","coins arrive at the","幣送到這個","account number; hold","帳號；長期持有","var(--panel)","currentColor","currentColor"),
       ("Move","轉移","one cheque =","一張支票 =","one transfer, up to 10","一次轉移，最多 10 次","var(--accent-soft)","var(--accent)","var(--accent)"),
       ("New book","新簿子","cheque 10, amount 0000,","第 10 號，金額 0000、","exponent 9 = everything","指數 9 = 全部轉走","var(--panel)","currentColor","currentColor")]
sv=""
for i,(e,z,e1,z1,e2,z2,f,st,tc) in enumerate(steps):
    x=10+i*130
    sw="1.5" if i==4 else "1"
    sv+=box(x,40,112,64,f,st,sw)
    sv+=T(x+56,62,e,z,f'text-anchor="middle" font-weight="600" fill="{tc}"')
    sv+=T(x+56,80,e1,z1,f'text-anchor="middle" font-size="11" fill="{tc}"')
    sv+=T(x+56,94,e2,z2,f'text-anchor="middle" font-size="11" fill="{tc}"')
FIG7=f'''<svg role="img" aria-label="Six steps: print halves on two domains, register the book and each batch, honesty check with cheque 0, fund the account, spend one cheque per payment, sweep to a new book with the last cheque" viewBox="0 0 780 170" xmlns="http://www.w3.org/2000/svg" font-family="var(--sans)" font-size="12">
{AR%("ar3","currentColor")}
{sv}
<g stroke="currentColor" stroke-width="1.2" marker-end="url(#ar3)"><line x1="124" y1="72" x2="138" y2="72"/><line x1="254" y1="72" x2="268" y2="72"/><line x1="384" y1="72" x2="398" y2="72"/><line x1="514" y1="72" x2="528" y2="72"/><line x1="644" y1="72" x2="658" y2="72"/></g>
<path d="M716 106 V 134 H 66 V 106" fill="none" stroke="currentColor" stroke-width="1.2" marker-end="url(#ar3)"/>
{T(391,150,"new book = new account; several can be live at once","新簿子 = 新帳戶，可同時有多本",'text-anchor="middle" font-size="11" fill="var(--muted)"')}
{T(10,22,"Only step 1 touches a computer that matters, and each one sees half. Registration is paid by a minute of proof-of-work or by any account's fee cheque. Step 5 is paper and any computer at all.","只有第 1 步接觸到要緊的電腦，而每台只看到一半。登記可用一分鐘的工作量證明或任何帳戶的手續費支票支付。第 5 步只需紙和任何一台電腦。",'font-size="11" fill="var(--muted)"')}
</svg>'''


EXAMPLE = f'''<div class="example">
<p><b>{S("Example. Mei's savings account is 00000051900-8, a cheque book holding 3 coins.","例子：小美的儲蓄帳戶是 00000051900-8，一本存著 3 枚幣的支票簿。")}</b> {S("Part A of her book is at home, part B at her parents' place, and the seed paper in a bank box.","她的簿子 A 部分放家裡，B 部分放父母家，種子紙放在銀行保管箱。")}</p>
<p><b>{S("Selling some: she moves 0.5 coin to her exchange account, 00000048213-5.","賣出一部分：她把 0.5 幣轉到自己在交易所的帳號 00000048213-5。")}</b></p>
<ol>
<li>{S("0.5 coin = 50,000,000 base units = 5000 × 10<sup>4</sup>, so mantissa 5000, exponent 4; fee tier 2. She writes at the top of cheque 7: <code>000000482135 5000 4 2</code>.","0.5 幣 = 50,000,000 基本單位 = 5000 × 10<sup>4</sup>，所以金額 5000、指數 4；手續費等級 2。她在第 7 號支票上方寫：<code>000000482135 5000 4 2</code>。")}</li>
<li>{S("She brings both parts together, takes cheque 7, and tears 18 tabs: 12 from part A, 6 from part B.","她把兩部分放在一起，取第 7 號支票，撕下 18 格：A 部分 12 格、B 部分 6 格。")}</li>
<li>{S("She photographs the 18 tabs with her laptop. The app says: “Cheque 7: pay 00000048213-5 0.5 coin, fee 0.0002.” She taps broadcast. About 330 bytes go on chain; confirmed in about 10 minutes. She burns what is left of cheque 7. Balance now 2.4998.","她用筆電拍下 18 格。App 顯示：「第 7 號支票：付 0.5 幣給 00000048213-5，手續費 0.0002」。按廣播。鏈上約 330 位元組，約 10 分鐘確認。燒掉第 7 號剩餘部分。餘額剩 2.4998 幣。")}</li>
</ol>
<p><b>{S("Buying more: 2 coins arrive from the exchange.","買入更多：交易所送來 2 幣。")}</b> {S("The exchange's software drives its own large cheque book and writes a cheque to 00000051900-8. Nothing for Mei to do; her balance becomes 4.4998. She has used one of her ten moves.","交易所的軟體操作自己的大本支票簿，開一張支票給 00000051900-8。小美什麼都不用做，餘額變成 4.4998 幣。她用掉了十次轉移中的一次。")}</p>
<p>{S("<b>If the laptop is infected:</b> it saw 18 cells that are good for exactly one payment of 0.5 coin to 00000048213-5. It never saw the seed or the rest of the book. It can send the payment as written, or not send it.","<b>如果筆電中毒：</b>它看到的 18 格只能用於那一筆付 0.5 幣給 00000048213-5 的付款。它從未見過種子或簿子其餘部分。它只能照送，或不送。")}</p>
</div>'''


# ---------- Figure 8: hashed, compared, verified ----------
FIG8=f"""<svg role="img" aria-label="At printing, a seed derives a cheque key, then a secret cell; the cell is hashed into a public commitment stored on chain. At spending, the revealed cell is hashed again by any computer and every node and compared with the stored commitment; a match fixes that digit. Nothing is encrypted." viewBox="0 0 780 400" xmlns="http://www.w3.org/2000/svg" font-family="var(--sans)" font-size="12">
{AR%("ar8","currentColor")}{AR%("ars8","var(--secret)")}{AR%("arp8","var(--public)")}
{T(20,24,"At printing (domain A; B is identical)","印製時（環境 A；B 相同）",'font-weight="600"')}
{box(20,40,120,50,"var(--secret-soft)","var(--secret)","1.5")}{T(80,60,"seed A","種子 A",'text-anchor="middle" font-weight="600" fill="var(--secret)"')}{T(80,78,"256 random bits","256 個隨機位元",'text-anchor="middle" fill="var(--secret)" font-size="10"')}
{arrow(142,65,168,65,"var(--secret)","ars8")}{T(155,56,"hash","雜湊",'text-anchor="middle" font-size="9" fill="var(--secret)"')}
{box(170,40,120,50,"var(--secret-soft)","var(--secret)","1.5")}{T(230,60,"cheque key №7","第 7 號支票金鑰",'text-anchor="middle" font-weight="600" fill="var(--secret)"')}{T(230,78,"hash(seed, 7)","hash(種子, 7)",'text-anchor="middle" fill="var(--secret)" font-size="10"')}
{arrow(292,65,318,65,"var(--secret)","ars8")}{T(305,56,"hash","雜湊",'text-anchor="middle" font-size="9" fill="var(--secret)"')}
{box(320,40,130,50,"var(--secret-soft)","var(--secret)","1.5")}{T(385,60,"cell half a","格子左半 a",'text-anchor="middle" font-weight="600" fill="var(--secret)"')}{T(385,78,"hash(key, col, row) → paper","hash(金鑰, 欄, 列) → 紙上",'text-anchor="middle" fill="var(--secret)" font-size="10"')}
{arrow(452,65,478,65,"var(--public)","arp8")}{T(465,56,"hash","雜湊",'text-anchor="middle" font-size="9" fill="var(--public)"')}
{box(480,40,130,50,"var(--public-soft)","var(--public)","1.5")}{T(545,60,"commitment","承諾值",'text-anchor="middle" font-weight="600" fill="var(--public)"')}{T(545,78,"hash(addr, hash(a) ‖ hash(b))","hash(位址, hash(a) ‖ hash(b))",'text-anchor="middle" fill="var(--public)" font-size="9"')}
{arrow(612,65,638,65,"var(--public)","arp8")}
{box(640,40,120,50,"var(--public-soft)","var(--public)","1.5")}{T(700,60,"on chain","上鏈",'text-anchor="middle" font-weight="600" fill="var(--public)"')}{T(700,78,"Merkle-checked vs root","以 Merkle 路徑對照根",'text-anchor="middle" fill="var(--public)" font-size="10"')}
{T(20,118,"Secret values (red) are one-way hashed into public values (green). Hashing cannot be reversed; there is no key that unlocks it, because nothing was encrypted.","秘密值（紅）經單向雜湊成公開值（綠）。雜湊無法反推；沒有任何鑰匙能解開，因為根本沒有加密。",'font-size="11" fill="var(--muted)"')}
<line x1="20" y1="136" x2="760" y2="136" stroke="var(--line)"/>
{T(20,160,"At spending","付款時",'font-weight="600"')}
{box(20,176,130,50,"var(--secret-soft)","var(--secret)","1.5")}{T(85,196,"torn tab","撕下的格子",'text-anchor="middle" font-weight="600" fill="var(--secret)"')}{T(85,214,"cell a (and b) revealed","公開格子 a（和 b）",'text-anchor="middle" fill="var(--secret)" font-size="10"')}
{arrow(152,201,178,201)}{T(165,192,"hash","雜湊",'text-anchor="middle" font-size="9"')}
{box(180,176,150,50)}{T(255,196,"any computer, every node","任何電腦、每個節點",'text-anchor="middle" font-weight="600"')}{T(255,214,"recompute the commitment","重新算出承諾值",'text-anchor="middle" fill="var(--muted)" font-size="10"')}
{arrow(332,201,358,201)}{T(345,192,"compare","比對",'text-anchor="middle" font-size="9"')}
{box(360,176,170,50,"var(--public-soft)","var(--public)","1.5")}{T(445,196,"== stored commitment?","== 鏈上的承諾值？",'text-anchor="middle" font-weight="600" fill="var(--public)"')}{T(445,214,"match at row 5 of P12 → digit 5","在 P12 第 5 列吻合 → 數字 5",'text-anchor="middle" fill="var(--public)" font-size="10"')}
{arrow(532,201,558,201)}
{box(560,160,200,82,"var(--public-soft)","var(--public)","1.5")}{T(660,180,"when 18 columns match","18 欄都吻合時",'text-anchor="middle" font-weight="600" fill="var(--public)"')}
{T(660,198,"check digit → 0?  number mature?","檢查碼 → 0？帳號已滿 100 區塊？",'text-anchor="middle" fill="var(--public)" font-size="10"')}
{T(660,214,"№7 > last used?  balance ≥ amount+fee?","第 7 號 > 上次？餘額 ≥ 金額+手續費？",'text-anchor="middle" fill="var(--public)" font-size="10"')}
{T(660,232,"→ transfer; delete cheque 7's hashes","→ 轉帳；刪除第 7 號的雜湊值",'text-anchor="middle" fill="var(--public)" font-size="10" font-weight="600"')}
{T(20,270,"Then the miner hashes the block header (proof of work), and every other node repeats every comparison above before accepting the block.","接著礦工對區塊頭做雜湊（工作量證明），其他每個節點在接受區塊前都會重做上述每一項比對。",'font-size="11" fill="var(--muted)"')}
<line x1="20" y1="288" x2="760" y2="288" stroke="var(--line)"/>
{T(20,312,"What an attacker sees: every green box. What they would need: a red cell that was never torn out, i.e. an input whose hash equals a stored commitment.","攻擊者看得到：所有綠色方塊。攻擊者需要：一個從未撕下的紅色格子，也就是找到一個雜湊值等於鏈上承諾值的輸入。",'font-size="11"')}
{T(20,332,"Classical: 2^128 hashes, about 9 billion years for all of Bitcoin's miners. Quantum (Grover): 2^64 sequential steps. Both are the NIST category-1 budget.","傳統電腦：2^128 次雜湊，全比特幣算力約需 90 億年。量子（Grover）：2^64 個循序步驟。兩者都在 NIST 第 1 類安全預算內。",'font-size="11"')}
{T(20,362,"Node-to-node traffic is encrypted (hybrid X25519 + ML-KEM) only to hide it from onlookers. It plays no part in whether a cheque is valid.","節點之間的傳輸有加密（X25519 + ML-KEM 混合），只是為了不讓旁人看到。它和支票是否有效無關。",'font-size="11" fill="var(--muted)"')}
{T(20,382,"Encryption is two-way: lock, then unlock with a key. The chain never does that. It only hashes (one-way) and compares (equal or not).","加密是雙向的：上鎖，再用鑰匙解鎖。這條鏈從不這麼做。它只做雜湊（單向）和比對（相等或不相等）。",'font-size="11" fill="var(--muted)"')}
</svg>"""

lc_rows=[("1","Seed","種子","device A (B likewise)","裝置 A（B 同理）","256 random bits, shown as 24 words","256 個隨機位元，顯示為 24 個字","—","—","yes, paper","是，紙上"),
("2","Cheque key","支票金鑰","device A","裝置 A","hash(seed A, №)","hash(種子 A, 號碼)","—","—","yes","是"),
("3","Cell half","格子半段","device A","裝置 A","hash(key, column, row); printed as 12 words","hash(金鑰, 欄, 列)；印成 12 個字","—","—","yes, paper","是，紙上"),
("4","Commitment","承諾值","A, B, then any computer","A、B，再任何電腦","hash(a), hash(b), then hash(addr, both)","hash(a)、hash(b)，再 hash(位址, 兩者)","—","—","no","否"),
("5","Root","根雜湊","any computer","任何電腦","Merkle tree over all commitments → account id","所有承諾值的 Merkle 樹 → 帳戶 ID","—","—","no","否"),
("6","Registration","登記","every node","每個節點","leaves from submitted commitments","由送交的承諾值算出葉節點","Merkle path ends at the root; not a duplicate; PoW or fee valid","Merkle 路徑須到達根；非重複；工作量證明或手續費有效","no","否"),
("7","Writing","開票","you","你","nothing","不計算","read a row per digit, tear 18 × 2 tabs","每個數字找一列，撕 18 × 2 格","reveals those cells only","只公開這些格子"),
("8","Decoding","解碼","broadcasting computer","廣播電腦","hash(addr, half) per tab","每格做 hash(位址, 半段)","which stored commitment matches → the digit; shows payee and amount","哪個鏈上承諾值吻合 → 得出數字；顯示收款人與金額","sees revealed cells only","只看到公開的格子"),
("9","Piece check","碎片驗證","every node","每個節點","recompute the commitment","重新算出承諾值","equals stored one; № > last used; column not locked yet; batch registered; first piece consumes №","等於鏈上值；號碼 > 上次；該欄尚未鎖定；批次已登記；第一塊即用掉號碼","no","否"),
("10","Completion","完成","every node","每個節點","check digit; amount = mantissa × 10^E; fee = F × unit","檢查碼；金額 = 尾數 × 10^E；手續費 = F × 單位","check digit → 0; payee number mature; balance ≥ amount + fee → transfer, delete this cheque's hashes","檢查碼 → 0；收款帳號已成熟；餘額 ≥ 金額 + 手續費 → 轉帳、刪除本票雜湊值","no","否"),
("11","Block","區塊","miner, then every node","礦工，再每個節點","SHA-256d of the header; tx root; state root","區塊頭 SHA-256d；交易根；狀態根","difficulty met; every piece re-checked; state root matches","達到難度；每塊碎片重驗；狀態根吻合","no","否"),
("12","Afterwards","之後","anyone, light clients","任何人、輕節點","—","—","Merkle proofs against the state root for balance, nonce, number","以狀態根的 Merkle 證明查餘額、nonce、帳號","no","否")]
lct="".join(f"<tr><td>{n}</td><td>{S(a,az)}</td><td>{S(w,wz)}</td><td>{S(c,cz)}</td><td>{S(v,vz)}</td><td>{S(sec,secz)}</td></tr>" for n,a,az,w,wz,c,cz,v,vz,sec,secz in lc_rows)


cmp_rows=[("Buy","購買","one device","一台裝置","nothing new; two devices you already have, two printers","不用買；兩台你已有的裝置、兩台印表機"),
("Set up","設定","20 minutes, one seed","20 分鐘，一組種子","about 20 minutes on one offline computer, then a day of waiting before the number is live","在一台離線電腦上約 20 分鐘，之後等約一天帳號才可用"),
("Store","保存","one seed card","一張種子卡","one seed and a book in two parts, kept in different places","一組種子和分兩部分的簿子，分開存放"),
("Receive","收款","share an address","給對方地址","share a 12-digit number","給對方 12 位數帳號"),
("Send","轉出","app, scan, confirm on device: seconds","App 掃描、裝置確認：幾秒","both parts in one room, 18 tabs, a photo: about five minutes","兩部分放一起、18 張標籤、拍照：約五分鐘"),
("How often","次數","unlimited","不限","ten moves, then a new book","十次，然後換新簿"),
("Amounts","金額","anything","任意","four significant digits","四位有效數字"),
("Restore","復原","type 24 words once","輸入 24 個字一次","type 24 words twice, into two devices","輸入 24 個字兩次，到兩台裝置"),
("Must trust","必須信任","the device and its maker","裝置和它的製造商","nobody: two unrelated devices must not both be compromised","沒有人：只要兩台不相關的裝置沒有同時被入侵"),
("Breaks under","會失守於","a quantum computer; a tampered device","量子電腦；被動過手腳的裝置","losing one seed; breaking one of four rules","遺失任一種子；違反四條規則之一")]
cmpt="".join(f"<tr><td>{S(a,az)}</td><td>{S(b,bz)}</td><td>{S(c,cz)}</td></tr>" for a,az,b,bz,c,cz in cmp_rows)

keep=[("Your seed, 24 words","你的種子，24 個字","paper, place 3","紙本，地點 3"),
      ("Book part A · payee","簿子 A 部分 · 收款帳號","place 1","地點 1"),
      ("Book part B · amount, exponent, fee","簿子 B 部分 · 金額、指數、手續費","place 2","地點 2"),
      ("Counters, files, backups of anything else","計數器、檔案、其他任何備份","none","無")]
keeptab="".join(f"<tr><td>{S(e,z)}</td><td>{S(w,wz)}</td></tr>" for e,z,w,wz in keep)
rows=[("Cells per cheque","每張支票的格數","180"),
      ("Printed pages per book (A + B)","每本印出頁數（A + B）","≈ 44"),
      ("Codes copied to sign (18 cells × 2 halves)","簽名要抄的碼（18 格 × 2 半）","36"),
      ("Words, if typed instead of photographed (12 per cell)","若用輸入而非拍照的字數（每格 12 字）","432"),
      ("Public hashes registered on chain, per cheque","每張支票登記上鏈的公開雜湊","≈ 5.8 KB"),
      ("On-chain size of one cheque payment","一筆支票付款的鏈上大小","≈ 580 B"),
      ("Cheques per book","每本支票數","11: one check, ten moves")]
table="".join(f"<tr><td>{S(e,z)}</td><td>{v}</td></tr>" for e,z,v in rows)
limits=[("It is a safe, not a wallet.","這是保險箱，不是錢包。","Ten moves per book, one payee per move, and whoever holds both parts of an unused cheque can make one move. Keep the two parts apart, split large holdings across books in different places, and do daily spending somewhere else.","每本十次轉移，每次一個收款人；持有未用支票兩部分的人就能做一次轉移。把兩部分分開保存，大額資產分散在不同地點的多本簿子，日常消費另用其他工具。"),
        ("Privacy is weaker than Bitcoin.","隱私比比特幣差。","Accounts and numbers make every payment from a book linkable.","帳戶與編號讓同一本簿子的每筆付款都能被關聯。"),
        ("A reprint needs one rule.","重印需要遵守一條規則。","Before using a reprinted book, confirm a cheque numbered above anything the old book held, then destroy the old one.","使用重印本前，先確認一張號碼大於舊簿所有號碼的支票，再銷毀舊簿。"),
        ("A new chain is the real risk.","新鏈本身才是真正的風險。","Cryptography is the strongest part. Hashpower, code maturity and adoption decide whether the chain lives, which is why launching merge-mined with Bitcoin is recommended.","密碼學是最穩固的部分。算力、程式碼成熟度和採用率才決定鏈能否存活，因此建議與比特幣合併挖礦啟動。")]
limhtml="".join(f"<li><strong>{S(e,z)}</strong> {S(d,dz)}</li>" for e,z,d,dz in limits)

html=f'''<title>Cheque Book Explained</title>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;600&family=IBM+Plex+Mono:wght@400;700&family=Noto+Sans+TC:wght@400;600&display=swap">
<style>
/* layout: one column of figures, each figure = one claim; secret=red, public=green, accent=ink blue; bilingual via data-lang on root; light theme only by choice */
:root{{
  --bg:#f5f6f8; --fg:#1b2330; --muted:#5e6b7d; --line:#c9d0da; --panel:#ffffff;
  --accent:#1f5bb5; --accent-soft:#e3ebf8;
  --secret:#b8322a; --secret-soft:#fbe6e3;
  --public:#1f7a4d; --public-soft:#dff3e8;
  --sans:"IBM Plex Sans","Noto Sans TC","PingFang TC","Microsoft JhengHei",system-ui,sans-serif; --mono:"IBM Plex Mono",ui-monospace,monospace;
  color-scheme:light;
}}
body{{background:var(--bg);color:var(--fg);font-family:var(--sans);font-size:15px;line-height:1.55;margin:0}}
.wrap{{max-width:860px;margin:0 auto;padding-block:24px 64px;padding-inline:16px}}
.top{{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;flex-wrap:wrap}}
h1{{font-size:28px;line-height:1.15;margin:0 0 6px;text-wrap:balance}}
.lede{{color:var(--muted);margin:0 0 24px;max-width:62ch}}
h2{{font-size:17px;margin:40px 0 8px}}
p{{max-width:66ch;margin:0 0 10px}}
figure{{margin:12px 0 0;background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:14px 12px 10px}}
.scroll{{overflow-x:auto}}
svg{{max-width:100%;height:auto;display:block;color:var(--fg)}}
figcaption{{font-size:13px;color:var(--muted);margin-top:10px;max-width:70ch}}
.key{{display:flex;gap:18px;flex-wrap:wrap;font-size:13px;margin:0 0 4px}}
.key > span::before{{content:"";display:inline-block;width:12px;height:12px;border-radius:2px;margin-right:6px;vertical-align:-1px}}
.k-s::before{{background:var(--secret)}} .k-p::before{{background:var(--public)}} .k-a::before{{background:var(--accent)}}
table{{border-collapse:collapse;font-size:14px;margin-top:10px;font-variant-numeric:tabular-nums}}
td,th{{padding:6px 12px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}}
th{{font-weight:600;color:var(--muted);font-size:12px;letter-spacing:.04em;text-transform:uppercase}}
.num td:last-child,.num th:last-child{{text-align:right}}
ul.lim{{padding-left:20px;max-width:70ch}} table.lc{{font-size:12.5px;min-width:700px}} table.lc td{{vertical-align:top}} table.lc td:first-child{{color:var(--muted)}} .example{{margin-top:12px;border-left:3px solid var(--accent);padding:4px 14px;max-width:70ch;background:var(--panel)}} .example ol,.example ul{{padding-left:22px;margin:0 0 8px}} .example li{{margin:4px 0}} .example code{{font-family:var(--mono);font-size:13px}} ul.lim li{{margin:6px 0}}
.lang{{display:flex;gap:4px;border:1px solid var(--line);border-radius:6px;padding:3px;background:var(--panel)}}
.lang button{{font:inherit;font-size:13px;border:0;background:none;color:var(--muted);padding:4px 10px;border-radius:4px;cursor:pointer}}
.lang button[aria-pressed="true"]{{background:var(--accent-soft);color:var(--accent);font-weight:600}}
.lang button:focus-visible{{outline:2px solid var(--accent);outline-offset:1px}}
:root:not([data-lang="zh"]) .zh{{display:none!important}}
:root[data-lang="zh"] .en{{display:none!important}}
:root[data-lang="zh"] body{{font-family:"Noto Sans TC","PingFang TC","Microsoft JhengHei","IBM Plex Sans",system-ui,sans-serif}}
</style>
<div class="wrap">
<div class="top">
<div>
<h1>{S("How the paper cheque book works","紙本支票簿如何運作")}</h1>
<p class="lede">{S("A quantum-safe chain for storing value, not for daily spending. Every account is a paper cheque book with ten moves in it, signed with a pen. Nothing anywhere needs to be remembered except the seed words and the paper. Any computer, trusted or not, can only broadcast exactly what you wrote.","一條用來儲存價值、而非日常消費的抗量子區塊鏈。每個帳戶都是一本只有十次轉移的紙本支票簿，用筆簽名。除了種子字和紙本之外，任何地方都不需要記住任何狀態。任何電腦，不論可不可信，都只能廣播你寫下的那筆轉移。")}</p>
</div>
<div class="lang" role="group" aria-label="Language"><button type="button" id="lang-en" aria-pressed="true">English</button><button type="button" id="lang-zh" aria-pressed="false">繁體中文</button></div>
</div>
<div class="key"><span class="k-s">{S("secret, only on paper","秘密，只存在紙上")}</span><span class="k-p">{S("public, on the chain","公開，在鏈上")}</span><span class="k-a">{S("the action in this step","本步驟的動作")}</span></div>

<h2>1. {S("How a payment travels","一筆付款怎麼走")}</h2>
<p>{S("There is one kind of account. Its signature is a cheque: one payee, one amount, 18 digits, each digit answered by a pre-printed secret. A person signs with a pen; an exchange or a miner lets software do the copying with the same format. Nothing is ever computed by the signer. A printed book holds ten such moves, which for savings is years.","只有一種帳戶。它的簽名就是一張支票：一個收款人、一個金額、18 個數字，每個數字對應一個預先印好的秘密。一般人用筆簽；交易所或礦工讓軟體用同樣格式代抄。簽名者從不做任何計算。一本印好的簿子有十次轉移，對儲蓄來說就是好幾年。")}</p>
<figure class="scroll">{FIG0}
<figcaption>{S("One account type, one signature format, one hash function. Large holdings are split across several books in several places rather than kept behind any device.","一種帳戶、一種簽名格式、一個雜湊函數。大額資產分散在不同地點的多本簿子，而不是交給任何裝置。")}</figcaption></figure>
{EXAMPLE}

<h2>2. {S("Who holds what","誰持有什麼")}</h2>
<p>{S("Two independent devices each make half of every secret. Each prints its half and publishes only the hashes. No device ever sees the other half.","兩台互不相干的裝置各自產生每個秘密的一半。各自印出自己那一半，並只公開其雜湊值。沒有任何裝置看得到另一半。")}</p>
<figure class="scroll">{FIG1}
<figcaption>{S("Key generation needs no trusted device. Each domain knows only its half; the chain knows only hashes; only the paper has everything.","產生金鑰不需要任何可信裝置。每個環境只知道自己那一半，鏈上只有雜湊值，只有紙本同時擁有全部。")}</figcaption></figure>

<h2>3. {S("Where the book comes from","簿子從哪裡來")}</h2>
<p>{S("One seed of 24 words makes the whole book. Every cell is derived from that seed by a keyed hash, so the seed is a recipe that reproduces the book exactly. The book is printed on a clean, offline computer in two separate print runs: part A holds the payee columns, part B the amount, exponent and fee. The whole book, eleven cheques, is registered once, and the seed is never typed again unless the book is lost.","一組 24 個字的種子產生整本簿子。每一格都由種子經金鑰雜湊導出，所以種子就是一份能完全重現簿子的配方。簿子在乾淨、離線的電腦上分兩次列印：A 部分是收款帳號欄，B 部分是金額、指數和手續費。整本十一張只登記一次，除非簿子遺失，種子不會再輸入第二次。")}</p>
<figure class="scroll">{FIG2}
<figcaption>{S("The seed is the backup. Keep it apart from both parts of the book. Losing the seed and the book together loses the account. For large savings, an optional split book uses two seeds on two machines.","種子就是備份，要和簿子的兩部分分開保存。種子和簿子同時遺失就會失去帳戶。大額儲蓄可選分割簿子，在兩台機器上使用兩組種子。")}</figcaption></figure>

<h2>4. {S("One cheque is a grid","一張支票就是一個格子表")}</h2>
<p>{S("A cheque can say one thing: pay an account number an amount. The message is 18 digits. Each digit has its own column, and each value 0 to 9 has its own row. The cell where they meet holds a secret: 12 ordinary words.","一張支票只能說一件事：付多少錢給某個帳號。訊息共 18 個數字。每個數字一欄，0 到 9 各一列。欄列交會的格子裡就是一個秘密：12 個普通單字。")}</p>
<figure class="scroll">{FIG3}
<figcaption>{S('To sign "pay 00000048213-5 the amount 1500 × 10^5", find row 0 in column P1, row 0 in P2, … row 5 in P12, then the amount digits, exponent and fee tier. Copy those 18 cells. That is the whole signature; nothing is computed. The last payee digit is a check digit, so one mis-copied digit makes the cheque invalid instead of paying a stranger.',"要簽「付 1500 × 10^5 給 00000048213-5」，就在 P1 欄找第 0 列、P2 欄找第 0 列……P12 欄找第 5 列，再找金額、指數和手續費各欄。把這 18 格抄下來，這就是完整的簽名，不需要任何計算。帳號最後一位是檢查碼，抄錯一個數字支票會作廢，而不是付錯人。")}</figcaption></figure>

<p>{S("Every cell is written as 12 words from the same 2,048-word list used for seed phrases, so a cell looks exactly like a 12-word seed. Underneath it is 128 random bits; the chain only ever sees those bits. Words are used because people copy them reliably: each word is unique in its first four letters, so typing four letters is enough; a misspelt word is not in the list and is refused on entry; a wrong word fails the built-in checksum 15 times in 16. A Traditional Chinese word list exists too, with the same bits behind it.","每一格都寫成 12 個字，取自種子助記詞所用的同一份 2,048 字表，所以一格看起來就像一組 12 字種子。底下其實是 128 個隨機位元，鏈上看到的只有這些位元。用字而不用亂碼，是因為人抄字比較不會錯：每個英文字前四個字母就能唯一辨認，所以只要打四個字母；拼錯的字不在表上，輸入時就會被擋下；抄成另一個字，內建的檢查碼有 16 分之 15 的機率會發現。也有繁體中文字表，底下的位元完全一樣。")}</p>

<h2>5. {S("Signing and checking","簽名與驗證")}</h2>
<p>{S("You tear out (or copy) the 18 cells and give them to any computer. The computer and every node check them against the hashes published in step 3.","你撕下（或抄下）這 18 格，交給任何一台電腦。電腦和每個節點都會拿它們和第 3 步公開的雜湊值比對。")}</p>
<figure class="scroll">{FIG4}
<figcaption>{S("Verification needs no secrets, so anyone can do it. Forgery needs an unrevealed cell, which no one has.","驗證不需要任何秘密，所以人人可驗。偽造需要一個未公開的格子，而沒有人有。")}</figcaption></figure>

<h2>6. {S("Cheque numbers are the account counter","支票號碼就是帳戶計數器")}</h2>
<p>{S("Cheques are used in rising order. The chain remembers the highest number it has seen, and anything at or below it is dead forever. No device keeps a counter: the paper is the only state, and the chain is the only record.","支票必須按遞增順序使用。鏈會記住見過的最大號碼，小於等於它的號碼永遠失效。沒有任何裝置保存計數器：紙本是唯一的狀態，鏈是唯一的紀錄。")}</p>
<figure class="scroll">{FIG5}
<figcaption>{S("The cheque number is the nonce. It makes reuse impossible, makes lost cheques harmless, and gives you a way to void a cheque that is out of your hands.","支票號碼就是 nonce。它讓重複使用不可能、遺失無害，也讓你能作廢已離手的支票。")}</figcaption></figure>

<h2>7. {S("A cheque can arrive in pieces","支票可以分批送達")}</h2>
<p>{S("Each code is self-describing: its hash identifies the account, the cheque, the column and the digit. So the 18 cells need not travel together. Send some from one place, some from another, some by a friend. The chain assembles them.","每個碼都能自我說明：它的雜湊值就指出了帳戶、支票、欄位和數字。所以 18 格不必一起送出。可以從不同地方、不同時間、甚至請朋友代送。鏈會自行組合。")}</p>
<figure class="scroll">{FIG6}
<figcaption>{S("No single machine ever needs to hold a whole cheque. Several people can each hold a few columns, so a payment goes through only when all of them submit.","沒有任何一台機器需要持有整張支票。幾個人可以各持幾欄，只有全部送出時付款才成立。")}</figcaption></figure>

<h2>8. {S("Life of a book","一本支票簿的一生")}</h2>
<figure class="scroll">{FIG7}
<figcaption>{S("A book is eleven cheques: one honesty check and ten moves. For a store of value that is years of use. When they are gone, print a new book and sweep the balance across with cheque 10.","一本有十一張：一張誠實檢查，十次轉移。作為價值儲存，這足夠用上好幾年。用完就印新簿子，用第 10 號把餘額全部轉過去。")}</figcaption></figure>

<h2>9. {S("What you keep, and what the chain keeps","你保存什麼，鏈保存什麼")}</h2>
<table><tr><th>{S("You keep","你保存")}</th><th>{S("Where","放在哪")}</th></tr>{keeptab}</table>
<p style="margin-top:12px">{S("The chain keeps the hashes of every cell, which cheque numbers are used, the account number table and balances. A wallet restored from the seeds asks the chain what is spent and reprints the rest.","鏈保存每一格的雜湊值、哪些支票號碼已用、帳號對照表和餘額。從種子復原的錢包只要問鏈哪些已用，其餘重印即可。")}</p>

<h2>10. {S("Sizes, two domains","數量（兩個環境）")}</h2>
<table class="num"><tr><th>{S("Item","項目")}</th><th>{S("Amount","數量")}</th></tr>{table}</table>

<h2>11. {S("Limits, stated plainly","限制，直說")}</h2>
<ul class="lim">{limhtml}</ul>

<h2>14. {S("What it asks of you, compared with Bitcoin","和比特幣相比，它要求你做什麼")}</h2>
<div class="scroll"><table class="lc"><tr><th>{S("","")}</th><th>{S("Bitcoin, hardware wallet","比特幣，硬體錢包")}</th><th>{S("This chain","這條鏈")}</th></tr>{cmpt}</table></div>
<p style="margin-top:10px">{S("Harder to use, easier to trust. It suits someone who touches their savings a few times a year and wants nothing between them and their coins but paper. It does not suit anyone who pays for things with it.","比較難用，但比較容易信任。它適合一年只動幾次儲蓄、希望自己和幣之間只有紙的人。不適合任何拿它來付款的人。")}</p>
</div>
<script>
(function(){{
  var root=document.documentElement, be=document.getElementById('lang-en'), bz=document.getElementById('lang-zh');
  function set(l){{ if(l==='zh'){{root.setAttribute('data-lang','zh');}} else {{root.removeAttribute('data-lang');}}
    be.setAttribute('aria-pressed', l!=='zh'); bz.setAttribute('aria-pressed', l==='zh');
    try{{localStorage.setItem('lang',l);}}catch(e){{}} }}
  var saved=null; try{{saved=localStorage.getItem('lang');}}catch(e){{}}
  var nav=(navigator.language||'').toLowerCase();
  set(saved || (nav.indexOf('zh')===0?'zh':'en'));
  be.addEventListener('click',function(){{set('en');}});
  bz.addEventListener('click',function(){{set('zh');}});
}})();
</script>
'''
open(os.path.join(os.path.dirname(os.path.abspath(__file__)),"cheque-book-explained.raw.html"),"w").write(html)
print(len(html))

# ---------- step-by-step guides ----------
def ol(items):
    return "<ol>"+"".join(f"<li>{S(e,z)}</li>" for e,z in items)+"</ol>"
def h3(en,zh): return f"<h3>{S(en,zh)}</h3>"
cheque = (
 h3("Set up once","一次性設定")+ol([
 ("<b>Prepare one clean, offline computer.</b> A freshly booted machine with the internet disconnected and a printer on a USB cable only.","<b>準備一台乾淨、離線的電腦。</b>剛開機、已中斷網路的電腦，印表機只用 USB 線連接。"),
 ("<b>Print the book.</b> On a clean, offline computer with a USB-only printer, the wallet shows your seed (24 words): write it down. It derives all eleven cheques and prints part A, the payee columns, then part B, the amount, exponent and fee, as a separate print run. It exports a public hash file (USB or QR) with no secrets, then you switch everything off.","<b>印出簿子。</b>在乾淨、離線、只接 USB 印表機的電腦上，錢包顯示你的種子（24 個字）：寫下來。它導出全部十一張支票，先印 A 部分（收款帳號欄），再分開印 B 部分（金額、指數、手續費）。它匯出不含秘密的公開雜湊檔（USB 或 QR），然後全部關機。"),
 ("<b>Keep the parts apart.</b> Store part A and part B in different places from the moment they are printed.","<b>兩部分分開。</b>從印好的那一刻起，A、B 兩部分就存放在不同地方。"),
 ("<b>Combine and register.</b> Any computer imports both hash files, computes the account id and sends the registration, which covers the whole book. Pay it either with about a minute of proof-of-work (no coins needed) or with a fee cheque from any account, such as a friend's or an employer's. After 100 blocks the account has a number. A proof-of-work account never funded is deleted after 30 days.","<b>合併並登記。</b>任何電腦匯入兩個雜湊檔，算出帳戶 ID，送出登記交易（涵蓋整本）。可用約一分鐘的工作量證明支付（不需要幣），或由任何帳戶（例如朋友或雇主）開一張手續費支票支付。100 個區塊後帳戶取得編號。用工作量證明登記但從未存入的帳戶 30 天後刪除。"),
 ("<b>Honesty check.</b> Write cheque 0 for zero coins (amount 0000, exponent 0, fee tier 0) to any number, following the signing steps below. If it confirms, both devices printed what they hashed.","<b>誠實檢查。</b>依下方簽名步驟，用第 0 號支票付 0 幣（金額 0000、指數 0、手續費等級 0）給任何帳號。確認後即證明兩台裝置印的就是它們雜湊的內容。"),
 ("<b>Receive.</b> Give your account number to whoever pays you, or write a cheque to it from another book. Keep large holdings split across several books in several places.","<b>收款。</b>把帳號給付款人，或從另一本簿子開支票給它。大額資產分散在不同地點的多本簿子。"),
 ("<b>Store.</b> Part A in place one, part B in place two, the seed paper in place three. Bring the two parts together only to write a cheque.","<b>保存。</b>A 部分放地點一、B 部分放地點二、種子紙放地點三。只有要開支票時才把兩部分放在一起。")])+
 h3("Write a cheque","開一張支票")+ol([
 ("<b>Get the payee's number,</b> 12 digits including the check digit, from them directly.","<b>向收款人直接取得帳號，</b>含檢查碼共 12 位數字。"),
 ("<b>Work out the amount digits.</b> 1.5 coins = 1500 with exponent 5. The app or a printed table converts this; it is public information.","<b>換算金額數字。</b>1.5 幣 = 1500、指數 5。App 或印好的對照表可代勞，這是公開資訊。"),
 ("<b>Take the next unused cheque,</b> the same number in part A and part B. Write the payee digits, amount, exponent and fee tier at the top.","<b>取下一張未用支票，</b>A、B 兩部分的同一號碼。在上方寫下收款帳號數字、金額、指數和手續費等級。"),
 ("<b>Tear the tabs.</b> For each of the 18 columns, find the row for that digit and tear out that tab: 12 from part A, 6 from part B. No other tab leaves the page.","<b>撕下標籤。</b>18 欄中每一欄找到該數字的列並撕下那一格：A 部分 12 張、B 部分 6 張。其他格子都不離開紙面。"),
 ("<b>Hand them to any computer.</b> Photograph the tabs or type the words (the first four letters of each are enough). The app shows what they decode to: account, cheque number, payee, amount. Check, then broadcast. Pieces may be sent from different places; send the payee columns first.","<b>交給任何電腦。</b>拍下標籤或輸入單字（每個字打前四個字母即可）。App 顯示解碼結果：帳戶、支票號、收款人、金額。核對後廣播。可以分批從不同地方送出；先送收款帳號的欄位。"),
 ("<b>Destroy the rest of that cheque</b> in both parts. Wait for confirmation.","<b>銷毀該張支票在兩部分的剩餘部分。</b>等待確認。")])+
 h3("Restore, or run out","復原，或用完")+ol([
 ("<b>Lost the book.</b> Enter the seed into a clean, offline computer and reprint the numbers the chain shows as unused. Before using the reprint, confirm one zero-coin cheque numbered above anything the old book held; destroy the old book if it turns up.","<b>簿子遺失。</b>把種子輸入一台乾淨、離線的電腦，重印鏈上顯示未用的號碼。使用重印本前，先確認一張號碼大於舊簿所有號碼的 0 幣支票；舊簿若找到就銷毀。"),
 ("<b>Ten moves used.</b> Make a new book with a new seed, register it, honesty-check it, then write cheque 10 with amount 0000 and exponent 9 (“everything”) to the new book's number.","<b>十次轉移用完。</b>用新種子做新簿子並登記、做誠實檢查，然後用第 10 號支票以金額 0000、指數 9（「全部」）轉到新簿子的帳號。")]))
guides=f'''

<h2>12. {S("What is hashed, what is compared, what is verified","什麼被雜湊、什麼被比對、什麼被驗證")}</h2>
<p>{S("Nothing is encrypted. Encryption locks data so a key can unlock it later; the chain never needs that. It only runs data one way through SHA-256 and checks whether two results are equal. Here is every cryptographic step in the life of cheque 7, from printing to confirmation.","沒有任何東西被加密。加密是把資料鎖起來、之後用鑰匙解開；這條鏈從不需要那樣做。它只把資料單向送進 SHA-256，再檢查兩個結果是否相等。以下是第 7 號支票從印製到確認的每一個密碼學步驟。")}</p>
<figure class="scroll">{FIG8}
<figcaption>{S("Red is secret and lives on paper. Green is public and lives on chain. Every arrow labelled hash is one-way. Every check is an equality test.","紅色是秘密，只在紙上。綠色是公開的，在鏈上。每個標示雜湊的箭頭都是單向的。每項檢查都是相等測試。")}</figcaption></figure>
<div class="scroll"><table class="lc"><tr><th>#</th><th>{S("Stage","階段")}</th><th>{S("Who","誰")}</th><th>{S("Computes","計算")}</th><th>{S("Compares / verifies","比對／驗證")}</th><th>{S("Secret?","秘密？")}</th></tr>{lct}</table></div>
<p style="color:var(--muted);font-size:13px;margin-top:10px">{S("Transport between nodes is encrypted with a hybrid of X25519 and ML-KEM so onlookers cannot read traffic. That is the only encryption in the system, and it has no effect on whether a cheque is valid.","節點之間的傳輸以 X25519 與 ML-KEM 混合加密，讓旁人無法讀取流量。這是整個系統唯一的加密，且與支票是否有效無關。")}</p>

<h2 id="steps">13. {S("Step by step","逐步說明")}</h2>
<div class="guide">{cheque}</div>
'''
html=html.replace("</div>\n<script>", guides+"</div>\n<script>")
html=html.replace("ul.lim{padding-left:20px;max-width:70ch}", "ul.lim{padding-left:20px;max-width:70ch} .guide{max-width:70ch} .guide h3{font-size:14px;margin:18px 0 4px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em} .guide ol{padding-left:22px;margin:0} .guide li{margin:6px 0}")
open(os.path.join(os.path.dirname(os.path.abspath(__file__)),"cheque-book-explained.raw.html"),"w").write(html)
print("with guides", len(html))
