# Provenza — Administrator qo‘llanmasi

Ushbu qo‘llanma Provenza  platformasidan administrator sifatida
veb-interfeys orqali qanday **foydalanishni** tushuntiradi. O‘rnatish,
joylashtirish va dasturlash uchun [README.md](README.md) ga qarang.

> English version: **[USER_GUIDE.md](USER_GUIDE.md)**

---

## 1. Birinchi kirish

1. Brauzeringizda platforma manzilini oching.
2. Agar tashkilotingiz hali mavjud bo‘lmasa, **Register organization**
   tugmasini bosib uni yarating — birinchi foydalanuvchi **admin**
   bo‘ladi.
3. Kirish uchun tashkilotingizning qisqa identifikatorini (masalan,
   `corp`), **elektron pochta** va **parol**ingizni kiriting.
4. Kirish sahifasi yuqorisidagi **Language** tanlagichi orqali istalgan
   vaqtda English va O‘zbekcha o‘rtasida almashishingiz mumkin.

### Rollar

| Rol | Nimalar qila oladi |
|-----|--------------------|
| **admin** | Hamma narsa: foydalanuvchilar, ulanishlar, telemetriya manbalari, domenlar katalogi, kashfiyot |
| **approver** | Tasdiqlash so‘rovlarini ko‘rib chiqish va hal qilish; kundalik amallar |
| **user** | So‘rov yuborish, o‘z ma’lumotlarini ko‘rish |

---

## 2. Boshqaruv paneli (Dashboard)

Kirgandan so‘ng siz **Dashboard**ga tushasiz — bu so‘rovlar, hodisalar
va kutilayotgan tasdiqlarning qisqacha ko‘rinishi.

Chapdagi yon menyu tashkilotingizdagi AI tizimining hayot yo‘liga mos
tuzilgan:

- **Aniqlash (Discovery)** — Provenza o‘zi topgan narsalar: agentlarning
  jonli xaritasi, shadow AI topilmalari, tarmoq kashfiyoti va ularni
  yig‘uvchi kollektorlar.
- **Reyestr (Registry)** — ishlatilayotgan AI ning yagona ro‘yxati:
  inventar, agentlar, provayder ulanishlari, agent identifikatorlari va
  vositalar reyestri.
- **Siyosatlar (Policies)** — qoidalar: siyosat versiyalari, agent
  siyosatlari, foydalanish holatlari va muvofiqlik.
- **Nazorat (Enforcement)** — ish vaqtidagi nazorat: AI shlyuzi,
  tasdiqlar, circuit breaker, agent himoyalari va boshqariladigan sinov
  maydoni.
- **Audit** — dalillar: foydalanish reyestri, audit jurnali, hodisalar va
  imzolangan vakolat zanjirlari.

---

## 3. Ulanishlar (AI provayderlar)

Platforma promptlarni AI provayderga yuborishidan oldin ulanish qo‘shing.

1. Yon menyu → **Registry → Connections**.
2. **New provider** → turini tanlang (OpenAI, Anthropic, Azure OpenAI
   yoki Shaxsiy), nom bering va API kalitni joylashtiring.
3. Kalit **shifrlangan holda saqlanadi** va boshqa hech qachon
   ko‘rsatilmaydi — interfeys faqat kalit o‘rnatilgan-o‘rnatilmaganini
   bildiradi.

Provayder xavfini kuzatish uchun SLA va xavf balini ham belgilashingiz
mumkin.

---

## 4. Siyosat markazi (Policy Center)

Siyosatlar nimaga ruxsat berilishini va promptlar qanday
filtrlanishini belgilaydi.

1. Yon menyu → **Policies → Policy Center** → **New policy**.
2. Siyosatni oching va **versiya yarating**. Versiya JSON qoidalarini
   saqlaydi: maskalash sozlamalari va **bloklangan atamalar** ro‘yxati.
3. Versiyani **tasdiqlang** (Approve) — shunda u faollashadi. Versiyalar
   o‘zgarmasdir — qoidalarni o‘zgartirish uchun yangi versiya yaratib,
   uni tasdiqlang.
4. Faol versiyani **foydalanish holati (use case)** ga bog‘lang.

**Prompt Firewall:** so‘rov siyosat asosida ishlaganda, PII (elektron
pochta, karta raqamlari, SSN, telefon raqamlari, IP manzillar, API
kalitlar) saqlashdan va provayderga yuborishdan oldin maskalanadi.
Bloklangan atamani o‘z ichiga olgan har qanday prompt rad etiladi va
yuborilmaydi.

---

## 5. Foydalanish holatlari (Use Cases)

Foydalanish holati maqsad, xavf darajasi va tasdiqlangan siyosat
versiyasini birlashtiradi.

1. Yon menyu → **Policies → Use Cases** → **New use case**.
2. Nom, xavf darajasi va (ixtiyoriy) tasdiqlangan siyosat versiyasi hamda
   egasini belgilang.

---

## 6. Foydalanish reyestri va tasdiqlash

- **Usage Registry** har bir AI so‘rovini maqsadi, holati va to‘liq
  so‘rov → javob izi bilan ko‘rsatadi.
- Agar so‘rov tasdiqlashni talab qilsa, u **Approval Workflow**da
  paydo bo‘ladi. Tasdiqlovchilar uni ochib, sabab bilan **Approve** yoki
  **Reject** qiladi. Barcha qarorlar auditga yoziladi.
- **Overrides** administratorga zarur bo‘lganda so‘rovni qo‘lda
  to‘xtatish, tahrirlash yoki orqaga qaytarish imkonini beradi.

---

## 7. Hodisalar kuzatuvchisi (Incident Tracker)

1. Yon menyu → **Audit → Incident Tracker**.
2. Hodisalar qo‘lda yoki avtomatik yaratilishi mumkin (masalan,
   bloklangan AI domeni aniqlanganda — Shadow AI Monitorga qarang).
3. Hodisani **Open → Investigating → Resolved** bosqichlaridan o‘tkazing
   va asosiy sababni yozing. Hammasi auditga yoziladi.

---

## 8. Shadow AI Monitor

Shadow AI Monitor tashkilotingizdagi ruxsatsiz AI foydalanishini
aniqlaydi. Ma’lumot uch manbadan keladi — **endpoint agenti**,
**brauzer kengaytmasi** va **tarmoq kashfiyoti** — va ularning barchasi
yagona **Sightings** ro‘yxatini to‘ldiradi.

### 8.1 Telemetriya manbalari (mashina kalitlari)

Kollektorlar foydalanuvchi hisobi bilan emas, mashina kaliti bilan
autentifikatsiya qiladi.

1. Yon menyu → **Discovery → Ingestion Sources** (faqat admin).
2. **New source** → turini tanlang (Gateway, Endpoint agent, Browser
   extension) va nom bering.
3. **Telemetriya kaliti faqat bir marta ko‘rsatiladi** — uni hozir
   nusxalab oling. U hesh ko‘rinishida saqlanadi va keyin qayta olib
   bo‘lmaydi. Yo‘qotsangiz, manbani bekor qilib, yangisini yarating.

### 8.2 AI domenlar katalogi

Katalog aniqlangan domen qanday qayta ishlanishini belgilaydi.

1. Yon menyu → **Discovery → AI Domain Catalog** (faqat admin).
2. Domen qo‘shing va siyosatini belgilang: **Allowed** (faqat qayd
   etiladi), **Blocked** (avtomatik hodisa yaratadi) yoki **Unknown**
   (ko‘rib chiqish uchun signal yaratadi). Katalogda yo‘q har qanday
   narsa Unknown deb hisoblanadi.
3. Mashhur domen (masalan, `chat.openai.com`) yozganingizda, forma vosita
   nomi va kategoriyasini avtomatik to‘ldirishni taklif qiladi.

### 8.3 Sightings (aniqlangan holatlar)

Yon menyu → **Discovery → Shadow AI Sightings**. Har bir yozuv vositani, manbani
(brauzer kengaytmasi, endpoint agenti, lokal jarayon/tarmoq/model fayli
yoki qo‘lda), ma’lum bo‘lsa xodim haqidagi malumotni, holatni va
takroriy aniqlashlar uchun "seen N times" hisoblagichini ko‘rsatadi. Har
biri uchun siz:

- uni ko‘rib chiqish uchun **Take** qilishingiz,
- **Register** orqali sanksiyalangan provayderga aylantirishingiz (haqiqiy
  ulanishga aylanadi),
- **Dismiss** qilishingiz mumkin.

Shuningdek, **Report a sighting** orqali qo‘lda ham qo‘shishingiz mumkin.

### 8.4 Endpoint agentini joylashtirish

Agent — bu kuzatmoqchi bo‘lgan mashinaga (server yoki MDM orqali xodim
kompyuteriga) o‘rnatiladigan kichik native dastur. U lokal AI
vositalarini (ishlayotgan jarayonlar, tinglayotgan portlar, model
fayllari) aniqlaydi va yoqilgan bo‘lsa, tarmoq xizmatlarini kashf qiladi.

1. *Endpoint agent* turidagi **Ingestion Source** yarating va kalitni
   nusxalang.
2. Kalit va server manzilini agentning `config.json` fayliga kiriting
   (`agent/config.example.json` ga qarang), so‘ng uni yig‘ing va ishga
   tushiring — to‘liq bosqichlar [README](README.md#7-endpoint-agent-optional)
   da.
3. Yangi topilmalar bir daqiqa ichida paydo bo‘ladi: lokal AI vositalari
   **Discovery → Shadow AI Sightings**da, AI agentlar **Discovery →
   Agents Found**da, mashinaning o‘zi esa **Discovery → Devices**da.

### 8.4.1 Topilgan agentlar va qurilmalar

Endpoint agent (v1.2.0 yoki yangiroq) mashinada ishlayotgan AI
agentlarni taniydi — kod agentlari (Claude Code, Cursor, GitHub Copilot,
Codex CLI, Gemini CLI, Aider, …), agent freymvorklari (CrewAI,
LangGraph, AutoGen Studio, Letta) va agent platformalari (n8n, Flowise,
Langflow). U faqat qaysi mahsulot topilganini va qanday tanilganini
yuboradi; API kalitlari bo‘lishi mumkin bo‘lgan jarayon buyruq qatori
mashinadan hech qachon chiqmaydi.

- **Discovery → Agents Found** har bir agentni qurilma bo‘yicha
  ko‘rsatadi, ko‘rib chiqilishi kerak bo‘lganlar birinchi. **Register**
  agentni ro‘yxatdan o‘tkazish formasini nom va tur bilan to‘ldirib
  ochadi; ro‘yxatdan o‘tgach topilma boshqariladigan agentga bog‘lanadi
  va uning siyosatlari ostiga o‘tadi. **Ignore** topilmani yashiradi
  (keyin qaytarish mumkin).
- **Discovery → Devices** hisobot beradigan barcha kompyuter va
  brauzerlarni ko‘rsatadi: foydalanuvchi, OT, kollektor versiyasi,
  oxirgi faollik va unda topilgan agentlar. Bir kun jim bo‘lgan qurilma
  *quiet* deb belgilanadi.

Tanilgan mahsulot bo‘lmagan agentlar — kompaniyaning o‘z botlari va
skriptlari — xatti-harakati bo‘yicha topiladi (endpoint agent v1.3.0 yoki
yangiroq) va ishlayotgan skript yoki dastur nomi bilan **Tanilmagan
agent** sifatida ko‘rsatiladi:

- jarayon LLM API bilan ulangan (OpenAI, Anthropic, Google Gemini,
  Mistral, Groq, DeepSeek, OpenRouter, AWS Bedrock, …);
- yoki unda LLM SDK yuklangan (OpenAI / Anthropic Python SDK, tiktoken,
  Hugging Face tokenizers).

Muhitdagi LLM API kalit o‘zgaruvchilari (`OPENAI_API_KEY`, …) ishonchni
oshiradi; faqat ularning nomlari yuboriladi, qiymatlari hech qachon.
Faqat API ulanishi asosidagi topilma *o‘rtacha ishonchli*: ba’zi
provayderlar CDN manzillarini boshqa saytlar bilan bo‘lishadi. Mashinadagi
barcha foydalanuvchilar jarayonlarini ko‘rish uchun endpoint agentni root
sifatida ishga tushiring; oddiy foydalanuvchi sifatida u faqat o‘sha
foydalanuvchi jarayonlarini ko‘radi. Xuddi shu mashinadagi LLMga ataylab
murojaat qiladigan xizmatlar (masalan, Provenzaning o‘z backendi) ham bu
yerda paydo bo‘ladi — ularni bir marta e’tiborsiz qoldiring.

Ikkala sahifa adminlar va tasdiqlovchilarga ko‘rinadi; topilmalarni
faqat adminlar ro‘yxatdan o‘tkazadi yoki e’tiborsiz qoldiradi.

### 8.5 Brauzer kengaytmasini joylashtirish

1. **Ingestion Sources** sahifasida **Download extension** tugmasini
   bosing. Server kengaytmani sizning server manzilingiz va
   tashkilotingiz uchun yangi kalit bilan oldindan sozlab paketlaydi.
2. Yuklab olingan `.zip` faylni xodimlarga tarqating (yoki Chrome
   siyosati / MDM orqali joylashtiring).
3. Qo‘lda o‘rnatish: arxivdan chiqaring, `chrome://extensions` oching,
   **Developer mode**ni yoqing, **Load unpacked** bosing va arxivdan
   chiqarilgan papkani tanlang.

Kengaytma foydalanuvchi maxfiy ma’lumotlarni (API kalitlar, karta
raqamlari, maxfiy kalitlar) tanilgan AI vositasiga joylashtirish yoki
yozishdan oldin sahifada ogohlantiradi va urinish sodir bo‘lganini
xabar qiladi — lekin maxfiy ma’lumotning o‘zini **hech qachon**
yubormaydi.

---

## 9. Tarmoq kashfiyoti (aniq ulanish)

Yon menyu → **Discovery → Network Discovery** (faqat admin).

Endpoint agenti kashfiyot yoqilgan holda ishlaganda, u tarmoq
xizmatlarini **passiv** ravishda topadi (DNS, shlyuz, Active Directory
va — tegishli ruxsatlar bilan — ARP orqali hostlar hamda DHCP
serverlar). Ular bu yerda faqat o‘qish uchun kuzatuvlar sifatida paydo
bo‘ladi.

**Hech narsa avtomatik ulanmaydi.** Aniqlangan xizmatga ulanish uchun
(masalan, Active Directory’dan foydalanuvchilarni o‘qish) **Connect**
tugmasini bosing va aynan shu xizmat uchun faqat o‘qish huquqli hisob
ma’lumotlarini kiriting. Agar xizmat turi uchun hali konnektor bo‘lmasa,
platforma ulanganday ko‘rsatmaydi, balki buni aniq aytadi. Keraksiz
xizmatlarni **Ignore** qilishingiz ham mumkin.

---

## 10. Bildirishnomalar

Yon menyu → **Settings → Notifications**. **Email** yoki **webhook**
kanallarini qo‘shing va har birini o‘zingizga kerakli hodisalarga obuna
qiling (`incident_created`, `approval_pending`, `request_blocked`,
`shadow_ai_reported`, `shadow_ai_blocked_domain` va boshqalar). Agar
serverda email (SMTP) sozlanmagan bo‘lsa, email kanallari jimgina
o‘tkazib yuboriladi; webhooklar doim ishlaydi.

---

## 11. Audit va hisobot

Yon menyu → **Audit → Audit Log**. Platforma orqali qilingan har bir
o‘zgarish — kim, nimani, qaysi obyektga, qachon qilgani — filtrlash va
ko‘rib chiqish mumkin bo‘lgan faqat qo‘shiladigan jurnalga yoziladi.

---

## 12. Maslahatlar

- **Domenlar katalogini dolzarb saqlang** — aynan u xom telemetriyani
  mazmunli "allowed / blocked / unknown" signallariga aylantiradi.
- **Har bir kollektor joylashtiruvi uchun bitta telemetriya manbasi** —
  shunda bitta agent yoki kengaytma tarqatuvini boshqalarga ta’sir
  qilmasdan bekor qila olasiz.
- **Sightings’ni muntazam ko‘rib chiqing** va ularni sanksiyalang
  (Register) yoki Dismiss qiling, shunda "Active" bo‘limi faqat hali
  e’tibor talab qiladiganlarni aks ettiradi.
- **Eng kam imtiyoz** — endpoint agentiga `CAP_NET_RAW`ni faqat ARP/DHCP
  kashfiyotini xohlasangiz bering; qolgan hammasi busiz ham ishlaydi.
