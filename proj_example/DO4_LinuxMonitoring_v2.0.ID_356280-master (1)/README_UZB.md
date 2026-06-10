# LinuxMonitoring v2.0

Real vaqt rejimida tizim holatini monitoring qilish va o'rganish.

💡 Ushbu loyiha bo’yicha fikr-mulohazalaringizni biz bilan baham ko’rish uchun [**shu yerni bosing**](https://new.oprosso.net/p/4cb31ec3f47a4596bc758ea1861fb624). Bu anonim va jamoamizga mashg'ulotlarni yaxshilashga yordam beradi. Loyihani tugatgandan so'ng darhol so'rovnomani to'ldirishni tavsiya qilamiz.

## Contents

1. [Chapter I](#chapter-i) 
2. [Chapter II](#chapter-ii) \
    2.1. [GoAccess](#goaccess) \
    2.2. [Prometheus](#prometheus) \
    2.3. [Grafana](#grafana)
3. [Chapter III](#chapter-iii) \
    3.1. [Fayllar generatori](#part-1-fayllar-generatori)  
    3.2. [Fayl tizimining tiqilishi](#part-2-fayl-tizimining-tiqilishi)  
    3.3. [Fayl tiziminibtozalash](#part-3-fayl-tizimini-tozalash)  
    3.4. [Loglar-generatori](#part-4-loglar-generatori)  
    3.5. [Monitoring](#part-5-monitoring)  
    3.6. [GoAccess](#part-6-goaccess)  
    3.7. [Prometheus va Grafana](#part-7-prometheus-va-grafana)  
    3.8. [Tayyor dashbord](#part-8-tayyor-dashbord)  
    3.9. [Qo'shimcha. Sizning node_exporter](#part-9-qoshimcha-sizning-node_exporter)  


## Chapter I

![linux_monitoringv2.0](misc/images/linux_monitoringv2.0.png)

Yer sayyorasi, hozirgi kunlar.

Ish kunining boshidayoq Jon (ya'ni, ushbu loyihani qabul qilgan ekansiz, siz) boshqarmaga chaqirildi. U yerda sizga do'stingiz Sebning to'rt kundan beri ishga kelmayotgani va u vazifani bajarishga ulgurmasligi ehtimoli borligi haqida xabar berildi. Shuning uchun, sizga, zarur bo’lganda ishyoqmas o'rtog’ingizni almashtirishingiz mumkin bo’lishi uchun Linuksda monitoring bilan shug'ullanish topshirildi.
Siz Sebning kabinetiga kirib, uning kompyuteri oldiga o'tirdingiz va darhol shubhali qisqa eslatma faylini ochdingiz. Afsuski, Seb to'plagan ma'lumotlarni o'rganar ekansiz, siz dam olish xonasida qoldirgan mazali tushlik haqida o'ylashni hecham to’xtatolmadingiz ...

## Chapter II

### **GoAccess**

Vaqt qatoridagi ma'lumotlar bazalari, nomidan ko'rinib turibdiki, vaqt bilan bog'liq ma'lumotlarni qayta ishlash uchun maxsus mo'ljallangan ma'lumotlar bazasi tizimlari demakdir.

Aksariyat tizimlar jadvalga asoslangan relyatsion ma'lumotlar bazalaridan foydalanadi. Vaqt qatoridagi ma'lumotlar bazalari boshqacha ishlaydi. Ma'lumotlar hali ham "to'plamlar" da saqlanadi, ammo bu to'plamlar umumiy maxrajga ega: ular vaqt o'tishi bilan jamlanadi. Aslida, bu saqlanishi mumkin bo'lgan har bir nuqta uchun u bilan bog'liq vaqt belgisi mavjudligini anglatadi.

Prometheus – bu vaqt qatoridagi ma'lumotlar bazasi bo'lib, uning funksionalligini kengaytirish uchun asboblarning butun ekotizimi unga biriktirilishi mumkin. \
Prometheus turli xil tizimlarni kuzatish uchun yaratilgan: serverlar, ma'lumotlar bazalari, alohida virtual mashinalar, deyarli hamma narsa.

### **Grafana**

Grafana – bu ma'lumotlarni vizualizatsiya qilish, monitoring qilish va tahlil qilish uchun platforma. Grafana foydalanuvchilarga panellarga ega dashbordlar yaratish imkonini beradi, ularning har biri ma'lum vaqt oralig'ida o'ziga xos ko'rsatkichlarni aks ettiradi. Har bir dashbord universaldir, shuning uchun uni ma'lum bir loyiha uchun moslashtirish mumkin.

*Panel* – tanlangan ko'rsatkichlarni vizualizatsiya qilishning asosiy elementidir.

*Dashbord* – o'zgaruvchilar to'plamiga (masalan, server, ilova nomi va boshqalar) ega bo’lgan panjara ichida joylashgan alohida panellar to'plami.

## Chapter III

- Yozilgan Bash skriptlar src papkasida joylashgan bo'lishi kerak;
- Har bir topshiriq uchun quyidagi nomli papka yaratilishi kerak: **Ox**, bunda x – topshiriq raqami;
- Barcha skriptlar dekompozitsiyalanishi va bir nechta fayllarga bo'linishi kerak;
- Har bir vazifa uchun asosiy ssenariyga ega fayl **main.sh** deb nomlanishi kerak;
- Barcha skriptlar noto'g'ri kiritilganligini (barcha parametrlar ko'rsatilmaganligi, noto'g'ri formatlangan parametrlar borligi va h.k.) tekshirishni nazarda tutishi kerak; 
- Barcha yozilgan skriptlar *Ubuntu Server 24.04 LTS* virtual mashinasida ishga tushirilishi kerak.

## Part 1. Fayllar generatori

Sebning kompyuterida topilgan ma'lumotlarni qisqacha o'rganib chiqqaningizdan so'ng, siz dam olish xonasiga kirdingiz va siz uydan maxsus olib kelgan mazali sendvichingizni Mayk olganini aniqladingiz.
Buni shunchaki qoldirib bo'lmaydi – endi siz bunga javob sifatida uning ustidan kulishingiz va unga saboq berib qo’yishingiz kerak.
Shu bilan birga, siz yana bir bor bash skriptlarida fayllar bilan ishlashni mashq qilishingiz mumkin. Bu faqat monitoring vazifalarini sozlash uchun sinov muhitini tayyorlashda ayniqsa foydali bo'lishi mumkin.

**== Topshiriq ==**

Bash skript yozing. Skript 6 ta parametr bilan ishga tushiriladi. Skriptni ishga tushirishga misol: \
`main.sh /opt/test 4 az 5 az.az 3kb` 

**Parametr 1** – mutlaq yo'l. \
**Parametr 2** – qo’shilgan papkalar soni. \
**Parametr 3** – papka nomlarida qo'llaniladigan ingliz alifbosi harflari ro'yxati (7 belgidan oshmasligi kerak). /
**Parametr 4** – har bir yaratilgan papkadagi fayllar soni. /
**Parametr 5** – fayl nomi va kengaytmasida ishlatiladigan inglizcha harflar ro'yxati (nom uchun 7 belgidan, kengaytma uchun 3 belgidan oshmasligi kerak). /
**Parametr 6** – fayl hajmi (kilobaytlarda, lekin 100 dan oshmasligi kerak).

Papka va fayl nomlari faqat parametrlarda ko'rsatilgan harflardan iborat bo'lishi va ularning har biri kamida bir marta ishlatilishi kerak.

Nomning ushbu qismi uzunligi kamida to'rtta belgidan, shuningdek, pastki chiziq bilan ajratilgan DDMMYY formatidagi skriptni ishga tushirish sanasidan iborat bo'lishi kerak, masalan: \
**./aaaz_021121/**, **./aaazzzz_021121** 

Bundan tashqari, agar papkalar yoki fayllar nomlari uchun `az` belgilar berilgan bo'lsa, u holda fayl yoki papkalar nomlarida teskari yozuv bo'lishi mumkin emas: \
**./zaaa_021121/**, ya'ni parametrdagi ko'rsatilgan belgilar tartibi saqlanishi kerak.

Skriptni 1-parametrda ko'rsatilgan joyda ishga tushirishda ulardagi tegishli nomlar va o'lchamlarga ega papkalar va fayllar yaratilishi kerak.
Fayl tizimida 1 GB bo'sh joy qolsa (/ bo'limida) skript ishlashni to'xtatishi kerak.
Barcha yaratilgan papkalar va fayllar (to'liq yo'l, yaratilgan sana, fayllar uchun o'lcham) ma'lumotlariga ega bo’lgan log-fayl yozing.

## Part 2. Fayl tizimining tiqilishi

Ana endi Maykga sendvichidan mahrum qilingan odam nimalarga qodirligini ko'rsatish vaqti keldi.  

**== Topshiriq ==**

Bash skriptini yozing. Skript 3 parametr bilan ishlaydi. Skriptni ishga tushirish misoli: \
`main.sh az az.az 3Mb`

**Parametr 1** – papka nomlarida qo'llaniladigan ingliz alifbosi harflari ro'yxati (7 belgidan oshmasligi kerak). \
**Parametr 2** – fayl nomi va kengaytmasida ishlatiladigan inglizcha harflar ro'yxati (nom uchun 7 belgidan, kengaytma uchun 3 belgidan oshmasligi kerak). \
**Parametr 3** – fayl hajmi (Megabaytlarda, lekin 100 dan oshmasligi kerak).

Papka va fayl nomlari faqat parametrlarda ko'rsatilgan harflardan iborat bo'lishi va ularning har biri kamida bir marta ishlatilishi kerak.
Nomning ushbu qismi uzunligi kamida 5 belgidan, shuningdek, pastki chiziq bilan ajratilgan DDMMYY formatidagi skriptni ishga tushirish sanasidan iborat bo'lishi kerak, masalan: \
**./aaazz_021121/**, **./aaazzzz_021121** 

Bundan tashqari, agar papkalar yoki fayllar nomlari uchun `az` belgilar berilgan bo'lsa, u holda fayl yoki papkalar nomlarida teskari yozuv bo'lishi mumkin emas: **./zaaa_021121/**, ya'ni parametrdagi ko'rsatilgan belgilar tartibi saqlanishi kerak.

Skriptni ishga tushirishda fayl tizimidagi turli xil joylarda (**bin** yoki **sbin** ni o'z ichiga olgan yo'llardan tashqari) fayllarga ega papkalar yaratilishi kerak. Qo’yilgan papkalar soni – 100 tagacha. Har bir papkadagi fayllar soni – tasodifiy son (har bir papka uchun har xil).
Fayl tizimida 1 GB bo'sh joy qolganda (/ bo'limida) skript ishlashni to'xtatishi kerak.
Quyidagi buyruq bilan fayl tizimidagi bo'sh joyni aniqlash mumkin: `df -h /` 

Barcha yaratilgan papkalar va fayllar (to'liq yo'l, yaratilgan sana, fayllar uchun o'lcham) ma'lumotlariga ega log faylini yozing.
Skript ishi oxirida script ishining boshlanish vaqtini, tugash vaqtini va uning ishlashining umumiy vaqtini ekranga chiqaring. Ushbu ma'lumotlar bilan log faylini to’ldiring.

## Part 3. Fayl tizimini tozalash

Jin ursin! Siz skriptni noto'g'ri kompyuterda ishga tushirdingiz. Endi siz zudlik bilan hammasini tuzatadigan skript yozishingiz kerak ...

**== Topshiriq ==**

Bash skript yozing. Skript 1 parametr bilan ishga tushiriladi. Skript [Part 2](#part-2-fayl-tizimining-tiqilishi) da yaratilgan papkalar va fayllar tizimini 3 usulda tozalashi kerak:

1. Log fayli bo'yicha
2. Yaratilgan sana va vaqt bo'yicha
3. Nom maskasi bo'yicha (ya'ni, belgilar, pastki chiziq va sana). 

Tozalash usuli skriptni ishga tushirishda 1, 2 yoki 3 qiymatiga ega parametr sifatida beriladi.

*Yaratilgan sana va vaqt bo'yicha o'chirishda foydalanuvchi boshlanish va tugash vaqtlarini daqiqagacha aniqlikda kiritadi. Belgilangan vaqt oralig'ida yaratilgan barcha fayllar o'chiriladi. Kirish parametrlar orqali yoki dasturni bajarish jarayonida amalga oshirilishi mumkin.*

## Part 4. Loglar generatori

Nihoyat ishlaringizni tugatib, monitoring bilan shug'ullanishni davom ettirishga tayyorsiz.

Boshlanishida tahlil qilinishi mumkin bo’lgan loglarni yaratish yaxshi bo’lgan bo’lardi.

**== Topshiriq ==**

*combined* formatida 5 ta **nginx** log faylini yaratadigan bash skript yoki C dasturini yozing. Har bir logda bir kunlik ma'lumotlar bo'lishi kerak.

Kuniga 100 dan 1000 gacha bo'lgan tasodifiy sonlardagi qaydlar yaratilishi kerak, har bir yozuv uchun quyidagilar tasodifiy tarzda yaratilishi kerak:

1. IP (har qanday to'g'risi, ya'ni 999.111.777.777 kabi ip bo'lmasligi kerak)
2. Javob kodlari (200, 201, 400, 401, 403, 404, 500, 501, 502, 503)
3. Metodlar (GET, POST, PUT, PATCH, DELETE)
4. Sanalar (logning berilgan kuni doirasida, o'sish tartibida bo'lishi kerak)
5. Agent so'rovi URL si
6. Agentlar (Mozilla, Google Chrome, Opera, Safari, Internet Explorer, Microsoft Edge, Crawler and bot, Library and net tool)

Skript/dasturingizga izoharda, ishlatilgan javob kodlarining har biri nimani anglatishini ko'rsating.

## Part 5. Monitoring

Endi sizda tahlil qilish uchun fayllar bor ekan, siz to'g'ridan-to'g'ri monitoringga o'tishingiz mumkin.

**== Topshiriq ==**

**awk** orqali [Part 4](#part-4-loglar-generatori) nginx loglarini tahlil qilish uchun bash skriptni yozing.

Skript 1, 2, 3 yoki 4 qiymatini oladigan 1 parametr bilan ishlaydi.
Parametr qiymatiga qarab chiqish:

1. Javob kodi bo'yicha tartiblangan barcha yozuvlar;
2. Yozuvlarda uchraydigan barcha noyob IP-lar;
3. Xatolari bor barcha so'rovlar (javob kodi - 4xx yoki 5xx);
4. Noto'g'ri so'rovlar orasida yuzaga keladigan barcha noyob IP-lar.

## Part 6. **GoAccess**

Konsolda ish natijalariga qarash, albatta, yomon emas, lekin nima uchun qo'shimcha ravishda qulay interfeysni ta'minlaydigan tayyor yechimdan foydalanmaslik kerak?

**== Topshiriq ==**

GoAccess utilitasidan foydalanib, [Part 5](#part-5-monitoring) kabi ma'lumotlarni oling.

Mahalliy mashinada utilitaning veb-interfeysini oching.

## Part 7. **Prometheus** va **Grafana**

Loglar bilan mashq qilish hozircha yakullandi. Endi butun tizimning holatini monitoring qilish vaqti keldi.

**== Topshiriq ==**

##### **Prometheus** va **Grafana**-ni virtual mashinaga o'rnating va sozlang.
##### Mahalliy mashinadan **Prometheus** va **Grafana** veb-interfeyslariga kiring.

##### **Grafana** dashbordiga markaziy protsessor ko’rsatilishi, mavjud operativ xotira, bo'sh joy va qattiq diskdagi kiritish-chiqarish operatsiyalari sonini qo'shing.

##### [Part 2](#part-2-fayl-tizimining-tiqilishi) bash skriptingizni ishga tushiring.
##### Qattiq diskdagi yukni ko'ring (diskdagi joy va o'qish/yozish operatsiyalari).

##### **stress** utilitasini o'rnating va buyruqni ishga tushiring `stress -c 2 -i 1 -m 1 --vm-bytes 32M -t 10s`
##### Qattiq diskdagi, operativ xotira va markaziy protsessordagi yukni ko'ring.

## Part 8. Tayyor dashbord 

Umuman olganda, agar aytilganidek, "bizgacha hamma narsa o'g'irlangan" bo'lsa, nega shaxsiy dashbordni yaratish kerak? Nega barcha kerakli metrikaga ega bo'lgan tayyor dashbordni olmaslik kerak ekan?

**== Topshiriq ==**

##### Rasmiy **Grafana Labs** saytidan tayyor *Node Exporter Quickstart and Dashboard* dashbordini o'rnating.

##### [Part 7](#part-7-prometheus-va-grafana) kabi testlarni bajaring.

##### Joriy tarmoq bilan bir xil tarmoqda joylashgan yana bir virtual mashinani ishga tushiring.
##### **iperf3** utilitasidan foydalanib, tarmoq yukini sinovdan o'tkazing.

##### Tarmoq interfeysi yuklanishiga qarang.

## Part 9. Qo'shimcha. Sizning **node_exporter**

Maxsus utilita yordamida tizimni tahlil qilish foydali va qulaydir, lekin siz har doim ular qanday ishlashini tushunishni xohlab kelgansiz.

**== Topshiriq ==**

Asosiy tizim metrikalari (parkaziy protsessor, operativ xotira, qattiq disk (hajmi)) haqida ma'lumot to'playdigan bash skript yoki C dasturini yozing. Skript yoki dastur **nginx** tomonidan beriladigan **Prometheus** formatida html sahifani shakllantirishi kerak. \
Sahifaning o'zi ham bash skripti yoki dasturida (siklda) yoki cron utilitasi yordamida yangilanishi mumkin, lekin har 3 soniyada bir martadan ko'p bo'lmasligi kerak.

##### **Prometheus** konfiguratsiya faylini o’zingiz yaratgan sahifadan ma'lumot to'playdigan qilib o'zgartiring.

##### [Part 7](#part-7-prometheus-va-grafana) kabi testlarni o’tkazing.

