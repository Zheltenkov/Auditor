# Bash skriptlar, 7-qism: awk ma'lumotlarni qayta ishlash tili

awk utilitasi, yoki aniqrog'i GNU awk, sed bilan solishtirganda, ma'lumotlar oqimini qayta ishlashni yanada yuqoriroq darajaga olib chiqadi. awk tufayli bizda muharrirga beriluvchi oddiy buyruqlar to'plami emas, balki dasturlash tili mavjud. awk dasturlash tilidan foydalanib, quyidagilarni amalga oshirishingiz mumkin:
- Ma'lumotlarni saqlash uchun o'zgaruvchilarni e'lon qilish.
- Ma'lumotlar bilan ishlash uchun arifmetik va satr operatorlaridan foydalanish.
- Ma'lumotlarni qayta ishlashning murakkab algoritmlarini amalga oshirish imkonini beruvchi if-then operatori va sikllar kabi tizimli elementlar va tilning boshqaruv tuzilmalaridan foydalanish.
- Formatlangan hisobotlarni yaratish.

awk utilitasi juda ko'p imkoniyatlarni taqdim etadi, chunki u to'liq dasturlash tillariga xos bo'lgan ko'plab konstruksiyalarni o'z ichiga oladi, masalan, shartli operatolar, sikllar, foydalanuvchi o'zgaruvchilari va funksiyalari va boshqalar. Biroq, bu utilita bilan ishlashning mohiyatini ko'rsatish uchun bu yerda faqat qisqacha misol tasvirlangan.

Agar biz faqat o'qish va tahlil qilish uchun qulay bo'lgan formatlangan hisobotlarni yaratish imkoniyati haqida gapiradigan bo'lsak, bu log fayllar bilan ishlashda juda foydali bo'ladi.

awk chaqiruvi sxemasi quyidagicha ko'rinadi:
```shell
awk options program file
```

Awk unga kelgan ma'lumotlarni yozuvlar to'plami sifatida qabul qiladi. Yozuvlar – bu maydonlar to'plami. Oddiy qilib aytganda, agar awk-ning sozlash imkoniyatlari hisobga olinmasa va satrlari yangi satrga o’tish belgilari bilan ajratilgan mutlaqo oddiy matn haqida gapirilsa, yozuv – bu satrdir. Maydon – bu satrdagi so'z.

### Pozitsion o'zgaruvchilar

awk da o'zgaruvchilar bilan ishlash bash da buyruq satri parametrlari bilan ishlashga o'xshaydi. Asl sozlamalar bo’yicha awk, u tomonidan yozuvda uchratiladigan har bir ma'lumot maydoniga quyidagi o'zgaruvchilarni tayinlaydi:
- $0 – matnning butun satrini ifodalaydi (yozuv).
- $1 – birinchi maydon.
- $2 – ikkinchi maydon.
- $n — n-maydon.

Maydonlar matndan ajratuvchi belgi yordamida ajratiladi. Asl sozlamalar bo’yicha, ular probel yoki tabulyatsiya belgisi kabi probel belgilaridir.

### Bir nechta buyruqlardan foydalanish

Awk ko'p satrli skriptlar yordamida ma'lumotlarni qayta ishlash imkonini beradi. Konsoldan uni chaqirishda awk-ga ko'p satrli buyruq berish uchun uning qismlarini nuqtali vergul bilan ajratish kerak:
```shell
echo "My name is Tom" |
awk '{
$4="Adam";
print $0
}'
```

Ushbu misolda birinchi buyruq yangi qiymatni $4 o'zgaruvchisiga yozadi va ikkinchi buyruq butun satrni ekranga chiqaradi. Skript ishining natijasi:
```shell
My name is Adam
```

### Formatlangan ma'lumotlar chiqishi

awk-dagi printf buyrug'i formatlash spetsifikatorlari yordamida formatlangan ma'lumotlarni chiqarish imkonini beradi.

Formatlash spetsifikatorlari quyidagicha yoziladi:
```shell
%[modifier]control-letter
```

Mana ulardan ba'zilari:
- c – unga uzatilgan raqamni ASCII belgisining kodi sifatida qabul qiladi va bu belgini chiqaradi.
- d — oʻnlik butun sonni chiqaradi.
- i – d bilan bir xil.
- e — sonni eksponensial shaklda chiqaradi.
- f — suzuvchi vergulli raqamni chiqaradi.
- g — raqamni eksponensial yozuv yoki suzuvchi vergul formatida, qaysi biri qisqaroq bo'lishiga qarab, chiqaradi.
- o — raqamning sakkizlik ko'rinishini chiqaradi.
- s — matnli satrni chiqaradi.

printf yordamida chiqish ma’lumotlarini formatlashga misol:
```shell
awk 'BEGIN{
x = 100 * 100
printf "The result is: %e\n", x
}'
```
