## Kombinatsiyalangan jurnal formati

Jurnal fayllari bilan bog'liq asosiy muammo shundaki, ular odatda strukturali bo’lmagan matnli ma'lumotlar bo'lib, ularda foydali ma'lumotlarni topishni qiyin kechadi. Shuning uchun ularning strukturaliligiga ehtiyoj bor.

Jurnal formati – jurnallarni osongina tahlil qilish va mashina usulida o'qish imkonini beruvchi strukturalashtirilgan formatdir. Bu strukturalashtirilgan jurnallar va ularni qo'llab-quvvatlaydigan jurnallarni boshqarish tizimidan foydalanishning afzalligidir.

Kombinatsiyalangan jurnal formati veb-saytlarga kirishni kuzatish uchun bir qator veb-serverlar tomonidan qo'llaniladigan standart jurnal formatidir.

Format quyidagi ifoda bilan aniqlanadi:
```
"%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-agent}i\""
```

U probellar bilan ajratilgan quyidagi maydonlardan iborat:

- Sayt foydalanuvchisining xost nomi yoki IP manzili.

- RFC 1413 mijoz identifikatori. Ishonchsiz deb hisoblanadi va odatda bo'sh bo’ladi (faylda chiziqcha (-) bilan ko'rsatiladi).

- Hujjatga kiruvchi foydalanuvchining nomi. Foydalanuvchi kirish huquqiga ega bo'lmagan ommaviy veb-saytlar uchun chiziqcha bilan belgilanadi.

- Kvadrat qavs ichiga olingan vaqt belgisi satri, masalan *[12/Dec/2012:12:12:12 -0500]*.

- Ikkitalik qo’shtirnoq ichida HTTP so'rovi, masalan, *"GET /stuff.html HTTP/1.1"*.

- HTTP holat kodi.

- So'ralgan obyektda uzatilgan baytlar soni.

- Foydalanuvchini saytga olib kelgan URL manzili (ikkitalik qo’shtirnoq ichida).

- Mijoz tomonidan yuborilgan foydalanuvchi agenti satri (ikkitalik qo’shtirnoq ichida). Ishlatilayotgan brauzerni aniqlash uchun foydalanish mumkin.
