# Bash skriptlar, 6-qism: sed va matnni qayta ishlash

### Lirik chekinish – bashdagi konveyer

Pipe (konveyer) – jarayonlararo aloqa uchun bir yo'nalishli kanaldir. Konveyerlar ko'pincha shell skriptlarda I konveyer belgisi yordamida bir buyruqning chiqishini (stdout) keyingisining kirishiga (stdin) yo'naltirish orqali bir nechta buyruqlarni bog'lash uchun ishlatiladi:
```shell
cmd1 | cmd2 | .... | cmdN
```

Masalan:
```shell
index=$(echo $arg | cut -f1 -d=)
val=$(echo $arg | cut -f2 -d=)
```

Agar matnning bir qismini kesib tashlash kerak bo'lsa, `cut` buyrug'i ishlatiladi. `f` kaliti kesilishi kerak bo'lgan maydonlar ro'yxatini belgilaydi. `d` kaliti maydonlar orasidagi ajratgichni o'rnatadi.

Shunday qilib, agar `arg` o'zgaruvchisi, masalan, `"X=45"` qatorini o'z ichiga olsa, u holda `X` indeks o'zgaruvchiga, `45` esa valga yoziladi.

Bundan tashqari, konveyerdan foydalanib, oldingi buyruqdan olingan massivni qulay tarzda saralash mumkin.

### sed bilan ishlash asoslari

sed utilitasi oqimli matn muharriri deb ataladi. Sed ishlab chiquvchi tomonidan belgilangan qoidalar to'plami asosida ma'lumotlar oqimini tahrirlash imkonini beradi. Bu buyruqni chaqirish sxemasi quyidagicha ko’rinadi:
```shell
sed options file
```

Asl sozlamalar bo’yicha, sed chaqirilganda ko’rsatilgan buyruqlar to'plami sifatida ifodalangan qoidalarni STDINga qo'llaydi. Bu ma'lumotlarni to'g'ridan-to'g'ri sed-ga o'tkazish imkonini beradi. Masalan:
```shell
echo "This is a test" |
sed 's/test/another test/'
```

Bu holda, sed qayta ishlash uchun o'tgan qatordagi "test" so'zini "another test" so'zlari bilan almashtiradi. Bizning holatimizda `s/pattern1/pattern2/` ko’rinishidagi buyruqdan foydalanildi. "s" harfi "substitute" so'zining qisqartmasi bo’lib, almashtirish buyrug'i degan ma’noni anglatadi. Sed, ushbu buyruqni bajarayotganda, yuborilgan matnni ko'rib chiqadi va undagi pattern1 ga mos keladigan topilgan fragmentlarni pattern2 bilan almashtiradi.

Ma'lumotlar bilan bir nechta amallarni bajarish uchun sed ni chaqirishda -e kalitidan foydalaning. Masalan, ikkita matn bo'lagini almashtirishni quyidagicha tashkil qilish kerak:
```shell
sed -e 's/This/That/; s/test/another test/'
```

sed shuningdek, massivlarni qulay qayta ishlash uchun buyruqlarga ega, masalan, faqat ma'lum miqdordagi elementlarni qoldirish yoki element raqamlarini tartibga solish.

### Qayta ishlash uchun matn qismlarini tanlash

Yana bir misol keltiramiz. Ba'zi hollarda, sed yordamida matnning faqat bir qismini - ma'lum bir satr yoki satrlar guruhini qayta ishlash kerak. Ushbu maqsadga erishish uchun qayta ishlanuvchi qatorlar soniga cheklov qo'yish mumkin.

myfile tarkibi:
```
This is a test.
This is the second test.
This is the third test.
This is the fourth test.
```

Qayta ishlanishi kerak bo'lgan bitta satr raqamini ko'rsatishni nazarda tutuvchi misolni ko'rib chiqamiz:
```shell
sed '2s/test/another test/' myfile
```

Skript ishining natijasi:
```
This is a test.
This is the second another test.
This is the third test.
This is the fourth test.
```

Ikkinchi variant – satrlar diapazoni:
```shell
sed '2,3s/test/another test/' myfile
```

Ish natijasi:
```
This is a test.
This is the second another test.
This is the third another test.
This is the fourth test.
```

Bundan tashqari, fayl ma'lum bir satrdan oxirigacha qayta ishlanishi uchun almashtirish buyrug'ini chaqirish mumkin. Buning uchun "$" belgisidan foydalaniladi:
```shell
sed '2,$s/test/another test/' myfile
```

Natija:
```
This is a test.
This is the second another test.
This is the third another test.
This is the fourth another test.
```
