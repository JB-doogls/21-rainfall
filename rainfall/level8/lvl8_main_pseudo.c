int __cdecl main(int argc, const char **argv, const char **envp)
{
  char *v3; // eax
  bool v4; // cf
  bool v5; // zf
  signed int v6; // ecx
  char *v7; // esi
  const char *v8; // edi
  int v9; // eax
  bool v10; // cf
  bool v11; // zf
  unsigned int v12; // kr04_4
  signed int v13; // ecx
  char *v14; // esi
  const char *v15; // edi
  int v16; // eax
  bool v17; // cf
  bool v18; // zf
  signed int v19; // ecx
  char *v20; // esi
  const char *v21; // edi
  int v22; // eax
  bool v23; // cf
  bool v24; // zf
  signed int v25; // ecx
  char *v26; // esi
  const char *v27; // edi
  char s; // [esp+20h] [ebp-88h]
  _BYTE v30[3]; // [esp+25h] [ebp-83h]

  while ( 1 )
  {
    printf("%p, %p \n", auth, service);
    v3 = fgets(&s, 128, stdin);
    v4 = 0;
    v5 = v3 == 0;
    if ( !v3 )
      break;
    v6 = 5;
    v7 = &s;
    v8 = "auth ";
    do
    {
      if ( !v6 )
        break;
      v4 = (unsigned __int8)*v7 < *v8;
      v5 = *v7++ == *v8++;
      --v6;
    }
    while ( v5 );
    v9 = (char)((!v4 && !v5) - v4);
    v10 = 0;
    v11 = v9 == 0;
    if ( !v9 )
    {
      auth = (char *)malloc(4u);
      *(_DWORD *)auth = 0;
      v12 = strlen(v30) + 1;
      v10 = v12 - 1 < 0x1E;
      v11 = v12 == 31;
      if ( v12 - 1 <= 0x1E )
        strcpy(auth, v30);
    }
    v13 = 5;
    v14 = &s;
    v15 = "reset";
    do
    {
      if ( !v13 )
        break;
      v10 = (unsigned __int8)*v14 < *v15;
      v11 = *v14++ == *v15++;
      --v13;
    }
    while ( v11 );
    v16 = (char)((!v10 && !v11) - v10);
    v17 = 0;
    v18 = v16 == 0;
    if ( !v16 )
      free(auth);
    v19 = 6;
    v20 = &s;
    v21 = "service";
    do
    {
      if ( !v19 )
        break;
      v17 = (unsigned __int8)*v20 < *v21;
      v18 = *v20++ == *v21++;
      --v19;
    }
    while ( v18 );
    v22 = (char)((!v17 && !v18) - v17);
    v23 = 0;
    v24 = v22 == 0;
    if ( !v22 )
      service = (int)strdup(&v30[2]);
    v25 = 5;
    v26 = &s;
    v27 = "login";
    do
    {
      if ( !v25 )
        break;
      v23 = (unsigned __int8)*v26 < *v27;
      v24 = *v26++ == *v27++;
      --v25;
    }
    while ( v24 );
    if ( (!v23 && !v24) == v23 )
    {
      if ( *((_DWORD *)auth + 8) )
        system("/bin/sh");
      else
        fwrite("Password:\n", 1u, 0xAu, stdout);
    }
  }
  return 0;
}
