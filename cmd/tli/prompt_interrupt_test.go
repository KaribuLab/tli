package main

import (
	"os"
	"os/exec"
	"runtime"
	"testing"
)

func TestCLIPromptInterruptRestoresTerminal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("PTY regression requires Unix")
	}
	python, e := exec.LookPath("python3")
	if e != nil {
		t.Skip("Python stdlib PTY driver unavailable")
	}
	const driver = `import os,pty,select,signal,sys,time,termios
mode=sys.argv[2]
pid,fd=pty.fork()
if pid==0:
 env=dict(os.environ, TLI_TEST_CHILD='1',CI='false',GITHUB_ACTIONS='false',BITBUCKET_BUILD_NUMBER='',TERM='xterm')
 args=[sys.argv[1],'-test.run=^TestCLIProcess$','--']
 if mode=='password': args+=['setup']
 os.execve(sys.argv[1],args,env)
try:
 before=termios.tcgetattr(fd)
 output=b''
 deadline=time.monotonic()+5
 expected=b'Salir' if mode=='menu' else b'API Key:'
 while expected not in output and time.monotonic()<deadline:
  ready,_,_=select.select([fd],[],[],.1)
  if ready:
   try: output+=os.read(fd,4096)
   except OSError: break
  if mode=='password' and b'URL de su API:' in output and b'https://fixture.test' not in output:
   os.write(fd,b'https://fixture.test\nfixture\n')
 if expected not in output: raise RuntimeError('prompt not reached: '+repr(output))
 os.write(fd,b'\x03')
 deadline=time.monotonic()+2
 while time.monotonic()<deadline:
  done,status=os.waitpid(pid,os.WNOHANG)
  if done:
   after=termios.tcgetattr(fd)
   mask=termios.ECHO|termios.ICANON
   if after[3]&mask != before[3]&mask: raise RuntimeError('terminal state not restored')
   if os.waitstatus_to_exitcode(status)!=1: raise RuntimeError('expected exit 1')
   sys.exit(0)
  select.select([],[],[],.05)
 raise RuntimeError('Ctrl+C left prompt blocked')
finally:
 try: os.kill(pid,signal.SIGKILL)
 except ProcessLookupError: pass
 os.close(fd)
`
	for _, mode := range []string{"menu", "password"} {
		t.Run(mode, func(t *testing.T) {
			c := exec.Command(python, "-c", driver, os.Args[0], mode)
			if out, e := c.CombinedOutput(); e != nil {
				t.Fatalf("PTY interrupt: %v\n%s", e, out)
			}
		})
	}
}
