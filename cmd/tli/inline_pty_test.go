package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"runtime"
	"sync/atomic"
	"testing"
)

const inlinePTYDriver = `import os,pty,select,signal,sys,time,termios,fcntl,struct,json,re,unicodedata
mode,work=sys.argv[2:4]
pid,fd=pty.fork()
if pid==0:
 os.chdir(work)
 fcntl.ioctl(0,termios.TIOCSWINSZ,struct.pack('HHHH',9 if mode=='small' else 28,39 if mode=='small' else 96,0,0))
 env=dict(os.environ,TLI_TEST_CHILD='1',CI='false',GITHUB_ACTIONS='false',BITBUCKET_BUILD_NUMBER='',TERM='xterm',NO_COLOR='1',TLI_NO_ANIMATION='1',GORACE='atexit_sleep_ms=0')
 args=[sys.argv[1],'-test.run=^TestCLIProcess$','--']
 if mode=='direct':args+=['preview','--staged','--output','json']
 else:os.write(1,b'SHELL-PREVIO\r\n')
 os.execve(sys.argv[1],args,env)
alive=True;output=b'';mark=0
before=termios.tcgetattr(fd)
def read_some(delay=.03):
 global output
 ready,_,_=select.select([fd],[],[],delay)
 if ready:
  try:output+=os.read(fd,65536)
  except OSError:pass
def expect(text):
 deadline=time.monotonic()+5
 while text.encode() not in output[mark:] and time.monotonic()<deadline:read_some()
 if text.encode() not in output[mark:]:raise RuntimeError('missing '+repr(text)+'\n'+repr(output[-6000:]))
def send(data):
 global mark
 mark=len(output);os.write(fd,data)
def resize(w,h):
 global mark
 mark=len(output);fcntl.ioctl(fd,termios.TIOCSWINSZ,struct.pack('HHHH',h,w,0,0))
def screen_text():
 lines=[[' ']*96];row=col=0
 def ensure():
  while len(lines)<=row:lines.append([' ']*96)
 text=output.decode(errors='replace');i=0
 while i<len(text):
  if text[i]=='\x1b':
   m=re.match(r'\x1b\[([0-9;?]*)([A-Za-z])',text[i:])
   if m:
    arg,op=m.groups();n=int(arg) if arg.isdigit() and int(arg)>0 else 1
    if op=='A':row=max(max(0,len(lines)-28),row-n)
    elif op=='K':lines[row]=[' ']*96
    elif op in ('H','J'):raise RuntimeError('global cursor/erase in inline')
    i+=len(m.group(0));continue
  c=text[i];i+=1
  if c=='\r':col=0
  elif c=='\n':row+=1;ensure()
  elif unicodedata.category(c)[0]!='C':
   cells=0 if unicodedata.combining(c) else 2 if unicodedata.east_asian_width(c) in ('W','F') else 1
   if col+cells>96:row+=1;col=0;ensure()
   if cells:lines[row][col]=c;col+=cells
 return '\n'.join(''.join(x).rstrip() for x in lines)
def finish(want):
 global alive
 deadline=time.monotonic()+5
 while time.monotonic()<deadline:
  read_some();done,status=os.waitpid(pid,os.WNOHANG)
  if done:
   alive=False
   for _ in range(3):read_some(.01)
   if os.waitstatus_to_exitcode(status)!=want:raise RuntimeError('exit '+str(os.waitstatus_to_exitcode(status))+repr(output[-3000:]))
   after=termios.tcgetattr(fd);mask=termios.ECHO|termios.ICANON
   if after[3]&mask!=before[3]&mask:raise RuntimeError('terminal not restored')
   for bad in [b'\x1b[?1049',b'\x1b[2J',b'\x1b[3J',b'\x1b[H']:
    if bad in output:raise RuntimeError('forbidden inline control '+repr(bad))
   if mode!='direct':
    text=screen_text()
    if 'SHELL-PREVIO' not in text:raise RuntimeError('prior shell output was overwritten')
    if text.count('TITVO')!=1:raise RuntimeError('welcome duplicated or removed '+repr(text))
    if mode in ('running','success') and 'scan-running' not in text:raise RuntimeError('result identity lost from scrollback')
   return
 raise RuntimeError('process remained blocked '+repr(output[-3000:]))
try:
 if mode=='direct':finish(0);json.loads(output.decode().strip());sys.exit(0)
 if mode=='small':expect('1. Escanear');send(b'4\n');finish(0);sys.exit(0)
 expect('¿Qué quieres revisar?')
 if mode=='selector':send(b'\x03');finish(1)
 elif mode=='eof':send(b'\x04');finish(0)
 elif mode=='commit':send(b'commit\r');expect('Referencia del commit');send(b'\x03');finish(1)
 elif mode=='password':send(b'config\r');expect('URL de su API:');send(b'https://fixture.test\nfixture\n');expect('API Key:');send(b'\x03');finish(1)
 elif mode=='navigation':
  send(b'zzxy\r');expect('Sin coincidencias');send(b'\x1b');expect('¿Qué quieres revisar?')
  send(b'commit\r');expect('Referencia del commit');send(b'q\x7f\r');expect('¿Iniciar este análisis?');expect('main.go')
  send(b'\r');expect('¿Qué quieres revisar?');send(b'solo\r');expect('¿Qué alcance');send(b'\r');expect('Archivos incluidos');send(b'\t');expect('No hay archivos');send(b'\x1b');expect('¿Qué quieres revisar?');send(b'\x1b');finish(0)
 elif mode in ('resize','roundtrip','running','success'):
  send(b'\r');expect('¿Iniciar este análisis?');send(b'\x1b[B');expect('> Enviar')
  if mode=='resize':
   resize(39,9);send(b'\r');expect('Ajustando tamaño');send(b'\x1b[B\r');resize(96,28);expect('¿Iniciar este análisis?');send(b'\r');expect('¿Qué quieres revisar?');send(b'\x1b');finish(0)
  elif mode=='roundtrip':
   resize(39,9);resize(96,28);expect('Vista anterior anulada');expect('¿Iniciar este análisis?');send(b'\r');expect('¿Qué quieres revisar?');send(b'\x1b');finish(0)
  else:
   send(b'\r')
   if mode=='running':expect('scan_id: scan-running');send(b'\x03');finish(1)
   else:
    expect('¿Qué quieres hacer ahora?');send(b'\r');expect('Hallazgo 1');send(b'\x1b');expect('¿Qué quieres hacer ahora?');send(b'salir\r');finish(0)
finally:
 if alive:
  try:os.kill(pid,signal.SIGKILL);os.waitpid(pid,0)
  except ProcessLookupError:pass
 os.close(fd)
`

func runInlinePTY(t *testing.T, mode string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("numeric fallback; Unix PTY only")
	}
	python, e := exec.LookPath("python3")
	if e != nil {
		t.Skip("Python stdlib PTY driver unavailable")
	}
	root, _ := sourceFixture(t)
	var requests, starts atomic.Int32
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		switch r.URL.Path {
		case "/cli-files":
			fmt.Fprintf(w, `{"presigned_urls":{"snapshot.tar.gz":%q}}`, server.URL+"/upload")
		case "/upload":
			io.Copy(io.Discard, r.Body)
		case "/run-scan":
			starts.Add(1)
			fmt.Fprint(w, `{"scan_id":"scan-running"}`)
		case "/scan-status":
			if mode == "success" {
				fmt.Fprint(w, `{"status":"COMPLETED","result":{"status":"WARNING","issues_count":1,"coverage":{"complete":true},"annotations":[{"title":"Fixture finding","path":"main.go","line":1,"code":"source"}]}}`)
			} else {
				fmt.Fprint(w, `{"status":"IN_PROGRESS"}`)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	cmd := exec.Command(python, "-c", inlinePTYDriver, os.Args[0], mode, root)
	cmd.Env = testProcessEnv(t, server, t.TempDir())
	if out, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("inline PTY %s: %v\n%s", mode, e, out)
	}
	if mode == "running" || mode == "success" {
		if starts.Load() != 1 {
			t.Fatal("duplicate/missing scan")
		}
	} else if requests.Load() != 0 {
		t.Fatal("unexpected network")
	}
}
func TestInlineRootOnlyNoArgsTTY(t *testing.T)               { runInlinePTY(t, "direct"); runInlinePTY(t, "small") }
func TestInlinePTYPreservesPriorShellAndResult(t *testing.T) { runInlinePTY(t, "success") }
func TestInlinePTYKeyboardAndSearch(t *testing.T)            { runInlinePTY(t, "navigation") }
func TestInlinePTYResizeNeverSubmits(t *testing.T)           { runInlinePTY(t, "resize") }
func TestInlinePTYResizeRoundTrip(t *testing.T)              { runInlinePTY(t, "roundtrip") }
func TestInlinePTYCancelPasswordAndWait(t *testing.T) {
	for _, mode := range []string{"selector", "commit", "password", "running", "eof"} {
		t.Run(mode, func(t *testing.T) { runInlinePTY(t, mode) })
	}
}
