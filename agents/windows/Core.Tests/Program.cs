using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using NetShield.Agent;

// No test packages or Windows mock claims: this exercises the shared core on the host OS.
class TestProtector : IProtector {
    public bool Fail;
    public byte[] Protect(byte[] value) { if(Fail) throw new IOException("disk/protection failure"); return value.Select(b => (byte)(b ^ 0xAA)).ToArray(); }
    public byte[] Unprotect(byte[] value) { return value.Select(b => (byte)(b ^ 0xAA)).ToArray(); }
}
class Handler : HttpMessageHandler {
    public Func<HttpRequestMessage,CancellationToken,Task<HttpResponseMessage>> Callback;
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken token) { return Callback(request,token); }
}
class Program {
    static int passed;
    static void Assert(bool condition,string message) { if(!condition) throw new Exception(message); }
    static Configuration Config() { return new Configuration { Server="https://netshield.example",DeviceId="pc1",Token=new string('a',43) }; }
    static void Test(string name,Action<string> test) {
        string directory=Path.Combine(Path.GetTempPath(),"netshield-core-"+Guid.NewGuid().ToString("N")); Directory.CreateDirectory(directory);
        try { test(Path.Combine(directory,"state.dat")); Console.WriteLine("PASS "+name); passed++; }
        finally { Directory.Delete(directory,true); }
    }
    static void Main(string[] args) {
        if(args.Length == 2) {
            Configuration imported=Json.Decode<Configuration>(File.ReadAllBytes(args[0]));
            using(var q=new DurableQueue(args[1],new TestProtector(),imported))
            using(var transport=new Transport()) {
                string boot=DateTimeOffset.UtcNow.ToString("o");
                q.Enqueue("agent_started",DateTimeOffset.UtcNow,3,boot);
                var result=transport.SendAsync(q,q.Batch(boot,"unknown","running",3),CancellationToken.None).GetAwaiter().GetResult();
                Console.WriteLine("RESULT "+result.Code+" pending="+q.Count);
                Environment.ExitCode=result.Success ? 0 : 2;
            }
            return;
        }
        Test("persist/reopen and no plaintext credential",path => {
            TestProtector protector=new TestProtector(); string id;
            using(var q=new DurableQueue(path,protector,Config())) { id=q.Enqueue("agent_started",DateTimeOffset.UtcNow); }
            Assert(!Encoding.UTF8.GetString(File.ReadAllBytes(path)).Contains(new string('a',43)),"plaintext token");
            using(var q=new DurableQueue(path,protector,null)) {
                Assert(q.Count==1,"lost persisted event"); Assert(q.Batch("boot","unknown","running").Events[0].Id==id,"changed event identity");
            }
        });
        Test("failed durable write preserves previous state",path => {
            var protector=new TestProtector();
            using(var q=new DurableQueue(path,protector,Config())) {
                q.Enqueue("agent_started",DateTimeOffset.UtcNow); byte[] before=File.ReadAllBytes(path); protector.Fail=true;
                try { q.Enqueue("session_lock",DateTimeOffset.UtcNow); throw new Exception("write unexpectedly succeeded"); } catch(IOException) { }
                Assert(q.Count==1 && before.SequenceEqual(File.ReadAllBytes(path)),"partial update");
            }
        });
        Test("only acknowledged batch is removed",path => {
            using(var q=new DurableQueue(path,new TestProtector(),Config())) {
                string first=q.Enqueue("agent_started",DateTimeOffset.UtcNow); var sent=q.Batch("boot","unknown","running");
                string next=q.Enqueue("session_lock",DateTimeOffset.UtcNow);
                try { q.Acknowledge(sent,new Acknowledgment{Protocol=2,Code="accepted",Ids=new[]{"not-sent"}}); throw new Exception("bad ACK accepted"); } catch(InvalidDataException) { }
                Assert(q.Count==2,"bad ACK lost data");
                q.Acknowledge(sent,new Acknowledgment{Protocol=2,Code="accepted",Ids=new[]{first}});
                Assert(q.Count==1 && q.Batch("boot","locked","running").Events[0].Id==next,"concurrent event deleted");
            }
        });
        Test("queue bound and visible dropped counter",path => {
            using(var q=new DurableQueue(path,new TestProtector(),Config())) {
                for(int i=0;i<1002;i++) q.Enqueue("session_lock",DateTimeOffset.UtcNow);
                Assert(q.Count==1000 && q.Dropped==2,"capacity not enforced");
                Assert(q.Batch("boot","locked","running").Events.Count==100,"batch too large");
            }
            using(var q=new DurableQueue(path,new TestProtector(),null)) Assert(q.Dropped==2,"lost overflow counter");
        });
        Test("corrupt state fails closed",path => {
            File.WriteAllBytes(path,new byte[]{1,2,3});
            try { using(var q=new DurableQueue(path,new TestProtector(),Config())) {} throw new Exception("corruption accepted"); }
            catch(System.Runtime.Serialization.SerializationException) { }
            Assert(File.ReadAllBytes(path).SequenceEqual(new byte[]{1,2,3}),"corruption overwritten");
        });
        Test("one instance owns the queue",path => {
            using(var q=new DurableQueue(path,new TestProtector(),Config())) {
                try { using(var second=new DurableQueue(path,new TestProtector(),null)) {} throw new Exception("double owner"); }
                catch(IOException) { }
            }
        });
        Test("transport commits ACK and uses explicit HTTPS credential",path => {
            using(var q=new DurableQueue(path,new TestProtector(),Config())) {
                string id=q.Enqueue("agent_started",DateTimeOffset.UtcNow);
                var handler=new Handler { Callback=(request,token) => {
                    Assert(request.RequestUri.AbsoluteUri=="https://netshield.example/v2/status/pc1","wrong endpoint");
                    Assert(request.Headers.Authorization.Scheme=="Bearer","missing auth");
                    return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content=new ByteArrayContent(Json.Encode(new Acknowledgment { Code="accepted",Protocol=2,Ids=new[]{id} })) });
                }};
                using(var transport=new Transport(handler)) {
                    Assert(transport.SendAsync(q,q.Batch("2026-09-18T08:00:00Z","unknown","running"),CancellationToken.None).GetAwaiter().GetResult().Success,"ACK failed");
                    Assert(q.Count==0,"ACK not persisted");
                }
            }
        });
        Test("rejected credential and redirect keep queue",path => {
            using(var q=new DurableQueue(path,new TestProtector(),Config())) {
                q.Enqueue("agent_started",DateTimeOffset.UtcNow);
                foreach(var code in new[]{HttpStatusCode.Forbidden,HttpStatusCode.Redirect}) {
                    using(var transport=new Transport(new Handler { Callback=(request,token) => Task.FromResult(new HttpResponseMessage(code)) })) {
                        var result=transport.SendAsync(q,q.Batch("boot","unknown","running"),CancellationToken.None).GetAwaiter().GetResult();
                        Assert(!result.Success && q.Count==1,"failure removed pending event");
                    }
                }
            }
        });
        Test("runtime returns immediately and cancellation keeps events",path => {
            var q=new DurableQueue(path,new TestProtector(),Config()); q.Enqueue("agent_started",DateTimeOffset.UtcNow);
            var started=new TaskCompletionSource<bool>(); var ended=new TaskCompletionSource<bool>();
            var handler=new Handler { Callback=async (request,token) => {
                started.SetResult(true);
                try { await Task.Delay(30000,token); return new HttpResponseMessage(HttpStatusCode.OK); }
                finally { ended.SetResult(true); }
            }};
            var runtime=new AgentRuntime(q,new Transport(handler));
            Assert(runtime.BeginSend("boot","unknown","running"),"not started");
            Assert(!runtime.BeginSend("boot","unknown","running"),"multiple sends");
            Assert(runtime.Poll()==null,"blocked instead of pending");
            Assert(started.Task.Wait(2000),"send not scheduled"); runtime.Dispose();
            Assert(ended.Task.Wait(2000),"cancellation did not reach request");
            bool opened=false;
            for(int i=0;i<100 && !opened;i++) {
                try { using(var next=new DurableQueue(path,new TestProtector(),null)) { Assert(next.Count==1,"cancelled event lost"); opened=true; } }
                catch(IOException) { Thread.Sleep(10); }
            }
            Assert(opened,"ownership was not released");
        });
        Test("retention removes expired events with visible accounting",path => {
            using(var q=new DurableQueue(path,new TestProtector(),Config())) {
                q.Enqueue("session_lock",DateTimeOffset.UtcNow.AddDays(-8));
                q.Enqueue("session_unlock",DateTimeOffset.UtcNow);
                q.Prune(DateTimeOffset.UtcNow);
                Assert(q.Count==1 && q.Dropped==1,"retention accounting failed");
            }
        });
        Test("DNS and TLS failures are distinguished without exposing secrets",path => {
            using(var q=new DurableQueue(path,new TestProtector(),Config())) {
                q.Enqueue("agent_started",DateTimeOffset.UtcNow);
                Exception[] failures={new System.Security.Authentication.AuthenticationException("SECRET"), new System.Net.Sockets.SocketException((int)System.Net.Sockets.SocketError.HostNotFound)};
                string[] codes={"tls_error","dns_error"};
                for(int i=0;i<failures.Length;i++) {
                    Exception failure=failures[i];
                    using(var transport=new Transport(new Handler { Callback=(request,token) => { throw new HttpRequestException("SECRET",failure); } })) {
                        var result=transport.SendAsync(q,q.Batch("boot","unknown","running"),CancellationToken.None).GetAwaiter().GetResult();
                        Assert(result.Code==codes[i] && q.Count==1,"incorrect failure diagnosis or queue loss");
                    }
                }
            }
        });
        Test("malformed or oversized ACK does not clear events",path => {
            using(var q=new DurableQueue(path,new TestProtector(),Config())) {
                q.Enqueue("agent_started",DateTimeOffset.UtcNow);
                foreach(string body in new[]{"{invalid",new string('x',17000)}) {
                    using(var transport=new Transport(new Handler { Callback=(request,token) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) {Content=new StringContent(body)}) })) {
                        var result=transport.SendAsync(q,q.Batch("boot","unknown","running"),CancellationToken.None).GetAwaiter().GetResult();
                        Assert(result.Code=="protocol_error" && q.Count==1,"bad response lost data");
                    }
                }
            }
        });
        Test("abandoned encrypted temporary files are cleaned after valid reopen",path => {
            using(var q=new DurableQueue(path,new TestProtector(),Config())) q.Enqueue("agent_started",DateTimeOffset.UtcNow);
            string abandoned=path+"."+Guid.NewGuid().ToString("N")+".tmp";
            File.WriteAllText(abandoned,"synthetic incomplete encrypted bytes");
            string unrelated=path+".notes.tmp"; File.WriteAllText(unrelated,"keep");
            using(var q=new DurableQueue(path,new TestProtector(),null)) Assert(q.Count==1,"primary queue lost");
            Assert(!File.Exists(abandoned) && File.Exists(unrelated),"incorrect orphan cleanup");
        });
        Test("old session and boot context survive restart and a new observer",path => {
            string oldBoot=DateTimeOffset.UtcNow.AddDays(-1).ToString("o");
            using(var q=new DurableQueue(path,new TestProtector(),Config())) {
                q.Enqueue("session_lock",DateTimeOffset.UtcNow,2,oldBoot);
            }
            using(var q=new DurableQueue(path,new TestProtector(),null)) {
                var batch=q.Batch(DateTimeOffset.UtcNow.ToString("o"),"unknown","running",7);
                Assert(batch.SessionId==7 && batch.Events[0].SessionId==2 && batch.Events[0].BootTime==oldBoot,"history relabeled as current session");
                var wire=Json.Decode<StatusMessage>(Json.Encode(batch));
                Assert(wire.SessionId==7 && wire.Events[0].SessionId==2,"wire lost session context");
                try { q.Enqueue("session_lock",DateTimeOffset.UtcNow,-1,oldBoot); throw new Exception("negative ID accepted"); } catch(InvalidDataException) { }
                try { q.Enqueue("session_lock",DateTimeOffset.UtcNow,1,null); throw new Exception("incomplete context accepted"); } catch(InvalidDataException) { }
                try { q.Enqueue("session_lock",DateTimeOffset.UtcNow,1,"2026-09-18T08:00:00"); throw new Exception("timezone missing"); } catch(InvalidDataException) { }
                Assert(q.Count==1,"invalid context changed queue");
            }
        });
        Test("legacy queue upgrade preserves IDs without inventing session context",path => {
            var protector=new TestProtector();
            var state=new State {Version=1,Configuration=Config()};
            state.Pending.Add(new AgentEvent {Id=new string('b',32),Kind="agent_started",Time=DateTimeOffset.UtcNow.ToString("o")});
            File.WriteAllBytes(path,protector.Protect(Json.Encode(state)));
            using(var q=new DurableQueue(path,protector,null)) {
                var entry=q.Batch("boot","unknown","running",7).Events[0];
                Assert(entry.Id==new string('b',32) && entry.SessionId==null && entry.BootTime==null,"legacy context fabricated");
            }
            Assert(Json.Decode<State>(protector.Unprotect(File.ReadAllBytes(path))).Version==2,"upgrade not persisted");
        });
        Console.WriteLine(passed+" shared-core tests passed. Windows DPAPI and UI require Windows validation.");
    }
}
