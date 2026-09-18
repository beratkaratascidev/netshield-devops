// Shared transport/storage implementation. C# 5 syntax for Windows PowerShell 5.1 Add-Type.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Security.Cryptography;
using System.Security.Authentication;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace NetShield.Agent {
    public interface IProtector { byte[] Protect(byte[] value); byte[] Unprotect(byte[] value); }
    public sealed class WindowsProtector : IProtector {
        [StructLayout(LayoutKind.Sequential)] private struct Blob { public int Length; public IntPtr Data; }
        [DllImport("crypt32.dll", SetLastError=true, CharSet=CharSet.Unicode, ExactSpelling=true)]
        private static extern bool CryptProtectData(ref Blob input, string description, IntPtr entropy, IntPtr reserved, IntPtr prompt, int flags, out Blob output);
        [DllImport("crypt32.dll", SetLastError=true)]
        private static extern bool CryptUnprotectData(ref Blob input, IntPtr description, IntPtr entropy, IntPtr reserved, IntPtr prompt, int flags, out Blob output);
        [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr value);
        private byte[] Transform(byte[] value, bool protect) {
            if (Environment.OSVersion.Platform != PlatformID.Win32NT) throw new PlatformNotSupportedException("Windows DPAPI required");
            Blob input = new Blob { Length=value.Length, Data=Marshal.AllocHGlobal(value.Length) };
            Blob output = new Blob();
            try {
                Marshal.Copy(value, 0, input.Data, value.Length);
                bool ok = protect ? CryptProtectData(ref input, "NetShield agent state", IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 1, out output)
                                  : CryptUnprotectData(ref input, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 1, out output);
                if (!ok) throw new CryptographicException("Windows could not protect/open the agent state.");
                byte[] result = new byte[output.Length];
                Marshal.Copy(output.Data, result, 0, output.Length);
                return result;
            } finally {
                for (int i=0; i<input.Length; i++) Marshal.WriteByte(input.Data, i, 0);
                Marshal.FreeHGlobal(input.Data);
                if (output.Data != IntPtr.Zero) LocalFree(output.Data);
            }
        }
        public byte[] Protect(byte[] value) { return Transform(value, true); }
        public byte[] Unprotect(byte[] value) { return Transform(value, false); }
    }
    public static class Json {
        public static byte[] Encode<T>(T value) { using (MemoryStream stream = new MemoryStream()) {
            new DataContractJsonSerializer(typeof(T)).WriteObject(stream, value); return stream.ToArray(); } }
        public static T Decode<T>(byte[] value) { using (MemoryStream stream = new MemoryStream(value)) {
            return (T)new DataContractJsonSerializer(typeof(T)).ReadObject(stream); } }
    }
    [DataContract] public sealed class Configuration {
        [DataMember(Name="server")] public string Server;
        [DataMember(Name="device_id")] public string DeviceId;
        [DataMember(Name="token")] public string Token;
        public void Validate() {
            Uri uri;
            if (!Uri.TryCreate(Server, UriKind.Absolute, out uri) || uri.Scheme != "https" || uri.UserInfo != "" ||
                uri.AbsolutePath != "/" || uri.Query != "" || uri.Fragment != "" || uri.Port <= 0)
                throw new InvalidDataException("An HTTPS origin is required.");
            if (DeviceId == null || !Regex.IsMatch(DeviceId, @"\A[a-zA-Z0-9_-]{1,64}\z") ||
                Token == null || !Regex.IsMatch(Token, @"\A[a-zA-Z0-9_-]{40,128}\z")) throw new InvalidDataException("Invalid device credential.");
            Server = Server.TrimEnd('/');
        }
    }
    [DataContract] public sealed class AgentEvent {
        [DataMember(Name="id")] public string Id;
        [DataMember(Name="kind")] public string Kind;
        [DataMember(Name="time")] public string Time;
        [DataMember(Name="session_id", EmitDefaultValue=false)] public int? SessionId;
        [DataMember(Name="boot_time", EmitDefaultValue=false)] public string BootTime;
        public void ValidateContext() {
            DateTimeOffset parsed;
            if (SessionId.HasValue != (BootTime != null) || SessionId < 0 ||
                (BootTime != null && (BootTime.Length > 40 ||
                    !Regex.IsMatch(BootTime, @"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?(?:Z|[+-]\d{2}:\d{2})\z") ||
                    !DateTimeOffset.TryParse(BootTime, out parsed))))
                throw new InvalidDataException("Invalid event session context.");
        }
    }
    [DataContract] public sealed class State {
        [DataMember] public int Version = 2;
        [DataMember] public Configuration Configuration;
        [DataMember] public List<AgentEvent> Pending = new List<AgentEvent>();
        [DataMember] public long Dropped;
    }
    [DataContract] public sealed class StatusMessage {
        [DataMember(Name="boot_time")] public string BootTime;
        [DataMember(Name="session")] public string Session;
        [DataMember(Name="events")] public List<AgentEvent> Events;
        [DataMember(Name="agent_state")] public string AgentState;
        [DataMember(Name="dropped_events")] public long Dropped;
        [DataMember(Name="pending_events")] public int Pending;
        [DataMember(Name="session_id", EmitDefaultValue=false)] public int? SessionId;
    }
    [DataContract] public sealed class Acknowledgment {
        [DataMember(Name="code")] public string Code;
        [DataMember(Name="protocol")] public int Protocol;
        [DataMember(Name="accepted_event_ids")] public string[] Ids;
    }
    public sealed class DurableQueue : IDisposable {
        private readonly object gate = new object();
        private readonly string path;
        private readonly IProtector protector;
        private readonly FileStream ownership;
        private State state;
        public const int Capacity=1000;
        public const int RetentionDays=7;
        public static readonly string[] Kinds = { "agent_started", "agent_stopped", "session_lock", "session_unlock", "suspend", "resume", "session_logoff" };
        public DurableQueue(string path, IProtector protector, Configuration configuration) {
            this.path = Path.GetFullPath(path); this.protector = protector;
            Directory.CreateDirectory(Path.GetDirectoryName(this.path));
            ownership = new FileStream(this.path + ".lock", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            try {
                if (File.Exists(this.path)) {
                    if (new FileInfo(this.path).Length > 1024*1024) throw new InvalidDataException("Agent state exceeds limit.");
                    state = Json.Decode<State>(protector.Unprotect(File.ReadAllBytes(this.path)));
                    if (state == null || (state.Version != 1 && state.Version != 2) || state.Configuration == null || state.Pending == null || state.Pending.Count > Capacity || state.Dropped < 0)
                        throw new InvalidDataException("Invalid agent state; recovery is required.");
                    state.Configuration.Validate();
                    HashSet<string> ids = new HashSet<string>();
                    foreach (AgentEvent entry in state.Pending) {
                        DateTimeOffset parsed;
                        if (entry == null || entry.Id == null || !Regex.IsMatch(entry.Id, @"\A[0-9a-f]{32}\z") || !ids.Add(entry.Id) ||
                            !Kinds.Contains(entry.Kind) || !DateTimeOffset.TryParse(entry.Time, out parsed)) throw new InvalidDataException("Invalid queued event.");
                        entry.ValidateContext();
                    }
                    if (state.Version == 1) { State upgraded=Copy(); upgraded.Version=2; Save(upgraded); state=upgraded; }
                    if (configuration != null) {
                        configuration.Validate();
                        if (state.Configuration.DeviceId != configuration.DeviceId || state.Configuration.Server != configuration.Server)
                            throw new InvalidDataException("A different device/server cannot reuse this queue.");
                        State replacement = Copy(); replacement.Configuration = configuration; Save(replacement); state = replacement;
                    }
                } else {
                    if (configuration == null) throw new InvalidDataException("Import configuration before starting the agent.");
                    configuration.Validate();
                    state = new State { Configuration=configuration }; Save(state);
                }
                Prune(DateTimeOffset.UtcNow);
                // Only our abandoned encrypted temporary files; the valid primary state is already open.
                string prefix=Path.GetFileName(this.path);
                foreach(string stale in Directory.EnumerateFiles(Path.GetDirectoryName(this.path), prefix+".*.tmp")) {
                    if(Regex.IsMatch(Path.GetFileName(stale), "\\A"+Regex.Escape(prefix)+@"\.[0-9a-f]{32}\.tmp\z")) File.Delete(stale);
                }
            } catch { ownership.Dispose(); throw; }
        }
        private State Copy() { return Json.Decode<State>(Json.Encode(state)); }
        private void Save(State candidate) {
            byte[] clear = Json.Encode(candidate); byte[] encrypted;
            try { encrypted = protector.Protect(clear); } finally { Array.Clear(clear, 0, clear.Length); }
            string temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
            try {
                using (FileStream stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None)) {
                    stream.Write(encrypted, 0, encrypted.Length); stream.Flush(true);
                }
                if (File.Exists(path)) File.Replace(temporary, path, null); else File.Move(temporary, path);
            } finally { if (File.Exists(temporary)) File.Delete(temporary); }
        }
        public Configuration Configuration { get { lock(gate) { return Json.Decode<Configuration>(Json.Encode(state.Configuration)); } } }
        public int Count { get { lock(gate) { return state.Pending.Count; } } }
        public long Dropped { get { lock(gate) { return state.Dropped; } } }
        public string Enqueue(string kind, DateTimeOffset when) {
            return Enqueue(kind, when, null, null);
        }
        public string Enqueue(string kind, DateTimeOffset when, int? sessionId, string bootTime) {
            if (!Kinds.Contains(kind)) throw new ArgumentException("Unknown event kind");
            AgentEvent entry = new AgentEvent { Id=Guid.NewGuid().ToString("N"), Kind=kind,
                Time=when.ToUniversalTime().ToString("o"), SessionId=sessionId, BootTime=bootTime };
            entry.ValidateContext();
            lock(gate) {
                State candidate = Copy();
                if (candidate.Pending.Count == Capacity) { candidate.Pending.RemoveAt(0); candidate.Dropped++; }
                candidate.Pending.Add(entry);
                Save(candidate); state=candidate; return entry.Id;
            }
        }
        public void Prune(DateTimeOffset now) {
            lock(gate) {
                State candidate = Copy();
                int removed=candidate.Pending.RemoveAll(e => DateTimeOffset.Parse(e.Time).ToUniversalTime() < now.ToUniversalTime().AddDays(-RetentionDays));
                if(removed > 0) { candidate.Dropped += removed; Save(candidate); state=candidate; }
            }
        }
        public StatusMessage Batch(string bootTime, string session, string agentState) {
            return Batch(bootTime, session, agentState, null);
        }
        public StatusMessage Batch(string bootTime, string session, string agentState, int? sessionId) {
            if (sessionId < 0) throw new ArgumentException("Invalid session ID");
            Prune(DateTimeOffset.UtcNow);
            lock(gate) { return new StatusMessage { BootTime=bootTime, Session=session, AgentState=agentState,
                Events=Copy().Pending.Take(100).ToList(), Dropped=state.Dropped, Pending=state.Pending.Count, SessionId=sessionId }; }
        }
        public void Acknowledge(StatusMessage sent, Acknowledgment ack) {
            HashSet<string> expected = new HashSet<string>(sent.Events.Select(e => e.Id));
            if (ack == null || ack.Protocol != 2 || ack.Code != "accepted" || ack.Ids == null ||
                ack.Ids.Length != expected.Count || !expected.SetEquals(ack.Ids)) throw new InvalidDataException("Invalid server acknowledgment.");
            lock(gate) {
                State candidate = Copy(); candidate.Pending.RemoveAll(e => expected.Contains(e.Id));
                Save(candidate); state=candidate;
            }
        }
        public void Dispose() { ownership.Dispose(); }
    }
    public sealed class SendResult {
        public string Code { get; private set; }
        public bool Success { get { return Code == "accepted"; } }
        public SendResult(string code) { Code=code; }
    }
    public sealed class Transport : IDisposable {
        private readonly HttpClient client;
        public Transport() : this(new HttpClientHandler { AllowAutoRedirect=false, UseCookies=false }) { }
        public Transport(HttpMessageHandler handler) { client=new HttpClient(handler); client.Timeout=Timeout.InfiniteTimeSpan; }
        private static string ConnectionError(Exception error) {
            for(Exception current=error; current != null; current=current.InnerException) {
                if(current is AuthenticationException) return "tls_error";
                SocketException socket=current as SocketException;
                if(socket != null && (socket.SocketErrorCode == SocketError.HostNotFound || socket.SocketErrorCode == SocketError.NoData || socket.SocketErrorCode == SocketError.TryAgain)) return "dns_error";
                WebException web=current as WebException;
                if(web != null && (web.Status == WebExceptionStatus.TrustFailure || web.Status == WebExceptionStatus.SecureChannelFailure)) return "tls_error";
                if(web != null && web.Status == WebExceptionStatus.NameResolutionFailure) return "dns_error";
            }
            return "connection_error";
        }
        public async Task<SendResult> SendAsync(DurableQueue queue, StatusMessage body, CancellationToken cancellation) {
            Configuration config=queue.Configuration;
            using (CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellation)) {
                timeout.CancelAfter(TimeSpan.FromSeconds(5));
                try {
                    using (HttpRequestMessage request=new HttpRequestMessage(HttpMethod.Post, config.Server + "/v2/status/" + config.DeviceId)) {
                        request.Headers.Authorization=new AuthenticationHeaderValue("Bearer", config.Token);
                        request.Content=new ByteArrayContent(Json.Encode(body));
                        request.Content.Headers.ContentType=new MediaTypeHeaderValue("application/json");
                        using (HttpResponseMessage response=await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token).ConfigureAwait(false)) {
                            if (response.StatusCode == HttpStatusCode.Forbidden) return new SendResult("credential_rejected");
                            if ((int)response.StatusCode == 429 || (int)response.StatusCode == 503) return new SendResult("receiver_busy");
                            if ((int)response.StatusCode != 200) return new SendResult("protocol_error");
                            using (Stream stream=await response.Content.ReadAsStreamAsync().ConfigureAwait(false))
                            using (MemoryStream bytes=new MemoryStream()) {
                                byte[] buffer=new byte[1024]; int size;
                                while ((size=await stream.ReadAsync(buffer, 0, buffer.Length, timeout.Token).ConfigureAwait(false)) > 0) {
                                    if (bytes.Length+size > 16384) return new SendResult("protocol_error");
                                    bytes.Write(buffer, 0, size);
                                }
                                try { queue.Acknowledge(body, Json.Decode<Acknowledgment>(bytes.ToArray())); }
                                catch(InvalidDataException) { return new SendResult("protocol_error"); }
                                catch(IOException) { return new SendResult("storage_error"); }
                                catch(UnauthorizedAccessException) { return new SendResult("storage_error"); }
                            }
                        }
                    }
                    return new SendResult("accepted");
                } catch (OperationCanceledException) { return new SendResult(cancellation.IsCancellationRequested ? "cancelled" : "timeout"); }
                catch (HttpRequestException error) { return new SendResult(ConnectionError(error)); }
                catch (SerializationException) { return new SendResult("protocol_error"); }
                catch (InvalidDataException) { return new SendResult("protocol_error"); }
                catch (IOException) { return new SendResult("connection_error"); }
                catch (CryptographicException) { return new SendResult("storage_error"); }
            }
        }
        public void Dispose() { client.Dispose(); }
    }
    public sealed class AgentRuntime : IDisposable {
        private readonly DurableQueue queue;
        private readonly Transport transport;
        private readonly CancellationTokenSource stop = new CancellationTokenSource();
        private Task<SendResult> pending;
        public AgentRuntime(DurableQueue queue, Transport transport) { this.queue=queue; this.transport=transport; }
        public bool Busy { get { return pending != null; } }
        public bool BeginSend(string bootTime, string session, string agentState) {
            return BeginSend(bootTime, session, agentState, null);
        }
        public bool BeginSend(string bootTime, string session, string agentState, int? sessionId) {
            if (pending != null || stop.IsCancellationRequested) return false;
            pending=Task.Run(async delegate { return await transport.SendAsync(queue, queue.Batch(bootTime, session, agentState, sessionId), stop.Token).ConfigureAwait(false); });
            return true;
        }
        public SendResult Poll() {
            if (pending == null || !pending.IsCompleted) return null;
            try { return pending.GetAwaiter().GetResult(); }
            catch { return new SendResult("storage_error"); }
            finally { pending=null; }
        }
        public void Dispose() {
            stop.Cancel(); transport.Dispose();
            Task<SendResult> finishing=pending;
            if (finishing == null || finishing.IsCompleted) { queue.Dispose(); stop.Dispose(); }
            else { finishing.ContinueWith(delegate { queue.Dispose(); stop.Dispose(); }, TaskScheduler.Default); }
        }
    }
}
