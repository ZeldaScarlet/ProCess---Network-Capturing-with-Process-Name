using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using PacketDotNet;
using SharpPcap;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;

namespace TrafficCapturer
{
    // --- PAKET KUYRUĞU YAPISI ---
    public struct QueuedPacket
    {
        public byte[] Data;
        public PosixTimeval Timeval;
        public LinkLayers LinkLayerType;

        public QueuedPacket(byte[] data, PosixTimeval time, LinkLayers linkLayer)
        {
            Data = data;
            Timeval = time;
            LinkLayerType = linkLayer;
        }
    }

    class Program
    {
        // --- AYARLAR ---
        static int _interfaceIndex = -1;
        static int _durationSeconds = 30;
        static string _outputFile = "capture.pcapng";
        static bool _verbose = false;
        static bool _showHelp = false;
        static bool _promiscuousMode = false;

        // --- GLOBAL NESNELER ---
        static BlockingCollection<QueuedPacket> _packetQueue = new BlockingCollection<QueuedPacket>(new ConcurrentQueue<QueuedPacket>(), 100000);
        static ConcurrentDictionary<int, string> _processNameCache = new ConcurrentDictionary<int, string>();

        // Mapper (IPv4/IPv6 + ETW/Polling Hibrit)
        static PortToPidMapper _portMapper = new PortToPidMapper();
        static CustomPcapNgWriter _pcapWriter;
        static long _totalPacketsCaptured = 0;
        static long _totalPacketsProcessed = 0;

        static void Main(string[] args)
        {

            ParseArguments(args);

            if (_showHelp) { ShowHelp(); return; }

            // 1. Cihaz Seçimi
            var devices = CaptureDeviceList.Instance;
            if (devices.Count < 1)
            {
                Console.WriteLine("HATA: Ağ adaptörü bulunamadı. Npcap kurulu mu?");
                return;
            }

            ICaptureDevice device = null;
            if (_interfaceIndex == -1)
            {
                Console.WriteLine("--- Ağ Adaptörleri ---");
                for (int i = 0; i < devices.Count; i++)
                {
                    string desc = devices[i].Description.Length > 50 ? devices[i].Description.Substring(0, 47) + "..." : devices[i].Description;
                    Console.WriteLine($"{i}) {desc} [{devices[i].Name}]");
                }

                int selectedIndex = -1;
                while (selectedIndex < 0 || selectedIndex >= devices.Count)
                {
                    Console.Write($"\nSeçmek istediğiniz adaptör numarası (0-{devices.Count - 1}): ");
                    if (int.TryParse(Console.ReadLine(), out int idx)) selectedIndex = idx;
                }
                device = devices[selectedIndex];
            }
            else
            {
                if (_interfaceIndex >= 0 && _interfaceIndex < devices.Count) device = devices[_interfaceIndex];
                else { Console.WriteLine($"HATA: {_interfaceIndex} numaralı interface bulunamadı."); return; }
            }

            // 2. Dosya Hazırlığı
            _outputFile = GetUniqueFilePath(_outputFile);
            string dir = Path.GetDirectoryName(_outputFile);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir)) Directory.CreateDirectory(dir);

            // 3. Mod Başlatma (ETW vs Polling Fallback)
            bool etwStarted = _portMapper.StartTracking();

            Console.WriteLine($"\n--- DURUM RAPORU ---");
            Console.WriteLine($"Interface        : {device.Description}");
            Console.WriteLine($"Çıktı            : {_outputFile}");
            if (_promiscuousMode)
            {
                Console.WriteLine($"Promiscuous Mode : Aktif");
            }
            else {
                Console.WriteLine($"Promiscuous Mode : Kapalı");
            }


            if (etwStarted)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"Mod       : REAL-TIME (ETW Kernel Events)");
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"Mod       : POLLING (Yönetici izni yok, saniyede 0.5 tarama yapılıyor)");
                Console.WriteLine("UYARI     : Kısa süreli bağlantılar kaçırılabilir. Tam performans için 'Yönetici Olarak' çalıştırın.");
            }
            Console.ResetColor();
            Console.WriteLine("--------------------\n");

            try
            {
                var mode = _promiscuousMode ? DeviceModes.Promiscuous : DeviceModes.None;
                device.Open(mode, 1000);

                _pcapWriter = new CustomPcapNgWriter(_outputFile);

                // Producer
                device.OnPacketArrival += (s, e) =>
                {
                    var raw = e.GetPacket();
                    byte[] dataCopy = new byte[raw.Data.Length];
                    Buffer.BlockCopy(raw.Data, 0, dataCopy, 0, raw.Data.Length);
                    _packetQueue.Add(new QueuedPacket(dataCopy, raw.Timeval, raw.LinkLayerType));
                    Interlocked.Increment(ref _totalPacketsCaptured);
                };

                // Consumer
                var processingTask = Task.Factory.StartNew(() => ProcessQueue(), TaskCreationOptions.LongRunning);

                device.StartCapture();
                Console.WriteLine($"Yakalama başladı. {_durationSeconds} saniye çalışacak...");
                Console.WriteLine("(İptal için CTRL+C)");

                DateTime endTime = DateTime.Now.AddSeconds(_durationSeconds);
                while (DateTime.Now < endTime)
                {
                    if (Console.KeyAvailable)
                    {
                        var keyInfo = Console.ReadKey(true);
                        if (keyInfo.Key == ConsoleKey.C && (keyInfo.Modifiers & ConsoleModifiers.Control) != 0)
                        {
                            Console.WriteLine("\nİptal edildi.");
                            break;
                        }
                    }
                    Thread.Sleep(100);
                }

                Console.WriteLine("\nDurduruluyor...");
                device.StopCapture();
                device.Close();
                _packetQueue.CompleteAdding();
                processingTask.Wait();

                _pcapWriter.Close();
                _portMapper.Dispose();

                Console.WriteLine($"\nTamamlandı!");
                Console.WriteLine($"Yakalanan: {_totalPacketsCaptured}, Kaydedilen: {_totalPacketsProcessed}");
                Console.WriteLine($"Dosya: {Path.GetFullPath(_outputFile)}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"KRİTİK HATA: {ex.Message}");
            }
        }

        static void ProcessQueue()
        {
            foreach (var qPacket in _packetQueue.GetConsumingEnumerable())
            {
                try
                {
                    string processInfo = "";
                    string logMsg = "";
                    int pid = 0;

                    var packet = Packet.ParsePacket(qPacket.LinkLayerType, qPacket.Data);

                    var ipPacket = packet.Extract<IPPacket>();

                    if (ipPacket != null)
                    {
                        var tcpPacket = packet.Extract<TcpPacket>();
                        var udpPacket = packet.Extract<UdpPacket>();

                        string srcIp = ipPacket.SourceAddress.ToString();
                        string dstIp = ipPacket.DestinationAddress.ToString();
                        int srcPort = 0, dstPort = 0;
                        string proto = "IP";

                        if (tcpPacket != null)
                        {
                            proto = "TCP";
                            srcPort = tcpPacket.SourcePort;
                            dstPort = tcpPacket.DestinationPort;
                            pid = _portMapper.GetPid(srcPort, true);
                            if (pid == 0) pid = _portMapper.GetPid(dstPort, true);
                        }
                        else if (udpPacket != null)
                        {
                            proto = "UDP";
                            srcPort = udpPacket.SourcePort;
                            dstPort = udpPacket.DestinationPort;
                            pid = _portMapper.GetPid(srcPort, false);
                            if (pid == 0) pid = _portMapper.GetPid(dstPort, false);
                        }

                        if (pid > 0)
                        {
                            string pName = GetProcessName(pid);
                            processInfo = $"{pName} (PID:{pid})";
                            logMsg = $"[{proto}] [{pName}] {srcIp}:{srcPort} -> {dstIp}:{dstPort} Len:{qPacket.Data.Length}";
                        }
                        else
                        {
                            logMsg = $"[{proto}] [Unknown] {srcIp}:{srcPort} -> {dstIp}:{dstPort} Len:{qPacket.Data.Length}";
                        }
                    }

                    if (_verbose && !string.IsNullOrEmpty(logMsg)) Console.WriteLine(logMsg);

                    _pcapWriter.WritePacket(qPacket.Data, qPacket.Timeval, processInfo);
                    Interlocked.Increment(ref _totalPacketsProcessed);
                }
                catch { }
            }
        }

        static string GetProcessName(int pid)
        {
            if (_processNameCache.TryGetValue(pid, out string name)) return name;
            try
            {
                var proc = Process.GetProcessById(pid);
                try { name = proc.MainModule.ModuleName; }
                catch { name = proc.ProcessName + ".exe"; }
            }
            catch { name = "Terminated"; }
            _processNameCache.TryAdd(pid, name);
            return name;
        }

        static void ParseArguments(string[] args)
        {
            for (int i = 0; i < args.Length; i++)
            {
                string arg = args[i].ToLower();
                if (arg == "-h" || arg == "-help") _showHelp = true;
                else if (arg == "-v" || arg == "-verbose") _verbose = true;
                else if (arg == "-p" || arg == "-promiscuous") _promiscuousMode = true;
                else if (arg == "-t" || arg == "-time") { if (i + 1 < args.Length && int.TryParse(args[i + 1], out int t)) { _durationSeconds = t; i++; } }
                else if (arg == "-o" || arg == "-output") { if (i + 1 < args.Length) { _outputFile = args[i + 1]; i++; } }
                else if (arg == "-i" || arg == "-interface") { if (i + 1 < args.Length && int.TryParse(args[i + 1], out int idx)) { _interfaceIndex = idx; i++; } }
            }
        }

        static void ShowHelp()
        {
            Console.WriteLine("Kullanım: ProCess.exe [parametreler]");
            Console.WriteLine("-i interface [no]    : Interface seçimi. Numara verilmezse listeyi gösterir.");
            Console.WriteLine("-t time [sn]         : Yakalama süresi (saniye). Default: 30");
            Console.WriteLine("-o output [path]     : Çıktı dosya yolu. Örn: ../data/out.pcapng");
            Console.WriteLine("-v verbose           : Verbose mod (Anlık paket detaylarını basar).");
            Console.WriteLine("-p promiscuous       : Promiscuous Mod");
            Console.WriteLine("-h help              : Bu yardım ekranını gösterir.");
            Console.WriteLine("\nÖrnek: ProCess.exe -i 1 -t 60 -v -p -o captures/test.pcapng");
            Console.WriteLine("\nÖrnek: ProCess.exe --verbose -time 90");
        }

        static string GetUniqueFilePath(string path)
        {
            if (!File.Exists(path)) return path;
            string dir = Path.GetDirectoryName(path);
            string name = Path.GetFileNameWithoutExtension(path);
            string ext = Path.GetExtension(path);
            int count = 1;
            if (string.IsNullOrEmpty(dir)) dir = Directory.GetCurrentDirectory();
            while (true) { string newName = Path.Combine(dir, $"{name}_{count}{ext}"); if (!File.Exists(newName)) return newName; count++; }
        }
    }

    // --- PCAPNG WRITER 
    public class CustomPcapNgWriter
    {
        private BinaryWriter _writer;
        private readonly object _lock = new object();

        public CustomPcapNgWriter(string filename)
        {
            var fs = new FileStream(filename, FileMode.Create, FileAccess.Write, FileShare.Read);
            _writer = new BinaryWriter(fs);
            WriteSectionHeader();
            WriteInterfaceDescription();
        }

        public void Close() { lock (_lock) { _writer.Flush(); _writer.Close(); } }

        private void WriteSectionHeader()
        {
            _writer.Write(0x0A0D0D0A); _writer.Write(28); _writer.Write(0x1A2B3C4D);
            _writer.Write((short)1); _writer.Write((short)0); _writer.Write((long)-1); _writer.Write(28);
        }

        private void WriteInterfaceDescription()
        {
            _writer.Write(1); _writer.Write(20); _writer.Write((short)1);
            _writer.Write((short)0); _writer.Write(65535); _writer.Write(20);
        }

        public void WritePacket(byte[] data, PosixTimeval time, string comment)
        {
            lock (_lock)
            {
                int dataPadLen = (4 - (data.Length % 4)) % 4;
                byte[] commentBytes = string.IsNullOrEmpty(comment) ? new byte[0] : Encoding.UTF8.GetBytes(comment);
                int commentOptLen = commentBytes.Length;
                int commentPadLen = (4 - (commentOptLen % 4)) % 4;
                int optionsTotalLen = commentOptLen > 0 ? 4 + commentOptLen + commentPadLen + 4 : 0;

                int blockTotalLength = 28 + data.Length + dataPadLen + optionsTotalLen + 4;

                _writer.Write(6);
                _writer.Write(blockTotalLength);
                _writer.Write(0);
                ulong timestamp = (ulong)time.Date.ToUniversalTime().Subtract(new DateTime(1970, 1, 1)).TotalMilliseconds * 1000;
                _writer.Write((uint)(timestamp >> 32)); _writer.Write((uint)(timestamp & 0xFFFFFFFF));
                _writer.Write(data.Length); _writer.Write(data.Length);
                _writer.Write(data); for (int i = 0; i < dataPadLen; i++) _writer.Write((byte)0);
                if (commentOptLen > 0)
                {
                    _writer.Write((short)1); _writer.Write((short)commentOptLen);
                    _writer.Write(commentBytes); for (int i = 0; i < commentPadLen; i++) _writer.Write((byte)0);
                    _writer.Write((short)0); _writer.Write((short)0);
                }
                _writer.Write(blockTotalLength);
            }
        }
    }

    public class PortToPidMapper : IDisposable
    {
        private ConcurrentDictionary<int, int> _portTable = new ConcurrentDictionary<int, int>();
        private TraceEventSession _session;
        private Task _pollingTask;
        private CancellationTokenSource _cts;
        private bool _isEtwActive = false;

        public bool StartTracking()
        {
            // 1. Önce tabloları (IPv4 + IPv6) doldur
            RefreshWin32Tables();

            // 2. ETW Başlatmayı Dene
            try
            {
                _session = new TraceEventSession("TrafficCapturerSession_" + Guid.NewGuid().ToString());
                _session.EnableKernelProvider(KernelTraceEventParser.Keywords.NetworkTCPIP);

                // TCP Events
                _session.Source.Kernel.TcpIpConnect += (data) => { UpdateTable(data.sport, data.ProcessID, true); UpdateTable(data.dport, data.ProcessID, true); };
                _session.Source.Kernel.TcpIpAccept += (data) => { UpdateTable(data.sport, data.ProcessID, true); UpdateTable(data.dport, data.ProcessID, true); };
                _session.Source.Kernel.TcpIpDisconnect += (data) => { /* Silme işlemini es geçiyoruz, overwrite yeterli */ };

                // UDP Events
                _session.Source.Kernel.UdpIpSend += (data) => { UpdateTable(data.sport, data.ProcessID, false); };
                _session.Source.Kernel.UdpIpRecv += (data) => { UpdateTable(data.dport, data.ProcessID, false); };

                // Session'ı ayrı thread'de çalıştır (Blocking olduğu için)
                Task.Run(() =>
                {
                    try { _session.Source.Process(); }
                    catch { /* Session durdurulursa burası fırlatabilir, yutuyoruz */ }
                });

                _isEtwActive = true;
                return true; // ETW Başarılı
            }
            catch (Exception)
            {
                // ETW Başarısız (Yönetici izni yok) -> Polling Başlat
                _isEtwActive = false;
                StartPollingFallback();
                return false;
            }
        }

        private void StartPollingFallback()
        {
            _cts = new CancellationTokenSource();
            _pollingTask = Task.Run(async () =>
            {
                while (!_cts.Token.IsCancellationRequested)
                {
                    RefreshWin32Tables();
                    await Task.Delay(500);
                }
            });
        }

        public int GetPid(int port, bool isTcp)
        {
            if (_portTable.TryGetValue(GetKey(port, isTcp), out int pid)) return pid;
            return 0;
        }

        private void UpdateTable(int port, int pid, bool isTcp)
        {
            if (port <= 0 || pid <= 0) return;
            _portTable[GetKey(port, isTcp)] = pid;
        }

        private int GetKey(int port, bool isTcp) => (port << 1) | (isTcp ? 1 : 0);

        public void Dispose()
        {
            if (_session != null) { _session.Stop(); _session.Dispose(); }
            if (_cts != null) _cts.Cancel();
        }

        // --- WIN32 API (IPv4 & IPv6) ---

        [DllImport("iphlpapi.dll", SetLastError = true)]
        static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int dwOutBufLen, bool sort, int ipVersion, int tblClass, int reserved);

        [DllImport("iphlpapi.dll", SetLastError = true)]
        static extern uint GetExtendedUdpTable(IntPtr pUdpTable, ref int dwOutBufLen, bool sort, int ipVersion, int tblClass, int reserved);

        private const int AF_INET = 2;   // IPv4
        private const int AF_INET6 = 23; // IPv6

        // Structs for IPv4
        [StructLayout(LayoutKind.Sequential)] public struct MIB_TCPROW_OWNER_PID { public uint state; public uint localAddr; [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)] public byte[] localPort; public uint remoteAddr; [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)] public byte[] remotePort; public int owningPid; public int LocalPort => (localPort[0] << 8) + localPort[1]; }
        [StructLayout(LayoutKind.Sequential)] public struct MIB_TCPTABLE_OWNER_PID { public uint dwNumEntries; }
        [StructLayout(LayoutKind.Sequential)] public struct MIB_UDPROW_OWNER_PID { public uint localAddr; [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)] public byte[] localPort; public int owningPid; public int LocalPort => (localPort[0] << 8) + localPort[1]; }
        [StructLayout(LayoutKind.Sequential)] public struct MIB_UDPTABLE_OWNER_PID { public uint dwNumEntries; }

        // Structs for IPv6 (Different Layout)
        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_TCP6ROW_OWNER_PID
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] localAddr;
            public uint localScopeId;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)] public byte[] localPort;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] remoteAddr;
            public uint remoteScopeId;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)] public byte[] remotePort;
            public uint state;
            public int owningPid;
            public int LocalPort => (localPort[0] << 8) + localPort[1];
        }
        [StructLayout(LayoutKind.Sequential)] public struct MIB_TCP6TABLE_OWNER_PID { public uint dwNumEntries; }

        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_UDP6ROW_OWNER_PID
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] localAddr;
            public uint localScopeId;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)] public byte[] localPort;
            public int owningPid;
            public int LocalPort => (localPort[0] << 8) + localPort[1];
        }
        [StructLayout(LayoutKind.Sequential)] public struct MIB_UDP6TABLE_OWNER_PID { public uint dwNumEntries; }

        private void RefreshWin32Tables()
        {
            // IPv4 TCP
            ProcessTable(AF_INET, true, (ptr) => {
                var tab = (MIB_TCPTABLE_OWNER_PID)Marshal.PtrToStructure(ptr, typeof(MIB_TCPTABLE_OWNER_PID));
                IntPtr rowPtr = (IntPtr)((long)ptr + Marshal.SizeOf(tab.dwNumEntries));
                for (int i = 0; i < tab.dwNumEntries; i++)
                {
                    var row = (MIB_TCPROW_OWNER_PID)Marshal.PtrToStructure(rowPtr, typeof(MIB_TCPROW_OWNER_PID));
                    UpdateTable(row.LocalPort, row.owningPid, true);
                    rowPtr = (IntPtr)((long)rowPtr + Marshal.SizeOf(row));
                }
            });

            // IPv4 UDP
            ProcessTable(AF_INET, false, (ptr) => {
                var tab = (MIB_UDPTABLE_OWNER_PID)Marshal.PtrToStructure(ptr, typeof(MIB_UDPTABLE_OWNER_PID));
                IntPtr rowPtr = (IntPtr)((long)ptr + Marshal.SizeOf(tab.dwNumEntries));
                for (int i = 0; i < tab.dwNumEntries; i++)
                {
                    var row = (MIB_UDPROW_OWNER_PID)Marshal.PtrToStructure(rowPtr, typeof(MIB_UDPROW_OWNER_PID));
                    UpdateTable(row.LocalPort, row.owningPid, false);
                    rowPtr = (IntPtr)((long)rowPtr + Marshal.SizeOf(row));
                }
            });

            // IPv6 TCP
            ProcessTable(AF_INET6, true, (ptr) => {
                var tab = (MIB_TCP6TABLE_OWNER_PID)Marshal.PtrToStructure(ptr, typeof(MIB_TCP6TABLE_OWNER_PID));
                IntPtr rowPtr = (IntPtr)((long)ptr + Marshal.SizeOf(tab.dwNumEntries));
                for (int i = 0; i < tab.dwNumEntries; i++)
                {
                    var row = (MIB_TCP6ROW_OWNER_PID)Marshal.PtrToStructure(rowPtr, typeof(MIB_TCP6ROW_OWNER_PID));
                    UpdateTable(row.LocalPort, row.owningPid, true);
                    rowPtr = (IntPtr)((long)rowPtr + Marshal.SizeOf(row));
                }
            });

            // IPv6 UDP
            ProcessTable(AF_INET6, false, (ptr) => {
                var tab = (MIB_UDP6TABLE_OWNER_PID)Marshal.PtrToStructure(ptr, typeof(MIB_UDP6TABLE_OWNER_PID));
                IntPtr rowPtr = (IntPtr)((long)ptr + Marshal.SizeOf(tab.dwNumEntries));
                for (int i = 0; i < tab.dwNumEntries; i++)
                {
                    var row = (MIB_UDP6ROW_OWNER_PID)Marshal.PtrToStructure(rowPtr, typeof(MIB_UDP6ROW_OWNER_PID));
                    UpdateTable(row.LocalPort, row.owningPid, false);
                    rowPtr = (IntPtr)((long)rowPtr + Marshal.SizeOf(row));
                }
            });
        }

        private void ProcessTable(int ipVersion, bool isTcp, Action<IntPtr> processAction)
        {
            int buffSize = 0;
            int tblClass = isTcp ? 5 : 1;

            if (isTcp) GetExtendedTcpTable(IntPtr.Zero, ref buffSize, true, ipVersion, tblClass, 0);
            else GetExtendedUdpTable(IntPtr.Zero, ref buffSize, true, ipVersion, tblClass, 0);

            if (buffSize == 0) return;

            IntPtr buffPtr = Marshal.AllocHGlobal(buffSize);
            try
            {
                uint ret = isTcp
                    ? GetExtendedTcpTable(buffPtr, ref buffSize, true, ipVersion, tblClass, 0)
                    : GetExtendedUdpTable(buffPtr, ref buffSize, true, ipVersion, tblClass, 0);

                if (ret == 0) processAction(buffPtr);
            }
            finally { Marshal.FreeHGlobal(buffPtr); }
        }
    }
}