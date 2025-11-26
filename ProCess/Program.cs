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

namespace TrafficCapturer
{
    // Kuyrukta işlenmeyi bekleyen ham paket yapısı
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
        static PortToPidMapper _portMapper = new PortToPidMapper();
        static CustomPcapNgWriter _pcapWriter;
        static long _totalPacketsCaptured = 0;
        static long _totalPacketsProcessed = 0;

        static void Main(string[] args)
        {
            ParseArguments(args);

            if (_showHelp)
            {
                ShowHelp();
                return;
            }

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
                if (_interfaceIndex >= 0 && _interfaceIndex < devices.Count)
                    device = devices[_interfaceIndex];
                else
                {
                    Console.WriteLine($"HATA: {_interfaceIndex} numaralı interface bulunamadı.");
                    return;
                }
            }

            // 2. Dosya İsmi Kontrolü
            _outputFile = GetUniqueFilePath(_outputFile);
            string dir = Path.GetDirectoryName(_outputFile);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir)) Directory.CreateDirectory(dir);

            Console.WriteLine($"\nAyarlar:");
            Console.WriteLine($"---------------------------");
            Console.WriteLine($"Interface : {device.Description}");
            Console.WriteLine($"Mod       : {(_promiscuousMode ? "Promiscuous Mod " : "Normal Mod ")}");
            Console.WriteLine($"Süre      : {_durationSeconds} saniye");
            Console.WriteLine($"Çıktı     : {_outputFile}");
            Console.WriteLine($"Verbose   : {(_verbose ? "Açık" : "Kapalı")}");
            Console.WriteLine($"---------------------------\n");

            // 3. Başlatma
            try
            {
                // Mod seçimi 
                var mode = _promiscuousMode ? DeviceModes.Promiscuous : DeviceModes.None;

                // Bazı kartlar None modunda Open timeout verebilir, standart read timeout 1000ms ekliyoruz.
                device.Open(mode, 1000);

                _pcapWriter = new CustomPcapNgWriter(_outputFile);

                // Capture Event
                device.OnPacketArrival += (s, e) =>
                {
                    var raw = e.GetPacket();
                    byte[] dataCopy = new byte[raw.Data.Length];
                    Buffer.BlockCopy(raw.Data, 0, dataCopy, 0, raw.Data.Length);

                    _packetQueue.Add(new QueuedPacket(dataCopy, raw.Timeval, raw.LinkLayerType));
                    Interlocked.Increment(ref _totalPacketsCaptured);
                };

                // Consumer & Mapper Threads
                var processingTask = Task.Factory.StartNew(() => ProcessQueue(), TaskCreationOptions.LongRunning);
                var tokenSource = new CancellationTokenSource();
                Task.Run(() => UpdatePortMappingsLoop(tokenSource.Token));

                device.StartCapture();
                Console.WriteLine($"Yakalama başladı. {_durationSeconds} saniye çalışacak...");
                Console.WriteLine("(Durdurmak için CTRL+C tuşlayın)");

                DateTime endTime = DateTime.Now.AddSeconds(_durationSeconds);
                while (DateTime.Now < endTime)
                {
                    if (Console.KeyAvailable)
                    {
                        var keyInfo = Console.ReadKey(true);
                        if (keyInfo.Key == ConsoleKey.C && (keyInfo.Modifiers & ConsoleModifiers.Control) != 0)
                        {
                            Console.WriteLine("\nKullanıcı tarafından iptal edildi.");
                            break;
                        }
                    }
                    Thread.Sleep(100);
                }

                Console.WriteLine("\nDurduruluyor, lütfen bekleyin...");
                device.StopCapture();
                device.Close();
                _packetQueue.CompleteAdding();

                processingTask.Wait(); 
                tokenSource.Cancel();
                _pcapWriter.Close();

                Console.WriteLine($"\nTamamlandı!");
                Console.WriteLine($"Yakalanan: {_totalPacketsCaptured}, İşlenen: {_totalPacketsProcessed}");
                Console.WriteLine($"Dosya: {Path.GetFullPath(_outputFile)}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"KRİTİK HATA: {ex.Message}");
            }
        }

        static void ParseArguments(string[] args)
        {
            for (int i = 0; i < args.Length; i++)
            {
                string arg = args[i].ToLower();

                if (arg == "-h" || arg == "-help") _showHelp = true;
                else if (arg == "-v" || arg == "-verbose") _verbose = true;
                else if (arg == "-p" || arg == "-promiscuous") _promiscuousMode = true; // YENİ PARAMETRE
                else if (arg == "-t" || arg == "-time")
                {
                    if (i + 1 < args.Length && int.TryParse(args[i + 1], out int t)) { _durationSeconds = t; i++; }
                }
                else if (arg == "-o" || arg == "-output")
                {
                    if (i + 1 < args.Length) { _outputFile = args[i + 1]; i++; }
                }
                else if (arg == "-i" || arg == "-interface")
                {
                    if (i + 1 < args.Length && int.TryParse(args[i + 1], out int idx))
                    {
                        _interfaceIndex = idx;
                        i++;
                    }
                }
            }
        }

        static void ShowHelp()
        {
            Console.WriteLine("Kullanım: ProCess.exe [parametreler]");
            Console.WriteLine("-i [no]    : Interface seçimi");
            Console.WriteLine("-t [sn]    : Yakalama süresi (saniye), Default: 30");
            Console.WriteLine("-o [path]  : Çıktı dosya yolu, Default: capture.pcapng");
            Console.WriteLine("-p         : Promiscuous Mod");
            Console.WriteLine("-v         : Verbose mod (Paketleri ekrana yazar)");
            Console.WriteLine("-h         : Yardım");
            Console.WriteLine("\nÖrnek: exe -i 1 -t 60 -p -v");
        }

        static string GetUniqueFilePath(string path)
        {
            if (!File.Exists(path)) return path;

            string dir = Path.GetDirectoryName(path);
            string name = Path.GetFileNameWithoutExtension(path);
            string ext = Path.GetExtension(path);
            int count = 1;

            if (string.IsNullOrEmpty(dir)) dir = Directory.GetCurrentDirectory();

            while (true)
            {
                string newName = Path.Combine(dir, $"{name}_{count}{ext}");
                if (!File.Exists(newName)) return newName;
                count++;
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

                        if (tcpPacket != null)
                        {
                            srcPort = tcpPacket.SourcePort;
                            dstPort = tcpPacket.DestinationPort;
                            pid = _portMapper.GetPid(srcPort, true);
                            if (pid == 0) pid = _portMapper.GetPid(dstPort, true);
                        }
                        else if (udpPacket != null)
                        {
                            srcPort = udpPacket.SourcePort;
                            dstPort = udpPacket.DestinationPort;
                            pid = _portMapper.GetPid(srcPort, false);
                            if (pid == 0) pid = _portMapper.GetPid(dstPort, false);
                        }

                        if (pid > 0)
                        {
                            string pName = GetProcessName(pid);
                            processInfo = $"{pName} (PID:{pid})";
                            logMsg = $"[{pName}] {srcIp}:{srcPort} -> {dstIp}:{dstPort} Len:{qPacket.Data.Length}";
                        }
                        else
                        {
                            logMsg = $"[Unknown] {srcIp}:{srcPort} -> {dstIp}:{dstPort} Len:{qPacket.Data.Length}";
                        }
                    }

                    if (_verbose && !string.IsNullOrEmpty(logMsg))
                    {
                        Console.WriteLine(logMsg);
                    }

                    _pcapWriter.WritePacket(qPacket.Data, qPacket.Timeval, processInfo);
                    Interlocked.Increment(ref _totalPacketsProcessed);
                }
                catch { }
            }
        }

        // Uzantıları al
        static string GetProcessName(int pid)
        {
            if (_processNameCache.TryGetValue(pid, out string name)) return name;

            try
            {
                var proc = Process.GetProcessById(pid);
                try
                {
                    // Tam modül ismini (örn: chrome.exe) almaya çalış
                    // Sistem dosyaları veya yetki yetmezse hata fırlatabilir.
                    name = proc.MainModule.ModuleName;
                }
                catch
                {
                    name = proc.ProcessName;
                }
            }
            catch
            {
                name = "Terminated";
            }

            _processNameCache.TryAdd(pid, name);
            return name;
        }

        static void UpdatePortMappingsLoop(CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                try
                {
                    _portMapper.RefreshTable();
                    Thread.Sleep(500);
                }
                catch { }
            }
        }
    }

    // --- CUSTOM PCAPNG WRITER
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

        public void Close()
        {
            lock (_lock)
            {
                _writer.Flush();
                _writer.Close();
            }
        }

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
                _writer.Write((uint)(timestamp >> 32));
                _writer.Write((uint)(timestamp & 0xFFFFFFFF));

                _writer.Write(data.Length);
                _writer.Write(data.Length);
                _writer.Write(data);
                for (int i = 0; i < dataPadLen; i++) _writer.Write((byte)0);

                if (commentOptLen > 0)
                {
                    _writer.Write((short)1); _writer.Write((short)commentOptLen);
                    _writer.Write(commentBytes);
                    for (int i = 0; i < commentPadLen; i++) _writer.Write((byte)0);
                    _writer.Write((short)0); _writer.Write((short)0);
                }
                _writer.Write(blockTotalLength);
            }
        }
    }

    // --- PORT MAPPER (Değişmedi)
    public class PortToPidMapper
    {
        private Dictionary<string, int> _table = new Dictionary<string, int>();
        private readonly object _lock = new object();

        public void RefreshTable()
        {
            var newTable = new Dictionary<string, int>();

            // 1. TCP Bağlantılarını Al
            var tcpRows = GetAllTcpConnections();
            foreach (var row in tcpRows)
            {
                string key = $"TCP_{row.LocalPort}";
                if (!newTable.ContainsKey(key)) newTable[key] = row.OwningPid;
            }

            // 2. UDP Dinleyicilerini Al
            var udpRows = GetAllUdpListeners();
            foreach (var row in udpRows)
            {
                string key = $"UDP_{row.LocalPort}";
                if (!newTable.ContainsKey(key)) newTable[key] = row.OwningPid;
            }

            lock (_lock) { _table = newTable; }
        }

        public int GetPid(int port, bool isTcp)
        {
            string key = $"{(isTcp ? "TCP" : "UDP")}_{port}";
            lock (_lock)
            {
                if (_table.TryGetValue(key, out int pid)) return pid;
            }
            return 0;
        }

        // --- Win32 API Tanımları ---

        // TCP API
        [DllImport("iphlpapi.dll", SetLastError = true)]
        static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int dwOutBufLen, bool sort, int ipVersion, int tblClass, int reserved);

        // UDP API
        [DllImport("iphlpapi.dll", SetLastError = true)]
        static extern uint GetExtendedUdpTable(IntPtr pUdpTable, ref int dwOutBufLen, bool sort, int ipVersion, int tblClass, int reserved);

        // -- TCP STRUCTS --
        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_TCPROW_OWNER_PID
        {
            public uint state; public uint localAddr;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)] public byte[] localPort;
            public uint remoteAddr;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)] public byte[] remotePort;
            public int owningPid;
            public int LocalPort => (localPort[0] << 8) + localPort[1];
            public int OwningPid => owningPid;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_TCPTABLE_OWNER_PID { public uint dwNumEntries; }

        // -- UDP STRUCTS
        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_UDPROW_OWNER_PID
        {
            public uint localAddr;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)] public byte[] localPort;
            public int owningPid;
            public int LocalPort => (localPort[0] << 8) + localPort[1];
            public int OwningPid => owningPid;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_UDPTABLE_OWNER_PID { public uint dwNumEntries; }

        // -- METHODS --

        private List<MIB_TCPROW_OWNER_PID> GetAllTcpConnections()
        {
            List<MIB_TCPROW_OWNER_PID> tTable = new List<MIB_TCPROW_OWNER_PID>();
            int buffSize = 0;
            // AF_INET (2) = IPv4, TCP_TABLE_OWNER_PID_ALL (5)
            GetExtendedTcpTable(IntPtr.Zero, ref buffSize, true, 2, 5, 0);

            IntPtr buffPtr = Marshal.AllocHGlobal(buffSize);
            try
            {
                if (GetExtendedTcpTable(buffPtr, ref buffSize, true, 2, 5, 0) == 0)
                {
                    MIB_TCPTABLE_OWNER_PID tab = (MIB_TCPTABLE_OWNER_PID)Marshal.PtrToStructure(buffPtr, typeof(MIB_TCPTABLE_OWNER_PID));
                    IntPtr rowPtr = (IntPtr)((long)buffPtr + Marshal.SizeOf(tab.dwNumEntries));

                    for (int i = 0; i < tab.dwNumEntries; i++)
                    {
                        MIB_TCPROW_OWNER_PID row = (MIB_TCPROW_OWNER_PID)Marshal.PtrToStructure(rowPtr, typeof(MIB_TCPROW_OWNER_PID));
                        tTable.Add(row);
                        rowPtr = (IntPtr)((long)rowPtr + Marshal.SizeOf(row));
                    }
                }
            }
            finally { Marshal.FreeHGlobal(buffPtr); }
            return tTable;
        }

        // UDP Listeners Metodu
        private List<MIB_UDPROW_OWNER_PID> GetAllUdpListeners()
        {
            List<MIB_UDPROW_OWNER_PID> uTable = new List<MIB_UDPROW_OWNER_PID>();
            int buffSize = 0;
            // AF_INET (2) = IPv4, UDP_TABLE_OWNER_PID (1)
            GetExtendedUdpTable(IntPtr.Zero, ref buffSize, true, 2, 1, 0);

            IntPtr buffPtr = Marshal.AllocHGlobal(buffSize);
            try
            {
                if (GetExtendedUdpTable(buffPtr, ref buffSize, true, 2, 1, 0) == 0)
                {
                    MIB_UDPTABLE_OWNER_PID tab = (MIB_UDPTABLE_OWNER_PID)Marshal.PtrToStructure(buffPtr, typeof(MIB_UDPTABLE_OWNER_PID));
                    IntPtr rowPtr = (IntPtr)((long)buffPtr + Marshal.SizeOf(tab.dwNumEntries));

                    for (int i = 0; i < tab.dwNumEntries; i++)
                    {
                        MIB_UDPROW_OWNER_PID row = (MIB_UDPROW_OWNER_PID)Marshal.PtrToStructure(rowPtr, typeof(MIB_UDPROW_OWNER_PID));
                        uTable.Add(row);
                        rowPtr = (IntPtr)((long)rowPtr + Marshal.SizeOf(row));
                    }
                }
            }
            finally { Marshal.FreeHGlobal(buffPtr); }
            return uTable;
        }
    }
}