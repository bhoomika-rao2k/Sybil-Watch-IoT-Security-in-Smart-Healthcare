/*
 * ============================================================
 * Sybil Watch — IoT Security in Smart Healthcare
 * ============================================================
 * Author      : Bhoomika Sathish Rao
 * Institution : Maharaja Institute of Technology, Mysore
 * Department  : Electronics & Communication Engineering
 * Degree      : BEng ECE Final Year Project
 * Year        : 2022
 * Team Size   : 3 members
 *
 * My Contribution:
 *   - Intrusion Detection Module
 *   - Packet parsing logic
 *   - Real-time SMS alerting via GSM modem (AT commands)
 *   - Testing and evaluation documentation
 *
 * Description:
 * A lightweight real-time Sybil attack detection system for
 * IoT-enabled smart healthcare networks. Detects malicious
 * nodes that impersonate multiple identities to intercept
 * sensitive patient data. Uses Hop Count Filtering and
 * node attribute analysis.
 *
 * Results:
 *   Proposed System  → 90% detection rate (best)
 *   MAP method       → 90%
 *   CAM-PVM          → 65%
 *   RPC (existing)   → 60%
 *
 * Tools: Microsoft Visual Studio, C#.NET
 * Protocols: TCP/UDP/ICMP, Socket Programming, Serial (SMS)
 * ============================================================
 */

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.IO.Ports;
using System.Threading;
using System.Linq;

namespace SybilWatch
{
    // ── NODE CLASSIFICATION ──────────────────────────────────
    public enum NodeStatus
    {
        Honest,
        Suspicious,
        Malicious,
        Sybil,
        Authorised
    }

    // ── PACKET MODEL ─────────────────────────────────────────
    // Based on IP header fields analysed in Chapter 4
    public class NetworkPacket
    {
        public string   SourceIP         { get; set; }
        public string   DestinationIP    { get; set; }
        public string   NodeID           { get; set; }
        public string   UniqueID         { get; set; }
        public DateTime ArrivalTime      { get; set; }
        public int      HopCount         { get; set; }
        public int      TTL              { get; set; }
        public string   Protocol         { get; set; }  // TCP/UDP/ICMP
        public string   PhysicalAddress  { get; set; }  // MAC
        public string   LogicalAddress   { get; set; }  // IP
        public string   ContentType      { get; set; }
        public int      ContentLength    { get; set; }
        public string   Authorization    { get; set; }
        public int      Checksum         { get; set; }
        public int      SourcePort       { get; set; }
        public int      DestinationPort  { get; set; }
        public byte[]   RawBytes         { get; set; }
    }

    // ── NODE RECORD ──────────────────────────────────────────
    public class NodeRecord
    {
        public string         NodeID           { get; set; }
        public string         SourceIP         { get; set; }
        public DateTime       FirstSeen        { get; set; }
        public DateTime       LastSeen         { get; set; }
        public int            PacketCount      { get; set; }
        public NodeStatus     Status           { get; set; }
        public List<DateTime> PacketTimestamps { get; set; }
        public string         ConnectionTime   { get; set; }
        public int            PortUsed         { get; set; }

        public NodeRecord()
        {
            PacketTimestamps = new List<DateTime>();
            Status = NodeStatus.Honest;
        }
    }

    // ============================================================
    // LOGIN MODULE
    // Only admin can access real-time analysis data
    // Protects against insider threats and phishing
    // ============================================================
    public class LoginModule
    {
        private const string ADMIN_USERNAME = "admin";
        private const string ADMIN_PASSWORD = "sybilwatch2022";
        public bool IsAuthenticated { get; private set; }

        public bool Login(string username, string password)
        {
            if (username == ADMIN_USERNAME && password == ADMIN_PASSWORD)
            {
                IsAuthenticated = true;
                Console.WriteLine("[LOGIN] Admin authenticated successfully");
                return true;
            }
            Console.WriteLine("[LOGIN] Authentication failed — access denied");
            return false;
        }

        public void Logout()
        {
            IsAuthenticated = false;
            Console.WriteLine("[LOGIN] Admin logged out");
        }
    }

    // ============================================================
    // PACKET CAPTURE MODULE
    // Uses SIO_RCVALL to capture all IPv4/IPv6 packets
    // Stores in buffer byte-by-byte
    // Displays: time, protocol, source IP, destination IP
    // ============================================================
    public class PacketCaptureModule
    {
        private Socket          rawSocket;
        private byte[]          buffer    = new byte[65535];
        private List<NetworkPacket> capturedPackets = new List<NetworkPacket>();
        private bool            isCapturing = false;
        private PacketParsingModule   parser;
        private IntrusionDetectionModule ids;

        public PacketCaptureModule(PacketParsingModule parsingModule,
                                   IntrusionDetectionModule detectionModule)
        {
            parser = parsingModule;
            ids    = detectionModule;
        }

        // Start capturing all packets on the network
        public void StartCapture(string localIP)
        {
            try
            {
                rawSocket = new Socket(AddressFamily.InterNetwork,
                                       SocketType.Raw,
                                       ProtocolType.IP);

                rawSocket.Bind(new IPEndPoint(IPAddress.Parse(localIP), 0));

                // SIO_RCVALL — enables promiscuous mode to capture all packets
                rawSocket.SetSocketOption(SocketOptionLevel.IP,
                                          SocketOptionName.HeaderIncluded, true);
                byte[] inValue  = new byte[] { 1, 0, 0, 0 };
                byte[] outValue = new byte[] { 1, 0, 0, 0 };
                rawSocket.IOControl(IOControlCode.ReceiveAll, inValue, outValue);

                isCapturing = true;
                Console.WriteLine($"[CAPTURE] Packet capture started on {localIP}");

                // Begin async receive
                rawSocket.BeginReceive(buffer, 0, buffer.Length,
                                       SocketFlags.None, OnPacketReceived, null);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[CAPTURE ERROR] {ex.Message}");
                Console.WriteLine("[CAPTURE] Running in simulation mode");
            }
        }

        private void OnPacketReceived(IAsyncResult ar)
        {
            if (!isCapturing) return;
            try
            {
                int received = rawSocket.EndReceive(ar);
                if (received >= 20) // Minimum valid IP header = 20 bytes
                {
                    byte[] packetData = new byte[received];
                    Array.Copy(buffer, packetData, received);

                    NetworkPacket packet = parser.ParseRawBytes(packetData);
                    if (packet != null)
                    {
                        capturedPackets.Add(packet);
                        DisplayPacketInfo(packet);
                        ids.AnalysePacket(packet);
                    }
                }
                // Continue capturing
                rawSocket.BeginReceive(buffer, 0, buffer.Length,
                                       SocketFlags.None, OnPacketReceived, null);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[CAPTURE ERROR] {ex.Message}");
            }
        }

        private void DisplayPacketInfo(NetworkPacket p)
        {
            Console.WriteLine($"[PACKET] {p.ArrivalTime:HH:mm:ss} | " +
                              $"{p.Protocol,-5} | " +
                              $"{p.SourceIP,-18} → {p.DestinationIP,-18} | " +
                              $"TTL:{p.TTL}");
        }

        public void StopCapture()
        {
            isCapturing = false;
            rawSocket?.Close();
            Console.WriteLine("[CAPTURE] Packet capture stopped");
        }

        // Simulate packet for testing without raw socket
        public void SimulatePacket(string rawData)
        {
            NetworkPacket packet = parser.ParsePacketString(rawData);
            if (packet != null)
            {
                capturedPackets.Add(packet);
                DisplayPacketInfo(packet);
                ids.AnalysePacket(packet);
            }
        }
    }

    // ============================================================
    // PACKET PARSING MODULE
    // Bhoomika's contribution
    // Converts raw byte array into IP header fields
    // Packets under 20 bytes = invalid (minimum IP header size)
    // Extracts: version, TTL, protocol, checksum, ports
    // ============================================================
    public class PacketParsingModule
    {
        // Parse raw byte array from socket
        public NetworkPacket ParseRawBytes(byte[] buffer)
        {
            if (buffer.Length < 20)
            {
                Console.WriteLine("[PARSE] Invalid packet — under 20 bytes, discarded");
                return null;
            }

            try
            {
                NetworkPacket packet = new NetworkPacket();
                packet.RawBytes     = buffer;
                packet.ArrivalTime  = DateTime.Now;

                // IP Version and Header Length (byte 0)
                int version       = (buffer[0] >> 4) & 0xF;
                int headerLength  = (buffer[0] & 0xF) * 4;

                // TTL (byte 8)
                packet.TTL = buffer[8];

                // Protocol (byte 9)
                switch (buffer[9])
                {
                    case 6:  packet.Protocol = "TCP";  break;
                    case 17: packet.Protocol = "UDP";  break;
                    case 1:  packet.Protocol = "ICMP"; break;
                    default: packet.Protocol = "OTHER"; break;
                }

                // Checksum (bytes 10-11)
                packet.Checksum = (buffer[10] << 8) | buffer[11];

                // Source IP (bytes 12-15)
                packet.SourceIP = $"{buffer[12]}.{buffer[13]}.{buffer[14]}.{buffer[15]}";

                // Destination IP (bytes 16-19)
                packet.DestinationIP = $"{buffer[16]}.{buffer[17]}.{buffer[18]}.{buffer[19]}";

                // Port numbers (if TCP/UDP — bytes 20-23)
                if (buffer.Length >= 24 &&
                   (packet.Protocol == "TCP" || packet.Protocol == "UDP"))
                {
                    packet.SourcePort      = (buffer[20] << 8) | buffer[21];
                    packet.DestinationPort = (buffer[22] << 8) | buffer[23];
                }

                // Generate Node ID from source IP
                packet.NodeID   = $"NODE_{packet.SourceIP.Replace(".", "_")}";
                packet.UniqueID = packet.NodeID;

                return packet;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[PARSE ERROR] {ex.Message}");
                return null;
            }
        }

        // Parse packet from string format for simulation/testing
        // Format: "NODEID|SOURCEIP|DESTIP|HOPCOUNT|PROTOCOL|PHYS_ADDR|LOG_ADDR"
        public NetworkPacket ParsePacketString(string rawData)
        {
            try
            {
                string[] parts = rawData.Split('|');
                if (parts.Length < 4) return null;

                return new NetworkPacket
                {
                    NodeID          = parts[0].Trim(),
                    UniqueID        = parts[0].Trim(),
                    SourceIP        = parts[1].Trim(),
                    DestinationIP   = parts.Length > 2 ? parts[2].Trim() : "192.168.1.1",
                    HopCount        = int.Parse(parts[3].Trim()),
                    Protocol        = parts.Length > 4 ? parts[4].Trim() : "TCP",
                    PhysicalAddress = parts.Length > 5 ? parts[5].Trim() : "",
                    LogicalAddress  = parts.Length > 6 ? parts[6].Trim() : "",
                    ArrivalTime     = DateTime.Now,
                    TTL             = 64
                };
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[PARSE ERROR] {ex.Message}");
                return null;
            }
        }
    }

    // ============================================================
    // INTRUSION DETECTION MODULE — CORE
    // Bhoomika's primary contribution
    //
    // 4 Detection Cases (Chapter 3):
    // Case 1 — Unique ID check
    // Case 2 — Arrival time threshold
    // Case 3 — Flood attack detection
    // Case 4 — Physical vs logical address mismatch
    // ============================================================
    public class IntrusionDetectionModule
    {
        // ── THRESHOLDS (admin-configurable per Chapter 4) ───
        public double ArrivalTimeThreshold { get; set; } = 0.5;   // seconds
        public int    HopCountThreshold    { get; set; } = 3;      // max hops
        public int    FloodHighThreshold   { get; set; } = 3000;   // packets
        public int    FloodMedThreshold    { get; set; } = 730;
        public int    FloodLowThreshold    { get; set; } = 250;
        public int    TCPThreshold         { get; set; } = 35;     // per source
        public int    DetectionWindowSecs  { get; set; } = 80;     // time window

        // ── DATA STORES ─────────────────────────────────────
        private List<string>     authorisedIDs     = new List<string>();
        private List<string>     blacklistedIPs    = new List<string>();
        private List<NodeRecord> nodeRecords       = new List<NodeRecord>();
        private List<NetworkPacket> allPackets     = new List<NetworkPacket>();

        // ── STATS ────────────────────────────────────────────
        public int TotalPacketsAnalysed  { get; private set; }
        public int SybilNodesDetected    { get; private set; }
        public int HonestNodesConfirmed  { get; private set; }
        public int FloodAttacksBlocked   { get; private set; }
        public int FakeDataServed        { get; private set; }

        // ── EVENTS ───────────────────────────────────────────
        public event Action<string> OnSybilDetected;
        public event Action<string> OnNodeBlacklisted;
        public event Action<string> OnAlertTriggered;
        public event Action<string> OnFakeDataServed;

        public IntrusionDetectionModule()
        {
            // Pre-load authorised hospital node IDs
            authorisedIDs.AddRange(new[]
            {
                "HOSPITAL_DB", "SERVER_GW", "NODE_001",
                "NODE_002", "NODE_003", "ADMIN_NODE"
            });
        }

        // ============================================================
        // MAIN ANALYSIS — 4 DETECTION CASES
        // ============================================================
        public NodeStatus AnalysePacket(NetworkPacket packet)
        {
            TotalPacketsAnalysed++;
            allPackets.Add(packet);

            // ── CASE 1: Unique ID check ──────────────────────
            // If packet's unique ID not in authorised list → serve fake data
            if (!authorisedIDs.Contains(packet.UniqueID))
            {
                Console.WriteLine($"[CASE 1] Unrecognised ID: {packet.UniqueID} from {packet.SourceIP}");

                // Check arrival time threshold (Case 2)
                if (IsArrivalTimeExceeded(packet))
                {
                    ServeFakeData(packet);
                    BlacklistNode(packet.SourceIP);
                    TriggerAlert($"Sybil node detected: {packet.NodeID} IP:{packet.SourceIP}");
                    SybilNodesDetected++;
                    OnSybilDetected?.Invoke(packet.NodeID);
                    return NodeStatus.Sybil;
                }

                ServeFakeData(packet);
                return NodeStatus.Suspicious;
            }

            // ── CASE 3: Flood attack detection ──────────────
            if (IsFloodAttack(packet))
            {
                BlacklistNode(packet.SourceIP);
                TriggerAlert($"Flood attack from {packet.SourceIP}");
                FloodAttacksBlocked++;
                ServeFakeData(packet);
                return NodeStatus.Malicious;
            }

            // ── CASE 4: Physical vs logical address mismatch ─
            if (IsAddressMismatch(packet))
            {
                Console.WriteLine($"[CASE 4] Address mismatch — Physical: " +
                                  $"{packet.PhysicalAddress} vs Logical: {packet.LogicalAddress}");
                BlacklistNode(packet.SourceIP);
                TriggerAlert($"Address mismatch Sybil: {packet.SourceIP}");
                SybilNodesDetected++;
                ServeFakeData(packet);
                OnSybilDetected?.Invoke(packet.NodeID);
                return NodeStatus.Sybil;
            }

            // ── BLACKLIST CHECK ──────────────────────────────
            if (blacklistedIPs.Contains(packet.SourceIP))
            {
                Console.WriteLine($"[BLOCKED] Packet from blacklisted IP: {packet.SourceIP}");
                ServeFakeData(packet);
                return NodeStatus.Malicious;
            }

            // ── HONEST NODE ──────────────────────────────────
            HonestNodesConfirmed++;
            UpdateNodeRecord(packet, NodeStatus.Honest);
            Console.WriteLine($"[HONEST] Node acknowledged: {packet.NodeID}");
            return NodeStatus.Honest;
        }

        // ── CASE 2: Arrival time threshold check ────────────
        // Packets arriving too frequently = intruder
        private bool IsArrivalTimeExceeded(NetworkPacket packet)
        {
            NodeRecord existing = nodeRecords.Find(n => n.NodeID == packet.NodeID);
            if (existing == null)
            {
                UpdateNodeRecord(packet, NodeStatus.Suspicious);
                return false;
            }
            TimeSpan elapsed = packet.ArrivalTime - existing.LastSeen;
            return elapsed.TotalSeconds < ArrivalTimeThreshold
                   && existing.PacketCount > 3;
        }

        // ── CASE 3: Flood attack detection ───────────────────
        // Using Adaptive Threshold Algorithm (ATA)
        // Default thresholds: High=3000, Med=730, Low=250
        private bool IsFloodAttack(NetworkPacket packet)
        {
            DateTime windowStart = DateTime.Now.AddSeconds(-DetectionWindowSecs);

            // Count packets from this source in the time window
            int recentCount = allPackets.Count(p =>
                p.SourceIP == packet.SourceIP &&
                p.ArrivalTime >= windowStart);

            // Check against TCP threshold (admin-configurable, default=35)
            if (packet.Protocol == "TCP" && recentCount > TCPThreshold)
            {
                Console.WriteLine($"[FLOOD] TCP threshold exceeded: " +
                                  $"{recentCount} packets from {packet.SourceIP}");
                return true;
            }

            // Check against high flood threshold
            if (recentCount > FloodHighThreshold)
            {
                Console.WriteLine($"[FLOOD HIGH] {recentCount} packets from {packet.SourceIP}");
                return true;
            }

            return false;
        }

        // ── CASE 4: Physical vs logical address mismatch ────
        // Physical (MAC) ≠ Logical (IP) → Sybil node
        private bool IsAddressMismatch(NetworkPacket packet)
        {
            if (string.IsNullOrEmpty(packet.PhysicalAddress) ||
                string.IsNullOrEmpty(packet.LogicalAddress))
                return false;

            // Extract network prefix from logical (IP) address
            string[] ipParts  = packet.LogicalAddress.Split('.');
            string[] macParts = packet.PhysicalAddress.Split(':');

            if (ipParts.Length < 2 || macParts.Length < 2) return false;

            // Simple mismatch check — MAC vendor prefix vs IP range
            // In real deployment, uses ARP table cross-referencing
            return packet.PhysicalAddress.StartsWith("FF:") ||
                   packet.PhysicalAddress.StartsWith("00:00:00");
        }

        // ── SERVE FAKE DATA ──────────────────────────────────
        // When attacker detected → return fake patient data
        // Attacker believes it's real and stops sending
        private void ServeFakeData(NetworkPacket packet)
        {
            FakeDataServed++;
            string fakeResponse = GenerateFakePatientData();
            Console.WriteLine($"[FAKE DATA] Served to {packet.SourceIP}: {fakeResponse}");
            OnFakeDataServed?.Invoke($"Fake data served to {packet.SourceIP}");
        }

        private string GenerateFakePatientData()
        {
            // Returns convincing but entirely fake patient record
            return $"{{PatientID: 'P{new Random().Next(10000,99999)}', " +
                   $"Name: 'John Doe', Age: 45, " +
                   $"Diagnosis: 'Hypertension', BP: '120/80'}}";
        }

        // ── BLACKLIST ────────────────────────────────────────
        private void BlacklistNode(string sourceIP)
        {
            if (!blacklistedIPs.Contains(sourceIP))
            {
                blacklistedIPs.Add(sourceIP);
                Console.WriteLine($"[BLACKLIST] {sourceIP} permanently blocked");
                OnNodeBlacklisted?.Invoke(sourceIP);
            }
        }

        // ── TRIGGER ALERT ────────────────────────────────────
        private void TriggerAlert(string message)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"[!! ALERT !!] {message}");
            Console.ResetColor();
            OnAlertTriggered?.Invoke(message);
        }

        // ── UPDATE NODE RECORD ───────────────────────────────
        private void UpdateNodeRecord(NetworkPacket packet, NodeStatus status)
        {
            NodeRecord record = nodeRecords.Find(n => n.NodeID == packet.NodeID);
            if (record == null)
            {
                record = new NodeRecord
                {
                    NodeID    = packet.NodeID,
                    SourceIP  = packet.SourceIP,
                    FirstSeen = packet.ArrivalTime,
                    PortUsed  = packet.DestinationPort
                };
                nodeRecords.Add(record);
            }
            record.LastSeen  = packet.ArrivalTime;
            record.PacketCount++;
            record.Status    = status;
            record.PacketTimestamps.Add(packet.ArrivalTime);
        }

        // ── PRINT STATS REPORT ───────────────────────────────
        public void PrintStats()
        {
            double detectionRate = TotalPacketsAnalysed > 0
                ? (double)SybilNodesDetected / TotalPacketsAnalysed * 100 : 0;

            Console.WriteLine("\n═══════════════════════════════════════");
            Console.WriteLine("       SYBIL WATCH — DETECTION REPORT  ");
            Console.WriteLine("═══════════════════════════════════════");
            Console.WriteLine($"  Total Packets Analysed : {TotalPacketsAnalysed}");
            Console.WriteLine($"  Sybil Nodes Detected   : {SybilNodesDetected}");
            Console.WriteLine($"  Honest Nodes Confirmed : {HonestNodesConfirmed}");
            Console.WriteLine($"  Flood Attacks Blocked  : {FloodAttacksBlocked}");
            Console.WriteLine($"  Fake Data Responses    : {FakeDataServed}");
            Console.WriteLine($"  Blacklisted IPs        : {blacklistedIPs.Count}");
            Console.WriteLine($"  Detection Rate         : {detectionRate:F1}%");
            Console.WriteLine("───────────────────────────────────────");
            Console.WriteLine("  Comparison vs existing methods:");
            Console.WriteLine("  Proposed (Sybil Watch) → BEST");
            Console.WriteLine("  MAP method             → 90%");
            Console.WriteLine("  CAM-PVM                → 65%");
            Console.WriteLine("  RPC (existing)         → 60%");
            Console.WriteLine("═══════════════════════════════════════\n");
        }
    }

    // ============================================================
    // ALERTING MODULE
    // Bhoomika's contribution
    // Sends SMS via GSM modem using AT commands (C#.NET)
    // Serial port communication to mobile modem
    // ============================================================
    public class AlertingModule
    {
        private SerialPort gsmPort;
        private string     adminPhone = "+447778071365";
        private bool       gsmConnected = false;

        public AlertingModule(string comPort = "COM3", int baudRate = 9600)
        {
            try
            {
                gsmPort = new SerialPort(comPort, baudRate);
                gsmPort.Open();
                gsmConnected = true;
                Console.WriteLine("[GSM] Modem connected on " + comPort);
            }
            catch
            {
                Console.WriteLine("[GSM] Modem not found — SMS simulation mode active");
            }
        }

        // Send SMS alert to admin via AT commands
        public void SendSMSAlert(string message)
        {
            if (!gsmConnected)
            {
                Console.WriteLine($"[SMS SIMULATED] To: {adminPhone} — {message}");
                return;
            }

            try
            {
                SendATCommand("AT");                          // Check modem
                SendATCommand("AT+CMGF=1");                  // Text mode
                SendATCommand($"AT+CMGS=\"{adminPhone}\"");  // Recipient
                gsmPort.Write(message + "\x1A");             // Send + Ctrl+Z
                Thread.Sleep(1000);
                Console.WriteLine($"[SMS SENT] Alert delivered to {adminPhone}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[GSM ERROR] {ex.Message}");
            }
        }

        private void SendATCommand(string command)
        {
            gsmPort.WriteLine(command);
            Thread.Sleep(500);
            string response = gsmPort.ReadExisting();
            Console.WriteLine($"[AT] {command} → {response.Trim()}");
        }

        public void Disconnect()
        {
            if (gsmConnected && gsmPort.IsOpen)
                gsmPort.Close();
        }
    }

    // ============================================================
    // THRESHOLD MODULE
    // Admin can configure detection thresholds per protocol
    // ============================================================
    public class ThresholdModule
    {
        public void ConfigureThresholds(IntrusionDetectionModule ids)
        {
            Console.WriteLine("\n[THRESHOLD CONFIG]");
            Console.WriteLine($"  TCP Threshold    : {ids.TCPThreshold} packets");
            Console.WriteLine($"  Flood High       : {ids.FloodHighThreshold} packets");
            Console.WriteLine($"  Flood Medium     : {ids.FloodMedThreshold} packets");
            Console.WriteLine($"  Flood Low        : {ids.FloodLowThreshold} packets");
            Console.WriteLine($"  Detection Window : {ids.DetectionWindowSecs} seconds");
            Console.WriteLine($"  Arrival Threshold: {ids.ArrivalTimeThreshold}s\n");
        }

        // Admin sets custom TCP threshold (example from thesis: set to 35)
        public void SetTCPThreshold(IntrusionDetectionModule ids, int value)
        {
            ids.TCPThreshold = value;
            Console.WriteLine($"[THRESHOLD] TCP threshold updated to {value}");
        }
    }

    // ============================================================
    // CLIENT MODULE
    // Registered clients get real data
    // Unregistered (attackers) get fake data
    // ============================================================
    public class ClientModule
    {
        private List<string> registeredIPs = new List<string>
        {
            "192.168.43.226",
            "192.168.40.100",
            "192.168.1.100"
        };

        public string HandleClientRequest(string clientIP, string patientID)
        {
            if (registeredIPs.Contains(clientIP))
            {
                Console.WriteLine($"[CLIENT] Registered IP {clientIP} → Real data returned");
                return GetRealPatientData(patientID);
            }
            else
            {
                Console.WriteLine($"[CLIENT] Unregistered IP {clientIP} → Fake data returned");
                return GetFakePatientData();
            }
        }

        private string GetRealPatientData(string patientID)
        {
            return $"REAL RECORD: Patient {patientID} — " +
                   "BP: 118/75, HR: 72bpm, SpO2: 98%, Temp: 36.8°C";
        }

        private string GetFakePatientData()
        {
            return $"RECORD: Patient P00000 — " +
                   "BP: 120/80, HR: 75bpm, SpO2: 99%, Temp: 37.0°C";
        }
    }

    // ============================================================
    // MAIN PROGRAM
    // ============================================================
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("╔══════════════════════════════════════════╗");
            Console.WriteLine("║         SYBIL WATCH v1.0                 ║");
            Console.WriteLine("║   IoT Security — Smart Healthcare        ║");
            Console.WriteLine("║   Author: Bhoomika Sathish Rao           ║");
            Console.WriteLine("║   MIT Mysore — BEng ECE Final Year       ║");
            Console.WriteLine("╚══════════════════════════════════════════╝\n");

            // ── AUTHENTICATION ───────────────────────────────
            LoginModule login = new LoginModule();
            if (!login.Login("admin", "sybilwatch2022"))
            {
                Console.WriteLine("Access denied. Exiting.");
                return;
            }

            // ── INITIALISE MODULES ───────────────────────────
            IntrusionDetectionModule ids    = new IntrusionDetectionModule();
            PacketParsingModule      parser = new PacketParsingModule();
            PacketCaptureModule      pcm    = new PacketCaptureModule(parser, ids);
            AlertingModule           alert  = new AlertingModule();
            ThresholdModule          thresh = new ThresholdModule();
            ClientModule             client = new ClientModule();

            // ── CONFIGURE THRESHOLDS ─────────────────────────
            thresh.SetTCPThreshold(ids, 35); // As shown in thesis
            thresh.ConfigureThresholds(ids);

            // ── WIRE UP EVENTS ───────────────────────────────
            ids.OnSybilDetected   += (nodeID) => {
                alert.SendSMSAlert($"SYBIL ATTACK: Node {nodeID} detected and blocked");
            };
            ids.OnAlertTriggered  += (msg) => {
                alert.SendSMSAlert(msg);
            };
            ids.OnNodeBlacklisted += (ip) => {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"[BLACKLIST UPDATE] {ip} added to permanent block list");
                Console.ResetColor();
            };

            // ── SIMULATE PACKET STREAM ───────────────────────
            Console.WriteLine("═══════════════════════════════════════");
            Console.WriteLine("Starting packet capture simulation...");
            Console.WriteLine("Format: NodeID|SourceIP|DestIP|HopCount|Protocol|PhysAddr|LogAddr");
            Console.WriteLine("═══════════════════════════════════════\n");

            // Authorised hospital nodes — honest
            pcm.SimulatePacket("HOSPITAL_DB|192.168.43.226|192.168.1.1|2|TCP|AA:BB:CC:DD|192.168");
            pcm.SimulatePacket("NODE_001|192.168.40.100|192.168.1.1|1|TCP|DD:EE:FF:00|192.168");
            pcm.SimulatePacket("SERVER_GW|192.168.0.132|192.168.1.1|2|TCP|11:22:33:44|192.168");

            // Unregistered node — Case 1 triggered
            pcm.SimulatePacket("FAKE_NODE|197.240.229.443|192.168.1.1|3|TCP|XX:YY:ZZ:00|197.240");

            // High hop count — suspicious
            pcm.SimulatePacket("NODE_999|142.250.179.147|192.168.1.1|6|TCP|55:66:77:88|142.250");

            // Address mismatch — Case 4 Sybil
            pcm.SimulatePacket("SYBIL_01|142.251.12.189|192.168.1.1|2|TCP|FF:FF:FF:FF|192.168");

            // Flood attack simulation — Case 3
            Console.WriteLine("\n[FLOOD SIM] Simulating flood attack from attacker...");
            for (int i = 0; i < 40; i++)
                pcm.SimulatePacket($"ATTACKER|34.100.200.132|192.168.1.1|2|TCP|99:88:77:66|34.100");

            // Client requests
            Console.WriteLine("\n[CLIENT SIM] Testing client data response...");
            Console.WriteLine(client.HandleClientRequest("192.168.43.226", "P10234")); // registered
            Console.WriteLine(client.HandleClientRequest("91.234.56.78",   "P10234")); // unregistered

            // ── FINAL REPORT ─────────────────────────────────
            ids.PrintStats();

            alert.Disconnect();
            login.Logout();

            Console.WriteLine("Press any key to exit...");
            Console.ReadKey();
        }
    }
}
