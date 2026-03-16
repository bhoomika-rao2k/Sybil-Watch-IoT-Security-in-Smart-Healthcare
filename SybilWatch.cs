/*
 * ============================================================
 * Sybil Watch — IoT Security in Smart Healthcare
 * ============================================================
 * Author      : Bhoomika Sathish Rao
 * Institution : Maharaja Institute of Technology
 * Degree      : BEng Electronics & Communication Engineering
 * Year        : 2022
 * Team Size   : 3 members
 *
 * My Contribution:
 *   - Intrusion Detection Module (this file)
 *   - Packet parsing logic
 *   - Real-time SMS alerting via GSM modem
 *   - Testing and evaluation documentation
 *
 * Description:
 * A lightweight real-time detection system to identify and
 * block Sybil attacks in IoT-enabled smart healthcare networks.
 * Achieved 90% detection rate vs 60% in existing RPC methods.
 *
 * Detection Method:
 *   - Hop Count Filtering
 *   - Packet arrival time threshold analysis
 *   - Node classification: Honest / Malicious / Sybil
 *   - Automatic blacklisting + GSM SMS alerts
 * ============================================================
 */

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.IO.Ports;
using System.Threading;

namespace SybilWatch
{
    // ── NODE CLASSIFICATION ──────────────────────────────────
    public enum NodeStatus
    {
        Honest,
        Suspicious,
        Malicious,
        Sybil
    }

    // ── PACKET MODEL ────────────────────────────────────────
    public class NetworkPacket
    {
        public string SourceIP       { get; set; }
        public string NodeID         { get; set; }
        public DateTime ArrivalTime  { get; set; }
        public int HopCount          { get; set; }
        public string PhysicalAddress { get; set; }
        public string LogicalAddress  { get; set; }
        public bool IsFloodPacket    { get; set; }
    }

    // ── NODE RECORD ─────────────────────────────────────────
    public class NodeRecord
    {
        public string NodeID          { get; set; }
        public string SourceIP        { get; set; }
        public DateTime FirstSeen     { get; set; }
        public DateTime LastSeen      { get; set; }
        public int PacketCount        { get; set; }
        public NodeStatus Status      { get; set; }
        public List<DateTime> PacketTimestamps { get; set; }

        public NodeRecord()
        {
            PacketTimestamps = new List<DateTime>();
            Status = NodeStatus.Honest;
        }
    }

    // ============================================================
    // INTRUSION DETECTION MODULE
    // Bhoomika's primary contribution
    // ============================================================
    public class IntrusionDetectionModule
    {
        // ── CONFIGURATION ───────────────────────────────────
        private const double ARRIVAL_TIME_THRESHOLD = 0.5;    // seconds
        private const int    HOP_COUNT_THRESHOLD    = 3;      // max hops
        private const int    FLOOD_PACKET_THRESHOLD = 50;     // packets/min
        private const int    DETECTION_WINDOW_SECS  = 60;     // monitoring window

        // ── DATA STORES ─────────────────────────────────────
        private List<string>     authorizedNodeIDs = new List<string>();
        private List<string>     blacklistedIPs    = new List<string>();
        private List<NodeRecord> nodeRecords       = new List<NodeRecord>();

        // ── EVENTS ──────────────────────────────────────────
        public event Action<string> OnSybilDetected;
        public event Action<string> OnNodeBlacklisted;
        public event Action<string> OnAlertTriggered;

        // ── STATS ───────────────────────────────────────────
        public int TotalPacketsAnalysed { get; private set; }
        public int SybilNodesDetected   { get; private set; }
        public int HonestNodesConfirmed { get; private set; }

        public IntrusionDetectionModule()
        {
            // Pre-load authorised node IDs
            authorizedNodeIDs.Add("NODE_001");
            authorizedNodeIDs.Add("NODE_002");
            authorizedNodeIDs.Add("NODE_003");
            authorizedNodeIDs.Add("HOSPITAL_DB");
            authorizedNodeIDs.Add("SERVER_GW");
        }

        // ============================================================
        // CORE DETECTION LOGIC
        // Based on flowchart: Bhoomika's thesis portfolio
        // ============================================================
        public NodeStatus AnalysePacket(NetworkPacket packet)
        {
            TotalPacketsAnalysed++;

            // ── STEP 1: Check if already blacklisted ────────
            if (blacklistedIPs.Contains(packet.SourceIP))
            {
                Console.WriteLine($"[BLOCKED] Packet from blacklisted IP: {packet.SourceIP}");
                return NodeStatus.Malicious;
            }

            // ── STEP 2: Check if Node ID is authorised ──────
            if (!authorizedNodeIDs.Contains(packet.NodeID))
            {
                // Node not in authorised list — check arrival time
                if (IsArrivalTimeExcessive(packet))
                {
                    // Blacklist and alert
                    BlacklistNode(packet.SourceIP);
                    TriggerAlert(packet.SourceIP);
                    SybilNodesDetected++;
                    Console.WriteLine($"[SYBIL DETECTED] Node: {packet.NodeID} IP: {packet.SourceIP}");
                    OnSybilDetected?.Invoke($"Sybil node detected: {packet.NodeID}");
                    return NodeStatus.Sybil;
                }

                // Check for flood attack
                if (IsFloodAttack(packet))
                {
                    BlacklistNode(packet.SourceIP);
                    TriggerAlert(packet.SourceIP);
                    Console.WriteLine($"[FLOOD ATTACK] From: {packet.SourceIP}");
                    return NodeStatus.Malicious;
                }

                // Check physical vs logical address mismatch
                if (IsAddressMismatch(packet))
                {
                    BlacklistNode(packet.SourceIP);
                    TriggerAlert(packet.SourceIP);
                    SybilNodesDetected++;
                    Console.WriteLine($"[SYBIL — ADDRESS MISMATCH] Node: {packet.NodeID}");
                    return NodeStatus.Sybil;
                }
            }

            // ── STEP 3: Hop count filtering ─────────────────
            if (packet.HopCount > HOP_COUNT_THRESHOLD)
            {
                Console.WriteLine($"[SUSPICIOUS] Hop count exceeded: {packet.HopCount} hops from {packet.NodeID}");
                UpdateNodeRecord(packet, NodeStatus.Suspicious);
                return NodeStatus.Suspicious;
            }

            // ── STEP 4: Node passes all checks — Honest ─────
            HonestNodesConfirmed++;
            UpdateNodeRecord(packet, NodeStatus.Honest);
            Console.WriteLine($"[HONEST] Node acknowledged: {packet.NodeID}");
            return NodeStatus.Honest;
        }

        // ============================================================
        // CHECK ARRIVAL TIME THRESHOLD
        // Excessive arrival time indicates potential Sybil behaviour
        // ============================================================
        private bool IsArrivalTimeExcessive(NetworkPacket packet)
        {
            NodeRecord existing = nodeRecords.Find(n => n.NodeID == packet.NodeID);
            if (existing == null) return false;

            TimeSpan timeSinceLastSeen = packet.ArrivalTime - existing.LastSeen;
            return timeSinceLastSeen.TotalSeconds > ARRIVAL_TIME_THRESHOLD
                   && existing.PacketCount > 5;
        }

        // ============================================================
        // FLOOD ATTACK DETECTION
        // Checks if a node is sending too many packets per minute
        // ============================================================
        private bool IsFloodAttack(NetworkPacket packet)
        {
            NodeRecord record = nodeRecords.Find(n => n.NodeID == packet.NodeID);
            if (record == null) return false;

            DateTime windowStart = DateTime.Now.AddSeconds(-DETECTION_WINDOW_SECS);
            int recentPackets = record.PacketTimestamps.FindAll(t => t > windowStart).Count;

            return recentPackets > FLOOD_PACKET_THRESHOLD;
        }

        // ============================================================
        // ADDRESS MISMATCH DETECTION
        // Physical address not matching logical address = Sybil indicator
        // ============================================================
        private bool IsAddressMismatch(NetworkPacket packet)
        {
            if (string.IsNullOrEmpty(packet.PhysicalAddress) ||
                string.IsNullOrEmpty(packet.LogicalAddress))
                return false;

            // Compare physical address origin with logical address
            // Mismatch indicates a node spoofing its identity
            return !packet.PhysicalAddress.StartsWith(
                packet.LogicalAddress.Substring(0, 
                Math.Min(4, packet.LogicalAddress.Length)));
        }

        // ============================================================
        // BLACKLIST A NODE
        // Prevents future packets from this IP being processed
        // ============================================================
        private void BlacklistNode(string sourceIP)
        {
            if (!blacklistedIPs.Contains(sourceIP))
            {
                blacklistedIPs.Add(sourceIP);
                Console.WriteLine($"[BLACKLISTED] IP added to blacklist: {sourceIP}");
                OnNodeBlacklisted?.Invoke(sourceIP);
            }
        }

        // ============================================================
        // TRIGGER ALERT
        // Sends alert — connected to GSM SMS module
        // ============================================================
        private void TriggerAlert(string sourceIP)
        {
            string alertMessage = $"ALERT: Sybil/Malicious node detected. IP: {sourceIP} at {DateTime.Now}";
            Console.WriteLine($"[ALERT] {alertMessage}");
            OnAlertTriggered?.Invoke(alertMessage);
        }

        // ============================================================
        // UPDATE NODE RECORD
        // Maintains history of each node's behaviour
        // ============================================================
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
                    Status    = status
                };
                nodeRecords.Add(record);
            }

            record.LastSeen  = packet.ArrivalTime;
            record.PacketCount++;
            record.Status    = status;
            record.PacketTimestamps.Add(packet.ArrivalTime);
        }

        // ── STATS REPORT ────────────────────────────────────
        public void PrintStats()
        {
            double detectionRate = TotalPacketsAnalysed > 0
                ? (double)SybilNodesDetected / TotalPacketsAnalysed * 100 : 0;

            Console.WriteLine("\n═══════════════════════════════");
            Console.WriteLine("     SYBIL WATCH — STATISTICS  ");
            Console.WriteLine("═══════════════════════════════");
            Console.WriteLine($"Total Packets Analysed : {TotalPacketsAnalysed}");
            Console.WriteLine($"Sybil Nodes Detected   : {SybilNodesDetected}");
            Console.WriteLine($"Honest Nodes Confirmed : {HonestNodesConfirmed}");
            Console.WriteLine($"Blacklisted IPs        : {blacklistedIPs.Count}");
            Console.WriteLine($"Detection Rate         : {detectionRate:F1}%");
            Console.WriteLine("═══════════════════════════════\n");
        }
    }

    // ============================================================
    // PACKET CAPTURE MODULE
    // Bhoomika's contribution — packet parsing logic
    // ============================================================
    public class PacketCaptureModule
    {
        private IntrusionDetectionModule ids;

        public PacketCaptureModule(IntrusionDetectionModule detectionModule)
        {
            ids = detectionModule;
        }

        // Parse and analyse a raw packet string
        public void ProcessRawPacket(string rawData)
        {
            NetworkPacket packet = ParsePacket(rawData);
            if (packet != null)
            {
                ids.AnalysePacket(packet);
            }
        }

        // ── PACKET PARSER ───────────────────────────────────
        private NetworkPacket ParsePacket(string rawData)
        {
            try
            {
                // Expected format: "NODEID|SOURCEIP|HOPCOUNT|PHYS_ADDR|LOG_ADDR"
                string[] parts = rawData.Split('|');
                if (parts.Length < 4) return null;

                return new NetworkPacket
                {
                    NodeID          = parts[0].Trim(),
                    SourceIP        = parts[1].Trim(),
                    HopCount        = int.Parse(parts[2].Trim()),
                    PhysicalAddress = parts.Length > 3 ? parts[3].Trim() : "",
                    LogicalAddress  = parts.Length > 4 ? parts[4].Trim() : "",
                    ArrivalTime     = DateTime.Now,
                    IsFloodPacket   = false
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
    // GSM ALERT MODULE
    // Bhoomika's contribution — real-time SMS via GSM modem
    // ============================================================
    public class GSMAlertModule
    {
        private SerialPort gsmPort;
        private string alertPhoneNumber = "+447778071365"; // configurable

        public GSMAlertModule(string comPort = "COM3", int baudRate = 9600)
        {
            try
            {
                gsmPort = new SerialPort(comPort, baudRate);
                gsmPort.Open();
                Console.WriteLine("[GSM] Modem connected successfully");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[GSM] Could not connect to modem: {ex.Message}");
            }
        }

        // ── SEND SMS ALERT ──────────────────────────────────
        public void SendSMSAlert(string message)
        {
            if (gsmPort == null || !gsmPort.IsOpen)
            {
                Console.WriteLine($"[GSM SIMULATION] SMS Alert: {message}");
                return;
            }

            try
            {
                // AT commands for GSM modem
                gsmPort.WriteLine("AT");
                Thread.Sleep(500);

                gsmPort.WriteLine("AT+CMGF=1"); // Set SMS to text mode
                Thread.Sleep(500);

                gsmPort.WriteLine($"AT+CMGS=\"{alertPhoneNumber}\"");
                Thread.Sleep(500);

                gsmPort.WriteLine(message + "\x1A"); // \x1A = Ctrl+Z to send
                Thread.Sleep(1000);

                Console.WriteLine($"[GSM] SMS sent: {message}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[GSM ERROR] {ex.Message}");
            }
        }

        public void Disconnect()
        {
            if (gsmPort != null && gsmPort.IsOpen)
                gsmPort.Close();
        }
    }

    // ============================================================
    // MAIN PROGRAM — SYSTEM ENTRY POINT
    // ============================================================
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("╔════════════════════════════════════╗");
            Console.WriteLine("║     SYBIL WATCH v1.0               ║");
            Console.WriteLine("║  IoT Security — Smart Healthcare   ║");
            Console.WriteLine("║  Author: Bhoomika Sathish Rao      ║");
            Console.WriteLine("╚════════════════════════════════════╝\n");

            // Initialise modules
            IntrusionDetectionModule ids = new IntrusionDetectionModule();
            PacketCaptureModule      pcm = new PacketCaptureModule(ids);
            GSMAlertModule           gsm = new GSMAlertModule();

            // Wire up events
            ids.OnSybilDetected   += (msg) => {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"[!] {msg}");
                Console.ResetColor();
                gsm.SendSMSAlert(msg);
            };

            ids.OnNodeBlacklisted += (ip) => {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"[BLACKLIST] {ip} has been blocked");
                Console.ResetColor();
            };

            ids.OnAlertTriggered  += (alert) => {
                Console.ForegroundColor = ConsoleColor.Magenta;
                Console.WriteLine($"[ALERT TRIGGERED] {alert}");
                Console.ResetColor();
            };

            // ── SIMULATE PACKET STREAM ──────────────────────
            Console.WriteLine("Starting packet capture simulation...\n");

            // Honest nodes
            pcm.ProcessRawPacket("NODE_001|192.168.43.226|2|AA:BB:CC|192.168");
            pcm.ProcessRawPacket("NODE_002|192.168.40.100|1|DD:EE:FF|192.168");
            pcm.ProcessRawPacket("HOSPITAL_DB|192.168.43.226|2|AA:BB:CC|192.168");

            // Suspicious — high hop count
            pcm.ProcessRawPacket("NODE_999|197.240.229.443|5|XX:YY:ZZ|197.240");

            // Sybil node — unauthorised ID
            pcm.ProcessRawPacket("FAKE_NODE|142.250.179.147|3|AA:BB:CC|192.168");

            // Flood simulation
            for (int i = 0; i < 5; i++)
                pcm.ProcessRawPacket($"NODE_003|142.251.12.189|2|GG:HH:II|142.251");

            // Print detection statistics
            ids.PrintStats();

            gsm.Disconnect();

            Console.WriteLine("Press any key to exit...");
            Console.ReadKey();
        }
    }
}
