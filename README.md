# Sybil Watch — IoT Security in Smart Healthcare
**BEng Final Year Thesis — Maharaja Institute of Technology (2022)**

A lightweight, real-time intrusion detection system built to identify and block Sybil attacks in IoT-enabled smart healthcare networks. Achieved a **90% detection rate** compared to 60% in existing RPC-based methods.

---

## 🛠️ Tools & Technologies
- **Language:** C#, .NET
- **Networking:** TCP/IP, Wireless Networks
- **Tools:** Visual Studio, Database Systems
- **Alerting:** GSM Modem (AT Commands) for SMS-based real-time alerts

---

## 🎯 Objective
Detect and block Sybil attacks in IoT healthcare networks while preserving data integrity, user privacy, and network reliability — using lightweight detection logic that outperforms existing methods.

---

## ⚙️ System Architecture

```
IoT Network
    ↓
Packet Capture Layer (TCP/IP parsing)
    ↓
Detection Engine
  ├── Hop Count Filtering
  ├── Packet Timing Analysis
  └── Node Classification: Honest / Malicious / Sybil
    ↓
Prevention Layer
  ├── Auto-blacklist intruding nodes
  └── SMS Alert via GSM Modem
```

---

## 🧠 Detection Logic (Pseudocode)
```
if (packet.ID not in authorizedList) {
  if (packet.arrivalTime > threshold) {
    blacklist(packet.sourceIP);
    sendAlert();
  }
}
```

---

## 🔧 Modular Architecture
| Module | Function |
|---|---|
| Login & Authorization | Secure access control |
| Packet Capture | Live TCP/IP packet parsing |
| Intrusion Detection | Hop Count + timing-based node classification |
| Flood Attack Mitigation | Rate limiting and pattern analysis |
| Real-time Alerts | GSM modem SMS notification system |

---

## 👩‍💻 My Contribution (3-member team)
- **Intrusion Detection Module** — core detection logic
- **Packet parsing implementation** — live TCP/IP analysis
- **GSM modem SMS alerting** — real-time notification system
- **Testing & evaluation documentation** — full test report

---

## 📊 Results
| Metric | Sybil Watch | Existing RPC Method |
|---|---|---|
| Detection Rate | **90%** | 60% |
| False Positive Rate | Low | High |
| Response Time | Real-time | Delayed |

- Strengthened network security in IoT healthcare environments
- Reduced vulnerability to identity spoofing and DDoS attacks
- Automated prevention with dynamic blacklist updating

---

## 📁 Repository Structure
```
sybil-watch/
├── src/
│   ├── DetectionModule/      # Core intrusion detection logic
│   ├── PacketCapture/        # TCP/IP packet parsing
│   └── AlertSystem/          # GSM modem SMS alerts
├── docs/
│   └── thesis_report.pdf
├── images/
│   ├── architecture_diagram.png
│   ├── monitoring_window.png
│   └── flowchart.png
└── README.md
```

---

## 👩‍💻 About
Built by **Bhoomika Sathish Rao** as BEng Final Year Thesis at Maharaja Institute of Technology.
- 📧 bhoomikasrao2k@gmail.com
- 🔗 [LinkedIn](https://linkedin.com/in/bhoomika-sathish-rao-030095229)
- 🗂️ [Full Portfolio](https://bit.ly/45JJ9Zg)
