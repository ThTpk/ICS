# เนื้อหารายวิชา Information and Computer Security (ICS)

> แหล่งที่มา: https://sites.google.com/kmitl.ac.th/ics/home (สไลด์ 14 ไฟล์ + Infographics + Clips)
> ผู้สอน: ผศ.ดร. ธนัญชัย ตรีภาค · ภาคเรียน 2569/1
> เอกสารนี้ = โครงเนื้อหาสำหรับทำ visualization ยังไม่ได้เขียนโค้ดใดๆ

---

## 0. ภาพรวม — ปรัชญาของวิชานี้

วิชานี้ **ไม่ได้สอนให้ท่องศัพท์** แต่ไล่ระดับพฤติกรรมการเรียนรู้ตาม Bloom's Taxonomy
และเน้นหนักที่ 3 ระดับกลาง:

| ระดับ | คำถามที่ใช้ |
|---|---|
| รู้ | คืออะไร มีอะไรบ้าง |
| **เข้าใจ** | ทำอย่างไร ยกตัวอย่าง อธิบายด้วยสำนวนตนเอง |
| **ประยุกต์** | นำไปใช้กับอะไรได้ จงออกแบบ |
| **วิเคราะห์** | ข้อดีข้อเสียคืออะไร แล้วจะเกิดอะไรขึ้นถ้า... |
| สังเคราะห์ | องค์ประกอบของระบบมีอะไร กระทบใครบ้าง อย่างไร |
| ประเมิน/สร้างสรรค์ | อะไรดีกว่ากัน เลือกทางไหนดี สร้างอะไรใหม่ได้ |

**นัยต่อการทำ visualization:** ของทุกชิ้นต้อง "ให้ผู้เรียนลงมือตัดสินใจ" ไม่ใช่แค่ดูภาพเคลื่อนไหว
ทุกบทในสไลด์จบด้วยคำถาม `Q :` และกิจกรรมกลุ่ม — คำถามเหล่านี้คือ **บทสรุปของ interaction** ที่ควรแปลงเป็น widget

**เกณฑ์ให้คะแนน:** Assignment 40 · การบ้าน/quiz/กิจกรรมในห้อง 10 · Final 50

---

## 1. Introduction / Course Outline
`00 Course Outline.pdf`

### แก่นเนื้อหา
- เส้นเวลาวิวัฒนาการ: TCP/IP (1975) → IEEE 802.11 (1997) → IPv6 (1998) → Web Service → Cloud
  เทียบกับเส้น Security: *No security* → *Security as optional/tools* → *Secure Design*
  และ *Simple Attacks* → *Threats* ที่ซับซ้อนขึ้น
- ผลลัพธ์การเรียนรู้ 5 ข้อ: อธิบายศัพท์+ยกตัวอย่างได้ / ระบุปัญหาความปลอดภัยจากสเปกระบบได้ /
  เลือกวิธีกับเครื่องมือตรวจสอบ-ป้องกัน-แก้ไขได้ / ประยุกต์หลักการกับเครือข่ายได้ / ระบุอุปกรณ์-ซอฟต์แวร์ที่จำเป็นได้

### 💡 Visualization ที่เสนอ
**"Security Timeline"** — แถบเวลาเลื่อนได้ 1975 → ปัจจุบัน สองเลน (Technology / Threat)
เลื่อนไปจุดไหนแล้วเห็นว่า "ยุคนั้นมีเทคโนโลยีอะไร ภัยหน้าตาแบบไหน และมาตรฐานตอบสนองยังไง"
ใช้เป็นหน้าแรกของเว็บ ทำหน้าที่เป็น **สารบัญของทั้งคอร์ส** (คลิกยุค → กระโดดไปบทที่เกี่ยวข้อง)

---

## 2. IT Systems & Enterprise Architecture
`01 Information Systems.pdf`

### แก่นเนื้อหา
- **คำถามหลัก:** "ผู้ดูแลระบบทะเบียน ควรรู้รายละเอียดเกี่ยวกับอะไรบ้าง"
- องค์ประกอบระบบสารสนเทศ 6 ด้าน: **Hardware · Software · Network · Data · People · Process**
- 7 เสาของ IT Infrastructure: Hardware, Software, Network, Security, Cloud, Data, Management
  (แต่ละเสามี: อุปกรณ์/เครื่องมือ → ข้อกำหนดการติดตั้ง → เครื่องมือ config → เส้นทางอาชีพ → certification)
- **Enterprise Architecture frameworks:** TOGAF (ADM 8 เฟส A–H), Zachman (6×6 What/How/Where/Who/When/Why), FEAF, Gartner
- TOGAF 4 ชั้น: Business → Application → Data → Technology Architecture (ต้อง *align* กัน)
- สิ่งที่ต้องรู้เกี่ยวกับองค์กร 10 ข้อ: Vision/Mission, โครงสร้างองค์กร, IT Infrastructure ปัจจุบัน,
  Application Portfolio, Data & Analytics, Cybersecurity Landscape, Compliance, งบ IT, Business Process, IT Governance

### กิจกรรม
กลุ่ม — สมมติบริษัทขึ้นมา 1 แห่ง แล้วเขียน TOGAF EA ครบ 4 ชั้น + วาด Network Diagram + ระบุว่าอะไรต้อง align กัน

### 💡 Visualization ที่เสนอ
**"EA Stack Explorer"** — ปิรามิด 4 ชั้นของ TOGAF คลิกชั้นไหนขยายเห็นองค์ประกอบ
และมี **เส้น align** ลากข้ามชั้น: เปลี่ยน Business Process หนึ่งข้อ → ไฮไลต์ว่า Application/Data/Technology ใดกระทบ
เสริมด้วย **Zachman Matrix 6×6** แบบคลิกช่อง (เติมตัวอย่างจริงของระบบทะเบียนมหาวิทยาลัย)

---

## 3. CIA / AAA / PDR ⭐ (บทแกนของวิชา)
`02 CIAAAAPDR.pdf` · Infographic: *CIA/AAA/PDR* · Clips 3 ตอน · Activity Sheet

### แก่นเนื้อหา — 9 หลักการ
| กลุ่ม | หลักการ | นิยามสั้น | ตัวอย่าง Process / System / Device |
|---|---|---|---|
| **CIA** | Confidentiality | ข้อมูลลับต้องไม่ถูกเปิดเผยต่อผู้ไม่มีสิทธิ์ | Data Classification Policy / BitLocker, VeraCrypt, SSL-TLS / HSM |
| | Integrity | ข้อมูลถูกต้อง สมบูรณ์ ไม่ถูกแก้ไข | Change Control / FIM (Tripwire, OSSEC, SHA-256) / Digital Signature Pad |
| | Availability | เรียกใช้ได้ตาม SLA | DR Plan + hot site / Load Balancer (F5, AWS ELB) / RAID 1 |
| **AAA** | Authentication | "คุณเป็นใครจริงไหม" — What you know / have / are | MFA / RADIUS, TACACS+ (Cisco ISE, FreeRADIUS) / YubiKey |
| | Authorization | "รู้แล้วว่าคุณคือใคร แล้วทำอะไรได้" — Least Privilege | RBAC / Active Directory Security Groups + ACL / Firewall ACL |
| | Accounting | "คุณทำอะไรไว้ เมื่อไหร่" — audit trail, non-repudiation | Log Review & Audit (PCI-DSS) / SIEM (Splunk, QRadar) / Syslog Server |
| **PDR** | Prevent | ภัยที่รู้ว่าจะเกิด ต้องกำหนดการป้องกัน — Defense in Depth | Patch Management / Antivirus-EDR (CrowdStrike) / NGFW (Palo Alto) |
| | Detect | ต้องตรวจจับและแจ้งเตือนได้ — สมมติว่า Prevent จะพังสักวัน | SOC Alert Triage / IDS (Snort, Suricata) / Network TAP |
| | Respond | ตอบสนองทันท่วงที — Contain → Eradicate → Recover → Lessons Learned | IR Playbook / SOAR (Cortex XSOAR) / NAC quarantine VLAN |

- **ตาราง Concept × Component** (9 หลักการ × Hardware/Software/Network/Data/People/Process) — ตารางกากบาทในสไลด์
- Activity 5 ตาราง: (1) ภัยคุกคาม 10 อันดับ + ผลกระทบ → (2) ภัยคุกคามกับหลักการที่ขาด →
  (4) กิจกรรมส่งเสริมความปลอดภัย → (5) จับคู่กิจกรรมกับภัยคุกคาม
  พร้อมคำถามปิดท้าย: *ทำครั้งเดียว / ทำทุกปี / ทำ N ปีครั้ง — ทำทั้งหมดแล้วมั่นใจกี่ %*

### 💡 Visualization ที่เสนอ
1. **"CIA/AAA/PDR Matrix"** — ตาราง 9 × 6 แบบ interactive คลิกช่องแล้วขึ้นการ์ด Process/System/Device จริง
2. **"Threat → Missing Principle"** — ลากภัยคุกคาม (ไฟฟ้าดับ, ลักลอบใช้งาน, ransomware, sniffing...)
   ไปวางบนหลักการที่ขาด ระบบเฉลยพร้อมเหตุผล → นี่คือ **Activity Sheet ในรูปแบบดิจิทัล**
3. **"PDR Lifecycle"** — วงจร Prevent → Detect → Respond ที่กดจำลองเหตุได้ เห็นว่าถ้า Prevent พัง Detect ต้องทำอะไรต่อ

---

## 4. Computer Networking & Network Diagram
`03 NetworkDiagram.pdf` · Clip

### แก่นเนื้อหา
- ทบทวนพื้นฐาน: **TCP, UDP, IP, ARP, ICMP**
- คำถามไล่ลำดับ packet:
  - A ping B ในเครือข่ายเดียวกัน → เกิดการส่งข้อมูลกี่ครั้ง ใช้โปรโตคอลอะไรบ้าง (ARP → ICMP)
  - A เปิดหน้าเว็บของ Server B ในเครือข่ายติดกัน → กี่ครั้ง โปรโตคอลอะไรบ้าง (ARP → DNS → TCP handshake → HTTP)
- **ชนิดของ Network Diagram**
  - Logical Network Diagram (L3+)
  - Physical Network Diagram (L2−): Site Connection / Switch Network / Device Connection
- คำถามเชิงวิพากษ์: *ไม่มี Diagram แล้วดูแลระบบไม่ได้ จริงหรือไม่* · *Diagram รูปเดียวอธิบายได้ครบไหม* ·
  *Diagram ควรให้รายละเอียดอะไรบ้าง*
- กิจกรรม 4 สาขา (A–D) ที่มีสเปกต่างกัน (จำนวนอาคาร/ชั้น/แผนก/อุปกรณ์, Web/DB/FTP/Mail Server,
  การ Sync Database ข้ามสาขา, Lease Line) → ให้วาด Diagram รวม

### 💡 Visualization ที่เสนอ
1. **"Packet Journey"** — แอนิเมชันเดินแพ็กเก็ตทีละสเต็ป (ARP → ICMP / ARP → DNS → SYN-SYNACK-ACK → HTTP GET)
   มีตัวนับ "ส่งไปแล้วกี่ครั้ง" ซึ่งคือคำตอบของคำถามในสไลด์พอดี
2. **"Network Diagram Builder"** — ลากอุปกรณ์ (Router, Switch, Firewall, Server, PC, VPN) ลงผืนผ้าใบ
   ตามโจทย์สาขา A–D แล้วระบบตรวจว่า "ขาดอะไร / มีความเสี่ยงตรงไหน" (เช่น DB เปิดออกเน็ตตรง, ไม่มี DMZ)

---

## 5. Network Attack
`03_temp Network Attack.pdf` · Clip01, Clip02

### แก่นเนื้อหา
- สามคำที่ต้องแยกให้ออก: **Threat** (ภัยคุกคาม) → **Vulnerability** (ช่องโหว่) → **Exploit** (การอาศัยช่องโหว่โจมตี)
- **Malware taxonomy:** Virus, Worm, Trojan Horse, Rootkit, Ransomware, Spyware, Adware, Spam
- **Sniffing:** Internal / External / Wireless sniffer (ตัวอย่าง SmartSniff เห็น HTTP header แบบ clear-text)
- **DoS / DDoS:** SYN Flood, Land Attack, Smurf, Ping of Death, Ping Flood, Teardrop, Fraggle, Trinoo, TFN, TFN2K
- **Scanning (nmap):** `-sS` SYN, `-sT` Connect, `-sF` FIN, `-sX` XMAS, `-sN` Null, `-sP` Ping,
  `-sV` Version, `-sU` UDP, `-sO` IP Protocol, `-sA` ACK, `-sW` Window, `-sL` List
- **Exploit:** Buffer Overflow → ได้ root (ตัวอย่าง eggshell + return address overwrite)
- **TCP/IP & Session Hijacking:** คาดเดา Seq#/Ack# แล้วสวมรอย session
- **Rogue Access Point**
- ทุกหัวข้อปิดด้วย `Q : จะป้องกัน / แก้ไข ... ได้อย่างไร` และกิจกรรมทำ **MindMap ภัยคุกคาม** แล้วเติมวิธีป้องกันกลับเข้าไป

### 💡 Visualization ที่เสนอ
1. **"Threat → Vulnerability → Exploit Chain"** — สามกล่องต่อกัน เลือกภัยหนึ่งแล้วเห็นโซ่เต็มเส้นพร้อมจุดที่ตัดวงจรได้
2. **"Attack Lab"** — แผงจำลอง 4 แบบในหน้าเดียว:
   - *SYN Flood*: ตารางคิว half-open connection เติมจนเต็ม ปรับ rate ดู server ล้ม แล้วเปิด SYN cookie ดูผล
   - *Port Scan*: ตารางพอร์ตที่ nmap เห็น เทียบ `-sS` vs `-sT` vs `-sF` ว่าต่างกันตรงไหนใน TCP flag
   - *Session Hijack*: เส้น Seq#/Ack# สามฝ่าย (A, B, Attacker) ที่เห็นจังหวะการสวมรอย
   - *Sniffer*: หน้าจอจับแพ็กเก็ตที่สลับ HTTP ↔ HTTPS ให้เห็นว่าอ่านได้/ไม่ได้
3. **"Malware MindMap"** — MindMap แบบคลิกขยาย ที่ผู้เรียนเพิ่ม "วิธีป้องกัน" เข้าไปเองได้ (ตรงกับกิจกรรมในห้อง)

---

## 6. Firewall & Policy ⭐
`04-05 Firewall and Policy.pdf` · Clip01, Clip02

### แก่นเนื้อหา
- รูปแบบ: Appliance / Switch-based (หน้าตาคล้าย Switch ต้องดู Data Sheet) และ **Host-based Firewall**
- **4 ชนิดตามเทคโนโลยี**
  1. Packet Filtering — ดู Source IP/Port, Destination IP/Port, Flag, Action
  2. Stateful Inspection — เพิ่ม Protocol (TCP/UDP/ICMP/Application) และ **State**
  3. Application Proxy
  4. Next Generation Firewall — Source IP, Destination IP, **Application Protocol**, **Application Service**
     (Facebook, Google-Talk, eDonkey...), Action · *Classify all traffic, across all ports, all the time*
- **2 ปรัชญาของนโยบาย:** `Allow All / Deny Some` vs `Deny All / Allow Some` → *แบบไหนปลอดภัยกว่า?*
- **Zoning:** Untrusted Zone · DMZ · Trust Zone 1..n — แบ่งโซนตามความเสี่ยง/บทบาท แล้วเอา Firewall คั่น
- **ตำแหน่งติดตั้ง:** Firewall เป็น Default Gateway vs Router เป็น Default Gateway vs **Transparent Firewall**
- ตารางเปรียบเทียบ: Packet Filtering / Stateful / Application Proxy / NGFW ป้องกันภัยชนิดใดได้บ้าง

### กิจกรรม
กลุ่ม 5–6 คน — ออกแบบเครือข่าย ≥ 6 เครือข่าย มี Firewall ≥ 3 ตัว กำหนดบริการพื้นฐาน + นโยบาย + **เขียนกฎของ Firewall ทุกตัว**
แล้วระบุว่ากฎนั้นกันภัยอะไรได้

### 💡 Visualization ที่เสนอ
**"Firewall Rule Sandbox"** (ชิ้นเด่นของคอร์ส) — สองแผง:
- ซ้าย: ตารางกฎที่แก้ไขได้ (คอลัมน์ Src IP/Port, Dst IP/Port, Protocol, State, Action) เรียงลำดับได้ด้วยการลาก
- ขวา: แผนผัง 3 โซน (Untrusted / DMZ / Trust) ที่มีแพ็กเก็ตทดสอบวิ่งเข้ามาเป็นชุด
  (HTTP เข้า Web Server, ICMP flood, SSH จากภายนอก, DB connection จาก DMZ เข้า Trust ...)
  แสดงผลว่าแต่ละแพ็กเก็ตถูก **Allow/Deny ด้วยกฎข้อที่เท่าไร**
- ปุ่มสลับ `Allow All/Deny Some` ↔ `Deny All/Allow Some` เพื่อเห็นความต่างทันที
- สวิตช์ยกระดับ Packet Filtering → Stateful → NGFW ให้เห็นว่าภัยไหนเพิ่งจะกันได้เมื่อยกระดับ

---

## 7. Security Infrastructure & Tools
`06 Network Security Tools.pdf` · Clip01, Clip02 · Infographic: *IDS Accuracy*, *IDS Concept*

### แก่นเนื้อหา
- **กรอบการบริหารบริการไอที:** ISO/IEC 20000 (SMS, certification) · **ITIL** (Service Strategy → Design →
  Transition → Operation → Continual Improvement) · **COBIT** (IT Governance: Plan & Organise,
  Acquire & Implement, Deliver & Support, Monitor & Evaluate)
- งานที่ต้องมีเครื่องมือช่วย: Availability, System Monitoring (Application/Network/System),
  Change Mgmt, Problem Mgmt, Network Mgmt, Storage Mgmt, Capacity Planning, Performance Tuning, Security
- **จัดกลุ่มเครื่องมือ 3 ประเภท:** Monitoring Tools / Detection Tools / Protection Tools
- สิ่งที่ monitor: System (CPU, Memory, Disk) · Application (No response, Shutdown) · Network (Utilization, Connectivity)
  — ตัวอย่างจริง: Cacti, SolarWinds Orion / Server & Application Monitor
- **IDS / IPS**
  - ตำแหน่ง: Network-based vs Host-based
  - วิธีตรวจ: **Signature-Based** · **Statistical Anomaly-Based** · **Stateful Protocol Analysis**
  - การติดตั้ง: **IDS mode** (ต่อ SPAN/Mirror port — passive) vs **IPS mode** (in-line — ตัดได้)
  - **IDS Accuracy:** True Positive / True Negative / False Positive / False Negative

### 💡 Visualization ที่เสนอ
1. **"IDS Confusion Matrix"** — ตาราง 2×2 เลื่อน threshold ของ detector แล้วเห็น FP/FN แกว่งแบบ real-time
   (ตรงกับ Infographic *IDS Accuracy* ที่อาจารย์ทำไว้แล้ว) + ปุ่มสลับ Signature-based ↔ Anomaly-based
   ให้เห็นว่า zero-day ทำไม signature ถึงพลาด
2. **"IDS vs IPS Placement"** — แผนผังเครือข่ายเดียวกัน สลับการวางเป็น SPAN port (IDS) กับ in-line (IPS)
   แล้วปล่อยการโจมตี เห็นต่างชัดว่า "แค่แจ้งเตือน" กับ "ตัดทิ้ง" ต่างกันยังไง และ in-line พังแล้วเครือข่ายล่มด้วย
3. **"Tool Picker"** — โจทย์แบบในสไลด์ ("อยากตรวจไวรัสที่มากับอีเมล", "อยากรู้ Utilization ของเครือข่าย",
   "อยากรู้ว่าเซิร์ฟเวอร์ทำงานหนักเกินไป") → ผู้เรียนเลือกหมวด Monitoring/Detection/Protection แล้วเลือกเครื่องมือ

---

## 8. Incident Response
`07 Incident Response.pdf` · Clip01 + Section 1–3

### แก่นเนื้อหา
- เส้นแบ่งที่ต้องตอบให้ได้: **อะไรคือเหตุฉุกเฉิน (Incident)** vs **อะไรคือภัยพิบัติ (Disaster)**
- โครงแผนรับมือ 3 ช่วงเวลา: **ก่อนเหตุเกิด → เมื่อพบเหตุ → หลังจัดการ**
  ทุกช่วงต้องตอบ 5 คำถาม: **ใคร · ทำอะไร · เมื่อไหร่ · อย่างไร · ใช้เครื่องมืออะไร**
- องค์ประกอบของแผน: รายละเอียดระบบงาน → บุคลากร (ตำแหน่ง : ความสามารถ) → การเตรียมการก่อนเหตุ →
  แต่ละเหตุฉุกเฉิน (การระบุเหตุ / การดำเนินการเมื่อตรวจพบ / การดำเนินการหลังจัดการ)
- เชื่อมกลับบทที่ 3: *การรับมือเหตุฉุกเฉินใช้หลักการข้อใดใน CIA/AAA/PDR*
- คำถามปิด: *สถานะของระบบต้องเป็นอย่างไร จึงเรียกว่า "พร้อม" รับทั้ง 3 เหตุ*

### 💡 Visualization ที่เสนอ
**"Incident Playbook Simulator"** — เลือกเหตุ (Ransomware / ไวรัสระบาดในองค์กร / เว็บถูก deface /
User โดน phishing) แล้วเดินไทม์ไลน์ 3 ช่วง ทีละสเต็ป ผู้เรียนเลือก "ทำอะไรต่อ" จากตัวเลือก
→ ระบบคิดผลกระทบ (ข้อมูลหายเพิ่ม / downtime ยาวขึ้น / หลักฐานถูกทำลาย)
ปิดท้ายด้วยสรุปว่าตัดสินใจไหนตรงกับ NIST IR phases และใช้หลักการ CIA/AAA/PDR ข้อใด

---

## 9. Web Security ⭐
`08 WebSecurity.pdf` · `08 OWASP-top-10 2021.pdf` (+ NotebookLM) · Clips 4 ตอน · Infographics: *Web Architecture*, *OWASP Top 10 2021*

### แก่นเนื้อหา
- **Web Architecture 4 ชั้น** (Internet → DMZ → Protected network)
  `Browser → Web Server (Apache/IIS) → App Server (Servlet/J2EE/ColdFusion) → DB (Oracle/SQL Server)`
  พร้อมโปรโตคอลเชื่อมแต่ละชั้น (HTTP/SSL, AJP/IIOP, ADO/ODBC/JDBC) และภาษา (Perl, C++, CGI, Java, ASP, PHP)
- การทำงานของ HTTP Protocol (Clip Section 1)
- **ช่องโหว่และการ exploit ของจริง**
  - **Heartbleed** (OpenSSL Heartbeat) — ขอ payload เล็กแต่แจ้งขนาดใหญ่ → เซิร์ฟเวอร์ส่งหน่วยความจำข้างเคียงกลับมา
    (TLS private key, session cookie, รหัสผ่าน) · เว็บใน Top 10,000 ติด 628 ไซต์
  - **Shellshock** (Bash) — คำสั่งแฝงใน environment variable ผ่านการตรวจของ "ยาม" ไปได้
  - อ้างอิงฐานช่องโหว่: cvedetails.com, CVSS ≥ 8
### OWASP Top 10 — ชุด 2021 (ใช้ชุดนี้)

> ที่มาของ 10 หมวด: **8 หมวดมาจากข้อมูลจริง** ที่องค์กรส่งเข้ามา + **2 หมวดมาจาก community survey**
> (บางความเสี่ยงยังไม่ปรากฏในข้อมูล แต่ผู้เชี่ยวชาญเห็นว่าสำคัญ)
> แต่ละหมวดผูกกับ **CWE** และมี Data Factors กำกับ: CWEs Mapped, Incidence Rate, Weighted Exploit,
> Weighted Impact, Total Occurrences, Total CVEs

| # | หมวด | CWEs | Avg Exploit | Avg Impact | CVEs | CWE เด่น |
|---|---|---|---|---|---|---|
| **A01** | **Broken Access Control** | 34 | 6.92 | 5.93 | 19,013 | CWE-200 Exposure of Sensitive Info · CWE-352 CSRF |
| **A02** | **Cryptographic Failures** | 29 | 7.29 | 6.81 | 3,075 | CWE-259 Hard-coded Password · CWE-327 Broken Crypto |
| **A03** | **Injection** (รวม SQLi + **XSS**) | 33 | 7.25 | 7.15 | 32,078 | CWE-89 SQL Injection · CWE-79 Cross-site Scripting |
| **A04** | **Insecure Design** *(ใหม่ 2021)* | 40 | 6.46 | 6.78 | 2,691 | CWE-501 Trust Boundary Violation · CWE-522 |
| **A05** | **Security Misconfiguration** | 20 | 8.12 | 6.56 | 789 | CWE-16 Configuration · CWE-611 XXE |
| **A06** | **Vulnerable and Outdated Components** | 3 | — | — | 0 | CWE-1104 Unmaintained Third-Party Components |
| **A07** | **Identification and Authentication Failures** | 22 | 7.40 | 6.50 | 3,897 | CWE-287 Improper Auth · CWE-384 Session Fixation |
| **A08** | **Software and Data Integrity Failures** *(ใหม่ 2021)* | 10 | 6.94 | 7.94 | 1,152 | CWE-502 Deserialization · CWE-494 Download w/o Integrity Check |
| **A09** | **Security Logging and Monitoring Failures** | 4 | 6.87 | 4.99 | 242 | CWE-778 Insufficient Logging · CWE-532 Sensitive Info in Log |
| **A10** | **Server-Side Request Forgery (SSRF)** *(ใหม่ 2021)* | 1 | 8.28 | 6.72 | 385 | CWE-918 SSRF |

**สิ่งที่เปลี่ยนไปจากชุด 2017 และต้องเน้นในห้อง**
- **A01 ขึ้นมาเป็นอันดับ 1** — Broken Access Control พบในแอป **94%** ที่ทดสอบ (เดิมอยู่ A5)
  → เชื่อมตรงกับบท 3 เรื่อง **Authorization / Least Privilege** และ **RBAC**
- **XSS ถูกยุบเข้า A03 Injection** ไม่แยกหมวดอีกต่อไป (XSS = CWE-79 อยู่ใต้ Injection)
- **Insecure Design (A04) เป็นหมวดใหม่** — ย้ำว่าบั๊กบางอย่างแก้ด้วยโค้ดไม่ได้ ต้องแก้ที่ **การออกแบบ**
  (ตัวอย่างในสไลด์: โรงหนังให้ส่วนลดกรุ๊ป 15 คนขึ้นไป ผู้โจมตีจองเป็นร้อยที่นั่งข้ามสาขา ทำให้เสียรายได้ —
  **ไม่มีโค้ดบรรทัดไหนผิด แต่ธุรกิจเสียหาย**) → ต้องใช้ **Threat Modeling** และ Secure Development Lifecycle
- **Software and Data Integrity Failures (A08) เป็นหมวดใหม่** — เคสอ้างอิงคือ **SolarWinds Orion**
  (update mechanism ถูกแทรกโค้ด กระทบกว่า 18,000 องค์กร) → supply chain security
- **SSRF (A10) เป็นหมวดใหม่** มาจาก community survey ไม่ใช่จากข้อมูล — CWE เดียว แต่ **Exploit score สูงสุด 8.28**
- **A09 Logging & Monitoring** → เชื่อมตรงกับบท 3 (**Accounting**) และบท 7 (SIEM) และบท 8 (Incident Response)
  เคสอ้างอิง: ผู้ให้บริการแผนสุขภาพเด็กถูกเข้าถึงข้อมูลสุขภาพกว่า 3.5 ล้านรายการ **โดยไม่มีใครรู้ตั้งแต่ปี 2013**

**OWASP Top 10 ใช้เป็นมาตรฐานได้แค่ไหน** (ตารางท้ายสไลด์)
เหมาะกับ *Awareness* และ *Training ระดับเริ่มต้น* — แต่สำหรับ coding standard, secure code review,
unit/integration test, penetration test ให้ใช้ **OWASP ASVS (Application Security Verification Standard)** แทน

- มุมมอง 3 บทบาทที่ต้องตระหนักต่างกัน: **User / ผู้ดูแลระบบ / Developer**
- กรณีศึกษาในประเทศ: DDoS เว็บกระทรวง ICT (#OpSingleGateway), เว็บร้านดังถูก deface,
  Dropbox credential leak, iCloud leak

### 💡 Visualization ที่เสนอ
1. **"Web Stack X-ray"** — แผนผัง 4 ชั้น ที่ยิงคำขอหนึ่งครั้งแล้วเห็นข้อมูลเดินทะลุชั้น
   คลิกชั้นไหน = เห็นว่าช่องโหว่ชนิดใดเกิดที่ชั้นนั้น (XSS ที่ browser, SQLi ที่ DB layer, misconfig ที่ web server)
2. **"Heartbleed Memory Leak"** ⭐ — ของเล่นชิ้นเดียวที่อธิบายได้ดีที่สุด:
   ช่องกรอก payload + ช่องกรอก "ขนาดที่แจ้ง" ตั้งไม่เท่ากันแล้วดู **บล็อกหน่วยความจำ** ที่หลุดกลับมา
   (มี private key / cookie / password ปนอยู่) แล้วกดปุ่ม patch ดูผลต่าง
3. **"OWASP Top 10 2021 Board"** — การ์ด 10 ใบ (A01–A10) แต่ละใบมีเดโมเล็กๆ ใช้งานได้จริง
   - การ์ดแสดง **Exploit / Impact score** เป็นแถบ เรียงการ์ดใหม่ตาม Exploit หรือ Impact ได้
     (เห็นทันทีว่า A05 Misconfiguration exploit ง่ายสุด 8.12 แต่ A08 impact สูงสุด 7.94)
   - เดโมที่ควรมี: **A01** เปลี่ยน `?acct=` ใน URL แล้วเห็นบัญชีคนอื่น (IDOR) ·
     **A03** ช่อง input เดียวสลับโหมด SQLi / XSS แล้วกดเปิด prepared statement + escaping ดูผล ·
     **A04** เคสโรงหนังจองกรุ๊ปข้ามสาขา (โค้ดถูกหมด แต่ธุรกิจพัง) · **A10** SSRF ยิงไปที่ `169.254.169.254`
   - ของเดิมในโปรเจกต์ `sqli.js` + `xss.js` → **ยุบรวมเป็นการ์ด A03 ใบเดียว** ตามการจัดหมวดของ 2021
4. **"2017 → 2021 Shift"** — ผังลากเส้นว่าหมวดเดิมย้ายไปไหน (XSS ยุบเข้า Injection, A5 ขึ้นเป็น A01,
   สามหมวดใหม่โผล่มา) ช่วยนักศึกษาที่ไปอ่านเอกสารเก่าเจอชุด 2013/2017 แล้วสับสน
4. **"Same bug, 3 roles"** — ช่องโหว่เดียวกัน เล่าสามมุม User / Admin / Developer ว่าต้องทำอะไรต่างกัน

---

## 10. Wireless LAN Security
`09 WirelessNetworkSecurity.pdf` · Clip + Section 1–5

### แก่นเนื้อหา
- ตารางวิวัฒนาการ 802.11 / b / a / g / n — ปี, ความเร็ว, ความถี่, จำนวนช่อง, ระยะ
- **กระบวนการเชื่อมต่อ:** Beacon → (Probe Req/Resp) → SSID Matches → Association Req → Association Resp → Associated
- **Authentication 2 แบบตามมาตรฐาน**
  - *Open System* — ผ่านทุกคนที่ร้องขอ ไม่มีรหัสผ่าน
  - *Shared-Key* — challenge text เข้ารหัสด้วย shared key **แต่ดักจับแล้วหาคีย์ได้**
- **WEP:** คีย์ 40/104-bit, RC4, IV 24-bit, ICV = CRC-32 → ช่องโหว่ครบทุกด้าน
- **WPA (2003):** TKIP/MIC, คีย์แยกต่อ packet, IV 48-bit, ส่ง IV แบบเข้ารหัส, MIC แทน CRC,
  อัปเกรดผ่าน firmware ได้ · 2 โหมด Enterprise (802.1X/EAP + RADIUS) / Personal (PSK)
- **WPA2 = IEEE 802.11i:** RSN, **AES-CCMP** (block 128 bits, 10 รอบ), Enterprise/Personal เหมือนกัน
- **ตารางเปรียบเทียบ WEP / WPA / WPA2:** Cipher, Key Size, Key Life, Packet Key, Data Integrity, Key Management
- EAP methods: TLS, TTLS (certificate) · PEAP, LEAP (password)
- คำถามประยุกต์: องค์กร **10 / 50 / 300+ users** ควรวางกระบวนการต่างกันอย่างไร

### 💡 Visualization ที่เสนอ
1. **"802.11 Association Flow"** — sequence diagram เดินทีละเฟรม (Beacon → Probe → Auth → Assoc)
   สลับโหมด Open vs Shared-Key เห็นว่า Shared-Key ปล่อย challenge/response ให้ดักได้ตรงไหน
2. **"WEP → WPA → WPA2"** — ตารางเปรียบเทียบที่คลิกแถวแล้วเห็น "ช่องโหว่ข้อนี้ถูกปิดยังไงในรุ่นถัดไป"
   + ตัวจำลอง IV reuse ของ WEP (24-bit IV หมดเร็วแค่ไหนที่ traffic ระดับหนึ่ง)
3. **"เลือกสถาปัตยกรรมตามขนาดองค์กร"** — สไลเดอร์จำนวนผู้ใช้ 10 → 50 → 300+
   แล้วระบบแนะสถาปัตยกรรม (PSK ธรรมดา → PSK + VLAN → 802.1X/EAP + RADIUS + Certificate)

---

## 11. IT Risk Management ⭐
`10 ITRiskManagement.pdf` · Clip

### แก่นเนื้อหา
- แยกให้ออก: **ความเสี่ยง vs ปัญหา** และ **ความเสี่ยงระบบสารสนเทศ vs ภัยคุกคามสารสนเทศ**
- สามเหลี่ยม Target ↔ Key Success Factors ↔ Risk
- **กระบวนการบริหารความเสี่ยง 7 ขั้น (COSO ERM)**
  1. Objective Setting — กำหนดเป้าหมายการบริหารความเสี่ยง
  2. Event Identification — ระบุความเสี่ยง
  3. Risk Assessment — ประเมิน
  4. Risk Response — กลยุทธ์จัดการ
  5. Control Activities — กิจกรรมบริหารความเสี่ยง
  6. Information and Communication
  7. Monitoring — ติดตามและเฝ้าระวัง
- **รายละเอียดความเสี่ยงที่ต้องระบุ:** ชื่อ, ประเภท (เทคนิค / ผู้ปฏิบัติงาน / ภัยพิบัติ-เหตุฉุกเฉิน / การบริหารจัดการ),
  รายละเอียด, ปัจจัยเสี่ยง, ผลกระทบ/ผู้รับผลกระทบ
- **การประเมิน:** ตารางโอกาส 5 ระดับ × ตารางความรุนแรง 5 ระดับ → **Risk Map 5×5** →
  ระดับความเสี่ยง = **โอกาส (A) × ความรุนแรง (B)** · เกณฑ์ยอมรับได้ที่ยกตัวอย่างคือ **A × B ≤ 9**
  (ใช้ Scenario Analysis ช่วยให้ระบุความรุนแรงแม่นขึ้น)
- **4 กลยุทธ์ตอบสนอง:** หลีกเลี่ยง · ถ่ายโอน · ลด · ยอมรับ
- แผนกิจกรรม: ชื่องาน, รายละเอียด, ผลที่คาดหวัง, งบประมาณ, ผู้รับผิดชอบ, ระยะเวลา
- คำถามปิด: *หลังทำกิจกรรมบริหารความเสี่ยงแล้ว ความเสี่ยงควรเป็นอย่างไร* (การเคลื่อนตำแหน่งบน Risk Map)

### 💡 Visualization ที่เสนอ
**"Risk Map 5×5"** (มี `risk.js` อยู่แล้วในโปรเจกต์ — ควรยกระดับเป็นเครื่องมือเต็ม)
- ตาราง 5×5 วางจุดความเสี่ยงได้ สีตามระดับ A×B พร้อมเส้นเกณฑ์ยอมรับ ≤ 9
- เลือกกลยุทธ์ (หลีกเลี่ยง/ถ่ายโอน/ลด/ยอมรับ) แล้ว **เห็นจุดเคลื่อนที่บนแผนที่** — ลดโอกาสเลื่อนลง ลดความรุนแรงเลื่อนซ้าย
- แผงข้างบอกงบประมาณรวมกับความเสี่ยงคงเหลือ (residual risk) → ตอบคำถาม "ทำแล้วมั่นใจกี่ %"
- เดินครบ 7 ขั้น COSO เป็น wizard ได้ตรงกับใบงานทั้ง 7 ตาราง

---

## 12. Security Standards & Frameworks
`11 SecurityProcedure_Standard.pdf` · `NIST.CSWP.29.pdf` (NIST CSF 2.0) · Infographics: *ISO27001*, *NIST CSF 2.0* · Clip Section 1–7

### แก่นเนื้อหา
**ตระกูล ISO 27000**
`27000` Fundamentals & Vocabulary · **`27001` ISMS (ตัวที่ขอ certify)** · `27002` Code of Practice ·
`27003` Implementation Guidance · `27004` Metrics & Measurement · `27005` Risk Management · `27006` Accreditation

**ISO 27001 — 11 โดเมนควบคุม**
1. Security Policy · 2. Organization of Information Security · 3. Asset Management ·
4. Human Resources Security · 5. Physical and Environmental Security ·
6. Communications and Operations Management · 7. Access Control ·
8. Information Systems Acquisition, Development and Maintenance ·
9. Information Security Incident Management · 10. Business Continuity Management · 11. Compliance

- วงจร **PDCA**: Plan → Do → Check → Act ของ ISMS
- ภาพ 4 แบบของความสัมพันธ์ `My Process` กับ `ISO27001` (ไม่ทับกัน / ทับบางส่วน / ครอบ / ถูกครอบ)
- คำถามวิพากษ์: *ทำตาม ISO27001 แล้วมั่นใจกี่ %* · *อะไรคือความเสี่ยงที่ยังเหลืออยู่*

**NIST CSF 2.0** (ก.พ. 2024) — 6 Functions: **GOVERN · IDENTIFY · PROTECT · DETECT · RESPOND · RECOVER**
โครงสร้าง Functions → Categories → Subcategories + **Profiles** (Current/Target) และ **Tiers** 1–4
จุดเด่น: บอก *outcome* ไม่บอก *วิธีทำ*

### 💡 Visualization ที่เสนอ
1. **"ISO 27001 Control Map"** — 11 โดเมนเป็นวงล้อ/กริด คลิกเข้าไปเห็น Objective + Controls ย่อย
   และ **ลิงก์ย้อนกลับไปบทที่สอนเรื่องนั้น** (เช่น โดเมน 7 Access Control → บท AAA, โดเมน 10 BCM → บท 14)
2. **"PDCA Wheel"** — วงล้อหมุนได้ แต่ละเฟสมีกิจกรรมจริงของ ISMS
3. **"ISO 27001 ↔ NIST CSF 2.0 Crosswalk"** — สองคอลัมน์ ลากเส้นจับคู่ว่าโดเมนไหนตรงกับฟังก์ชันใด
   (ช่วยตอบคำถาม "ใช้อันไหนดี" ซึ่งเป็นคำถามประเมิน/สร้างสรรค์ระดับบนสุดของ Bloom)
4. **"Self-assessment Tier"** — แบบประเมิน 6 ฟังก์ชัน ให้คะแนนแล้วได้ **เรดาร์ชาร์ต Current vs Target Profile**

---

## 13. กฎหมายด้าน Security (ประเทศไทย)
`12 LAW.pdf` + กฎหมายแนบ 7 ฉบับ · Clip Section 1

### แก่นเนื้อหา
- กรอบคิดตั้งต้น: **กฎหมาย · จริยธรรม · ศีลธรรม** สัมพันธ์กันอย่างไร
- กฎหมาย IT ของไทยเริ่ม **15 ธันวาคม 2541** โดย กทสช. ยกร่าง 6 ฉบับ:
  ธุรกรรมทางอิเล็กทรอนิกส์ · ลายมือชื่ออิเล็กทรอนิกส์ · โครงสร้างพื้นฐานสารสนเทศ ·
  คุ้มครองข้อมูลส่วนบุคคล · อาชญากรรมคอมพิวเตอร์ · โอนเงินทางอิเล็กทรอนิกส์
- **กฎหมายหลัก 4 ฉบับที่ใช้จริง**
  - พ.ร.บ. ว่าด้วยธุรกรรมทางอิเล็กทรอนิกส์ **พ.ศ. 2544** (แก้ไข ฉบับที่ 2 **พ.ศ. 2551**)
    + ประกาศฯ *มาตรฐานการรักษาความมั่นคงปลอดภัยของระบบสารสนเทศตามวิธีการแบบปลอดภัย พ.ศ. 2555*
  - พ.ร.บ. ว่าด้วยการกระทำความผิดเกี่ยวกับคอมพิวเตอร์ **พ.ศ. 2550** (ปรับปรุง **พ.ศ. 2560**)
  - พ.ร.บ. การรักษาความมั่นคงปลอดภัยไซเบอร์ **พ.ศ. 2562** + ประมวลแนวทางปฏิบัติฯ
  - พ.ร.บ. คุ้มครองข้อมูลส่วนบุคคล **พ.ศ. 2562 (PDPA)** + Diagram
- กรณีศึกษาจริงในสไลด์: อีเมลปลอมธนาคาร (phishing จาก `scb.bank70@mail.ru`),
  โพสต์ขู่วางระเบิด, เพจแจ้งด่านตรวจปิดตัว, #OpSingleGateway
- คำถาม: *องค์กรแบบไหนได้รับผลกระทบ / ไม่ได้รับผลกระทบ* ·
  *โรงเรียนมัธยมที่ให้นักเรียนต่ออินเทอร์เน็ต ต้องทำอะไรให้สอดคล้องกับ พ.ร.บ.คอมพิวเตอร์ 2550*

### 💡 Visualization ที่เสนอ
1. **"Case → Section"** — ให้เคสจริง (โพสต์ข้อความเท็จ, แชร์ต่อ, DDoS, ทำข้อมูลรั่ว, เก็บ log ไม่ครบ 90 วัน)
   ผู้เรียนเลือกว่าผิดกฎหมายฉบับใด **มาตราใด** แล้วเฉลยพร้อมบทลงโทษ
2. **"Compliance Checklist Generator"** — เลือกประเภทองค์กร (โรงเรียน / ร้านค้าออนไลน์ / โรงพยาบาล /
   หน่วยงานรัฐ / ผู้ให้บริการ) → ได้รายการสิ่งที่ต้องทำตาม 4 พ.ร.บ.
   (เก็บ log 90 วัน, แต่งตั้ง DPO, ขอ consent, แจ้งเหตุละเมิดภายใน 72 ชม. ...)
3. **"PDPA Data Flow"** — ไดอะแกรม Data Subject → Controller → Processor พร้อมสิทธิ 8 ข้อของเจ้าของข้อมูล

---

## 14. Business Continuity Management ⭐
`13 BCM.pdf` · Clip Section 1–2

### แก่นเนื้อหา
- ความคาดหวังของผู้ใช้ = **Availability (เพียงพอ)** + **Reliability (ถูกต้อง)**
- หลักคิด: *ระบบมี Downtime ได้ แต่ต้องไม่กระทบการดำเนินธุรกิจ* → เตรียมทรัพยากรให้ downtime อยู่ในระดับที่ยอมรับได้
- **ตัวชี้วัด 5 ตัว ที่ต้องแยกให้ขาด**
  | ตัว | ความหมาย | ลักษณะ |
  |---|---|---|
  | **RTO** | Recovery Time Objective — เวลาเป้าหมายในการกู้ระบบ | **TARGET** |
  | **MTTR** | Mean Time To Recover — เวลาเฉลี่ยที่ใช้จริง ยิ่งน้อยยิ่งดี | **FACT** |
  | **RPO** | Recovery Point Objective — ข้อมูลย้อนกลับไปจุดไหน = "acceptable loss" | ยิ่งมาก data loss ยิ่งเยอะ |
  | **WRT** | Work Recovery Time — เวลากู้ data, test และตรวจสอบ process | |
  | **MTD** | Maximum Tolerable Downtime = **RTO + WRT** | ธุรกิจทนได้สูงสุด |
  - คำถามแกน: **MTTR > RTO หรือ MTTR < RTO** → ถ้าเกินต้องเพิ่ม Tools / Design / Process
- **Recovery Site 3 ระดับ**
  - **Cold Site** — มีพื้นที่และเครื่องมือ แต่ไม่มีคอมพิวเตอร์และข้อมูล · RTO สูงมาก
  - **Warm Site** — มีเครื่องพร้อมประกอบเป็น backup data center แต่ไม่มีข้อมูลสำรองจากไซต์หลัก ·
    ต้องตั้งค่าและ restore · RTO อาจเกิน 1 วัน
  - **Hot Site** — ทำซ้ำทั้งระบบและข้อมูล · RTO ต่ำสุด หน่วยวินาที – 2 ชั่วโมง · Synchronous replication → **RPO = 0**
  - คำถามตัดสินใจ: ทำเอง vs จ้าง contract · มีเจ้าหน้าที่ประจำไหม · Online vs Standby · Sync vs Async
- กรณีศึกษาในสไลด์: ไฟไหม้ห้องเซิร์ฟเวอร์บริษัทต่างชาติ เสียหายกว่าร้อยล้าน (14 ต.ค. 2557),
  DDoS ถล่มเว็บ ICT (30 ก.ย. 2558) — `Network Error (tcp_error)`

### 💡 Visualization ที่เสนอ
**"BCM Timeline"** ⭐ (อธิบาย 5 ตัวชี้วัดได้ในภาพเดียว — เป็นเรื่องที่นักศึกษาสับสนที่สุด)
- แกนเวลาแนวนอน มีหมุด *จุดสำรองข้อมูลล่าสุด* → *เวลาเกิดเหตุ* → *ระบบกลับมา* → *ธุรกิจกลับเป็นปกติ*
- ลากหมุดได้ แล้วแถบ **RPO / RTO / WRT / MTD** ขยับตาม พร้อมตัวเลขอัปเดตสด
- สลับ Cold / Warm / Hot Site แล้วเห็นแถบ RTO หดทันที พร้อม **ตัวเลขต้นทุน** ประกบ → ตอบคำถาม "ทำเอง vs จ้าง"
- สวิตช์ Synchronous / Asynchronous replication → เห็น RPO เป็นศูนย์หรือไม่

---

## สรุปแผนที่ Visualization

### ของที่มีอยู่แล้วในโปรเจกต์ (`assets/js/lessons/`)
| ไฟล์ | เข้ากับบท | สถานะที่ควรเป็น |
|---|---|---|
| `cia.js` | บท 3 | ขยายเป็น Matrix 9×6 เต็ม + Threat mapping |
| `mfa.js`, `rbac.js` | บท 3 (AAA) | คงไว้ ผูกเข้าเป็นส่วนย่อยของบท 3 |
| `firewall.js` | บท 6 | ยกระดับเป็น Rule Sandbox 3 โซน |
| `sqli.js`, `xss.js` | บท 9 | **ยุบรวมเป็นการ์ด A03 Injection ใบเดียว** (ชุด 2021 ไม่แยก XSS แล้ว) แล้วขยายเป็นชุด A01–A10 |
| `risk.js` | บท 11 | ยกระดับเป็น Risk Map 5×5 + 4 กลยุทธ์ |
| `symmetric.js`, `asymmetric.js`, `hashing.js`, `tls.js` | บท 3 / 9 / 10 | **ไม่ใช่บทแยกในคอร์สนี้** → ย้ายเป็น "กล่องเครื่องมือ Crypto" ที่บทอื่นเรียกใช้ (Confidentiality, Integrity, Heartbleed, WPA2) |

### ของที่ต้องทำใหม่ (เรียงตามความคุ้มค่า)
| ลำดับ | ชิ้นงาน | บท | เหตุผล |
|---|---|---|---|
| 1 | **Firewall Rule Sandbox** | 6 | เป็นกิจกรรมกลุ่มหลักอยู่แล้ว ฝึกเขียนกฎได้จริง |
| 2 | **BCM Timeline (RPO/RTO/WRT/MTD)** | 14 | 5 ตัวชี้วัดที่สับสนที่สุด ภาพเดียวจบ |
| 3 | **Risk Map 5×5 + กลยุทธ์** | 11 | ใบงาน 7 ตารางแปลงเป็นดิจิทัลได้ตรงๆ |
| 4 | **OWASP Top 10 2021 Board** | 9 | 10 การ์ด A01–A10 เป็นแกนของบท Web Security ทั้งบท |
| 5 | **Heartbleed Memory Leak** | 9 | ช่องโหว่ที่เห็นภาพชัดที่สุด สอน TLS ไปในตัว |
| 6 | **Packet Journey + Diagram Builder** | 4 | ตอบคำถาม "ส่งกี่ครั้ง โปรโตคอลอะไร" ได้โดยตรง |
| 7 | **IDS Confusion Matrix + IDS/IPS Placement** | 7 | ตรงกับ Infographic ที่อาจารย์ทำไว้แล้ว |
| 8 | **802.11 Association + WEP/WPA/WPA2** | 10 | ลำดับเฟรมเข้าใจยาก เหมาะกับ animation |
| 9 | **CIA/AAA/PDR Matrix + Threat mapping** | 3 | บทแกน เชื่อมทุกบทเข้าหากัน |
| 10 | **Attack Lab (SYN Flood / Scan / Hijack)** | 5 | สนุก ดึงความสนใจ |
| 11 | **ISO27001 ↔ NIST CSF Crosswalk** | 12 | ระดับ Bloom สูงสุด เหมาะเป็นบทท้าย |
| 12 | **Incident Playbook Simulator** | 8 | ฝึกตัดสินใจภายใต้ความกดดัน |
| 13 | **Case → Section (กฎหมาย)** | 13 | เคสไทยจริงจากสไลด์ |
| 14 | **EA Stack Explorer** | 2 | นามธรรมสูง ต้องใช้ภาพช่วย |
| 15 | **Security Timeline** | 1 | ใช้เป็นหน้าแรก/สารบัญของคอร์ส |

### หลักการออกแบบร่วม
1. ทุกชิ้นต้องมี **"ให้ลองเปลี่ยนค่าแล้วดูผล"** ไม่ใช่ดูอย่างเดียว — ตรงกับระดับ *ประยุกต์/วิเคราะห์*
2. ทุกชิ้นจบด้วย **คำถาม `Q :` ที่ยกมาจากสไลด์จริง** ไม่ต้องคิดคำถามใหม่
3. ทุกบทผูกกลับไปที่ **CIA/AAA/PDR** — เป็นแกนที่อาจารย์ใช้ร้อยทั้งคอร์ส (บท 8 ถามตรงๆ ว่า "ใช้หลักการข้อใด")
4. ศัพท์เทคนิคคงภาษาอังกฤษ คำอธิบายเป็นภาษาไทย ตามสไตล์สไลด์เดิม
5. ทำงานออฟไลน์ได้ ไม่มี build step (ตามโครงเดิมของโปรเจกต์: vanilla JS + inline SVG)
