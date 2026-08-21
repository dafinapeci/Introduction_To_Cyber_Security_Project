# ShadowGuard — Yapay Zekâ Destekli Honeypot Sistemi

> 2026 Bahar Dönemi’nde *Introduction to Cyber Security* dersi kapsamında geliştirilmiş, yüksek etkileşimli
> (high-interaction) bir bal küpü / tuzak sistemi.

[Click here to jump to the English version](#english-version)

ShadowGuard, saldırganları sahte bir sunucuya çekip **davranışlarını analiz eden** ve
tehdit istihbaratı toplayan bir honeypot sistemidir. Klasik honeypot'ların statik ve
kolayca fark edilen yapısının aksine, yerel bir **büyük dil modeliyle (LLM)** çalışır:
her saldırgan IP'si için ayrı, tutarlı ve ikna edici bir **sanal dosya sistemi** üretir.

Saldırgan `ls` yazdığında gördüğü klasörler, `cat` ile açtığı dosyaların içeriği,
karşısına çıkan sahte şirket adı ve sızdırılmış gibi görünen kimlik bilgileri — hepsi
o oturuma özel olarak anlık üretilir.

---

## İçindekiler

- [Nasıl çalışır?](#nasıl-çalışır)
- [Depo yapısı: iki sürüm](#depo-yapısı-iki-sürüm)
- [Öne çıkan özellikler](#öne-çıkan-özellikler)
- [Mimari](#mimari)
- [Risk skorlama ve saldırgan profilleme](#risk-skorlama-ve-saldırgan-profilleme)
- [Sanal dosya sistemi (VFS)](#sanal-dosya-sistemi-vfs)
- [Kurulum](#kurulum)
- [Kullanım](#kullanım)
- [Teknoloji yığını](#teknoloji-yığını)
- [Yasal uyarı](#yasal-uyarı)

---

## Nasıl çalışır?

1. Honeypot seçilen portları dinlemeye başlar (SSH, HTTP, Telnet vb. taklidi).
2. Bağlanan saldırganın IP adresi bir **kimlik tohumuna (identity seed)** dönüştürülür.
3. Bu tohumdan, o IP'ye özel ve her bağlantıda **aynı kalan** sahte bir kurumsal kimlik
   ile dosya hiyerarşisi üretilir.
4. Saldırganın her komutu, LM Studio'da çalışan yerel modele "sen bir Linux
   terminalisin" talimatıyla iletilir; dönen çıktı gerçek bir kabuk yanıtı gibi sunulur.
5. Komutlar aynı anda analiz edilir, risk puanı hesaplanır ve UDP soketi üzerinden
   **Monitor** ekranına canlı olarak akar.
6. Saldırganın indirmeye çalıştığı dosyalar çalıştırılmaz; `quarantine/` klasörüne alınır.

Yapay zekânın yerel çalışması kritiktir: hiçbir saldırgan verisi dış servise gönderilmez.

---

## Depo yapısı: iki sürüm

Proje iki farklı ortam için ayrı ayrı paketlenmiştir:

| Klasör | Sürüm | Açıklama |
|---|---|---|
| **`shadowguard-honeypot/`** | Linux (Docker + GUI) | Asıl sürüm. Tkinter tabanlı grafik arayüzler X11 forwarding ile konteynerden dışarı taşınır. Web tarama modülü ve gelişmiş VFS bu sürümdedir. |
| **`Windows Version/`** | Windows / başsız (CLI) | X-Server gerektirmeyen hafif port. Grafik arayüz yerine terminal arayüzü kullanır; VirusTotal entegrasyonu ve PDF raporlama bu sürüme eklenmiştir. |

Her iki klasörün kendi ayrıntılı İngilizce `README.md` dosyası vardır.

---

## Öne çıkan özellikler

| Özellik | Açıklama |
|---|---|
| 🧠 **Dinamik yapay zekâ tepkileri** | Saldırganın komutuna ve açmak istediği dosyaya göre gerçekçi içerik saniyeler içinde üretilir |
| 📂 **Kişiselleştirilmiş sanal sistem** | Her IP için sabit bir tohum; sahte kurumsal profil, dosya ağacı ve kimlik bilgileri hep aynı kalır |
| 📊 **Gerçek zamanlı risk skorlama** | Girilen komutlar anında analiz edilir, profil belirlenir, UDP ile Monitor ekranına canlı iletilir |
| 🦠 **VirusTotal entegrasyonu** *(Windows sürümü)* | Saldıran IP'nin bilinen küresel bir tehdit olup olmadığı otomatik sorgulanır |
| 📄 **Otomatik olay raporu** *(Windows sürümü)* | Sistem kapatılırken saldırgan komutlarını ve risk profilini özetleyen PDF tehdit raporu üretilir |
| 🕸️ **Red Team ve web analiz modülü** | Sistemi kendi kendine test etmek için Base64/Hex gizleme yapabilen saldırgan istemcisi |
| 🔒 **Karantina** | İndirilmeye çalışılan zararlı dosyalar çalıştırılmadan `quarantine/` altına alınır |
| 🐳 **İzole ortam** | Tüm sistem Docker konteynerlerinde, dış dünyaya kapalı bir `internal` ağda çalışır |

---

## Mimari

Sistem `docker-compose.yml` ile 4 servis olarak ayağa kalkar:

```
                    ┌──────────────────────────┐
   Saldırgan  ─────▶│  HONEYPOT                │
   (dış dünya)      │  · portları dinler       │
                    │  · VFS kurar             │
                    │  · komutu LLM'e sorar    │
                    │  · payload'ı karantinaya │
                    └───┬──────────────────┬───┘
                        │ UDP log          │ HTTP
                        ▼                  ▼
              ┌───────────────┐   ┌────────────────────┐
              │  MONITOR      │   │  AI BRIDGE (Flask) │
              │  · canlı log  │   │  /ai-sor  /status  │
              │  · risk skoru │   └─────────┬──────────┘
              │  · PDF rapor  │             │ host-gateway
              └───────────────┘             ▼
                                  ┌────────────────────┐
              ┌───────────────┐   │  LM Studio         │
              │  ATTACKER     │   │  ana makinede      │
              │  (Red Team)   │   └────────────────────┘
              └───────────────┘
```

| Servis | Görevi |
|---|---|
| **Honeypot** | Ana tuzak. Portları dinler, bağlantıları karşılar, VFS ve LLM senaryolarını yürütür, karantina klasörünü yönetir |
| **Monitor** | Toplanan logları, risk istatistiklerini ve UDP üzerinden gelen canlı trafiği görselleştirir |
| **AI Bridge** | İzole ağdaki honeypot ile ana makinedeki LM Studio arasında köprü kuran Flask servisi |
| **Attacker** | Sistemi test etmek ve otomatik senaryo çalıştırmak için yazılmış Red Team modülü |

Ağ tasarımı bilinçli olarak ikiye ayrılmıştır: `shadow_net` **internal** (dışarıya
çıkışı yok), yalnızca AI Bridge ikinci bir köprü ağ üzerinden ana makineye erişebilir.

---

## Risk skorlama ve saldırgan profilleme

Monitor, her komutu iki listeye karşı denetler:

- **Kritik komutlar** (+25 puan): `wget`, `curl`, `chmod +x`, `rm -rf`, `id_rsa`,
  `shadow`, `python3 -c`, `bash -i`, `nc`, `socat`, `/dev/tcp`, `.ssh`,
  `authorized_keys`, `crontab`, `sudoers`
- **Keşif komutları** (+5 puan): `ls`, `whoami`, `pwd`, `id`, `uname`, `netstat`,
  `ps`, `cat /etc`, `env`, `history`, `find /`, `hostname`

Biriken puana göre oturuma bir profil atanır:

| Puan | Profil |
|---|---|
| ≥ 175 | **Advanced Threat** |
| ≥ 100 | **Professional Attacker** |
| ≥ 60 | **Explorer** |
| 25+ komut, düşük puan | **Kiddie** |
| Diğer | **Bot** |

Profil değiştiği anda Monitor ekranındaki gösterge güncellenir.

---

## Sanal dosya sistemi (VFS)

Saldırganın IP'si hash'lenerek sabit bir tohum üretilir; bu tohumla:

- Dört sahte kurumsal kimlikten biri seçilir 
- Kullanıcı adı, hostname ve iç ağ IP'si üretilir
- Gerçekçi görünümlü sahte sırlar oluşturulur: veritabanı parolası, API anahtarı,
  oturum imzalama anahtarı ve bulut sağlayıcı erişim anahtarı — hepsi yem amaçlıdır
- `/root/Desktop/credentials.txt`, `/root/Documents/employee_database.csv`,
  `VPN_access.ovpn` gibi yem dosyalarla dolu bir dizin ağacı kurulur

Tohum sabit olduğu için aynı saldırgan tekrar bağlandığında **aynı sistemi** görür —
tutarsızlık honeypot'u ele veren en büyük ipucudur ve bu tasarımla ortadan kaldırılmıştır.

---

## Kurulum

### Ortak gereksinim: LM Studio

Her iki sürüm de yerel bir dil modeline ihtiyaç duyar.

1. LM Studio'yu kurun ve bir model indirin.
2. Sol menüden **Local Server** sekmesine geçip yerel sunucuyu başlatın.
3. Docker konteynerlerinin erişebilmesi için **CORS'u açın** ve gerekirse dinleme
   adresini tüm arayüzlere açın.

### 🐧 Linux sürümü (Docker + GUI)

```bash
xhost +local:docker          # X11 arayüzlerinin konteynerden açılabilmesi için
cd shadowguard-honeypot
sudo docker compose up --build
```

Bu komut izole Docker ağını kurar, Monitor'ü başlatır, Honeypot'u dinlemeye alır ve
AI Bridge ile Attacker servislerini senkronize eder.

Durdurmak için terminalde `Ctrl+C`, arka planda çalışıyorsa `sudo docker compose down`.

### 🪟 Windows sürümü (başsız CLI)

Python 3.10+ gerekir. Docker ve XLauncher gerekmez.

```powershell
cd "Windows Version"
pip install flask requests fpdf

# 1. terminal — saldırıları izle
python monitor/monitor_cli.py

# 2. terminal — Red Team modülüyle sistemi test et
python attacker/main_cli.py
```

Monitor'ü `Ctrl+C` ile kapattığınızda `./data/reports` klasörüne otomatik olarak bir
PDF raporu üretilir.

**VirusTotal için:** Monitor modülünde IP itibar sorgusu, kendi VirusTotal API
anahtarınızı tanımladığınızda etkinleşir. Anahtar tanımlanmazsa sistem çalışmaya
devam eder, yalnızca bu sorgu atlanır.

---

## Kullanım

**Honeypot arayüzünden** dinlenecek portları seçip *Listen on Selected Ports* ile
sistemi başlatırsınız. Bir port hakkında bilgi almak isterseniz yapay zekâya
sorabilirsiniz; web analiz modülü ise verilen yerel adres veya dosyayı basit güvenlik
kontrollerinden geçirir; kapsam bilinçli olarak dar tutulmuştur — yalnızca yerel
makine ile özel ağlar ve sınırlı bir dosya uzantısı listesi taranabilir.

**Monitor ekranında** canlı log akışı, oturum istatistikleri, IP ve tarihe göre
geçmiş log filtreleme ve saldırgan profil göstergesi bulunur.

**Attacker modülü** honeypot'a bağlanıp elle komut göndermenizi ya da hazır bir
saldırı senaryosunu otomatik çalıştırmanızı sağlar. Komutları `plain`, `base64` veya
`hex` olarak kodlayabilir — böylece honeypot'un gizleme tespitini test edebilirsiniz.

---

## Teknoloji yığını

**Dil:** Python 3.10+

**Kütüphaneler:** Flask (AI Bridge) · requests · socket / threading (dinleme ve UDP
log kanalı) · Tkinter (Linux GUI) · fpdf (PDF raporlama) · hashlib & random (VFS tohumu)

**Altyapı:** Docker · Docker Compose · X11 forwarding · LM Studio (OpenAI uyumlu
yerel çıkarım sunucusu)

---

## Yasal uyarı

Bu proje **yalnızca eğitim amaçlı**, siber güvenlik araştırması ve savunma
mekanizmalarının analizi için geliştirilmiştir.

Yüksek etkileşimli özellikler içerdiği ve yapay zekâ tarafından üretilen metni
doğrudan işlediği için, **yeterli izolasyon sağlanmadan üretim ağlarına doğrudan
bağlanması önerilmez**. Geliştiriciler, bu aracın kötüye kullanımından doğacak
sonuçlardan sorumlu değildir.


## English Version

# ShadowGuard — AI-Powered Honeypot System

> A high-interaction honeypot/trap system developed for the *Introduction to Cyber Security* course during Spring Semester 2026.

ShadowGuard is a honeypot system that lures attackers to a fake server to **analyze their behavior** and gather threat intelligence. Unlike the static and easily detectable structure of traditional honeypots, it operates with a local **large language model (LLM)**: it generates a distinct, consistent and convincing **virtual file system** for each attacker IP.

The folders the attacker sees when they type `ls`, the contents of the files they open with `cat`, the fake company name they encounter and the seemingly leaked credentials — all are generated instantly and specifically for that session.

---

## Table of Contents

- [How it works?](#how-it-works)
- [Repository structure: two versions](#repository-structure-two-versions)
- [Key features](#key-features)
- [Architecture](#architecture)
- [Risk scoring and attacker profiling](#risk-scoring-and-attacker-profiling)
- [Virtual File System (VFS)](#virtual-file-system-vfs)
- [Installation](#installation)
- [Usage](#usage)
- [Tech stack](#tech-stack)
- [Disclaimer](#disclaimer)

---

## How it works?

1. The honeypot starts listening on selected ports (mimicking SSH, HTTP, Telnet, etc.).
2. The connected attacker's IP address is converted into an **identity seed**.
3. From this seed, a fake corporate identity and file hierarchy are generated, which are specific to that IP and **remain the same** for every connection.
4. Every command from the attacker is forwarded to the local model running on LM Studio with the instruction "you are a Linux terminal"; the returned output is presented as a real shell response.
5. Commands are simultaneously analyzed, a risk score is calculated and it flows live to the **Monitor** screen via a UDP socket.
6. Files the attacker attempts to download are not executed; they are moved to the `quarantine/` folder.

*Note:* The local execution of the AI is critical: no attacker data is sent to external services.

---

## Repository structure: two versions

The project is packaged separately for two different environments:

| Folder | Version | Description |
|---|---|---|
| **`shadowguard-honeypot/`** | Linux (Docker + GUI) | The main version. Tkinter-based graphical interfaces are exported from the container using X11 forwarding. The web scanning module and advanced VFS are in this version. |
| **`Windows Version/`** | Windows / headless (CLI) | A lightweight port that does not require an X-Server. It uses a terminal interface instead of a graphical one; VirusTotal integration and PDF reporting are added to this version. |

Both folders have their own detailed English `README.md` files.

---

## Key features

| Feature | Description |
|---|---|
| 🧠 **Dynamic AI responses** | Realistic content is generated in seconds based on the attacker's command and the file they want to open |
| 📂 **Personalized virtual system** | A fixed seed for each IP; the fake corporate profile, file tree and credentials always remain the same |
| 📊 **Real-time risk scoring** | Entered commands are analyzed instantly, a profile is determined and transmitted live to the Monitor screen via UDP |
| 🦠 **VirusTotal integration** *(Windows version)* | Automatically queries whether the attacking IP is a known global threat |
| 📄 **Automated incident report** *(Windows version)* | A PDF threat report summarizing the attacker's commands and risk profile is generated when shutting down the system |
| 🕸️ **Red Team and web analysis module** | An attacker client capable of Base64/Hex obfuscation to test the system yourself |
| 🔒 **Quarantine** | Malicious files attempted to be downloaded are placed under `quarantine/` without being executed |
| 🐳 **Isolated environment** | The entire system runs in Docker containers on a closed `internal` network |

---

## Architecture

The system boots up as 4 services using `docker-compose.yml`:

```text
                    ┌──────────────────────────┐
   Attacker  ─────▶│  HONEYPOT                │
   (outside)       │  · listens to ports      │
                   │  · sets up VFS           │
                   │  · sends command to LLM  │
                   │  · quarantines payload   │
                   └───┬──────────────────┬───┘
                       │ UDP log          │ HTTP
                       ▼                  ▼
             ┌───────────────┐  ┌────────────────────┐
             │  MONITOR      │  │  AI BRIDGE (Flask) │
             │  · live log   │  │  /ai-ask  /status  │
             │  · risk score │  └─────────┬──────────┘
             │  · PDF report │            │ host-gateway
             └───────────────┘            ▼
                                ┌────────────────────┐
             ┌───────────────┐  │  LM Studio         │
             │  ATTACKER     │  │  on host machine   │
             │  (Red Team)   │  └────────────────────┘
             └───────────────┘

```

| Service | Task |
| --- | --- |
| **Honeypot** | The main trap. Listens to ports, receives connections, runs VFS and LLM scenarios, manages the quarantine folder |
| **Monitor** | Visualizes collected logs, risk statistics and live traffic arriving via UDP |
| **AI Bridge** | A Flask service acting as a bridge between the honeypot on the isolated network and LM Studio on the host machine |
| **Attacker** | A Red Team module written to test the system and run automated scenarios |

The network design is deliberately split into two: `shadow_net` is **internal** (no outbound access) and only the AI Bridge can access the host machine via a second bridge network.

---

## Risk scoring and attacker profiling

Monitor checks every command against two lists:

* **Critical commands** (+25 points): `wget`, `curl`, `chmod +x`, `rm -rf`, `id_rsa`, `shadow`, `python3 -c`, `bash -i`, `nc`, `socat`, `/dev/tcp`, `.ssh`, `authorized_keys`, `crontab`, `sudoers`
* **Exploration commands** (+5 points): `ls`, `whoami`, `pwd`, `id`, `uname`, `netstat`, `ps`, `cat /etc`, `env`, `history`, `find /`, `hostname`

A profile is assigned to the session based on the accumulated score:

| Score | Profile |
| --- | --- |
| ≥ 175 | **Advanced Threat** |
| ≥ 100 | **Professional Attacker** |
| ≥ 60 | **Explorer** |
| 25+ cmds, low score | **Kiddie** |
| Other | **Bot** |

As soon as the profile changes, the indicator on the Monitor screen updates.

---

## Virtual File System (VFS)

The attacker's IP is hashed to generate a fixed seed; with this seed:

* One of four fake corporate identities is selected
* Username, hostname and internal network IP are generated
* Realistic-looking fake secrets are created: database password, API key, session signing key and cloud provider access key — all intended as bait
* A directory tree full of bait files like `/root/Desktop/credentials.txt`, `/root/Documents/employee_database.csv`, and `VPN_access.ovpn` is set up

Because the seed is fixed, when the same attacker reconnects, they see the **same system** — inconsistency is the biggest clue that gives away a honeypot and this design eliminates it.

---

## Installation

### Common requirement: LM Studio

Both versions require a local language model.

1. Install LM Studio and download a model.
2. Switch to the **Local Server** tab from the left menu and start the local server.
3. **Enable CORS** so Docker containers can access it, and if necessary, expose the listening address to all network interfaces.

### 🐧 Linux version (Docker + GUI)

```bash
xhost +local:docker          # To allow X11 interfaces to open from the container
cd shadowguard-honeypot
sudo docker compose up --build

```

This command sets up the isolated Docker network, starts the Monitor, puts the Honeypot into listening mode and synchronizes the AI Bridge and Attacker services.

To stop the system, press `Ctrl+C` in the terminal or run `sudo docker compose down` if it's running in the background.

### 🪟 Windows version (headless CLI)

Python 3.10+ is required. Docker and an X-Server are not needed.

```powershell
cd "Windows Version"
pip install flask requests fpdf

# 1st terminal — monitor attacks
python monitor/monitor_cli.py

# 2nd terminal — test the system with the Red Team module
python attacker/main_cli.py

```

When you close the Monitor with `Ctrl+C`, a PDF report is automatically generated in the `./data/reports` folder.

**For VirusTotal:** In the Monitor module, the IP reputation query becomes active when you define your own VirusTotal API key. If a key is not defined, the system continues to work and only this query is skipped.

---

## Usage

From the **Honeypot interface**, select the ports to listen to and start the system with *Listen on Selected Ports*. If you want information about a port, you can ask the AI; the web analysis module runs simple security checks on a given local address or file; the scope is deliberately kept narrow — only the local machine, private networks and a limited list of file extensions can be scanned.

The **Monitor screen** features a live log stream, session statistics, historical log filtering by IP and date and an attacker profile indicator.

The **Attacker module** allows you to connect to the honeypot and send commands manually or run a ready-made attack scenario automatically. It can encode commands in `plain`, `base64`, or `hex` — allowing you to test the honeypot's obfuscation detection.

---

## Tech stack

**Language:** Python 3.10+

**Libraries:** Flask (AI Bridge) · requests · socket / threading (listening and UDP log channel) · Tkinter (Linux GUI) · fpdf (PDF reporting) · hashlib & random (VFS seed)

**Infrastructure:** Docker · Docker Compose · X11 forwarding · LM Studio (OpenAI compatible local inference server)

---

## Disclaimer

This project was developed **solely for educational purposes**, cybersecurity research and the analysis of defense mechanisms.

Because it contains high-interaction features and directly processes text generated by AI, **it is not recommended to connect it directly to production networks without providing adequate isolation**. The developers are not responsible for any consequences arising from the misuse of this tool.

```

```
