# ShadowGuard — Yapay Zekâ Destekli Honeypot Sistemi

> *Introduction to Cyber Security* dersi kapsamında geliştirilmiş, yüksek etkileşimli
> (high-interaction) bir bal küpü / tuzak sistemi.

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
