# DoPing

> Bir alan adıyla ilgili **tüm alt alan adlarını ve ilişkili domainleri bulan**, her biri için **gerçek gecikmeyi (ms)** ölçen ve DNS / TLS / HTTP sağlık analizi yapan tek dosyalık Windows aracı.

![Platform](https://img.shields.io/badge/platform-Windows-blue)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE)
![Kurulum](https://img.shields.io/badge/kurulum-gerekmiyor-brightgreen)
![Sürüm](https://img.shields.io/badge/sürüm-2.0-orange)

DoPing tek bir `DoPing.bat` dosyasıdır. Python, Node veya ek bir kurulum gerektirmez. Çift tıklayın, alan adını yazın, sonucu bekleyin.

---

## İçindekiler

- [Neden DoPing?](#neden-doping)
- [Özellikler](#özellikler)
- [Hızlı başlangıç](#hızlı-başlangıç)
- [Tarama modları](#tarama-modları)
- [Nasıl çalışır?](#nasıl-çalışır)
- [Ölçüm doğruluğu: ICMP neden güvenilmez olabilir?](#ölçüm-doğruluğu-icmp-neden-güvenilmez-olabilir)
- [Çıktılar](#çıktılar)
- [Konsol tablosu nasıl okunur?](#konsol-tablosu-nasıl-okunur)
- [Bulgular ve sağlık puanı](#bulgular-ve-sağlık-puanı)
- [Etkileşimli menü](#etkileşimli-menü)
- [Gereksinimler](#gereksinimler)
- [Gizlilik: hangi dış servislere bağlanır?](#gizlilik-hangi-dış-servislere-bağlanır)
- [Sorun giderme](#sorun-giderme)
- [Sınırlamalar](#sınırlamalar)
- [Proje yapısı](#proje-yapısı)
- [Katkı](#katkı)
- [Yasal uyarı](#yasal-uyarı)
- [Lisans](#lisans)

---

## Neden DoPing?

Klasik `ping` tek bir hostun cevap verip vermediğini söyler. DoPing ise şu soruları tek seferde yanıtlar:

- Bu alan adının **hangi alt alan adları** var? (`api`, `staging`, `mail`, `cdn` ...)
- Bunların her birine **gerçekte kaç ms** gecikmeyle ulaşıyorum?
- Sertifikaları geçerli mi, ne zaman bitiyor, TLS sürümü ne?
- DNS, SPF, DMARC, DNSSEC yapılandırması sağlıklı mı?
- Unutulmuş, **sahipsiz bir CNAME** (subdomain takeover riski) var mı?
- Aldığım ping değerlerine **güvenebilir miyim**, yoksa araya giren bir VPN/güvenlik yazılımı sahte yanıt mı üretiyor?

Son soru DoPing'i sıradan araçlardan ayıran noktadır. Ayrıntısı [aşağıda](#ölçüm-doğruluğu-icmp-neden-güvenilmez-olabilir).

---

## Özellikler

### Keşif
- **DNS kayıtları:** A, AAAA, NS, MX, SOA, TXT, CNAME, SRV, CAA, DNSKEY
- **SPF / DMARC içindeki alan adları** (`include:`, `redirect=`, `rua=`) ilişkili domain olarak eklenir
- **8 pasif kaynak** (sertifika şeffaflığı ve pasif DNS):
  `crt.sh`, `CertSpotter`, `Anubis (jldc.me)`, `HackerTarget`, `AlienVault OTX`, `RapidDNS`, `urlscan.io`, `Wayback Machine`
- **Alt alan adı sözlüğü:** moda göre ~60 ile 600+ kelime (numaralı varyasyonlar dahil: `mail01`, `vpn3` ...)
- **Permütasyon motoru:** bulunan isimlerden türetme (`web-prod-eastus-03` → `-04`, `-05`; `dev` ↔ `staging` ↔ `qa`)
- **Özyinelemeli tarama:** bulunan alt alan adlarının altında alt-alt arama (`api.dev.example.com`)
- **Sertifika SAN genişlemesi:** her hostun TLS sertifikasındaki ek isimler yeni aday olarak taranır
- **HTTP yönlendirme takibi:** `Location` başlığındaki aynı alan adlı hostlar eklenir
- **Joker (wildcard) DNS tespiti:** sahte sonuçlar otomatik elenir
- **Benzer TLD varyasyonları** (`example.net`, `example.com.tr` ...) ve **RDAP ile sahiplik ilişkisi tahmini**

### Ölçüm
- **TCP bağlantı süresi** (443, yoksa 80): min / ortalama / medyan / p95 / maks / standart sapma / kayıp
- **TLS el sıkışma süresi**, **TTFB** (ilk bayt süresi), toplam HTTP süresi
- **ICMP ping:** min / ortalama / maks / jitter / kayıp / TTL / tahmini hop sayısı
- **Hassas (seri) ölçüm:** paralel taramadan sonra en önemli IP'ler tek tek, eş zamanlı yük olmadan yeniden ölçülür
- **IP başına birden fazla adres:** bir hostun birden fazla IP'si varsa hepsi ölçülür, en iyisi seçilir
- **Yol analizi (`tracert`)** şüpheli veya ana hedefler için
- **Referans ölçümleri:** varsayılan ağ geçidi, 1.1.1.1 ve 8.8.8.8

### Analiz
- **Ölçüm bütünlüğü kontrolü** (sahte ICMP tespiti, fiziksel imkansızlık testi)
- Sertifika: bitiş günü, ad uyumu, zincir doğrulaması, anahtar türü, imza algoritması
- TLS sürümü ve şifre, eski TLS (1.0 / 1.1) tespiti
- HTTP güvenlik başlıkları: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy
- CDN / sunucu parmak izi (Cloudflare, CloudFront, Akamai, Fastly, Azure Front Door, Vercel, Netlify ...)
- Yetkili isim sunucularına doğrudan sorgu, yanıt süresi ve **SOA seri tutarlılığı**
- **Dört farklı DNS çözücünün karşılaştırması** (sistem, Cloudflare, Google, Quad9)
- SPF `all` mekanizması, DMARC politikası, CAA, DNSSEC
- **Dangling CNAME** tespiti
- Hassas görünen isimler (`dev`, `staging`, `admin`, `jenkins`, `phpmyadmin` ...)
- **Geo-IP / ASN / barındırma sağlayıcısı** bilgisi
- Alan adı kaydı (RDAP): kayıtçı, oluşturma ve bitiş tarihi
- 0-100 arası **sağlık puanı** ve harf notu

### Rapor
- Renkli konsol tablosu
- Sıralanabilir ve filtrelenebilir **HTML raporu** (karanlık/aydınlık tema, histogram, CSV indirme düğmesi)
- **CSV** (Türkçe Excel uyumlu), **JSON**, **TXT**, host listesi
- **Önceki taramayla karşılaştırma:** yeni / kaybolan host, IP değişimi, belirgin yavaşlama / hızlanma
- **Canlı izleme paneli** (ASCII grafikli)

---

## Hızlı başlangıç

1. `DoPing.bat` dosyasını indirin.
2. Çift tıklayın.
3. Alan adını yazın (`example.com`, `https://www.example.com/yol` de olur, otomatik temizlenir).
4. Bir mod seçin ve bekleyin.

Komut satırından:

```bat
:: Etkileşimli
DoPing.bat

:: Alan adını önceden ver
DoPing.bat example.com

:: Tam otomatik (alan adı + mod 1-3), menü açmadan çalışır ve kapanır
DoPing.bat example.com 2
```

Sonuçlar `DoPing.bat` ile aynı klasörde oluşan **`Sonuclar`** klasörüne kaydedilir.

> **Not:** Windows SmartScreen veya antivirüs ilk çalıştırmada uyarı verebilir. Bkz. [Sorun giderme](#sorun-giderme).

---

## Tarama modları

| Mod | Süre* | Ne yapar |
|---|---|---|
| **1 Hızlı** | ~15-30 sn | DNS kayıtları, küçük sözlük, TCP/ICMP ölçümü, en fazla 30 host için TLS/HTTP |
| **2 Standart** (varsayılan) | ~1-2 dk | + 8 pasif kaynak, orta sözlük, permütasyon, alt-alt tarama, SAN genişlemesi (1 tur), CNAME kontrolü, hassas ölçüm, yol analizi |
| **3 Derin** | ~3-6 dk | + benzer TLD'ler ve RDAP ilişki analizi, 600+ kelimelik sözlük, geniş permütasyon, 3 tekrarlı TLS/HTTP, SAN genişlemesi (2 tur), 15 IP'de hassas ölçüm |
| **4 Özel** | değişken | Pasif kaynaklar, sözlük seviyesi, permütasyon, paket sayısı, tekrar sayısı, zaman aşımı vb. tüm ayarları kendiniz seçersiniz |

\* Hedefin büyüklüğüne ve ağınıza göre değişir.

---

## Nasıl çalışır?

Tarama 10 adımda ilerler:

```
[1] Ağ ortamı ve referans ölçümleri (genel IP, VPN/proxy, ağ geçidi, 1.1.1.1 / 8.8.8.8)
[2] DNS kayıtları, SPF/DMARC/CAA/DNSSEC, yetkili NS sorguları, çözücü karşılaştırması
[3] Joker (wildcard) DNS testi
[4] Pasif kaynaklar (sertifika şeffaflığı, pasif DNS, arşiv)
[5] Sözlük + (Derin modda) benzer TLD adayları
[6] Toplu DNS çözümleme + permütasyon + alt-alt tarama
[7] Gecikme ölçümü (ICMP + TCP), TLS/HTTP testi, sertifika SAN genişlemesi
[8] CNAME (dangling) kontrolü, Geo-IP, RDAP
[9] Hassas (seri) ölçüm
[10] Analiz, bulgular, rapor
```

### Teknik mimari

- `DoPing.bat` hem bir toplu iş dosyası hem de **gömülü bir PowerShell programıdır**. Başlık kısmı kendi dosyasını okur, `#PSBEGIN#` satırından sonrasını ayıklar ve PowerShell'de çalıştırır. Ayrı bir `.ps1` dosyası yoktur.
- Ağ ölçümleri için programın içine gömülü küçük bir **C# sınıfı** (`DpNet`, `Add-Type` ile derlenir) kullanılır. Bu sayede TCP/TLS/HTTP ölçümleri yüksek çözünürlüklü `Stopwatch` ile yapılır ve sertifika SAN alanları işletim sistemi diline bağımlı olmadan ham ASN.1 olarak okunur.
- Paralellik için PowerShell **runspace havuzu** kullanılır (ek modül gerekmez).
- Tüm rapor biçimleri (HTML dahil) tek dosya ve dış bağımlılıksız üretilir.

---

## Ölçüm doğruluğu: ICMP neden güvenilmez olabilir?

DoPing'in geliştirilmesinin asıl nedeni budur. Gerçek bir taramada, onlarca farklı ülkedeki sunucunun tümü **aynı TTL değeriyle (126)** ve **1-3 ms**'de yanıt verdi. Türkiye'deki bir sunucuya Almanya'dan 1 ms'de ulaşmak fiziksel olarak mümkün değildir. Bu tür yanıtları genellikle ağdaki bir **VPN, güvenlik yazılımı, proxy veya modem** yerelde üretir.

DoPing bunu şöyle ele alır:

| Kontrol | Mantık |
|---|---|
| **Işık hızı sınırı** | Işık fiberde ~200 km/ms ilerler; gidiş-dönüş süresi en az `mesafe_km / 100` ms olmalıdır. Ölçülen değer bunun çok altındaysa satır **F (fiziksel imkansız)** olarak işaretlenir. Anycast/CDN IP'leri (en yakın noktaya gittiği için) bu testten muaftır. |
| **ICMP ↔ TCP tutarlılığı** | Bir TCP el sıkışması da 1 RTT sürer; ICMP ile TCP aynı büyüklükte olmalıdır. ICMP, TCP'nin %40'ından kısaysa **I (ICMP şüpheli)**. |
| **TTL tekdüzeliği** | Birbirinden farklı ülke/AS'lerdeki 6+ IP'nin %90'ı aynı TTL ile yanıt veriyorsa tüm ICMP değerleri geçersiz sayılır. |
| **Referans hedefler** | 1.1.1.1 ve 8.8.8.8 için ICMP ve TCP ayrıca karşılaştırılır. |

Bu yüzden **ana gecikme değeri TCP bağlantı süresidir** (`GercekMs`). ICMP yalnızca ek bilgi olarak gösterilir ve şüpheliyse `*` ile işaretlenir.

> TCP bağlantısı da bir VPN/proxy tarafından yerelde sonlandırılıyorsa, ölçüm yine yanıltıcı olur. Böyle bir durumda DoPing satırı **F** olarak işaretler ve bulgularda bunu belirtir. Ölçümler her zaman **bulunduğunuz ağdan** yapılır; VPN açıksa VPN çıkış noktasından yapılmış olur.

---

## Çıktılar

Her tarama `Sonuclar\<alanadi>_<tarih_saat>.*` olarak şu dosyaları üretir:

| Dosya | İçerik |
|---|---|
| `.html` | Etkileşimli rapor: özet kartları, bulgular, gecikme histogramı, sıralanabilir/filtrelenebilir host tablosu, veri kaynakları ve NS tabloları. Tarayıcıda açılır, internet gerektirmez. |
| `.csv` | Tüm hostlar ve ~60 sütun. `;` ayraçlı, UTF-8 BOM'lu, ondalık ayıracı virgül (Türkçe Excel'de doğrudan açılır). |
| `.json` | Aynı veri makine okunur biçimde. Önceki tarama karşılaştırması bu dosyayı kullanır. |
| `.txt` | Konsol çıktısının birebir kaydı. |
| `_hostlar.txt` | Çözümlenen hostların düz listesi (başka araçlara girdi olarak kullanılabilir). |

### CSV / JSON sütunlarından bazıları

`Host`, `Tur` (Ana / Alt / TLD / Harici), `IP`, `TumIPler`, `GercekMs`, `Yontem`, `TcpMin`, `TcpOrt`, `TcpMed`, `TcpP95`, `TcpMax`, `TcpStd`, `TcpKayip`, `IcmpOrt`, `IcmpMin`, `IcmpMax`, `IcmpJit`, `IcmpKayip`, `TTL`, `Hop`, `DnsMs`, `TlsMs`, `TtfbMs`, `ToplamMs`, `Http`, `Sunucu`, `CDN`, `Yonlendirme`, `TlsSurum`, `Sifre`, `SertKonu`, `SertVeren`, `SertGun`, `SertBitis`, `SertUyum`, `SertZincir`, `SertAnahtar`, `SANsayisi`, `HSTS`, `CSP`, `XFO`, `XCTO`, `RefPol`, `GuvPuan`, `Ulke`, `Sehir`, `ISP`, `ASN`, `Anycast`, `PTR`, `MesafeKm`, `CNAME`, `Dangling`, `Kayitci`, `Olusturma`, `Iliski`, `Uyari`, `Kaynak`, `Durum`

---

## Konsol tablosu nasıl okunur?

```
#    HOST                     TUR    IP                TCP ms     TLS    TTFB    ICMP HTTP SUNUCU/CDN   ULKE ISARET
1    cdn.example.com          Alt    104.18.1.1          4.00    8.00    16.0   1.00* 200  Cloudflare   CA   AI
2    example.com              Ana    203.0.113.10        24.0    48.0    96.0   1.20* 200               DE   I+
```

| Sütun | Anlamı |
|---|---|
| **TCP ms** | 443 (yoksa 80) portuna bağlantı kurma süresi. **Ana ölçüt.** |
| **TLS** | TLS el sıkışma süresi |
| **TTFB** | İsteğin gönderilmesinden ilk yanıt baytına kadar geçen süre |
| **ICMP** | Klasik ping ortalaması. `*` = güvenilmez |
| **HTTP** | Ana sayfanın durum kodu |
| **ISARET** | Aşağıdaki harf kodları |

**Renkler:** 🟢 <30 ms · 🟡 <100 ms · 🟠 <200 ms · 🔴 ≥200 ms · gri: yanıt yok · mor: fiziksel olarak imkansız

**İşaret kodları**

| Kod | Anlamı |
|---|---|
| `F` | Fiziksel olarak imkansız gecikme |
| `I` | ICMP şüpheli |
| `D` | Dangling CNAME (hedefi çözülmüyor) |
| `S` | Sertifika sorunu (süresi dolmuş / yakında bitiyor / ad uyumsuz / zincir doğrulanamadı) |
| `T` | Eski TLS (1.0 / 1.1) |
| `X` | Çözülüyor ama ICMP ve TCP yanıt vermiyor |
| `H` | Hassas görünen isim (`dev`, `admin`, `jenkins` ...) |
| `E` | HTTP 5xx hatası |
| `A` | Anycast / CDN IP'si |
| `+` | Hassas (seri) ölçüm yapıldı |

---

## Bulgular ve sağlık puanı

Bulgular dört seviyede listelenir:

| Seviye | Puan etkisi | Örnek |
|---|---|---|
| **KRITIK** | −15 | Süresi dolmuş sertifika, dangling CNAME, SPF `+all`, ICMP yanıtlarının yerelde üretilmesi |
| **UYARI** | −5 | SPF/DMARC yok, port 80'de HTTPS yönlendirmesi yok, NS seri uyumsuzluğu, ad uyumsuz sertifika |
| **BILGI** | −1 | CAA/DNSSEC yok, DMARC `p=none`, hassas isimler, VPN aktif |
| **IYI** | 0 | SPF `-all`, DMARC `reject`, TLS 1.3, HSTS, geçerli sertifikalar |

100'den başlayıp düşer; 90+ → **A**, 75+ → **B**, 60+ → **C**, 40+ → **D**, altı **F**.

> Puan, görünen yapılandırmanın bir **özetidir**, güvenlik denetimi veya sızma testi yerine geçmez.

---

## Etkileşimli menü

Tarama bittikten sonra:

| Seçenek | İşlev |
|---|---|
| **1** Yeni alan adı | Başka bir hedef tara |
| **2** Aynı alanı yeniden tara | Farklı modla tekrar çalıştır (önceki taramayla fark gösterilir) |
| **3** Canlı izleme paneli | Seçtiğiniz hostları saniyede bir TCP + ICMP ile ölçer; son / ort / min / maks / kayıp ve ASCII grafik. `Q` ile çıkılır |
| **4** Canlı ping (-t) | Seçtiğiniz host için ayrı bir `ping -t` penceresi açar |
| **5** Host detayı | Seçilen satırın tüm alanlarını gösterir |
| **6** HTML raporu aç | Son raporu tarayıcıda açar |
| **7** Rapor klasörü | `Sonuclar` klasörünü açar |
| **0** Çıkış | |

---

## Gereksinimler

| | |
|---|---|
| **İşletim sistemi** | Windows 10 / 11 önerilir. Windows 8+ için tam özellik; Windows 7 SP1'de DNS kayıt analizi sınırlıdır (`Resolve-DnsName` yok) |
| **PowerShell** | 5.1 (Windows ile birlikte gelir) |
| **.NET Framework** | 4.5+ (TLS 1.3 gösterimi için 4.8 + güncel Windows önerilir) |
| **İnternet** | Gerekli. Pasif kaynaklar, Geo-IP, RDAP ve ölçüm hedefleri için |
| **Yönetici hakkı** | Gerekmez |
| **Kurulum** | Gerekmez |

---

## Gizlilik: hangi dış servislere bağlanır?

DoPing bilgisayarınızda çalışır ve sonuçları yalnızca yerel `Sonuclar` klasörüne yazar. Tarama sırasında şu üçüncü taraf servislere istek gider:

| Servis | Gönderilen bilgi | Amaç |
|---|---|---|
| crt.sh, CertSpotter, Anubis, HackerTarget, AlienVault OTX, RapidDNS, urlscan.io, Wayback Machine | Taranan **alan adı** | Pasif alt alan adı keşfi |
| ip-api.com (HTTP) | Bulunan **IP adresleri** ve sizin genel IP'niz | Konum / ASN / barındırma bilgisi |
| rdap.org | Alan adı | Kayıt bilgisi (kayıtçı, tarihler) |
| 1.1.1.1, 8.8.8.8, 9.9.9.9 | Alan adı (DNS sorgusu) | Çözücü karşılaştırması |
| Hedef sunucular | Standart TCP/TLS/HTTP/ICMP istekleri | Gecikme ve sertifika ölçümü |

Hiçbir veri bir DoPing sunucusuna gönderilmez; böyle bir sunucu yoktur. Bu çağrıları istemiyorsanız **Hızlı** modu kullanın (pasif kaynaklar kapalıdır). Geo-IP ve RDAP yine de çalışır; kodda ilgili bölümleri devre dışı bırakabilirsiniz.

---

## Sorun giderme

**"Windows bilgisayarınızı korudu" (SmartScreen) uyarısı**
İndirilen `.bat` dosyaları için normaldir. *Ek bilgi → Yine de çalıştır* deyin ya da dosyaya sağ tıklayıp *Özellikler → Engellemeyi kaldır*'ı işaretleyin.

**Antivirüs uyarısı / dosya siliniyor**
DoPing, bir `.bat` içinden PowerShell başlatır ve C# kodunu çalışma anında derler (`Add-Type`). Bu davranış bazı antivirüslerde yanlış pozitif tetikleyebilir. Kaynak kod tamamen açıktır (dosyayı bir metin düzenleyicide açıp inceleyebilirsiniz); gerekirse klasörü antivirüs istisnasına ekleyin.

**"Ağ motoru derlenemedi" uyarısı**
C# bileşeni derlenemedi. TLS/HTTP testleri kapanır; ICMP ve basit TCP ölçümleri çalışmaya devam eder. Hata mesajı uyarının yanında yazılır; lütfen bir Issue açarken bu mesajı ekleyin.

**Bazı pasif kaynaklar "BASARISIZ" görünüyor**
Normaldir. crt.sh gibi servisler yoğunluk nedeniyle zaman aşımına uğrayabilir veya sınırlama uygulayabilir. Hangi kaynağın çalıştığı raporda ve konsolda görünür. Birkaç dakika sonra tekrar deneyin.

**Çok az host buluyor**
Hızlı mod pasif kaynakları kullanmaz. Standart veya Derin modu deneyin.

**Tüm ICMP değerleri 1-3 ms ve işaretli**
Ağınızda ICMP yanıtlarını yerelde üreten bir cihaz/yazılım olabilir (VPN, güvenlik yazılımı, bazı modemler). Bu durumda TCP değerlerine bakın. Bu araçtan beklenen davranıştır, hata değil.

**Türkçe karakterler bozuk görünüyor**
Konsol yazı tipini *Consolas* veya *Lucida Console* yapın. Windows Terminal'de sorun yaşanmaz.

**Yavaş çalışıyor**
Derin mod yüzlerce DNS sorgusu ve onlarca TLS bağlantısı yapar. Ağ/güvenlik duvarı kısıtlamaları süreyi uzatabilir. Özel moddan zaman aşımını ve paket sayısını düşürebilirsiniz.

---

## Sınırlamalar

- **Pasif keşif eksiksiz değildir.** Hiçbir yerde kayıtlı olmayan, sözlükte de bulunmayan bir alt alan adı bulunamaz.
- **IP konumu yaklaşıktır.** Geo-IP verisi özellikle anycast/CDN IP'lerinde yanıltıcıdır; bu IP'ler fiziksel imkansızlık testinden muaf tutulur.
- **TLS testi, istemcinin desteklediği sürümlerle sınırlıdır.** DoPing sunucunun tüm TLS sürümlerini taramaz; yalnızca müzakere edilen sürümü raporlar.
- **Sertifika zinciri doğrulaması** yerel Windows güven deposuna göre yapılır.
- **Benzer TLD ilişki puanı bir tahmindir.** `example.net` ile `example.com` aynı sahibe ait olabilir de olmayabilir de; sonuç kesin kanıt değildir. Bazı ülke uzantıları RDAP desteklemez.
- **Rate limit:** ip-api.com ve bazı pasif servisler ücretsiz kullanımda istek sınırı uygular.
- **Yalnızca Windows.** Betik Windows'a özgü bileşenlere (`tracert`, `Resolve-DnsName`, kayıt defteri proxy ayarı) dayanır.
- **IPv6** hostlar yalnızca IPv4'ü olmayan hostlar için ölçülür (öncelik IPv4).

---

## Proje yapısı

```
DoPing/
├── DoPing.bat      # Tüm program (bat başlatıcı + gömülü PowerShell + gömülü C#)
├── README.md
└── Sonuclar/       # İlk taramada otomatik oluşturulur
    ├── example.com_20261008_213517.html
    ├── example.com_20261008_213517.csv
    ├── example.com_20261008_213517.json
    ├── example.com_20261008_213517.txt
    └── example.com_20261008_213517_hostlar.txt
```

`.gitignore` önerisi:

```
Sonuclar/
```

### Geliştiriciler için: rapor hattını ağsız test etme

Ortam değişkeni `DOPING_SELFTEST=1` verilirse program ağa çıkmadan sentetik verilerle analiz, bulgu ve rapor üretimini çalıştırır:

```powershell
$env:DOPING_SELFTEST = '1'
.\DoPing.bat
```

Bu mod, rapor biçimlerini ve bulgu mantığını değiştirdiğinizde hızlı doğrulama için kullanışlıdır. Dosyayı CRLF satır sonlarıyla ve **BOM'suz UTF-8** olarak kaydedin; BOM, ilk satırdaki `@echo off` komutunu bozar.

---

## Katkı

Hata raporları ve öneriler memnuniyetle karşılanır.

- **Issue açarken** şunları ekleyin: Windows ve PowerShell sürümü (`$PSVersionTable`), kullandığınız mod, konsol çıktısı veya `.txt` raporu (gerekirse hassas alan adlarını silerek).
- **Pull request** için: değişikliğin ne yaptığını açıklayın ve mümkünse `DOPING_SELFTEST=1` ile rapor hattının hâlâ çalıştığını doğrulayın.

Fikir listesi: Markdown/PDF rapor, yapılandırma dosyası, ek pasif kaynaklar, port taraması olmayan servis tespiti, Windows dışı sürüm.

---

## Yasal uyarı

DoPing **yalnızca herkese açık bilgileri** (DNS kayıtları, sertifika şeffaflık günlükleri, arşivler) okur ve **standart bağlantı testleri** (TCP bağlantısı, TLS el sıkışması, tek bir HTTP GET isteği, ICMP) yapar. Zafiyet taraması, kaba kuvvet, port taraması veya sömürü içermez.

Buna rağmen:

- Aracı yalnızca **sahibi olduğunuz** veya **test etmek için izniniz bulunan** alan adlarında kullanın.
- Yerel yasalara ve hedef servislerin kullanım koşullarına uymak kullanıcının sorumluluğundadır.
- Yazar(lar), aracın kötüye kullanımından veya sonuçlarının yanlış yorumlanmasından sorumlu tutulamaz.
- Sağlık puanı ve bulgular bilgilendirme amaçlıdır; profesyonel güvenlik denetiminin yerine geçmez.

---

