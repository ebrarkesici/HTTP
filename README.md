# HTTP
*curl -I komutuyla https://www.pcichecklist.com adresine istek gonderdik ve response'un sadece header kismini ogrenmek istedik.* <br/>
C:\Users\SSB>curl -I https://www.pcichecklist.com  
HTTP/1.1 403 Forbidden *(403 uyarisi erisime iznimiz olmadiginda aldigimiz hata mesaji)*  
Date: Thu, 03 Aug 2023 15:41:00 GMT  
Content-Type: text/html; charset=UTF-8 *(belgenin karakter kodlamasini belirtmek icin HTTP basliginda bir karakter kumesi parametresi gonderir)*  
Connection: close *(HTTP başlığı sunucuya, istemcinin HTTP işlemini tamamladıktan sonra bağlantıyı kapatmak istediğini bildirir.)*  
Cross-Origin-Embedder-Policy: require-corp *(belirli saldırı türlerinin önlenmesine yardımcı olan, ancak farklı bir kaynaktan gelen kaynakların paylaşılmasından yararlanabilen bir güvenlik önlemidir.)*  
Cross-Origin-Opener-Policy: same-origin *(Tarama bağlamını yalnızca aynı kaynaklı belgelere izole eder. Kaynaklar arası belgeler aynı tarama bağlamında yüklenmez.)*  
Cross-Origin-Resource-Policy: same-origin *(Yalnızca aynı kaynaktan ( yani şema + ana bilgisayar + bağlantı noktası) gelen istekler kaynağı okuyabilir.)*  
Origin-Agent-Cluster: ?1 *(tarayıcıya, aynı sitedeki kaynaklar arası sayfalar arasında eşzamanlı komut dizisi erişimini engellemesi talimatını veren yeni bir HTTP yanıt başlığıdır.)*(true)  
Permissions-Policy: accelerometer=(),autoplay=(),camera=(),clipboard-read=(),clipboard-write=(),geolocation=(),gyroscope=(),hid=(),interest-cohort=(),magnetometer=(),microphone=(),payment=(),publickey-credentials-get=(),screen-wake-lock=(),serial=(),sync-xhr=(),usb=()  
*(geçerli belgenin arabirim aracılığıyla aygıtın hızlanması hakkında bilgi toplamasına izin verilip verilmediğini kontrol eder)*  
Referrer-Policy: same-origin *(yönlendiren olarak kullanılmak üzere çıkarılan tam bir URL'nin, belirli bir istemciden aynı kaynaklı istekler yapılırken yönlendiren bilgisi olarak gönderildiğini belirtir.)*  
X-Frame-Options: SAMEORIGIN *(siteyi tıklama saldırılarından korumak için kullanılır.Bu yönerge, frame sayfa ile aynı orijine sahipse, sayfanın frame'de işlenmesine izin verir.)*  
cf-mitigated: challenge *(Bir web sitesi Cloudflare tarafından korunduğunda ziyaretçinin IP adresi çevrimiçi olarak şüpheli davranış göstermis olabilir.)*  
Cache-Control: private, max-age=0, no-store, no-cache, must-revalidate, post-check=0, pre-check=0 *(tarayıcılarda ve paylaşılan önbelleklerde, önbelleğe almayı kontrol eden yönergeleri  hem isteklerde hem de yanıtlarda tutar.)*  
Expires: Thu, 01 Jan 1970 00:00:01 GMT *(suresi dolmus demek)*  
Report-To: {"endpoints":[{"url":"https:\/\/a.nel.cloudflare.com\/report\/v3?s=JnTjQzfD7ENnKab9H9AYnB4se4Sev1dXAvixDni0T3a22A9yOiE84EXWg5b3poQPZkBlGQ2vZHlpI1JMOFIhzRhA0TG0i9jQH7FFBZhMkru6Cgf7eo1NHysbZWVZOKIuudZuMOEO"}],"group":"cf-nel","max_age":604800}  
NEL: {"success_fraction":0,"report_to":"cf-nel","max_age":604800} *(Network Error Logging)(NEL, site ziyaretçilerinin Cloudflare'a bağlanmasıyla ilgili sorunları hızlı bir şekilde belirlemek için kullanılan tarayıcı tabanlı bir teknolojidir)*  
Server: cloudflare  
CF-RAY: 7f0fa9900e741c7e-AMS  
alt-svc: h3=":443"; ma=86400  

## HTTP Header icerisinde gelen 405 Method Not Allowed nedir? <br/>
## 405 Durum Kodu (Method Not Allowed): <br/>
- Gonderilen sorgu turunu HTTP'nin kabul etmedigini belirtir.Bu baglamda sorgu turunuzu GET veya POST olarak degistirip tekrar denemelisiniz.  
Izin verilmeyen bir dosyaya ulasilmaya calisildigi takdirde sunucu bu islemi engeller.ornegin GET'i kullanarak POST ya da PUT icerisinde bulunan sadece okunabilir kaynaklara ulasmaya calismaniz durumunda bu hatayla karsilasabilirsiniz.  

##HTTP HEADER CONTROL
C:\Users\SSB>curl -I https://http.dev/cross-origin-embedder-policy  
HTTP/1.1 200 OK  
content-type: text/html; charset=utf-8  
strict-transport-security: max-age=63072000; includeSubDomains; preload  
pragma: public  
cache-control: public, max-age=86400  
x-content-type-options: nosniff  
x-frame-options: SAMEORIGIN  
x-ua-compatible: IE=Edge,chrome=1  
x-xss-protection: 1; mode=block  
vary: Accept-Encoding  
x-versionid: 467gRk3Q  
x-production: True  
link: <https://http.dev/css/app.min.css?v=467gRk3Q>; rel="preload"; as="style"   
x-request-id: 340a5e04-28d3-4818-bd3a-fd8cb923df47  
Content-Encoding: br  
X-Cloud-Trace-Context: 4e5690eea8628c23bb70a3cf90eeafbb  
Content-Length: 6980  
Date: Fri, 04 Aug 2023 09:50:21 GMT  
Server: Google Frontend  
*Google Frontend terimi, genellikle Google'ın altyapısında bulunan ve kullanıcıların internet tarayıcıları aracılığıyla eriştiği hizmetlerin ön yüzünü (frontend) ifade eder. Google'ın büyük ölçekli hizmetlerini sağlamak için kullandığı bir tür sunucu altyapısıdır. Bu ön yüz sunucuları, kullanıcı taleplerini yönlendirme, işleme ve sonuçları geri döndürme görevlerini üstlenirler. Google Frontend sunucuları, ağ trafiğini yönlendirme, yük dengeleme, güvenlik ve diğer önemli işlevleri gerçekleştirebilirler. Ayrıca, içerik dağıtımı (CDN) gibi özellikleri de destekleyerek, kullanıcılara daha hızlı ve güvenilir bir deneyim sunmayı amaçlarlar.*

C:\Users\SSB>curl -I https://www.w3.org/TR/referrer-policy/#referrer-policy-same-origin  
HTTP/1.1 200 OK  
Date: Fri, 04 Aug 2023 09:55:20 GMT  
Content-Type: text/html; charset=utf-8  
Connection: keep-alive  
content-location: Overview.html  
last-modified: Mon, 23 Jan 2017 19:51:44 GMT  
etag: W/"1f414-546c854395400-gzip"  
Cache-Control: public, max-age=86400  
vary: Accept-Encoding,Origin  
link: <https://www.w3.org/TR/referrer-policy/>;rel="canonical",   <https://timetravel.mementoweb.org/w3c/timegate/https://www.w3.org/TR/referrer-policy/>;rel="timegate"  
access-control-allow-origin: *  
x-backend: www-mirrors  
x-request-id: 7f15ec9178576238  
strict-transport-security: max-age=15552000; includeSubdomains; preload  
content-security-policy: frame-ancestors 'self' https://cms.w3.org/; upgrade-insecure-requests  
CF-Cache-Status: BYPASS  
Set-Cookie: __cf_bm=j9c4CE.yTz8tS8t4AcHngjhfZ4qJLGJo_EKFGWiu3ro-1691142920-0-AWjV2A9XPY3ky7Kx760pUTkK9eXl/gdJwc/5ia+6vynzx8BoiB94PROFwKhT6uTLcEKBLCcLjat2Vo3DD1DibCQ=; path=/; expires=Fri, 04-Aug-23 10:25:20 GMT; domain=.w3.org; HttpOnly; Secure; SameSite=None  
Server: cloudflare  
*Cloudflare, web sitelerinin daha hızlı yüklenmesini sağlamak, güvenliği artırmak ve DDoS saldırıları gibi tehditlere karşı korumak amacıyla tasarlanmış bir platformdur. Cloudflare, kullanıcıların web sitelerine erişirken trafiği optimize ederek, içerikleri sunuculardan daha yakın noktalara taşıyarak ve güvenlik önlemleri uygulayarak daha iyi bir deneyim sunmayı amaçlar.*  

C:\Users\SSB>curl -I https://www.geeksforgeeks.org/http-headers-x-frame-options/  
HTTP/1.1 200 OK  
Server: nginx  
*Nginx, açık kaynaklı bir web sunucusu yazılımıdır ve yüksek performanslı, ölçeklenebilir ve hızlı bir şekilde çalışan web siteleri oluşturmak için kullanılır. Nginx, istemcilere (kullanıcı tarayıcılarına) web içeriği sunarken, aynı anda birden fazla isteği ele alabilir ve trafiği etkili bir şekilde yönetebilir.*  
Content-Type: text/html; charset=UTF-8  
X-Frame-Options: DENY  
Strict-Transport-Security: max-age=31536000; includeSubdomains  
Cache-Control: max-age=6800  
Date: Fri, 04 Aug 2023 09:56:36 GMT  
Connection: keep-alive  
Server-Timing: ak_p; desc="1691142996060_3283072311_314087296_256_4333_18_-_-";dur=1  

C:\Users\SSB>curl -I https://www.cloudflare.com/learning/cdn/glossary/reverse-proxy/  
HTTP/1.1 403 Forbidden  
*HTTP/1.1 403 Forbidden ifadesi, bir web sunucusunun istemcinin (genellikle tarayıcının) isteğini reddettiğini belirten bir HTTP durum kodudur. Bu durum kodu, sunucunun istemciye, istenen kaynağa erişim izninin olmadığını ve isteğin reddedildiğini bildirir.*  
Date: Fri, 04 Aug 2023 10:00:57 GMT  
Content-Type: text/html; charset=UTF-8  
Connection: close  
Cross-Origin-Embedder-Policy: require-corp  
Cross-Origin-Opener-Policy: same-origin  
Cross-Origin-Resource-Policy: same-origin  
Origin-Agent-Cluster: ?1  
Permissions-Policy: accelerometer=(),autoplay=(),camera=(),clipboard-read=(),clipboard-write=(),geolocation=(),gyroscope=(),hid=(),interest-cohort=(),magnetometer=(),microphone=(),payment=(),publickey-credentials-get=(),screen-wake-lock=(),serial=(),sync-xhr=(),usb=()  
Referrer-Policy: same-origin  
X-Frame-Options: SAMEORIGIN  
cf-mitigated: challenge  
Cache-Control: private, max-age=0, no-store, no-cache, must-revalidate, post-check=0, pre-check=0  
Expires: Thu, 01 Jan 1970 00:00:01 GMT  
Set-Cookie: __cf_bm=oEMTsyn8N56t4IPMuf0D5LJNDwBznFa3qySbijuce5Q-1691143257-0-AbSIGHHjqMCVSXsy4XHk84fXw3mP+GAdhqeBJDKlVHo3Y9xv/ISg4WM1b6UDwUAVXUZYimHCOZwjt73h3ew3UF8LBe1RuSxPrfdS1NNqmXW0; path=/; expires=Fri, 04-Aug-23 10:30:57 GMT; domain=.www.cloudflare.com; HttpOnly; Secure; SameSite=None  
Report-To: {"endpoints":[{"url":"https:\/\/a.nel.cloudflare.com\/report\/v3? s=kjyrug9xEsohxpKTGuSU3DCVpUGBOFO8w89FqliZAc5%2FVyJZU10cSBtJOH95zh5Z7024OJsq4CETektFXkwLbLpIxwEa1vYGyOh%2Bq7HhgMbsbBZ4glWCuQq2tp52As2GiNL44Q%3D%3D"}],"group":"cf-nel","max_age":604800}  
NEL: {"success_fraction":0,"report_to":"cf-nel","max_age":604800}  
Server: cloudflare  
CF-RAY: 7f15f4cf393b0564-OTP  
alt-svc: h3=":443"; ma=86400  

C:\Users\SSB>curl -I https://www.youtube.com/watch?v=KlzSBk7VMss&ab_channel=HackerSploit  
HTTP/1.1 200 OK  
Content-Type: text/html; charset=utf-8  
X-Content-Type-Options: nosniff  
Cache-Control: no-cache, no-store, max-age=0, must-revalidate  
Pragma: no-cache  
Expires: Mon, 01 Jan 1990 00:00:00 GMT  
Date: Fri, 04 Aug 2023 10:02:02 GMT  
Content-Length: 836214  
X-Frame-Options: SAMEORIGIN  
Strict-Transport-Security: max-age=31536000  
Report-To: {"group":"youtube_main","max_age":2592000,"endpoints":[{"url":"https://csp.withgoogle.com/csp/report-to/youtube_main"}]}  
Cross-Origin-Opener-Policy-Report-Only: same-origin-allow-popups; report-to="youtube_main"  
Permissions-Policy: ch-ua-arch=*, ch-ua-bitness=*, ch-ua-full-version=*, ch-ua-full-version-list=*, ch-ua-model=*, ch-ua-wow64=*, ch-ua-form-factor=*, ch-ua-platform=*, ch-ua-platform-version=*  
Origin-Trial: AvC9UlR6RDk2crliDsFl66RWLnTbHrDbp+DiY6AYz/PNQ4G4tdUTjrHYr2sghbkhGQAVxb7jaPTHpEVBz0uzQwkAAAB4eyJvcmlnaW4iOiJodHRwczovL3lvdXR1YmUuY29tOjQ0MyIsImZlYXR1cmUiOiJXZWJWaWV3WFJlcXVlc3RlZFdpdGhEZXByZWNhdGlvbiIsImV4cGlyeSI6MTcxOTUzMjc5OSwiaXNTdWJkb21haW4iOnRydWV9
P3P: CP="This is not a P3P policy! See http://support.google.com/accounts/answer/151657?hl=tr for more info."  
Server: ESF ???  
Server: ESF ifadesi, bir web sitesinin sunucu yanıt başlığında bulunan bir bilgidir. Ancak, "ESF" terimi genelde yaygın bir sunucu yazılımı veya hizmetini tanımlamak için kullanılan bir terim değildir. Bu nedenle, kesin bir cevap vermek zor olabilir çünkü "ESF" terimi, belirli bir sunucu yazılımını ifade etmek yerine, web sitesinin arkasındaki altyapıya veya kullanılan özel bir sistem veya kısaltmaya işaret ediyor olabilir.  
X-XSS-Protection: 0  
Set-Cookie: GPS=1; Domain=.youtube.com; Expires=Fri, 04-Aug-2023 10:32:02 GMT; Path=/; Secure; HttpOnly  
Set-Cookie: YSC=FrVX0TP0TA0; Domain=.youtube.com; Path=/; Secure; HttpOnly; SameSite=none  
Set-Cookie: VISITOR_INFO1_LIVE=uDhXpQz7ja0; Domain=.youtube.com; Expires=Wed, 31-Jan-2024 10:02:02 GMT; Path=/; Secure; HttpOnly; SameSite=none  
Alt-Svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000  
'ab_channel' is not recognized as an internal or external command,  
operable program or batch file.  

C:\Users\SSB>curl -I https://www.ionos.com/digitalguide/server/tools/netcat/  
HTTP/1.1 200 OK  
Date: Fri, 04 Aug 2023 10:03:47 GMT  
Content-Type: text/html; charset=utf-8  
Content-Length: 134771  
Connection: keep-alive  
Keep-Alive: timeout=15  
Server: Apache  
*Apache HTTP Sunucusu, en popüler ve yaygın olarak kullanılan web sunucu yazılımlarından biridir. İnternet üzerindeki birçok web sitesi ve hizmet, Apache'i altyapılarında kullanır. Apache, istemcilere (kullanıcı tarayıcılarına) web içeriği sunmanın yanı sıra, çoklu bağlantıları yönetme, dinamik içeriği işleme, güvenlik önlemleri uygulama gibi bir dizi görevi yerine getirir.*  
Strict-Transport-Security: max-age=31536000  
Strict-Transport-Security: max-age=31536000  
Last-Modified: Wed, 02 Aug 2023 11:38:42 GMT  
Accept-Ranges: bytes  
Cache-Control: max-age=0  
Expires: Fri, 04 Aug 2023 10:03:47 GMT  
Vary: Accept-Encoding  
X-UA-Compatible: IE=edge  
X-Content-Type-Options: nosniff  
Content-Language: en  
X-SFC-Tags: menuId_3, menuId_4, menuId_5, menuId_7, menuId_8, menuId_13, menuId_23113, menuId_23119, menuId_23120, menuId_23114, menuId_23123, menuId_23124, menuId_23115, menuId_23121, menuId_23116, menuId_23125, menuId_29, menuId_3775, pageId_2722  
Via: 1.1 www.ionos.com  
X-Cache-Status: MISS  

C:\Users\SSB>curl -I https://www.solvusoft.com/tr/errors/tarayici-durum-kodlari/microsoft-corporation/windows-operating-system/http-error-405-method-not-allowed/  
HTTP/1.1 200 OK  
Server: SSWS???  
Content-Type: text/html; charset=UTF-8  
ZPC: HIT  
Date: Fri, 04 Aug 2023 10:05:37 GMT  
Connection: keep-alive  

C:\Users\SSB>curl -I https://www.btk.gov.tr/  
HTTP/1.1 200 OK  
Date: Fri, 04 Aug 2023 10:10:01 GMT  
Content-Type: text/html; charset=utf-8  
Content-Length: 526608  
Connection: keep-alive  
Vary: Accept-Encoding  
ETag: "80910-PspEI7MQdEUYz8P7CGpbIjoTosY"  
X-Content-Type-Options: nosniff  
X-XSS-Protection: 1; mode=block  
X-Frame-Options: deny  
Strict-Transport-Security: max-age=16070400  
Referrer-Policy: no-referrer  
Set-Cookie: TS012038c6=01e3f3f97d0782bb1b5aa8b304d8f7f5b31aec7defd875120050c391a86a1e07edfa24ee981cb05287f0abf2b65efba18ab914c627;   Path=/; Domain=.www.btk.gov.tr; Secure; HTTPOnly  
BTK’nin server’I yok! 

C:\Users\SSB>curl -I https://tr.wikipedia.org/wiki/Bilgi_Teknolojileri_ve_%C4%B0leti%C5%9Fim_Kurumu  
HTTP/1.1 200 OK  
date: Fri, 04 Aug 2023 00:34:02 GMT  
vary: Accept-Encoding,Cookie,Authorization  
server: ATS/9.1.4  
*ATS, Apache Traffic Server'ın (ATS) kısaltmasıdır ve bir açık kaynaklı içerik dağıtım ağı (CDN) ve caching (önbellekleme) çözümüdür. Istemcilere daha hızlı ve daha düşük gecikmeli içerik sunmak amacıyla kullanılan bir yazılımdır. Özellikle büyük ölçekli web siteleri ve hizmetleri için performans artırıcı bir rol oynar. ATS, içerik dağıtımı, önbellekleme, yük dengeleme, hızlandırma ve güvenlik gibi işlevleri yerine getirebilir."ATS/9.1.4" ifadesi, web sitesinin Apache Traffic Server'ın 9.1.4 sürümünü kullanarak hizmet verdiğini gösterir. Bu sürüm, belirli bir zaman diliminde ATS yazılımının o sürümüne ait olan özellikleri, düzeltmeleri ve geliştirmeleri içerir.*
.x-content-type-options: nosniff  
content-language: tr  
last-modified: Wed, 02 Aug 2023 19:20:16 GMT  
content-type: text/html; charset=UTF-8  
age: 34691  
x-cache: cp6009 miss, cp6014 hit/3  
x-cache-status: hit-front  
server-timing: cache;desc="hit-front", host;desc="cp6014"  
strict-transport-security: max-age=106384710; includeSubDomains; preload  
report-to: { "group": "wm_nel", "max_age": 604800, "endpoints": [{ "url": "https://intake-logging.wikimedia.org/v1/events?stream=w3c.reportingapi.network_error&schema_uri=/w3c/reportingapi/network_error/1.0.0" }] }  
nel: { "report_to": "wm_nel", "max_age": 604800, "failure_fraction": 0.05, "success_fraction": 0.0}  
set-cookie: WMF-Last-Access=04-Aug-2023;Path=/;HttpOnly;secure;Expires=Tue, 05 Sep 2023 00:00:00 GMT  
set-cookie: WMF-Last-Access-Global=04-Aug-2023;Path=/;Domain=.wikipedia.org;HttpOnly;secure;Expires=Tue, 05 Sep 2023 00:00:00 GMT  
set-cookie: WMF-DP=95e;Path=/;HttpOnly;secure;Expires=Fri, 04 Aug 2023 00:00:00 GMT  
x-client-ip: 92.45.88.18  
cache-control: private, s-maxage=0, max-age=0, must-revalidate  
set-cookie: GeoIP=TR:06:Ankara:39.96:32.79:v4; Path=/; secure; Domain=.wikipedia.org  
set-cookie: NetworkProbeLimit=0.001;Path=/;Secure;Max-Age=3600  
accept-ranges: bytes  
content-length: 81945  

C:\Users\SSB>curl -I https://www.tbmm.gov.tr/  
curl: (56) Send failure: Connection was reset 

C:\Users\SSB>curl -I https://www.aile.gov.tr/  
HTTP/1.1 302 Found  
*HTTP/1.1 302 Found, bir HTTP yanıt durum kodudur ve bir tarayıcının veya istemcinin bir yönlendirme (redirection) durumu ile karşılaştığını belirtir. Bu durum kodu, sunucunun, istemciyi talep ettiği kaynağın başka bir yerde bulunduğu bir yere yönlendirdiğini ifade eder.*  
Cache-Control: private  
Content-Length: 159  
Content-Type: text/html; charset=utf-8  
Location: /ErrorPages/tr-TR/400.html?aspxerrorpath=/  
Date: Fri, 04 Aug 2023 10:28:39 GMT  
Set-Cookie: BIGipServerAile_WebSitesi_Pool_80=677188780.20480.0000; path=/; Httponly; Secure  
Set-Cookie: TS01d8a40f=01b15b2fcc03daea7ce41b4b17395979eb202b546a7347134299d093e596e101a886d6266d2e222fad8c08aeaaf5cb55a41a33ad0b4d1b5d6e92d6b9ed3007294c15deb1b1; Path=/; Domain=.www.aile.gov.tr  

C:\Users\SSB>curl -I https://www.csgb.gov.tr/  
HTTP/1.1 500 Internal Server Error  
*500 Internal Server Error durum kodu, genellikle sunucu tarafinda bir konfigurasyon hatasi, veritabani sorunu , yazilim hatalari, hafiza sinirlarinin asilmasi gibi icsel sorunlarla iliskilendirilir.Sunucu tarafinda meydana gelen bu hatalar nedeniyle istemciye beklenmeyen bir yanit verilir ve genellikle kullaniciya web sitesinin normal sekilde calisamadigini gosterir.*  
Cache-Control: private  
Content-Length: 75  
Content-Type: text/html  
X-Frame-Options: sameorigin  
Date: Fri, 04 Aug 2023 10:29:17 GMT  

C:\Users\SSB>curl -I https://www.mfa.gov.tr/default.tr.mfa  (disisleri bakanligi)
HTTP/1.1 404 Not Found  
*404 Not Found bir HTTP yanit durum kodudur ve istemcinin talep ettigi kaynagin sunucu uzerinde bulunmadiini belirtir. Istemcinin istedigi URL veya kaynagin sunucu tarafinda mevcut olmadigini ifade eder.*  
content-length: 1245  
content-type: text/html  
date: Fri, 04 Aug 2023 10:31:31 GMT  
set-cookie: TS016fdcf6=0102bb402d816ed00dc22dd78f8412fd70403975ef65cf03ffab0c408811c14d6dc903939cbeb1803dc2978a7973cd18ae65353eba; Path=/; Domain=.www.mfa.gov.tr  

C:\Users\SSB>curl -I http://www.ktb.gov.tr/  
HTTP/1.0 301 Moved Permanently  
*HTTP/1.0 301 Moved Permanently, bir HTTP yanıt durum kodudur ve bir web sitesinin veya kaynağının kalıcı olarak başka bir yere taşındığını belirtir. Bu durum kodu, istemcinin (tarayıcının veya istemcinin) talep ettiği kaynağın artık geçerli URL'de bulunmadığını, kalıcı olarak taşındığını ve gelecekte bu yeni URL'yi kullanması gerektiğini ifade eder. Bu durum kodu, tarayıcıların ve diğer istemcilerin otomatik olarak yeni URL'ye yönlendirilmesini sağlar. Kullanıcı, tarayıcı adres çubuğuna eski URL'yi girdiğinde veya eski bir bağlantıyı tıkladığında, tarayıcı otomatik olarak yeni URL'ye yönlendirir.*  
Location: https://www.ktb.gov.tr/  
Server: BigIP  
*Bu ifade, web sitesinin F5 BIG-IP adlı bir ürün veya teknolojiyi kullanarak hizmet verdiğini gösterir. F5 BIG-IP, bir uygulama teslim kontrol cihazıdır. Bu cihaz, ağ trafiğini yönlendirme, yük dengeleme, hızlandırma, güvenlik, oturum yönetimi ve diğer uygulama katmanı işlevlerini yerine getirmek için kullanılır. BIG-IP, büyük ölçekli web siteleri, uygulama sunucuları, veritabanları ve diğer altyapılar için performansı artırmak, yükü denglemek ve güvenliği sağlamak amacıyla kullanılır.*  
Connection: Keep-Alive  
Content-Length: 0  

C:\Users\SSB>curl -I https://www.meb.gov.tr/  
HTTP/1.1 200 OK  
Content-Length: 0  
Content-Type: text/html; charset=UTF-8  
Server: Microsoft-IIS/10.0  
*Bir web sitesinin sunucu yanıt başlığında bulunan bir bilgidir. Bu ifade, web sitesinin Microsoft Internet Information Services (IIS) adlı bir web sunucusu yazılımını ve belirli bir sürümünü kullanarak hizmet verdiğini gösterir. IIS, Microsoft tarafından geliştirilen ve Windows işletim sistemlerinde çalışan bir web sunucusu yazılımıdır. IIS, web sayfalarını ve diğer içerikleri istemcilere (kullanıcı tarayıcılarına) sunmak için kullanılır. Aynı zamanda ASP.NET gibi Microsoft'un web tabanlı teknolojilerini desteklemek için kullanılır.* 
X-Powered-By: ASP.NET  
Date: Fri, 04 Aug 2023 10:40:22 GMT  

C:\Users\SSB>curl -I https://www.msb.gov.tr/  
HTTP/1.1 403 Forbidden  
Date: Fri, 04 Aug 2023 10:56:28 GMT  
Content-Type: text/html  
Content-Length: 103801  
Connection: keep-alive  
Server: Harpp-foton ???  

##PYTHON ILE REQUEST GONDERME  
C:\Users\SSB>python  
Python 3.9.12 (main, Apr  4 2022, 05:22:27) [MSC v.1916 64 bit (AMD64)] :: Anaconda, Inc. on win32  
>>> import requestes  
>>> url = 'https://eoawsh0d2xvhx5o.m.pipedream.net' (bize verilen rastgele bir URL adresi)  
>>> requests.get(url) (url’e atayip request ile cagirdik)  
<Response [200]> (basarili döndü)  
>>> type(requests.get(url)) =tipini verir.  
<class 'requests.models.Response'>  
>>> r= requests.get(url) (r’ye atadik bu sefer)  
>>> r.status_code (durum kodunu öğrenmek istiyoruz.)  
200 (basarili dondu)  
>>> r.ok  
True (basarili dondu)  
>>> r.url (url adresini öğrenmek istedik)  
'https://eoawsh0d2xvhx5o.m.pipedream.net/'  


>>> url2 = 'https://www.pcichecklist.com'  
>>> requests.get(url2)  
<Response [403]>  
>>> url3 = 'https://gateway.onlayer.com/trn/v2/dashboard/'  
>>> requests.get(url3)  
<Response [401]> (Unautorizhed=siteye erişmek için yetkimiz yok)  
Terminalde curl ile istek attigimda 405 uyarisi vermişti ama python ile istek attigimda 401 uyarisi verdi.  
>>> requests.put(url3)   
<Response [405]>  
>>> requests.post(url3)  
<Response [405]>  

>>> r.encoding  
'utf-8'  
>>> r.headers  
{'Date': 'Fri, 04 Aug 2023 12:01:58 GMT', 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': '408', 'Connection': 'keep-alive', 'X-Powered-By': 'Express', 'Access-Control-Allow-Origin': '*'}  
>>> r.url  
'https://eoawsh0d2xvhx5o.m.pipedream.net/'  
>>> r.text  *(Sitenin HTML içeriğini döndürür.)*
'{"about":"Pipedream is the fastest way to connects APIs. Build and run workflows with code-level control when you need it — and no code when you  don\'t.","event_id":"2TWEcqO4E3S8KEnD3uWtiaxf5UZ","workflow_id":"p_xMCPaaZ","owner_id":"o_JvIqzoE","deployment_id":"d_84semY8Y","timestamp":"2023-08-04T12:01:58.332Z","inspect":"https://pipedream.com/@/p_xMCPaaZ","quickstart":"https://pipedream.com/quickstart/"}'   
>>> r.elapsed  *(gecen zamani doner.)*
datetime.timedelta(seconds=1, microseconds=245010)  

## 405 durum kodu hatasi alan yanitlarin bir dosyaya yazilmasi
import requests  

def main():  
    url = ["'https://gateway.onlayer.com/trn/v2/dashboard/"]  # İstek atmak istediğiniz URL'leri buraya ekleyin  
    output_file = "405_responses.txt"  # 405 durum kodlu yanıtların yazılacağı dosya  

    with open(output_file, "w") as file:  
        for url in urls:  
            response = requests.get(url)  # İstek gönder  
            if response.status_code == 405:  # Durum kodu 405 ise dosyaya yaz  
                file.write(f"URL: {url}\nStatus Code: {response.status_code}\n\n")  

if __name__ == "__main__":  
    main()  

    ###Google dork 
    google dork ile arama yapmayi ogrendim.

### REFERENCES:<br/>  
https://www.hosting.com.tr/bilgi-bankasi/405-durum-kodu-method-not-allowed/#:~:text=405%20Durum%20Kodu%20(%20Method%20Not%20Allowed%20)&text=G%C3%B6nderilen%20sorgu%20t%C3%BCr%C3%BCn%C3%BC%20HTTP'nin,POST%20olarak%20de%C4%9Fi%C5%9Ftirip%20tekrar%20denemelisiniz.<br/>
https://www.sinanerdinc.com/python-requests-modulu <br/>
https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy <br/>
https://developers.cloudflare.com/fundamentals/get-started/concepts/how-cloudflare-works/#:~:text=Fundamentally%2C%20Cloudflare%20is%20a%20large,link%20for%20your%20web%20traffic. <br/>
https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control <br/>
https://www.geeksforgeeks.org/http-headers-x-frame-options/ <br/>
https://www.w3.org/TR/referrer-policy/#referrer-policy-same-origin <br/>
https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy/accelerometer <br/>
https://web.dev/origin-agent-cluster/ <br/>
https://developer.mozilla.org/en-US/docs/Web/HTTP/Cross-Origin_Resource_Policy  <br/>
https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy <br/>
https://http.dev/cross-origin-embedder-policy <br/>
https://learn.microsoft.com/tr-tr/aspnet/web-api/overview/testing-and-debugging/troubleshooting-http-405-errors-after-publishing-web-api-applications <br/>
https://elitemedya.com/405-method-not-allowed-hatasi-nasil-duzeltilir/ <br/>
https://reqbin.com/req/84xntxmp/close-connection-example#:~:text=The%20%22Connection%3A%20close%22%20HTTP,after%20the%20request%20or%20not. <br/>
https://www.sinanerdinc.com/python-requests-modulu <br/>
https://www.youtube.com/watch?v=3yLrXiZEsBg&list=PLLftmqJYInB1rUu9f6q-JWJMHLZ6C22qp&index=25&ab_channel=SinanErdin%C3%A7 <br/>
https://www.youtube.com/watch?v=tb8gHvYlCFs&ab_channel=CoreySchafer <br/>
https://www.sadikturan.com/python-gelistirme-ortami/python-icin-komut-satiri-programinin-kullanimi/1367 <br/>
https://pipedream.com/@ebrarkesici11/requestbin-p_xMCPaaZ/build *(rastgele web sitesi adresi aldigimiz site)* <br/>
https://pipedream.com/@ebrarkesici11/requestbin-p_xMCPaaZ/build <br/>
https://pwnlab.me/tr-google-dorks-ve-google-hacking/  <br/>
https://www.google.com/search?q=intitle%3AHTTP%2F1.1+405+Not+Allowed&rlz=1C1GCEU_trTR921TR921&biw=1366&bih=619&ei=jOPMZNSMAvq9xc8P5qSSsAU&ved=0ahUKEwjUgt7Y9cKAAxX6XvEDHWaSBFYQ4dUDCA8&uact=5&oq=intitle%3AHTTP%2F1.1+405+Not+Allowed&gs_lp=Egxnd3Mtd2l6LXNlcnAiIGludGl0bGU6SFRUUC8xLjEgNDA1IE5vdCBBbGxvd2VkSKsnUM0FWNYhcAF4AJABAZgBmQSgAbwHqgEJMC4xLjEuNS0xuAEDyAEA-AEB4gMEGAEgQYgGAQ&sclient=gws-wiz-serp  <br/>
