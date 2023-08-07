# HTTP
*curl -I komutuyla https://www.pcichecklist.com adresine istek gonderdik ve response'un sadece header kismini ogrenmek istedik.* <br/>
C:\Users\SSB>curl -I https://www.pcichecklist.com <br/>
HTTP/1.1 403 Forbidden *(403 uyarisi erisime iznimiz olmadiginda aldigimiz hata mesaji)* <br/>
Date: Thu, 03 Aug 2023 15:41:00 GMT <br/>
Content-Type: text/html; charset=UTF-8 *(belgenin karakter kodlamasini belirtmek icin HTTP basliginda bir karakter kumesi parametresi gonderir)* <br/>
Connection: close *(HTTP başlığı sunucuya, istemcinin HTTP işlemini tamamladıktan sonra bağlantıyı kapatmak istediğini bildirir.)* <br/>
Cross-Origin-Embedder-Policy: require-corp *(belirli saldırı türlerinin önlenmesine yardımcı olan, ancak farklı bir kaynaktan gelen kaynakların paylaşılmasından yararlanabilen bir güvenlik önlemidir.)* <br/>
Cross-Origin-Opener-Policy: same-origin *(Tarama bağlamını yalnızca aynı kaynaklı belgelere yalıtır. Kaynaklar arası belgeler aynı tarama bağlamında yüklenmez.)* <br/>
Cross-Origin-Resource-Policy: same-origin *(Yalnızca aynı kaynaktan ( yani şema + ana bilgisayar + bağlantı noktası) gelen istekler kaynağı okuyabilir.)* <br/>
Origin-Agent-Cluster: ?1 *(tarayıcıya, aynı sitedeki kaynaklar arası sayfalar arasında eşzamanlı komut dizisi erişimini engellemesi talimatını veren yeni bir HTTP yanıt başlığıdır.)*(true) <br/>
Permissions-Policy: accelerometer=(),autoplay=(),camera=(),clipboard-read=(),clipboard-write=(),geolocation=(),gyroscope=(),hid=(),interest-cohort=(),magnetometer=(),microphone=(),payment=(),publickey-credentials-get=(),screen-wake-lock=(),serial=(),sync-xhr=(),usb=() <br/>
*(geçerli belgenin arabirim aracılığıyla aygıtın hızlanması hakkında bilgi toplamasına izin verilip verilmediğini kontrol eder)* <br/>
Referrer-Policy: same-origin *(yönlendiren olarak kullanılmak üzere çıkarılan tam bir URL'nin, belirli bir istemciden aynı kaynaklı istekler yapılırken yönlendiren bilgisi olarak gönderildiğini belirtir.)* <br/>
X-Frame-Options: SAMEORIGIN *(siteyi tıklama saldırılarından korumak için kullanılır.Bu yönerge, frame sayfa ile aynı orijine sahipse, sayfanın frame'de işlenmesine izin verir.)* <br/>
cf-mitigated: challenge *(Bir web sitesi Cloudflare tarafından korunduğunda ziyaretçinin IP adresi çevrimiçi olarak şüpheli davranış göstermis olabilir.)* <br/>
Cache-Control: private, max-age=0, no-store, no-cache, must-revalidate, post-check=0, pre-check=0 *(tarayıcılarda ve paylaşılan önbelleklerde, önbelleğe almayı kontrol eden yönergeleri  hem isteklerde hem de yanıtlarda tutar.)* <br/>
Expires: Thu, 01 Jan 1970 00:00:01 GMT *(suresi dolmus demek)* <br/>
Report-To: {"endpoints":[{"url":"https:\/\/a.nel.cloudflare.com\/report\/v3?s=JnTjQzfD7ENnKab9H9AYnB4se4Sev1dXAvixDni0T3a22A9yOiE84EXWg5b3poQPZkBlGQ2vZHlpI1JMOFIhzRhA0TG0i9jQH7FFBZhMkru6Cgf7eo1NHysbZWVZOKIuudZuMOEO"}],"group":"cf-nel","max_age":604800} <br/>
NEL: {"success_fraction":0,"report_to":"cf-nel","max_age":604800} *(Network Error Logging)(NEL, site ziyaretçilerinin Cloudflare'a bağlanmasıyla ilgili sorunları hızlı bir şekilde belirlemek için kullanılan tarayıcı tabanlı bir teknolojidir)* <br/>
Server: cloudflare <br/>
CF-RAY: 7f0fa9900e741c7e-AMS <br/>
alt-svc: h3=":443"; ma=86400 <br/>










## HTTP Header icerisinde gelen 405 Method Not Allowed nedir? <br/>
## 405 Durum Kodu (Method Not Allowed): <br/>
- Gonderilen sorgu turunu HTTP'nin kabul etmedigini belirtir.Bu baglamda sorgu turunuzu GET veya POST olarak degistirip tekrar denemelisiniz. <br/>
Izin verilmeyen bir dosyaya ulasilmaya calisildigi takdirde sunucu bu islemi engeller.ornegin GET'i kullanarak POST ya da PUT icerisinde bulunan sadece okunabilir kaynaklara ulasmaya calismaniz durumunda bu hatayla karsilasabilirsiniz. <br/>






### REFERENCES:
https://www.hosting.com.tr/bilgi-bankasi/405-durum-kodu-method-not-allowed/#:~:text=405%20Durum%20Kodu%20(%20Method%20Not%20Allowed%20)&text=G%C3%B6nderilen%20sorgu%20t%C3%BCr%C3%BCn%C3%BC%20HTTP'nin,POST%20olarak%20de%C4%9Fi%C5%9Ftirip%20tekrar%20denemelisiniz.
