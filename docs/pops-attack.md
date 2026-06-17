# pops-attacks.md: Các nhóm tấn công DNS Cache Poisoning trong POPS

## 1. Bối cảnh chung

DNS Cache Poisoning là nhóm tấn công trong đó attacker tìm cách đưa một bản ghi DNS sai lệch vào bộ nhớ đệm của resolver. Nếu thành công, các truy vấn sau này của người dùng đến một domain hợp lệ có thể bị trả về địa chỉ IP do attacker kiểm soát. Trong mô hình phổ biến, attacker không cần kiểm soát resolver hay authoritative server, mà cố gắng gửi các DNS response giả mạo đến resolver trong lúc resolver đang chờ response thật từ authoritative server.

Một DNS response chỉ được resolver chấp nhận khi nó khớp với các thông tin của truy vấn đang chờ, bao gồm domain name, TXID, cổng tương ứng và địa chỉ IP của authoritative name server. Vì các giá trị như TXID và source port thường được sinh ngẫu nhiên, attacker phải đoán đúng các giá trị này hoặc tìm cách né tránh quá trình kiểm tra đó. Đây chính là nền tảng của các nhóm tấn công được POPS phân loại và xử lý.

Theo bài báo POPS, phạm vi nghiên cứu tập trung vào các tấn công **off-path network-based DNS cache poisoning**, tức attacker nằm ngoài đường truyền trực tiếp nhưng vẫn có thể gửi các gói DNS response giả mạo đến resolver. POPS chia các tấn công trong phạm vi này thành bốn nhóm chính: **S**, **SFrag**, **BFrag** và **SOoB**.

---

## 2. Nhóm S: Statistical poisoning

Nhóm **S** là nhóm tấn công thống kê dựa trên việc gửi nhiều DNS response giả mạo để đoán đúng các tham số mà resolver đang chờ. Đây là nhóm tấn công nền tảng của nhiều kỹ thuật DNS Cache Poisoning kinh điển, bao gồm TXID brute-force, source port brute-force và Kaminsky-style attack.

Trong một truy vấn DNS thông thường, resolver gửi query đến authoritative server và chờ response hợp lệ. Attacker lợi dụng khoảng thời gian chờ này để gửi hàng loạt forged responses giả mạo địa chỉ nguồn của authoritative server. Mỗi response thử một giá trị TXID hoặc source port khác nhau. Nếu một response giả có đúng domain, đúng TXID, đúng cổng và đến trước response thật, resolver có thể chấp nhận response đó và lưu bản ghi độc hại vào cache.

Nếu attacker không biết cả TXID lẫn source port, không gian đoán là khoảng 32 bit. Khi đó xác suất đoán trúng một lần là rất thấp. Tuy nhiên, trong nhiều biến thể tấn công, attacker có thể biết trước hoặc làm giảm entropy của một trong hai giá trị này. Khi chỉ còn phải đoán TXID hoặc source port 16 bit, attacker có thể gửi hàng chục nghìn response giả mạo để tăng xác suất thành công.

Kaminsky-style attack cũng thuộc nhóm S, nhưng thay vì chỉ tấn công trực tiếp một record đã biết, attacker tạo nhiều truy vấn đến các subdomain ngẫu nhiên của domain mục tiêu, ví dụ `a1.victim.test`, `a2.victim.test`, `a3.victim.test`. Với mỗi truy vấn như vậy, attacker gửi nhiều forged responses chứa bản ghi NS/glue độc hại, nhằm làm resolver cache sai thông tin về authoritative name server của cả zone. Trong bảng tổng hợp của bài báo, Kaminsky được xếp vào nhóm S và được ánh xạ với Rule 1 của POPS.

Dấu hiệu quan trọng của nhóm S là **số lượng lớn response gần giống nhau xuất hiện trong thời gian ngắn**. Các response này thường chỉ khác nhau ở TXID hoặc cổng. Vì vậy, POPS sử dụng **Rule 1 (Rl1)** để phát hiện hành vi đoán hàng loạt TXID/port.

---

## 3. Nhóm SFrag: Statistical fragmentation poisoning

Nhóm **SFrag** khai thác cơ chế phân mảnh IP thay vì brute-force trực tiếp TXID hoặc source port trong DNS header. Ý tưởng chính của nhóm này là attacker không cần tạo một DNS response hoàn chỉnh. Thay vào đó, attacker gửi một fragment độc hại và tìm cách để resolver ghép nó với fragment hợp lệ từ authoritative server.

Trong IP fragmentation, chỉ fragment đầu tiên chứa đầy đủ UDP header và DNS header. Các fragment sau không có đủ thông tin TXID hoặc source port, nhưng vẫn có thể chứa một phần dữ liệu DNS. Attacker có thể gửi trước nhiều “second fragments” chứa nội dung độc hại, sau đó kích hoạt một truy vấn DNS khiến authoritative server trả về response đủ lớn để bị phân mảnh. Nếu một fragment độc hại của attacker có IPID trùng với fragment hợp lệ, resolver hoặc hệ thống mạng có thể ghép chúng lại thành một DNS response bị đầu độc.

Với SFrag, attacker không biết trước IPID của response hợp lệ nên phải gửi nhiều fragment giả với các giá trị IPID khác nhau. Vì IPID thường là trường 16 bit, attacker có thể phải thử một lượng lớn giá trị để tăng xác suất trùng khớp. Bài báo mô tả SFrag là nhóm tấn công dùng second fragment làm vector chính, và POPS ánh xạ nhóm này với Rule 2.

Điểm nguy hiểm của SFrag nằm ở chỗ các fragment sau không chứa đầy đủ thông tin DNS để resolver kiểm tra như một response bình thường. Do đó, nếu hệ thống chỉ kiểm tra DNS header ở fragment đầu tiên mà bỏ qua rủi ro từ fragment sau, attacker có thể chèn dữ liệu độc hại vào quá trình tái lắp ráp.

---

## 4. Nhóm BFrag: Bullseye fragmentation poisoning

**BFrag** có cơ chế gần giống SFrag, nhưng attacker ở trạng thái “bullseye”, tức đã biết hoặc dự đoán được chính xác IPID cần dùng. Vì vậy, thay vì phải flood hàng nghìn hoặc hàng chục nghìn fragment với nhiều IPID khác nhau, attacker chỉ cần gửi một fragment độc hại có IPID trùng với response hợp lệ.

Điểm khác biệt chính giữa SFrag và BFrag nằm ở mức độ thông tin mà attacker có được. Với SFrag, attacker phải đoán IPID bằng phương pháp thống kê. Với BFrag, attacker đã có IPID mục tiêu, nên số lượng packet cần gửi có thể giảm xuống rất thấp. Trong bảng các cuộc tấn công lịch sử của bài báo, BFrag được mô tả là nhóm fragmentation attack có thể chỉ cần một packet attacker tạo ra để thành công, và cũng được ánh xạ với Rule 2 của POPS.

Từ góc nhìn phòng thủ, cả SFrag và BFrag đều có cùng vấn đề cốt lõi: attacker lợi dụng quá trình tái lắp ráp IP fragment để đưa dữ liệu độc hại vào DNS response. Vì vậy, POPS xử lý hai nhóm này bằng cùng một rule phát hiện fragmentation.

---

## 5. Nhóm SOoB: Statistical Out-of-Bailiwick poisoning

Nhóm **SOoB** khai thác việc resolver xử lý không chặt chẽ các bản ghi nằm ngoài phạm vi thẩm quyền của name server được truy vấn. Trong DNS, một authoritative server chỉ nên cung cấp thông tin thuộc zone mà nó quản lý. Nếu response cho `example.net` lại chứa bản ghi liên quan đến `bank.com`, resolver không nên tin tưởng và cache bản ghi đó.

Trong tấn công out-of-bailiwick, attacker gửi một response giả mạo có kèm thêm các bản ghi nằm ngoài phạm vi hợp lệ. Các bản ghi này có thể nằm trong phần Answer, Authority hoặc Additional của DNS response. Nếu resolver không kiểm tra nghiêm ngặt nguyên tắc bailiwick, nó có thể lưu các bản ghi ngoài phạm vi này vào cache. Khi đó, các truy vấn về sau đến domain bị chèn có thể bị chuyển hướng đến địa chỉ độc hại.

Ví dụ, resolver đang xử lý một truy vấn liên quan đến `example.net`, nhưng response lại chứa thêm bản ghi cho `bank.com` hoặc một delegation trỏ domain khác về name server của attacker. Nếu resolver cache bản ghi này, attacker có thể ảnh hưởng đến những truy vấn không liên quan đến domain ban đầu.

Khác với nhóm S, SOoB không nhất thiết tạo ra dấu hiệu “nhiều response brute-force” rõ ràng. Dấu hiệu quan trọng hơn nằm ở **nội dung response vi phạm phạm vi thẩm quyền**. Vì vậy, POPS dùng **Rule 3 (Rl3)** để kiểm tra các bản ghi trong DNS response có tuân thủ nguyên tắc bailiwick hay không. Trong bài báo, SOoB là nhóm được ánh xạ với Rule 3.

---

## 6. Các tấn công nằm ngoài phạm vi POPS

POPS không cố gắng giải quyết mọi hình thức tấn công DNS. Mô hình đe dọa của hệ thống tập trung vào attacker off-path, gửi DNS response giả mạo qua mạng và cố gắng đầu độc cache của resolver. Vì vậy, một số nhóm tấn công không nằm trong phạm vi chính của POPS.

Thứ nhất, các tấn công **Man-in-the-Middle** hoặc **BGP hijacking** không được xem là trọng tâm. Trong các kịch bản này, attacker có khả năng can thiệp trực tiếp vào đường truyền hoặc định tuyến, nên không còn phải phụ thuộc vào việc đoán TXID, source port hay IPID như attacker off-path.

Thứ hai, POPS không xét trường hợp attacker **chiếm quyền trực tiếp resolver**. Nếu resolver đã bị compromise, bài toán không còn là phát hiện response giả mạo từ bên ngoài, mà chuyển thành vấn đề bảo vệ hệ thống, phân quyền và khôi phục máy chủ.

Thứ ba, các tấn công nhắm vào **DNS client hoặc forwarder đơn lẻ** cũng không phải trọng tâm chính. Bài báo có nhắc rằng một số điều chỉnh có thể giúp POPS bảo vệ client trong vài kịch bản nhất định, nhưng phạm vi chính vẫn là resolver trong quá trình phân giải DNS.

Ngoài ra, POPS cũng không tập trung vào các lỗi xử lý sai cú pháp DNS response hoặc các kỹ thuật **TCP session hijacking**. Với TCP hijacking, attacker phải đoán hoặc suy ra sequence number của phiên TCP, điều này thuộc một mô hình tấn công khác và thường cần các năng lực mạnh hơn như malware trên host, middlebox bị compromise hoặc side-channel.

---

## 7. Liên hệ giữa nhóm tấn công và rule phát hiện

Các nhóm tấn công được POPS phân loại tương ứng trực tiếp với ba rule trong Detection Module.

| Nhóm tấn công | Đặc điểm chính                                          | Rule phát hiện |
| ------------- | ------------------------------------------------------- | -------------- |
| S             | Gửi nhiều forged DNS responses để đoán TXID/source port | Rl1            |
| SFrag         | Flood second fragments để đoán IPID                     | Rl2            |
| BFrag         | Gửi fragment độc hại khi đã biết IPID                   | Rl2            |
| SOoB          | Chèn record ngoài phạm vi thẩm quyền                    | Rl3            |

Cách phân loại này giúp POPS không cần viết một rule riêng cho từng CVE hoặc từng kỹ thuật cụ thể. Thay vào đó, hệ thống tập trung vào các dấu hiệu nền tảng: brute-force TXID/port, lạm dụng fragmentation và vi phạm bailiwick. Đây cũng là cơ sở để repository này xây dựng các lab mô phỏng tương ứng với từng nhóm tấn công.
