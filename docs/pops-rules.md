# Module Phát hiện (Detection) của hệ thống POPS

## 1. Tổng quan Detection Module

POPS (*POisoning Prevention System*) là một hệ thống được đề xuất nhằm phát hiện và giảm thiểu các cuộc tấn công **DNS Cache Poisoning**. Trong kiến trúc của POPS, hệ thống được chia thành hai phần chính: **Detection Module** và **Mitigation Module**. Phần nội dung này chỉ tập trung mô tả **Detection Module**, tức thành phần chịu trách nhiệm quan sát các gói DNS response và xác định xem chúng có mang dấu hiệu của một cuộc tấn công đầu độc bộ đệm DNS hay không.

Ý tưởng chính của Detection Module là các cuộc tấn công DNS Cache Poisoning tuy có nhiều biến thể khác nhau, nhưng khi quan sát ở mức lưu lượng mạng, chúng thường để lại một số đặc điểm có thể nhận diện. Cụ thể, bài báo POPS phân loại các tấn công thống kê thành ba nhóm lớn: nhóm tấn công phải đoán TXID hoặc cổng nguồn, nhóm tấn công lợi dụng phân mảnh IP, và nhóm tấn công chèn bản ghi nằm ngoài phạm vi thẩm quyền của máy chủ DNS. Tương ứng với ba nhóm này, Detection Module triển khai ba quy tắc phát hiện: **Rℓ1**, **Rℓ2** và **Rℓ3**.

Ba quy tắc này không cố gắng phân tích toàn bộ hành vi của ứng dụng hay phụ thuộc vào chữ ký cố định của từng cuộc tấn công cụ thể. Thay vào đó, chúng tập trung vào các dấu hiệu cốt lõi xuất hiện trong quá trình tấn công. Nhờ vậy, Detection Module có thể bao phủ nhiều biến thể tấn công DNS Cache Poisoning khác nhau, bao gồm cả các kỹ thuật kinh điển như brute-force TXID, brute-force source port, Kaminsky-style attack, fragmentation-based attack và out-of-bailiwick attack.

Trong hệ thống POPS, khi một gói tin hoặc một nhóm gói tin thỏa điều kiện của một trong ba quy tắc, Detection Module sẽ đánh dấu chúng là đáng ngờ. Sau đó, các gói tin này được chuyển sang Mitigation Module để xử lý tiếp. Nói cách khác, Detection Module không trực tiếp quyết định toàn bộ quá trình phòng thủ, mà đóng vai trò như lớp nhận diện ban đầu, giúp hệ thống biết khi nào cần kích hoạt cơ chế giảm thiểu.

---

## 2. Quy tắc Rℓ1: Phát hiện hành vi đoán quá mức TXID hoặc cổng

### 2.1. Mục tiêu của Rℓ1

Quy tắc Rℓ1 được thiết kế để phát hiện nhóm tấn công thống kê, còn được gọi là **Type S**. Đây là nhóm tấn công phổ biến trong DNS Cache Poisoning, trong đó attacker gửi một lượng lớn DNS response giả mạo đến resolver với hy vọng một trong số đó sẽ trùng với thông tin mà resolver đang chờ.

Trong một truy vấn DNS thông thường, resolver chỉ chấp nhận response nếu response đó khớp với các thông tin quan trọng của truy vấn ban đầu, bao gồm domain name, TXID, source port/destination port tương ứng, và địa chỉ IP của authoritative name server. Vì attacker không biết chính xác các giá trị ngẫu nhiên như **Transaction ID (TXID)** hoặc **source port**, attacker buộc phải gửi nhiều response giả mạo với các giá trị khác nhau để brute-force.

Chính hành vi gửi nhiều response gần giống nhau cho cùng một truy vấn là dấu hiệu mà Rℓ1 muốn phát hiện. Thay vì cần biết response nào là đúng hoặc sai, Rℓ1 chỉ cần nhận ra rằng đang có một lượng response bất thường được gửi đến resolver cho cùng một domain trong một khoảng thời gian rất ngắn.

### 2.2. Cách Rℓ1 quan sát lưu lượng DNS

Rℓ1 tập trung vào các DNS response đi về resolver. Với mỗi response, hệ thống trích xuất các thông tin như domain được truy vấn, loại bản ghi, TXID, cổng, địa chỉ nguồn và địa chỉ đích. Sau đó, các response được gom theo cùng một truy vấn DNS hoặc cùng một domain cần theo dõi.

Trong lưu lượng hợp lệ, một truy vấn DNS thường chỉ sinh ra một hoặc một vài response. Ngược lại, trong các cuộc tấn công brute-force, attacker có thể gửi hàng trăm, hàng nghìn hoặc thậm chí hàng chục nghìn response giả mạo cho cùng một truy vấn. Các response này thường giống nhau ở hầu hết các trường, nhưng khác nhau ở TXID hoặc cổng. Ví dụ, trong tấn công brute-force TXID, attacker giữ nguyên domain và cổng đích nhưng thay đổi TXID liên tục. Trong tấn công brute-force port, attacker có thể giữ nguyên TXID nhưng thay đổi cổng đích. Trong Kaminsky-style attack, attacker lặp lại quá trình này trên nhiều subdomain ngẫu nhiên của cùng một domain mục tiêu.

Vì vậy, Rℓ1 không cần phân biệt cụ thể attacker đang đoán TXID hay source port. Từ góc nhìn của Detection Module, cả hai trường hợp đều tạo ra cùng một kiểu bất thường: **nhiều DNS response cho cùng một truy vấn hoặc cùng một domain trong thời gian ngắn, trong đó các response chỉ khác nhau ở một số trường dùng để xác thực truy vấn**.

### 2.3. Cửa sổ thời gian và ngưỡng phát hiện

Để tránh việc đánh dấu nhầm các response hợp lệ, Rℓ1 không chỉ dựa trên số lượng response tuyệt đối, mà theo dõi chúng trong một **cửa sổ thời gian ngắn**. Bài báo sử dụng ví dụ cửa sổ khoảng 1 giây và một ngưỡng hệ thống, chẳng hạn 5 response.

Cách hoạt động có thể hiểu như sau: trong mỗi cửa sổ thời gian `W`, hệ thống đếm số DNS response tương ứng với cùng một domain hoặc cùng một truy vấn. Nếu số lượng response vượt qua ngưỡng `τ`, domain hoặc truy vấn đó được xem là đáng ngờ. Từ thời điểm này trở đi, các response tiếp theo khớp với cùng truy vấn/domain sẽ không còn được xem là lưu lượng bình thường, mà được chuyển sang giai đoạn xử lý tiếp theo của POPS.

Cơ chế này phù hợp với bản chất của tấn công DNS Cache Poisoning dạng thống kê. Attacker phải gửi nhiều response thật nhanh để response giả có cơ hội đến trước response hợp lệ từ authoritative server. Do đó, một cửa sổ thời gian ngắn giúp hệ thống phát hiện được hành vi brute-force trong lúc cuộc tấn công đang diễn ra, thay vì chỉ phát hiện sau khi cache đã bị đầu độc.

### 2.4. Sử dụng Count-Min Sketch trong Rℓ1

Nếu triển khai Rℓ1 bằng cách lưu đầy đủ mọi domain và mọi response trong bộ nhớ, hệ thống có thể gặp vấn đề khi lưu lượng DNS lớn. Một resolver thực tế có thể xử lý rất nhiều truy vấn DNS mỗi giây, trong khi attack traffic có thể tạo ra hàng chục nghìn response giả mạo. Do đó, POPS sử dụng **Count-Min Sketch (CMS)** để ước lượng tần suất xuất hiện của domain một cách nhẹ hơn.

CMS là một cấu trúc dữ liệu xác suất dùng để đếm tần suất phần tử trong luồng dữ liệu lớn. Khi một DNS response đi vào hệ thống, domain name của response được đưa qua nhiều hàm băm. Mỗi hàm băm ánh xạ domain đến một vị trí trong bảng đếm, và bộ đếm tại các vị trí đó được tăng lên. Khi cần ước lượng số lần domain đã xuất hiện, hệ thống lấy giá trị nhỏ nhất trong các bộ đếm tương ứng.

Cách làm này giúp Rℓ1 tiết kiệm bộ nhớ và vẫn đủ nhanh để hoạt động trong môi trường lưu lượng cao. Thay vì lưu toàn bộ danh sách response, hệ thống chỉ duy trì một bảng đếm có kích thước cố định. Khi hết cửa sổ thời gian `W`, bảng CMS được làm sạch để bắt đầu chu kỳ đếm mới. Nhờ đó, Rℓ1 có thể phát hiện các đợt response bất thường theo thời gian thực mà không tạo ra chi phí lưu trữ quá lớn.

### 2.5. Ý nghĩa của Rℓ1 trong các kịch bản tấn công

Rℓ1 là quy tắc quan trọng nhất đối với các tấn công dạng brute-force. Với **TXID brute-force**, attacker gửi nhiều response có cùng domain nhưng thay đổi TXID. Với **source port brute-force**, attacker gửi nhiều response có cùng domain nhưng thay đổi cổng. Với **Kaminsky-style attack**, attacker tạo nhiều truy vấn đến các subdomain không tồn tại của domain mục tiêu, sau đó gửi nhiều response giả mạo chứa bản ghi độc hại nhằm đầu độc cache của resolver.

Mặc dù ba kịch bản này khác nhau về cách tổ chức tấn công, chúng đều có điểm chung là tạo ra số lượng lớn response giả mạo trong thời gian ngắn. Vì vậy, Rℓ1 có thể được dùng làm cơ chế phát hiện chung cho cả ba trường hợp. Đây cũng là lý do trong quá trình xây dựng lab, Rℓ1 thường được dùng để đo khả năng phòng thủ đối với TXID brute-force, port brute-force và Kaminsky-style poisoning.

---

## 3. Quy tắc Rℓ2: Phát hiện tấn công dựa trên phân mảnh

### 3.1. Mục tiêu của Rℓ2

Rℓ2 được thiết kế để phát hiện nhóm tấn công lợi dụng **IP fragmentation**, bao gồm các biến thể như **SFrag** và **BFrag**. Khác với nhóm tấn công brute-force TXID/port, các tấn công phân mảnh không nhất thiết phải đoán trực tiếp TXID hoặc source port trong DNS header. Thay vào đó, attacker khai thác cách hệ thống tái lắp ráp các IP fragment.

Trong DNS, nếu response có kích thước lớn, nó có thể bị phân mảnh ở tầng IP. Gói fragment đầu tiên thường chứa header quan trọng, bao gồm UDP header và DNS header. Các fragment sau không chứa đầy đủ các trường này, nhưng vẫn có thể chứa một phần dữ liệu DNS. Attacker có thể lợi dụng đặc điểm này bằng cách gửi trước một fragment thứ hai độc hại, sau đó chờ resolver nhận fragment đầu tiên hợp lệ từ authoritative server. Nếu hai fragment bị ghép lại với nhau, resolver có thể xử lý một DNS response đã bị chèn dữ liệu độc hại.

Mục tiêu của Rℓ2 là ngăn chặn khả năng resolver tái lắp ráp fragment hợp lệ với fragment giả mạo của attacker.

### 3.2. Cách Rℓ2 nhận diện phân mảnh

Rℓ2 quan sát các trường liên quan đến phân mảnh trong IP header, đặc biệt là giá trị **fragment offset** và cờ **MF (More Fragments)**. Hai trường này cho biết một packet có phải là một phần của chuỗi fragment hay không, và nếu có thì nó nằm ở vị trí nào trong chuỗi.

Nếu packet có `offset = 0` và cờ `MF` được bật, hệ thống hiểu rằng đây là fragment đầu tiên của một DNS response bị phân mảnh. Fragment đầu tiên này được xem là dấu hiệu cần xử lý cẩn thận, vì sự tồn tại của nó cho thấy response DNS không còn là một gói UDP đơn lẻ. Theo thiết kế của POPS, fragment đầu tiên được chuyển sang bước xử lý tiếp theo.

Ngược lại, nếu packet có `offset > 0`, nghĩa là đây là fragment thứ hai hoặc các fragment sau đó. Các fragment này bị loại bỏ ngay trong Detection Module. Lý do là các fragment sau có thể không chứa đủ thông tin DNS để xác thực, nhưng lại có thể chứa dữ liệu độc hại mà attacker muốn ghép vào response hợp lệ. Việc loại bỏ các fragment sau giúp chặn khả năng resolver ghép một fragment độc hại vào DNS response.

### 3.3. Đặc điểm vận hành của Rℓ2

Khác với Rℓ1, Rℓ2 không cần dùng bộ đếm, cửa sổ thời gian hay cấu trúc dữ liệu như Count-Min Sketch. Quy tắc này hoạt động trực tiếp trên từng packet bằng cách kiểm tra hai thông tin có sẵn trong IP header. Vì vậy, chi phí lưu trữ của Rℓ2 gần như không đáng kể.

Điểm mạnh của Rℓ2 là khả năng phản ứng tức thời với các DNS response bị phân mảnh. Chỉ cần phát hiện packet là fragment đầu tiên hoặc fragment sau, hệ thống có thể đưa ra quyết định ngay. Tuy nhiên, chính vì Rℓ2 xử lý dựa trên đặc điểm phân mảnh nên trong triển khai thực tế cần cân nhắc ảnh hưởng đến các DNS response hợp lệ có kích thước lớn. Đây cũng là lý do có thể nghiên cứu thêm các hướng cải tiến Rℓ2 theo hướng chọn lọc hơn, chẳng hạn chỉ áp dụng xử lý mạnh với các fragment thuộc DNS response có dấu hiệu rủi ro hoặc có liên quan đến truy vấn đang được theo dõi.

---

## 4. Quy tắc Rℓ3: Phát hiện bản ghi ngoài phạm vi thẩm quyền

### 4.1. Mục tiêu của Rℓ3

Rℓ3 được dùng để phát hiện nhóm tấn công **Out-of-Bailiwick**, tức các trường hợp DNS response chứa bản ghi không thuộc phạm vi thẩm quyền của máy chủ DNS được truy vấn. Trong DNS, một name server chỉ nên trả lời hoặc cung cấp thông tin liên quan đến vùng tên miền mà nó có thẩm quyền. Nếu một response cho truy vấn thuộc `example.net` lại chứa bản ghi nhằm thay đổi ánh xạ của `bank.com`, resolver không nên tin tưởng và cache thông tin đó.

Các cuộc tấn công Out-of-Bailiwick lợi dụng việc resolver hoặc hệ thống DNS xử lý không chặt chẽ các bản ghi nằm trong phần Answer, Authority hoặc Additional của DNS response. Attacker có thể chèn một bản ghi không liên quan vào response, với mục tiêu làm resolver cache một ánh xạ độc hại cho domain khác. Nếu resolver chấp nhận bản ghi này, attacker có thể điều hướng các truy vấn tương lai đến máy chủ do mình kiểm soát.

### 4.2. Nguyên tắc Bailiwick trong Rℓ3

Rℓ3 dựa trên nguyên tắc **Bailiwick checking**. Khi một DNS response được gửi về resolver, hệ thống kiểm tra xem các bản ghi trong response có thuộc phạm vi hợp lệ so với domain đang được truy vấn và authoritative server tương ứng hay không.

Việc kiểm tra không chỉ áp dụng cho phần Answer mà còn áp dụng cho cả Authority và Additional. Đây là điểm quan trọng, vì nhiều cuộc tấn công DNS Cache Poisoning không chỉ đầu độc trực tiếp bản ghi trả lời, mà còn chèn bản ghi NS hoặc glue record vào phần Authority/Additional. Những bản ghi này có thể làm resolver tin rằng authoritative name server của một domain đã bị thay đổi sang địa chỉ IP do attacker kiểm soát.

Nếu một bản ghi trong response nằm ngoài phạm vi thẩm quyền hợp lệ, packet đó được đánh dấu là đáng ngờ. Ví dụ, nếu response cho một truy vấn thuộc `example.net` lại chứa thông tin ánh xạ hoặc ủy quyền cho `bank.com`, bản ghi này vi phạm nguyên tắc bailiwick và cần được xử lý như một dấu hiệu tấn công.

### 4.3. Đặc điểm vận hành của Rℓ3

Tương tự Rℓ2, Rℓ3 không cần duy trì trạng thái phức tạp hoặc lưu trữ lịch sử dài hạn. Quy tắc này hoạt động bằng cách phân tích nội dung của từng DNS response và kiểm tra tính hợp lệ của các record theo nguyên tắc bailiwick. Vì vậy, Rℓ3 có chi phí vận hành thấp nhưng vẫn có khả năng phát hiện một nhóm tấn công quan trọng.

Rℓ3 đặc biệt hữu ích đối với các tấn công không dựa chủ yếu vào việc brute-force TXID hoặc source port, mà dựa vào việc resolver xử lý sai các bản ghi ngoài phạm vi thẩm quyền. Trong khi Rℓ1 tập trung vào số lượng response bất thường, Rℓ3 tập trung vào tính hợp lệ về mặt ngữ nghĩa của nội dung DNS response.

---

## 5. Quan hệ giữa ba quy tắc trong Detection Module

Ba quy tắc Rℓ1, Rℓ2 và Rℓ3 được thiết kế để bổ sung cho nhau. Mỗi quy tắc tập trung vào một dấu hiệu tấn công khác nhau, tương ứng với một nhóm kỹ thuật DNS Cache Poisoning.

Rℓ1 xử lý các tấn công thống kê dựa trên việc gửi nhiều response giả mạo để đoán TXID hoặc source port. Đây là nhóm bao gồm các kịch bản như TXID brute-force, port brute-force và Kaminsky-style attack. Rℓ2 xử lý các tấn công dựa trên phân mảnh IP, nơi attacker cố gắng chèn fragment độc hại vào quá trình tái lắp ráp DNS response. Rℓ3 xử lý các response có nội dung vi phạm phạm vi thẩm quyền, đặc biệt là các bản ghi ngoài bailiwick trong phần Answer, Authority hoặc Additional.

Điểm chung của ba quy tắc là chúng đều được thiết kế đơn giản, có thể triển khai trực tiếp trên luồng DNS response và không phụ thuộc vào signature cụ thể của từng CVE. Điều này giúp Detection Module không chỉ phát hiện các tấn công đã biết, mà còn có khả năng bao phủ các biến thể tương tự trong tương lai, miễn là chúng vẫn để lại các dấu hiệu thuộc một trong ba nhóm trên.

Trong phạm vi một hệ thống lab, Detection Module có thể được triển khai theo hướng đơn giản hóa như sau: Rℓ1 đếm số response theo domain trong cửa sổ thời gian ngắn, Rℓ2 kiểm tra fragment offset và cờ MF, còn Rℓ3 kiểm tra các record trong response có vượt khỏi phạm vi thẩm quyền hay không. Khi một packet hoặc một domain bị đánh dấu bởi bất kỳ quy tắc nào, hệ thống ghi nhận alert và chuyển packet sang bước xử lý tiếp theo.
