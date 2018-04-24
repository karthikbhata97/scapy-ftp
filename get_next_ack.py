if IPv6:
	ip_payload_len = pkt.getlayer(IP).plen
	tcp_hdr_len = pkt.getlayer(TCP).dataofs * 32 / 8
	ans = ip_payload_len - tcp_hdr_len
else:
	total_len = pkt.getlayer(IP).len
	ip_hdr_len = pkt.getlayer(IP).ihl * 32 / 8
	tcp_hdr_len = pkt.getlayer(TCP).dataofs * 32 / 8
	ans = total_len - ip_hdr_len - tcp_hdr_len