import clipboard
import time
import re

# maximum on 127.12.145.18/12
# private
# 10.22.36.123
# 12.5.53.5

IP_patt = re.compile(	r"([0-9]{1,3})\." \
						r"([0-9]{1,3})\." \
						r"([0-9]{1,3})\." \
						r"([0-9]{1,3})" \
						r"(/[0-9]{1,2})?")

comm_patt = re.compile(r"(?i)(?:communicate)|(?:communiquer)")
plage_patt = re.compile(r"(?i)(?:range)|(?:plage)")
private_patt = re.compile(r"(?i)(?:private)|(?:privé)")
maximum_patt = re.compile(r"(?i)(?:max)|(?:how many)|(?:combien)")
network_patt = re.compile(r"(?i)(?:network address)|(?:réseau)")
osi_patt = re.compile(r"(?i)\Wosi\W?")

OSI_str = """
Layer 1: Physical Layer
Layer 2: Data Link Layer
Layer 3: Network Layer
Layer 4: Transport Layer
Layer 5: Session Layer
Layer 6: Presentation Layer
Layer 7: Application Layer"""

m4 = 255
m3 = m4 << 8
m2 = m3 << 8
m1 = m2 << 8

def ip_to_s(ip):
	ipparts = []
	for i in range(4):
		ipparts.append(ip % 256)
		ip //= 256
	return '.'.join(str(ipp) for ipp in ipparts[-1::-1])

def get_ip(s):
	m = re.search(IP_patt, s)
	if (not m):
		return None
	ip = int(m.group(1)) << 24
	ip += int(m.group(2)) << 16
	ip += int(m.group(3)) << 8
	ip += int(m.group(4))
	if m.group(5):
		masklen = int(m.group(5)[1:])
		mask = (pow(2, masklen) - 1) << (32 - masklen)
		ip_net = ip & mask
		ip_broad = ((pow(2, 32) - 1) ^ mask) | ip
		return (ip, ip_net, ip_broad)
	else:
		return ip

def communicate_choice(qu):
	ls = qu.split('\n')
	res = get_ip(ls[0])
	if (not res):
		return '?????'
	ip_net, ip_broad = res[1:3]
	answ = ''
	for l in ls[1:]:
		ip = get_ip(l)
		if (not ip):
			continue
		if (ip_net < ip < ip_broad):
			answ += 'valid ip : ' + l + '\n'
	return answ if len(answ) > 0 else '?????'

#TODO selction of answ
def plage(qu):
	res = get_ip(qu)
	if (not res or type(res) == int):
		return '?????'
	return (ip_to_s(res[1] + 1)
				+ " - "
				+ ip_to_s(res[2] - 1))

def is_private(ip):
	if (ip >> 24) == 10:
		return True
	if (ip >> 24) == 172 and 16 <= ((ip & m2) >> 16) <= 32:
		return True
	if (ip >> 24) == 192 and ((ip & m2) >> 16) == 168:
		return True
	return False

def private_question(qu):
	ls = qu.split('\n')
	answ = ''
	i = 0
	for l in ls:
		ip = get_ip(l)
		if (not ip):
			continue
		i += 1
		if (is_private(ip)):
			answ += 'line ' + str(i) + ': private ip : ' + l + '\n'
	return answ if len(answ) > 0 else '?????'

def get_class(ip):
	n1 = ip >> 24
	if (n1 <= 127):
		return 'A'
	if (n1 <= 191):
		return 'B'
	if (n1 <= 223):
		return 'C'
	if (n1 <= 239):
		return 'D'
	if (n1 <= 255):
		return 'E'

#TODO selction of answ
def maximum(qu):
	res = get_ip(qu)
	if (not res):
		simplenum_patt = re.compile("[^0-9]([0-9]{1,2})[^0-9]*")
		m = simplenum_patt.search(qu)
		if (not m):
			return '??????'
		masklen = int(m.group(1))
	else:
		if (type(res) == int):
			mask = res
			i = 0
			while ((mask % 2) == 0):
				i += 1
				mask //= 2
			masklen = 32 - i
		else:
			m = re.search(IP_patt, s)
			masklen = int(m.group(5)[1:])
	answ = 'Mask len : ' + str(masklen) + '\n'
	answ += 'Max number of hosts : ' + str(pow(2, 32 - masklen) - 2) + '\n'
	return answ
	
def network_addr_question(qu):
	ls = qu.split('\n')
	res = get_ip(ls[0])
	if (not res):
		return '?????'
	ip_net, ip_broad = res[1:3]
	answ = ''
	for l in ls[1:]:
		ip = get_ip(l)
		if (not ip):
			continue
		if (ip_net == ip):
			answ += 'network ip : ' + l + '\n'
	return answ if len(answ) > 0 else '?????'

def all(qu):
	res = get_ip(qu)
	if (not res):
		return '?????'
	if (type(res) == int):
		ip = res
	else:
		ip = res[0]
	answ = 'IP : ' + ip_to_s(ip) + '\n'
	answ += 'Class ' + get_class(ip) + '\n'
	if (type(res) != int):
		ip_net, ip_broad = res[1:3]
		answ += "Network addr : " + ip_to_s(ip_net) + "\n"
		answ += "Broadc. addr : " + ip_to_s(ip_broad) + "\n"
	return answ
	


def redirect_question(qu):
	answ = ''
	if (osi_patt.search(qu)):
		answ = "(detected) OSI :\n"
		answ += OSI_str
	elif (comm_patt.search(qu)):
		answ = "(detected) Is able to communicate... :\n"
		answ += communicate_choice(qu)
	elif (plage_patt.search(qu)):
		answ = "(detected) Valid range for host :\n"
		answ += plage(qu)
	elif (private_patt.search(qu)):
		answ = "(detected) Private IP... :\n"
		answ += private_question(qu)
	elif (maximum_patt.search(qu)):
		answ = "(detected) Max number of hosts : \n"
		answ += maximum(qu)
	elif (network_patt.search(qu)):
		answ = "(detected) Network IP : \n"
		answ += network_addr_question(qu)
	answ += '\n'
	answ += all(qu)
	answ += '\n\n'
	print(answ)

s = ''
s_p = ''
while (True):
	s = clipboard.paste()
	if (len(s) == 0 and len(s_p) == 0):
		print("Empty clipboard")
	elif (s != s_p):
		print("Q : " + s[:100] + "..." if len(s) > 100 else '')
		redirect_question(s)
		print()
		s_p = s
	time.sleep(1)