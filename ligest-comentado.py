import socket, sys

#Dicionario de dominios.
domain_dict={	'br':{	'com':{	'google':'216.58.206.3',#google
								'vivo':'177.79.246.174'#vivo
							},
						'gov':{'ibama':'177.15.128.137'}#ibama
					},
				'com':{ 'ananas': '209.59.129.83',
						'reddit': '151.101.65.140'
					},
				'tv':{ 'twitch': '50.112.196.159'
					}
			}


#Função que seta as flags baseado nas flags do pacote de pergunta, modificando-o para usar como flags no apcote de resposta.
#Flags de resposta: QR = 1 (resposta), Opcode = Opcode de pergunta, AA = 1 (resposta autorizada), TC = 0 (não truncada),
#RD = 0 (sem recursão), RA = 0 (sem recursão), Z = 0 (sem uso), RCODE = 0 (codigo de resposta).
def getFlags(flags):
	byte1 = flags[0]

	byte2 = flags[1]

	byte1 = byte1 & int('01111000',2)
	byte1 = byte1 | int('10000100',2)

	byte2 = int('00000000',2)

	resp_flags = bytes([byte1])+bytes([byte2])

	return resp_flags

#Percorre data, que já começa contendo a URL do site, separando nome e domínios em uma variável "domain_list".
#Também devolve quantos bytes tem a URL, modificando "size_resp".
def getURL(data, size_resp):
	domain = ''
	pointer = 0
	n_char = data[pointer]
	pointer+=1
	domain_list=[]
	while(n_char != 0):
		for x in range(n_char):
			domain+=chr(data[pointer])
			pointer+=1
			size_resp[0]+=1
		n_char = data[pointer]
		domain_list.append(domain)
		if n_char!=0:
			domain = ''
			pointer+=1
		size_resp[0]+=1
	return domain_list

#Função recursiva que recebe vetor com URL e compara elementos com dicionário de domínios até obter IP 
#que corresponde a aquele domínio, ou não encontrar e retornar -1.
def getIP(site,temp_dict):
	for part in site:
		if part in temp_dict:
			if(type(temp_dict[part]) is str):
				return(temp_dict[part])
			else:
				temp_list = site[:]
				temp_list.remove(part)
				temp = getIP(temp_list,temp_dict[part])
				return(temp)	
	return -1	

#Função que recebe data( pacote DNS completo) provida por DNS do Google e retorna index onde começa IP.
def getURLGoogle(data):
	size_resp = 29
	pointer = 12
	n_char = data[pointer]
	pointer+=1
	while(n_char != 0):
		for x in range(n_char):
			pointer+=1
			size_resp+=1
		n_char = data[pointer]
		if n_char!=0:
			pointer+=1
		size_resp+=1
	return size_resp

#Função que obtem nome completo do site em bytes a partir de vetor de URL.
def full_name_bytes(site):
	qbytes = b''
	for part in site:
		length = len(part)
		qbytes+= bytes([length])

		for char in part:
			qbytes+= ord(char).to_bytes(1,byteorder='big')

	qbytes+= b'\x00'
	return qbytes

#Função que cria inicio do corpo da resposta, este contem URL de pergunta, typo da pergunta e sua classe, tudo na forma de bytes. 
def build_body_beginning(site, TYPE, CLASS, resp_IP_str, size_url):
	#Constroi string com nome a partir de site.
	qbytes = b''
	for part in site:
		length = len(part)
		qbytes+= bytes([length])

		for char in part:
			qbytes+= ord(char).to_bytes(1,byteorder='big')

	qbytes+= b'\x00'

	#Adiciona tipo e classe depois de nome.
	if TYPE == b'\x00\x01':
		qbytes+= (1).to_bytes(2,byteorder='big') #type
	if TYPE == b'\x00\x1c':	
		qbytes+= (28).to_bytes(2,byteorder='big') #type
	qbytes+= (1).to_bytes(2,byteorder='big') #class

	#Converte IP de string para bytes.
	resp_ip_bytes = IP_str2bytes(resp_IP_str)

	#Define nome comprimido (0xc000 mais a distancia do inicio do pacote DNS até a url).
	compressed_name = b'\xc0\x0c'

	#Usa time-to-live padrão e tamanho de IPv4 (sempre 4).
	TTL = b'\x00\x00\x02\x58'
	ADDR_LEN = b'\x00\x04'

	#Concatena informações para compor corpo de resposta.
	DNS_BODY = qbytes+compressed_name+TYPE+CLASS+TTL+ADDR_LEN+resp_ip_bytes

	return DNS_BODY

#Função que converte string com IP para bytes.
def IP_str2bytes(str_ip):
	str_ip=str_ip.split('.')

	byte_ip = b''
	for piece in str_ip:
		byte_ip += (int(piece)).to_bytes(1,byteorder='big')
	return(byte_ip)

#Função que constroi resposta a partir de pergunta feita pela Client, na qual data é o conteúdo da pergunta.
def DNSQuery(data, udps):
	#Obtem ID de transação do pacote de pergunta, diferente por cada pedido.
	transaction_ID = data[0:2]
	#Obtem flags do pacote de pergunta.
	req_flags = data[2:4]
	#Constroi flags para resposta.
	resp_flags = getFlags(req_flags)
	#Seta resto de cabeçalho DNS
	QDCOUNT = b'\x00\x01'
	NSCOUNT = b'\x00\x00'
	ARCOUNT = b'\x00\x00'
	ANCOUNT = b'\x00\x01'

	#constroi o cabeçalho DNS juntando todas as partes produzidas.
	DNS_HEADER = transaction_ID+resp_flags+QDCOUNT+ANCOUNT+NSCOUNT+ARCOUNT

	#Obtém vetor com URL a partir de data (pula-se 12, que é apenas o cabeçalho DNS) e modifica size_resp com tamanho de URL.
	size_url = [0]
	site = getURL(data[12:], size_url)

	#Obtem IP a partir de vetor com URL se este estiver no dicionário de domínios, ou -1 se não estiver.
	resp_IP_str = getIP(site,domain_dict)

	#Se URL não estiver em dicionário, repassa a pergunta para o servidor do Google e obtem IP, que é armazenado em resp_IP_str
	if(resp_IP_str == -1):
		udps.sendto(data,('8.8.8.8',53))
		data2, addr = udps.recvfrom(1024)
		indexIP = getURLGoogle(data2)	
		resp_IP_str = str(data2[indexIP])+'.'+str(data2[indexIP+1])+'.'+str(data2[indexIP+2])+'.'+str(data2[indexIP+3])
		print('Google IP')
	else:
		print('My IP')

	#Define tipo e classe da pergunta por data.
	TYPE = data[size_url[0]+13:size_url[0]+15]
	CLASS = data[size_url[0]+15:size_url[0]+17]

	#Constroi parte corpo da resposta.
	DNS_BODY = build_body_beginning(site, TYPE, CLASS, resp_IP_str, size_url[0])

	#Concatena header e corpo de resposta DNS.
	TOTAL_RESPONSE = DNS_HEADER+DNS_BODY

	return(TOTAL_RESPONSE)

#Cria socket para comunicação com Usuario e DNS do Google.
udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
aboveDNS = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

#Bind de scoket para comunicação com Usuario.
udps.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
udps.bind(('127.0.0.1',53))

#Bind de scoket para comunicação com DNS do Google.
aboveDNS.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
aboveDNS.bind(('0.0.0.0',1234))

while 1:

	#Espera pergunta de DNS de Usuario.
	data, addr = udps.recvfrom(512)

	try:	
		#Constroi resposta para pergunta (passa socket de comunicação com DNS da Google caso URL não esteja armazenada).
		response = DNSQuery(data, aboveDNS)

		#Envia resposta para usuario.
		udps.sendto(response, addr)

	except Exception:
		print('Exception')

