import logging
import socket
import sys
import ssl
from urllib.parse import urlparse
import hashlib



def retrieve_url(url):

	url_parts = urlparse(url)
	if url_parts.netloc.find(":") > 0:
		host,port = url_parts.netloc[:url_parts.netloc.find(":")],int(url_parts.netloc[url_parts.netloc.find(":")+1:],10)
	else:
		host,port= url_parts.netloc,80
	
	path = url_parts.path
	if(path == ""):
		path ="/"

	ssl_validate = False
	if(url_parts.scheme == "https"):
		ssl_validate = True
		port = 443

	#Create socket
	context = ssl.SSLContext(ssl.PROTOCOL_TLS)
	context.verify_mode = ssl.CERT_REQUIRED
	context.check_hostname = True
	context.load_default_certs()
	try:
		soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		if ssl_validate:
			ssl_soc = context.wrap_socket(soc, server_hostname=host)
			soc = ssl_soc
			
	except socket.error as e:
		return None

	#******---- Create connection and validate SSL -----******#
	try:
		# soc.connect((host_ip,port))
		soc.connect((host,port))

	except ssl.SSLError as err:
		return None
	except ssl.CertificateError:
		return None
	except Exception as e:
		return None
	
	#******---- Send message for GET -----******#

	message = "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n".format(path,host)
	soc.sendall(message.encode())

	#******---- Get Status & Header fields -----******#

	response = soc.recv(2048)
	headers=[]
	response_parts = response.split(b"\r\n")	
	status = response_parts[0]

	#******---- If Status is 200 OK -----******#

	if(b"200 OK" in status):

		end_of_header = response.lower().find(b'\r\n\r\n')
		while end_of_header == -1:
			response+=soc.recv(2048)
			end_of_header = response.lower().find(b'\r\n\r\n')

		transfer_encoding = response.lower().find(b'transfer-encoding:')
		chunked_encoding = -1
		if(transfer_encoding > -1):
			
			transfer_encoding_crlf = response.lower().find(b'\r\n', transfer_encoding+19)
			transfer_encoding_value = response[transfer_encoding+19:transfer_encoding_crlf]
			chunked_encoding = transfer_encoding_value.lower().find(b'chunked')

		#******---- If Transfer-encoding : chunked -----******#

		if(chunked_encoding > -1):
			#******------------------ Get part of response body next to headers -------------------******#
			
			response_body = response[end_of_header+4:]

			#******------------------ Get first chunk -------------------******#

			chunk_part1_end = response.lower().find(b'\r\n', end_of_header+4)
			if(chunk_part1_end > -1):
				chunk_part1 = response[end_of_header+4:chunk_part1_end]
			else:
				response+=soc.recv(1024)
				chunk_part1_end = response.lower().find(b'\r\n', end_of_header+4)
				chunk_part1 = response[end_of_header+4:chunk_part1_end]

			chunk_size = int(chunk_part1.split(b";")[0],16)

			#******------- Get part of 1st chunk from recv already done  -------******#

			body = b""+ response[chunk_part1_end+2:]
			response_left = response_body
			while(chunk_size < len(response_left)):

					#******--------- Read 1st chunk (Whole chunk already present along with headers) ------------******#

					chunk_message_end = response.lower().find(b'\r\n', chunk_part1_end+2)
					body = b""+ response[chunk_part1_end+2:chunk_message_end]
					chunk_part1_end = response.lower().find(b'\r\n', chunk_message_end+2)
					chunk_part1 = response[chunk_message_end+2:chunk_part1_end]

					if chunk_part1 != b"":
						chunk_size = int(chunk_part1.split(b";")[0],16)
						response_left = response[chunk_part1_end+2:]
					else:
						break
			#******------------------ Read all chunks -------------------******#
			chunk_size = chunk_size-len(response_left)

			while(chunk_size > 0):

				#******------- Fetch rest of the chunk  -------******#

				bytes_read = b""

				while(len(bytes_read) < chunk_size-8196):
					bytes_read += soc.recv(8196)
				while(len(bytes_read) < chunk_size-2048):
					bytes_read += soc.recv(2048)
				while(len(bytes_read) < chunk_size-512):
					bytes_read += soc.recv(512)
				
				#******------- Keep fetching until \r\n found  -------******#
				crlr_found = False
				while crlr_found == False:
					bytes_read += soc.recv(1)
					chunk_end = bytes_read.find(b'\r\n')
					if (chunk_end > 0 and len(bytes_read) > chunk_size):
						crlr_found = True
				body += bytes_read[:chunk_end]

				#******------- Fetch next chunk size  -------******#

				sizeFound = False
				bytes_read = b""

				while(sizeFound == False):

					bytes_read += soc.recv(1)
					chunk_end = bytes_read.find(b'\r\n')
					if chunk_end > 0:
						sizeFound = True

				chunk_size = int(bytes_read[:chunk_end].split(b';')[0],16)

		else:
			pos_content_length = response.lower().find(b'content-length:')

			pos_content_length_crlf = response.lower().find(b'\r\n', pos_content_length+15)

			content_length = int(response[pos_content_length+15:pos_content_length_crlf])

			body = b""+response[end_of_header+4:]
			remaining_body = content_length - len(body)

			while len(body) < content_length:
				body += soc.recv(content_length)
		soc.close()
		return body
	elif (b"301" in status or b"302" in status):

		redirect_location = response.lower().find(b'location:')
		redirect_location_crlf = response.lower().find(b'\r\n', redirect_location+9)
		location = response[redirect_location+10:redirect_location_crlf].decode()
		if(location.find("http") > -1):
			soc.close()
			return retrieve_url(location)
		else:
			redirect_url =  url_parts.scheme+"://"+url_parts.netloc+location
			soc.close()
			return retrieve_url(redirect_url)
		
	else:
		soc.close()
		return None
	

# def __main__():
# 	urls = [ \
# 	"http://www.example.com",\
# 	"http://accc.uic.edu/contact",\
# 	"http://i.imgur.com/fyxDric.jpg",\
# 	"http://illinois.edu/doesnotexist",\
# 	 "http://doesthisdomainevenexistfam.com/",\
# 	 "http://marvin.cs.uic.edu:8080",\
# 	 "https://preloaded-hsts.badssl.com/",\
# 	 "https://expired.badssl.com/",\
# 	 "https://wrong.host.badssl.com/"\
# 	 "http://www.crunchyroll.com/",\
# 	 "http://www.httpwatch.com/httpgallery/chunked/chunkedimage.aspx",\
# 	 "https://untrusted-root.badssl.com/",\
# 	"https://self-signed.badssl.com/"# bad
# 	 ]

# 	count = 1
# 	# for url in urls:
# 	# 	with open("output_"+str(count)+".txt", "w") as text_file:
# 	# 		print(retrieve_url(url), file=text_file)	
# 	# 	count+=1

# 	for url in urls:
# 		returned_bytes = set()
# 		for x in range(1,20):
# 			a = retrieve_url(url)
# 			# with open("output.txt", "a") as text_file:
# 			# 	print(a, file=text_file)
# 			# print(a)
# 			# print("length of body-----",len(a))
# 			# with open("output_new_"+str(count)+".txt", "w") as text_file:
# 			# 	print(retrieve_url(url), file=text_file)
# 			# count+=1
# 			m = hashlib.md5()
# 			if(a != None):
# 				m.update(a)
# 			else:
# 				print("None")
# 			returned_bytes.update([(m.hexdigest())])
# 		print(url, returned_bytes)


# if __name__=="__main__":
# 	__main__()


