#!/usr/bin/python3

import sys

from scapy.all import *
from argparse import *
from termcolor import *
from scapy.layers.http import HTTPRequest

class Sniffer:
	def __init__(self):

		# Calling some functions.
		
		self.args()
		self.r = ''
		self.result = ''
		self.result += (f"[{colored('+', 'green')}] Started Sniffing On Interface - {self.args.nic}\n") + '\n'
		self.result += (f"[{colored('+', 'green')}] Legend: ") + '\n'
		self.result += (f"  Ethernet: Magenta ({colored('*', 'magenta')})" + '\n')
		self.result += (f"  TCP: Green ({colored('*', 'green')})") + '\n'
		self.result += (f"  UDP: Cyan({colored('*', 'cyan')})") + '\n'
		self.result += (f"  ARP: Magenta({colored('*', 'red')})") + '\n'
		self.result += (f"  ICMP: Blue ({colored('*', 'blue')})") + '\n'
		self.result += (f"  DNS: Yellow ({colored('*', 'yellow')})") + '\n'
		self.result += (f"  HTTP: Red({colored('*', 'red')})") + '\n'
		self.result += '\n'

		print(self.result, end="")
		self.result = ''

		try:
			
			self.sniff_packets()
		except PermissionError:
			sys.stderr.write(f"[{colored('!', 'red')}] Need root privileges for execution.\n")
			sys.exit()

	def args(self):

		# Preparing Command Line self.args.

		parser = ArgumentParser(description='Simple Packet Sniffer.', usage='./%(prog)s NIC')
		parser.add_argument(metavar='NIC', dest='nic', help='NIC of your computer, to sniff packets.')
		parser.add_argument("-v", "--version", action="version", help="shows this version message and exit", version="version: 1.0")
		parser.add_argument('-o', '--output', metavar='', help='Stores the output to a file.', default="sniffer.log")
		self.args = parser.parse_args()

	def sniff_packets(self):
		
		# Sniff Packets.

		capture = sniff(prn=self.process_packets, iface=self.args.nic, store=False)

	def lan(self):
		try:
			if self.packet.haslayer(Ether):
				src = self.packet[Ether].src
				dst = self.packet[Ether].dst
				self.result += (f"[{colored('+', 'green')}] Ethernet data: \n") + '\n'
				self.result += (f"  Source: {colored(src, 'magenta')}") + '\n'
				self.result += (f"  Destination: {colored(dst, 'magenta')}\n") + '\n'

		except IndexError:
			pass
		except Exception as e:
			sys.stderr.write(f"[{colored('!', 'red')}] Exception: {e}" + '\n')
			self.result += (f"[{colored('!', 'red')}] Exception: {e}") + '\n'
			sys.exit()

	def process_packets(self, packet):
		self.packet = packet

		self.lan()

		if packet.haslayer(ARP):

			# ARP Packets Sniffing

			try:
				src_ip = packet[ARP].psrc
				dst_ip = packet[ARP].pdst
				src_mac = packet[ARP].hwsrc
				dst_mac = packet[ARP].hwdst

				self.result += (f"[{colored('+', 'green')}] ARP data: \n") + '\n'
				self.result += (f"  Source: {colored(src_ip, 'magenta')} , {colored(src_mac, 'magenta')}") + '\n'
				self.result += (f"  Destination: {colored(dst_ip, 'magenta')} , {colored(dst_mac, 'magenta')}") + '\n'
				self.result += '\n'

			except IndexError:
				pass
			except Exception as e:
				sys.stderr.write(f"[{colored('!', 'red')}] Exception: {e}" + '\n')
				sys.exit()

		if packet.haslayer(TCP):
			
			# TCP Packets Sniffing

			try:
				src_ip = packet[IP].src
				dst_ip = packet[IP].dst
				src_port = packet[TCP].sport
				dst_port = packet[TCP].dport

				self.result += (f"[{colored('+', 'green')}] TCP data: \n") + '\n'
				self.result += (f"  Source: {colored(src_ip, 'green')} , {colored(packet[Ether].src, 'green')} , {colored(src_port, 'green')}") + '\n'
				self.result += (f"  Destination: {colored(dst_ip, 'green')} , {colored(packet[Ether].dst, 'green')} , {colored(dst_port, 'green')}\n") + '\n'

			except IndexError:
				pass
			except Exception as e:
				sys.stderr.write(f"[{colored('!', 'red')}] Exception: {e}" + '\n')
				sys.exit()

		if packet.haslayer(UDP):
			
			# UDP Packets Sniffing

			try:
				src_ip = packet[IP].src
				dst_ip = packet[IP].dst
				src_port = packet[UDP].sport
				dst_port = packet[UDP].dport

				self.result += (f"[{colored('+', 'green')}] UDP data: \n") + '\n'
				self.result += (f"  Source: {colored(src_ip, 'cyan')} , {colored(packet[Ether].src, 'cyan')} , {colored(src_port, 'cyan')}") + '\n'
				self.result += (f"  Destination: {colored(dst_ip, 'cyan')} , {colored(packet[Ether].dst, 'cyan')} , {colored(dst_port, 'cyan')}\n") + '\n'

			except IndexError:
				pass
			except Exception as e:
				sys.stderr.write(f"[{colored('!', 'red')}] Exception: {e}" + '\n')
				sys.exit()

		if packet.haslayer(ICMP):
			
			# ICMP Packets Sniffing

			try:
				src_ip = packet[IP].src
				dst_ip = packet[IP].dst
				checksum = packet[ICMP].chksum

				self.result += (f"[{colored('+', 'green')}] ICMP data: \n") + '\n'
				if packet.haslayer(UDP):
					self.result += (f"  Source: {colored(src_ip, 'blue')} , {colored(packet[UDP].sport, 'blue')}") + '\n'
					self.result += (f"  Destination: {colored(dst_ip, 'blue')} , {colored(packet[UDP].dport, 'blue')}") + '\n'
				else:
					self.result += (f"  Source: {colored(src_ip, 'blue')}") + '\n'
					self.result += (f"  Destination: {colored(dst_ip, 'blue')}") + '\n'
				self.result += (f"  Checksum: {colored(checksum, 'blue')}\n") + '\n'

				if packet.haslayer(IP):
					version = packet[IP].version
					ihl = packet[IP].ihl
					i_d = packet[IP].id
					frag = packet[IP].frag

					self.result += (f"[{colored('+', 'green')}] IP in ICMP data: \n") + '\n'
					self.result += (f"  Header Length: {colored(ihl, 'blue')}") + '\n'
					self.result += (f"  ID: {colored(i_d, 'blue')}") + '\n'
					self.result += (f"  Fragments: {colored(frag, 'blue')}") + '\n'

					if packet.haslayer(Raw):
						self.result += ("  payload: "+colored(packet.getlayer(Raw).load, 'red')+'\n') + '\n'
					else:
						self.result += '\n'

			except IndexError:
				pass
			except Exception as e:
				sys.stderr.write(f"[{colored('!', 'red')}] Exception: {e}" + '\n')
				sys.exit()

		if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
			try:
				src = packet[IP].src
				dst = packet[IP].dst
				domain = packet.getlayer(DNS).qd.qname
				self.result += (f"[{colored('+', 'green')}] DNS data: \n") + '\n'
				self.result += (f"  Source: {colored(src, 'yellow')} , {colored(packet[Ether].src, 'yellow')}") + '\n'
				self.result += (f"  Destination: {colored(dst, 'yellow')} , {colored(packet[Ether].dst, 'yellow')}") + '\n'
				try:
					self.result += (f"  Domain Name: {colored(domain.decode()[:-1], 'yellow')}\n") + '\n'
				except:
					pass
			except IndexError:
				pass
			except Exception as e:
				sys.stderr.write(f"[{colored('!', 'red')}] Exception: {e}" + '\n')
				sys.exit()

		if packet.haslayer(HTTPRequest):
			
			# HTTP Packet Sniffing.

			try:
				try:

					# Some basic headers which can be decoded at every request.

					url = 'http://' + packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
					method = packet[HTTPRequest].Method.decode()
					accept = packet[HTTPRequest].Accept.decode()
					http_version = packet[HTTPRequest].Http_Version.decode()
					
					# Some Headers which are sometimes none, hence can't be decoded.

					try:
						accept_charset = packet[HTTPRequest].Accept_Charset.decode()

					except AttributeError:
						accept_charset = packet[HTTPRequest].Accept_Charset

					try:
						accept_encoding = packet[HTTPRequest].Accept_Encoding.decode()

					except AttributeError:
						accept_encoding = packet[HTTPRequest].Accept_Encoding

					try:
						accept_language = packet[HTTPRequest].Accept_Language.decode()

					except AttributeError:
						accept_language = packet[HTTPRequest].Accept_Language

					try:
						authorization = packet[HTTPRequest].Authorization.decode()

					except AttributeError:
						authorization = packet[HTTPRequest].Authorization

					try:
						cache_control = packet[HTTPRequest].Cache_Control.decode()

					except AttributeError:
						cache_control = packet[HTTPRequest].Cache_Control

					try:
						connection = packet[HTTPRequest].Connection.decode()

					except AttributeError:
						connection = packet[HTTPRequest].Connection

					try:
						content_length = packet[HTTPRequest].Content_Length.decode()

					except AttributeError:
						content_length = packet[HTTPRequest].Content_Length

					try:
						content_md5 = packet[HTTPRequest].Content_MD5.decode()

					except AttributeError:
						content_md5 = packet[HTTPRequest].Content_MD5
					try:
						content_type = packet[HTTPRequest].Content_Type.decode()

					except AttributeError:
						content_type = packet[HTTPRequest].Content_Type

					try:
						cookie = packet[HTTPRequest].Cookie.decode()

					except AttributeError:
						cookie = packet[HTTPRequest].Cookie

					try:
						origin = packet[HTTPRequest].Origin.decode()

					except AttributeError:
						origin = packet[HTTPRequest].Origin

					try:
						proxy_authorization = packet[HTTPRequest].Proxy_Authorization.decode()

					except AttributeError:
						proxy_authorization = packet[HTTPRequest].Proxy_Authorization

					try:
						proxy_connection = packet[HTTPRequest].Proxy_Connection.decode()

					except AttributeError:
						proxy_connection = packet[HTTPRequest].Proxy_Connection

					try:
						save_data = packet[HTTPRequest].Save_Data.decode()

					except AttributeError:
						save_data = packet[HTTPRequest].Save_Data

					try:
						user_agent = packet[HTTPRequest].User_Agent.decode()

					except AttributeError:
						user_agent = packet[HTTPRequest].User_Agent

					try:
						x_csrf_token = packet[HTTPRequest].X_Csrf_Token.decode()

					except AttributeError:
						x_csrf_token = packet[HTTPRequest].X_Csrf_Token

					try:
						unknown_headers = packet[HTTPRequest].Unknown_Headers.decode()

					except AttributeError:
						unknown_headers = packet[HTTPRequest].Unknown_Headers

					# Now appending the data.

					self.result += (f"[{colored('+', 'green')}] HTTP data: \n") + '\n'
					self.result += ("  Method: "+colored(method, 'green')) + '\n'
					self.result += ("  Host: "+colored(origin, 'red')) + '\n'
					self.result += ("  HTTP Version: "+colored(http_version, 'red')) + '\n'
					self.result += ("  URL: "+colored(url, 'red')) + '\n'
					self.result += ("  Accept: "+colored(accept, 'red')) + '\n'
					self.result += ("  Accept Charset: "+colored(accept_charset, 'red')) + '\n'
					self.result += ("  Accept Encoding: "+colored(accept_encoding, 'red')) + '\n'
					self.result += ("  Accept Language: "+colored(accept_language, 'red')) + '\n'
					self.result += ("  User Agent: "+colored(user_agent, 'red')) + '\n'
					self.result += ("  Cookie: "+colored(cookie, 'red')) + '\n'
					self.result += ("  Connection: "+colored(connection, 'red')) + '\n'
					self.result += ("  Content Type: "+colored(content_type, 'red')) + '\n'
					self.result += ("  Content Length: "+colored(content_length, 'red')) + '\n'
					self.result += ("  MD5 Content: "+colored(content_md5, 'red')) + '\n'
					self.result += ("  Cache Control: "+colored(cache_control, 'red')) + '\n'
					self.result += ("  Authorization: "+colored(authorization, 'red')) + '\n'
					self.result += ("  Proxy Authorization: "+colored(proxy_authorization, 'red')) + '\n'
					self.result += ("  Proxy Connection: "+colored(proxy_connection, 'red')) + '\n'
					self.result += ("  Saved Data: "+colored(save_data, 'red')) + '\n'
					self.result += ("  X CSRF Token: "+colored(x_csrf_token, 'red')) + '\n'
					self.result += ("  Unknown Headers: "+colored(unknown_headers, 'red')+'\n') + '\n'
					if packet.haslayer(Raw):
						
						# The raw data; specific for POST method.

						self.result += ("  payload: "+colored(packet.getlayer(Raw).load.decode(), 'red')+'\n') + '\n'
					
				except (TypeError):
					pass
			
			except UnicodeDecodeError:
				pass
			
			except Exception as e:
				sys.stderr.write(f"[{colored('!', 'red')}] Exception: {e}" + '\n')
				sys.exit()

		r = self.result.replace(self.r, '')
		sys.stdout.write(r)
		file = open(self.args.output, 'a+')
		file.write(r)
		file.close()
		self.r = self.result

if __name__ == "__main__":
	sniffer = Sniffer()
