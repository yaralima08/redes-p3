import ipaddress
import struct

from iputils import *
from tcputils import calc_checksum, str2addr


class IP:
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        self.tabela = []   # [(rede, next_hop)] ordenada do prefixo mais longo ao mais curto

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador

            # ===================== PASSO 4: tratamento do TTL =====================
            if ttl <= 1:
                # O TTL chegaria a zero: descarta o datagrama em vez de encaminhá-lo
                # ================= PASSO 5: ICMP Time exceeded =================
                self._enviar_time_exceeded(datagrama, src_addr)
                return

            # Decrementa o TTL e corrige o checksum do cabeçalho
            ihl = datagrama[0] & 0xf
            total_len, = struct.unpack('!H', datagrama[2:4])
            cabecalho = bytearray(datagrama[:4 * ihl])
            cabecalho[8] = ttl - 1
            cabecalho[10:12] = b'\x00\x00'
            cabecalho[10:12] = struct.pack('!H', calc_checksum(bytes(cabecalho)))
            datagrama = bytes(cabecalho) + datagrama[4 * ihl:total_len]

            # Encaminha sempre ao enlace; se nenhuma rota casar, next_hop é None
            next_hop = self._next_hop(dst_addr)
            self.enlace.enviar(datagrama, next_hop)

    # ===================== PASSOS 1 e 3: tabela de encaminhamento =====================
    def _next_hop(self, dest_addr):
        # Passo 1: procura na tabela a entrada cujo CIDR casa com dest_addr.
        # Passo 3: como a tabela está ordenada do prefixo mais longo ao mais curto,
        # a primeira entrada que casar é a de maior prefixo (longest prefix match).
        try:
            destino = ipaddress.ip_address(dest_addr)
        except ValueError:
            return None
        for rede, next_hop in self.tabela:
            if destino in rede:
                return next_hop
        return None

    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]

        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        # Passo 1: converte os CIDRs para objetos de rede.
        # Passo 3: ordena por tamanho de prefixo (maior primeiro). A ordenação
        # do Python é estável, então empates mantêm a ordem original da tabela.
        entradas = [(ipaddress.ip_network(cidr, strict=False), next_hop)
                    for cidr, next_hop in tabela]
        entradas.sort(key=lambda e: e[0].prefixlen, reverse=True)
        self.tabela = entradas

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    # ===================== PASSO 2: montagem do datagrama =====================
    def _montar_datagrama(self, payload, dest_addr, proto, ttl=64):
        versao_ihl = (4 << 4) | 5                    # IPv4, cabeçalho de 20 bytes
        total_len = 20 + len(payload)
        cabecalho = struct.pack('!BBHHHBBH',
                                versao_ihl,          # versão + IHL
                                0,                   # DSCP + ECN
                                total_len,           # tamanho total
                                0,                   # identification
                                0,                   # flags + fragment offset
                                ttl,                 # TTL
                                proto,               # protocolo da camada superior
                                0)                   # checksum (calculado abaixo)
        cabecalho += str2addr(self.meu_endereco) + str2addr(dest_addr)
        checksum = calc_checksum(cabecalho)
        cabecalho = cabecalho[:10] + struct.pack('!H', checksum) + cabecalho[12:]
        return cabecalho + payload

    def enviar(self, segmento, dest_addr):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        next_hop = self._next_hop(dest_addr)
        datagrama = self._montar_datagrama(segmento, dest_addr, IPPROTO_TCP)
        self.enlace.enviar(datagrama, next_hop)

    # ===================== PASSO 5: ICMP Time exceeded =====================
    def _enviar_time_exceeded(self, datagrama_original, dest_addr):
        next_hop = self._next_hop(dest_addr)
        ihl = datagrama_original[0] & 0xf
        # Corpo do ICMP: cabeçalho IP original + 8 primeiros bytes do payload original
        corpo = datagrama_original[:4 * ihl + 8]
        # Tipo 11 (Time Exceeded), código 0 (TTL excedido em trânsito), 4 bytes não usados
        icmp = struct.pack('!BBHI', 11, 0, 0, 0) + corpo
        icmp = icmp[:2] + struct.pack('!H', calc_checksum(icmp)) + icmp[4:]
        datagrama = self._montar_datagrama(icmp, dest_addr, IPPROTO_ICMP)
        self.enlace.enviar(datagrama, next_hop)
