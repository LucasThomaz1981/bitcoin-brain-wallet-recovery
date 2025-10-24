#!/usr/bin/env python3
"""
Bitcoin Brain Wallet Recovery Program - Versão Final
Programa de Recuperação de Chaves Bitcoin a partir de Brain Wallets

Este programa utiliza:
- Gerador de máscaras do hashcat para gerar senhas candidatas
- Biblioteca coincurve para operações criptográficas secp256k1
- SHA-256 e RIPEMD-160 para derivação de endereços Bitcoin

Requisitos:
- coincurve: Biblioteca Python para operações criptográficas secp256k1
- hashlib: Biblioteca padrão para hashing

Uso:
    python3 bitcoin_recovery_final.py [mask_file] [addresses_file] [output_file]

Exemplos:
    python3 bitcoin_recovery_final.py rockyou-1-60.hcmask target_addresses.txt recovered_keys.txt
    python3 bitcoin_recovery_final.py  # Usa valores padrão
"""

import hashlib
import os
import sys
import time
import itertools
from pathlib import Path
from typing import Set, List, Tuple, Optional, Iterator, Dict

# Importação condicional, pois a coincurve pode não estar instalada no ambiente de execução
try:
    from coincurve.keys import PrivateKey
except ImportError:
    print("Aviso: A biblioteca 'coincurve' não está instalada. O script pode falhar.")
    print("Instale com: pip install coincurve")
    sys.exit(1)


class HashcatMaskGenerator:
    """Gerador de senhas a partir de máscaras do hashcat."""

    # Charsets padrão do hashcat
    CHARSET_LOWER = 'abcdefghijklmnopqrstuvwxyz'
    CHARSET_UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    CHARSET_DIGIT = '0123456789'
    CHARSET_SPECIAL = ' !"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'
    CHARSET_ALL = CHARSET_LOWER + CHARSET_UPPER + CHARSET_DIGIT + CHARSET_SPECIAL

    def __init__(self, custom_charsets: Dict[str, str] = None):
        """Inicializa o gerador de máscaras."""
        self.custom_charsets = custom_charsets or {}

    def parse_mask(self, mask: str) -> List[tuple]:
        """Analisa uma máscara e retorna uma lista de (tipo, valor) para cada posição."""
        positions = []
        i = 0
        while i < len(mask):
            if mask[i] == '?':
                if i + 1 < len(mask):
                    placeholder = mask[i + 1]
                    if placeholder == 'l':
                        positions.append(('charset', self.CHARSET_LOWER))
                    elif placeholder == 'u':
                        positions.append(('charset', self.CHARSET_UPPER))
                    elif placeholder == 'd':
                        positions.append(('charset', self.CHARSET_DIGIT))
                    elif placeholder == 's':
                        positions.append(('charset', self.CHARSET_SPECIAL))
                    elif placeholder == 'a':
                        positions.append(('charset', self.CHARSET_ALL))
                    elif placeholder == 'b':
                        positions.append(('charset', ''.join(chr(i) for i in range(32, 127))))
                    elif placeholder in '1234':
                        charset = self.custom_charsets.get(placeholder, self.CHARSET_ALL)
                        positions.append(('charset', charset))
                    elif placeholder == '?':
                        positions.append(('static', '?'))
                    else:
                        positions.append(('static', '?'))
                    i += 2
                else:
                    positions.append(('static', '?'))
                    i += 1
            else:
                positions.append(('static', mask[i]))
                i += 1

        return positions

    def generate_passwords(self, mask: str, max_passwords: int = None) -> Iterator[str]:
        """Gera senhas a partir de uma máscara."""
        positions = self.parse_mask(mask)

        charsets = []
        static_positions = {}

        for i, (tipo, valor) in enumerate(positions):
            if tipo == 'charset':
                charsets.append((i, valor))
            else:
                static_positions[i] = valor

        if not charsets:
            password = ''.join(valor for _, valor in positions)
            yield password
            return

        charset_indices = [i for i, _ in charsets]
        charset_values = [valor for _, valor in charsets]

        count = 0
        for combination in itertools.product(*charset_values):
            if max_passwords and count >= max_passwords:
                break

            password_list = [''] * len(positions)

            for pos, char in static_positions.items():
                password_list[pos] = char

            for idx, charset_idx in enumerate(charset_indices):
                password_list[charset_idx] = combination[idx]

            yield ''.join(password_list)
            count += 1

    def generate_passwords_from_file(self, mask_file: str, max_passwords_per_mask: int = None) -> Iterator[str]:
        """Gera senhas a partir de um arquivo contendo máscaras."""
        try:
            with open(mask_file, 'r', encoding='latin-1') as f:
                for line in f:
                    mask = line.strip()
                    if mask and not mask.startswith('#'):
                        for password in self.generate_passwords(mask, max_passwords_per_mask):
                            yield password
        except FileNotFoundError:
            print(f"✗ Erro: Arquivo de máscaras '{mask_file}' não encontrado.")
            return

    def estimate_keyspace(self, mask: str) -> int:
        """Estima o número de senhas que serão geradas a partir de uma máscara."""
        positions = self.parse_mask(mask)
        keyspace = 1

        for tipo, valor in positions:
            if tipo == 'charset':
                keyspace *= len(valor)

        return keyspace


class BitcoinRecovery:
    """Classe para recuperação de chaves Bitcoin a partir de brain wallets."""

    def __init__(self, target_addresses_file: str, output_file: str = 'recovered_keys.txt'):
        """Inicializa o programa de recuperação."""
        self.target_addresses: Set[str] = set()
        self.output_file = output_file
        self.found_count = 0
        self.processed_count = 0
        self.start_time = None
        self.mask_generator = HashcatMaskGenerator()

        self.load_target_addresses(target_addresses_file)

    def load_target_addresses(self, file_path: str) -> None:
        """Carrega os endereços Bitcoin alvo de um arquivo."""
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    address = line.strip()
                    if address and address.startswith('1'):
                        self.target_addresses.add(address)
            print(f"✓ Carregados {len(self.target_addresses)} endereços alvo.")
        except FileNotFoundError:
            print(f"✗ Erro: Arquivo de endereços alvo '{file_path}' não encontrado.")
            sys.exit(1)

        if not self.target_addresses:
            print("✗ Nenhum endereço alvo válido encontrado. Saindo.")
            sys.exit(0)

    def password_to_private_key(self, password: str) -> bytes:
        """Converte uma senha em uma chave privada usando SHA-256."""
        return hashlib.sha256(password.encode('utf-8')).digest()

    def private_key_to_wif(self, private_key_bytes: bytes) -> str:
        """Converte uma chave privada em bytes para o formato WIF."""
        extended_key = b'\x80' + private_key_bytes
        sha256_1 = hashlib.sha256(extended_key).digest()
        sha256_2 = hashlib.sha256(sha256_1).digest()
        checksum = sha256_2[:4]
        final_key = extended_key + checksum
        return self.base58_encode(final_key)

    def base58_encode(self, v: bytes) -> str:
        """Codifica bytes em Base58."""
        alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        base = len(alphabet)
        long_value = int.from_bytes(v, byteorder='big')
        result = ''

        while long_value >= base:
            div, mod = divmod(long_value, base)
            result = alphabet[mod] + result
            long_value = div

        result = alphabet[long_value] + result

        for byte in v:
            if byte == 0:
                result = alphabet[0] + result
            else:
                break

        return result

    def get_bitcoin_address_p2pkh(self, public_key_bytes: bytes) -> str:
        """Deriva um endereço Bitcoin P2PKH de uma chave pública."""
        sha256_pubkey = hashlib.sha256(public_key_bytes).digest()
        ripemd160_pubkey = hashlib.new('ripemd160', sha256_pubkey).digest()
        extended_ripemd160 = b'\x00' + ripemd160_pubkey
        sha256_1 = hashlib.sha256(extended_ripemd160).digest()
        sha256_2 = hashlib.sha256(sha256_1).digest()
        checksum = sha256_2[:4]
        final_address = extended_ripemd160 + checksum
        return self.base58_encode(final_address)

    def process_password(self, password: str) -> Optional[Tuple[str, str, str]]:
        """Processa uma senha candidata e verifica se corresponde a um endereço alvo."""
        try:
            private_key_bytes = self.password_to_private_key(password)
            private_key = PrivateKey(private_key_bytes)
            public_key_bytes = private_key.public_key.format(compressed=True)
            derived_address = self.get_bitcoin_address_p2pkh(public_key_bytes)

            if derived_address in self.target_addresses:
                wif_key = self.private_key_to_wif(private_key_bytes)
                return (password, wif_key, derived_address)

        except Exception:
            pass

        return None

    def run(self, mask_file_path: str) -> None:
        """Executa o programa de recuperação."""
        print("\n" + "=" * 70)
        print("Bitcoin Brain Wallet Recovery Program - Versão Final")
        print("=" * 70 + "\n")

        print(f"Lendo máscaras de: {mask_file_path}")
        
        # Estimar keyspace total
        total_keyspace = 0
        try:
            with open(mask_file_path, 'r', encoding='latin-1') as f:
                for line in f:
                    mask = line.strip()
                    if mask and not mask.startswith('#'):
                        total_keyspace += self.mask_generator.estimate_keyspace(mask)
        except FileNotFoundError:
            print(f"✗ Erro: Arquivo de máscaras '{mask_file_path}' não encontrado.")
            sys.exit(1)

        print(f"✓ Keyspace estimado: {total_keyspace:,} senhas\n")

        if total_keyspace == 0:
            print("✗ Nenhuma máscara válida encontrada. Saindo.")
            sys.exit(0)

        # Limpar arquivo de saída
        with open(self.output_file, 'w') as f:
            f.write("# Bitcoin Recovery Results\n")
            f.write(f"# Data: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("# Formato: Senha | Chave Privada (WIF) | Endereço Bitcoin\n\n")

        self.start_time = time.time()
        self.processed_count = 0
        self.found_count = 0

        print("Iniciando busca...\n")

        # Gerar senhas a partir das máscaras
        for password in self.mask_generator.generate_passwords_from_file(mask_file_path):
            self.processed_count += 1

            if self.processed_count % 10000 == 0:
                elapsed_time = time.time() - self.start_time
                speed = self.processed_count / elapsed_time if elapsed_time > 0 else 0
                percent = (self.processed_count / total_keyspace * 100) if total_keyspace > 0 else 0
                eta = (total_keyspace - self.processed_count) / speed if speed > 0 else 0
                print(f"Processadas {self.processed_count:,} senhas ({percent:.2f}%). "
                      f"Velocidade: {speed:.0f} senhas/segundo. ETA: {eta:.0f}s")

            result = self.process_password(password)
            if result:
                password, wif_key, address = result
                self.found_count += 1
                print(f"\n✓ Chave encontrada!")
                print(f"  Senha: {password}")
                print(f"  Chave Privada (WIF): {wif_key}")
                print(f"  Endereço Bitcoin: {address}\n")

                with open(self.output_file, 'a') as f:
                    f.write(f"{password} | {wif_key} | {address}\n")

        # Resumo final
        elapsed_time = time.time() - self.start_time
        print("\n" + "=" * 70)
        print("Resumo Final")
        print("=" * 70)
        print(f"Senhas processadas: {self.processed_count:,}")
        print(f"Chaves encontradas: {self.found_count}")
        print(f"Tempo decorrido: {elapsed_time:.2f} segundos")
        if elapsed_time > 0:
            print(f"Velocidade média: {self.processed_count / elapsed_time:.0f} senhas/segundo")
        print(f"Resultados salvos em: {self.output_file}")
        print("=" * 70 + "\n")


def main():
    """Função principal."""
    mask_file = 'rockyou-1-60.hcmask'
    addresses_file = 'addresses_to_check.txt'
    output_file = 'recovered_keys.txt'

    if len(sys.argv) > 1:
        mask_file = sys.argv[1]
    if len(sys.argv) > 2:
        addresses_file = sys.argv[2]
    if len(sys.argv) > 3:
        output_file = sys.argv[3]

    recovery = BitcoinRecovery(addresses_file, output_file)
    recovery.run(mask_file)


if __name__ == '__main__':
    main()
