import hashlib
import json
from time import time
from typing import List, Dict, Any, Optional, NamedTuple


from cryptography.hazmat.primitives import hashes          #####
from cryptography.hazmat.primitives.asymmetric import ec   #######
from cryptography.exceptions import InvalidSignature       ######
from cryptography.fernet import Fernet

from crypto import key_management

class Transaction(NamedTuple):
    sender: str  # PEM encoded public key
    recipient: str  # PEM encoded public key
    message: str  # Зашифрованное сообщение
    signature: str
    timestamp: float

class Block:
    def __init__(self, index: int, transactions: List[Transaction], timestamp: float, previous_hash: str, nonce: int = 0):
        self.index = index
        self.transactions: List[Transaction] = transactions #  List[Transaction]
        self.timestamp = timestamp
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.hash = self.compute_hash()

    def compute_hash(self) -> str:
        # NamedTuple._asdict() для преобразования транзакций в словарь
        block_string = json.dumps(
            {
                'index': self.index,
                'transactions': [t._asdict() for t in self.transactions], #  _asdict()
                'timestamp': self.timestamp,
                'previous_hash': self.previous_hash,
                'nonce': self.nonce,
            },
            sort_keys=True,
            default=str
        )
        return hashlib.sha256(block_string.encode()).hexdigest()

    def to_json(self):
        return {
            'index': self.index,
            'transactions': [t._asdict() for t in self.transactions],
            'timestamp': self.timestamp,
            'previous_hash': self.previous_hash,
            'nonce': self.nonce,
            'hash': self.hash,
        }

class Blockchain:
    def __init__(self, difficulty: int = 2):
        self.chain: List[Block] = []
        self.unconfirmed_transactions: List[Transaction] = []  # List[Transaction]
        self.difficulty = difficulty
        self.create_genesis_block()

    def create_genesis_block(self):
        genesis_block = Block(0, [], time(), "0")
        self.chain.append(genesis_block)

    @property
    def last_block(self) -> Block:
        return self.chain[-1]


    def add_new_transaction(self, transaction: Transaction): # Transaction
        required_fields = ['sender', 'recipient', 'message', 'signature', 'timestamp']
        if not all(field in transaction._asdict() for field in required_fields): #  _asdict()
            raise ValueError("Transaction must contain all required fields.")

        sender_public_key = key_management.load_public_key(transaction.sender) #  load_public_key

        if not self.verify_signature(transaction, sender_public_key):
            raise ValueError("Invalid transaction signature")

        self.unconfirmed_transactions.append(transaction)



    def proof_of_work(self, block: Block) -> str: # Возвращаем str (хеш)
        """
        Выполняет Proof-of-Work для данного блока.

        Args:
            block: Блок, для которого нужно найти PoW.

        Returns:
            Хэш блока, удовлетворяющий условию сложности.
        """

        computed_hash = block.compute_hash()
        while not computed_hash.startswith('0' * self.difficulty):
            block.nonce += 1
            computed_hash = block.compute_hash()
        return computed_hash

    def add_block(self, block: Block, proof: str) -> bool:
        """
        Добавляет блок в цепочку после проверки.

        Args:
            block: Блок для добавления.
            proof:  Доказательство работы (хеш).

        Returns:
             True, если блок успешно добавлен, False иначе.
        """
        previous_hash = self.last_block.hash

        if previous_hash != block.previous_hash:
            return False

        if not self.is_valid_proof(block, proof):
            return False

        # block.hash = proof  # Хэш уже вычислен в конструкторе блока
        self.chain.append(block)
        return True


    def is_valid_proof(self, block: Block, block_hash: str) -> bool:
        """
        Проверяет, является ли данный хеш действительным доказательством работы для данного блока.
        """
        return (block_hash.startswith('0' * self.difficulty) and
                block_hash == block.compute_hash())

    def add_new_transaction(self, transaction: dict):
        self.unconfirmed_transactions.append(transaction)

    def mine(self) -> Optional[int]: #  Optional[int], т.к. может вернуть None
        """
        Майнит новый блок.

        Returns:
            Индекс нового блока, если он был добыт, None иначе.
        """
        if not self.unconfirmed_transactions:
            return None

        last_block = self.last_block

        new_block = Block(index=last_block.index + 1,
                          transactions=self.unconfirmed_transactions,
                          timestamp=time(),
                          previous_hash=last_block.hash)

        proof = self.proof_of_work(new_block)
        self.add_block(new_block, proof)
        self.unconfirmed_transactions = []
        return new_block.index

    def encrypt_message(self, message: str, recipient_public_key_pem: str, private_key_pem: str) -> str:
        """Шифрует сообщение."""
        private_key = key_management.load_private_key(private_key_pem)
        recipient_public_key = key_management.load_public_key(recipient_public_key_pem)
        shared_key = key_management.generate_shared_key(private_key, recipient_public_key)

        f = Fernet(shared_key)
        encrypted_message = f.encrypt(message.encode()).decode()
        return encrypted_message

    def decrypt_message(self, encrypted_message: str, sender_public_key_pem: str, private_key_pem: str) -> str:
        """Дешифрует сообщение."""
        private_key = key_management.load_private_key(private_key_pem)
        sender_public_key = key_management.load_public_key(sender_public_key_pem)

        shared_key = key_management.generate_shared_key(private_key, sender_public_key)

        f = Fernet(shared_key)
        decrypted_message = f.decrypt(encrypted_message.encode()).decode()
        return decrypted_message

    def verify_signature(self, transaction: Transaction, sender_public_key: ec.EllipticCurvePublicKey) -> bool:  # Transaction
        """Проверяет подпись транзакции."""
        signature = bytes.fromhex(transaction.signature)
        message = json.dumps(
            {k: v for k, v in transaction._asdict().items() if k != 'signature'},  # Исключаем подпись
            sort_keys=True,
            default=str  # Для обработки timestamp
        ).encode()

        try:
            sender_public_key.verify(
                signature,
                message,
                ec.ECDSA(hashes.SHA256())  # Используем ECDSA для эллиптических кривых
            )
            return True
        except InvalidSignature:
            return False

    def get_block_by_index(self, index: int) -> Optional[Block]:
        """
        Возвращает блок по индексу, или None, если блок не найден.
        """
        try:
            return self.chain[index]
        except IndexError:
            return None

    def to_json(self):
        return {
            'chain': [block.to_json() for block in self.chain],
            'length': len(self.chain), # Удобно иметь длину цепочки
        }